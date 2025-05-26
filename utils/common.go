package utils

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/miniblocks-app/miniblocks-core/logger"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

// handleUpload handles the incoming request, writes the user code to main.dart,
// zips the Flutter project, uploads it to Firebase Storage, and triggers the GitHub Actions workflow.
func HandleUpload(w http.ResponseWriter, r *http.Request) {
	log := logger.Get()

	// --- 1) Parse JSON ---
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Warn("Invalid JSON body", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	code := payload.Code
	if code == "" {
		log.Warn("Code not provided in request")
		http.Error(w, "code field is empty", http.StatusBadRequest)
		return
	}

	// --- 2) Create a temporary directory ---
	tempDir, err := ioutil.TempDir("", "flutter_project")
	if err != nil {
		log.Error("Failed to create temp dir", zap.Error(err))
		http.Error(w, "failed to create temp dir", http.StatusInternalServerError)
		return
	}
	defer func(path string) {
		if rmErr := os.RemoveAll(path); rmErr != nil {
			log.Error("Failed to remove temp dir", zap.Error(rmErr))
		}
	}(tempDir)

	// --- 3) Copy the Flutter project template ---
	if err := copyDir("./flutter", tempDir); err != nil {
		log.Error("Failed to copy project template", zap.Error(err))
		http.Error(w, "failed to copy project template", http.StatusInternalServerError)
		return
	}
	log.Info("Copied Flutter template", zap.String("tempDir", tempDir))

	// --- 4) Write the code to lib/main.dart ---
	mainDartPath := filepath.Join(tempDir, "lib", "main.dart")
	if err := os.WriteFile(mainDartPath, []byte(code), 0644); err != nil {
		log.Error("Failed to write main.dart", zap.Error(err))
		http.Error(w, "failed to write main.dart", http.StatusInternalServerError)
		return
	}
	log.Info("Wrote code to main.dart")

	// --- 5) Zip the project directory ---
	zipFilePath := tempDir + ".zip"
	if err := zipDir(tempDir, zipFilePath); err != nil {
		log.Error("Failed to create zip file", zap.Error(err))
		http.Error(w, "failed to create zip file", http.StatusInternalServerError)
		return
	}
	log.Info("Zipped directory", zap.String("zipPath", zipFilePath))

	// --- 6) Upload the ZIP to Firebase Storage ---
	firebaseURL, err := uploadToFirebase(zipFilePath)
	if err != nil {
		log.Error("Failed to upload to Firebase", zap.Error(err))
		http.Error(w, "failed to upload to Firebase: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("Uploaded ZIP to Firebase", zap.String("firebaseURL", firebaseURL))

	// --- 7) Trigger GitHub workflow via workflow_dispatch ---
	if err := triggerWorkflowDispatch(firebaseURL); err != nil {
		log.Error("Failed to trigger GitHub workflow", zap.Error(err))
		http.Error(w, "failed to trigger GitHub workflow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Project successfully processed and GitHub workflow triggered."))
}

// handleCompile handles the compilation request, builds the Flutter web version,
// and returns the build file as a response.
func HandleCompile(w http.ResponseWriter, r *http.Request) {
	log := logger.Get()

	// --- 1) Parse JSON ---
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Warn("Invalid JSON body", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	code := payload.Code
	if code == "" {
		log.Warn("Code not provided in request")
		http.Error(w, "code field is empty", http.StatusBadRequest)
		return
	}

	// --- 2) Create a temporary directory ---
	tempDir, err := ioutil.TempDir("", "flutter_project")
	if err != nil {
		log.Error("Failed to create temp dir", zap.Error(err))
		http.Error(w, "failed to create temp dir", http.StatusInternalServerError)
		return
	}
	defer func(path string) {
		if rmErr := os.RemoveAll(path); rmErr != nil {
			log.Error("Failed to remove temp dir", zap.Error(rmErr))
		}
	}(tempDir)

	// --- 3) Copy the Flutter project template ---
	if err := copyDir("./flutter", tempDir); err != nil {
		log.Error("Failed to copy project template", zap.Error(err))
		http.Error(w, "failed to copy project template", http.StatusInternalServerError)
		return
	}
	log.Info("Copied Flutter template", zap.String("tempDir", tempDir))

	// --- 4) Write the code to lib/main.dart ---
	mainDartPath := filepath.Join(tempDir, "lib", "main.dart")
	if err := os.WriteFile(mainDartPath, []byte(code), 0644); err != nil {
		log.Error("Failed to write main.dart", zap.Error(err))
		http.Error(w, "failed to write main.dart", http.StatusInternalServerError)
		return
	}
	log.Info("Wrote code to main.dart")

	// --- 5) Zip the project directory ---
	zipFilePath := tempDir + ".zip"
	if err := zipDir(tempDir, zipFilePath); err != nil {
		log.Error("Failed to create zip file", zap.Error(err))
		http.Error(w, "failed to create zip file", http.StatusInternalServerError)
		return
	}
	log.Info("Zipped directory", zap.String("zipPath", zipFilePath))

	// --- 6) Upload the ZIP to Firebase Storage ---
	firebaseURL, err := uploadToFirebase(zipFilePath)
	if err != nil {
		log.Error("Failed to upload to Firebase", zap.Error(err))
		http.Error(w, "failed to upload to Firebase: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("Uploaded ZIP to Firebase", zap.String("firebaseURL", firebaseURL))

	// --- 7) Trigger GitHub workflow for web build ---
	runID, err := triggerWebBuildWorkflow(firebaseURL)
	if err != nil {
		log.Error("Failed to trigger GitHub workflow", zap.Error(err))
		http.Error(w, "failed to trigger GitHub workflow: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Info("Triggered web build workflow", zap.Int64("runID", runID))

	// --- 8) Poll for build completion and get artifact URL ---
	artifactURL, err := waitForBuildAndGetArtifact(runID)
	if err != nil {
		log.Error("Failed to get build artifact", zap.Error(err))
		http.Error(w, "failed to get build artifact: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// --- 9) Download and send the build files ---
	resp, err := http.Get(artifactURL)
	if err != nil {
		log.Error("Failed to download artifact", zap.Error(err))
		http.Error(w, "failed to download artifact", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=web_build.zip")

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Error("Failed to send build files", zap.Error(err))
		http.Error(w, "failed to send build files", http.StatusInternalServerError)
		return
	}
	log.Info("Successfully sent build files")
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	log := logger.Get()
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Failed walking source directory", zap.String("path", path), zap.Error(err))
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			log.Error("Failed to get relative path", zap.Error(err))
			return err
		}
		destPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		in, err := os.Open(path)
		if err != nil {
			log.Error("Failed to open source file", zap.String("path", path), zap.Error(err))
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, info.Mode())
		if err != nil {
			log.Error("Failed to open destination file", zap.String("path", destPath), zap.Error(err))
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}

// zipDir zips a directory into a target file path.
func zipDir(source, target string) error {
	log := logger.Get()
	zipFile, err := os.Create(target)
	if err != nil {
		log.Error("Failed to create zip file", zap.String("target", target), zap.Error(err))
		return err
	}
	defer func(zipFile *os.File) {
		_ = zipFile.Close()
	}(zipFile)

	archive := zip.NewWriter(zipFile)
	defer func(archive *zip.Writer) {
		if closeErr := archive.Close(); closeErr != nil {
			log.Error("Failed to close zip archive", zap.Error(closeErr))
		}
	}(archive)

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error walking directory for zipping", zap.String("path", path), zap.Error(err))
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			log.Error("Failed to get relative path while zipping", zap.Error(err))
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			log.Error("Failed to open file for zipping", zap.String("path", path), zap.Error(err))
			return err
		}
		defer func(file *os.File) {
			if closeErr := file.Close(); closeErr != nil {
				log.Error("Failed to close file while zipping", zap.Error(closeErr))
			}
		}(file)

		f, err := archive.Create(relPath)
		if err != nil {
			log.Error("Failed to create file in zip archive", zap.String("relPath", relPath), zap.Error(err))
			return err
		}
		_, err = io.Copy(f, file)
		return err
	})
	return err
}

func uploadToFirebase(zipFilePath string) (string, error) {
	log := logger.Get()
	key := []byte(os.Getenv("KEY_ENCRYPT"))
	if len(key) == 0 {
		log.Error("KEY_ENCRYPT environment variable not set")
		return "", fmt.Errorf("KEY_ENCRYPT environment variable not set")
	}

	// Create a temporary file for encryption
	encryptedFile, err := ioutil.TempFile("", "encrypted_*.dat")
	if err != nil {
		log.Error("Failed to create temp file for encryption", zap.Error(err))
		return "", err
	}
	defer os.Remove(encryptedFile.Name())

	// Encrypt the file
	if err := encryptFile(zipFilePath, encryptedFile.Name(), key); err != nil {
		log.Error("Failed to encrypt file", zap.Error(err))
		return "", err
	}

	// Initialize Firebase Storage client
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile("firebase-credentials.json"))
	if err != nil {
		log.Error("Failed to create Firebase client", zap.Error(err))
		return "", err
	}
	defer client.Close()

	// Upload the encrypted file
	bucket := client.Bucket("miniblocks-app.appspot.com")
	obj := bucket.Object(fmt.Sprintf("uploads/%s", filepath.Base(encryptedFile.Name())))
	writer := obj.NewWriter(ctx)
	defer writer.Close()

	file, err := os.Open(encryptedFile.Name())
	if err != nil {
		log.Error("Failed to open encrypted file", zap.Error(err))
		return "", err
	}
	defer file.Close()

	if _, err := io.Copy(writer, file); err != nil {
		log.Error("Failed to upload file to Firebase", zap.Error(err))
		return "", err
	}

	// Get the public URL
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		log.Error("Failed to get object attributes", zap.Error(err))
		return "", err
	}

	log.Info("Successfully uploaded file to Firebase", zap.String("url", attrs.MediaLink))
	return attrs.MediaLink, nil
}

// triggerWorkflowDispatch triggers a GitHub Actions workflow_dispatch event for the "build-and-release.yml" workflow.
// Instead of sending the zip contents, it sends a link in the `zip_url` input.
func triggerWorkflowDispatch(zipURL string) error {
	log := logger.Get()
	payload := map[string]interface{}{
		"ref": "main",
		"inputs": map[string]string{
			"zip_url": zipURL,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Error("Failed to marshal workflow payload", zap.Error(err))
		return err
	}

	req, err := http.NewRequest("POST", "https://api.github.com/repos/miniblocks-app/miniblocks-core/actions/workflows/web-build.yml/dispatches", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error("Failed to create workflow request", zap.Error(err))
		return err
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Error("GITHUB_TOKEN environment variable not set")
		return fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to trigger workflow", zap.Error(err))
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Failed to trigger workflow", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return fmt.Errorf("failed to trigger workflow: %s", resp.Status)
	}

	log.Info("Successfully triggered workflow")
	return nil
}

// decryptFile reads the encrypted file from inFile, decrypts it using AES-GCM,
// and writes the plaintext to outFile.
func decryptFile(inFile, outFile string, key []byte) error {
	log := logger.Get()
	data, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Error("Failed to read encrypted file", zap.Error(err))
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Failed to create cipher", zap.Error(err))
		return err
	}

	if len(data) < aes.BlockSize {
		log.Error("Ciphertext too short")
		return fmt.Errorf("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	if err := ioutil.WriteFile(outFile, data, 0644); err != nil {
		log.Error("Failed to write decrypted file", zap.Error(err))
		return err
	}

	log.Info("Successfully decrypted file", zap.String("outFile", outFile))
	return nil
}

// triggerWebBuildWorkflow triggers a GitHub Actions workflow for web build
func triggerWebBuildWorkflow(zipURL string) (int64, error) {
	log := logger.Get()
	payload := map[string]interface{}{
		"ref": "main",
		"inputs": map[string]string{
			"zip_url": zipURL,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Error("Failed to marshal workflow payload", zap.Error(err))
		return 0, err
	}

	req, err := http.NewRequest("POST", "https://api.github.com/repos/miniblocks-app/miniblocks-core/actions/workflows/web-build.yml/dispatches", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error("Failed to create workflow request", zap.Error(err))
		return 0, err
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Error("GITHUB_TOKEN environment variable not set")
		return 0, fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to trigger workflow", zap.Error(err))
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Failed to trigger workflow", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return 0, fmt.Errorf("failed to trigger workflow: %s", resp.Status)
	}

	// Get the latest workflow run
	req, err = http.NewRequest("GET", "https://api.github.com/repos/miniblocks-app/miniblocks-core/actions/runs", nil)
	if err != nil {
		log.Error("Failed to create runs request", zap.Error(err))
		return 0, err
	}

	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = client.Do(req)
	if err != nil {
		log.Error("Failed to get workflow runs", zap.Error(err))
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Failed to get workflow runs", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return 0, fmt.Errorf("failed to get workflow runs: %s", resp.Status)
	}

	var runs struct {
		WorkflowRuns []struct {
			ID int64 `json:"id"`
		} `json:"workflow_runs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&runs); err != nil {
		log.Error("Failed to decode workflow runs", zap.Error(err))
		return 0, err
	}

	if len(runs.WorkflowRuns) == 0 {
		log.Error("No workflow runs found")
		return 0, fmt.Errorf("no workflow runs found")
	}

	log.Info("Successfully triggered workflow", zap.Int64("runID", runs.WorkflowRuns[0].ID))
	return runs.WorkflowRuns[0].ID, nil
}

// waitForBuildAndGetArtifact polls the GitHub API until the build is complete and returns the artifact URL
func waitForBuildAndGetArtifact(runID int64) (string, error) {
	log := logger.Get()
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Error("GITHUB_TOKEN environment variable not set")
		return "", fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	client := &http.Client{}
	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/miniblocks-app/miniblocks-core/actions/runs/%d", runID), nil)
		if err != nil {
			log.Error("Failed to create run status request", zap.Error(err))
			return "", err
		}

		req.Header.Set("Authorization", "Bearer "+githubToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			log.Error("Failed to get run status", zap.Error(err))
			return "", err
		}

		var run struct {
			Status string `json:"status"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&run); err != nil {
			resp.Body.Close()
			log.Error("Failed to decode run status", zap.Error(err))
			return "", err
		}
		resp.Body.Close()

		if run.Status == "completed" {
			break
		}

		log.Info("Build in progress", zap.String("status", run.Status))
		time.Sleep(10 * time.Second)
	}

	// Get the artifact URL
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.github.com/repos/miniblocks-app/miniblocks-core/actions/runs/%d/artifacts", runID), nil)
	if err != nil {
		log.Error("Failed to create artifacts request", zap.Error(err))
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		log.Error("Failed to get artifacts", zap.Error(err))
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Error("Failed to get artifacts", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return "", fmt.Errorf("failed to get artifacts: %s", resp.Status)
	}

	var artifacts struct {
		Artifacts []struct {
			Name       string `json:"name"`
			ArchiveURL string `json:"archive_download_url"`
		} `json:"artifacts"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
		log.Error("Failed to decode artifacts", zap.Error(err))
		return "", err
	}

	if len(artifacts.Artifacts) == 0 {
		log.Error("No artifacts found")
		return "", fmt.Errorf("no artifacts found")
	}

	log.Info("Successfully retrieved artifact URL", zap.String("url", artifacts.Artifacts[0].ArchiveURL))
	return artifacts.Artifacts[0].ArchiveURL, nil
}

// encryptFile encrypts the contents of inFile using AES-CFB and writes the result to outFile.
func encryptFile(inFile, outFile string, key []byte) error {
	log := logger.Get()
	data, err := ioutil.ReadFile(inFile)
	if err != nil {
		log.Error("Failed to read input file", zap.Error(err))
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error("Failed to create cipher", zap.Error(err))
		return err
	}

	// Create a new CFB encrypter
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error("Failed to generate IV", zap.Error(err))
		return err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	// Write the IV first
	if err := ioutil.WriteFile(outFile, iv, 0644); err != nil {
		log.Error("Failed to write IV", zap.Error(err))
		return err
	}

	// Open the file for appending
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Failed to open output file for appending", zap.Error(err))
		return err
	}
	defer f.Close()

	// Encrypt and write the data
	stream.XORKeyStream(data, data)
	if _, err := f.Write(data); err != nil {
		log.Error("Failed to write encrypted data", zap.Error(err))
		return err
	}

	log.Info("Successfully encrypted file", zap.String("outFile", outFile))
	return nil
}
