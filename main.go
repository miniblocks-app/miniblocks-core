package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

var logger *zap.Logger

func init() {
	logger = zap.Must(zap.NewProduction())
}

func main() {
	defer func() {
		_ = logger.Sync() // Flush any buffered log entries
	}()

	logger.Info("Starting server on :8080")
	http.HandleFunc("/upload", handleUpload)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}

// handleUpload handles the incoming request, writes the user code to main.dart,
// zips the flutter project, and triggers the GitHub workflow.
func handleUpload(w http.ResponseWriter, r *http.Request) {
	// --- 1) Parse JSON ---
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logger.Warn("Invalid JSON body", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	code := payload.Code
	if code == "" {
		logger.Warn("Code not provided in request")
		http.Error(w, "code field is empty", http.StatusBadRequest)
		return
	}

	// --- 2) Create a temporary directory ---
	tempDir, err := ioutil.TempDir("", "flutter_project")
	if err != nil {
		logger.Error("Failed to create temp dir", zap.Error(err))
		http.Error(w, "failed to create temp dir", http.StatusInternalServerError)
		return
	}
	defer func(path string) {
		if rmErr := os.RemoveAll(path); rmErr != nil {
			logger.Error("Failed to remove temp dir", zap.Error(rmErr))
		}
	}(tempDir)

	// --- 3) Copy the Flutter project template ---
	if err := copyDir("./flutter", tempDir); err != nil {
		logger.Error("Failed to copy project template", zap.Error(err))
		http.Error(w, "failed to copy project template", http.StatusInternalServerError)
		return
	}
	logger.Info("Copied Flutter template", zap.String("tempDir", tempDir))

	// --- 4) Write the code to lib/main.dart ---
	mainDartPath := filepath.Join(tempDir, "lib", "main.dart")
	if err := os.WriteFile(mainDartPath, []byte(code), 0644); err != nil {
		logger.Error("Failed to write main.dart", zap.Error(err))
		http.Error(w, "failed to write main.dart", http.StatusInternalServerError)
		return
	}
	logger.Info("Wrote code to main.dart")

	// --- 5) Zip the project directory ---
	zipFilePath := tempDir + ".zip"
	if err := zipDir(tempDir, zipFilePath); err != nil {
		logger.Error("Failed to create zip file", zap.Error(err))
		http.Error(w, "failed to create zip file", http.StatusInternalServerError)
		return
	}
	logger.Info("Zipped directory", zap.String("zipPath", zipFilePath))

	// --- 6) Trigger GitHub workflow ---
	if err := triggerGitHubWorkflow(zipFilePath); err != nil {
		logger.Error("Failed to trigger GitHub workflow", zap.Error(err))
		http.Error(w, "failed to trigger GitHub workflow: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Project successfully processed and GitHub workflow triggered."))
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Failed walking source directory", zap.String("path", path), zap.Error(err))
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			logger.Error("Failed to get relative path", zap.Error(err))
			return err
		}
		destPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		in, err := os.Open(path)
		if err != nil {
			logger.Error("Failed to open source file", zap.String("path", path), zap.Error(err))
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, info.Mode())
		if err != nil {
			logger.Error("Failed to open destination file", zap.String("path", destPath), zap.Error(err))
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}

// zipDir zips a directory into a target file path.
func zipDir(source, target string) error {
	zipFile, err := os.Create(target)
	if err != nil {
		logger.Error("Failed to create zip file", zap.String("target", target), zap.Error(err))
		return err
	}
	defer func(zipFile *os.File) {
		if closeErr := zipFile.Close(); closeErr != nil {
			logger.Error("Failed to close zip file", zap.Error(closeErr))
		}
	}(zipFile)

	archive := zip.NewWriter(zipFile)
	defer func(archive *zip.Writer) {
		if closeErr := archive.Close(); closeErr != nil {
			logger.Error("Failed to close zip archive", zap.Error(closeErr))
		}
	}(archive)

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error walking directory for zipping", zap.String("path", path), zap.Error(err))
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			logger.Error("Failed to get relative path while zipping", zap.Error(err))
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			logger.Error("Failed to open file for zipping", zap.String("path", path), zap.Error(err))
			return err
		}
		defer func(file *os.File) {
			if closeErr := file.Close(); closeErr != nil {
				logger.Error("Failed to close file while zipping", zap.Error(closeErr))
			}
		}(file)

		f, err := archive.Create(relPath)
		if err != nil {
			logger.Error("Failed to create file in zip archive", zap.String("relPath", relPath), zap.Error(err))
			return err
		}
		_, err = io.Copy(f, file)
		return err
	})
	return err
}

// triggerGitHubWorkflow sends a POST request to the GitHub dispatches API with base64-encoded zip data.
func triggerGitHubWorkflow(zipPath string) error {
	data, err := os.ReadFile(zipPath)
	if err != nil {
		logger.Error("Failed to read zip file", zap.String("zipPath", zipPath), zap.Error(err))
		return err
	}
	encodedZip := base64.StdEncoding.EncodeToString(data)

	payload := map[string]interface{}{
		"event_type": "flutter_project_submission",
		"client_payload": map[string]string{
			"zip_data": encodedZip,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal payload for GitHub dispatch", zap.Error(err))
		return err
	}

	url := "https://api.github.com/repos/your-username/your-repo/dispatches"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Error("Failed to create request to GitHub dispatch", zap.Error(err))
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token YOUR_GITHUB_TOKEN")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send request to GitHub dispatch", zap.Error(err))
		return err
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", zap.Error(closeErr))
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Non-2XX status returned by GitHub dispatch", zap.Int("statusCode", resp.StatusCode))
		return fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	logger.Info("Successfully triggered GitHub workflow")
	return nil
}
