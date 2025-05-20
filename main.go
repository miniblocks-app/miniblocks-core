package main

import (
	"archive/zip"
	"bytes"
	"cloud.google.com/go/storage"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"google.golang.org/api/option"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/miniblocks-app/miniblocks-core/db"
	"github.com/miniblocks-app/miniblocks-core/handlers"
	"github.com/miniblocks-app/miniblocks-core/middleware"
)

var logger *zap.Logger

func init() {
	logger = zap.Must(zap.NewProduction())
}

func main() {
	defer func() {
		_ = logger.Sync() // Flush any buffered log entries
	}()

	// Connect to MongoDB
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb+srv://mrmihiraj:miniblocks@core-cluster.bnpvs.mongodb.net/?retryWrites=true&w=majority&appName=core-cluster"
	}
	if err := db.Connect(mongoURI); err != nil {
		logger.Fatal("Failed to connect to MongoDB", zap.Error(err))
	}
	defer func() {
		err := db.Disconnect()
		if err != nil {
			logger.Error("Failed to disconnect from MongoDB", zap.Error(err))
		}
	}()

	// Initialize handlers
	userHandler := handlers.NewUserHandler(logger)

	// Setup routes
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/register", corsMiddleware(userHandler.Register))
	mux.HandleFunc("/api/login", corsMiddleware(userHandler.Login))

	// Protected routes
	mux.HandleFunc("/api/profile", corsMiddleware(middleware.AuthMiddleware(userHandler.GetProfile)))
	mux.HandleFunc("/api/profile/update", corsMiddleware(middleware.AuthMiddleware(userHandler.UpdateProfile)))
	mux.HandleFunc("/upload", corsMiddleware(middleware.AuthMiddleware(handleUpload)))

	logger.Info("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}

// handleUpload handles the incoming request, writes the user code to main.dart,
// zips the Flutter project, uploads it to Firebase Storage, and triggers the GitHub Actions workflow.
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

	// --- 6) Upload the ZIP to Firebase Storage ---
	firebaseURL, err := uploadToFirebase(zipFilePath)
	if err != nil {
		logger.Error("Failed to upload to Firebase", zap.Error(err))
		http.Error(w, "failed to upload to Firebase: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Info("Uploaded ZIP to Firebase", zap.String("firebaseURL", firebaseURL))

	// --- 7) Trigger GitHub workflow via workflow_dispatch ---
	if err := triggerWorkflowDispatch(firebaseURL); err != nil {
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

func uploadToFirebase(zipFilePath string) (string, error) {

	key := []byte(os.Getenv("KEY_ENCRYPT"))

	fmt.Println("File encrypted to encrypted.dat")

	// Decrypt encrypted.dat -> decrypted.txt
	if err := decryptFile("mini.dat", "mini.json", key); err != nil {
		fmt.Println("Decryption failed:", err)
		return "", err
	}

	bucketName := "miniblocks-ecd95.firebasestorage.app"
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile("mini.json"))
	if err != nil {
		return "", fmt.Errorf("failed to create storage client: %w", err)
	}
	defer client.Close()

	f, err := os.Open(zipFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open zip file for reading: %w", err)
	}
	defer f.Close()

	objectName := fmt.Sprintf("%d.zip", time.Now().UnixNano())

	wc := client.Bucket(bucketName).Object(objectName).NewWriter(ctx)
	wc.ACL = []storage.ACLRule{{Entity: storage.AllUsers, Role: storage.RoleReader}}
	wc.Metadata = map[string]string{
		"firebaseStorageDownloadTokens": "", // Empty token makes it public
	}
	if _, err = io.Copy(wc, f); err != nil {
		return "", fmt.Errorf("failed to write zip to bucket: %w", err)
	}
	if err := wc.Close(); err != nil {
		return "", fmt.Errorf("failed to close writer: %w", err)
	}

	// Firebase Storage download URL format
	publicURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media",
		bucketName,
		url.PathEscape(objectName))

	logger.Info(fmt.Sprintf("Uploaded %s to %s", zipFilePath, publicURL))
	return publicURL, nil
}

// triggerWorkflowDispatch triggers a GitHub Actions workflow_dispatch event for the "build-and-release.yml" workflow.
// Instead of sending the zip contents, it sends a link in the `zip_url` input.
func triggerWorkflowDispatch(zipURL string) error {
	// "ref" must be a valid branch or tag in your repo, e.g., "main"
	payload := map[string]interface{}{
		"ref": "main",
		"inputs": map[string]string{
			"code_zip_url": zipURL, // Pass the Firebase (signed) URL to your GitHub Actions workflow
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal payload for workflow dispatch", zap.Error(err))
		return err
	}

	url := "https://api.github.com/repos/miniblocks-app/compiler/actions/workflows/125375079/dispatches"

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Error("Failed to create request to GitHub workflow dispatch", zap.Error(err))
		return err
	}

	// Optional: debug logging of request
	dump, _ := httputil.DumpRequest(req, true)
	logger.Info("Workflow Dispatch Request", zap.String("dump", string(dump)))

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+githubToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send request to GitHub workflow dispatch", zap.Error(err))
		if resp != nil {
			logger.Error("Response from GitHub", zap.Any("resp", resp))
		}
		return err
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			logger.Error("Failed to close response body", zap.Error(closeErr))
		}
	}(resp.Body)

	// GitHub returns 204 No Content on a successful dispatch.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Non-2XX status returned by GitHub workflow dispatch", zap.Int("statusCode", resp.StatusCode))
		return fmt.Errorf("GitHub API returned status: %s", resp.Status)
	}

	logger.Info("Successfully triggered GitHub workflow via workflow_dispatch")
	return nil
}

// decryptFile reads the encrypted file from inFile, decrypts it using AES-GCM,
// and writes the plaintext to outFile.
func decryptFile(inFile, outFile string, key []byte) error {
	// Read the encrypted data.
	data, err := ioutil.ReadFile(inFile)
	if err != nil {
		return err
	}

	// Create a new AES cipher block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Wrap the block in GCM mode.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	// Split the nonce and the ciphertext.
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the data.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write the decrypted plaintext to the output file.
	return ioutil.WriteFile(outFile, plaintext, 0644)
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set the CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// If this is a preflight (OPTIONS) request, then respond OK and return
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Otherwise, call the next handler
		next.ServeHTTP(w, r)
	}
}
