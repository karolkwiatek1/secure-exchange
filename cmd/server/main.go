// Binary server runs the file server that serves encrypted files to users.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
	"github.com/karolkwiatek1/secure-exchange/node"
)

// InitResponse represents the initial session response sent to the user.
type InitResponse struct {
	SessionID string `json:"session_id"`
	ServerID  string `json:"server_id"`
	Message   string `json:"message"`
}

// DownloadRequest represents a file download request from the user.
type DownloadRequest struct {
	SessionID string `json:"session_id"`
	Filename  string `json:"filename"`
}

// DownloadResponse represents an encrypted file download response.
type DownloadResponse struct {
	EncryptedDataBase64 string `json:"encrypted_data_base64"`
}

func setupRouter(node *node.Node, log *logger.EventLogger) *http.ServeMux {
	mux := http.NewServeMux()

	// User asks for resource
	mux.HandleFunc("/request-file", func(w http.ResponseWriter, r *http.Request) {
		log.Log("SERVER", fmt.Sprintf(">>> /request-file from %s", r.RemoteAddr))

		sessionID, err := node.InitSession()
		if err != nil {
			log.Log("SERVER", fmt.Sprintf("ERROR: Failed to init session: %v", err))
			http.Error(w, "Failed to initialize session with TTP", http.StatusInternalServerError)
			return
		}

		response := InitResponse{
			SessionID: sessionID,
			ServerID:  node.ID,
			Message:   "Session initialzied. Please authenticate at TTP with this SessionID",
		}

		log.Log("SERVER", fmt.Sprintf("<<< Returning session %s..., server_id=%s...", sessionID[:8], node.ID[:8]))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// User asks for file list
	mux.HandleFunc("/request-file-list", func(w http.ResponseWriter, r *http.Request) {
		log.Log("SERVER", fmt.Sprintf(">>> /request-file-list from %s", r.RemoteAddr))

		sessionID, err := node.InitSession()
		if err != nil {
			log.Log("SERVER", fmt.Sprintf("ERROR: Failed to init session: %v", err))
			http.Error(w, "Failed to initialize session with TTP", http.StatusInternalServerError)
			return
		}

		response := InitResponse{
			SessionID: sessionID,
			ServerID:  node.ID,
			Message:   "Session initialized for file listing. Please authenticate at TTP.",
		}

		log.Log("SERVER", fmt.Sprintf("<<< Returning session %s..., server_id=%s...", sessionID[:8], node.ID[:8]))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// User comes back for resource after authentication
	mux.HandleFunc("/download-file", func(w http.ResponseWriter, r *http.Request) {
		var req DownloadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		log.Log("SERVER", fmt.Sprintf(">>> /download-file file=%s session=%s...", req.Filename, req.SessionID[:8]))

		log.Log("SERVER", "[DOWNLOAD] Step 1/4: Fetching AES session key from TTP...")
		aesKey, err := node.FetchSessionKey(req.SessionID)
		if err != nil {
			log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] REJECTED: %v", err))
			http.Error(w, "Unauthorized or session invalid", http.StatusForbidden)
			return
		}

		safeFilename := filepath.Base(req.Filename)
		log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] Step 2/4: Reading file from disk: shared_files/%s", safeFilename))
		filePath := filepath.Join(".", "shared_files", safeFilename)

		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] ERROR: file not found: %s", safeFilename))
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] File read: %d bytes", len(fileContent)))

		log.Log("SERVER", "[DOWNLOAD] Step 3/4: Encrypting file with AES-256-GCM...")
		encryptedData, err := crypto.EncryptAES_GCM(aesKey, fileContent)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] Encrypted: %d -> %d bytes (AES-256-GCM)", len(fileContent), len(encryptedData)))

		response := DownloadResponse{
			EncryptedDataBase64: base64.StdEncoding.EncodeToString(encryptedData),
		}

		log.Log("SERVER", fmt.Sprintf("[DOWNLOAD] Step 4/4: Sending encrypted data (%d bytes base64)", len(response.EncryptedDataBase64)))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// User requests encrypted file list after authentication
	mux.HandleFunc("/list-files-encrypted", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		log.Log("SERVER", fmt.Sprintf(">>> /list-files-encrypted session=%s...", req.SessionID[:8]))

		log.Log("SERVER", "[LIST] Step 1/3: Fetching AES session key from TTP...")
		aesKey, err := node.FetchSessionKey(req.SessionID)
		if err != nil {
			log.Log("SERVER", fmt.Sprintf("[LIST] REJECTED: %v", err))
			http.Error(w, "Unauthorized or session invalid", http.StatusForbidden)
			return
		}

		log.Log("SERVER", "[LIST] Step 2/3: Reading shared_files/ directory...")
		files, err := os.ReadDir("./shared_files")
		if err != nil {
			http.Error(w, "Unable to read directory", http.StatusInternalServerError)
			return
		}

		var fileNames []string
		for _, file := range files {
			if !file.IsDir() {
				fileNames = append(fileNames, file.Name())
			}
		}
		log.Log("SERVER", fmt.Sprintf("[LIST] Found %d files: %v", len(fileNames), fileNames))

		fileListJSON, _ := json.Marshal(fileNames)

		log.Log("SERVER", "[LIST] Step 3/3: Encrypting file list with AES-256-GCM...")
		encryptedData, err := crypto.EncryptAES_GCM(aesKey, fileListJSON)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		log.Log("SERVER", fmt.Sprintf("[LIST] Encrypted: %d -> %d bytes, sending to User", len(fileListJSON), len(encryptedData)))

		response := DownloadResponse{
			EncryptedDataBase64: base64.StdEncoding.EncodeToString(encryptedData),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	return mux
}

func main() {
	log := logger.New(os.Stdout)
	if err := log.EnableFileLogging("logs/server.log"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not enable file logging: %v\n", err)
	}
	defer log.Close()

	log.Log("SYSTEM", "Booting up File Server Node...")

	ttpAddress := os.Getenv("TTP_ADDRESS")
	if ttpAddress == "" {
		ttpAddress = "http://localhost:8181"
	}

	// Initialize the Server Node
	serverNode, err := node.NewNode("Secure_File_Server", node.TypeServer, ttpAddress, log)

	if err != nil {
		log.Log("FATAL", fmt.Sprintf("Failed to initialize server node: %v", err))
		os.Exit(1)
	}

	// Register and obtain certificate
	err = serverNode.RegisterAtTTP()
	if err != nil {
		log.Log("FATAL", fmt.Sprintf("Registration at TTP failed. Maybe check if TTP is running? Error: %v", err))
		os.Exit(1)
	}

	os.MkdirAll("./shared_files", os.ModePerm)

	// Setup HTTP server for incoming requests
	mux := setupRouter(serverNode, log)

	// Start listening
	port := ":8282"
	log.Log("HTTP_SERVER", "File Server ready and listening on port "+port)

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Log("FATAL", fmt.Sprintf("Server crashed: %v", err))
		os.Exit(1)
	}
}
