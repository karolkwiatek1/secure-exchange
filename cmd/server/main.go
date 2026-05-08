package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"secure-exchange/crypto"
	"secure-exchange/logger"
	"secure-exchange/node"
)

// Structs for User <-> Server communication
type InitResponse struct {
	SessionID string `json:"session_id"`
	ServerID  string `json:"server_id"`
	Message   string `json:"message"`
}
type DownloadRequest struct {
	SessionID string `json:"session_id"`
	Filename  string `json:"filename"`
}
type DownloadResponse struct {
	EncryptedDataBase64 string `json:"encrypted_data_base64"`
}

func setupRouter(node *node.Node, log *logger.EventLogger) *http.ServeMux {
	mux := http.NewServeMux()

	// User asks for resource
	mux.HandleFunc("/request-file", func(w http.ResponseWriter, r *http.Request) {
		log.Log("HTTP_SERVER", "Received initial file request from User: "+r.RemoteAddr)

		// Server asks TTP for a new session
		sessionID, err := node.InitSession()
		if err != nil {
			http.Error(w, "Failed to initialize session with TTP", http.StatusInternalServerError)
			return
		}

		// Server returns SessionID to the User
		response := InitResponse{
			SessionID: sessionID,
			ServerID:  node.ID,
			Message:   "Session initialzied. Please authenticate at TTP with this SessionID",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// User asks for file list
	mux.HandleFunc("/request-file-list", func(w http.ResponseWriter, r *http.Request) {
		log.Log("HTTP_SERVER", "Received file list request from User: "+r.RemoteAddr)

		sessionID, err := node.InitSession()
		if err != nil {
			http.Error(w, "Failed to initialize session with TTP", http.StatusInternalServerError)
			return
		}

		response := InitResponse{
			SessionID: sessionID,
			ServerID:  node.ID,
			Message:   "Session initialized for file listing. Please authenticate at TTP.",
		}

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

		log.Log("HTTP_SERVER", "User returned to download file using Session: "+req.SessionID[:8]+"...")

		// Server tries to fetch AES key from TTP
		aesKey, err := node.FetchSessionKey(req.SessionID)
		if err != nil {
			log.Log("HTTP_SERVER", "Download rejected: User not authenticated at TTP")
			http.Error(w, "Unauthorized or session invalid", http.StatusForbidden)
			return
		}

		safeFilename := filepath.Base(req.Filename)
		filePath := filepath.Join(".", "shared_files", safeFilename)

		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			log.Log("HTTP_SERVER", "File not found: "+safeFilename)
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		log.Log("HTTP_SERVER", "Encrypting file data with AES-256-GCM...")
		encryptedData, err := crypto.EncryptAES_GCM(aesKey, fileContent)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		response := DownloadResponse{
			EncryptedDataBase64: base64.StdEncoding.EncodeToString(encryptedData),
		}

		log.Log("HTTP_SERVER", "Sending encrypted data to User")
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

		log.Log("HTTP_SERVER", "User requested encrypted file list using Session: "+req.SessionID[:8]+"...")

		aesKey, err := node.FetchSessionKey(req.SessionID)
		if err != nil {
			log.Log("HTTP_SERVER", "File list request rejected: User not authenticated at TTP")
			http.Error(w, "Unauthorized or session invalid", http.StatusForbidden)
			return
		}

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

		fileListJSON, _ := json.Marshal(fileNames)

		log.Log("HTTP_SERVER", "Encrypting file list with AES-256-GCM...")
		encryptedData, err := crypto.EncryptAES_GCM(aesKey, fileListJSON)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		response := DownloadResponse{
			EncryptedDataBase64: base64.StdEncoding.EncodeToString(encryptedData),
		}

		log.Log("HTTP_SERVER", "Sending encrypted file list to User")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	return mux
}

func main() {
	log := logger.New(os.Stdout)
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
