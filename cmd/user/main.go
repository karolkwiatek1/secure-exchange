package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"secure-exchange/crypto"
	"secure-exchange/logger"
	"secure-exchange/node"
)

type AuthUserRequest struct {
	SessionID             string `json:"session_id"`
	EncryptedUserIDBase64 string `json:"encrypted_user_id_base64"`
}
type AuthUserResponse struct {
	EncryptedAESForUserBase64 string `json:"encrypted_aes_for_user_base64"`
}

func setupRouter(userNode *node.Node, log *logger.EventLogger, ttpAddress, serverAddress string) *http.ServeMux {
	mux := http.NewServeMux()

	// Serving html/css/js files from './static' folder
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// UI API for registering at TTP
	mux.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check if user is already registered
		if userNode.CertPEM != "" {
			json.NewEncoder(w).Encode(map[string]string{"status": "already_registered"})
			return
		}

		// Register and obtain certificate
		if err := userNode.RegisterAtTTP(); err != nil {
			log.Log("FATAL", fmt.Sprintf("Registration at TTP failed. Maybe check if TTP is running? Error: %v", err.Error()))
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	})

	// UI API for getting list of files from the server
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(serverAddress + "/list-files")
		if err != nil {
			http.Error(w, "Cannot reach file server", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, resp.Body)
	})

	// UI API for initalizing safe download
	mux.HandleFunc("/api/download", func(w http.ResponseWriter, r *http.Request) {
		targetFilename := r.URL.Query().Get("file")
		if targetFilename == "" {
			http.Error(w, "Missing file parameter", http.StatusBadRequest)
			return
		}

		// Initializing session with a server
		reqBody, _ := json.Marshal(map[string]string{"filename": targetFilename})
		resp1, err := http.Post(serverAddress+"/request-file", "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			http.Error(w, "Failed to contact Server", http.StatusInternalServerError)
			return
		}
		var initResp struct {
			SessionID string `json:"session_id"`
		}
		json.NewDecoder(resp1.Body).Decode(&initResp)
		resp1.Body.Close()

		// Authentication at TTP and obtaining AES key
		ttpCert, _ := x509.ParseCertificate(userNode.TTPCaCert)
		ttpPubKey := ttpCert.PublicKey.(*rsa.PublicKey)
		encryptedID, _ := crypto.EncryptRSA(ttpPubKey, []byte(userNode.ID))

		authReq := AuthUserRequest{
			SessionID:             initResp.SessionID,
			EncryptedUserIDBase64: base64.StdEncoding.EncodeToString(encryptedID),
		}
		authReqBytes, _ := json.Marshal(authReq)
		resp2, _ := http.Post(ttpAddress+"/auth-user", "application/json", bytes.NewBuffer(authReqBytes))

		if resp2.StatusCode != http.StatusOK {
			http.Error(w, "TTP Authentication Failed", http.StatusForbidden)
			return
		}

		var authResp AuthUserResponse
		json.NewDecoder(resp2.Body).Decode(&authResp)
		resp2.Body.Close()

		encryptedAES, _ := base64.StdEncoding.DecodeString(authResp.EncryptedAESForUserBase64)
		aesKey, _ := crypto.DecryptRSA(userNode.PrivateKey, encryptedAES)

		// Downloading encrypted file
		dlReqBody, _ := json.Marshal(map[string]string{
			"session_id": initResp.SessionID,
			"filename":   targetFilename,
		})
		resp3, _ := http.Post(serverAddress+"/download-file", "application/json", bytes.NewBuffer(dlReqBody))

		var dlResp struct {
			EncryptedDataBase64 string `json:"encrypted_data_base64"`
		}
		json.NewDecoder(resp3.Body).Decode(&dlResp)
		resp3.Body.Close()

		// Decrypting file and saving it disk
		encryptedData, _ := base64.StdEncoding.DecodeString(dlResp.EncryptedDataBase64)
		plaintext, err := crypto.DecryptAES_GCM(aesKey, encryptedData)
		if err != nil {
			http.Error(w, "Data corrupted or MITM attack!", http.StatusInternalServerError)
			return
		}

		savePath := filepath.Join(".", "downloads", targetFilename)
		os.WriteFile(savePath, plaintext, 0644)

		log.Log("USER", "FILE SECURELY SAVED TO: "+savePath)

		// Zwracamy odpowiedź sukcesu do przeglądarki
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "path": savePath})
	})

	return mux
}

func main() {
	log := logger.New(os.Stdout)
	log.Log("SYSTEM", "Booting up User Web UI Node...")

	ttpAddress := "http://localhost:8181"
	serverAddress := "http://localhost:8282"

	userNode, err := node.NewNode("Client_PC_1", node.TypeUser, ttpAddress, log)
	if err != nil {
		os.Exit(1)
	}

	os.MkdirAll("./downloads", os.ModePerm)

	mux := setupRouter(userNode, log, ttpAddress, serverAddress)

	log.Log("HTTP_SERVER", "User Web UI is running on http://localhost:9000")
	http.ListenAndServe(":9000", mux)
}
