// Binary user runs the user (client) HTTP server with web frontend.
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

	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
	"github.com/karolkwiatek1/secure-exchange/node"
)

// AuthUserRequest represents a user authentication request sent to TTP.
type AuthUserRequest struct {
	SessionID             string `json:"session_id"`
	EncryptedUserIDBase64 string `json:"encrypted_user_id_base64"`
	CertificatePEM        string `json:"certificate_pem"`
}

// AuthUserResponse represents a user authentication response from TTP.
type AuthUserResponse struct {
	EncryptedPayloadForUser string `json:"encrypted_payload_for_user"`
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

	// UI API for getting list of files from the server (encrypted flow)
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Request file-list session from Server
		resp1, err := http.Post(serverAddress+"/request-file-list", "application/json", nil)
		if err != nil {
			http.Error(w, "Cannot reach file server", http.StatusBadGateway)
			return
		}
		var initResp struct {
			SessionID string `json:"session_id"`
			ServerID  string `json:"server_id"`
		}
		json.NewDecoder(resp1.Body).Decode(&initResp)
		resp1.Body.Close()

		claimedServerID := initResp.ServerID

		// Step 2: Authenticate at TTP and obtain AES key
		ttpCert, _ := x509.ParseCertificate(userNode.TTPCaCert)
		ttpPubKey := ttpCert.PublicKey.(*rsa.PublicKey)
		encryptedID, _ := crypto.EncryptRSA(ttpPubKey, []byte(userNode.ID))

		authReq := AuthUserRequest{
			SessionID:             initResp.SessionID,
			EncryptedUserIDBase64: base64.StdEncoding.EncodeToString(encryptedID),
			CertificatePEM:        userNode.CertPEM,
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

		encryptedPayload, _ := base64.StdEncoding.DecodeString(authResp.EncryptedPayloadForUser)
		decryptedPayloadBytes, err := crypto.DecryptRSA(userNode.PrivateKey, encryptedPayload)
		if err != nil {
			http.Error(w, "Failed to decrypt TTP payload", http.StatusForbidden)
			return
		}

		var ttpPayload map[string]string
		if err := json.Unmarshal(decryptedPayloadBytes, &ttpPayload); err != nil {
			http.Error(w, "Malformed payload from TTP", http.StatusInternalServerError)
			return
		}

		// Verify server identity
		if ttpPayload["server_id"] != claimedServerID {
			log.Log("FATAL", "SECURITY ALERT: Session belongs to untrusted Server! MITM detected.")
			http.Error(w, "TTP reported invalid Server Identity. Connection aborted.", http.StatusForbidden)
			return
		}

		aesKey, _ := base64.StdEncoding.DecodeString(ttpPayload["aes_key"])

		log.Log("USER", "TTP confirmed Server identity cryptographically.")

		// Step 3: Request encrypted file list from Server
		dlReqBody, _ := json.Marshal(map[string]string{"session_id": initResp.SessionID})
		resp3, err := http.Post(serverAddress+"/list-files-encrypted", "application/json", bytes.NewBuffer(dlReqBody))
		if err != nil {
			http.Error(w, "Cannot reach file server", http.StatusBadGateway)
			return
		}

		var listResp struct {
			EncryptedDataBase64 string `json:"encrypted_data_base64"`
		}
		json.NewDecoder(resp3.Body).Decode(&listResp)
		resp3.Body.Close()

		encryptedData, _ := base64.StdEncoding.DecodeString(listResp.EncryptedDataBase64)
		plaintext, err := crypto.DecryptAES_GCM(aesKey, encryptedData)
		if err != nil {
			http.Error(w, "Data corrupted or MITM attack!", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(plaintext)
	})

	// UI API for simulating MITM attack via proxy
	mux.HandleFunc("/api/test-mitm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		mitmAddress := "http://localhost:9393"

		resp1, err := http.Post(mitmAddress+"/request-file-list", "application/json", nil)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"detail": "Cannot reach MITM proxy on port 9393. Is the proxy running?",
			})
			return
		}
		var initResp struct {
			SessionID string `json:"session_id"`
			ServerID  string `json:"server_id"`
		}
		json.NewDecoder(resp1.Body).Decode(&initResp)
		resp1.Body.Close()

		claimedServerID := initResp.ServerID

		ttpCert, _ := x509.ParseCertificate(userNode.TTPCaCert)
		ttpPubKey := ttpCert.PublicKey.(*rsa.PublicKey)
		encryptedID, _ := crypto.EncryptRSA(ttpPubKey, []byte(userNode.ID))

		authReq := AuthUserRequest{
			SessionID:             initResp.SessionID,
			EncryptedUserIDBase64: base64.StdEncoding.EncodeToString(encryptedID),
			CertificatePEM:        userNode.CertPEM,
		}
		authReqBytes, _ := json.Marshal(authReq)
		resp2, err := http.Post(ttpAddress+"/auth-user", "application/json", bytes.NewBuffer(authReqBytes))
		if err != nil || resp2.StatusCode != http.StatusOK {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"detail": "TTP auth failed during MITM test",
			})
			return
		}

		var authResp AuthUserResponse
		json.NewDecoder(resp2.Body).Decode(&authResp)
		resp2.Body.Close()

		encryptedPayload, _ := base64.StdEncoding.DecodeString(authResp.EncryptedPayloadForUser)
		decryptedPayloadBytes, err := crypto.DecryptRSA(userNode.PrivateKey, encryptedPayload)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"detail": "Failed to decrypt TTP payload in MITM test",
			})
			return
		}

		var ttpPayload map[string]string
		if err := json.Unmarshal(decryptedPayloadBytes, &ttpPayload); err != nil {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"detail": "Malformed TTP payload in MITM test",
			})
			return
		}

		if ttpPayload["server_id"] != claimedServerID {
			log.Log("USER", "MITM TEST: Attack correctly detected and blocked!")
			json.NewEncoder(w).Encode(map[string]string{
				"status":            "attack_blocked",
				"detail":            fmt.Sprintf("MITM wykryty i zablokowany! TTP potwierdza prawdziwy serwer, a proxy próbowało podszyć się jako '%s'", claimedServerID[:16]+"..."),
				"ttp_server_id":     ttpPayload["server_id"][:16] + "...",
				"claimed_server_id": claimedServerID[:16] + "...",
			})
			return
		}

		log.Log("USER", "MITM TEST WARNING: Attack NOT detected - system may be vulnerable!")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "vulnerable",
			"detail": "UWAGA: MITM nie został wykryty – system może być podatny na atak!",
		})
	})

	// UI API for simulating forged certificate attack
	mux.HandleFunc("/api/test-forged-cert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if userNode.TTPCaCert == nil || userNode.CertPEM == "" {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error", "detail": "User not registered at TTP. Register first.",
			})
			return
		}

		resp1, err := http.Post(serverAddress+"/request-file-list", "application/json", nil)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error", "detail": "Cannot reach server",
			})
			return
		}
		var initResp struct {
			SessionID string `json:"session_id"`
			ServerID  string `json:"server_id"`
		}
		json.NewDecoder(resp1.Body).Decode(&initResp)
		resp1.Body.Close()

		ttpCert, _ := x509.ParseCertificate(userNode.TTPCaCert)
		ttpPubKey := ttpCert.PublicKey.(*rsa.PublicKey)
		encryptedID, _ := crypto.EncryptRSA(ttpPubKey, []byte(userNode.ID))

		forgedKey, _ := crypto.GenerateRSAKeys()
		forgedCertBytes, _ := crypto.GenerateRootCA(forgedKey, "FAKE_EVIL_USER")
		forgedCertPEM := crypto.CertToPEM(forgedCertBytes)

		authReq := AuthUserRequest{
			SessionID:             initResp.SessionID,
			EncryptedUserIDBase64: base64.StdEncoding.EncodeToString(encryptedID),
			CertificatePEM:        forgedCertPEM,
		}
		authReqBytes, _ := json.Marshal(authReq)
		resp2, err := http.Post(ttpAddress+"/auth-user", "application/json", bytes.NewBuffer(authReqBytes))
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{
				"status": "error", "detail": "TTP unreachable",
			})
			return
		}

		if resp2.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			log.Log("USER", "FORGED CERT TEST: Attack correctly blocked by TTP!")
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "attack_blocked",
				"detail":  fmt.Sprintf("TTP odrzucił fałszywy certyfikat: %s", string(body)),
			})
			return
		}
		resp2.Body.Close()

		log.Log("USER", "FORGED CERT TEST WARNING: TTP accepted forged certificate!")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "vulnerable",
			"detail": "UWAGA: TTP zaakceptował fałszywy certyfikat!",
		})
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
			ServerID  string `json:"server_id"`
		}
		json.NewDecoder(resp1.Body).Decode(&initResp)
		resp1.Body.Close()

		// Store server claimed identity
		claimedServerID := initResp.ServerID

		// Authentication at TTP and obtaining AES key
		ttpCert, _ := x509.ParseCertificate(userNode.TTPCaCert)
		ttpPubKey := ttpCert.PublicKey.(*rsa.PublicKey)
		encryptedID, _ := crypto.EncryptRSA(ttpPubKey, []byte(userNode.ID))

		authReq := AuthUserRequest{
			SessionID:             initResp.SessionID,
			EncryptedUserIDBase64: base64.StdEncoding.EncodeToString(encryptedID),
			CertificatePEM:        userNode.CertPEM,
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

		encryptedPayload, _ := base64.StdEncoding.DecodeString(authResp.EncryptedPayloadForUser)
		decryptedPayloadBytes, err := crypto.DecryptRSA(userNode.PrivateKey, encryptedPayload)
		if err != nil {
			http.Error(w, "Failed to decrypt TTP payload", http.StatusForbidden)
			return
		}

		var ttpPayload map[string]string
		if err := json.Unmarshal(decryptedPayloadBytes, &ttpPayload); err != nil {
			http.Error(w, "Malformed payload from TTP", http.StatusInternalServerError)
			return
		}

		// Check if ServerID returned by TTP is the same as one returned by server
		if ttpPayload["server_id"] != claimedServerID {
			log.Log("FATAL", "SECURITY ALERT: Session belongs to untrusted Server! MITM detected.")
			http.Error(w, "TTP reported invalid Server Identity. Connection aborted.", http.StatusForbidden)
			return
		}

		aesKey, _ := base64.StdEncoding.DecodeString(ttpPayload["aes_key"])

		log.Log("USER", "TTP confirmed Server identity cryptographically.")

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
