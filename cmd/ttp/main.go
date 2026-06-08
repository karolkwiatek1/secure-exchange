// Binary ttp runs the Trusted Third Party HTTP server.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
	"github.com/karolkwiatek1/secure-exchange/ttp"
)

// AuthServerRequest represents a server authentication request.
type AuthServerRequest struct {
	ServerID      string `json:"server_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// AuthServerResponse represents a server authentication response.
type AuthServerResponse struct {
	SessionID string `json:"session_id"`
}

// AuthUserRequest represents a user authentication request.
type AuthUserRequest struct {
	SessionID             string `json:"session_id"`
	EncryptedUserIDBase64 string `json:"encrypted_user_id_base64"`
	CertificatePEM        string `json:"certificate_pem"`
}

// AuthUserResponse represents a user authentication response.
type AuthUserResponse struct {
	EncryptedPayloadForUser string `json:"encrypted_payload_for_user"`
}

// FetchKeyRequest represents a request to fetch an encrypted session key.
type FetchKeyRequest struct {
	SessionID string `json:"session_id"`
	ServerID  string `json:"server_id"`
}

// FetchKeyResponse represents a response containing the encrypted AES key.
type FetchKeyResponse struct {
	EncryptedAESForServerBase64 string `json:"encrypted_aes_for_server_base64"`
}

// RegisterRequest represents an entity registration request.
type RegisterRequest struct {
	EncryptedIDBase64 string `json:"encrypted_id_base64"`
	PublicKeyPEM      string `json:"public_key_pem"`
}

// RegisterResponse represents an entity registration response.
type RegisterResponse struct {
	CertificatePEM string `json:"certificate_pem"`
}

// CAResponse represents the CA certificate response.
type CAResponse struct {
	CACertificatePEM string `json:"ca_certificate_pem"`
}

// setupRouter configures the HTTP multiplexer with all TTP endpoints.
func setupRouter(service *ttp.Service, log *logger.EventLogger) *http.ServeMux {
	mux := http.NewServeMux()

	// Endpoint: Provide the Root CA certificate
	mux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		caPEM := crypto.CertToPEM(service.GetCACert())
		response := CAResponse{CACertificatePEM: caPEM}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		if !strings.Contains(r.Header.Get("User-Agent"), "Wget") {
			log.Log("HTTP_SERVER", fmt.Sprintf("Server Root CA certificate to %s", r.RemoteAddr))
		}
	})

	// Endpoint: Register User/Server
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request payload", http.StatusBadRequest)
			return
		}

		// decoding from base 64 to raw encrypted bytes
		encryptedID, err := base64.StdEncoding.DecodeString(req.EncryptedIDBase64)
		if err != nil {
			http.Error(w, "Invalid Base64 ID", http.StatusBadRequest)
			return
		}

		pubKey, err := crypto.PEMToPublicKey(req.PublicKeyPEM)
		if err != nil {
			http.Error(w, "Invalid public key format", http.StatusBadRequest)
		}

		certBytes, err := service.RegisterEntity(encryptedID, pubKey)
		if err != nil {
			http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
			return
		}

		response := RegisterResponse{
			CertificatePEM: crypto.CertToPEM(certBytes),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Endpoint: Authenticate server
	mux.HandleFunc("/auth-server", func(w http.ResponseWriter, r *http.Request) {
		var req AuthServerRequest
		json.NewDecoder(r.Body).Decode(&req)

		sessionID, err := service.InitServerAuth(req.ServerID, req.CertificatePEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(AuthServerResponse{SessionID: sessionID})
	})

	// Endpoint: Authenticate user
	mux.HandleFunc("/auth-user", func(w http.ResponseWriter, r *http.Request) {
		var req AuthUserRequest
		json.NewDecoder(r.Body).Decode(&req)

		encryptedUserID, _ := base64.StdEncoding.DecodeString(req.EncryptedUserIDBase64)

		userPayload, err := service.AuthUserAndGenerateKey(req.SessionID, encryptedUserID, req.CertificatePEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(AuthUserResponse{
			EncryptedPayloadForUser: base64.StdEncoding.EncodeToString(userPayload),
		})
	})

	// Endpoint: Fetch key by a server
	mux.HandleFunc("/fetch-key", func(w http.ResponseWriter, r *http.Request) {
		var req FetchKeyRequest
		json.NewDecoder(r.Body).Decode(&req)

		serverAES, err := service.FetchServiceKey(req.SessionID, req.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(FetchKeyResponse{
			EncryptedAESForServerBase64: base64.StdEncoding.EncodeToString(serverAES),
		})
	})

	return mux
}

func main() {
	log := logger.New(os.Stdout)
	if err := log.EnableFileLogging("logs/ttp.log"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not enable file logging: %v\n", err)
	}
	defer log.Close()

	log.Log("SYSTEM", "Booting up TTP node...")

	service, err := ttp.NewService(log)
	if err != nil {
		log.Log("FATAL", fmt.Sprintf("Failed to initalize TTP service: %v", err))
		os.Exit(1)
	}

	// Initalize router
	mux := setupRouter(service, log)

	port := ":8181"
	log.Log("HTTP_SERVER", "Listening for incoming connections on port "+port)

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Log("FATAL", fmt.Sprintf("Server failed: %v", err))
		os.Exit(1)
	}
}
