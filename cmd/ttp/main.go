package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"secure-exchange/crypto"
	"secure-exchange/logger"
	"secure-exchange/ttp"
)

type RegisterRequest struct {
	EncryptedIDBase64 string `json:"encrypted_id_base64"`
	PublicKeyPEM      string `json:"public_key_pem"`
}

type RegisterResponse struct {
	CertificatePEM string `json:"certificate_pem"`
}

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

		log.Log("HTTP_SERVER", fmt.Sprintf("Server Root CA certificate to %s", r.RemoteAddr))
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

	return mux
}

func main() {
	log := logger.New(os.Stdout)
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
