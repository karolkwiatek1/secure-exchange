package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
	"github.com/karolkwiatek1/secure-exchange/ttp"
)

// setupTestEnvironment initializes the router and service for testing.
func setupTestEnvironment(t *testing.T) (*http.ServeMux, *ttp.Service) {
	var buf bytes.Buffer
	testLogger := logger.New(&buf) // Suppress logs in console during tests

	service, err := ttp.NewService(testLogger)
	if err != nil {
		t.Fatalf("Failed to start TTP service for testing: %v", err)
	}

	mux := setupRouter(service, testLogger)
	return mux, service
}

// TestCAEndpoint tests the GET /ca endpoint.
func TestCAEndpoint(t *testing.T) {
	mux, _ := setupTestEnvironment(t)

	// Create an HTTP GET request to /ca
	req := httptest.NewRequest(http.MethodGet, "/ca", nil)
	// Create a ResponseRecorder to record the response
	rr := httptest.NewRecorder()

	// Serve the HTTP request
	mux.ServeHTTP(rr, req)

	// 1. Check status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// 2. Parse JSON response
	var response CAResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// 3. Verify content
	if !strings.Contains(response.CACertificatePEM, "BEGIN CERTIFICATE") {
		t.Error("Response does not contain a valid PEM certificate structure")
	}
}

// TestRegisterEndpoint_MethodNotAllowed tests that GET /register returns 405.
func TestRegisterEndpoint_MethodNotAllowed(t *testing.T) {
	mux, _ := setupTestEnvironment(t)

	// Send GET instead of POST
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %v", status)
	}
}

// TestRegisterEndpoint_Success tests the full POST /register flow.
func TestRegisterEndpoint_Success(t *testing.T) {
	mux, service := setupTestEnvironment(t)

	// 1. Generate client keys to simulate a real payload
	privKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Failed to generate test RSA keys: %v", err)
	}

	pubKeyPEM, err := crypto.PublicKeyToPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	// 2. Obtaining TTP public key from CA certificate
	caCertBytes := service.GetCACert()
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse TTP CA certificate: %v", err)
	}
	ttpPubKey, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("TTP public key is not of type RSA")
	}

	// 3. Encrypting ID with TTP public key and encoding to Base64
	rawID := "Test_User_HTTP"
	encryptedID, err := crypto.EncryptRSA(ttpPubKey, []byte(rawID))
	if err != nil {
		t.Fatalf("Failed to encrypt ID: %v", err)
	}
	encryptedIDBase64 := base64.StdEncoding.EncodeToString(encryptedID)

	// 4. Prepare JSON payload

	reqData := RegisterRequest{
		EncryptedIDBase64: encryptedIDBase64,
		PublicKeyPEM:      pubKeyPEM,
	}

	reqBytes, _ := json.Marshal(reqData)

	// 5. Send POST request
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	// 6. Verify HTTP Status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected 200 OK, got %v. Body: %s", status, rr.Body.String())
	}

	// 7. Decode response
	var response RegisterResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response JSON: %v", err)
	}

	if response.CertificatePEM == "" {
		t.Fatal("Received empty certificate PEM string")
	}

	// 8. Verify the issued certificate cryptographically using the service's CA
	issuedCertBytes, err := crypto.PEMToCert(response.CertificatePEM)
	if err != nil {
		t.Fatalf("Failed to parse returned PEM certificate: %v", err)
	}

	err = crypto.VerifyCertificate(issuedCertBytes, service.GetCACert())
	if err != nil {
		t.Errorf("The returned certificate failed cryptographic verification: %v", err)
	}
}
