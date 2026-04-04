package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secure-exchange/crypto"
	"secure-exchange/logger"
	"secure-exchange/ttp"
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

	// 2. Prepare JSON payload
	reqData := RegisterRequest{
		EntityID:     "Test_User_HTTP",
		PublicKeyPEM: pubKeyPEM,
	}

	reqBytes, _ := json.Marshal(reqData)

	// 3. Send POST request
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	// 4. Verify HTTP Status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Expected 200 OK, got %v. Body: %s", status, rr.Body.String())
	}

	// 5. Decode response
	var response RegisterResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response JSON: %v", err)
	}

	if response.CertificatePEM == "" {
		t.Fatal("Received empty certificate PEM string")
	}

	// 6. Verify the issued certificate cryptographically using the service's CA
	issuedCertBytes, err := crypto.PEMToCert(response.CertificatePEM)
	if err != nil {
		t.Fatalf("Failed to parse returned PEM certificate: %v", err)
	}

	err = crypto.VerifyCertificate(issuedCertBytes, service.GetCACert())
	if err != nil {
		t.Errorf("The returned certificate failed cryptographic verification: %v", err)
	}
}
