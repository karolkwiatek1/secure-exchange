package ttp

import (
	"bytes"
	"secure-exchange/crypto"
	"secure-exchange/logger"
	"testing"
)

func TestTTPRegistrationFlow(t *testing.T) {
	// 1. Initialize Logger and TTP Service
	var buf bytes.Buffer
	testLogger := logger.New(&buf)

	ttpService, err := NewService(testLogger)
	if err != nil {
		t.Fatalf("Failed to start TTP service: %v", err)
	}

	// 2. Simulate User generating keys and ID
	userPrivKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Failed to generate user keys: %v", err)
	}
	userID := crypto.GenerateID("Client_PC_1")

	// 3. User registers at TTP
	userCert, err := ttpService.RegisterEntity(userID, &userPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("User registration failed: %v", err)
	}

	if userCert == nil {
		t.Fatal("Returned user certificate is nil")
	}

	// 4. Verify the issued certificate using TTP's CA
	caCert := ttpService.GetCACert()
	err = crypto.VerifyCertificate(userCert, caCert)
	if err != nil {
		t.Fatalf("Certificate verification failed: %v", err)
	}

	// 5. Test invalid verification (tampered certificate)
	tamperedCert := make([]byte, len(userCert))
	copy(tamperedCert, userCert)
	tamperedCert[len(tamperedCert)/2] ^= 0xff // Flip a bit

	err = crypto.VerifyCertificate(tamperedCert, caCert)
	if err == nil {
		t.Fatal("Expected verification to fail for tampered certificate, but it succeeded")
	}

	// 6. Verify logging output
	logOutput := buf.String()
	if !bytes.Contains([]byte(logOutput), []byte("Successfully registered entity")) {
		t.Error("Expected success log entry missing")
	}
}
