package crypto

import (
	"crypto/x509"
	"testing"
)

// TestGenerateRootCA tests self-signed root CA certificate generation.
func TestGenerateRootCA(t *testing.T) {
	// 1. Generate a private key for the CA
	caPrivKey, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}

	// 2. Generate the Root CA certificate
	caCertBytes, err := GenerateRootCA(caPrivKey, "Test_Root_CA")
	if err != nil {
		t.Fatalf("Failed to generate Root CA: %v", err)
	}
	if len(caCertBytes) == 0 {
		t.Fatal("Generated Root CA certificate is empty")
	}

	// 3. Parse and validate the generated certificate properties
	parsedCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse the generated Root CA certificate: %v", err)
	}

	if !parsedCert.IsCA {
		t.Error("Expected certificate to be a CA, but it is not")
	}
	if parsedCert.Subject.CommonName != "Test_Root_CA" {
		t.Errorf("Expected CommonName 'Test_Root_CA', got '%s'", parsedCert.Subject.CommonName)
	}
}

// TestIssueAndVerifyCertificate tests certificate issuance and verification.
func TestIssueAndVerifyCertificate(t *testing.T) {
	// 1. Setup CA
	caPrivKey, _ := GenerateRSAKeys()
	caCertBytes, _ := GenerateRootCA(caPrivKey, "Test_Root_CA")

	// 2. Setup Entity (User/Server)
	entityPrivKey, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Failed to generate entity private key: %v", err)
	}
	entityID := "Test_Entity_1"

	// 3. Issue Certificate
	entityCertBytes, err := IssueCertificate(entityID, &entityPrivKey.PublicKey, caCertBytes, caPrivKey)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}
	if len(entityCertBytes) == 0 {
		t.Fatal("Issued entity certificate is empty")
	}

	// 4. Verify Certificate (Success case)
	err = VerifyCertificate(entityCertBytes, caCertBytes)
	if err != nil {
		t.Errorf("Valid certificate failed verification: %v", err)
	}
}

// TestVerifyCertificate_Failures tests certificate verification failure scenarios.
func TestVerifyCertificate_Failures(t *testing.T) {
	// 1. Setup Valid CA and issue a certificate for an entity
	caPrivKey1, _ := GenerateRSAKeys()
	caCertBytes1, _ := GenerateRootCA(caPrivKey1, "Test_Root_CA_1")

	entityPrivKey, _ := GenerateRSAKeys()
	entityCertBytes, _ := IssueCertificate("Entity_A", &entityPrivKey.PublicKey, caCertBytes1, caPrivKey1)

	// 2. Setup Rogue CA (Attacker trying to spoof TTP)
	caPrivKey2, _ := GenerateRSAKeys()
	caCertBytes2, _ := GenerateRootCA(caPrivKey2, "Rogue_CA")

	// 3. Test verification with the wrong CA (Should Fail)
	err := VerifyCertificate(entityCertBytes, caCertBytes2)
	if err == nil {
		t.Error("Expected verification to fail when using a different CA, but it succeeded")
	}

	// 4. Test verification with tampered certificate bytes (Should Fail)
	tamperedCertBytes := make([]byte, len(entityCertBytes))
	copy(tamperedCertBytes, entityCertBytes)
	// Flip a bit in the middle of the certificate to invalidate the signature/structure
	tamperedCertBytes[len(tamperedCertBytes)/2] ^= 0xff

	err = VerifyCertificate(tamperedCertBytes, caCertBytes1)
	if err == nil {
		t.Error("Expected verification to fail with tampered certificate bytes, but it succeeded")
	}
}
