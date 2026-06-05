package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// TestPublicKeyPEMConversion tests PEM encoding and decoding of RSA public keys.
func TestPublicKeyPEMConversion(t *testing.T) {
	// 1. Generate a real RSA key pair
	privKey, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}
	pubKey := &privKey.PublicKey

	// 2. Convert Public Key to PEM format
	pemStr, err := PublicKeyToPEM(pubKey)
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	if !strings.Contains(pemStr, "-----BEGIN PUBLIC KEY-----") {
		t.Error("PEM string is missing the expected public key header")
	}

	// 3. Parse the PEM string back into an RSA Public Key
	parsedPubKey, err := PEMToPublicKey(pemStr)
	if err != nil {
		t.Fatalf("Failed to parse PEM back to public key: %v", err)
	}

	// 4. Verify they are mathematically identical
	if !pubKey.Equal(parsedPubKey) {
		t.Error("Parsed public key does not match the original public key")
	}
}

// TestCertificatePEMConversion tests PEM encoding and decoding of X.509 certificates.
func TestCertificatePEMConversion(t *testing.T) {
	// 1. Generate a real certificate (using Root CA for testing)
	privKey, _ := GenerateRSAKeys()
	certBytes, err := GenerateRootCA(privKey, "Test_PEM_CA")
	if err != nil {
		t.Fatalf("Failed to generate Root CA: %v", err)
	}

	// 2. Convert Certificate to PEM format
	pemStr := CertToPEM(certBytes)
	if !strings.Contains(pemStr, "-----BEGIN CERTIFICATE-----") {
		t.Error("PEM string is missing the expected certificate header")
	}

	// 3. Parse the PEM string back into DER-encoded certificate bytes
	parsedCertBytes, err := PEMToCert(pemStr)
	if err != nil {
		t.Fatalf("Failed to parse PEM back to certificate bytes: %v", err)
	}

	// 4. Verify the byte arrays are exactly the same
	if !bytes.Equal(certBytes, parsedCertBytes) {
		t.Error("Parsed certificate bytes do not match the original bytes")
	}
}

// TestPEMParsingFailures tests error handling for invalid PEM inputs.
func TestPEMParsingFailures(t *testing.T) {
	invalidPEM := "-----BEGIN PUBLIC KEY-----\nNotABase64String!\n-----END PUBLIC KEY-----"
	garbageData := "Just some random unformatted text without PEM headers"

	// Test PublicKey parsing failure with garbage data
	_, err := PEMToPublicKey(garbageData)
	if err == nil {
		t.Error("Expected an error when parsing garbage string as a Public Key, but got nil")
	}

	// Test Certificate parsing failure with invalid base64 payload
	_, err = PEMToCert(invalidPEM)
	if err == nil {
		t.Error("Expected an error when parsing an invalid PEM block as a Certificate, but got nil")
	}
}
