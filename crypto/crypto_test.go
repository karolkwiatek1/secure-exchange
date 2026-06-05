package crypto

import (
	"bytes"
	"testing"
)

// TestGenerateRSAKeys tests RSA key pair generation and validation.
func TestGenerateRSAKeys(t *testing.T) {
	privKey, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Expected no error when generating RSA keys, got: %v", err)
	}
	if privKey == nil {
		t.Fatal("Generated key is nil")
	}

	// Mathematical validity verification of the generated key
	if err := privKey.Validate(); err != nil {
		t.Fatalf("Generated RSA key is invalid: %v", err)
	}
}

// TestGenerateID tests deterministic ID generation from a name string.
func TestGenerateID(t *testing.T) {
	id1 := GenerateID("Wenzel_TTP")
	id2 := GenerateID("Wenzel_TTP")
	id3 := GenerateID("Wenzel_User")

	if id1 != id2 {
		t.Errorf("IDs for the same input should be identical. Got %s and %s", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("IDs for different inputs should be different")
	}
}

// TestGenerateSessionKey tests AES session key generation.
func TestGenerateSessionKey(t *testing.T) {
	key, err := GenerateSessionKey()
	if err != nil {
		t.Fatalf("Unexpected CSPRNG error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected 32-byte key (256 bits), got %d bytes", len(key))
	}
}

// TestAES_GCM tests AES-256-GCM encryption and decryption.
func TestAES_GCM(t *testing.T) {
	key, _ := GenerateSessionKey()
	plaintext := []byte("Secret file content to be sent over the network")

	// Test correct encryption and decryption
	ciphertext, err := EncryptAES_GCM(key, plaintext)
	if err != nil {
		t.Fatalf("AES encryption error: %v", err)
	}

	decrypted, err := DecryptAES_GCM(key, ciphertext)
	if err != nil {
		t.Fatalf("AES decryption error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted message does not match the original. Expected '%s', got '%s'", plaintext, decrypted)
	}

	// Data integrity violation test (Man-in-the-Middle)
	// Modify the first byte of the ciphertext
	ciphertext[0] ^= 0xff
	_, err = DecryptAES_GCM(key, ciphertext)
	if err == nil {
		t.Error("Expected error when decrypting modified data, but the operation succeeded")
	}
}

// TestRSAEncryption tests RSA-OAEP encryption and decryption.
func TestRSAEncryption(t *testing.T) {
	privKey, _ := GenerateRSAKeys()
	pubKey := &privKey.PublicKey

	// Simulation of an AES session key to be transmitted
	message, _ := GenerateSessionKey()

	ciphertext, err := EncryptRSA(pubKey, message)
	if err != nil {
		t.Fatalf("RSA encryption error: %v", err)
	}

	decrypted, err := DecryptRSA(privKey, ciphertext)
	if err != nil {
		t.Fatalf("RSA decryption error: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted RSA message does not match the original payload")
	}
}
