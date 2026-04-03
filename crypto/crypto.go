package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateRSAKeys generates a 4096 bit long RSA key pair
func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA keys: %v", err)
	}
	return privateKey, nil
}

// GenerateID generates unique ID based on name with SHA-256
func GenerateID(entityName string) string {
	hash := sha256.Sum256([]byte(entityName))
	return hex.EncodeToString(hash[:])
}

// GenerateSessionKey generates random 256 bits (32 bytes) long key for AES
func GenerateSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("error CSPRNG: %v", err)
	}
	return key, nil
}

// EncryptAES_GCM encrypts data using AES-256 with GCM
func EncryptAES_GCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES_GCM decrypts data using AES-256 with GCM
func DecryptAES_GCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("encrypted data is too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptTSA encrypts small data chunks (eg. AES key, ID) using receiver public key
func EncryptRSA(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, message, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptRSA decrypts data using private key
func DecryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
