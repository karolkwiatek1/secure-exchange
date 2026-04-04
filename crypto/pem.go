package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// PublicKeyToPEM converts an RSA Public Key to a PEM formatted string.
func PublicKeyToPEM(pubKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// PEMToPublicKey parses a PEM formatted string into an RSA Public Key.
func PEMToPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not of type RSA")
	}
	return rsaPub, nil
}

// CertToPEM converts a DER-encoded certificate byte array to a PEM string
func CertToPEM(certBytes []byte) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// PEMToCert parses a PEM formatted string back into DER-encoded bytes.
func PEMToCert(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the certificate")
	}
	return block.Bytes, nil
}
