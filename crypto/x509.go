package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

// GenerateRootCA creates a self-signed X.509 certificate for the TTP.
func GenerateRootCA(privKey *rsa.PrivateKey, commonName string) ([]byte, error) {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Trusted Third Party"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, errors.New("failed to create Root CA certificate")
	}
	return caBytes, nil
}

// IssueCertificate creates an X.509 certificate for an entity, signed by the TTP.
func IssueCertificate(entityID string, entityPubKey *rsa.PublicKey, caCertBytes []byte, caPrivKey *rsa.PrivateKey) ([]byte, error) {
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, errors.New("failed to parse CA certificate")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.New("failed to generate serial number")
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Secure Exchange Network"},
			CommonName:   entityID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 1, 0), // Valid for 1 month
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, entityPubKey, caPrivKey)
	if err != nil {
		return nil, errors.New("failed to issue certificate")
	}

	return certBytes, nil
}

// VerifyCertificate checks if the provided certificate is valid and signed by the trusted CA.
func VerifyCertificate(certBytes, caCertBytes []byte) error {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return errors.New("failed to parse entity certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return errors.New("failed to parse CA certificate")
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return errors.New("certificate verification failed: invalid signature or expired")
	}

	return nil
}
