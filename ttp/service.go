package ttp

import (
	"crypto/rsa"
	"errors"
	"secure-exchange/crypto"
	"secure-exchange/logger"
)

// Service represents the Trusted Third Party server.
type Service struct {
	privateKey *rsa.PrivateKey
	caCert     []byte
	log        *logger.EventLogger
	registry   map[string][]byte // Maps entity ID to their issued certificate
}

// NewService initializes a new TTP instance with its own CA.
func NewService(log *logger.EventLogger) (*Service, error) {
	privKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		return nil, err
	}

	caCert, err := crypto.GenerateRootCA(privKey, "TTP_Main_CA")
	if err != nil {
		return nil, err
	}

	log.Log("TTP", "Service initialized and Root CA generated")

	return &Service{
		privateKey: privKey,
		caCert:     caCert,
		log:        log,
		registry:   make(map[string][]byte),
	}, nil
}

// RegisterEntity handles the registration request from User or Server.
func (s *Service) RegisterEntity(encryptedEntityID []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	if len(encryptedEntityID) == 0 || pubKey == nil {
		s.log.Log("TTP", "Registration failed: invalid payload received")
		return nil, errors.New("invalid registration data")
	}

	// Decrypt ID using TTP private key.
	decryptedIDBytes, err := crypto.DecryptRSA(s.privateKey, encryptedEntityID)
	if err != nil {
		s.log.Log("TTP", "Registration failed: could not decrypt entity ID")
		return nil, errors.New("failed to decrypt ID")
	}

	entityID := string(decryptedIDBytes)

	certBytes, err := crypto.IssueCertificate(entityID, pubKey, s.caCert, s.privateKey)
	if err != nil {
		s.log.Log("TTP", "Registration failed: could not issue certificate for "+entityID)
		return nil, err
	}

	s.registry[entityID] = certBytes
	s.log.Log("TTP", "Successfully registered entity and issued certificate: "+entityID)

	return certBytes, nil
}

// GetCACert returns the TTP's public CA certificate needed for verification.
func (s *Service) GetCACert() []byte {
	return s.caCert
}
