package ttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"secure-exchange/crypto"
	"secure-exchange/logger"
	"sync"
)

// PendingSession stores current session state
type PendingSession struct {
	SessionID          string
	ServerID           string
	ServerPubKey       *rsa.PublicKey
	ServerEncryptedAes []byte
}

// Service represents the Trusted Third Party server.
type Service struct {
	privateKey *rsa.PrivateKey
	caCert     []byte
	log        *logger.EventLogger
	registry   map[string][]byte // Maps entity ID to their issued certificate
	sessionsMu sync.Mutex
	sessions   map[string]*PendingSession
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
		sessions:   make(map[string]*PendingSession),
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

// InitServerAuth verifies the server and creates a remporary session key
func (s *Service) InitServerAuth(serverID string) (string, error) {
	s.log.Log("TTP", "Server Authentication requested by: "+serverID[:8]+"...")

	serverCertBytes, exists := s.registry[serverID]
	if !exists {
		s.log.Log("TTP", "Authentication rejected: unknnown Server ID")
		return "", errors.New("server not registered")
	}

	serverCert, _ := x509.ParseCertificate(serverCertBytes)
	serverPubKey := serverCert.PublicKey.(*rsa.PublicKey)

	// generating unique SessionID
	sessionBytes := make([]byte, 16)
	rand.Read(sessionBytes)
	sessionID := hex.EncodeToString(sessionBytes)

	s.sessionsMu.Lock()
	s.sessions[sessionID] = &PendingSession{
		SessionID:    sessionID,
		ServerID:     serverID,
		ServerPubKey: serverPubKey,
	}
	s.sessionsMu.Unlock()

	s.log.Log("TTP", "Server Authenticated. Session ID generated: "+sessionID[:8]+"...")
	return sessionID, nil
}

// AuthUserAndGenerateKey verifies the user and creates AES key
func (s *Service) AuthUserAndGenerateKey(sessionID string, encryptedUserID []byte) ([]byte, error) {
	s.sessionsMu.Lock()
	session, exists := s.sessions[sessionID]
	s.sessionsMu.Unlock()

	if !exists {
		return nil, errors.New("invalid or expired session ID")
	}

	s.log.Log("TTP", "User Authentication requested for session: "+sessionID[:8]+"...")

	decryptedUserIDBytes, err := crypto.DecryptRSA(s.privateKey, encryptedUserID)
	if err != nil {
		s.log.Log("TTP", "Auth rejected: failed to decrypt User ID")
		return nil, errors.New("failed to decrypt user ID")
	}
	userID := string(decryptedUserIDBytes)

	userCertBytes, exists := s.registry[userID]
	if !exists {
		s.log.Log("TTP", "Auth rejected: unknown User ID")
		return nil, errors.New("user not registered")
	}

	userCert, _ := x509.ParseCertificate(userCertBytes)
	userPubKey := userCert.PublicKey.(*rsa.PublicKey)

	// Generating AES (256-bit) key
	aesKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	// Encrypting the key for both parties
	serverEncryptedAES, _ := crypto.EncryptRSA(session.ServerPubKey, aesKey)
	userEncryptedAES, _ := crypto.EncryptRSA(userPubKey, aesKey)

	// Storing AES encrypted with server public key in session, so server can obtain it later
	s.sessionsMu.Lock()
	session.ServerEncryptedAes = serverEncryptedAES
	s.sessionsMu.Unlock()

	s.log.Log("TTP", "User Authenticated. AES key generated and ready for distribution.")

	return userEncryptedAES, nil
}

// FetchServerKey allows the server to obtain AES key
func (s *Service) FetchServiceKey(sessionID string, serverID string) ([]byte, error) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists || session.ServerID != serverID || session.ServerEncryptedAes == nil {
		return nil, errors.New("key not available or unauthorized access")
	}

	aesKey := session.ServerEncryptedAes

	// Remove session from memory - keys have been distributed
	delete(s.sessions, sessionID)
	s.log.Log("TTP", "Server fetched its AES key. Session fully established.")
	return aesKey, nil
}
