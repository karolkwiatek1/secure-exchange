// Package ttp provides the Trusted Third Party service for secure key exchange.
package ttp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
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
func (s *Service) InitServerAuth(serverID string, certPEM string) (string, error) {
	s.log.Log("TTP", "Server Authentication requested by: "+serverID[:8]+"...")

	certBytes, err := crypto.PEMToCert(certPEM)
	if err != nil {
		s.log.Log("TTP", "Authentication rejected: invalid server certificate format")
		return "", errors.New("invalid certificate format")
	}

	if err := crypto.VerifyCertificate(certBytes, s.caCert); err != nil {
		s.log.Log("TTP", "Authentication rejected: server certificate not signed by trusted CA")
		return "", errors.New("certificate verification failed")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		s.log.Log("TTP", "Authentication rejected: failed to parse server certificate")
		return "", errors.New("failed to parse certificate")
	}

	if cert.Subject.CommonName != serverID {
		s.log.Log("TTP", "Authentication rejected: certificate CN does not match server ID")
		return "", errors.New("certificate does not belong to claimed server")
	}

	serverPubKey := cert.PublicKey.(*rsa.PublicKey)

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
func (s *Service) AuthUserAndGenerateKey(sessionID string, encryptedUserID []byte, certPEM string) ([]byte, error) {
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

	certBytes, err := crypto.PEMToCert(certPEM)
	if err != nil {
		s.log.Log("TTP", "Auth rejected: invalid certificate format from user")
		return nil, errors.New("invalid certificate format")
	}

	if err := crypto.VerifyCertificate(certBytes, s.caCert); err != nil {
		s.log.Log("TTP", "Auth rejected: certificate not signed by trusted CA")
		return nil, errors.New("certificate verification failed")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		s.log.Log("TTP", "Auth rejected: failed to parse certificate")
		return nil, errors.New("failed to parse certificate")
	}

	if cert.Subject.CommonName != userID {
		s.log.Log("TTP", "Auth rejected: certificate CN does not match claimed user ID")
		return nil, errors.New("certificate does not belong to claimed user")
	}

	userPubKey := cert.PublicKey.(*rsa.PublicKey)

	// Generating AES (256-bit) key
	aesKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	// Encrypting the key for server
	serverEncryptedAES, _ := crypto.EncryptRSA(session.ServerPubKey, aesKey)

	// Encrypting key and server id for user
	userPayload := map[string]string{
		"aes_key":   base64.StdEncoding.EncodeToString(aesKey),
		"server_id": session.ServerID,
	}
	userPayloadBytes, _ := json.Marshal(userPayload)

	userEncryptedPayload, _ := crypto.EncryptRSA(userPubKey, userPayloadBytes)

	// Storing AES encrypted with server public key in session, so server can obtain it later
	s.sessionsMu.Lock()
	session.ServerEncryptedAes = serverEncryptedAES
	s.sessionsMu.Unlock()

	s.log.Log("TTP", "User Authenticated. AES key generated and ready for distribution.")

	return userEncryptedPayload, nil
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
