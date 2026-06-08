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
	"fmt"
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
	log.Log("TTP", "[INIT] Generating RSA-4096 key pair for TTP...")
	privKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		return nil, err
	}
	log.Log("TTP", "[INIT] RSA-4096 key pair generated")

	log.Log("TTP", "[INIT] Generating self-signed Root CA certificate (CN=TTP_Main_CA)...")
	caCert, err := crypto.GenerateRootCA(privKey, "TTP_Main_CA")
	if err != nil {
		return nil, err
	}
	log.Log("TTP", fmt.Sprintf("[INIT] Root CA certificate generated (%d bytes DER)", len(caCert)))

	log.Log("TTP", "========================================")
	log.Log("TTP", "TTP Service ready. Waiting for connections...")
	log.Log("TTP", "========================================")

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
		s.log.Log("TTP", "[REGISTER] Failed: invalid payload received")
		return nil, errors.New("invalid registration data")
	}

	s.log.Log("TTP", "[REGISTER] Step 1/3: Decrypting entity ID with TTP private key (RSA-OAEP)...")
	decryptedIDBytes, err := crypto.DecryptRSA(s.privateKey, encryptedEntityID)
	if err != nil {
		s.log.Log("TTP", "[REGISTER] Failed: could not decrypt entity ID")
		return nil, errors.New("failed to decrypt ID")
	}

	entityID := string(decryptedIDBytes)
	s.log.Log("TTP", fmt.Sprintf("[REGISTER] ID decrypted successfully: %s...", entityID[:8]))

	s.log.Log("TTP", "[REGISTER] Step 2/3: Issuing X.509 certificate signed by Root CA...")
	certBytes, err := crypto.IssueCertificate(entityID, pubKey, s.caCert, s.privateKey)
	if err != nil {
		s.log.Log("TTP", "[REGISTER] Failed: could not issue certificate for "+entityID[:8]+"...")
		return nil, err
	}
	s.log.Log("TTP", fmt.Sprintf("[REGISTER] Certificate issued (%d bytes DER, CN=%s...)", len(certBytes), entityID[:8]))

	s.registry[entityID] = certBytes
	s.log.Log("TTP", fmt.Sprintf("[REGISTER] Step 3/3: Entity stored in registry. Total registered: %d", len(s.registry)))
	s.log.Log("TTP", "[REGISTER] Registration completed successfully")

	return certBytes, nil
}

// GetCACert returns the TTP's public CA certificate needed for verification.
func (s *Service) GetCACert() []byte {
	return s.caCert
}

// InitServerAuth verifies the server and creates a remporary session key
func (s *Service) InitServerAuth(serverID string, certPEM string) (string, error) {
	s.log.Log("TTP", "========================================")
	s.log.Log("TTP", fmt.Sprintf("[AUTH-SRV] Server auth requested by: %s...", serverID[:8]))

	s.log.Log("TTP", "[AUTH-SRV] Step 1/4: Parsing server certificate PEM...")
	certBytes, err := crypto.PEMToCert(certPEM)
	if err != nil {
		s.log.Log("TTP", "[AUTH-SRV] REJECTED: invalid certificate format")
		return "", errors.New("invalid certificate format")
	}

	s.log.Log("TTP", "[AUTH-SRV] Step 2/4: Verifying certificate against Root CA...")
	if err := crypto.VerifyCertificate(certBytes, s.caCert); err != nil {
		s.log.Log("TTP", "[AUTH-SRV] REJECTED: certificate not signed by trusted CA")
		return "", errors.New("certificate verification failed")
	}
	s.log.Log("TTP", "[AUTH-SRV] Certificate signature verified - signed by Root CA")

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		s.log.Log("TTP", "[AUTH-SRV] REJECTED: failed to parse certificate")
		return "", errors.New("failed to parse certificate")
	}

	s.log.Log("TTP", "[AUTH-SRV] Step 3/4: Checking certificate Subject CN matches claimed server ID...")
	if cert.Subject.CommonName != serverID {
		s.log.Log("TTP", fmt.Sprintf("[AUTH-SRV] REJECTED: CN=%s... != serverID=%s...", cert.Subject.CommonName[:8], serverID[:8]))
		return "", errors.New("certificate does not belong to claimed server")
	}
	s.log.Log("TTP", "[AUTH-SRV] Identity confirmed: CN matches server ID")

	serverPubKey := cert.PublicKey.(*rsa.PublicKey)

	s.log.Log("TTP", "[AUTH-SRV] Step 4/4: Generating unique session ID (128-bit CSPRNG)...")
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

	s.log.Log("TTP", fmt.Sprintf("[AUTH-SRV] Session created: %s... | Active sessions: %d", sessionID[:8], len(s.sessions)))
	s.log.Log("TTP", "[AUTH-SRV] Server authentication successful!")
	s.log.Log("TTP", "========================================")
	return sessionID, nil
}

// AuthUserAndGenerateKey verifies the user and creates AES key
func (s *Service) AuthUserAndGenerateKey(sessionID string, encryptedUserID []byte, certPEM string) ([]byte, error) {
	s.log.Log("TTP", "========================================")
	s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] User auth requested for session: %s...", sessionID[:8]))

	s.sessionsMu.Lock()
	session, exists := s.sessions[sessionID]
	s.sessionsMu.Unlock()

	if !exists {
		s.log.Log("TTP", "[AUTH-USR] REJECTED: session not found or expired")
		return nil, errors.New("invalid or expired session ID")
	}

	s.log.Log("TTP", "[AUTH-USR] Step 1/5: Decrypting user ID with TTP private key (RSA-OAEP)...")
	decryptedUserIDBytes, err := crypto.DecryptRSA(s.privateKey, encryptedUserID)
	if err != nil {
		s.log.Log("TTP", "[AUTH-USR] REJECTED: failed to decrypt user ID")
		return nil, errors.New("failed to decrypt user ID")
	}
	userID := string(decryptedUserIDBytes)
	s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] User ID decrypted: %s...", userID[:8]))

	s.log.Log("TTP", "[AUTH-USR] Step 2/5: Parsing user certificate PEM...")
	certBytes, err := crypto.PEMToCert(certPEM)
	if err != nil {
		s.log.Log("TTP", "[AUTH-USR] REJECTED: invalid certificate format from user")
		return nil, errors.New("invalid certificate format")
	}

	s.log.Log("TTP", "[AUTH-USR] Step 3/5: Verifying certificate against Root CA...")
	if err := crypto.VerifyCertificate(certBytes, s.caCert); err != nil {
		s.log.Log("TTP", "[AUTH-USR] REJECTED: certificate not signed by trusted CA")
		return nil, errors.New("certificate verification failed")
	}
	s.log.Log("TTP", "[AUTH-USR] Certificate signature verified - signed by Root CA")

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		s.log.Log("TTP", "[AUTH-USR] REJECTED: failed to parse certificate")
		return nil, errors.New("failed to parse certificate")
	}

	s.log.Log("TTP", "[AUTH-USR] Step 4/5: Checking certificate CN matches decrypted user ID...")
	if cert.Subject.CommonName != userID {
		s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] REJECTED: CN=%s... != userID=%s...", cert.Subject.CommonName[:8], userID[:8]))
		return nil, errors.New("certificate does not belong to claimed user")
	}
	s.log.Log("TTP", "[AUTH-USR] Identity confirmed: CN matches user ID")

	userPubKey := cert.PublicKey.(*rsa.PublicKey)
	s.log.Log("TTP", "[AUTH-USR] User public key extracted from certificate")

	s.log.Log("TTP", "[AUTH-USR] Step 5/5: Generating AES-256 session key via CSPRNG...")
	aesKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, err
	}
	s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] AES-256 key generated (%d bytes)", len(aesKey)))

	s.log.Log("TTP", "[AUTH-USR] Encrypting AES key with Server's RSA public key (OAEP/SHA-256)...")
	serverEncryptedAES, _ := crypto.EncryptRSA(session.ServerPubKey, aesKey)
	s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] Server copy encrypted (%d bytes)", len(serverEncryptedAES)))

	s.log.Log("TTP", "[AUTH-USR] Building payload for User (AES key + server_id)...")
	userPayload := map[string]string{
		"aes_key":   base64.StdEncoding.EncodeToString(aesKey),
		"server_id": session.ServerID,
	}
	userPayloadBytes, _ := json.Marshal(userPayload)

	s.log.Log("TTP", "[AUTH-USR] Encrypting payload with User's RSA public key (OAEP/SHA-256)...")
	userEncryptedPayload, _ := crypto.EncryptRSA(userPubKey, userPayloadBytes)
	s.log.Log("TTP", fmt.Sprintf("[AUTH-USR] User payload encrypted (%d bytes)", len(userEncryptedPayload)))

	s.sessionsMu.Lock()
	session.ServerEncryptedAes = serverEncryptedAES
	s.sessionsMu.Unlock()

	s.log.Log("TTP", "[AUTH-USR] User authentication successful! AES key distributed to session.")
	s.log.Log("TTP", "========================================")

	return userEncryptedPayload, nil
}

// FetchServerKey allows the server to obtain AES key
func (s *Service) FetchServiceKey(sessionID string, serverID string) ([]byte, error) {
	s.log.Log("TTP", fmt.Sprintf("[FETCH-KEY] Server requests AES key for session %s...", sessionID[:8]+"..."))

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists || session.ServerID != serverID || session.ServerEncryptedAes == nil {
		s.log.Log("TTP", "[FETCH-KEY] REJECTED: key not available or unauthorized")
		return nil, errors.New("key not available or unauthorized access")
	}

	aesKey := session.ServerEncryptedAes

	delete(s.sessions, sessionID)
	s.log.Log("TTP", fmt.Sprintf("[FETCH-KEY] AES key delivered. Session %s... closed. Active sessions: %d", sessionID[:8], len(s.sessions)))
	return aesKey, nil
}
