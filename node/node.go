// Package node provides the participant representation in the secure exchange network.
package node

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/karolkwiatek1/secure-exchange/crypto"
	"github.com/karolkwiatek1/secure-exchange/logger"
)

// NodeType represents the type of participant in the network.
type NodeType string

const (
	// TypeServer identifies the node as a server participant.
	TypeServer NodeType = "SERVER"
	// TypeUser identifies the node as a user participant.
	TypeUser NodeType = "USER"
)

// Node represents the participant in the network (user or server).
type Node struct {
	ID         string
	Type       NodeType
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CertPEM    string
	TTPAddress string
	TTPCaCert  []byte
	Log        *logger.EventLogger
}

// NewNode initializes a new node with generated RSA keys.
func NewNode(name string, nodeType NodeType, ttpAddress string, log *logger.EventLogger) (*Node, error) {
	log.Log(string(nodeType), "[INIT] Generating RSA-4096 key pair...")
	privKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node keys: %v", err)
	}
	log.Log(string(nodeType), "[INIT] RSA-4096 key pair generated successfully")

	nodeID := crypto.GenerateID(name)
	log.Log(string(nodeType), fmt.Sprintf("[INIT] Node '%s' SHA-256 ID: %s", name, nodeID[:8]+"..."))

	return &Node{
		ID:         nodeID,
		Type:       nodeType,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		TTPAddress: ttpAddress,
		Log:        log,
	}, nil
}

// RegisterAtTTP contacts the TTP server to obtain an X.509 certificate.
func (n *Node) RegisterAtTTP() error {
	prefix := string(n.Type)

	n.Log.Log(prefix, "========================================")
	n.Log.Log(prefix, "[REGISTER] Step 1/5: Fetching TTP Root CA certificate...")
	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] GET %s/ca", n.TTPAddress))

	caResp, err := http.Get(fmt.Sprintf("%s/ca", n.TTPAddress))
	if err != nil {
		return fmt.Errorf("failed to contact TTP for CA certificate: %v", err)
	}
	defer caResp.Body.Close()

	var caData struct {
		CACertificatePem string `json:"ca_certificate_pem"`
	}
	if err := json.NewDecoder(caResp.Body).Decode(&caData); err != nil {
		return fmt.Errorf("failed to decode CA response: %v", err)
	}

	caCertBytes, err := crypto.PEMToCert(caData.CACertificatePem)
	if err != nil {
		return err
	}
	n.TTPCaCert = caCertBytes
	n.Log.Log(prefix, "[REGISTER] Root CA certificate received and stored")

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return err
	}

	ttpPubKey, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("TTP public key is not RSA")
	}
	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] TTP CA identity verified: CN=%s", caCert.Subject.CommonName))

	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] Step 2/5: Encrypting node ID '%s...' with TTP's RSA public key (OAEP/SHA-256)...", n.ID[:8]))
	encryptedID, err := crypto.EncryptRSA(ttpPubKey, []byte(n.ID))
	if err != nil {
		return fmt.Errorf("failed to encrypt ID: %v", err)
	}
	encryptedIDBase64 := base64.StdEncoding.EncodeToString(encryptedID)
	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] ID encrypted (%d bytes -> %d bytes base64)", len(encryptedID), len(encryptedIDBase64)))

	n.Log.Log(prefix, "[REGISTER] Step 3/5: Encoding public key in PEM format...")
	pubKeyPEM, err := crypto.PublicKeyToPEM(n.PublicKey)
	if err != nil {
		return err
	}
	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] Public key PEM: %d bytes", len(pubKeyPEM)))

	n.Log.Log(prefix, "[REGISTER] Step 4/5: Sending registration payload to TTP...")
	payload := map[string]string{
		"encrypted_id_base64": encryptedIDBase64,
		"public_key_pem":      pubKeyPEM,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] POST %s/register (%d bytes)", n.TTPAddress, len(jsonData)))
	registerURL := fmt.Sprintf("%s/register", n.TTPAddress)
	resp, err := http.Post(registerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("network error communicating with TTP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("TTP rejected registration: %s", string(bodyBytes))
	}

	n.Log.Log(prefix, "[REGISTER] Step 5/5: Decoding X.509 certificate from TTP response...")
	var response struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode TTP response: %v", err)
	}

	if response.CertificatePEM == "" {
		return errors.New("received empty certificate from TTP")
	}

	n.CertPEM = response.CertificatePEM
	n.Log.Log(prefix, fmt.Sprintf("[REGISTER] X.509 certificate obtained (%d bytes PEM)", len(response.CertificatePEM)))
	n.Log.Log(prefix, "[REGISTER] Registration completed successfully!")
	n.Log.Log(prefix, "========================================")

	return nil
}

// InitSession contacts the TTP to initialize new session
func (n *Node) InitSession() (string, error) {
	prefix := string(n.Type)
	n.Log.Log(prefix, "[SESSION] Step 1/2: Requesting new session from TTP...")
	n.Log.Log(prefix, fmt.Sprintf("[SESSION] Sending server_id=%s... + certificate PEM (%d bytes)", n.ID[:8]+"...", len(n.CertPEM)))

	payload := map[string]string{
		"server_id":       n.ID,
		"certificate_pem": n.CertPEM,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	n.Log.Log(prefix, fmt.Sprintf("[SESSION] POST %s/auth-server (%d bytes)", n.TTPAddress, len(jsonData)))
	resp, err := http.Post(fmt.Sprintf("%s/auth-server", n.TTPAddress), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("network error communicating with TTP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("TTP rejected session request: %s", string(bodyBytes))
	}

	n.Log.Log(prefix, "[SESSION] Step 2/2: Decoding session ID from TTP response...")
	var result struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	n.Log.Log(prefix, fmt.Sprintf("[SESSION] Session established. SessionID: %s...", result.SessionID[:8]))
	return result.SessionID, nil
}

// FetchSessionKey fetches encrypted AES key from the TTP, and decrypts it
func (n *Node) FetchSessionKey(sessionID string) ([]byte, error) {
	prefix := string(n.Type)
	n.Log.Log(prefix, fmt.Sprintf("[FETCH-KEY] Step 1/3: Requesting AES key for session %s...", sessionID[:8]+"..."))

	payload := map[string]string{
		"session_id": sessionID,
		"server_id":  n.ID,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	n.Log.Log(prefix, fmt.Sprintf("[FETCH-KEY] POST %s/fetch-key (%d bytes)", n.TTPAddress, len(jsonData)))
	resp, err := http.Post(fmt.Sprintf("%s/fetch-key", n.TTPAddress), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("TTP rejected key fetch (User might not be authenticated yet)")
	}

	n.Log.Log(prefix, "[FETCH-KEY] Step 2/3: Decoding encrypted AES key from response...")
	var result struct {
		EncryptedAESBase64 string `json:"encrypted_aes_for_server_base64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	encryptedAES, err := base64.StdEncoding.DecodeString(result.EncryptedAESBase64)
	if err != nil {
		return nil, err
	}
	n.Log.Log(prefix, fmt.Sprintf("[FETCH-KEY] Encrypted AES key: %d bytes (base64: %d bytes)", len(encryptedAES), len(result.EncryptedAESBase64)))

	n.Log.Log(prefix, "[FETCH-KEY] Step 3/3: Decrypting AES key with own RSA private key (OAEP/SHA-256)...")
	aesKey, err := crypto.DecryptRSA(n.PrivateKey, encryptedAES)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
	}

	n.Log.Log(prefix, fmt.Sprintf("[FETCH-KEY] AES-256 session key obtained (%d bytes)", len(aesKey)))
	return aesKey, nil
}
