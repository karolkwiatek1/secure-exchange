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

	"secure-exchange/crypto"
	"secure-exchange/logger"
)

// Enum for node types
type NodeType string

const (
	TypeServer NodeType = "SERVER"
	TypeUser   NodeType = "USER"
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
	privKey, err := crypto.GenerateRSAKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node keys: %v", err)
	}

	nodeID := crypto.GenerateID(name)

	log.Log(string(nodeType), fmt.Sprintf("Initialized node '%s' with ID: %s", name, nodeID[:8]+"..."))

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

	n.Log.Log(prefix, "Initiating registration at TTP....")

	n.Log.Log(prefix, "\tFetching TTP Root CA certificate...")

	// Obtain Root CA from TTP
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

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return err
	}

	ttpPubKey, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("TTP public key is not RSA")
	}

	// Encrypting node's own ID with TTP's public key
	n.Log.Log(prefix, "\tencrypting Node ID using TTP's Public Key...")

	encryptedID, err := crypto.EncryptRSA(ttpPubKey, []byte(n.ID))
	if err != nil {
		return fmt.Errorf("failed to encrypt ID: %v", err)
	}
	encryptedIDBase64 := base64.StdEncoding.EncodeToString(encryptedID)

	// Preparing own public key
	pubKeyPEM, err := crypto.PublicKeyToPEM(n.PublicKey)
	if err != nil {
		return err
	}

	// Constructing payload
	payload := map[string]string{
		"encrypted_id_base64": encryptedIDBase64,
		"public_key_pem":      pubKeyPEM,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Send HTTP Post request to TTP

	n.Log.Log(prefix, "\tSending registration payload to TTP...")

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

	// Decode the response containg the certificate
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
	n.Log.Log(string(n.Type), "Successfully obtained X.509 Certificate from TTP")

	return nil
}
