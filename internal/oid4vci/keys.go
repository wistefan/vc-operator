package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PEM block type identifiers for key serialization.
const (
	// PEMBlockTypeECPrivateKey is the PEM block type for EC private keys.
	PEMBlockTypeECPrivateKey = "EC PRIVATE KEY"

	// PEMBlockTypePublicKey is the PEM block type for public keys.
	PEMBlockTypePublicKey = "PUBLIC KEY"
)

// KeyManager handles generation and loading of ECDSA key pairs used
// for signing proof-of-possession JWTs in OID4VCI credential requests.
type KeyManager struct {
	// privateKey is the ECDSA private key used for signing.
	privateKey *ecdsa.PrivateKey
}

// NewKeyManager creates a new KeyManager with a freshly generated
// ECDSA P-256 key pair. The generated key is ephemeral and will be
// lost when the process exits unless explicitly persisted.
func NewKeyManager() (*KeyManager, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}
	return &KeyManager{privateKey: key}, nil
}

// NewKeyManagerFromPEM creates a KeyManager from a PEM-encoded EC private key.
// This allows loading a previously persisted key (e.g., from a Kubernetes Secret)
// for consistency across operator restarts.
func NewKeyManagerFromPEM(pemData []byte) (*KeyManager, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found in input", ErrKeyGeneration)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}

	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: expected P-256 curve, got %s", ErrKeyGeneration, key.Curve.Params().Name)
	}

	return &KeyManager{privateKey: key}, nil
}

// PrivateKey returns the ECDSA private key managed by this KeyManager.
func (km *KeyManager) PrivateKey() *ecdsa.PrivateKey {
	return km.privateKey
}

// PublicKey returns the ECDSA public key corresponding to the managed private key.
func (km *KeyManager) PublicKey() *ecdsa.PublicKey {
	return &km.privateKey.PublicKey
}

// MarshalPrivateKeyPEM serializes the private key to PEM-encoded format
// suitable for storage in a Kubernetes Secret or file.
func (km *KeyManager) MarshalPrivateKeyPEM() ([]byte, error) {
	derBytes, err := x509.MarshalECPrivateKey(km.privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}

	pemBlock := &pem.Block{
		Type:  PEMBlockTypeECPrivateKey,
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// MarshalPublicKeyPEM serializes the public key to PEM-encoded format.
func (km *KeyManager) MarshalPublicKeyPEM() ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(&km.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}

	pemBlock := &pem.Block{
		Type:  PEMBlockTypePublicKey,
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
