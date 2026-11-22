package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// Keys holds the RSA key pair for signing tokens
type Keys struct {
	privateKey *rsa.PrivateKey
	kid        string
}

// NewKeys loads the RSA key from PEM (string or file).
// If both are empty, a random key is generated.
func NewKeys(pemData, pemFile string) (*Keys, error) {
	if pemFile != "" {
		b, err := os.ReadFile(pemFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		pemData = string(b)
	}

	var key *rsa.PrivateKey
	var err error
	if pemData == "" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = parsePrivateKey([]byte(pemData))
	}
	if err != nil {
		return nil, err
	}

	// kid = hash of the public key, changes when the key changes
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pub)

	return &Keys{
		privateKey: key,
		kid:        base64.RawURLEncoding.EncodeToString(sum[:12]),
	}, nil
}

// IsRandomKey reports whether a random key (changing on every restart) is used
func IsRandomKey(pemData, pemFile string) bool {
	return pemData == "" && pemFile == ""
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

// GeneratePrivateKeyPEM generates new RSA private key encoded as PKCS#8 PEM
func GeneratePrivateKeyPEM() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// PrivateKey returns the private key
func (k *Keys) PrivateKey() *rsa.PrivateKey {
	return k.privateKey
}

// PublicKey returns the public key
func (k *Keys) PublicKey() *rsa.PublicKey {
	return &k.privateKey.PublicKey
}

// KID returns the key ID
func (k *Keys) KID() string {
	return k.kid
}

// JWKS returns the JSON Web Key Set
func (k *Keys) JWKS() map[string]any {
	pub := k.PublicKey()
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": k.kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
