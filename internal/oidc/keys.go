package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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

// NewKeys loads the RSA key from PEM (string or file) or derives it
// deterministically from seed. If all are empty, a random key is generated.
func NewKeys(pemData, pemFile, seed string) (*Keys, error) {
	if pemFile != "" {
		b, err := os.ReadFile(pemFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		pemData = string(b)
	}

	var key *rsa.PrivateKey
	var err error
	switch {
	case pemData != "":
		key, err = parsePrivateKey([]byte(pemData))
	case seed != "":
		key, err = deterministicKey(seed, 2048)
	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
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
func IsRandomKey(pemData, pemFile, seed string) bool {
	return pemData == "" && pemFile == "" && seed == ""
}

// deterministicKey derives an RSA key from seed. rsa.GenerateKey can't be used
// for this, it ignores custom random readers since Go 1.26.
func deterministicKey(seed string, bits int) (*rsa.PrivateKey, error) {
	stream := &seedStream{seed: sha256.Sum256([]byte(seed))}
	e := big.NewInt(65537)
	one := big.NewInt(1)

	var p, q *big.Int
	for {
		p = stream.prime(bits / 2)
		q = stream.prime(bits - bits/2)
		if p.Cmp(q) == 0 {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		phi := new(big.Int).Mul(pm1, qm1)
		if new(big.Int).GCD(nil, nil, e, phi).Cmp(one) != 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         new(big.Int).ModInverse(e, phi),
			Primes:    []*big.Int{p, q},
		}
		if err := key.Validate(); err != nil {
			return nil, err
		}
		key.Precompute()
		return key, nil
	}
}

// seedStream is a deterministic byte stream: SHA-256(seed || counter)
type seedStream struct {
	seed    [32]byte
	counter uint64
}

func (s *seedStream) read(n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for len(out) < n {
		var buf [40]byte
		copy(buf[:32], s.seed[:])
		binary.BigEndian.PutUint64(buf[32:], s.counter)
		s.counter++
		sum := sha256.Sum256(buf[:])
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// prime returns a deterministic prime with exactly bits bits
func (s *seedStream) prime(bits int) *big.Int {
	nbytes := (bits + 7) / 8
	extra := uint(nbytes*8 - bits)
	for {
		b := s.read(nbytes)
		b[0] &= byte(0xff >> extra)
		// top two bits set, so the product of two primes has the full length
		b[0] |= byte(0xc0 >> extra)
		b[nbytes-1] |= 1
		p := new(big.Int).SetBytes(b)
		if p.ProbablyPrime(32) {
			return p
		}
	}
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
