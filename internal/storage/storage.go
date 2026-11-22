package storage

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	pendingAuthTTL = 10 * time.Minute
	authCodeTTL    = 2 * time.Minute
)

// PendingAuth is a downstream authorization request waiting for upstream login
type PendingAuth struct {
	// Downstream request
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string

	// Upstream request
	UpstreamNonce        string
	UpstreamCodeVerifier string

	CreatedAt time.Time
}

// AuthorizationCode is a downstream OAuth2 authorization code
type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	CreatedAt           time.Time
}

// Storage is in-memory storage for pending auths and authorization codes
type Storage struct {
	mu           sync.Mutex
	pendingAuths map[string]*PendingAuth       // upstream state -> pending auth
	authCodes    map[string]*AuthorizationCode // code -> auth code
}

// NewStorage creates a new storage instance
func NewStorage() *Storage {
	s := &Storage{
		pendingAuths: make(map[string]*PendingAuth),
		authCodes:    make(map[string]*AuthorizationCode),
	}
	go s.cleanup()
	return s
}

// CreatePendingAuth stores pending auth and returns the upstream state key
func (s *Storage) CreatePendingAuth(p *PendingAuth) (string, error) {
	key, err := GenerateToken()
	if err != nil {
		return "", err
	}
	p.CreatedAt = time.Now()

	s.mu.Lock()
	s.pendingAuths[key] = p
	s.mu.Unlock()

	return key, nil
}

// TakePendingAuth returns pending auth and removes it (single use)
func (s *Storage) TakePendingAuth(key string) (*PendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.pendingAuths[key]
	if !ok {
		return nil, false
	}
	delete(s.pendingAuths, key)
	if time.Since(p.CreatedAt) > pendingAuthTTL {
		return nil, false
	}
	return p, true
}

// CreateAuthorizationCode stores a new authorization code
func (s *Storage) CreateAuthorizationCode(c *AuthorizationCode) error {
	code, err := GenerateToken()
	if err != nil {
		return err
	}
	c.Code = code
	c.CreatedAt = time.Now()

	s.mu.Lock()
	s.authCodes[code] = c
	s.mu.Unlock()

	return nil
}

// TakeAuthorizationCode returns authorization code and removes it (single use)
func (s *Storage) TakeAuthorizationCode(code string) (*AuthorizationCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.authCodes[code]
	if !ok {
		return nil, false
	}
	delete(s.authCodes, code)
	if time.Since(c.CreatedAt) > authCodeTTL {
		return nil, false
	}
	return c, true
}

// cleanup removes expired entries
func (s *Storage) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		for k, p := range s.pendingAuths {
			if time.Since(p.CreatedAt) > pendingAuthTTL {
				delete(s.pendingAuths, k)
			}
		}
		for k, c := range s.authCodes {
			if time.Since(c.CreatedAt) > authCodeTTL {
				delete(s.authCodes, k)
			}
		}
		s.mu.Unlock()
	}
}

// GenerateToken generates a random URL safe token
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
