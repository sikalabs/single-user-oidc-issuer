package oidc

import (
	"testing"

	"github.com/sikalabs/single-user-oidc-issuer/internal/config"
)

func TestIsAllowedRedirectURI(t *testing.T) {
	tests := []struct {
		allowed []string
		uri     string
		want    bool
	}{
		// empty list = any http(s)
		{nil, "https://app.example.com/cb", true},
		{nil, "javascript:alert(1)", false},
		// "*" = any http(s)
		{[]string{"*"}, "http://localhost:8000/callback", true},
		{[]string{"*"}, "ftp://example.com/cb", false},
		{[]string{"*"}, "https://app.example.com/cb#frag", false},
		// exact
		{[]string{"https://app.example.com/cb"}, "https://app.example.com/cb", true},
		{[]string{"https://app.example.com/cb"}, "https://app.example.com/cb2", false},
		// prefix wildcard
		{[]string{"https://app.example.com/*"}, "https://app.example.com/oauth/callback", true},
		{[]string{"https://app.example.com/*"}, "https://app.example.com.evil.com/cb", false},
		{[]string{"https://other.com/cb", "http://localhost:*"}, "http://localhost:3000/cb", true},
		{[]string{"https://other.com/cb", "http://localhost:*"}, "https://evil.com/cb", false},
	}
	for _, tt := range tests {
		p := &Provider{cfg: &config.Config{RedirectURIs: tt.allowed}}
		if got := p.isAllowedRedirectURI(tt.uri); got != tt.want {
			t.Errorf("allowed=%v uri=%q: got %v, want %v", tt.allowed, tt.uri, got, tt.want)
		}
	}
}
