package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config holds the whole application configuration
type Config struct {
	Port   string
	Issuer string

	// Signing key (PEM), empty = random key on each start
	PrivateKey     string
	PrivateKeyFile string

	// Upstream OIDC provider (eg. Keycloak) used to authenticate real users
	UpstreamIssuer       string
	UpstreamClientID     string
	UpstreamClientSecret string
	UpstreamScopes       []string

	// Who is allowed to log in (empty = any user authenticated by upstream)
	AllowedEmails       []string
	AllowedEmailDomains []string

	// Downstream OIDC client (eg. application or Keycloak identity broker)
	ClientID     string
	ClientSecret string
	RedirectURIs []string

	// Static user every token is issued for
	StaticUser StaticUser
}

// StaticUser is the single identity issued in all tokens
type StaticUser struct {
	Sub               string
	Email             string
	Name              string
	PreferredUsername string
	Groups            []string
}

// Validate checks the configuration
func (c *Config) Validate() error {
	var errs []error
	req := func(name, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	req("issuer", c.Issuer)
	req("upstream-issuer", c.UpstreamIssuer)
	req("upstream-client-id", c.UpstreamClientID)
	req("client-id", c.ClientID)
	req("client-secret", c.ClientSecret)
	req("static-user-sub", c.StaticUser.Sub)
	if c.PrivateKey != "" && c.PrivateKeyFile != "" {
		errs = append(errs, errors.New("use only one of private-key and private-key-file"))
	}
	c.Issuer = strings.TrimSuffix(c.Issuer, "/")
	return errors.Join(errs...)
}

// GetEnv returns env variable or default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// SplitList splits comma separated list, trims spaces and drops empty items
func SplitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
