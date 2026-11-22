package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sikalabs/single-user-oidc-issuer/internal/config"
	"github.com/sikalabs/single-user-oidc-issuer/internal/storage"
	"golang.org/x/oauth2"
)

const tokenTTL = 1 * time.Hour

// Provider is an OIDC provider which authenticates users against
// an upstream OIDC provider and issues tokens for a single static user
type Provider struct {
	cfg      *config.Config
	storage  *storage.Storage
	keys     *Keys
	upstream *oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

// NewProvider creates a new provider and discovers the upstream provider
func NewProvider(ctx context.Context, cfg *config.Config, store *storage.Storage) (*Provider, error) {
	keys, err := NewKeys(cfg.PrivateKey, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	up, err := gooidc.NewProvider(ctx, cfg.UpstreamIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover upstream provider %s: %w", cfg.UpstreamIssuer, err)
	}

	return &Provider{
		cfg:     cfg,
		storage: store,
		keys:    keys,
		upstream: &oauth2.Config{
			ClientID:     cfg.UpstreamClientID,
			ClientSecret: cfg.UpstreamClientSecret,
			Endpoint:     up.Endpoint(),
			RedirectURL:  cfg.Issuer + "/callback",
			Scopes:       cfg.UpstreamScopes,
		},
		verifier: up.Verifier(&gooidc.Config{ClientID: cfg.UpstreamClientID}),
	}, nil
}

// Discovery returns the OIDC discovery document
func (p *Provider) Discovery() map[string]any {
	return map[string]any{
		"issuer":                                p.cfg.Issuer,
		"authorization_endpoint":                p.cfg.Issuer + "/authorize",
		"token_endpoint":                        p.cfg.Issuer + "/token",
		"userinfo_endpoint":                     p.cfg.Issuer + "/userinfo",
		"jwks_uri":                              p.cfg.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"grant_types_supported":                 []string{"authorization_code"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username", "groups",
		},
	}
}

// JWKS returns the JSON Web Key Set
func (p *Provider) JWKS() map[string]any {
	return p.keys.JWKS()
}

// HandleAuthorize validates the downstream request and redirects to upstream login
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")

	// Errors which can not be redirected back to the client
	if clientID != p.cfg.ClientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if !p.isAllowedRedirectURI(redirectURI) {
		http.Error(w, "redirect_uri is not allowed", http.StatusBadRequest)
		return
	}

	// Errors which are redirected back to the client
	if q.Get("response_type") != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "only code is supported")
		return
	}
	if !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		redirectError(w, r, redirectURI, state, "invalid_scope", "openid scope is required")
		return
	}
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		redirectError(w, r, redirectURI, state, "invalid_request", "unsupported code_challenge_method")
		return
	}

	upstreamNonce, err := storage.GenerateToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	upstreamVerifier := oauth2.GenerateVerifier()

	key, err := p.storage.CreatePendingAuth(&storage.PendingAuth{
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		State:                state,
		Nonce:                q.Get("nonce"),
		Scope:                q.Get("scope"),
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		UpstreamNonce:        upstreamNonce,
		UpstreamCodeVerifier: upstreamVerifier,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, p.upstream.AuthCodeURL(
		key,
		gooidc.Nonce(upstreamNonce),
		oauth2.S256ChallengeOption(upstreamVerifier),
	), http.StatusFound)
}

// HandleCallback handles the redirect back from the upstream provider
func (p *Provider) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	pending, ok := p.storage.TakePendingAuth(q.Get("state"))
	if !ok {
		http.Error(w, "invalid or expired login session, please start the login again", http.StatusBadRequest)
		return
	}

	if upErr := q.Get("error"); upErr != "" {
		log.Printf("Upstream login failed: %s: %s", upErr, q.Get("error_description"))
		redirectError(w, r, pending.RedirectURI, pending.State, "access_denied", "upstream login failed")
		return
	}

	ctx := r.Context()
	token, err := p.upstream.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pending.UpstreamCodeVerifier))
	if err != nil {
		log.Printf("Upstream code exchange failed: %v", err)
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "upstream code exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("Upstream token response has no id_token")
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "upstream returned no id_token")
		return
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Upstream id_token verification failed: %v", err)
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "upstream id_token is invalid")
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(pending.UpstreamNonce)) != 1 {
		log.Printf("Upstream id_token nonce mismatch")
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "upstream id_token nonce mismatch")
		return
	}

	var upstreamUser struct {
		Email             string `json:"email"`
		EmailVerified     *bool  `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&upstreamUser); err != nil {
		log.Printf("Failed to parse upstream claims: %v", err)
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "failed to parse upstream claims")
		return
	}

	identity := fmt.Sprintf("sub=%q email=%q preferred_username=%q", idToken.Subject, upstreamUser.Email, upstreamUser.PreferredUsername)
	if !p.isAllowedUser(upstreamUser.Email, upstreamUser.EmailVerified) {
		log.Printf("Login DENIED for upstream user %s", identity)
		redirectError(w, r, pending.RedirectURI, pending.State, "access_denied", "user is not allowed")
		return
	}
	log.Printf("Login ALLOWED for upstream user %s as static user sub=%q", identity, p.cfg.StaticUser.Sub)

	code := &storage.AuthorizationCode{
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		Nonce:               pending.Nonce,
		Scope:               pending.Scope,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		AuthTime:            time.Now(),
	}
	if err := p.storage.CreateAuthorizationCode(code); err != nil {
		redirectError(w, r, pending.RedirectURI, pending.State, "server_error", "failed to create authorization code")
		return
	}

	redirect(w, r, pending.RedirectURI, map[string]string{
		"code":  code.Code,
		"state": pending.State,
	})
}

// HandleToken exchanges an authorization code for tokens of the static user
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	clientID, clientSecret := clientCredentials(r)
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(p.cfg.ClientID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(p.cfg.ClientSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code, ok := p.storage.TakeAuthorizationCode(r.PostForm.Get("code"))
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	if code.ClientID != clientID {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if code.RedirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(code.CodeChallenge, code.CodeChallengeMethod, r.PostForm.Get("code_verifier")) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	now := time.Now()
	exp := now.Add(tokenTTL)

	idClaims := p.staticUserClaims()
	idClaims["iss"] = p.cfg.Issuer
	idClaims["aud"] = clientID
	idClaims["exp"] = exp.Unix()
	idClaims["iat"] = now.Unix()
	idClaims["auth_time"] = code.AuthTime.Unix()
	if code.Nonce != "" {
		idClaims["nonce"] = code.Nonce
	}
	idToken, err := p.sign(idClaims)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}

	accessClaims := p.staticUserClaims()
	accessClaims["iss"] = p.cfg.Issuer
	accessClaims["aud"] = clientID
	accessClaims["exp"] = exp.Unix()
	accessClaims["iat"] = now.Unix()
	accessClaims["jti"] = uuid.New().String()
	accessClaims["scope"] = code.Scope
	accessToken, err := p.sign(accessClaims)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(tokenTTL.Seconds()),
		"id_token":     idToken,
		"scope":        code.Scope,
	})
}

// HandleUserInfo returns claims of the static user for a valid access token
func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok || tokenString == "" {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	_, err := jwt.Parse(tokenString,
		func(t *jwt.Token) (any, error) { return p.keys.PublicKey(), nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(p.cfg.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, p.staticUserClaims())
}

// staticUserClaims returns user claims of the static user
func (p *Provider) staticUserClaims() jwt.MapClaims {
	u := p.cfg.StaticUser
	claims := jwt.MapClaims{"sub": u.Sub}
	if u.Email != "" {
		claims["email"] = u.Email
		claims["email_verified"] = true
	}
	if u.Name != "" {
		claims["name"] = u.Name
	}
	if u.PreferredUsername != "" {
		claims["preferred_username"] = u.PreferredUsername
	}
	if len(u.Groups) > 0 {
		claims["groups"] = u.Groups
	}
	return claims
}

func (p *Provider) sign(claims jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = p.keys.KID()
	return t.SignedString(p.keys.PrivateKey())
}

func (p *Provider) isAllowedRedirectURI(uri string) bool {
	if len(p.cfg.RedirectURIs) == 0 {
		u, err := url.Parse(uri)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	}
	return slices.Contains(p.cfg.RedirectURIs, uri)
}

func (p *Provider) isAllowedUser(email string, emailVerified *bool) bool {
	if len(p.cfg.AllowedEmails) == 0 && len(p.cfg.AllowedEmailDomains) == 0 {
		return true
	}
	// Email based rules require a (verified) email
	if email == "" || (emailVerified != nil && !*emailVerified) {
		return false
	}
	email = strings.ToLower(email)
	for _, allowed := range p.cfg.AllowedEmails {
		if strings.ToLower(allowed) == email {
			return true
		}
	}
	_, domain, _ := strings.Cut(email, "@")
	for _, allowed := range p.cfg.AllowedEmailDomains {
		if strings.ToLower(allowed) == domain {
			return true
		}
	}
	return false
}

// clientCredentials returns client credentials from basic auth or form
func clientCredentials(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		// RFC 6749 2.3.1: credentials are form-urlencoded
		if v, err := url.QueryUnescape(id); err == nil {
			id = v
		}
		if v, err := url.QueryUnescape(secret); err == nil {
			secret = v
		}
		return id, secret
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

func verifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return true
	}
	if verifier == "" {
		return false
	}
	var computed string
	switch method {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(sum[:])
	case "plain":
		computed = verifier
	default:
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func redirect(w http.ResponseWriter, r *http.Request, redirectURI string, params map[string]string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirect(w, r, redirectURI, map[string]string{
		"error":             code,
		"error_description": description,
		"state":             state,
	})
}

func tokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
