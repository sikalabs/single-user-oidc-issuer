package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sikalabs/single-user-oidc-issuer/internal/config"
	"github.com/sikalabs/single-user-oidc-issuer/internal/oidc"
)

const (
	clientID     = "app"
	clientSecret = "app-secret"
	clientRedir  = "https://app.example.com/callback"
)

// fakeUpstream is a minimal OIDC provider which logs in a fixed user
type fakeUpstream struct {
	srv   *httptest.Server
	keys  *oidc.Keys
	email string
	nonce map[string]string // code -> nonce
}

func newFakeUpstream(t *testing.T, email string) *fakeUpstream {
	keys, err := oidc.NewKeys("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{keys: keys, email: email, nonce: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                u.srv.URL,
			"authorization_endpoint":                u.srv.URL + "/auth",
			"token_endpoint":                        u.srv.URL + "/token",
			"jwks_uri":                              u.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(u.keys.JWKS())
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "upstream PKCE missing", http.StatusBadRequest)
			return
		}
		code := "upstream-code"
		u.nonce[code] = q.Get("nonce")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		code := r.PostForm.Get("code")
		claims := jwt.MapClaims{
			"iss":            u.srv.URL,
			"sub":            "real-user-id",
			"aud":            "upstream-client",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"nonce":          u.nonce[code],
			"email":          u.email,
			"email_verified": true,
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = u.keys.KID()
		s, _ := tok.SignedString(u.keys.PrivateKey())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-at",
			"token_type":   "Bearer",
			"id_token":     s,
		})
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

func newIssuer(t *testing.T, upstream *fakeUpstream) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)
	cfg := &config.Config{
		Issuer:               "http://" + srv.Listener.Addr().String(),
		UpstreamIssuer:       upstream.srv.URL,
		UpstreamClientID:     "upstream-client",
		UpstreamClientSecret: "upstream-secret",
		UpstreamScopes:       []string{"openid", "email"},
		AllowedEmailDomains:  []string{"allowed.com"},
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		RedirectURIs:         []string{clientRedir},
		StaticUser: config.StaticUser{
			Sub:               "shared-admin",
			Email:             "admin@example.com",
			PreferredUsername: "admin",
			Groups:            []string{"admins"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

// login runs the browser part of the flow and returns final redirect to the client
func login(t *testing.T, issuer string, extra url.Values) *url.URL {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {clientRedir},
		"scope":         {"openid email"},
		"state":         {"client-state"},
		"nonce":         {"client-nonce"},
	}
	for k, v := range extra {
		q[k] = v
	}
	next := issuer + "/authorize?" + q.Encode()
	for range 5 {
		resp, err := noRedirect.Get(next)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s: status %d", next, resp.StatusCode)
		}
		next = resp.Header.Get("Location")
		if strings.HasPrefix(next, clientRedir) {
			u, _ := url.Parse(next)
			return u
		}
	}
	t.Fatal("too many redirects")
	return nil
}

func exchange(t *testing.T, issuer string, form url.Values, secret string) (*http.Response, map[string]any) {
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", clientRedir)
	req, _ := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestFullFlowIssuesStaticUser(t *testing.T) {
	upstream := newFakeUpstream(t, "alice@allowed.com")
	issuer := newIssuer(t, upstream)

	verifier := "client-pkce-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	cb := login(t, issuer.URL, url.Values{
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	})
	if cb.Query().Get("state") != "client-state" {
		t.Fatalf("state not preserved: %s", cb)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", cb)
	}

	// Wrong PKCE verifier fails (and burns the code)
	resp, _ := exchange(t, issuer.URL, url.Values{"code": {code}, "code_verifier": {"wrong"}}, clientSecret)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected PKCE failure, got %d", resp.StatusCode)
	}

	cb = login(t, issuer.URL, url.Values{
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	})
	resp, body := exchange(t, issuer.URL, url.Values{"code": {cb.Query().Get("code")}, "code_verifier": {verifier}}, clientSecret)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, body)
	}

	// Verify id_token like a real client would
	ctx := context.Background()
	p, err := gooidc.NewProvider(ctx, issuer.URL)
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := p.Verifier(&gooidc.Config{ClientID: clientID}).Verify(ctx, body["id_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	idToken.Claims(&claims)
	if idToken.Subject != "shared-admin" || idToken.Nonce != "client-nonce" ||
		claims.Email != "admin@example.com" || claims.PreferredUsername != "admin" ||
		len(claims.Groups) != 1 || claims.Groups[0] != "admins" {
		t.Fatalf("unexpected id_token: sub=%s nonce=%s claims=%+v", idToken.Subject, idToken.Nonce, claims)
	}

	// Userinfo
	req, _ := http.NewRequest(http.MethodGet, issuer.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ui map[string]any
	json.NewDecoder(uiResp.Body).Decode(&ui)
	uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK || ui["sub"] != "shared-admin" {
		t.Fatalf("userinfo: %d %v", uiResp.StatusCode, ui)
	}
}

func TestCodeIsSingleUseAndClientSecretChecked(t *testing.T) {
	upstream := newFakeUpstream(t, "bob@allowed.com")
	issuer := newIssuer(t, upstream)

	code := login(t, issuer.URL, nil).Query().Get("code")
	if resp, _ := exchange(t, issuer.URL, url.Values{"code": {code}}, "bad-secret"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if resp, body := exchange(t, issuer.URL, url.Values{"code": {code}}, clientSecret); resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, body)
	}
	if resp, _ := exchange(t, issuer.URL, url.Values{"code": {code}}, clientSecret); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected reused code to fail, got %d", resp.StatusCode)
	}
}

func TestUpstreamUserNotAllowed(t *testing.T) {
	upstream := newFakeUpstream(t, "eve@evil.com")
	issuer := newIssuer(t, upstream)

	cb := login(t, issuer.URL, nil)
	if cb.Query().Get("error") != "access_denied" || cb.Query().Get("code") != "" {
		t.Fatalf("expected access_denied, got %s", cb)
	}
}

func TestAuthorizeRejectsUnknownRedirectURI(t *testing.T) {
	upstream := newFakeUpstream(t, "alice@allowed.com")
	issuer := newIssuer(t, upstream)

	resp, err := noRedirect.Get(issuer.URL + "/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {"https://evil.example.com/cb"},
		"scope":         {"openid"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
