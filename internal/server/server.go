package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sikalabs/single-user-oidc-issuer/internal/config"
	"github.com/sikalabs/single-user-oidc-issuer/internal/oidc"
	"github.com/sikalabs/single-user-oidc-issuer/internal/storage"
)

// Server is the HTTP server
type Server struct {
	cfg      *config.Config
	provider *oidc.Provider
	router   *chi.Mux
}

// NewServer creates a new HTTP server
func NewServer(ctx context.Context, cfg *config.Config) (*Server, error) {
	provider, err := oidc.NewProvider(ctx, cfg, storage.NewStorage())
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		provider: provider,
		router:   chi.NewRouter(),
	}
	s.setupRoutes()
	return s, nil
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) setupRoutes() {
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)

	// OIDC discovery
	s.router.Get("/.well-known/openid-configuration", s.handleJSON(s.provider.Discovery))
	s.router.Get("/.well-known/jwks.json", s.handleJSON(s.provider.JWKS))

	// OIDC endpoints
	s.router.Get("/authorize", s.provider.HandleAuthorize)
	s.router.Post("/token", s.provider.HandleToken)
	s.router.Get("/userinfo", s.provider.HandleUserInfo)
	s.router.Post("/userinfo", s.provider.HandleUserInfo)

	// Upstream login callback
	s.router.Get("/callback", s.provider.HandleCallback)

	s.router.Get("/health", s.handleJSON(func() map[string]any {
		return map[string]any{"status": "ok"}
	}))
	s.router.Get("/", s.handleHome)
}

func (s *Server) handleJSON(f func() map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f())
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <title>Single User OIDC Issuer</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; line-height: 1.6; color: #333; }
    code { background: #edf2f7; padding: 2px 6px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>Single User OIDC Issuer</h1>
  <p>Users log in with their own identity at the upstream provider.
  Every issued token belongs to one static user.</p>
  <ul>
    <li>Issuer: <code>%s</code></li>
    <li>Upstream issuer: <code>%s</code></li>
    <li>Static user: <code>%s</code></li>
    <li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
    <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a></li>
  </ul>
</body>
</html>`,
		html.EscapeString(s.cfg.Issuer),
		html.EscapeString(s.cfg.UpstreamIssuer),
		html.EscapeString(s.cfg.StaticUser.Sub),
	)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	if oidc.IsRandomKey(s.cfg.PrivateKey, s.cfg.PrivateKeyFile) {
		log.Printf("WARNING: no private key configured, using random key (tokens become invalid on restart)")
	}
	if len(s.cfg.AllowedEmails) == 0 && len(s.cfg.AllowedEmailDomains) == 0 {
		log.Printf("WARNING: no ALLOWED_EMAILS / ALLOWED_EMAIL_DOMAINS, every upstream user can log in")
	}
	if len(s.cfg.RedirectURIs) == 0 {
		log.Printf("WARNING: no REDIRECT_URIS, any http(s) redirect URI is accepted")
	}

	addr := ":" + s.cfg.Port
	log.Printf("Starting single user OIDC issuer on %s", addr)
	log.Printf("Issuer: %s", s.cfg.Issuer)
	log.Printf("Upstream issuer: %s (redirect URI: %s/callback)", s.cfg.UpstreamIssuer, s.cfg.Issuer)
	log.Printf("Static user: %s", s.cfg.StaticUser.Sub)

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}
