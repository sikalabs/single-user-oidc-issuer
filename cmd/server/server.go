package server

import (
	"log"

	"github.com/sikalabs/single-user-oidc-issuer/cmd/root"
	"github.com/sikalabs/single-user-oidc-issuer/internal/config"
	"github.com/sikalabs/single-user-oidc-issuer/internal/server"
	"github.com/spf13/cobra"
)

var (
	cfg                 config.Config
	upstreamScopes      string
	allowedEmails       string
	allowedEmailDomains string
	redirectURIs        string
	staticUserGroups    string
)

var Cmd = &cobra.Command{
	Use:   "server",
	Short: "Start the OIDC server",
	Long: `Start the single user OIDC issuer.

Users authenticate against an upstream OIDC provider (eg. Keycloak) with their
own identity. After a successful login, this issuer issues tokens for a single
static user, regardless of who logged in. The real identity is only logged.

Environment variables:
  PORT                    - Server port (default: 8080)
  ISSUER                  - Public URL of this issuer (default: http://localhost:8080)
  PRIVATE_KEY             - RSA private key (PEM) for signing tokens
  PRIVATE_KEY_FILE        - Path to RSA private key (PEM) for signing tokens

  UPSTREAM_ISSUER         - Upstream OIDC issuer URL (eg. https://keycloak/realms/main)
  UPSTREAM_CLIENT_ID      - Client ID registered in upstream provider
  UPSTREAM_CLIENT_SECRET  - Client secret registered in upstream provider
  UPSTREAM_SCOPES         - Upstream scopes (default: openid,email,profile)

  ALLOWED_EMAILS          - Comma separated list of emails allowed to log in
  ALLOWED_EMAIL_DOMAINS   - Comma separated list of email domains allowed to log in

  CLIENT_ID               - Client ID of the downstream client
  CLIENT_SECRET           - Client secret of the downstream client
  REDIRECT_URIS           - Comma separated list of allowed downstream redirect URIs,
                            supports wildcards: "*" (any) or trailing "*" (prefix)

  STATIC_USER_SUB                - Subject of the static user (default: static-user)
  STATIC_USER_EMAIL              - Email of the static user
  STATIC_USER_NAME               - Name of the static user
  STATIC_USER_PREFERRED_USERNAME - Preferred username of the static user
  STATIC_USER_GROUPS             - Comma separated groups of the static user

The upstream redirect URI is <ISSUER>/callback.
If no private key is provided, a random RSA key is generated on each startup.
If ALLOWED_EMAILS and ALLOWED_EMAIL_DOMAINS are empty, every user
authenticated by the upstream provider is allowed.`,
	Args: cobra.NoArgs,
	Run:  runServer,
}

func init() {
	root.Cmd.AddCommand(Cmd)

	e := config.GetEnv
	f := Cmd.Flags()

	f.StringVarP(&cfg.Port, "port", "p", e("PORT", "8080"), "Server port")
	f.StringVarP(&cfg.Issuer, "issuer", "i", e("ISSUER", "http://localhost:8080"), "Public URL of this issuer")
	f.StringVar(&cfg.PrivateKey, "private-key", e("PRIVATE_KEY", ""), "RSA private key (PEM) for signing tokens (empty = random)")
	f.StringVar(&cfg.PrivateKeyFile, "private-key-file", e("PRIVATE_KEY_FILE", ""), "Path to RSA private key (PEM) for signing tokens")

	f.StringVar(&cfg.UpstreamIssuer, "upstream-issuer", e("UPSTREAM_ISSUER", ""), "Upstream OIDC issuer URL")
	f.StringVar(&cfg.UpstreamClientID, "upstream-client-id", e("UPSTREAM_CLIENT_ID", ""), "Upstream client ID")
	f.StringVar(&cfg.UpstreamClientSecret, "upstream-client-secret", e("UPSTREAM_CLIENT_SECRET", ""), "Upstream client secret")
	f.StringVar(&upstreamScopes, "upstream-scopes", e("UPSTREAM_SCOPES", "openid,email,profile"), "Comma separated upstream scopes")

	f.StringVar(&allowedEmails, "allowed-emails", e("ALLOWED_EMAILS", ""), "Comma separated emails allowed to log in")
	f.StringVar(&allowedEmailDomains, "allowed-email-domains", e("ALLOWED_EMAIL_DOMAINS", ""), "Comma separated email domains allowed to log in")

	f.StringVar(&cfg.ClientID, "client-id", e("CLIENT_ID", ""), "Downstream client ID")
	f.StringVar(&cfg.ClientSecret, "client-secret", e("CLIENT_SECRET", ""), "Downstream client secret")
	f.StringVar(&redirectURIs, "redirect-uris", e("REDIRECT_URIS", ""), "Comma separated allowed downstream redirect URIs (\"*\" = any, trailing \"*\" = prefix)")

	f.StringVar(&cfg.StaticUser.Sub, "static-user-sub", e("STATIC_USER_SUB", "static-user"), "Subject of the static user")
	f.StringVar(&cfg.StaticUser.Email, "static-user-email", e("STATIC_USER_EMAIL", ""), "Email of the static user")
	f.StringVar(&cfg.StaticUser.Name, "static-user-name", e("STATIC_USER_NAME", ""), "Name of the static user")
	f.StringVar(&cfg.StaticUser.PreferredUsername, "static-user-preferred-username", e("STATIC_USER_PREFERRED_USERNAME", ""), "Preferred username of the static user")
	f.StringVar(&staticUserGroups, "static-user-groups", e("STATIC_USER_GROUPS", ""), "Comma separated groups of the static user")
}

func runServer(cmd *cobra.Command, args []string) {
	cfg.UpstreamScopes = config.SplitList(upstreamScopes)
	cfg.AllowedEmails = config.SplitList(allowedEmails)
	cfg.AllowedEmailDomains = config.SplitList(allowedEmailDomains)
	cfg.RedirectURIs = config.SplitList(redirectURIs)
	cfg.StaticUser.Groups = config.SplitList(staticUserGroups)

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration:\n%v", err)
	}

	srv, err := server.NewServer(cmd.Context(), &cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
