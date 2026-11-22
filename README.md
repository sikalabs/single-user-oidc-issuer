# single-user-oidc-issuer

OIDC issuer which lets people log in with **their own identity** (via an upstream OIDC provider like Keycloak, Google, GitLab, ...) but always issues tokens for **one single static user**.

Useful for applications which support OIDC but only have one (admin) account, or where you want a group of people to share one identity while still authenticating each person individually.

```
 Browser ──> Application / Keycloak broker ──> single-user-oidc-issuer ──> Upstream OIDC (Keycloak, ...)
                (downstream OIDC client)          (this project)           (real user identity)

  1. app redirects to          /authorize
  2. issuer redirects to                                                   upstream login
  3. upstream redirects to     /callback  (real user is checked against allowlist and logged)
  4. issuer redirects to app with code
  5. app exchanges code at     /token     -> id_token / access_token of the STATIC user
```

## Usage

```bash
# Generate signing key (keeps tokens valid across restarts)
single-user-oidc-issuer generate-key > key.pem

export ISSUER=https://single-user.example.com
export PRIVATE_KEY_FILE=key.pem

# Upstream provider, register redirect URI https://single-user.example.com/callback
export UPSTREAM_ISSUER=https://keycloak.example.com/realms/main
export UPSTREAM_CLIENT_ID=single-user-oidc-issuer
export UPSTREAM_CLIENT_SECRET=xxx

# Who can log in (empty = everyone authenticated by upstream)
export ALLOWED_EMAIL_DOMAINS=example.com
export ALLOWED_EMAILS=alice@other.com,bob@other.com

# Downstream client (your app or Keycloak identity broker)
export CLIENT_ID=my-app
export CLIENT_SECRET=yyy
export REDIRECT_URIS=https://app.example.com/oauth/callback

# The static user every token is issued for
export STATIC_USER_SUB=admin
export STATIC_USER_EMAIL=admin@example.com
export STATIC_USER_NAME="Admin"
export STATIC_USER_PREFERRED_USERNAME=admin
export STATIC_USER_GROUPS=admins

single-user-oidc-issuer server
```

All options are also available as flags, see `single-user-oidc-issuer server --help`.

| Env | Description |
| --- | --- |
| `PORT` | Server port (default `8080`) |
| `ISSUER` | Public URL of this issuer (default `http://localhost:8080`) |
| `PRIVATE_KEY` / `PRIVATE_KEY_FILE` | RSA private key (PEM) for signing tokens. Random key on each start if empty. |
| `UPSTREAM_ISSUER` | Upstream OIDC issuer URL (required) |
| `UPSTREAM_CLIENT_ID` / `UPSTREAM_CLIENT_SECRET` | Client registered in the upstream provider |
| `UPSTREAM_SCOPES` | Upstream scopes (default `openid,email,profile`) |
| `ALLOWED_EMAILS` | Comma separated emails allowed to log in |
| `ALLOWED_EMAIL_DOMAINS` | Comma separated email domains allowed to log in |
| `CLIENT_ID` / `CLIENT_SECRET` | Downstream client credentials (required) |
| `REDIRECT_URIS` | Comma separated allowed downstream redirect URIs (empty = any http(s) URI) |
| `STATIC_USER_SUB` | `sub` of the static user (default `static-user`) |
| `STATIC_USER_EMAIL` | `email` of the static user (`email_verified` is `true`) |
| `STATIC_USER_NAME` | `name` of the static user |
| `STATIC_USER_PREFERRED_USERNAME` | `preferred_username` of the static user |
| `STATIC_USER_GROUPS` | Comma separated `groups` of the static user |

When `ALLOWED_EMAILS` or `ALLOWED_EMAIL_DOMAINS` is set, the upstream user must have an email which is not marked as unverified (`email_verified: false`).

Every login is logged with the real upstream identity:

```
Login ALLOWED for upstream user sub="..." email="alice@example.com" preferred_username="alice" as static user sub="admin"
```

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery document |
| `GET /.well-known/jwks.json` | JWKS |
| `GET /authorize` | Authorization endpoint (`response_type=code`, PKCE `S256` / `plain` supported) |
| `POST /token` | Token endpoint (`client_secret_basic`, `client_secret_post`) |
| `GET/POST /userinfo` | Userinfo of the static user |
| `GET /callback` | Redirect URI for the upstream provider |
| `GET /health` | Health check |

## Keycloak as upstream

Create a confidential OpenID Connect client in your realm:

- Client ID: `single-user-oidc-issuer`
- Client authentication: `On`
- Valid redirect URIs: `https://single-user.example.com/callback`

## Keycloak as downstream (identity provider)

Add an **OpenID Connect v1.0** identity provider:

- Discovery endpoint: `https://single-user.example.com/.well-known/openid-configuration`
- Client authentication: `Client secret sent as basic auth` (or `as post`)
- Client ID / secret: `CLIENT_ID` / `CLIENT_SECRET`
- Add `https://keycloak.example.com/realms/<realm>/broker/<alias>/endpoint` to `REDIRECT_URIS`

## Docker

```bash
docker build -t single-user-oidc-issuer .
docker run -p 8080:8080 --env-file .env single-user-oidc-issuer
```

## Limitations

- In-memory storage, run a single replica.
- Only the `authorization_code` grant, no refresh tokens.
- One downstream client.
