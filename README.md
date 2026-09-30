# MCP Gateway OAuth Helpers

Library containing OAuth Dynamic Client Registration (DCR) functionality for MCP servers.

Note: This code was extracted from MCP Gateway PR: https://github.com/docker/mcp-gateway/pull/148

## Purpose

This library provides the core OAuth/DCR functions for MCP Gateway:

- **OAuth Discovery**: Discover OAuth requirements from MCP servers (RFC 9728 + 8414)
- **Dynamic Client Registration**: Register OAuth clients automatically (RFC 7591)
- **WWW-Authenticate Parsing**: Parse OAuth challenge headers

## Local development

OAuth discovery's authorization-server SSRF guard is advisory, not blocking:
by default it flags localhost, private, link-local, and reserved destinations
(including redirect targets and the DNS-rebinding-safe dial-time address) as
disallowed, logs a warning naming the rejected address via the `Logger`
installed with `WithLogger`, and then still makes the request against that
real address. Discovery only fails when the fetch itself fails for an
unrelated reason (connection error, TLS failure, timeout, non-200 status,
unparseable JSON, issuer mismatch).

For a single `DiscoverOAuthRequirements` call, `WithSkipSSRFCheck(ctx)` turns
the guard off entirely for that call: no scheme/hostname/address checks, no
dial-time pinning, and no warning log. Use it when the caller has already
made its own trust decision about the target (e.g. an operator explicitly
opted a request out of the guard).

`DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1` is unrelated and unaffected by the
above: it still exists to relax the RFC 8414 HTTPS scheme requirement for
local development with an HTTP OAuth provider, and continues to disable the
authorization server network guard process-wide when set. Because it is
process-wide and disables both the HTTPS requirement and the network guard
entirely, it must not be enabled with untrusted MCP servers.

For running a single MCP server on localhost during local development,
`WithAllowLocalHTTP(ctx)` is a narrower, recommended alternative: it scopes
the same "allow http" relaxation to `localhost`, `*.localhost`, and loopback
addresses (`127.0.0.0/8`, `::1`) for that one `DiscoverOAuthRequirements`
call, while every other blocked hostname (`.local`, `.internal`, cloud
metadata hosts, etc.) and every other blocked address range (RFC1918,
link-local, etc.) stays subject to the guard exactly as without the option.
It answers "is this destination local," not "is the guard on at all," so it
does not imply `WithSkipSSRFCheck` (or vice versa) — set either, both, or
neither depending on what the caller needs:

```go
ctx := oauth.WithAllowLocalHTTP(context.Background())
discovery, err := oauth.DiscoverOAuthRequirements(ctx, "http://localhost:8080/mcp")
```

## Reusing a registration (RFC 7592)

`PerformDCRWithConfig` keeps only the client credentials, so a caller cannot
reuse or manage the registration afterwards. To persist a registration and
reuse it instead of registering on every authorization, use these helpers:

- `RegisterClient(ctx, discovery, serverName, config)` — same request as
  `PerformDCRWithConfig`, but returns the full `ClientRegistration`: issuer,
  `client_id`, `client_secret`, `client_secret_expires_at`,
  `registration_access_token`, `registration_client_uri`, redirect URIs, scope
  and token endpoint auth method.
- `GetRegistration(ctx, reg)` — RFC 7592 GET of `registration_client_uri`.
  Returns the server's current view of the client.
- `UpdateRegistration(ctx, reg, req)` — RFC 7592 PUT. `req` is the complete
  client metadata (the server replaces, it does not merge); use it to renew an
  expired secret or add a scope or redirect URI.
- `ErrRegistrationGone` — returned by both when the server answers 401 or 404:
  the record was dropped, so discard it and register again.
  `ErrNoRegistrationManagement` — the registration has no
  `registration_client_uri` / `registration_access_token`, so RFC 7592 is not
  possible; register again instead.
  `ErrInsecureRegistrationURI` — `registration_client_uri`, or a redirect from
  it, is not https; the registration access token is never sent. The check
  follows the authorization-server transport: `WithAllowLocalHTTP` permits
  http to loopback hosts, and `WithSkipSSRFCheck` or
  `DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1` turn it off. The token is also
  dropped from any redirect that leaves the original origin.
- `(*ClientRegistration).SecretExpired(now)` — whether `client_secret_expires_at`
  has passed (`0` never expires).
- `IsInvalidClientError(status, body)` / `IsInvalidClientErrorCode(code)` —
  detect an `invalid_client` (RFC 6749 §5.2) token endpoint response or
  authorize redirect, meaning the cached registration should be discarded.

```go
reg, err := oauth.RegisterClient(ctx, discovery, "my-server", cfg)
// ... persist reg, keeping ClientSecret and RegistrationAccessToken out of
// plain-text storage ...

got, err := oauth.GetRegistration(ctx, reg)
switch {
case errors.Is(err, oauth.ErrRegistrationGone):
    // the server dropped the client: register again
case errors.Is(err, oauth.ErrNoRegistrationManagement):
    // nothing to validate with
}
```

`ClientRegistration` marshals `client_secret` and `registration_access_token`
into JSON, so do not write it to disk as is. mcpruntime keeps those two in a
separate secret store; see its `docs/dcr-memoization.md`.

## Configuring redirect URI validation

By default DCR only accepts redirect URI hosts for localhost, `mcp.docker.com`, and `mcp-stage.docker.com`.
Use `PerformDCRWithConfig` to provide a custom allowlist:

```go
allowedHosts := append(oauth.DefaultAllowedRedirectURIHosts(), "oauth.example.com")
creds, err := oauth.PerformDCRWithConfig(ctx, discovery, "my-server", oauth.DCRConfig{
    RedirectURI:             "https://oauth.example.com/callback",
    AllowedRedirectURIHosts: allowedHosts,
})
```
