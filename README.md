# MCP Gateway OAuth Helpers

Library containing OAuth Dynamic Client Registration (DCR) functionality for MCP servers.

Note: This code was extracted from MCP Gateway PR: https://github.com/docker/mcp-gateway/pull/148

## Purpose

This library provides the core OAuth/DCR functions for MCP Gateway:

- **OAuth Discovery**: Discover OAuth requirements from MCP servers (RFC 9728 + 8414)
- **Dynamic Client Registration**: Register OAuth clients automatically (RFC 7591)
- **WWW-Authenticate Parsing**: Parse OAuth challenge headers

## Local development

OAuth discovery allows public HTTP and HTTPS authorization servers, as well
as loopback destinations (`localhost`, `127.0.0.0/8`, `::1`), by default. It
still rejects private, link-local, cloud-metadata, and other reserved
destinations before dialing, including redirect targets, regardless of
scheme.

For local development with a genuinely private-network (e.g. RFC1918) OAuth
provider, set `DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1`. This disables the
authorization server network guard (the private/link-local address checks),
so it must not be enabled with untrusted MCP servers.

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
