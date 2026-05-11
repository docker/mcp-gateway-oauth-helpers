# MCP Gateway OAuth Helpers

Library containing OAuth Dynamic Client Registration (DCR) functionality for MCP servers.

Note: This code was extracted from MCP Gateway PR: https://github.com/docker/mcp-gateway/pull/148

## Purpose

This library provides the core OAuth/DCR functions for MCP Gateway:

- **OAuth Discovery**: Discover OAuth requirements from MCP servers (RFC 9728 + 8414)
- **Dynamic Client Registration**: Register OAuth clients automatically (RFC 7591)
- **WWW-Authenticate Parsing**: Parse OAuth challenge headers

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
