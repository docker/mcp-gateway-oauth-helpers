# Investigation: OAuth discovery failure against a private-IP authorization server

## Reported error

```
fetching metadata from https://dp.mcpgw-prod.us-east-1.800960612025.docker.team/.well-known/oauth-authorization-server:
Get "https://dp.mcpgw-prod.us-east-1.800960612025.docker.team/.well-known/oauth-authorization-server":
authorization server host "dp.mcpgw-prod.us-east-1.800960612025.docker.team" resolved to disallowed address
10.204.1.251: address is in blocked range 10.0.0.0/8
```

## Code path

1. `DiscoverOAuthRequirements` (`discovery.go:38`) fetches authorization server
   metadata as its final discovery step. At `discovery.go:161` it builds a
   guarded HTTP client via `authorizationServerHTTPClientFunc(client)`, whose
   production value is `newAuthorizationServerHTTPClient` (`ssrf.go:26`).
   The guarded client is then used at `discovery.go:165` to call
   `fetchAuthorizationServerMetadata`.

2. `fetchAuthorizationServerMetadata` (`discovery.go:321`) issues
   `client.Do(req)` at `discovery.go:336` against the authorization server's
   `/.well-known/oauth-authorization-server` URL, and on failure wraps the
   error as `"fetching metadata from %s: %w"` at `discovery.go:338` — this is
   the exact `"fetching metadata from ..."` prefix in the reported error.

3. `newAuthorizationServerHTTPClient` (`ssrf.go:26`) delegates to
   `newAuthorizationServerHTTPClientWithResolver` (`ssrf.go:30`), which clones
   the transport and installs a guarded `DialContext` (`ssrf.go:65-71`) that
   calls `dialPublicAddress` (`ssrf.go:115`) for every dial the transport
   attempts.

4. `dialPublicAddress` resolves the host via `resolver.LookupNetIP`
   (`ssrf.go:128`, backed by `net.DefaultResolver` in production) and, for
   each resolved IP, calls `validatePublicAddr` (`ssrf.go:136`). If any
   resolved address is rejected, it returns the wrapped error at
   `ssrf.go:137`:

   ```go
   return nil, fmt.Errorf("authorization server host %q resolved to disallowed address %s: %w", host, ip, err)
   ```

   This is a verbatim match for `authorization server host "..." resolved to
   disallowed address 10.204.1.251: ...` in the report.

5. `validatePublicAddr` (`ssrf.go:207`) checks the resolved IP against
   `blockedPrefixes` (`ssrf.go:182-205`), which includes
   `netip.MustParsePrefix("10.0.0.0/8")` at `ssrf.go:184`. `10.204.1.251` falls
   inside `10.0.0.0/8`, so the loop at `ssrf.go:216-220` returns
   `fmt.Errorf("address is in blocked range %s", prefix)` (`ssrf.go:218`) —
   the exact `"address is in blocked range 10.0.0.0/8"` suffix in the report.

The reported error is therefore produced entirely inside this library's SSRF
guard, before any dial is attempted, and matches the guard's code, almost
character-for-character, at every layer of wrapping.

## Reproduction

`discovery_test.go`'s `TestAuthorizationServerClientRejectsInternalCorporateHostname`
stubs the `ipResolver` seam (`ssrf.go:16-18`,
`newAuthorizationServerHTTPClientWithResolver` at `ssrf.go:30`) to resolve
`dp.mcpgw-prod.us-east-1.800960612025.docker.team` to `10.204.1.251`, exactly
as production DNS did for the reporter, and asserts:

- the guarded client's `Do` call fails with the same
  `authorization server host "...": resolved to disallowed address 10.204.1.251: address is in blocked range 10.0.0.0/8`
  error text, and
- the underlying `DialContext` is never invoked — the rejection happens
  before any network connection is attempted (`ssrf.go:136-139`, ahead of the
  dial loop at `ssrf.go:142-148`).

Run with:

```
go test ./... -run TestAuthorizationServerClientRejectsInternalCorporateHostname -v
```

This test only demonstrates the guard's existing behavior; nothing in
`ssrf.go` was changed.

## 1. Root cause

`dp.mcpgw-prod.us-east-1.800960612025.docker.team` is an internal/corporate
hostname. Its structure (env/region/account-scoped subdomain under
`docker.team`) is typical of a resource meant to be resolved and reached only
from inside a corporate network or VPN — split-horizon or VPN-scoped internal
DNS answers it with a private RFC 1918 address, `10.204.1.251`, rather than a
publicly routable one. Public resolvers (or the resolver used wherever this
error was observed) may return the same private answer if the zone is
globally published with an internal-only answer, or may fail to resolve it at
all outside the network — either way, the address that this library sees for
that host is private.

The library's SSRF guard in `ssrf.go` does not know, and structurally cannot
know, whether a given authorization-server host is "someone's legitimate
internal auth server" or "an attacker-controlled redirect aimed at an
internal service." `newAuthorizationServerHTTPClientWithResolver`
(`ssrf.go:30`) and `dialPublicAddress` (`ssrf.go:115`) apply the same
`validatePublicAddr` check (`ssrf.go:207`) to every authorization-server host
resolution, unconditionally, for every caller. Because `10.204.1.251` is in
`10.0.0.0/8` (`ssrf.go:184`), it is rejected — by design, not by accident.

## 2. Why this is not a normal misconfiguration

This is the guard working as intended, not a bug in discovery or a
misconfigured authorization server. `blockedPrefixes` (`ssrf.go:182-205`) and
`validatePublicAddr` (`ssrf.go:207-226`) exist specifically to stop OAuth
discovery — which follows attacker-influenced input (the target MCP server's
own metadata) — from being used to reach internal/private infrastructure
(cloud metadata endpoints, RFC 1918 ranges, loopback, link-local, etc.). The
README's "Local development" section (`README.md:15-24`) documents this
explicitly: "OAuth discovery allows only public HTTPS authorization servers
by default. It rejects localhost, private, link-local, and reserved
destinations before dialing." The behavior observed here is exactly that
guarantee holding: the caller's authorization server happens to live on a
private network the guard has no way to allowlist today, so it is blocked
along with everything else in `10.0.0.0/8`.

## 3. Existing escape hatch and its tradeoff

The only existing way to reach this authorization server today is
`DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1`, checked by `allowInsecureRemoteURLs`
(`ssrf.go:177-180`) and consulted at `ssrf.go:34` in
`newAuthorizationServerHTTPClientWithResolver`, where it causes the guard to
be skipped entirely and the original, unguarded client to be returned
(`ssrf.go:35-37`). As `README.md:21-24` warns, this "disables the
authorization server network guard and HTTPS requirement, so it must not be
enabled with untrusted MCP servers."

This is too broad for the reported situation: the authorization server here
is otherwise a legitimate, HTTPS-reachable production endpoint
(`dp.mcpgw-prod...`) — the problem is only that it resolves privately. Setting
this env var to unblock it would remove SSRF protection (and the HTTPS
requirement) for *every* authorization-server host this process ever
discovers, not just this one internal host, which is a much larger exposure
than the operator needs to accept.

## 4. Proposed scoped remediation (not implemented)

A narrower fix would add an explicit allowlist for authorization-server
hosts/CIDRs, mirroring the pattern `dcr.go` already uses for redirect URI
hosts:

- `dcr.go`'s `DCRConfig.AllowedRedirectURIHosts` (`dcr.go:29-32`) and
  `DefaultAllowedRedirectURIHosts()` (`dcr.go:35-37`) let callers extend the
  built-in redirect URI allowlist (`dcr.go:16-22`) via
  `PerformDCRWithConfig` (`dcr.go:120`), documented in
  `README.md:26-37`.
- An analogous mechanism for the SSRF guard — e.g. an
  `AllowedAuthorizationServerHosts`/CIDR list threaded into
  `newAuthorizationServerHTTPClientWithResolver` (`ssrf.go:30`) and consulted
  in `validatePublicAddr` (`ssrf.go:207`) or `dialPublicAddress`
  (`ssrf.go:115`) before the `blockedPrefixes` check — would let an operator
  permit a specific known-internal auth server (e.g.
  `dp.mcpgw-prod.us-east-1.800960612025.docker.team`, or its `10.204.1.0/24`)
  without disabling the guard, and thus SSRF protection, for every other
  authorization server the process might ever discover.

This option is described here for consideration only; it has not been
implemented, and the SSRF guard has not been weakened as part of this
investigation.
