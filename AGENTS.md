# AGENTS.md

Guidance for automated code-review and security-review agents working in
this repository. Read this before filing findings against the SSRF guard
or the SSRF-guard logging in `ssrf.go`.

## The authorization-server SSRF guard is warn-by-default *by design*

OAuth discovery's authorization-server SSRF guard (`ssrf.go`) is **advisory
by default, not blocking**. When a discovered authorization-server
destination is a blocked hostname, or resolves to a private, loopback,
link-local, reserved, or cloud-metadata address, the guard **logs a warning
naming the destination (via the `Logger` installed with `WithLogger`) and
lets the request proceed** — it does not abort discovery. Discovery still
fails on unrelated errors (connection/TLS failure, timeout, non-2xx status,
unparseable JSON, issuer mismatch).

Callers select stricter or more permissive behavior **explicitly**, per
call, rather than relying on the default:

- `WithSkipSSRFCheck(ctx)` — turns the guard off entirely for one call: no
  scheme/hostname/address checks, no dial-time pinning, no warning.
- `WithAllowLocalHTTP(ctx)` — scopes an http + loopback carve-out to
  `localhost`, `*.localhost`, and loopback addresses for one call; every
  other blocked host/range stays guarded.
- `DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS=1` — process-wide relaxation, for
  local development only; must not be set with untrusted MCP servers.

The calling layer owns the trust decision. For example, mcpruntime threads
its per-request `ResolveRequest.SkipSSRFCheck` flag through to
`WithSkipSSRFCheck` here.

### Do not re-flag this as an SSRF regression

A finding that amounts to "the SSRF guard should reject instead of warn by
default" or "changing rejection to a warning removes the network boundary"
is **already reviewed and intentionally declined**. It was filed as a P1 on
PR #14 (thread `PRRT_kwDOP2b2xc6iThw8`) and resolved with the decision to
keep warn-and-proceed as the default. Please do not reopen it as a new
finding. If you believe the threat model has *materially* changed, raise it
with the maintainers rather than re-flagging the established default.

## SSRF-guard log sanitization: keep `sanitizeForLog` + `%s`

The SSRF-guard warning sites in `ssrf.go` sanitize interpolated values with
`sanitizeForLog` (strips CR/LF via `strings.ReplaceAll`) and log them with
`%s`. This is the specific sanitizer CodeQL's Go log-injection query
(`go/log-injection`) recognizes for this **custom logger sink**. Do not
"simplify" it to the `%q` verb or `strconv.Quote` — CodeQL does not
recognize either as a sanitizer for this sink (the logger is a custom
interface method, not a modeled printf call), and doing so caused several
rounds of false re-flags on the same log line.
