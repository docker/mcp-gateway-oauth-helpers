package oauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const allowInsecureRemoteURLEnv = "DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS"

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// skipSSRFCheckKey is deliberately its own type (not log.go's contextKey) so
// that it can never collide with a value stored under another package key.
type skipSSRFCheckKey struct{}

// WithSkipSSRFCheck opts a single DiscoverOAuthRequirements call out of the
// authorization-server SSRF guard entirely. Unlike the default warn-and-
// proceed posture (see newAuthorizationServerHTTPClientWithResolver), this
// turns the check fully off for the call carrying this context: no scheme,
// hostname, or address checks, no dial-time pinning, and no warning log.
// This mirrors allowInsecureRemoteURLEnv but is scoped to one call instead
// of the whole process.
func WithSkipSSRFCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipSSRFCheckKey{}, true)
}

func skipSSRFCheck(ctx context.Context) bool {
	skip, _ := ctx.Value(skipSSRFCheckKey{}).(bool)
	return skip
}

// allowLocalHTTPKey is deliberately its own type (not log.go's contextKey or
// skipSSRFCheckKey) so that it can never collide with a value stored under
// another package key.
type allowLocalHTTPKey struct{}

// WithAllowLocalHTTP opts a single DiscoverOAuthRequirements call into
// treating localhost/loopback (127.0.0.0/8, ::1, "localhost", "*.localhost")
// as an allowed authorization server address, including over plain http.
// It is deliberately narrower than WithSkipSSRFCheck: every other blocked
// hostname suffix (.local, .internal, cloud-metadata hosts, etc.) and every
// other blocked address range (RFC1918, link-local, etc.) is still subject
// to the guard exactly as without this option. It answers "is this
// destination local," not "is the guard on at all," so it does not imply
// WithSkipSSRFCheck (or vice versa) — a caller may set either, both, or
// neither.
func WithAllowLocalHTTP(ctx context.Context) context.Context {
	return context.WithValue(ctx, allowLocalHTTPKey{}, true)
}

func allowLocalHTTP(ctx context.Context) bool {
	allow, _ := ctx.Value(allowLocalHTTPKey{}).(bool)
	return allow
}

// isLoopbackHost reports whether a normalized hostname or textual IP literal
// refers to localhost or a loopback address. It exists only to scope
// WithAllowLocalHTTP's carve-out and must not be consulted anywhere the
// guard's default posture applies.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return false
}

var authorizationServerHTTPClientFunc = newAuthorizationServerHTTPClient

// newAuthorizationServerHTTPClient by default resolves and pins the
// authorization server address at dial time so DNS rebinding cannot redirect
// the connection to a private service, but it never blocks the request: a
// rejection is logged as a warning (naming the address) and the same request
// proceeds anyway, unless the context carries WithSkipSSRFCheck, in which
// case the check is skipped entirely (no checks, no warning). The guarded
// transport is also used for every redirect.
func newAuthorizationServerHTTPClient(ctx context.Context, client *http.Client) (*http.Client, error) {
	return newAuthorizationServerHTTPClientWithResolver(ctx, client, net.DefaultResolver)
}

func newAuthorizationServerHTTPClientWithResolver(ctx context.Context, client *http.Client, resolver ipResolver) (*http.Client, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is nil")
	}
	if allowInsecureRemoteURLs() || skipSSRFCheck(ctx) {
		insecureClient := *client
		return &insecureClient, nil
	}
	if resolver == nil {
		return nil, fmt.Errorf("IP resolver is nil")
	}

	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("HTTP transport %T cannot be guarded at dial time", base)
	}

	guardedTransport := transport.Clone()
	if guardedTransport.DialTLS != nil || //nolint:staticcheck // A legacy TLS dialer would bypass the guarded DialContext.
		guardedTransport.DialTLSContext != nil {
		return nil, fmt.Errorf("HTTP transport with a custom TLS dialer cannot be guarded at dial time")
	}
	// A generic proxy cannot guarantee that the validated address is the one
	// ultimately dialed. Authorization-server discovery therefore uses a direct
	// connection whose resolved public address is pinned below.
	guardedTransport.Proxy = nil

	originalDialContext := guardedTransport.DialContext
	if originalDialContext == nil {
		originalDialContext = (&net.Dialer{}).DialContext
	}
	guardedTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid authorization server dial address %q: %w", address, err)
		}
		return dialPublicAddress(ctx, resolver, originalDialContext, network, host, port)
	}

	guardedClient := *client
	guardedClient.Transport = &publicOnlyRoundTripper{base: guardedTransport}
	return &guardedClient, nil
}

type publicOnlyRoundTripper struct {
	base http.RoundTripper
}

func (t *publicOnlyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ssrfErr, err := validatePublicHTTPSURL(req.Context(), req.URL)
	if err != nil {
		return nil, err
	}
	if ssrfErr != nil {
		quotedURL := strconv.Quote(req.URL.String())
		quotedErr := strconv.Quote(ssrfErr.Error())
		loggerFromContext(req.Context()).Warnf("authorization server request to %s was rejected by the SSRF guard; proceeding anyway: %s", quotedURL, quotedErr)
	}
	return t.base.RoundTrip(req)
}

// validatePublicHTTPSURL enforces the always-hard requirements for an
// authorization server URL (absolute, https scheme unless WithAllowLocalHTTP
// permits http for this specific loopback host, no userinfo, well-formed
// host) via hardErr. It separately reports, via ssrfErr, whether the host is
// blocked by the SSRF guard (a known-private hostname, or a literal IP in a
// private/loopback/link-local/metadata/reserved range). Callers treat
// ssrfErr as warn-and-continue and hardErr as a genuine failure.
func validatePublicHTTPSURL(ctx context.Context, target *url.URL) (ssrfErr, hardErr error) {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("authorization server URL must be absolute")
	}
	if target.User != nil {
		return nil, fmt.Errorf("authorization server URL must not include userinfo")
	}

	host := normalizeHostname(target.Hostname())
	if host == "" || strings.ContainsAny(host, "\x00%") {
		return nil, fmt.Errorf("authorization server URL host is malformed")
	}

	allowLocal := allowLocalHTTP(ctx) && isLoopbackHost(host)

	if !strings.EqualFold(target.Scheme, "https") {
		if !allowLocal || !strings.EqualFold(target.Scheme, "http") {
			return nil, fmt.Errorf("authorization server URL must use https")
		}
	}

	if allowLocal {
		return nil, nil
	}
	if isBlockedHostname(host) {
		return fmt.Errorf("authorization server URL host %q is not allowed", host), nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := validatePublicAddr(ip); err != nil {
			return fmt.Errorf("authorization server URL host %q is not allowed: %w", host, err), nil
		}
	}
	return nil, nil
}

// dialPublicAddress pins the dial to the address(es) validated above,
// closing the DNS-rebinding gap where a hostname could resolve differently
// between the RoundTrip-time check and the actual dial. A disallowed address
// is logged as a warning (naming the host/address) rather than rejected: the
// dial proceeds against the real, rejected address exactly like every other
// authorization-server SSRF rejection in this package.
func dialPublicAddress(
	ctx context.Context,
	resolver ipResolver,
	dial func(context.Context, string, string) (net.Conn, error),
	network, host, port string,
) (net.Conn, error) {
	logger := loggerFromContext(ctx)

	if ip, err := netip.ParseAddr(host); err == nil {
		if err := validateDialAddr(ctx, ip); err != nil {
			quotedIP := strconv.Quote(ip.String())
			quotedErr := strconv.Quote(err.Error())
			logger.Warnf("authorization server dial address %s was rejected by the SSRF guard; dialing anyway: %s", quotedIP, quotedErr)
		}
		return dial(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolving authorization server host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("authorization server host %q did not resolve to any IP addresses", host)
	}
	for _, ip := range ips {
		if err := validateDialAddr(ctx, ip); err != nil {
			quotedHost := strconv.Quote(host)
			quotedIP := strconv.Quote(ip.String())
			quotedErr := strconv.Quote(err.Error())
			logger.Warnf("authorization server host %s resolved to disallowed address %s; dialing anyway: %s", quotedHost, quotedIP, quotedErr)
		}
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func isBlockedHostname(host string) bool {
	host = normalizeHostname(host)
	switch host {
	case "localhost", "metadata", "metadata.google.internal", "metadata.azure.internal":
		return true
	}
	for _, suffix := range []string{
		".localhost",
		".local",
		".localdomain",
		".internal",
		".cluster.local",
		".svc",
	} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func allowInsecureRemoteURLs() bool {
	value := os.Getenv(allowInsecureRemoteURLEnv)
	return value == "1" || strings.EqualFold(value, "true")
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// validateDialAddr is validatePublicAddr scoped by WithAllowLocalHTTP: a
// loopback address is treated as allowed when the option is set on ctx,
// otherwise it defers to validatePublicAddr unchanged.
func validateDialAddr(ctx context.Context, ip netip.Addr) error {
	if allowLocalHTTP(ctx) && ip.Unmap().IsLoopback() {
		return nil
	}
	return validatePublicAddr(ip)
}

func validatePublicAddr(ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("invalid IP address")
	}
	if ip.Zone() != "" {
		return fmt.Errorf("scoped IPv6 addresses are not allowed")
	}

	ip = ip.Unmap()
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return fmt.Errorf("address is in blocked range %s", prefix)
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("address is not public")
	}
	return nil
}
