package oauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

const allowInsecureRemoteURLEnv = "DOCKER_MCP_ALLOW_INSECURE_REMOTE_URLS"

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

var authorizationServerHTTPClientFunc = newAuthorizationServerHTTPClient

// newAuthorizationServerHTTPClient limits attacker-influenced authorization
// server metadata requests to public HTTPS destinations. It resolves and pins
// the address at dial time so DNS rebinding cannot redirect the connection to
// a private service. The guarded transport is also used for every redirect.
func newAuthorizationServerHTTPClient(client *http.Client) (*http.Client, error) {
	return newAuthorizationServerHTTPClientWithResolver(client, net.DefaultResolver)
}

func newAuthorizationServerHTTPClientWithResolver(client *http.Client, resolver ipResolver) (*http.Client, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is nil")
	}
	if allowInsecureRemoteURLs() {
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
	if err := validatePublicHTTPSURL(req.URL); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func validatePublicHTTPSURL(target *url.URL) error {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return fmt.Errorf("authorization server URL must be absolute")
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return fmt.Errorf("authorization server URL must use https")
	}
	if target.User != nil {
		return fmt.Errorf("authorization server URL must not include userinfo")
	}

	host := normalizeHostname(target.Hostname())
	if host == "" || strings.ContainsAny(host, "\x00%") {
		return fmt.Errorf("authorization server URL host is malformed")
	}
	if isBlockedHostname(host) {
		return fmt.Errorf("authorization server URL host %q is not allowed", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := validatePublicAddr(ip); err != nil {
			return fmt.Errorf("authorization server URL host %q is not allowed: %w", host, err)
		}
	}
	return nil
}

func dialPublicAddress(
	ctx context.Context,
	resolver ipResolver,
	dial func(context.Context, string, string) (net.Conn, error),
	network, host, port string,
) (net.Conn, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := validatePublicAddr(ip); err != nil {
			return nil, err
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
		if err := validatePublicAddr(ip); err != nil {
			return nil, fmt.Errorf("authorization server host %q resolved to disallowed address %s: %w", host, ip, err)
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
