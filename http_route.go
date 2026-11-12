package oauth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// HTTPRouteSelector captures one route for a request before connection pools
// are consulted. base is an unused clone owned by the selector. Return base or
// another fresh, unused transport with Proxy nil; ownership passes to the helper,
// which disables connection reuse and closes idle connections after the
// response is consumed or closed.
// upstreamResolvesTarget is true only when the transport's dialer sends the
// destination to a captured upstream proxy without resolving it locally.
// Returned transports must not contain custom TLSNextProto callbacks, which can
// retain shared connection pools. An empty map may disable protocol upgrades.
// A guarded direct route must not use custom TLS dialers.
// Selectors must respect req.Context() and must not change shared transports.
type HTTPRouteSelector func(req *http.Request, base *http.Transport) (transport *http.Transport, upstreamResolvesTarget bool, err error)

type httpRouteSelectorKey struct{}

// WithHTTPRouteSelector selects a fresh transport for each authorization-server
// request and redirect. It preserves routing when WithSkipSSRFCheck is set.
// Requests outside authorization-server discovery and registration are unchanged.
func WithHTTPRouteSelector(ctx context.Context, selector HTTPRouteSelector) context.Context {
	return context.WithValue(ctx, httpRouteSelectorKey{}, selector)
}

func newRoutedAuthorizationServerHTTPClient(ctx context.Context, client *http.Client, resolver ipResolver, selector HTTPRouteSelector) (*http.Client, error) {
	guard := !allowInsecureRemoteURLs() && !skipSSRFCheck(ctx)
	if guard && resolver == nil {
		return nil, fmt.Errorf("IP resolver is nil")
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("HTTP transport %T cannot select a route", base)
	}
	routed := *client
	routed.Transport = &routedAuthorizationServerTransport{base: transport, selector: selector, resolver: resolver, guard: guard}
	return &routed, nil
}

type routedAuthorizationServerTransport struct {
	base     *http.Transport
	selector HTTPRouteSelector
	resolver ipResolver
	guard    bool
}

func (t *routedAuthorizationServerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.guard {
		if err := checkAuthorizationServerRequest(req); err != nil {
			return nil, err
		}
	}
	base := t.base.Clone()
	transport, upstreamResolvesTarget, err := t.selector(req, base)
	if transport != base {
		base.CloseIdleConnections()
	}
	if err != nil {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		return nil, err
	}
	if transport == nil {
		return nil, fmt.Errorf("HTTP route selector returned no transport")
	}
	if transport.Proxy != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("selected HTTP route must not resolve a proxy again")
	}
	if len(transport.TLSNextProto) != 0 {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("selected HTTP route must not use custom TLS protocol callbacks")
	}
	transport.DisableKeepAlives = true
	if t.guard && !upstreamResolvesTarget {
		if transport.DialTLS != nil || //nolint:staticcheck // A legacy TLS dialer would bypass the guarded DialContext.
			transport.DialTLSContext != nil {
			transport.CloseIdleConnections()
			return nil, fmt.Errorf("HTTP transport with a custom TLS dialer cannot be guarded at dial time")
		}
		dial := transport.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid authorization server dial address %q: %w", address, err)
			}
			return dialPublicAddress(ctx, t.resolver, dial, network, host, port)
		}
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		transport.CloseIdleConnections()
	} else {
		resp.Body = &routeResponseBody{ReadCloser: resp.Body, closeIdle: transport.CloseIdleConnections}
	}
	return resp, nil
}

type routeResponseBody struct {
	io.ReadCloser
	closeIdle func()
	once      sync.Once
}

func (b *routeResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.closeIdle)
	}
	return n, err
}

func (b *routeResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.closeIdle)
	return err
}
