package oauth

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPRouteSelectorIsolatesHTTPProtocols(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		name := "http1"
		if useHTTP2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			newOrigin := func(label string) *httptest.Server {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, label)
				}))
				s.EnableHTTP2 = useHTTP2
				s.StartTLS()
				t.Cleanup(s.Close)
				return s
			}
			first, second := newOrigin("first"), newOrigin("second")
			var selections int
			ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
				origin := first
				if selections%2 != 0 {
					origin = second
				}
				selections++
				base.Proxy = nil
				base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != "example.com:443" {
						return nil, errors.New("route destination changed")
					}
					return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
				}
				return base, true, nil
			})
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, first.Client(), staticResolver{})
			if err != nil {
				t.Fatal(err)
			}
			client.Timeout = 5 * time.Second
			for i, want := range []string{"first", "second", "first", "second"} {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || string(body) != want {
					t.Fatalf("request %d: body=%q error=%v, want %q", i, body, err, want)
				}
				wantProto := 1
				if useHTTP2 {
					wantProto = 2
				}
				if resp.ProtoMajor != wantProto {
					t.Fatalf("protocol=%s, want major %d", resp.Proto, wantProto)
				}
			}
			if selections != 4 {
				t.Fatalf("selections=%d, want 4", selections)
			}
		})
	}
}

func TestHTTPRouteSelectorDirectAdvisoryAndSkip(t *testing.T) {
	for _, skip := range []bool{false, true} {
		name := "guarded"
		if skip {
			name = "skip"
		}
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "metadata")
			}))
			defer origin.Close()
			logger := &testLogger{}
			ctx := WithLogger(context.Background(), logger)
			if skip {
				ctx = WithSkipSSRFCheck(ctx)
			}
			var dialed string
			ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
				base.Proxy = nil
				base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					dialed = address
					return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
				}
				return base, false, nil
			})
			resolver := staticResolver{"example.com": {netip.MustParseAddr("127.0.0.1")}}
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, origin.Client(), resolver)
			if err != nil {
				t.Fatal(err)
			}
			client.Timeout = 5 * time.Second
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			wantAddress := "127.0.0.1:443"
			if skip {
				wantAddress = "example.com:443"
			}
			if dialed != wantAddress {
				t.Fatalf("dialed %q, want %q", dialed, wantAddress)
			}
			if skip && len(logger.warns) != 0 {
				t.Fatalf("skip logged warnings: %v", logger.warns)
			}
			if !skip && !strings.Contains(strings.Join(logger.warns, "\n"), "resolved to disallowed address") {
				t.Fatalf("missing advisory warning: %v", logger.warns)
			}
		})
	}
}

func TestHTTPRouteSelectorRunsForRedirect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "https://redirect.example.com/metadata", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "redirected")
	}))
	defer origin.Close()
	var destinations []string
	ctx := WithHTTPRouteSelector(context.Background(), func(req *http.Request, base *http.Transport) (*http.Transport, bool, error) {
		destinations = append(destinations, req.URL.Host)
		base.Proxy = nil
		base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
		}
		return base, true, nil
	})
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, origin.Client(), staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(destinations, ",") != "example.com,redirect.example.com" {
		t.Fatalf("selected destinations: %v", destinations)
	}
}

type routeObservedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *routeObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestHTTPRouteSelectorReleasesTransport(t *testing.T) {
	for _, scenario := range []struct {
		name           string
		readEOF, http2 bool
	}{
		{name: "http1-close"},
		{name: "http1-eof", readEOF: true},
		{name: "http2-close", http2: true},
		{name: "http2-eof", readEOF: true, http2: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, strings.Repeat("x", 4096))
			}))
			origin.EnableHTTP2 = scenario.http2
			origin.StartTLS()
			defer origin.Close()
			connections := make(chan *routeObservedConn, 1)
			ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
				base.Proxy = nil
				base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
					if err != nil {
						return nil, err
					}
					observed := &routeObservedConn{Conn: conn, closed: make(chan struct{})}
					connections <- observed
					return observed, nil
				}
				return base, true, nil
			})
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, origin.Client(), staticResolver{})
			if err != nil {
				t.Fatal(err)
			}
			client.Timeout = 5 * time.Second
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			wantProto := 1
			if scenario.http2 {
				wantProto = 2
			}
			if resp.ProtoMajor != wantProto {
				t.Fatalf("protocol=%s, want major %d", resp.Proto, wantProto)
			}
			conn := <-connections
			if scenario.readEOF {
				if _, err := io.Copy(io.Discard, resp.Body); err != nil {
					t.Fatal(err)
				}
			} else if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-conn.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("selected transport retained its connection")
			}
		})
	}
}

type routeRequestBody struct {
	io.Reader
	closed bool
}

func (b *routeRequestBody) Close() error {
	b.closed = true
	return nil
}

func TestHTTPRouteSelectorFailureDoesNotFallBack(t *testing.T) {
	sentinel := errors.New("selection failed")
	var dials atomic.Int32
	base := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected fallback")
	}}
	ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, owned *http.Transport) (*http.Transport, bool, error) {
		if owned == base {
			t.Fatal("selector received shared transport")
		}
		return owned, false, sentinel
	})
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{Transport: base}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	body := &routeRequestBody{Reader: strings.NewReader("{}")}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", body)
	_, err = client.Do(req)
	if !errors.Is(err, sentinel) || dials.Load() != 0 {
		t.Fatalf("error=%v dials=%d", err, dials.Load())
	}
	if !body.closed {
		t.Fatal("selection failure left the request body open")
	}
}

func TestHTTPRouteSelectorRejectsInvalidRoutes(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		selectRoute HTTPRouteSelector
		wantError   string
	}{
		{name: "nil transport", selectRoute: func(_ *http.Request, _ *http.Transport) (*http.Transport, bool, error) {
			return nil, false, nil
		}},
		{name: "proxy re-resolution", selectRoute: func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
			base.Proxy = http.ProxyFromEnvironment
			return base, true, nil
		}},
		{name: "direct custom TLS dialer", selectRoute: func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
			base.Proxy = nil
			base.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unexpected TLS dial")
			}
			return base, false, nil
		}},
		{name: "direct legacy dialer", wantError: "requires DialContext", selectRoute: func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
			base.Proxy = nil
			base.Dial = func(string, string) (net.Conn, error) { //nolint:staticcheck // Verify legacy dialers are rejected rather than silently bypassed.
				return nil, errors.New("unexpected legacy dial")
			}
			return base, false, nil
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := WithHTTPRouteSelector(context.Background(), scenario.selectRoute)
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{Transport: &http.Transport{}}, staticResolver{})
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
			if _, err := client.Do(req); err == nil {
				t.Fatal("invalid route was accepted")
			} else if scenario.wantError != "" && !strings.Contains(err.Error(), scenario.wantError) {
				t.Fatalf("error=%v, want %q", err, scenario.wantError)
			}
		})
	}
}

func TestHTTPRouteSelectorRoundTripError(t *testing.T) {
	sentinel := errors.New("captured route unavailable")
	var selections atomic.Int32
	ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
		selections.Add(1)
		base.Proxy = nil
		base.DialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, sentinel
		}
		return base, true, nil
	})
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{}, staticResolver{})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	_, err = client.Do(req)
	if !errors.Is(err, sentinel) || selections.Load() != 1 {
		t.Fatalf("error=%v selections=%d", err, selections.Load())
	}
}

func TestHTTPRouteSelectorRejectsSharedProtocolCallbacks(t *testing.T) {
	for _, upstreamResolvesTarget := range []bool{false, true} {
		name := "direct"
		if upstreamResolvesTarget {
			name = "proxy"
		}
		t.Run(name, func(t *testing.T) {
			var callbacks atomic.Int32
			base := &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
				"h2": func(string, *tls.Conn) http.RoundTripper {
					callbacks.Add(1)
					return noopBaseRoundTripper{}
				},
			}}
			ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, owned *http.Transport) (*http.Transport, bool, error) {
				owned.Proxy = nil
				return owned, upstreamResolvesTarget, nil
			})
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{Transport: base}, staticResolver{})
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
			_, err = client.Do(req)
			if err == nil || !strings.Contains(err.Error(), "custom TLS protocol callbacks") {
				t.Fatalf("expected protocol callback rejection, got %v", err)
			}
			if callbacks.Load() != 0 {
				t.Fatalf("custom callbacks invoked %d times", callbacks.Load())
			}
		})
	}
}

func routeTestResolver(t *testing.T, answer net.IP) (*net.Resolver, *atomic.Int32) {
	t.Helper()
	var workers sync.WaitGroup
	calls := &atomic.Int32{}
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		client, server := net.Pipe()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, query); err != nil || len(query) < 17 {
				return
			}
			end := 12
			for end < len(query) && query[end] != 0 {
				end += int(query[end]) + 1
			}
			end++
			if end+4 > len(query) {
				return
			}
			kind := binary.BigEndian.Uint16(query[end : end+2])
			reply := append([]byte(nil), query[:end+4]...)
			reply[2], reply[3] = 0x81, 0x80
			for i := 6; i < 12; i++ {
				reply[i] = 0
			}
			if kind == 1 {
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				reply = append(reply, answer.To4()...)
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
			_, _ = server.Write(append(size[:], reply...))
		}()
		return client, nil
	}}
	t.Cleanup(workers.Wait)
	return resolver, calls
}

func TestHTTPResolverSelectedDirect(t *testing.T) {
	for _, skip := range []bool{false, true} {
		name := "guarded"
		if skip {
			name = "skip"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(allowInsecureRemoteURLEnv, "")
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "metadata") }))
			t.Cleanup(origin.Close)
			resolver, calls := routeTestResolver(t, net.IPv4(127, 0, 0, 1))
			logger := &testLogger{}
			ctx, recorder := contextWithSSRFRecorder(WithLogger(context.Background(), logger))
			if skip {
				ctx = WithSkipSSRFCheck(ctx)
			}
			ctx = WithHTTPResolver(ctx, resolver)
			var address string
			ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
				base.Proxy = nil
				base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					address = addr
					return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
				}
				return base, false, nil
			})
			client, err := newAuthorizationServerHTTPClient(ctx, origin.Client())
			if err != nil {
				t.Fatal(err)
			}
			client.Timeout = 5 * time.Second
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://selected.example.com/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if address != "127.0.0.1:443" || calls.Load() == 0 {
				t.Fatalf("address=%q DNS calls=%d", address, calls.Load())
			}
			warned := strings.Contains(strings.Join(logger.warns, "\n"), "resolved to disallowed address")
			if warned == skip {
				t.Fatalf("skip=%v warnings=%v", skip, logger.warns)
			}
			if recorder.failed == skip {
				t.Fatalf("skip=%v recorded rejection=%v", skip, recorder.failed)
			}
		})
	}
}

func TestHTTPResolverNotUsedForUpstream(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "remote") }))
	t.Cleanup(origin.Close)
	var lookups atomic.Int32
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("unexpected local DNS lookup")
	}}
	ctx := WithHTTPResolver(context.Background(), resolver)
	ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) {
		base.Proxy = nil
		base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
		}
		return base, true, nil
	})
	client, err := newAuthorizationServerHTTPClient(ctx, origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = 5 * time.Second
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://selected.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 0 {
		t.Fatalf("proxied request performed %d local lookups", lookups.Load())
	}
}

func TestHTTPResolverNilUsesDefault(t *testing.T) {
	ctx := WithHTTPResolver(context.Background(), nil)
	ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, base *http.Transport) (*http.Transport, bool, error) { return base, false, nil })
	client, err := newAuthorizationServerHTTPClient(ctx, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	routed, ok := client.Transport.(*routedAuthorizationServerTransport)
	if !ok || routed.resolver != net.DefaultResolver {
		t.Fatalf("resolver=%v, want net.DefaultResolver", client.Transport)
	}
}

func TestHTTPRouteSelectorRejectsUpstreamTLSDialers(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "DialTLSContext"
		if legacy {
			name = "DialTLS"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			ctx := WithHTTPRouteSelector(context.Background(), func(_ *http.Request, owned *http.Transport) (*http.Transport, bool, error) {
				owned.Proxy = nil
				if legacy {
					owned.DialTLS = func(string, string) (net.Conn, error) { //nolint:staticcheck // Verify legacy TLS dialing cannot bypass operation binding.
						calls.Add(1)
						return nil, errors.New("unexpected TLS dial")
					}
				} else {
					owned.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
						calls.Add(1)
						return nil, errors.New("unexpected TLS dial")
					}
				}
				return owned, true, nil
			})
			client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{}, staticResolver{})
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://auth.example.com/metadata", nil)
			_, err = client.Do(req)
			if err == nil || !strings.Contains(err.Error(), "must not use custom TLS dialers") || calls.Load() != 0 {
				t.Fatalf("error=%v TLS dials=%d", err, calls.Load())
			}
		})
	}
}
