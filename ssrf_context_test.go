package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDiscoverySkipSSRFCheckIsRequestScoped(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect=%t", redirect), func(t *testing.T) {
			const privateOrigin = "http://10.48.231.75"
			authOrigin := privateOrigin
			if redirect {
				authOrigin = "http://8.8.8.8"
			}
			var privateFetches atomic.Int32
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/mcp":
					w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", server.URL+"/metadata"))
					w.WriteHeader(http.StatusUnauthorized)
				case "/metadata":
					_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
						Resource:            server.URL + "/mcp",
						AuthorizationServer: authOrigin,
					})
				case "/.well-known/oauth-authorization-server":
					if r.Host == "8.8.8.8" {
						http.Redirect(w, r, privateOrigin+r.URL.Path, http.StatusFound)
						return
					}
					privateFetches.Add(1)
					_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
						Issuer:                authOrigin,
						AuthorizationEndpoint: privateOrigin + "/authorize",
						TokenEndpoint:         privateOrigin + "/token",
					})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)

			// Map every dial to the fixture; the real guard still validates the
			// advertised address before invoking this dialer.
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}
			t.Cleanup(transport.CloseIdleConnections)
			original := httpClientFunc
			httpClientFunc = func() *http.Client { return &http.Client{Transport: transport} }
			t.Cleanup(func() { httpClientFunc = original })

			parent := context.Background()
			trusted := WithSkipSSRFCheck(parent)
			check := func(ctx context.Context, skip bool) {
				discovery, err := DiscoverOAuthRequirements(ctx, server.URL+"/mcp")
				if skip {
					if err != nil {
						t.Errorf("trusted discovery failed: %v", err)
					} else if !discovery.RequiresOAuth || discovery.TokenEndpoint != privateOrigin+"/token" {
						t.Errorf("unexpected discovery: %+v", discovery)
					}
				} else if err == nil || !strings.Contains(err.Error(), "blocked range 10.0.0.0/8") {
					t.Errorf("expected private address rejection, got %v", err)
				}
			}

			check(parent, false)
			if privateFetches.Load() != 0 {
				t.Fatal("guarded discovery reached private metadata")
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(2)
				go func() { defer wg.Done(); check(parent, false) }()
				go func() { defer wg.Done(); check(trusted, true) }()
			}
			wg.Wait()
			check(parent, false)
			if got := privateFetches.Load(); got != 4 {
				t.Errorf("expected only the 4 trusted requests to reach private metadata, got %d", got)
			}
			if got := os.Getenv(allowInsecureRemoteURLEnv); got != "" {
				t.Errorf("discovery changed the process opt-in to %q", got)
			}
		})
	}
}
