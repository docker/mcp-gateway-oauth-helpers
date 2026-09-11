package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// setupTestHTTPClient configures httpClientFunc to accept test TLS certificates
func setupTestHTTPClient(_ *testing.T) func() {
	original := httpClientFunc
	originalAuthorizationServerClientFunc := authorizationServerHTTPClientFunc
	httpClientFunc = func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	authorizationServerHTTPClientFunc = func(_ context.Context, client *http.Client) (*http.Client, error) {
		return client, nil
	}
	return func() {
		httpClientFunc = original
		authorizationServerHTTPClientFunc = originalAuthorizationServerClientFunc
	}
}

// setupInsecureTLSClient configures httpClientFunc to accept test TLS
// certificates but, unlike setupTestHTTPClient, leaves
// authorizationServerHTTPClientFunc untouched so the real SSRF guard runs.
func setupInsecureTLSClient(_ *testing.T) func() {
	original := httpClientFunc
	httpClientFunc = func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return func() {
		httpClientFunc = original
	}
}

// TestDiscoveryFallback_NoWWWAuthenticate verifies the critical fallback behavior
// when MCP server doesn't provide WWW-Authenticate header
//
// This tests the fix for servers like Neon that:
// - Return 401 (correct)
// - Don't provide WWW-Authenticate header (MCP spec violation)
// - Do provide /.well-known/oauth-protected-resource endpoint (RFC 9728 compliant)
func TestDiscoveryFallback_NoWWWAuthenticate(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	// Mock authorization server (TLS)
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			// Use https scheme for test server
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                        baseURL,
				AuthorizationEndpoint:         baseURL + "/authorize",
				TokenEndpoint:                 baseURL + "/token",
				RegistrationEndpoint:          baseURL + "/register",
				CodeChallengeMethodsSupported: []string{"S256"},
			})
			return
		}
	}))
	defer authServer.Close()

	// Mock MCP server (returns 401 WITHOUT WWW-Authenticate) - TLS
	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			// Return 401 WITHOUT WWW-Authenticate header (Neon behavior)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			// Provide resource metadata at well-known endpoint
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/mcp",
				AuthorizationServer: authServer.URL, // httptest.NewTLSServer URL is already https
			})
			return
		}
	}))
	defer mcpServer.Close()

	// Setup logger to verify fallback triggered
	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)

	// Execute discovery
	discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
	// Verify no error
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	// Verify fallback was triggered
	if !logger.containsInfo("fallback: trying well-known") {
		t.Error("Expected fallback to well-known endpoint to be triggered")
	}
	if !logger.containsInfo("no WWW-Authenticate header present") {
		t.Error("Expected warning about missing WWW-Authenticate header")
	}

	// Verify discovery succeeded
	if !discovery.RequiresOAuth {
		t.Error("Expected RequiresOAuth=true")
	}
	if discovery.TokenEndpoint != authServer.URL+"/token" {
		t.Errorf("Expected TokenEndpoint=%s, got %s", authServer.URL+"/token", discovery.TokenEndpoint)
	}
	if !discovery.SupportsPKCE {
		t.Error("Expected SupportsPKCE=true")
	}
}

// TestDiscoveryHappyPath_WithWWWAuthenticate verifies the standard flow
// when server provides proper WWW-Authenticate header
func TestDiscoveryHappyPath_WithWWWAuthenticate(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	// Mock authorization server (TLS)
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                        baseURL,
				AuthorizationEndpoint:         baseURL + "/authorize",
				TokenEndpoint:                 baseURL + "/token",
				CodeChallengeMethodsSupported: []string{"S256"},
			})
			return
		}
	}))
	defer authServer.Close()

	// Mock MCP server (returns 401 WITH WWW-Authenticate) - TLS
	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		if r.URL.Path == "/mcp" {
			// Return 401 WITH WWW-Authenticate header (standard MCP behavior)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"test\", resource_metadata=\"%s/oauth-metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/oauth-metadata" {
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/mcp",
				AuthorizationServer: authServer.URL,
				Scopes:              []string{"read", "write"},
			})
		}
	}))
	defer mcpServer.Close()

	// Setup logger
	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)

	// Execute discovery
	discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
	// Verify no error
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	// Verify WWW-Authenticate was parsed (no fallback)
	if logger.containsInfo("FALLBACK") {
		t.Error("Should not use fallback when WWW-Authenticate present")
	}
	if !logger.containsInfo("WWW-Authenticate header present") {
		t.Error("Expected WWW-Authenticate header to be detected")
	}

	// Verify discovery succeeded
	if !discovery.RequiresOAuth {
		t.Error("Expected RequiresOAuth=true")
	}
	if len(discovery.Scopes) != 2 {
		t.Errorf("Expected 2 scopes from metadata, got %d", len(discovery.Scopes))
	}
	if discovery.ResourceURL != mcpServer.URL+"/mcp" {
		t.Errorf("Expected ResourceURL=%s, got %s", mcpServer.URL+"/mcp", discovery.ResourceURL)
	}
}

// TestDiscoveryError_AuthServerFails verifies error handling
// when authorization server metadata cannot be fetched
func TestDiscoveryError_AuthServerFails(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	// Mock MCP server (returns 401, no WWW-Authenticate) - TLS
	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			// Return resource metadata pointing to non-existent auth server
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/mcp",
				AuthorizationServer: "https://localhost:99999", // Invalid/unreachable
			})
			return
		}
	}))
	defer mcpServer.Close()

	// Execute discovery (should fail)
	discovery, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error when auth server metadata fetch fails")
	}
	if discovery != nil {
		t.Error("Expected nil discovery on error")
	}
	if !strings.Contains(err.Error(), "fetching authorization server metadata") {
		t.Errorf("Expected auth server error, got: %v", err)
	}
}

// TestDiscoveryWarnsButProceedsForPrivateAuthorizationServer proves the
// warn-not-abort default: a private/metadata authorization server address is
// still actually dialed and the real response used, but a warning naming the
// rejected address is logged.
func TestDiscoveryWarnsButProceedsForPrivateAuthorizationServer(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	// No path on the issuer so the well-known suffix check below matches
	// exactly (see buildRFC8414WellKnownURL, which appends the issuer's path
	// after the well-known segment).
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			const baseURL = "https://169.254.169.254"
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                baseURL,
				AuthorizationEndpoint: baseURL + "/authorize",
				TokenEndpoint:         baseURL + "/token",
			})
		}
	}))
	defer authServer.Close()

	original := httpClientFunc
	defer func() { httpClientFunc = original }()

	var privateDialed atomic.Bool
	dialer := &net.Dialer{}
	httpClientFunc = func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					if strings.HasPrefix(address, "169.254.169.254:") {
						privateDialed.Store(true)
						return dialer.DialContext(ctx, network, authServer.Listener.Addr().String())
					}
					return dialer.DialContext(ctx, network, address)
				},
			},
		}
	}

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/mcp",
				AuthorizationServer: "https://169.254.169.254",
			})
		}
	}))
	defer mcpServer.Close()

	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)

	discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
	if err != nil {
		t.Fatalf("expected discovery to proceed despite private authorization server, got error: %v", err)
	}
	if !privateDialed.Load() {
		t.Fatal("expected the private authorization server address to actually be dialed")
	}
	if !logger.containsWarn("169.254") {
		t.Fatalf("expected a warning naming the rejected private address, got: %v", logger.warns)
	}
	if discovery.TokenEndpoint != "https://169.254.169.254/token" {
		t.Fatalf("expected discovery to complete using the real fetch response, got token endpoint %q", discovery.TokenEndpoint)
	}
}

func TestDiscoveryAllowsLocalHTTPAuthorizationServerWithOptIn(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "1")

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", server.URL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            server.URL + "/mcp",
				AuthorizationServer: server.URL,
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                server.URL,
				AuthorizationEndpoint: server.URL + "/authorize",
				TokenEndpoint:         server.URL + "/token",
			})
		}
	}))
	defer server.Close()

	discovery, err := DiscoverOAuthRequirements(context.Background(), server.URL+"/mcp")
	if err != nil {
		t.Fatalf("discovering local OAuth server: %v", err)
	}
	if discovery.AuthorizationServer != server.URL {
		t.Fatalf("expected authorization server %q, got %q", server.URL, discovery.AuthorizationServer)
	}
	if discovery.TokenEndpoint != server.URL+"/token" {
		t.Fatalf("expected token endpoint %q, got %q", server.URL+"/token", discovery.TokenEndpoint)
	}
}

// TestDiscoveryRejectsPlainHTTPLoopbackAuthorizationServerByDefault proves
// that, without WithAllowLocalHTTP, a plain-http localhost authorization
// server is still hard-rejected exactly as today: the well-known URL is
// never even built, let alone fetched.
func TestDiscoveryRejectsPlainHTTPLoopbackAuthorizationServerByDefault(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")
	cleanup := setupInsecureTLSClient(t)
	defer cleanup()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("authorization server should not be contacted when its scheme is hard-rejected")
	}))
	defer authServer.Close()
	localhostAuthServerURL := strings.Replace(authServer.URL, "127.0.0.1", "localhost", 1)

	mcpServer := newMCPServerPointingTo(localhostAuthServerURL)
	defer mcpServer.Close()

	_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err == nil {
		t.Fatal("expected discovery to fail for a plain-http localhost authorization server without WithAllowLocalHTTP")
	}
	if !strings.Contains(err.Error(), "must use https scheme") {
		t.Fatalf("expected an https-scheme rejection, got: %v", err)
	}
}

// TestDiscoveryAllowsPlainHTTPLoopbackAuthorizationServerWithAllowLocalHTTP
// proves WithAllowLocalHTTP's core promise: both an http://localhost and an
// http://127.0.0.1 authorization server become reachable end-to-end through
// DiscoverOAuthRequirements, with no SSRF warning logged (the destination is
// classified as fully allowed, not merely warned-and-proceeded).
func TestDiscoveryAllowsPlainHTTPLoopbackAuthorizationServerWithAllowLocalHTTP(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")
	cleanup := setupInsecureTLSClient(t)
	defer cleanup()

	for _, host := range []string{"localhost", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			var authServer *httptest.Server
			var authServerURL string
			authServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
					_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
						Issuer:                authServerURL,
						AuthorizationEndpoint: authServerURL + "/authorize",
						TokenEndpoint:         authServerURL + "/token",
					})
				}
			}))
			defer authServer.Close()
			authServerURL = strings.Replace(authServer.URL, "127.0.0.1", host, 1)

			mcpServer := newMCPServerPointingTo(authServerURL)
			defer mcpServer.Close()

			logger := &testLogger{}
			ctx := WithAllowLocalHTTP(WithLogger(context.Background(), logger))

			discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
			if err != nil {
				t.Fatalf("expected discovery to succeed with WithAllowLocalHTTP for %s, got error: %v", host, err)
			}
			if discovery.TokenEndpoint != authServerURL+"/token" {
				t.Fatalf("expected token endpoint %q, got %q", authServerURL+"/token", discovery.TokenEndpoint)
			}
			if len(logger.warns) != 0 {
				t.Fatalf("expected no SSRF warnings with WithAllowLocalHTTP, got: %v", logger.warns)
			}
		})
	}
}

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestAuthorizationServerClientWarnsAndDialsPrivateDNSResult(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("private auth server response"))
	}))
	defer authServer.Close()

	var dialedAddress string
	dialer := &net.Dialer{}
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialedAddress = address
				return dialer.DialContext(ctx, network, authServer.Listener.Addr().String())
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(context.Background(), baseClient, staticResolver{
		"auth.example.com": {netip.MustParseAddr("10.0.0.1")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	logger := &testLogger{}
	req, err := http.NewRequestWithContext(WithLogger(context.Background(), logger), http.MethodGet, "https://auth.example.com/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected private DNS result to be dialed anyway, got error: %v", err)
	}
	defer resp.Body.Close()
	if dialedAddress != "10.0.0.1:443" {
		t.Fatalf("expected the resolved private IP to be dialed, got %q", dialedAddress)
	}
	if !logger.containsWarn("10.0.0.0/8") {
		t.Fatalf("expected a warning naming the blocked range, got: %v", logger.warns)
	}
}

// TestAuthorizationServerClientAllowLocalHTTPDoesNotBypassPrivateAddress
// proves WithAllowLocalHTTP's carve-out is scoped to loopback only: a
// non-local private address (10.0.0.5) is not silently allowed through it,
// it still falls through to the warn-and-proceed default exactly as without
// the option.
func TestAuthorizationServerClientAllowLocalHTTPDoesNotBypassPrivateAddress(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("private auth server response"))
	}))
	defer authServer.Close()

	var dialedAddress string
	dialer := &net.Dialer{}
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialedAddress = address
				return dialer.DialContext(ctx, network, authServer.Listener.Addr().String())
			},
		},
	}
	ctx := WithAllowLocalHTTP(context.Background())
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, baseClient, staticResolver{
		"auth.example.com": {netip.MustParseAddr("10.0.0.5")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	logger := &testLogger{}
	req, err := http.NewRequestWithContext(WithLogger(ctx, logger), http.MethodGet, "https://auth.example.com/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected private DNS result to be dialed anyway, got error: %v", err)
	}
	defer resp.Body.Close()
	if dialedAddress != "10.0.0.5:443" {
		t.Fatalf("expected the resolved private IP to be dialed, got %q", dialedAddress)
	}
	if !logger.containsWarn("10.0.0.0/8") {
		t.Fatalf("expected WithAllowLocalHTTP to still warn on a non-local private address, got: %v", logger.warns)
	}
}

func TestAuthorizationServerClientWarnsOnLocalhostByDefault(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	dialer := &net.Dialer{}
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server.Listener.Addr().String())
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(context.Background(), baseClient, staticResolver{
		"localhost": {netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	logger := &testLogger{}
	req, err := http.NewRequestWithContext(WithLogger(context.Background(), logger), http.MethodGet, "https://localhost/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected localhost request to proceed anyway, got error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the real response, got status %d", resp.StatusCode)
	}
	if !logger.containsWarn("localhost") {
		t.Fatalf("expected a warning naming the rejected localhost host, got: %v", logger.warns)
	}
}

func TestAuthorizationServerClientWarnsOnRedirectToPrivateAddress(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	privateTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("private metadata"))
	}))
	defer privateTarget.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirector.Close()

	var dialedAddresses []string
	dialer := &net.Dialer{}
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialedAddresses = append(dialedAddresses, address)
				target := redirector.Listener.Addr().String()
				if strings.HasPrefix(address, "169.254.169.254:") {
					target = privateTarget.Listener.Addr().String()
				}
				return dialer.DialContext(ctx, network, target)
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(context.Background(), baseClient, staticResolver{
		"auth.example.com": {netip.MustParseAddr("93.184.216.34")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	logger := &testLogger{}
	req, err := http.NewRequestWithContext(WithLogger(context.Background(), logger), http.MethodGet, "https://auth.example.com/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected redirect to a private address to proceed anyway, got error: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if string(body) != "private metadata" {
		t.Fatalf("expected the real private-target response, got %q", body)
	}
	if len(dialedAddresses) != 2 {
		t.Fatalf("expected two dials (public redirector, then the private redirect target), got %d: %v", len(dialedAddresses), dialedAddresses)
	}
	if dialedAddresses[0] != "93.184.216.34:443" {
		t.Fatalf("expected the validated public IP to be pinned for the first dial, got %q", dialedAddresses[0])
	}
	if dialedAddresses[1] != "169.254.169.254:443" {
		t.Fatalf("expected the redirect target to still be dialed, got %q", dialedAddresses[1])
	}
	if !logger.containsWarn("169.254.0.0/16") {
		t.Fatalf("expected a warning naming the blocked redirect target, got: %v", logger.warns)
	}
}

// newLoopbackAuthServer starts a TLS test server (bound to loopback, e.g.
// 127.0.0.1) that serves RFC 8414 authorization server metadata. Its own URL
// is used as the issuer/authorization server, so discovering it exercises
// the authorization-server SSRF guard against a genuinely private address.
func newLoopbackAuthServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                baseURL,
				AuthorizationEndpoint: baseURL + "/authorize",
				TokenEndpoint:         baseURL + "/token",
			})
		}
	}))
}

func newMCPServerPointingTo(authServerURL string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/mcp",
				AuthorizationServer: authServerURL,
			})
		}
	}))
}

// TestDiscoverySkipSSRFCheckAllowsLoopbackWithoutWarning proves
// WithSkipSSRFCheck turns the guard fully off: discovery against a
// loopback authorization server succeeds and logs no SSRF warning at all.
func TestDiscoverySkipSSRFCheckAllowsLoopbackWithoutWarning(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")
	cleanup := setupInsecureTLSClient(t)
	defer cleanup()

	authServer := newLoopbackAuthServer()
	defer authServer.Close()
	mcpServer := newMCPServerPointingTo(authServer.URL)
	defer mcpServer.Close()

	logger := &testLogger{}
	ctx := WithSkipSSRFCheck(WithLogger(context.Background(), logger))

	discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
	if err != nil {
		t.Fatalf("expected discovery to succeed with WithSkipSSRFCheck, got error: %v", err)
	}
	if discovery.TokenEndpoint != authServer.URL+"/token" {
		t.Fatalf("expected token endpoint %q, got %q", authServer.URL+"/token", discovery.TokenEndpoint)
	}
	if len(logger.warns) != 0 {
		t.Fatalf("expected no warnings with WithSkipSSRFCheck, got: %v", logger.warns)
	}
}

// TestDiscoveryWarnsAndProceedsForLoopbackAuthorizationServerByDefault proves
// the default (check "on") posture: the same loopback discovery still
// succeeds against the real address, but logs a warning identifying it.
func TestDiscoveryWarnsAndProceedsForLoopbackAuthorizationServerByDefault(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")
	cleanup := setupInsecureTLSClient(t)
	defer cleanup()

	authServer := newLoopbackAuthServer()
	defer authServer.Close()
	mcpServer := newMCPServerPointingTo(authServer.URL)
	defer mcpServer.Close()

	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)

	discovery, err := DiscoverOAuthRequirements(ctx, mcpServer.URL+"/mcp")
	if err != nil {
		t.Fatalf("expected discovery to proceed despite the loopback authorization server, got error: %v", err)
	}
	if discovery.TokenEndpoint != authServer.URL+"/token" {
		t.Fatalf("expected token endpoint %q, got %q", authServer.URL+"/token", discovery.TokenEndpoint)
	}
	if !logger.containsWarn("127.0.0.1") {
		t.Fatalf("expected a warning identifying the rejected loopback address, got: %v", logger.warns)
	}
}

// TestDiscoveryStillFailsForUnrelatedAuthorizationServerErrors proves that
// warn-not-abort only changes the "this address is private" classification:
// a public, reachable authorization server that fails for an unrelated
// reason (bad status, malformed body) still hard-fails discovery exactly as
// before.
func TestDiscoveryStillFailsForUnrelatedAuthorizationServerErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "500 status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: "returned status 500",
		},
		{
			name: "malformed JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("{not json"))
			},
			wantErr: "parsing JSON response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupTestHTTPClient(t)
			defer cleanup()

			authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
					tt.handler(w, r)
				}
			}))
			defer authServer.Close()

			mcpServer := newMCPServerPointingTo(authServer.URL)
			defer mcpServer.Close()

			_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected hard failure containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestDiscoveryRejectsCrossOriginResourceMetadataBeforeFetch(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	var metadataCalled atomic.Bool
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		metadataCalled.Store(true)
	}))
	defer metadataServer.Close()

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", metadataServer.URL))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer mcpServer.Close()

	_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err == nil || !strings.Contains(err.Error(), "must use the same origin") {
		t.Fatalf("expected same-origin validation error, got %v", err)
	}
	if metadataCalled.Load() {
		t.Fatal("cross-origin resource metadata endpoint must not be fetched")
	}
}

func TestDiscoveryRejectsCrossOriginResourceMetadataRedirect(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	var redirectTargetCalled atomic.Bool
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectTargetCalled.Store(true)
	}))
	defer redirectTarget.Close()

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			http.Redirect(w, r, redirectTarget.URL+"/captured", http.StatusFound)
		}
	}))
	defer mcpServer.Close()

	_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err == nil || !strings.Contains(err.Error(), "must use the same origin") {
		t.Fatalf("expected redirected metadata origin error, got %v", err)
	}
	if redirectTargetCalled.Load() {
		t.Fatal("cross-origin resource metadata redirect target must not be fetched")
	}
}

func TestDiscoveryRejectsMismatchedProtectedResource(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL + "/other",
				AuthorizationServer: "https://auth.example.com",
			})
		}
	}))
	defer mcpServer.Close()

	_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err == nil || !strings.Contains(err.Error(), "does not match requested resource") {
		t.Fatalf("expected protected resource mismatch error, got %v", err)
	}
}

// TestDiscoveryAllowsOriginProtectedResourceForPathBearingEndpoint guards a
// real-world shape: a resource server publishes its protected-resource
// document with a bare-origin `resource` (no path) even though the MCP
// endpoint being discovered has a path. Slack's MCP server does exactly this
// (resource "https://mcp.slack.com" for endpoint
// "https://mcp.slack.com/mcp"). RFC 8707 resource indicators identify a
// resource server rather than echo the request URL verbatim, so this must
// succeed rather than fail as a mismatch — only a metadata resource naming
// some OTHER path (TestDiscoveryRejectsMismatchedProtectedResource) is
// rejected.
func TestDiscoveryAllowsOriginProtectedResourceForPathBearingEndpoint(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                baseURL,
				AuthorizationEndpoint: baseURL + "/authorize",
				TokenEndpoint:         baseURL + "/token",
			})
		}
	}))
	defer authServer.Close()

	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=\"%s/metadata\"", baseURL))
			w.WriteHeader(http.StatusUnauthorized)
		case "/metadata":
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL,
				AuthorizationServer: authServer.URL,
			})
		}
	}))
	defer mcpServer.Close()

	discovery, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err != nil {
		t.Fatalf("expected origin-only protected resource to be accepted, got error: %v", err)
	}
	if !discovery.RequiresOAuth {
		t.Error("expected RequiresOAuth=true")
	}
}

func TestFetchAuthorizationServerMetadataRejectsIssuerMismatch(t *testing.T) {
	cleanup := setupTestHTTPClient(t)
	defer cleanup()

	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "https://" + r.Host
		_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
			Issuer:                baseURL + "/",
			AuthorizationEndpoint: baseURL + "/authorize",
			TokenEndpoint:         baseURL + "/token",
		})
	}))
	defer authServer.Close()

	_, err := fetchAuthorizationServerMetadata(context.Background(), httpClientFunc(), authServer.URL)
	if err == nil || !strings.Contains(err.Error(), "does not match requested issuer") {
		t.Fatalf("expected exact issuer mismatch error, got %v", err)
	}
}

func TestBuildRFC9728WellKnownURL(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		expected string
		wantErr  bool
	}{
		{
			name:     "origin resource",
			resource: "https://example.com",
			expected: "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:     "path and query",
			resource: "https://EXAMPLE.COM/mcp%20server?tenant=one",
			expected: "https://example.com/.well-known/oauth-protected-resource/mcp%20server?tenant=one",
		},
		{
			name:     "root path",
			resource: "https://example.com/",
			expected: "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:     "fragment rejected",
			resource: "https://example.com/mcp#fragment",
			wantErr:  true,
		},
		{
			name:     "relative URL rejected",
			resource: "/mcp",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := buildRFC9728WellKnownURL(tt.resource)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.resource)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if actual != tt.expected {
				t.Errorf("buildRFC9728WellKnownURL(%q) = %q, want %q", tt.resource, actual, tt.expected)
			}
		})
	}
}

func TestValidateSameOrigin(t *testing.T) {
	tests := []struct {
		name        string
		serverURL   string
		metadataURL string
		wantErr     bool
	}{
		{name: "same origin", serverURL: "https://EXAMPLE.com/mcp", metadataURL: "https://example.COM/metadata"},
		{name: "equivalent default port", serverURL: "https://example.com/mcp", metadataURL: "https://example.com:443/metadata"},
		{name: "sibling host", serverURL: "https://mcp.example.com/mcp", metadataURL: "https://metadata.example.com/metadata", wantErr: true},
		{name: "different scheme", serverURL: "https://example.com/mcp", metadataURL: "http://example.com/metadata", wantErr: true},
		{name: "different port", serverURL: "https://example.com/mcp", metadataURL: "https://example.com:8443/metadata", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSameOrigin(tt.serverURL, tt.metadataURL)
			if tt.wantErr && err == nil {
				t.Fatal("expected origin mismatch")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected origin error: %v", err)
			}
		})
	}
}

// TestBuildRFC8414WellKnownURL verifies RFC 8414 Section 3.1 URL construction
func TestBuildRFC8414WellKnownURL(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	tests := []struct {
		name     string
		issuer   string
		expected string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "simple issuer without path",
			issuer:   "https://example.com",
			expected: "https://example.com/.well-known/oauth-authorization-server",
		},
		{
			name:     "issuer with path",
			issuer:   "https://access.stripe.com/mcp",
			expected: "https://access.stripe.com/.well-known/oauth-authorization-server/mcp",
		},
		{
			name:     "issuer with uppercase host (should lowercase)",
			issuer:   "https://EXAMPLE.COM/path",
			expected: "https://example.com/.well-known/oauth-authorization-server/path",
		},
		{
			name:    "invalid URL",
			issuer:  "://invalid",
			wantErr: true,
			errMsg:  "invalid issuer URL",
		},
		{
			name:    "http scheme rejected (RFC 8414 requires https)",
			issuer:  "http://example.com",
			wantErr: true,
			errMsg:  "must use https scheme",
		},
		{
			name:    "query parameters rejected (RFC 8414 Section 2)",
			issuer:  "https://example.com?foo=bar",
			wantErr: true,
			errMsg:  "must not contain query parameters",
		},
		{
			name:    "fragment rejected (RFC 8414 Section 2)",
			issuer:  "https://example.com#fragment",
			wantErr: true,
			errMsg:  "must not contain fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildRFC8414WellKnownURL(context.Background(), tt.issuer)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for issuer %q, got nil", tt.issuer)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for issuer %q: %v", tt.issuer, err)
			}
			if result != tt.expected {
				t.Errorf("buildRFC8414WellKnownURL(%q)\n  got:  %s\n  want: %s", tt.issuer, result, tt.expected)
			}
		})
	}
}

// TestBuildRFC8414WellKnownURLAllowLocalHTTP proves the http-scheme
// carve-out is scoped to WithAllowLocalHTTP plus a loopback host: it accepts
// http for localhost/127.0.0.1 issuers, but still rejects http for a
// non-local issuer even when the option is set.
func TestBuildRFC8414WellKnownURLAllowLocalHTTP(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	tests := []struct {
		name     string
		issuer   string
		expected string
		wantErr  bool
	}{
		{
			name:     "http localhost issuer is accepted",
			issuer:   "http://localhost:8080",
			expected: "http://localhost:8080/.well-known/oauth-authorization-server",
		},
		{
			name:     "http loopback IP issuer is accepted",
			issuer:   "http://127.0.0.1:8080",
			expected: "http://127.0.0.1:8080/.well-known/oauth-authorization-server",
		},
		{
			name:    "http non-local issuer is still rejected",
			issuer:  "http://example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildRFC8414WellKnownURL(WithAllowLocalHTTP(context.Background()), tt.issuer)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for issuer %q, got nil", tt.issuer)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for issuer %q: %v", tt.issuer, err)
			}
			if result != tt.expected {
				t.Errorf("buildRFC8414WellKnownURL(%q)\n  got:  %s\n  want: %s", tt.issuer, result, tt.expected)
			}
		})
	}

	if _, err := buildRFC8414WellKnownURL(context.Background(), "http://localhost:8080"); err == nil {
		t.Fatal("expected http localhost issuer to be rejected without WithAllowLocalHTTP")
	}
}
