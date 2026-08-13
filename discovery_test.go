package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	authorizationServerHTTPClientFunc = func(client *http.Client) (*http.Client, error) {
		return client, nil
	}
	return func() {
		httpClientFunc = original
		authorizationServerHTTPClientFunc = originalAuthorizationServerClientFunc
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

func TestDiscoveryRejectsPrivateAuthorizationServerBeforeFetch(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

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
				AuthorizationServer: "https://169.254.169.254/latest/meta-data",
			})
		}
	}))
	defer mcpServer.Close()

	_, err := DiscoverOAuthRequirements(context.Background(), mcpServer.URL+"/mcp")
	if err == nil || !strings.Contains(err.Error(), "blocked range 169.254.0.0/16") {
		t.Fatalf("expected private authorization server rejection, got %v", err)
	}
	if privateDialed.Load() {
		t.Fatal("private authorization server must be rejected before dialing")
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

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestAuthorizationServerClientRejectsPrivateDNSResultBeforeDial(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	var dialed atomic.Bool
	baseClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, fmt.Errorf("unexpected dial")
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(baseClient, staticResolver{
		"auth.example.com": {netip.MustParseAddr("10.0.0.1")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://auth.example.com/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "blocked range 10.0.0.0/8") {
		t.Fatalf("expected private DNS result rejection, got %v", err)
	}
	if dialed.Load() {
		t.Fatal("private DNS result must be rejected before dialing")
	}
}

func TestAuthorizationServerClientRejectsLocalhostByDefault(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	var dialed atomic.Bool
	baseClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, fmt.Errorf("unexpected dial")
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(baseClient, staticResolver{})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://localhost/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "host \"localhost\" is not allowed") {
		t.Fatalf("expected localhost rejection, got %v", err)
	}
	if dialed.Load() {
		t.Fatal("localhost must be rejected before dialing")
	}
}

func TestAuthorizationServerClientRejectsRedirectToPrivateAddress(t *testing.T) {
	t.Setenv(allowInsecureRemoteURLEnv, "")

	var dialCount atomic.Int32
	var dialedAddress string
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirector.Close()

	dialer := &net.Dialer{}
	baseClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialCount.Add(1)
				dialedAddress = address
				return dialer.DialContext(ctx, network, redirector.Listener.Addr().String())
			},
		},
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(baseClient, staticResolver{
		"auth.example.com": {netip.MustParseAddr("93.184.216.34")},
	})
	if err != nil {
		t.Fatalf("creating guarded client: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://auth.example.com/.well-known/oauth-authorization-server", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), "blocked range 169.254.0.0/16") {
		t.Fatalf("expected private redirect rejection, got %v", err)
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("expected only the public redirector to be dialed, got %d dials", got)
	}
	if dialedAddress != "93.184.216.34:443" {
		t.Fatalf("expected the validated public IP to be pinned, got %q", dialedAddress)
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
			result, err := buildRFC8414WellKnownURL(tt.issuer)
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
