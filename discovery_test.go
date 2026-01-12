package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setupTestHTTPClient configures httpClientFunc to accept test TLS certificates
func setupTestHTTPClient(_ *testing.T) func() {
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
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			// Provide resource metadata at well-known endpoint
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL,
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

	// Mock metadata server (separate from MCP server) - TLS
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
			Resource:            "https://api.example.com",
			AuthorizationServer: authServer.URL,
			Scopes:              []string{"read", "write"},
		})
	}))
	defer metadataServer.Close()

	// Mock MCP server (returns 401 WITH WWW-Authenticate) - TLS
	mcpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			// Return 401 WITH WWW-Authenticate header (standard MCP behavior)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"test\", resource_metadata=\"%s\"", metadataServer.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
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
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			// Return resource metadata pointing to non-existent auth server
			baseURL := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL,
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

// TestBuildRFC8414WellKnownURL verifies RFC 8414 Section 3.1 URL construction
func TestBuildRFC8414WellKnownURL(t *testing.T) {
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
