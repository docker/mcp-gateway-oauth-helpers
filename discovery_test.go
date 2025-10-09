package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscoveryFallback_NoWWWAuthenticate verifies the critical fallback behavior
// when MCP server doesn't provide WWW-Authenticate header
//
// This tests the fix for servers like Neon that:
// - Return 401 (correct)
// - Don't provide WWW-Authenticate header (MCP spec violation)
// - Do provide /.well-known/oauth-protected-resource endpoint (RFC 9728 compliant)
func TestDiscoveryFallback_NoWWWAuthenticate(t *testing.T) {
	// Mock authorization server
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			// Use r.Host to construct URLs dynamically
			baseURL := "http://" + r.Host
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

	// Mock MCP server (returns 401 WITHOUT WWW-Authenticate)
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			// Return 401 WITHOUT WWW-Authenticate header (Neon behavior)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			// Provide resource metadata at well-known endpoint
			baseURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL,
				AuthorizationServer: authServer.URL,
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
	if !logger.containsInfo("FALLBACK: trying well-known") {
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
	// Mock authorization server
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server") {
			baseURL := "http://" + r.Host
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

	// Mock metadata server (separate from MCP server)
	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
			Resource:            "https://api.example.com",
			AuthorizationServer: authServer.URL,
			Scopes:              []string{"read", "write"},
		})
	}))
	defer metadataServer.Close()

	// Mock MCP server (returns 401 WITH WWW-Authenticate)
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	// Mock MCP server (returns 401, no WWW-Authenticate)
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			// Return resource metadata pointing to non-existent auth server
			baseURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:            baseURL,
				AuthorizationServer: "http://localhost:99999", // Invalid/unreachable
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
