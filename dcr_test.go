package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPerformDCR_PublicClient verifies Dynamic Client Registration
// for public clients (no client secret)
func TestPerformDCR_PublicClient(t *testing.T) {
	var capturedRequest *DCRRequest

	// Mock registration endpoint
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture and verify the request
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedRequest)

		// Return successful registration response
		_ = json.NewEncoder(w).Encode(DCRResponse{
			ClientID:                "test-client-id-123",
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			RedirectURIs:            []string{"https://mcp.docker.com/oauth/callback"},
		})
	}))
	defer regServer.Close()

	// Create discovery with registration endpoint
	discovery := &Discovery{
		RegistrationEndpoint:  regServer.URL,
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		ResourceURL:           "https://api.example.com",
		Scopes:                []string{"read", "write"},
	}

	// Perform DCR (empty redirectURI uses default)
	creds, err := PerformDCR(context.Background(), discovery, "test-server", "")
	// Verify no error
	if err != nil {
		t.Fatalf("DCR failed: %v", err)
	}

	// Verify credentials
	if creds.ClientID != "test-client-id-123" {
		t.Errorf("Expected ClientID=test-client-id-123, got %s", creds.ClientID)
	}
	if !creds.IsPublic {
		t.Error("Expected IsPublic=true for public client")
	}
	if creds.ServerURL != "https://api.example.com" {
		t.Errorf("Expected ServerURL=https://api.example.com, got %s", creds.ServerURL)
	}

	// Verify DCR request was correct
	if capturedRequest == nil {
		t.Fatal("DCR request not captured")
	}
	if capturedRequest.TokenEndpointAuthMethod != "none" {
		t.Errorf("Expected token_endpoint_auth_method=none for public client, got %s", capturedRequest.TokenEndpointAuthMethod)
	}
	if len(capturedRequest.RedirectURIs) == 0 {
		t.Error("Expected redirect_uris to be set")
	}
	if len(capturedRequest.GrantTypes) == 0 {
		t.Error("Expected grant_types to be set")
	}
}

// TestPerformDCR_NoRegistrationEndpoint verifies error handling
// when registration endpoint is not available
func TestPerformDCR_NoRegistrationEndpoint(t *testing.T) {
	// Create discovery WITHOUT registration endpoint
	discovery := &Discovery{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		RegistrationEndpoint:  "", // Empty - DCR not supported
	}

	// Attempt DCR (empty redirectURI uses default)
	creds, err := PerformDCR(context.Background(), discovery, "test-server", "")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error when registration endpoint missing")
	}
	if creds != nil {
		t.Error("Expected nil credentials on error")
	}
}

// TestIsValidRedirectURI verifies redirect URI validation logic
func TestIsValidRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		expectError bool
		description string
	}{
		{
			name:        "empty string",
			redirectURI: "",
			expectError: false,
			description: "Empty string should be allowed (uses default)",
		},
		{
			name:        "localhost http",
			redirectURI: "http://localhost:5000/callback",
			expectError: false,
			description: "Localhost with HTTP should be allowed",
		},
		{
			name:        "localhost https",
			redirectURI: "https://localhost:5000/callback",
			expectError: false,
			description: "Localhost with HTTPS should be allowed",
		},
		{
			name:        "127.0.0.1",
			redirectURI: "http://127.0.0.1:8080/callback",
			expectError: false,
			description: "127.0.0.1 should be allowed",
		},
		{
			name:        "IPv6 localhost",
			redirectURI: "http://[::1]:8080/callback",
			expectError: false,
			description: "IPv6 localhost should be allowed",
		},
		{
			name:        "mcp.docker.com production",
			redirectURI: "https://mcp.docker.com/oauth/callback",
			expectError: false,
			description: "Production mcp.docker.com should be allowed",
		},
		{
			name:        "evil domain",
			redirectURI: "https://evil.com/callback",
			expectError: true,
			description: "Arbitrary domains should be blocked",
		},
		{
			name:        "attacker ngrok",
			redirectURI: "https://attacker.ngrok.io/callback",
			expectError: true,
			description: "Attacker-controlled domains should be blocked",
		},
		{
			name:        "subdomain of docker.com",
			redirectURI: "https://evil.docker.com/callback",
			expectError: true,
			description: "Only mcp.docker.com should be allowed, not subdomains",
		},
		{
			name:        "invalid URL",
			redirectURI: "not-a-valid-url",
			expectError: true,
			description: "Invalid URL format should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidRedirectURI(tt.redirectURI)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %q (%s)", tt.redirectURI, tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %q: %v (%s)", tt.redirectURI, err, tt.description)
			}
		})
	}
}
