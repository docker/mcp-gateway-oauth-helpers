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

	// Perform DCR
	creds, err := PerformDCR(context.Background(), discovery, "test-server")
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

	// Attempt DCR
	creds, err := PerformDCR(context.Background(), discovery, "test-server")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error when registration endpoint missing")
	}
	if creds != nil {
		t.Error("Expected nil credentials on error")
	}
}
