package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestRegisterClient_ReturnsFullRegistration(t *testing.T) {
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DCRResponse{
			ClientID:                "client-1",
			ClientSecret:            "secret-1",
			ClientSecretExpiresAt:   1900000000,
			RegistrationAccessToken: "rat-1",
			RegistrationClientURI:   "https://auth.example.com/register/client-1",
			RedirectURIs:            []string{"https://mcp.docker.com/oauth/callback"},
			Scope:                   "mcp:read mcp:write",
			TokenEndpointAuthMethod: "client_secret_basic",
		})
	}))
	defer regServer.Close()

	discovery := &Discovery{
		Issuer:               "https://auth.example.com",
		RegistrationEndpoint: regServer.URL,
		Scopes:               []string{"mcp:read"},
	}

	reg, err := RegisterClient(context.Background(), discovery, "test-server", DCRConfig{})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	want := &ClientRegistration{
		Issuer:                  "https://auth.example.com",
		ClientID:                "client-1",
		ClientSecret:            "secret-1",
		ClientSecretExpiresAt:   1900000000,
		RegistrationAccessToken: "rat-1",
		RegistrationClientURI:   "https://auth.example.com/register/client-1",
		RedirectURIs:            []string{"https://mcp.docker.com/oauth/callback"},
		Scope:                   "mcp:read mcp:write",
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	if !reflect.DeepEqual(reg, want) {
		t.Fatalf("registration mismatch:\n got %#v\nwant %#v", reg, want)
	}
}

func TestRegisterClient_FallsBackToRequestedMetadata(t *testing.T) {
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer regServer.Close()

	discovery := &Discovery{
		Issuer:               "https://auth.example.com",
		RegistrationEndpoint: regServer.URL,
		Scopes:               []string{"read", "write"},
	}
	reg, err := RegisterClient(context.Background(), discovery, "test-server", DCRConfig{RedirectURI: "http://localhost:5000/callback"})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}
	if reg.Scope != "read write" {
		t.Errorf("Expected requested scope, got %q", reg.Scope)
	}
	if !reflect.DeepEqual(reg.RedirectURIs, []string{"http://localhost:5000/callback"}) {
		t.Errorf("Expected requested redirect URIs, got %#v", reg.RedirectURIs)
	}
	if reg.ClientSecretExpiresAt != 0 || reg.ClientSecret != "" {
		t.Errorf("Expected public client without secret, got %#v", reg)
	}
}

func TestRegisterClient_Errors(t *testing.T) {
	if _, err := RegisterClient(context.Background(), &Discovery{}, "test-server", DCRConfig{}); err == nil {
		t.Error("Expected error when registration endpoint missing")
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
	}))
	defer failing.Close()
	if _, err := RegisterClient(context.Background(), &Discovery{RegistrationEndpoint: failing.URL}, "test-server", DCRConfig{}); err == nil {
		t.Error("Expected error on non-2xx registration response")
	}

	noID := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer noID.Close()
	if _, err := RegisterClient(context.Background(), &Discovery{RegistrationEndpoint: noID.URL}, "test-server", DCRConfig{}); err == nil {
		t.Error("Expected error when response has no client_id")
	}
}

func TestGetRegistration(t *testing.T) {
	var gotAuth, gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(DCRResponse{
			ClientID:                "client-1",
			RegistrationAccessToken: "rat-rotated",
			RedirectURIs:            []string{"http://localhost:5000/callback"},
			Scope:                   "mcp:read",
		})
	}))
	defer server.Close()

	reg := &ClientRegistration{
		Issuer:                  "https://auth.example.com",
		ClientID:                "client-1",
		ClientSecret:            "secret-1",
		ClientSecretExpiresAt:   1900000000,
		RegistrationAccessToken: "rat-1",
		RegistrationClientURI:   server.URL + "/register/client-1",
		Scope:                   "old",
	}
	got, err := GetRegistration(context.Background(), reg)
	if err != nil {
		t.Fatalf("GetRegistration failed: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("Expected GET, got %s", gotMethod)
	}
	if gotAuth != "Bearer rat-1" {
		t.Errorf("Expected bearer registration access token, got %q", gotAuth)
	}
	if got.RegistrationAccessToken != "rat-rotated" {
		t.Errorf("Expected rotated token, got %q", got.RegistrationAccessToken)
	}
	if got.Scope != "mcp:read" {
		t.Errorf("Expected refreshed scope, got %q", got.Scope)
	}
	// Fields the server omitted are preserved.
	if got.Issuer != reg.Issuer || got.ClientSecret != "secret-1" || got.ClientSecretExpiresAt != 1900000000 || got.RegistrationClientURI != reg.RegistrationClientURI {
		t.Errorf("Expected omitted fields to be preserved, got %#v", got)
	}
	if reg.RegistrationAccessToken != "rat-1" || reg.Scope != "old" {
		t.Error("GetRegistration must not mutate its input")
	}
}

func TestRegistrationRequests_GoneAndErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantGone bool
	}{
		{"unauthorized", http.StatusUnauthorized, true},
		{"not found", http.StatusNotFound, true},
		{"server error", http.StatusInternalServerError, false},
		{"forbidden", http.StatusForbidden, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL}

			_, getErr := GetRegistration(context.Background(), reg)
			_, putErr := UpdateRegistration(context.Background(), reg, DCRRequest{})
			for op, err := range map[string]error{"GET": getErr, "PUT": putErr} {
				if err == nil {
					t.Fatalf("%s: expected error for status %d", op, tt.status)
				}
				if got := errors.Is(err, ErrRegistrationGone); got != tt.wantGone {
					t.Errorf("%s: errors.Is(ErrRegistrationGone) = %v, want %v (err: %v)", op, got, tt.wantGone, err)
				}
			}
		})
	}
}

func TestRegistrationRequests_NoManagementCredentials(t *testing.T) {
	cases := []*ClientRegistration{
		nil,
		{ClientID: "c", RegistrationAccessToken: "rat"},
		{ClientID: "c", RegistrationClientURI: "https://auth.example.com/register/c"},
	}
	for _, reg := range cases {
		if _, err := GetRegistration(context.Background(), reg); !errors.Is(err, ErrNoRegistrationManagement) {
			t.Errorf("GetRegistration(%#v): expected ErrNoRegistrationManagement, got %v", reg, err)
		}
		if _, err := UpdateRegistration(context.Background(), reg, DCRRequest{}); !errors.Is(err, ErrNoRegistrationManagement) {
			t.Errorf("UpdateRegistration(%#v): expected ErrNoRegistrationManagement, got %v", reg, err)
		}
	}
}

func TestGetRegistration_ClientIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "someone-else"})
	}))
	defer server.Close()

	_, err := GetRegistration(context.Background(), &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL})
	if err == nil {
		t.Fatal("Expected error when response client_id differs")
	}
}

func TestUpdateRegistration(t *testing.T) {
	var gotAuth, gotMethod, gotContentType string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		_ = json.NewEncoder(w).Encode(DCRResponse{
			ClientID:                "client-1",
			ClientSecret:            "secret-2",
			ClientSecretExpiresAt:   2000000000,
			RegistrationAccessToken: "rat-2",
			RedirectURIs:            []string{"http://localhost:6000/callback"},
			Scope:                   "mcp:read mcp:write",
		})
	}))
	defer server.Close()

	reg := &ClientRegistration{
		Issuer:                  "https://auth.example.com",
		ClientID:                "client-1",
		ClientSecret:            "secret-1",
		ClientSecretExpiresAt:   1,
		RegistrationAccessToken: "rat-1",
		RegistrationClientURI:   server.URL,
	}
	got, err := UpdateRegistration(context.Background(), reg, DCRRequest{
		ClientName:              "MCP Gateway - test",
		RedirectURIs:            []string{"http://localhost:6000/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scope:                   "mcp:read mcp:write",
	})
	if err != nil {
		t.Fatalf("UpdateRegistration failed: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("Expected PUT, got %s", gotMethod)
	}
	if gotAuth != "Bearer rat-1" {
		t.Errorf("Expected bearer registration access token, got %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("Expected JSON content type, got %q", gotContentType)
	}
	if gotBody["client_id"] != "client-1" || gotBody["client_name"] != "MCP Gateway - test" || gotBody["scope"] != "mcp:read mcp:write" {
		t.Errorf("Unexpected PUT body: %#v", gotBody)
	}
	for _, forbidden := range []string{"client_secret", "registration_access_token", "registration_client_uri", "client_secret_expires_at"} {
		if _, ok := gotBody[forbidden]; ok {
			t.Errorf("PUT body must not include %s (RFC 7592 §2.2)", forbidden)
		}
	}

	if got.RegistrationAccessToken != "rat-2" || got.ClientSecret != "secret-2" || got.ClientSecretExpiresAt != 2000000000 {
		t.Errorf("Expected rotated credentials, got %#v", got)
	}
	if !reflect.DeepEqual(got.RedirectURIs, []string{"http://localhost:6000/callback"}) || got.Scope != "mcp:read mcp:write" {
		t.Errorf("Expected refreshed metadata, got %#v", got)
	}
	if got.Issuer != "https://auth.example.com" || got.RegistrationClientURI != server.URL {
		t.Errorf("Expected issuer and URI preserved, got %#v", got)
	}
}

func TestSecretExpired(t *testing.T) {
	now := time.Unix(1000, 0)
	tests := []struct {
		name string
		reg  *ClientRegistration
		want bool
	}{
		{"never expires", &ClientRegistration{ClientSecretExpiresAt: 0}, false},
		{"future", &ClientRegistration{ClientSecretExpiresAt: 1001}, false},
		{"exactly now", &ClientRegistration{ClientSecretExpiresAt: 1000}, true},
		{"past", &ClientRegistration{ClientSecretExpiresAt: 999}, true},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reg.SecretExpired(now); got != tt.want {
				t.Errorf("SecretExpired = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsInvalidClientError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"json 401", 401, `{"error":"invalid_client","error_description":"unknown client"}`, true},
		{"json 400", 400, `{"error":"invalid_client"}`, true},
		{"form encoded", 400, "error=invalid_client&error_description=bad", true},
		{"no status", 0, `{"error":"invalid_client"}`, true},
		{"other error", 400, `{"error":"invalid_grant"}`, false},
		{"invalid_client in description only", 400, `{"error":"invalid_request","error_description":"invalid_client"}`, false},
		{"success status", 200, `{"error":"invalid_client"}`, false},
		{"empty body", 401, ``, false},
		{"html body", 401, `<html>Unauthorized</html>`, false},
		{"json array", 400, `["invalid_client"]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsInvalidClientError(tt.status, []byte(tt.body)); got != tt.want {
				t.Errorf("IsInvalidClientError(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

func TestIsInvalidClientErrorCode(t *testing.T) {
	if !IsInvalidClientErrorCode("invalid_client") {
		t.Error("Expected invalid_client to match")
	}
	for _, code := range []string{"", "access_denied", "Invalid_Client"} {
		if IsInvalidClientErrorCode(code) {
			t.Errorf("Expected %q not to match", code)
		}
	}
}
