package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
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

	reg, err := RegisterClient(localHTTPContext(), discovery, "test-server", DCRConfig{})
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
	reg, err := RegisterClient(localHTTPContext(), discovery, "test-server", DCRConfig{RedirectURI: "http://localhost:5000/callback"})
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
	if _, err := RegisterClient(localHTTPContext(), &Discovery{RegistrationEndpoint: failing.URL}, "test-server", DCRConfig{}); err == nil {
		t.Error("Expected error on non-2xx registration response")
	}

	noID := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer noID.Close()
	if _, err := RegisterClient(localHTTPContext(), &Discovery{RegistrationEndpoint: noID.URL}, "test-server", DCRConfig{}); err == nil {
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
	got, err := GetRegistration(localHTTPContext(), reg)
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

			_, getErr := GetRegistration(localHTTPContext(), reg)
			_, putErr := UpdateRegistration(localHTTPContext(), reg, DCRRequest{})
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

	_, err := GetRegistration(localHTTPContext(), &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL})
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
	got, err := UpdateRegistration(localHTTPContext(), reg, DCRRequest{
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

func TestManagementResponse_FieldPresence(t *testing.T) {
	previous := func(uri string) *ClientRegistration {
		return &ClientRegistration{
			Issuer:                  "https://auth.example.com",
			ClientID:                "client-1",
			ClientSecret:            "secret-1",
			ClientSecretExpiresAt:   1900000000,
			RegistrationAccessToken: "rat-1",
			RegistrationClientURI:   uri,
			RedirectURIs:            []string{"http://localhost:5000/callback"},
			Scope:                   "mcp:read mcp:write",
			TokenEndpointAuthMethod: "client_secret_basic",
		}
	}

	tests := []struct {
		name string
		body string
		// mutate turns the previous registration into the expected result.
		mutate func(*ClientRegistration)
	}{
		{
			name:   "absent fields are preserved",
			body:   `{"client_id":"client-1"}`,
			mutate: func(*ClientRegistration) {},
		},
		{
			name:   "null fields are treated as absent",
			body:   `{"client_id":"client-1","scope":null,"redirect_uris":null}`,
			mutate: func(*ClientRegistration) {},
		},
		{
			name: "explicit empty scope and redirect_uris are cleared",
			body: `{"client_id":"client-1","scope":"","redirect_uris":[]}`,
			mutate: func(r *ClientRegistration) {
				r.Scope = ""
				r.RedirectURIs = []string{}
			},
		},
		{
			name: "explicit empty token_endpoint_auth_method is cleared",
			body: `{"client_id":"client-1","token_endpoint_auth_method":""}`,
			mutate: func(r *ClientRegistration) {
				r.TokenEndpointAuthMethod = ""
			},
		},
		{
			name: "non-empty values replace previous ones",
			body: `{"client_id":"client-1","scope":"mcp:read","redirect_uris":["http://localhost:6000/callback"],"token_endpoint_auth_method":"none"}`,
			mutate: func(r *ClientRegistration) {
				r.Scope = "mcp:read"
				r.RedirectURIs = []string{"http://localhost:6000/callback"}
				r.TokenEndpointAuthMethod = "none"
			},
		},
		{
			name: "only the fields present are changed",
			body: `{"client_id":"client-1","scope":""}`,
			mutate: func(r *ClientRegistration) {
				r.Scope = ""
			},
		},
		{
			name: "rotated secret brings its expiry",
			body: `{"client_id":"client-1","client_secret":"secret-2","client_secret_expires_at":2000000000,"registration_access_token":"rat-2"}`,
			mutate: func(r *ClientRegistration) {
				r.ClientSecret = "secret-2"
				r.ClientSecretExpiresAt = 2000000000
				r.RegistrationAccessToken = "rat-2"
			},
		},
		{
			name: "explicit zero expiry without a secret keeps the secret",
			body: `{"client_id":"client-1","client_secret_expires_at":0}`,
			mutate: func(r *ClientRegistration) {
				r.ClientSecretExpiresAt = 0
			},
		},
		{
			name: "explicit empty secret is cleared with its expiry",
			body: `{"client_id":"client-1","client_secret":"","client_secret_expires_at":0}`,
			mutate: func(r *ClientRegistration) {
				r.ClientSecret = ""
				r.ClientSecretExpiresAt = 0
			},
		},
		{
			name: "explicit empty registration credentials are cleared",
			body: `{"client_id":"client-1","registration_access_token":"","registration_client_uri":""}`,
			mutate: func(r *ClientRegistration) {
				r.RegistrationAccessToken = ""
				r.RegistrationClientURI = ""
			},
		},
	}

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for _, tt := range tests {
			t.Run(method+"/"+tt.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(tt.body))
				}))
				defer server.Close()

				reg := previous(server.URL)
				want := previous(server.URL)
				tt.mutate(want)

				var got *ClientRegistration
				var err error
				if method == http.MethodGet {
					got, err = GetRegistration(localHTTPContext(), reg)
				} else {
					got, err = UpdateRegistration(localHTTPContext(), reg, DCRRequest{})
				}
				if err != nil {
					t.Fatalf("%s failed: %v", method, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("registration mismatch:\n got %#v\nwant %#v", got, want)
				}
				if !reflect.DeepEqual(reg, previous(server.URL)) {
					t.Errorf("input registration was modified: %#v", reg)
				}
			})
		}
	}
}

func TestManagementResponse_InvalidJSONObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`["not","an","object"]`))
	}))
	defer server.Close()

	_, err := GetRegistration(localHTTPContext(), &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL})
	if err == nil {
		t.Fatal("Expected error when response is not a JSON object")
	}
}

func TestRegisterClient_EmptyResponseFieldsFallBackToRequest(t *testing.T) {
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"client_id":"client-1","scope":"","redirect_uris":[]}`))
	}))
	defer regServer.Close()

	reg, err := RegisterClient(localHTTPContext(), &Discovery{
		Issuer:               "https://auth.example.com",
		RegistrationEndpoint: regServer.URL,
		Scopes:               []string{"read"},
	}, "test-server", DCRConfig{RedirectURI: "http://localhost:5000/callback"})
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}
	if reg.Scope != "read" || !reflect.DeepEqual(reg.RedirectURIs, []string{"http://localhost:5000/callback"}) {
		t.Errorf("Expected initial registration to keep requested metadata, got %#v", reg)
	}
}

// localHTTPContext opts a test into the http + loopback carve-out so the
// plain-http httptest servers used below are accepted. Tests of the https
// requirement itself use context.Background().
func localHTTPContext() context.Context {
	return WithAllowLocalHTTP(context.Background())
}

func TestRegistrationRequests_RejectNonHTTPSURI(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer server.Close()

	tests := []struct {
		name string
		uri  string
	}{
		{"http", server.URL + "/register/client-1"},
		{"remote http", "http://auth.example.com/register/client-1"},
		{"no scheme", "auth.example.com/register/client-1"},
		{"userinfo", "https://user:pw@auth.example.com/register/client-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat-secret", RegistrationClientURI: tt.uri}

			_, getErr := GetRegistration(context.Background(), reg)
			_, putErr := UpdateRegistration(context.Background(), reg, DCRRequest{})
			for op, err := range map[string]error{"GET": getErr, "PUT": putErr} {
				if !errors.Is(err, ErrInsecureRegistrationURI) {
					t.Errorf("%s: expected ErrInsecureRegistrationURI, got %v", op, err)
				}
			}
		})
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("server received %d requests; the registration token must not be sent to a non-https URI", n)
	}
}

func TestRegistrationRequests_HTTPSAllowed(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	var gotAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1", Scope: "mcp:read"})
	}))
	defer server.Close()

	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat-1", RegistrationClientURI: server.URL}
	got, err := GetRegistration(context.Background(), reg)
	if err != nil {
		t.Fatalf("GetRegistration over https failed: %v", err)
	}
	if gotAuth != "Bearer rat-1" || got.Scope != "mcp:read" {
		t.Errorf("unexpected https result: auth=%q registration=%#v", gotAuth, got)
	}
	if _, err := UpdateRegistration(context.Background(), reg, DCRRequest{}); err != nil {
		t.Fatalf("UpdateRegistration over https failed: %v", err)
	}
}

func TestRegistrationRequests_RejectHTTPRedirect(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	var plainRequests atomic.Int32
	var plainAuth atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		plainRequests.Add(1)
		plainAuth.Store(r.Header.Get("Authorization"))
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/register/client-1", http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat-secret", RegistrationClientURI: secure.URL}
	_, getErr := GetRegistration(context.Background(), reg)
	_, putErr := UpdateRegistration(context.Background(), reg, DCRRequest{})
	for op, err := range map[string]error{"GET": getErr, "PUT": putErr} {
		if !errors.Is(err, ErrInsecureRegistrationURI) {
			t.Errorf("%s: expected ErrInsecureRegistrationURI for https->http redirect, got %v", op, err)
		}
	}
	if n := plainRequests.Load(); n != 0 {
		t.Fatalf("http redirect target received %d requests (Authorization %v)", n, plainAuth.Load())
	}
}

// With the guard opted out the initial scheme check is off, but the token
// must still not follow a redirect to a different origin.
func TestRegistrationRequests_RedirectDropsAuthorizationAcrossOrigins(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	var otherAuth atomic.Value
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherAuth.Store(r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer other.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()

	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat-secret", RegistrationClientURI: secure.URL}
	if _, err := GetRegistration(context.Background(), reg); err != nil {
		t.Fatalf("GetRegistration failed: %v", err)
	}
	if got, _ := otherAuth.Load().(string); got != "" {
		t.Errorf("Authorization leaked to a different origin: %q", got)
	}
}

func TestRegistrationRequests_InsecureOptOuts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer server.Close()
	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL}

	t.Run("WithAllowLocalHTTP", func(t *testing.T) {
		if _, err := GetRegistration(WithAllowLocalHTTP(context.Background()), reg); err != nil {
			t.Fatalf("expected loopback http to be allowed: %v", err)
		}
	})
	t.Run("WithSkipSSRFCheck", func(t *testing.T) {
		if _, err := GetRegistration(WithSkipSSRFCheck(context.Background()), reg); err != nil {
			t.Fatalf("expected http to be allowed: %v", err)
		}
	})
	t.Run("environment override", func(t *testing.T) {
		t.Setenv(allowInsecureRemoteURLEnv, "1")
		if _, err := GetRegistration(context.Background(), reg); err != nil {
			t.Fatalf("expected http to be allowed: %v", err)
		}
	})
	t.Run("WithAllowLocalHTTP does not cover remote hosts", func(t *testing.T) {
		remote := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: "http://auth.example.com/register"}
		if _, err := GetRegistration(WithAllowLocalHTTP(context.Background()), remote); !errors.Is(err, ErrInsecureRegistrationURI) {
			t.Fatalf("expected ErrInsecureRegistrationURI, got %v", err)
		}
	})
}

// A private-range registration_client_uri is not a hard failure (the guard is
// advisory by default, see AGENTS.md), but it must be flagged through the
// guard's warning rather than dialed silently.
func TestRegistrationRequests_PrivateAddressIsFlagged(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer server.Close() // 127.0.0.1: a blocked address

	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)
	ctx, rec := contextWithSSRFRecorder(ctx)
	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL}
	if _, err := GetRegistration(ctx, reg); err != nil {
		t.Fatalf("advisory guard must not block the request: %v", err)
	}
	if !rec.failed {
		t.Fatal("expected the SSRF guard to flag the loopback registration_client_uri")
	}
	if len(logger.warns) == 0 {
		t.Error("expected an SSRF guard warning to be logged")
	}

	// The opt-out silences the guard entirely.
	logger = &testLogger{}
	ctx, rec = contextWithSSRFRecorder(WithSkipSSRFCheck(WithLogger(context.Background(), logger)))
	if _, err := GetRegistration(ctx, reg); err != nil {
		t.Fatalf("GetRegistration with WithSkipSSRFCheck failed: %v", err)
	}
	if rec.failed || len(logger.warns) != 0 {
		t.Errorf("WithSkipSSRFCheck should skip the guard: failed=%v warnings=%v", rec.failed, logger.warns)
	}
}

// The registration requests go through the guarded client: it pins dialing,
// ignores proxies, and carries a bounded timeout.
func TestDCRHTTPClient_GuardedAndBounded(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	client, err := dcrHTTPClient(context.Background())
	if err != nil {
		t.Fatalf("dcrHTTPClient failed: %v", err)
	}
	if _, ok := client.Transport.(*publicOnlyRoundTripper); !ok {
		t.Errorf("expected guarded transport, got %T", client.Transport)
	}
	if client.Timeout != registrationRequestTimeout {
		t.Errorf("expected timeout %v, got %v", registrationRequestTimeout, client.Timeout)
	}

	unguarded, err := dcrHTTPClient(WithSkipSSRFCheck(context.Background()))
	if err != nil {
		t.Fatalf("dcrHTTPClient failed: %v", err)
	}
	if _, ok := unguarded.Transport.(*publicOnlyRoundTripper); ok {
		t.Error("WithSkipSSRFCheck should leave the transport unguarded")
	}
	if unguarded.Timeout != registrationRequestTimeout {
		t.Errorf("timeout must apply with the guard opted out too, got %v", unguarded.Timeout)
	}
}

func TestRegistrationRequests_HonorContextDeadline(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(localHTTPContext(), 50*time.Millisecond)
	defer cancel()
	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL}
	start := time.Now()
	if _, err := GetRegistration(ctx, reg); err == nil {
		t.Fatal("expected a deadline error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("request ignored the context deadline (took %v)", elapsed)
	}
}

func TestRegistrationRequests_ErrorBodyTruncated(t *testing.T) {
	huge := strings.Repeat("secret-internal-data ", 50000) // ~1 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(huge))
	}))
	defer server.Close()

	reg := &ClientRegistration{ClientID: "client-1", RegistrationAccessToken: "rat", RegistrationClientURI: server.URL}
	_, getErr := GetRegistration(localHTTPContext(), reg)
	_, putErr := UpdateRegistration(localHTTPContext(), reg, DCRRequest{})
	for op, err := range map[string]error{"GET": getErr, "PUT": putErr} {
		if err == nil {
			t.Fatalf("%s: expected error", op)
		}
		if len(err.Error()) > maxErrorBodyBytes+200 {
			t.Errorf("%s: error is %d bytes; response body was not truncated", op, len(err.Error()))
		}
		if !strings.Contains(err.Error(), "secret-internal-data") || !strings.Contains(err.Error(), "truncated") {
			t.Errorf("%s: expected a truncated body excerpt, got %q", op, err.Error())
		}
	}
}

func TestRegisterClient_ErrorBodyTruncatedAndBounded(t *testing.T) {
	t.Run("plain body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(strings.Repeat("x", 4<<20)))
		}))
		defer server.Close()

		_, err := RegisterClient(localHTTPContext(), &Discovery{RegistrationEndpoint: server.URL}, "test-server", DCRConfig{})
		if err == nil || len(err.Error()) > maxErrorBodyBytes+200 {
			t.Fatalf("expected a bounded error, got %v", err)
		}
	})
	t.Run("json error_description", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error_description": strings.Repeat("y", 100000)})
		}))
		defer server.Close()

		_, err := RegisterClient(localHTTPContext(), &Discovery{RegistrationEndpoint: server.URL}, "test-server", DCRConfig{})
		if err == nil || len(err.Error()) > maxErrorBodyBytes+200 {
			t.Fatalf("expected a bounded error, got %v", err)
		}
	})
	t.Run("short body kept", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_redirect_uri"}`))
		}))
		defer server.Close()

		_, err := RegisterClient(localHTTPContext(), &Discovery{RegistrationEndpoint: server.URL}, "test-server", DCRConfig{})
		if err == nil || !strings.Contains(err.Error(), "invalid_redirect_uri") || strings.Contains(err.Error(), "truncated") {
			t.Fatalf("expected the short error intact, got %v", err)
		}
	})
}

func TestRegisterClient_RequiresHTTPSRegistrationEndpoint(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer server.Close()

	_, err := RegisterClient(context.Background(), &Discovery{RegistrationEndpoint: server.URL}, "test-server", DCRConfig{})
	if err == nil {
		t.Fatal("expected plain-http registration endpoint to be refused")
	}
	if requests.Load() != 0 {
		t.Errorf("server received %d requests", requests.Load())
	}
}

func TestRegisterClient_HTTPSPath(t *testing.T) {
	defer setupInsecureTLSClient(t)()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "client-1"})
	}))
	defer server.Close()

	reg, err := RegisterClient(context.Background(), &Discovery{RegistrationEndpoint: server.URL}, "test-server", DCRConfig{})
	if err != nil {
		t.Fatalf("RegisterClient over https failed: %v", err)
	}
	if reg.ClientID != "client-1" {
		t.Errorf("unexpected registration: %#v", reg)
	}
}
