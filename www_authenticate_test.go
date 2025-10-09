package oauth

import (
	"testing"
)

// TestParseWWWAuthenticate_Valid verifies parsing of standard WWW-Authenticate headers
func TestParseWWWAuthenticate_Valid(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		expectSchemes int
		expectParams  map[string]string
	}{
		{
			name:          "Bearer with resource_metadata",
			header:        `Bearer realm="example.com", resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			expectSchemes: 1,
			expectParams: map[string]string{
				"realm":             "example.com",
				"resource_metadata": "https://example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:          "Bearer with scope",
			header:        `Bearer realm="api", scope="read write"`,
			expectSchemes: 1,
			expectParams: map[string]string{
				"realm": "api",
				"scope": "read write",
			},
		},
		{
			name:          "Multiple schemes",
			header:        `Basic realm="web", Bearer realm="api" scope="read"`,
			expectSchemes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenges, err := ParseWWWAuthenticate(tt.header)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if len(challenges) != tt.expectSchemes {
				t.Errorf("Expected %d schemes, got %d", tt.expectSchemes, len(challenges))
			}

			if tt.expectParams != nil && len(challenges) > 0 {
				for key, expectedValue := range tt.expectParams {
					actualValue, exists := challenges[0].Parameters[key]
					if !exists {
						t.Errorf("Expected parameter %s not found", key)
					}
					if actualValue != expectedValue {
						t.Errorf("Parameter %s: expected %s, got %s", key, expectedValue, actualValue)
					}
				}
			}
		})
	}
}

// TestParseWWWAuthenticate_Malformed verifies error handling for invalid headers
func TestParseWWWAuthenticate_Malformed(t *testing.T) {
	// Empty header should return error
	_, err := ParseWWWAuthenticate("")
	if err == nil {
		t.Error("Expected error for empty header")
	}
}

// TestFindResourceMetadataURL verifies extraction of resource_metadata URL
func TestFindResourceMetadataURL(t *testing.T) {
	tests := []struct {
		name       string
		challenges []WWWAuthenticateChallenge
		expectURL  string
	}{
		{
			name: "Found in first challenge",
			challenges: []WWWAuthenticateChallenge{
				{
					Scheme: "Bearer",
					Parameters: map[string]string{
						"resource_metadata": "https://example.com/.well-known",
					},
				},
			},
			expectURL: "https://example.com/.well-known",
		},
		{
			name: "No resource_metadata parameter",
			challenges: []WWWAuthenticateChallenge{
				{
					Scheme: "Bearer",
					Parameters: map[string]string{
						"realm": "test",
					},
				},
			},
			expectURL: "",
		},
		{
			name:       "Nil challenges",
			challenges: nil,
			expectURL:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := FindResourceMetadataURL(tt.challenges)
			if url != tt.expectURL {
				t.Errorf("Expected URL %s, got %s", tt.expectURL, url)
			}
		})
	}
}

// TestFindRequiredScopes verifies scope extraction from Bearer challenges
func TestFindRequiredScopes(t *testing.T) {
	tests := []struct {
		name         string
		challenges   []WWWAuthenticateChallenge
		expectScopes []string
	}{
		{
			name: "Single scope",
			challenges: []WWWAuthenticateChallenge{
				{
					Scheme: "Bearer",
					Parameters: map[string]string{
						"scope": "read",
					},
				},
			},
			expectScopes: []string{"read"},
		},
		{
			name: "Multiple scopes",
			challenges: []WWWAuthenticateChallenge{
				{
					Scheme: "Bearer",
					Parameters: map[string]string{
						"scope": "read write admin",
					},
				},
			},
			expectScopes: []string{"read", "write", "admin"},
		},
		{
			name: "No scopes",
			challenges: []WWWAuthenticateChallenge{
				{
					Scheme:     "Bearer",
					Parameters: map[string]string{},
				},
			},
			expectScopes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := FindRequiredScopes(tt.challenges)
			if len(scopes) != len(tt.expectScopes) {
				t.Errorf("Expected %d scopes, got %d", len(tt.expectScopes), len(scopes))
			}
		})
	}
}
