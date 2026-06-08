package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const DefaultRedirectURI = "https://mcp.docker.com/oauth/callback"

var defaultAllowedRedirectURIHosts = []string{
	"localhost",
	"127.0.0.1",
	"::1",
	"mcp.docker.com",
	"mcp-stage.docker.com",
}

// DCRConfig configures Dynamic Client Registration behavior.
type DCRConfig struct {
	// RedirectURI is the OAuth callback URI to register. If empty, DefaultRedirectURI is used.
	RedirectURI string

	// AllowedRedirectURIHosts is the allowlist of hosts accepted for RedirectURI validation.
	// Hosts should not include a port. If nil, DefaultAllowedRedirectURIHosts is used.
	// Use DefaultAllowedRedirectURIHosts() and append to it to keep the built-in hosts.
	AllowedRedirectURIHosts []string
}

// DefaultAllowedRedirectURIHosts returns a copy of the built-in redirect URI host allowlist.
func DefaultAllowedRedirectURIHosts() []string {
	return append([]string(nil), defaultAllowedRedirectURIHosts...)
}

// isValidRedirectURI validates that the redirect URI host is allowed.
func isValidRedirectURI(redirectURI string, allowedHosts []string) error {
	if redirectURI == "" {
		return nil // Empty is OK (will use default)
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI format: %w", err)
	}

	// Extract hostname (handles ports automatically)
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("invalid redirect URI %q: missing host", redirectURI)
	}

	if allowedHosts == nil {
		allowedHosts = defaultAllowedRedirectURIHosts
	}

	for _, allowedHost := range allowedHosts {
		allowedHost = normalizeAllowedRedirectURIHost(allowedHost)
		if allowedHost == "" {
			continue
		}
		if strings.EqualFold(hostname, allowedHost) {
			return nil
		}
	}

	return fmt.Errorf("redirect URI host %q not allowed - allowed hosts: %s", hostname, formatAllowedRedirectURIHosts(allowedHosts))
}

func normalizeAllowedRedirectURIHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	// Be forgiving if callers pass a full redirect URI instead of just a host.
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}

	return host
}

func formatAllowedRedirectURIHosts(hosts []string) string {
	if len(hosts) == 0 {
		return "(none)"
	}

	formatted := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if normalized := normalizeAllowedRedirectURIHost(host); normalized != "" {
			formatted = append(formatted, normalized)
		}
	}
	if len(formatted) == 0 {
		return "(none)"
	}

	return strings.Join(formatted, ", ")
}

// PerformDCR performs Dynamic Client Registration with the authorization server
// Returns client credentials for the registered public client
//
// RFC 7591 COMPLIANCE:
// - Uses token_endpoint_auth_method="none" for public clients
// - Includes redirect_uris pointing to mcp-oauth proxy
// - Requests authorization_code and refresh_token grant types
//
// redirectURI: The OAuth callback URI to register. If empty, uses DefaultRedirectURI.
func PerformDCR(ctx context.Context, discovery *Discovery, serverName string, redirectURI string) (*ClientCredentials, error) {
	return PerformDCRWithConfig(ctx, discovery, serverName, DCRConfig{RedirectURI: redirectURI})
}

// PerformDCRWithConfig performs Dynamic Client Registration with configurable DCR behavior.
func PerformDCRWithConfig(ctx context.Context, discovery *Discovery, serverName string, config DCRConfig) (*ClientCredentials, error) {
	if discovery.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("no registration endpoint found for %s", serverName)
	}

	// Use provided redirectURI, fallback to default if empty.
	redirectURI := config.RedirectURI
	if redirectURI == "" {
		redirectURI = DefaultRedirectURI
	}

	// Validate redirect URI for security.
	if err := isValidRedirectURI(redirectURI, config.AllowedRedirectURIHosts); err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %w", err)
	}

	// Build DCR request for PUBLIC client
	registration := DCRRequest{
		ClientName:              fmt.Sprintf("MCP Gateway - %s", serverName),
		RedirectURIs:            []string{redirectURI},
		TokenEndpointAuthMethod: "none", // PUBLIC client (no client secret)
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},

		// Additional metadata for better client identification
		ClientURI:       "https://github.com/docker/mcp-gateway",
		SoftwareID:      "mcp-gateway",
		SoftwareVersion: "1.0.0",
		Contacts:        []string{"support@docker.com"},
	}

	// Add requested scopes if provided
	if len(discovery.Scopes) > 0 {
		registration.Scope = joinScopes(discovery.Scopes)
	}

	// Marshal the registration request
	body, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DCR request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create DCR request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MCP-Gateway/1.0.0")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send DCR request to %s: %w", discovery.RegistrationEndpoint, err)
	}
	defer resp.Body.Close()

	// Check response status (201 Created or 200 OK are acceptable)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// Read error response body to understand why DCR failed
		errorBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("DCR failed with status %d for %s", resp.StatusCode, serverName)
		}

		errorMsg := string(errorBody)

		// Try to parse as JSON for structured error
		var errorResp map[string]any
		if err := json.Unmarshal(errorBody, &errorResp); err == nil {
			// Successfully parsed as JSON - look for common error fields
			if errDesc, ok := errorResp["error_description"].(string); ok {
				errorMsg = errDesc
			} else if errField, ok := errorResp["error"].(string); ok {
				errorMsg = errField
			} else if message, ok := errorResp["message"].(string); ok {
				errorMsg = message
			}
		}

		return nil, fmt.Errorf("DCR failed with status %d for %s: %s", resp.StatusCode, serverName, errorMsg)
	}

	// Parse the response
	var dcrResponse DCRResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcrResponse); err != nil {
		return nil, fmt.Errorf("failed to decode DCR response: %w", err)
	}

	if dcrResponse.ClientID == "" {
		return nil, fmt.Errorf("DCR response missing client_id for %s", serverName)
	}

	// Create client credentials (public client - no secret)
	creds := &ClientCredentials{
		ClientID:              dcrResponse.ClientID,
		ServerURL:             discovery.ResourceURL,
		IsPublic:              true,
		AuthorizationEndpoint: discovery.AuthorizationEndpoint,
		TokenEndpoint:         discovery.TokenEndpoint,
		// No ClientSecret for public clients
	}

	return creds, nil
}

// joinScopes joins a slice of scopes into a space-separated string
// per OAuth 2.0 specification (RFC 6749 Section 3.3)
func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}

	// Use simple string concatenation for small arrays
	result := scopes[0]
	for i := 1; i < len(scopes); i++ {
		result += " " + scopes[i]
	}
	return result
}
