package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// httpClientFunc allows tests to inject a custom HTTP client (e.g., for TLS test servers)
var httpClientFunc = func() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// DiscoverOAuthRequirements probes an MCP server to discover OAuth requirements
//
// MCP AUTHORIZATION SPEC COMPLIANCE:
// - Implements MCP Authorization Specification Section 4.1 "Authorization Server Discovery"
// - Follows RFC 9728 "OAuth 2.0 Protected Resource Metadata"
// - Follows RFC 8414 "OAuth 2.0 Authorization Server Metadata"
// - Gracefully handles servers with partial MCP compliance
//
// ROBUST DISCOVERY FLOW (Inspector-inspired):
// 1. Make initial MCP request (expect 401 if OAuth required)
// 2. Parse WWW-Authenticate header (if present)
// 3. Initialize with intelligent defaults (fallback auth server = MCP domain)
// 4. Fetch resource metadata (from header URL or well-known endpoint fallback)
// 5. Fetch Authorization Server Metadata (REQUIRED)
// 6. Build discovery result with all gathered information
//
// FALLBACK BEHAVIOR: If WWW-Authenticate missing/unparseable, falls back to
// RFC 9728-required /.well-known/oauth-protected-resource endpoint
func DiscoverOAuthRequirements(ctx context.Context, serverURL string) (*Discovery, error) {
	// Extract logger from context (or use noop if not provided)
	logger := loggerFromContext(ctx)

	logger.Infof("starting OAuth discovery for server: %s", serverURL)

	// Create HTTP client (can be overridden in tests for TLS support)
	client := httpClientFunc()

	// Parse server URL to extract base domain for defaults
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// STEP 1: Make initial MCP request to trigger 401 Unauthorized
	// MCP Spec Section 4.1: "MCP request without token" should trigger 401
	// Use POST with initialize request as per spec diagrams
	mcpPayload := `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-gateway","version":"1.0.0"}},"id":1}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, strings.NewReader(mcpPayload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers for MCP protocol request
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "docker-mcp-gateway/1.0.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	logger.Infof("MCP server response: status=%d", resp.StatusCode)

	// If not 401, OAuth might not be required (Authorization is OPTIONAL per MCP spec Section 2.1)
	// We log a warning but continue discovery attempt in case server is misconfigured
	if resp.StatusCode != http.StatusUnauthorized {
		logger.Warnf("expected 401 Unauthorized, got %d - OAuth may not be required", resp.StatusCode)
	}

	// STEP 2: Parse WWW-Authenticate header (if present)
	// MCP Spec Section 4.1: "MCP servers MUST use the HTTP header WWW-Authenticate when returning a 401 Unauthorized"
	wwwAuth := resp.Header.Get("WWW-Authenticate")

	var challenges []WWWAuthenticateChallenge
	if wwwAuth != "" {
		logger.Infof("WWW-Authenticate header present: %s", wwwAuth)
		var err error
		challenges, err = ParseWWWAuthenticate(wwwAuth)
		if err != nil {
			// WWW-Authenticate header exists but isn't parseable - log but continue
			logger.Warnf("could not parse WWW-Authenticate header: %v", err)
			challenges = nil
		} else {
			logger.Infof("parsed %d WWW-Authenticate challenge(s)", len(challenges))
		}
	} else {
		logger.Infof("no WWW-Authenticate header present - will try well-known endpoint")
	}

	// STEP 3: Initialize with intelligent defaults (Inspector pattern)
	// Default authorization server to MCP server's domain
	defaultAuthServerURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	logger.Debugf("default authorization server: %s", defaultAuthServerURL)

	// Initialize discovery with defaults
	var resourceMetadata *ProtectedResourceMetadata
	var resourceMetadataError error
	authServerURL := defaultAuthServerURL
	resourceMetadataClient := sameOriginHTTPClient(client, serverURL)

	// STEP 4: Try to get resource metadata (OPTIONAL - don't fail if missing)
	// RFC 9728 Section 5.1: resource_metadata parameter in WWW-Authenticate
	resourceMetadataURL := ""
	if challenges != nil {
		resourceMetadataURL = FindResourceMetadataURL(challenges)
	}

	if resourceMetadataURL != "" {
		// Resource metadata URL found - try to fetch it
		logger.Infof("fetching protected resource metadata from: %s", resourceMetadataURL)
		if err := validateSameOrigin(serverURL, resourceMetadataURL); err != nil {
			return nil, fmt.Errorf("invalid protected resource metadata URL: %w", err)
		}
		resourceMetadata, resourceMetadataError = fetchOAuthProtectedResourceMetadata(ctx, resourceMetadataClient, resourceMetadataURL)
		if resourceMetadataError != nil {
			return nil, fmt.Errorf("fetching protected resource metadata from %s: %w", resourceMetadataURL, resourceMetadataError)
		}
		if err := validateProtectedResource(serverURL, resourceMetadata.Resource); err != nil {
			return nil, err
		}
		if resourceMetadataError == nil && resourceMetadata != nil && resourceMetadata.AuthorizationServer != "" {
			// Use authorization server from resource metadata if available
			authServerURL = resourceMetadata.AuthorizationServer
			logger.Infof("resource metadata retrieved, auth server: %s", authServerURL)
		} else if resourceMetadataError != nil {
			logger.Warnf("failed to fetch resource metadata: %v", resourceMetadataError)
		}
	} else {
		// No resource_metadata in WWW-Authenticate - try well-known endpoint
		wellKnownURL, err := buildRFC9728WellKnownURL(serverURL)
		if err != nil {
			return nil, fmt.Errorf("building protected resource metadata URL: %w", err)
		}
		logger.Infof("fallback: trying well-known resource metadata endpoint: %s", wellKnownURL)
		resourceMetadata, resourceMetadataError = fetchOAuthProtectedResourceMetadata(ctx, resourceMetadataClient, wellKnownURL)
		if resourceMetadataError == nil && resourceMetadata != nil {
			if err := validateProtectedResource(serverURL, resourceMetadata.Resource); err != nil {
				return nil, err
			}
		}
		if resourceMetadataError == nil && resourceMetadata != nil && resourceMetadata.AuthorizationServer != "" {
			authServerURL = resourceMetadata.AuthorizationServer
			logger.Infof("resource metadata from well-known endpoint, auth server: %s", authServerURL)
		}
	}

	// STEP 5: Fetch Authorization Server Metadata (REQUIRED)
	// MCP Spec Section 3.1: "Authorization servers MUST provide OAuth 2.0 Authorization Server Metadata (RFC8414)"
	logger.Infof("fetching authorization server metadata from: %s", authServerURL)
	authServerMetadata, err := fetchAuthorizationServerMetadata(ctx, client, authServerURL)
	if err != nil {
		logger.Warnf("failed to fetch authorization server metadata: %v", err)
		return nil, fmt.Errorf("fetching authorization server metadata from %s: %w", authServerURL, err)
	}
	logger.Infof("auth server metadata retrieved: token_endpoint=%s, registration_endpoint=%s",
		authServerMetadata.TokenEndpoint, authServerMetadata.RegistrationEndpoint)

	// STEP 6: Build discovery result with all available information
	discovery := &Discovery{
		RequiresOAuth: true,

		// Use resource metadata if available, otherwise use defaults
		ResourceURL:         serverURL,
		ResourceServer:      serverURL,
		AuthorizationServer: authServerURL,

		// From Authorization Server Metadata (RFC 8414) - always available
		Issuer:                            authServerMetadata.Issuer,
		AuthorizationEndpoint:             authServerMetadata.AuthorizationEndpoint,
		TokenEndpoint:                     authServerMetadata.TokenEndpoint,
		RegistrationEndpoint:              authServerMetadata.RegistrationEndpoint,
		JWKSUri:                           authServerMetadata.JWKSUri,
		ScopesSupported:                   authServerMetadata.ScopesSupported,
		ResponseTypesSupported:            authServerMetadata.ResponseTypesSupported,
		ResponseModesSupported:            authServerMetadata.ResponseModesSupported,
		GrantTypesSupported:               authServerMetadata.GrantTypesSupported,
		TokenEndpointAuthMethodsSupported: authServerMetadata.TokenEndpointAuthMethodsSupported,

		// PKCE support detection (OAuth 2.1 MUST requirement)
		SupportsPKCE:        slices.Contains(authServerMetadata.CodeChallengeMethodsSupported, "S256"),
		CodeChallengeMethod: authServerMetadata.CodeChallengeMethodsSupported,
	}

	// Override with resource metadata if successfully fetched
	if resourceMetadata != nil {
		if resourceMetadata.Resource != "" {
			discovery.ResourceURL = resourceMetadata.Resource
			discovery.ResourceServer = resourceMetadata.Resource
		}
		if len(resourceMetadata.Scopes) > 0 {
			discovery.Scopes = resourceMetadata.Scopes
		}
	}

	// Extract additional scopes from WWW-Authenticate if not available from metadata
	if len(discovery.Scopes) == 0 {
		discovery.Scopes = FindRequiredScopes(challenges)
	}

	logger.Infof("discovery complete: auth_server=%s, scopes=%v, pkce=%v",
		discovery.AuthorizationServer, discovery.Scopes, discovery.SupportsPKCE)

	return discovery, nil
}

// fetchOAuthProtectedResourceMetadata fetches metadata from /.well-known/oauth-protected-resource
//
// RFC 9728 COMPLIANCE:
// - Implements RFC 9728 Section 3 "Protected Resource Metadata"
// - Validates required fields: resource, authorization_server(s)
// - Handles both singular and plural authorization server formats
func fetchOAuthProtectedResourceMetadata(ctx context.Context, client *http.Client, metadataURL string) (*ProtectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// RFC 9728 Section 3.1: Response MUST be application/json
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata from %s: %w", metadataURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}

	// RFC 9728 Section 3.2: Validate required fields
	if metadata.Resource == "" {
		return nil, fmt.Errorf("resource field missing in protected resource metadata")
	}

	// COMPATIBILITY: Handle both authorization_server (singular) and authorization_servers (plural) formats
	// RFC 9728 defines authorization_servers as array, but some servers use singular form
	if metadata.AuthorizationServer == "" {
		if len(metadata.AuthorizationServers) == 0 {
			return nil, fmt.Errorf("authorization_server or authorization_servers field missing in protected resource metadata")
		}
		// MCP Spec Section 4.1: "The responsibility for selecting which authorization server to use lies with the MCP client"
		// Taking the first authorization server is a valid implementation per RFC 9728
		metadata.AuthorizationServer = metadata.AuthorizationServers[0]
	}

	return &metadata, nil
}

// buildRFC8414WellKnownURL constructs the well-known URL per RFC 8414 Section 3.1
// Inserts /.well-known/oauth-authorization-server between host and path.
func buildRFC8414WellKnownURL(issuerURL string) (string, error) {
	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL: %w", err)
	}

	// RFC 8414 Section 2: issuer must use https scheme
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("issuer URL must use https scheme")
	}

	// RFC 8414 Section 2: issuer must not have query
	if parsed.RawQuery != "" {
		return "", fmt.Errorf("issuer URL must not contain query parameters")
	}

	// RFC 8414 Section 2: issuer must not have fragment
	if parsed.Fragment != "" {
		return "", fmt.Errorf("issuer URL must not contain fragment")
	}

	// RFC 3986 Section 3.2.2: host is case-insensitive, canonicalize to lowercase
	host := strings.ToLower(parsed.Host)

	// RFC 8414 Section 3.1: Insert .well-known between host and path
	// Path may be empty, "/" or "/some/path"
	path := parsed.Path
	if path == "/" {
		path = ""
	}

	return fmt.Sprintf("https://%s/.well-known/oauth-authorization-server%s",
		host, path), nil
}

// fetchAuthorizationServerMetadata fetches metadata from /.well-known/oauth-authorization-server
//
// RFC 8414 COMPLIANCE:
// - Implements RFC 8414 Section 3 "Authorization Server Metadata"
// - Implements RFC 8414 Section 3.1 for well-known URL construction with path support
// - Validates required fields: issuer, authorization_endpoint, token_endpoint
// - Validates issuer URL matches authorization server URL (RFC 8414 Section 3.2)
func fetchAuthorizationServerMetadata(ctx context.Context, client *http.Client, authServerURL string) (*AuthorizationServerMetadata, error) {
	// RFC 8414 Section 3.1: Construct well-known URL (handles issuer paths correctly)
	metadataURL, err := buildRFC8414WellKnownURL(authServerURL)
	if err != nil {
		return nil, fmt.Errorf("building well-known URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// RFC 8414 Section 3.1: Response MUST be application/json
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata from %s: %w", metadataURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorization server metadata endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}

	// RFC 8414 Section 3.2: Validate required fields
	if metadata.Issuer == "" {
		return nil, fmt.Errorf("issuer field missing in authorization server metadata")
	}
	if metadata.Issuer != authServerURL {
		return nil, fmt.Errorf("authorization server metadata issuer %q does not match requested issuer %q", metadata.Issuer, authServerURL)
	}
	if metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization_endpoint field missing in authorization server metadata")
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("token_endpoint field missing in authorization server metadata")
	}

	// RFC 8414 Section 3.2: Validate issuer URL is valid
	_, err = url.Parse(metadata.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}

	return &metadata, nil
}

func validateProtectedResource(expected, actual string) error {
	if actual != expected {
		return fmt.Errorf("protected resource metadata resource %q does not match requested resource %q", actual, expected)
	}
	return nil
}

func validateSameOrigin(serverURL, metadataURL string) error {
	server, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	metadata, err := url.Parse(metadataURL)
	if err != nil {
		return fmt.Errorf("invalid metadata URL: %w", err)
	}
	if server.Scheme == "" || server.Hostname() == "" || server.User != nil {
		return fmt.Errorf("server URL must be an absolute URL without user information")
	}
	if metadata.Scheme == "" || metadata.Hostname() == "" || metadata.User != nil {
		return fmt.Errorf("metadata URL must be an absolute URL without user information")
	}

	serverPort := server.Port()
	if serverPort == "" {
		serverPort = defaultPort(server.Scheme)
	}
	metadataPort := metadata.Port()
	if metadataPort == "" {
		metadataPort = defaultPort(metadata.Scheme)
	}
	if !strings.EqualFold(server.Scheme, metadata.Scheme) ||
		!strings.EqualFold(server.Hostname(), metadata.Hostname()) ||
		serverPort != metadataPort {
		return fmt.Errorf("metadata URL %q must use the same origin as MCP server %q", metadataURL, serverURL)
	}
	return nil
}

func sameOriginHTTPClient(client *http.Client, originURL string) *http.Client {
	cloned := *client
	cloned.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return validateSameOrigin(originURL, req.URL.String())
	}
	return &cloned
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// buildRFC9728WellKnownURL constructs the protected-resource metadata URL by
// inserting the well-known suffix before the resource path while preserving
// its query, as required by RFC 9728 Section 3.1.
func buildRFC9728WellKnownURL(resourceURL string) (string, error) {
	parsed, err := url.Parse(resourceURL)
	if err != nil {
		return "", fmt.Errorf("invalid resource URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("resource URL must be an absolute URL without user information")
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("resource URL must not contain fragment")
	}

	resourcePath := parsed.EscapedPath()
	if resourcePath == "/" {
		resourcePath = ""
	}
	metadataURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource%s", parsed.Scheme, strings.ToLower(parsed.Host), resourcePath)
	if parsed.RawQuery != "" {
		metadataURL += "?" + parsed.RawQuery
	}
	return metadataURL, nil
}
