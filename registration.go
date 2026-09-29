package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxRegistrationResponseBytes bounds how much of an RFC 7592 response is read.
const maxRegistrationResponseBytes = 1 << 20

var (
	// ErrRegistrationGone is returned by GetRegistration and UpdateRegistration
	// when the authorization server answers 401 or 404 for the registration:
	// the record was dropped or the registration access token is no longer
	// valid (RFC 7592 §2.1). Callers should discard the registration and
	// register again. Test with errors.Is.
	ErrRegistrationGone = errors.New("client registration no longer exists on the authorization server")

	// ErrNoRegistrationManagement is returned when a registration carries no
	// registration_client_uri or registration_access_token, so RFC 7592
	// operations are not possible. Callers should re-register instead.
	ErrNoRegistrationManagement = errors.New("client registration has no RFC 7592 management credentials")
)

// SecretExpired reports whether the registration's client secret has expired
// at now (client_secret_expires_at is non-zero and now has reached it).
func (r *ClientRegistration) SecretExpired(now time.Time) bool {
	return r != nil && r.ClientSecretExpiresAt != 0 && now.Unix() >= r.ClientSecretExpiresAt
}

// GetRegistration reads the client's registration from its RFC 7592
// registration_client_uri using the registration access token. It returns a
// copy of reg refreshed with the server's view, including a rotated
// registration_access_token or client_secret if the server issued one.
//
// A 401 or 404 response is reported as ErrRegistrationGone.
func GetRegistration(ctx context.Context, reg *ClientRegistration) (*ClientRegistration, error) {
	return doRegistrationRequest(ctx, http.MethodGet, reg, nil)
}

// UpdateRegistration replaces the client's registered metadata via an RFC 7592
// PUT to registration_client_uri. req is the full set of client metadata (the
// server replaces, not merges); client_id is added automatically. It returns a
// copy of reg refreshed from the response, including a possibly rotated
// registration_access_token and client_secret.
//
// A 401 or 404 response is reported as ErrRegistrationGone.
func UpdateRegistration(ctx context.Context, reg *ClientRegistration, req DCRRequest) (*ClientRegistration, error) {
	if reg == nil {
		return nil, ErrNoRegistrationManagement
	}
	body, err := json.Marshal(struct {
		ClientID string `json:"client_id"`
		DCRRequest
	}{ClientID: reg.ClientID, DCRRequest: req})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client update request: %w", err)
	}
	return doRegistrationRequest(ctx, http.MethodPut, reg, body)
}

func doRegistrationRequest(ctx context.Context, method string, reg *ClientRegistration, body []byte) (*ClientRegistration, error) {
	if reg == nil || reg.RegistrationClientURI == "" || reg.RegistrationAccessToken == "" {
		return nil, ErrNoRegistrationManagement
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, reg.RegistrationClientURI, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create client configuration request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+reg.RegistrationAccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MCP-Gateway/1.0.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := dcrHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send client configuration request to %s: %w", reg.RegistrationClientURI, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistrationResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read client configuration response: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s %s returned status %d: %w", method, reg.RegistrationClientURI, resp.StatusCode, ErrRegistrationGone)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("client configuration %s failed with status %d: %s", method, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var dcrResponse DCRResponse
	if err := json.Unmarshal(respBody, &dcrResponse); err != nil {
		return nil, fmt.Errorf("failed to decode client configuration response: %w", err)
	}
	if dcrResponse.ClientID != "" && dcrResponse.ClientID != reg.ClientID {
		return nil, fmt.Errorf("client configuration response client_id %q does not match registered client_id %q", dcrResponse.ClientID, reg.ClientID)
	}

	return registrationFromResponse(reg.Issuer, &dcrResponse, reg), nil
}

// IsInvalidClientError reports whether an OAuth token endpoint response body
// carries the invalid_client error (RFC 6749 §5.2), meaning the client
// registration is unknown or rejected and should be discarded.
//
// The body may be JSON ({"error":"invalid_client"}) or form-encoded
// (error=invalid_client), as some servers send. statusCode is only used to
// rule out successful (2xx) responses; pass 0 when there is no HTTP status.
// For the error parameter of an authorize redirect, use
// IsInvalidClientErrorCode.
func IsInvalidClientError(statusCode int, body []byte) bool {
	if statusCode >= 200 && statusCode < 300 {
		return false
	}

	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		return IsInvalidClientErrorCode(parsed.Error)
	}
	if values, err := url.ParseQuery(strings.TrimSpace(string(body))); err == nil {
		return IsInvalidClientErrorCode(values.Get("error"))
	}
	return false
}

// IsInvalidClientErrorCode reports whether an OAuth error code, such as the
// error query parameter of an authorization response, is invalid_client.
func IsInvalidClientErrorCode(code string) bool {
	return code == "invalid_client"
}
