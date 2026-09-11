package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// noopBaseRoundTripper stands in for the underlying transport so the test
// never performs real network I/O: publicOnlyRoundTripper.RoundTrip logs its
// SSRF-guard warning before delegating, which is all this test needs to
// observe.
type noopBaseRoundTripper struct{}

func (noopBaseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("noopBaseRoundTripper: no network access in test")
}

// TestPublicOnlyRoundTripperEscapesControlCharactersInLog guards the fix for
// the CodeQL "Log entries created from user input" alerts on ssrf.go: a
// request URL whose host contains control characters (here a raw CRLF) must
// not be written raw into the SSRF-guard warning log, where it could forge
// or corrupt log entries. Both interpolated values (the URL and the
// validation error, which embeds the same host) must come through escaped.
func TestPublicOnlyRoundTripperEscapesControlCharactersInLog(t *testing.T) {
	logger := &testLogger{}
	ctx := WithLogger(context.Background(), logger)

	// Built directly (not via url.Parse, which rejects raw control bytes) to
	// simulate a host string that reaches this code with control characters
	// already present. The suffix keeps it matching isBlockedHostname so the
	// SSRF guard actually fires and logs.
	taintedHost := "evil\r\nInjected: true.internal"
	req := (&http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: "https",
			Host:   taintedHost,
			Path:   "/",
		},
	}).WithContext(ctx)

	rt := &publicOnlyRoundTripper{base: noopBaseRoundTripper{}}
	_, _ = rt.RoundTrip(req)

	if len(logger.warns) != 1 {
		t.Fatalf("expected exactly one SSRF warning, got: %v", logger.warns)
	}
	warning := logger.warns[0]

	if strings.ContainsAny(warning, "\r\n") {
		t.Fatalf("expected control characters to be escaped, got raw control characters in warning: %q", warning)
	}
	if !strings.Contains(warning, `\r`) || !strings.Contains(warning, `\n`) {
		t.Fatalf("expected the escaped form of the control characters in the warning, got: %q", warning)
	}
}
