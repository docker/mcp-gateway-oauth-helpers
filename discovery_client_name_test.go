package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryClientName(t *testing.T) {
	for _, tc := range []struct {
		name       string
		clientName string
		configured bool
		want       string
	}{
		{name: "default", want: "mcp-gateway"},
		{name: "empty", configured: true, want: "mcp-gateway"},
		{name: "custom", configured: true, clientName: "sbx", want: "sbx"},
		{name: "escaped", configured: true, clientName: "a\"b\\c\nλ", want: "a\"b\\c\nλ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got struct {
				Method string `json:"method"`
				Params struct {
					ClientInfo struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"clientInfo"`
				} `json:"params"`
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/mcp" {
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Errorf("decode initialize: %v", err)
					}
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()

			ctx := context.Background()
			if tc.configured {
				ctx = WithClientName(ctx, tc.clientName)
			}
			_, _ = DiscoverOAuthRequirements(ctx, srv.URL+"/mcp")
			if got.Method != "initialize" || got.Params.ClientInfo.Name != tc.want || got.Params.ClientInfo.Version != "1.0.0" {
				t.Fatalf("unexpected initialize: %+v", got)
			}
		})
	}
}
