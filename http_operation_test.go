package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func operationTestClient(ctx context.Context, t *testing.T, selected bool, resolver ipResolver, dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) (*http.Client, context.Context) {
	t.Helper()
	ctx = WithAllowLocalHTTP(ctx)
	if selected {
		ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, owned *http.Transport) (*http.Transport, bool, error) { return owned, false, nil })
	}
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: timeout}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return client, ctx
}

func TestAuthorizationServerOperationCancellation(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			entered, completed := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
				defer close(completed)
				calls.Add(1)
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			client, ctx := operationTestClient(ctx, t, selected, staticResolver{"localhost": {netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("2001:4860:4860::8844")}}, dial, 0)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metadata", nil)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := client.Do(req); result <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("dial did not start", ctx.Err())
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("error=%v, want cancellation", err)
			}
			<-completed
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want one", calls.Load())
			}
		})
	}
}

type operationResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f operationResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestAuthorizationServerOperationCancelsDNS(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			entered, completed := make(chan struct{}), make(chan struct{})
			resolver := operationResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				defer close(completed)
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			})
			var calls atomic.Int32
			client, ctx := operationTestClient(ctx, t, selected, resolver, func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("unexpected dial")
			}, 0)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metadata", nil)
			result := make(chan error, 1)
			go func() { _, err := client.Do(req); result <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("DNS did not start", ctx.Err())
			}
			cancel()
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("error=%v, want cancellation", err)
			}
			<-completed
			if calls.Load() != 0 {
				t.Fatalf("dialed during DNS cancellation: %d", calls.Load())
			}
		})
	}
}

func TestAuthorizationServerChecksCompleteSnapshotBeforeDial(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			logger := &testLogger{}
			ctx, recorder := contextWithSSRFRecorder(WithLogger(context.Background(), logger))
			failure := errors.New("observed pinned dial")
			var calls atomic.Int32
			var checked atomic.Bool
			dial := func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				checked.Store(recorder.failed && logger.containsWarn("resolved to disallowed address fc00::1"))
				return nil, failure
			}
			client, ctx := operationTestClient(ctx, t, selected, staticResolver{"auth.example.com": {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("fc00::1")}}, dial, time.Second)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://auth.example.com/metadata", nil)
			_, err := client.Do(req)
			if !errors.Is(err, failure) || calls.Load() != 2 || !checked.Load() {
				t.Fatalf("error=%v calls=%d complete checks=%v warnings=%v", err, calls.Load(), checked.Load(), logger.warns)
			}
		})
	}
}

func TestHTTPRouteUpstreamOperationCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, completed := make(chan struct{}), make(chan struct{})
	var lookups atomic.Int32
	resolver := operationResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, errors.New("unexpected local DNS")
	})
	ctx = WithHTTPRouteSelector(ctx, func(_ *http.Request, owned *http.Transport) (*http.Transport, bool, error) {
		owned.Proxy = nil
		owned.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			defer close(completed)
			if address != "auth.example.com:443" {
				return nil, errors.New("upstream target changed")
			}
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return owned, true, nil
	})
	client, err := newAuthorizationServerHTTPClientWithResolver(ctx, &http.Client{}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://auth.example.com/metadata", nil)
	result := make(chan error, 1)
	go func() { _, err := client.Do(req); result <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("upstream dial did not start", ctx.Err())
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want cancellation", err)
	}
	<-completed
	if lookups.Load() != 0 {
		t.Fatalf("upstream performed %d local lookups", lookups.Load())
	}
}
