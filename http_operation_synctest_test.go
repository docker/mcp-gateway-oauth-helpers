//go:build go1.25

package oauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestAuthorizationServerOperationFallback(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				var calls atomic.Int32
				primaryDone := make(chan struct{})
				served := make(chan error, 1)
				dial := func(ctx context.Context, network, address string) (net.Conn, error) {
					calls.Add(1)
					if address == "[2001:4860:4860::8888]:80" {
						defer close(primaryDone)
						<-ctx.Done()
						return nil, ctx.Err()
					}
					if network != "tcp" || address != "8.8.8.8:80" {
						return nil, fmt.Errorf("unexpected destination %s %s", network, address)
					}
					client, server := net.Pipe()
					go func() {
						defer server.Close()
						req, err := http.ReadRequest(bufio.NewReader(server))
						if err == nil {
							_ = req.Body.Close()
							_, err = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nmetadata")
						}
						served <- err
					}()
					return client, nil
				}
				client, ctx := operationTestClient(context.Background(), t, selected, staticResolver{"localhost": {netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("8.8.8.8")}}, dial, 30*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metadata", nil)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || string(body) != "metadata" {
					t.Fatalf("body=%q error=%v", body, err)
				}
				<-primaryDone
				if err := <-served; err != nil {
					t.Fatal(err)
				}
				if elapsed := time.Since(started); elapsed != 300*time.Millisecond {
					t.Fatalf("fallback elapsed=%s, want 300ms", elapsed)
				}
				if calls.Load() != 2 {
					t.Fatalf("dials=%d, want two", calls.Load())
				}
			})
		})
	}
}

func TestAuthorizationServerZeroTimeoutBoundsDNS(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				completed := make(chan struct{})
				resolver := operationResolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					defer close(completed)
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) != 30*time.Second {
						return nil, fmt.Errorf("DNS deadline=%v present=%v", deadline, ok)
					}
					<-ctx.Done()
					return nil, ctx.Err()
				})
				client, ctx := operationTestClient(context.Background(), t, selected, resolver, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected dial") }, 0)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metadata", nil)
				_, err := client.Do(req)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error=%v, want deadline", err)
				}
				<-completed
				if elapsed := time.Since(started); elapsed != 30*time.Second {
					t.Fatalf("elapsed=%s, want 30s", elapsed)
				}
			})
		})
	}
}

func TestAuthorizationServerLiteralHonorsEarlierOperationDeadline(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := time.Now()
				operation, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				completed := make(chan struct{})
				var lookups atomic.Int32
				resolver := operationResolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					lookups.Add(1)
					return nil, errors.New("unexpected DNS")
				})
				client, ctx := operationTestClient(operation, t, selected, resolver, func(ctx context.Context, _, address string) (net.Conn, error) {
					defer close(completed)
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) != 5*time.Second || address != "127.0.0.1:80" {
						return nil, fmt.Errorf("dial deadline=%v present=%v address=%s", deadline, ok, address)
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}, 0)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/metadata", nil)
				_, err := client.Do(req)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error=%v, want operation deadline", err)
				}
				<-completed
				if elapsed := time.Since(started); elapsed != 5*time.Second || lookups.Load() != 0 {
					t.Fatalf("elapsed=%s lookups=%d", elapsed, lookups.Load())
				}
			})
		})
	}
}

func TestAuthorizationServerOperationCancelsBothFamilies(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "legacy"
		if selected {
			name = "selected"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				operation, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered := make(chan string, 2)
				var completed sync.WaitGroup
				dial := func(ctx context.Context, _, address string) (net.Conn, error) {
					completed.Add(1)
					defer completed.Done()
					entered <- address
					<-ctx.Done()
					return nil, ctx.Err()
				}
				client, ctx := operationTestClient(operation, t, selected, staticResolver{"localhost": {netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("8.8.8.8")}}, dial, 30*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/metadata", nil)
				result := make(chan error, 1)
				go func() { _, err := client.Do(req); result <- err }()
				if address := <-entered; address != "[2001:4860:4860::8888]:80" {
					t.Fatalf("first=%s", address)
				}
				time.Sleep(300 * time.Millisecond)
				if address := <-entered; address != "8.8.8.8:80" {
					t.Fatalf("fallback=%s", address)
				}
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatalf("error=%v, want cancellation", err)
				}
				completed.Wait()
			})
		})
	}
}
