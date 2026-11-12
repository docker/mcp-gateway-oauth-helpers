//go:build go1.25

package transportdial

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestCrossFamilyFallbackDelayAndJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		var primaryJoined atomic.Bool
		winner := &trackedConn{}
		conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, func(attempt context.Context, _, address string) (net.Conn, error) {
			if address == "[2001:db8::1]:443" {
				<-attempt.Done()
				primaryJoined.Store(true)
				return nil, attempt.Err()
			}
			if elapsed := time.Since(start); elapsed != 300*time.Millisecond {
				t.Errorf("fallback began after %s", elapsed)
			}
			return winner, nil
		})
		if err != nil || conn != winner || !primaryJoined.Load() || winner.closes.Load() != 0 {
			t.Fatalf("conn=%v err=%v joined=%v closes=%d", conn, err, primaryJoined.Load(), winner.closes.Load())
		}
	})
}

func TestPrimaryFailureAcceleratesFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		winner := &trackedConn{}
		conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, func(_ context.Context, _, address string) (net.Conn, error) {
			if address == "192.0.2.1:443" {
				return nil, net.ErrClosed
			}
			if elapsed := time.Since(start); elapsed != 0 {
				t.Errorf("failed primary delayed fallback by %s", elapsed)
			}
			return winner, nil
		})
		if err != nil || conn != winner {
			t.Fatalf("conn=%v err=%v", conn, err)
		}
	})
}

func TestSameFamilyAttemptBudgets(t *testing.T) {
	for _, tc := range []struct {
		name         string
		total, first time.Duration
		wantAttempts int
	}{
		{"equal shares", 30 * time.Second, 15 * time.Second, 2},
		{"two second floor", 3 * time.Second, 2 * time.Second, 2},
		{"floor capped by remaining", time.Second, time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), tc.total)
				defer cancel()
				calls := 0
				winner := &trackedConn{}
				conn, err := DialAddresses(ctx, "tcp4", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, func(attempt context.Context, _, _ string) (net.Conn, error) {
					calls++
					if calls == 1 {
						deadline, _ := attempt.Deadline()
						if got := time.Until(deadline); got != tc.first {
							t.Errorf("first budget=%s want=%s", got, tc.first)
						}
						<-attempt.Done()
						return nil, attempt.Err()
					}
					return winner, nil
				})
				if calls != tc.wantAttempts {
					t.Fatalf("attempts=%d want=%d", calls, tc.wantAttempts)
				}
				if tc.wantAttempts == 1 {
					if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("conn=%v err=%v", conn, err)
					}
				} else if conn != winner || err != nil {
					t.Fatalf("conn=%v err=%v", conn, err)
				}
			})
		})
	}
}

func TestRaceClosesLateSuccessfulSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		late, peer := net.Pipe()
		defer peer.Close()
		winner := &trackedConn{}
		conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, func(attempt context.Context, _, address string) (net.Conn, error) {
			if address == "[2001:db8::1]:443" {
				<-attempt.Done()
				return late, nil
			}
			return winner, nil
		})
		if conn != winner || err != nil {
			t.Fatalf("conn=%v err=%v", conn, err)
		}
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("losing socket remained open: %v", err)
		}
	})
}

func TestRaceClosesSimultaneousSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ready := make(chan struct{}, 2)
		release := make(chan struct{})
		go func() { <-ready; <-ready; close(release) }()
		primary, fallback := &trackedConn{}, &trackedConn{}
		conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, func(_ context.Context, _, address string) (net.Conn, error) {
			ready <- struct{}{}
			<-release
			if address == "[2001:db8::1]:443" {
				return primary, nil
			}
			return fallback, nil
		})
		if err != nil || conn == nil || primary.closes.Load()+fallback.closes.Load() != 1 {
			t.Fatalf("conn=%v err=%v primary closes=%d fallback closes=%d", conn, err, primary.closes.Load(), fallback.closes.Load())
		}
		if conn.(*trackedConn).closes.Load() != 0 {
			t.Fatal("winning connection was closed")
		}
	})
}

func TestRaceOperationCancellationJoinsBothWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		operation, stopOperation := context.WithCancel(context.Background())
		defer stopOperation()
		ctx, cancel := OperationContext(operation, context.Background(), 30*time.Second)
		defer cancel()
		ready := make(chan struct{}, 2)
		go func() { <-ready; <-ready; stopOperation() }()
		var calls, completed atomic.Int32
		var late [2]trackedConn
		conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, func(attempt context.Context, _, _ string) (net.Conn, error) {
			index := calls.Add(1) - 1
			ready <- struct{}{}
			<-attempt.Done()
			completed.Add(1)
			return &late[index], nil
		})
		if conn != nil || !errors.Is(err, context.Canceled) || calls.Load() != 2 || completed.Load() != 2 || late[0].closes.Load() != 1 || late[1].closes.Load() != 1 {
			t.Fatalf("conn=%v err=%v calls=%d joined=%d closes=%d,%d", conn, err, calls.Load(), completed.Load(), late[0].closes.Load(), late[1].closes.Load())
		}
	})
}

func TestOperationDeadlineErrorIsStable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		operation, stopOperation := context.WithTimeout(context.Background(), time.Second)
		defer stopOperation()
		ctx, cancel := OperationContext(operation, context.Background(), 30*time.Second)
		defer cancel()
		<-ctx.Done()
		synctest.Wait()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("deadline error=%v", ctx.Err())
		}
	})
}
