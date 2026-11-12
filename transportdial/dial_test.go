package transportdial

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type trackedConn struct{ closes atomic.Int32 }

func (c *trackedConn) Close() error                   { c.closes.Add(1); return nil }
func (*trackedConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*trackedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*trackedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*trackedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*trackedConn) SetDeadline(time.Time) error      { return nil }
func (*trackedConn) SetReadDeadline(time.Time) error  { return nil }
func (*trackedConn) SetWriteDeadline(time.Time) error { return nil }

func boundedContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDialAddressesRejectsInvalidInputBeforeDial(t *testing.T) {
	valid := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		name, network string
		addresses     []netip.Addr
	}{
		{"empty", "tcp", nil},
		{"invalid after valid", "tcp", []netip.Addr{valid, {}}},
		{"no compatible", "tcp6", []netip.Addr{valid}},
		{"unsupported network", "udp", []netip.Addr{valid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			conn, err := DialAddresses(boundedContext(t), tc.network, "443", tc.addresses, func(context.Context, string, string) (net.Conn, error) {
				calls++
				return &trackedConn{}, nil
			})
			if err == nil || conn != nil || calls != 0 {
				t.Fatalf("conn=%v err=%v dials=%d", conn, err, calls)
			}
		})
	}
	if _, err := DialAddresses(context.Background(), "tcp", "443", []netip.Addr{valid}, nil); err == nil {
		t.Fatal("unbounded context accepted")
	}
	if _, err := DialAddresses(boundedContext(t), "tcp", "443", []netip.Addr{valid}, nil); err == nil {
		t.Fatal("nil dial function accepted")
	}
}

func TestDialAddressesFiltersAndNormalizesSnapshot(t *testing.T) {
	for _, tc := range []struct {
		network string
		want    []string
	}{
		{"tcp4", []string{"192.0.2.1:443", "192.0.2.2:443"}},
		{"tcp6", []string{"[2001:db8::1]:443", "[2001:db8::2]:443"}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			addresses := []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("192.0.2.2")}
			original := append([]netip.Addr(nil), addresses...)
			var got []string
			winner := &trackedConn{}
			conn, err := DialAddresses(boundedContext(t), tc.network, "443", addresses, func(_ context.Context, network, address string) (net.Conn, error) {
				if network != tc.network {
					t.Errorf("network=%s", network)
				}
				got = append(got, address)
				if len(got) == 1 {
					return nil, net.ErrClosed
				}
				return winner, nil
			})
			if err != nil || conn != winner || !reflect.DeepEqual(got, tc.want) || !reflect.DeepEqual(addresses, original) {
				t.Fatalf("conn=%v err=%v got=%v snapshot=%v", conn, err, got, addresses)
			}
			if winner.closes.Load() != 0 {
				t.Fatal("winning connection was closed")
			}
		})
	}
}

func TestDialAddressesPrimaryErrorWins(t *testing.T) {
	primary, fallback := errors.New("primary failed"), errors.New("fallback failed")
	_, err := DialAddresses(boundedContext(t), "tcp", "443", []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "[2001:db8::1]:443" {
			return nil, primary
		}
		return nil, fallback
	})
	if !errors.Is(err, primary) {
		t.Fatalf("error=%v, want primary failure", err)
	}
}

func TestDialAddressesCancellationWinsSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(boundedContext(t))
	defer cancel()
	late := &trackedConn{}
	conn, err := DialAddresses(ctx, "tcp", "443", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return late, nil
	})
	if conn != nil || !errors.Is(err, context.Canceled) || late.closes.Load() != 1 {
		t.Fatalf("conn=%v err=%v closes=%d", conn, err, late.closes.Load())
	}
}

func TestOperationContextPreservesValuesAndEarlierDeadline(t *testing.T) {
	type valueKey struct{}
	transportDeadline := time.Now().Add(5 * time.Second)
	transport, stopTransport := context.WithDeadline(context.WithValue(context.Background(), valueKey{}, "transport"), transportDeadline)
	defer stopTransport()
	operation, stopOperation := context.WithTimeout(context.Background(), 8*time.Second)
	defer stopOperation()
	ctx, cancel := OperationContext(operation, transport, 10*time.Second)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(transportDeadline) || ctx.Value(valueKey{}) != "transport" {
		t.Fatalf("deadline=%v values=%v", deadline, ctx.Value(valueKey{}))
	}
	operationDeadline := time.Now().Add(2 * time.Second)
	operation, stopEarlier := context.WithDeadline(context.Background(), operationDeadline)
	defer stopEarlier()
	ctx, cancelEarlier := OperationContext(operation, transport, 10*time.Second)
	defer cancelEarlier()
	deadline, _ = ctx.Deadline()
	if !deadline.Equal(operationDeadline) {
		t.Fatalf("deadline=%v want=%v", deadline, operationDeadline)
	}
}

func TestOperationContextCancellation(t *testing.T) {
	for _, source := range []string{"operation", "transport", "cleanup"} {
		t.Run(source, func(t *testing.T) {
			operation, stopOperation := context.WithCancel(context.Background())
			defer stopOperation()
			transport, stopTransport := context.WithCancel(context.Background())
			defer stopTransport()
			ctx, cancel := OperationContext(operation, transport, time.Minute)
			defer cancel()
			switch source {
			case "operation":
				stopOperation()
			case "transport":
				stopTransport()
			case "cleanup":
				cancel()
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation was not propagated")
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("error=%v", ctx.Err())
			}
		})
	}
	ctx, cancel := OperationContext(context.Background(), context.Background(), 0)
	defer cancel()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("nonpositive timeout error=%v", ctx.Err())
	}
}

func TestOperationContextAlreadyCompleted(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var operation context.Context
		var stop context.CancelFunc
		expected := context.Canceled
		if deadline {
			operation, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			expected = context.DeadlineExceeded
		} else {
			operation, stop = context.WithCancel(context.Background())
			stop()
		}
		defer stop()
		ctx, cancel := OperationContext(operation, context.Background(), 30*time.Second)
		if !errors.Is(ctx.Err(), expected) {
			t.Errorf("error=%v want=%v", ctx.Err(), expected)
		}
		cancel()
	}
}
