// Package transportdial connects to validated IP snapshots without resolving names.
package transportdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// OperationContext preserves transport values and cancellation while restoring
// the operation's cancellation and deadline. timeout bounds the whole connection
// operation, including resolution; a nonpositive timeout expires immediately.
// Call cancel after resolution and dialing finish to release the operation hook.
func OperationContext(operation, transport context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	if operationDeadline, ok := operation.Deadline(); ok && operationDeadline.Before(deadline) {
		deadline = operationDeadline
	}
	ctx, cancel := context.WithDeadline(transport, deadline)
	stop := context.AfterFunc(operation, func() {
		// The derived deadline supplies DeadlineExceeded without a cancellation race.
		if operation.Err() != context.DeadlineExceeded {
			cancel()
		}
	})
	if operation.Err() == context.Canceled {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

// DialAddresses connects only to the supplied IP literals. Callers must validate
// the complete snapshot before calling and supply a context with a deadline.
// tcp races the first address family against the other after 300 milliseconds,
// or immediately when the primary family fails. Each family tries its addresses
// serially, sharing its remaining deadline with a two-second minimum per attempt
// capped by the remaining time. tcp4 and tcp6 use only compatible addresses.
// dial must honor context cancellation: this function cancels and joins every
// worker and closes every losing connection before returning. Operation errors
// take precedence over connection errors; otherwise the primary family's final
// error wins. A successful connection belongs to the caller.
func DialAddresses(ctx context.Context, network, port string, addresses []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if err := operationError(ctx); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("IP dialing requires a deadline")
	}
	if dial == nil {
		return nil, errors.New("IP dial function is nil")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported IP dial network %q", network)
	}
	var primary, fallback []netip.Addr
	for _, address := range addresses {
		if !address.IsValid() {
			return nil, errors.New("IP dial snapshot contains an invalid address")
		}
		address = address.Unmap()
		if network == "tcp4" && !address.Is4() || network == "tcp6" && address.Is4() {
			continue
		}
		if len(primary) == 0 || address.Is4() == primary[0].Is4() {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	if len(primary) == 0 {
		return nil, errors.New("IP dial snapshot has no compatible addresses")
	}
	if len(fallback) == 0 {
		return dialSerial(ctx, network, port, primary, dial)
	}

	workers, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		primary bool
		conn    net.Conn
		err     error
	}
	results := make(chan result, 2)
	start := func(isPrimary bool, family []netip.Addr) {
		go func() {
			conn, err := dialSerial(workers, network, port, family, dial)
			results <- result{primary: isPrimary, conn: conn, err: err}
		}()
	}
	start(true, primary)
	started, finished := 1, 0
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	fallbackTimer := timer.C
	var primaryErr error
	finish := func(winner net.Conn, err error) (net.Conn, error) {
		cancel()
		for finished < started {
			other := <-results
			finished++
			if other.conn != nil {
				_ = other.conn.Close()
			}
		}
		if operationErr := operationError(ctx); operationErr != nil {
			if winner != nil {
				_ = winner.Close()
			}
			return nil, operationErr
		}
		return winner, err
	}
	for {
		select {
		case <-ctx.Done():
			return finish(nil, operationError(ctx))
		case <-fallbackTimer:
			if err := operationError(ctx); err != nil {
				return finish(nil, err)
			}
			fallbackTimer = nil
			start(false, fallback)
			started++
		case outcome := <-results:
			finished++
			if err := operationError(ctx); err != nil {
				if outcome.conn != nil {
					_ = outcome.conn.Close()
				}
				return finish(nil, err)
			}
			if outcome.err == nil {
				return finish(outcome.conn, nil)
			}
			if outcome.primary {
				primaryErr = outcome.err
			}
			if started == 1 {
				timer.Stop()
				fallbackTimer = nil
				start(false, fallback)
				started++
			}
			if finished == started {
				return finish(nil, primaryErr)
			}
		}
	}
}

func dialSerial(ctx context.Context, network, port string, addresses []netip.Addr, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	var lastErr error
	for i, address := range addresses {
		if err := operationError(ctx); err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		share := remaining / time.Duration(len(addresses)-i)
		if share < 2*time.Second {
			share = 2 * time.Second
		}
		if share > remaining {
			share = remaining
		}
		attempt, cancel := context.WithTimeout(ctx, share)
		conn, err := dial(attempt, network, net.JoinHostPort(address.String(), port))
		cancel()
		if operationErr := operationError(ctx); operationErr != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, operationErr
		}
		if err == nil && conn != nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			err = errors.New("IP dial function returned no connection")
		}
		lastErr = err
	}
	return nil, lastErr
}

func operationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
