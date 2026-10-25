package httpapi

import (
	"context"
	"sync"
	"time"
)

const (
	readinessTimeout = 2 * time.Second
	readinessTTL     = time.Second
)

// readiness bounds database work from public probes: concurrent checks share one
// ping, and its result is reused for a short period instead of drawing from the API quota.
type readiness struct {
	ping func(context.Context) error
	ttl  time.Duration

	mu      sync.Mutex
	ready   bool
	checked time.Time
	running chan struct{}
}

func newReadiness(ping func(context.Context) error, ttl time.Duration) *readiness {
	return &readiness{ping: ping, ttl: ttl}
}

func (c *readiness) check(ctx context.Context) bool {
	c.mu.Lock()
	// a running check implies an expired result, and a zero time is always expired.
	if time.Since(c.checked) < c.ttl {
		defer c.mu.Unlock()
		return c.ready
	}
	if running := c.running; running != nil {
		c.mu.Unlock()
		select {
		case <-running:
		case <-ctx.Done():
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.ready
	}
	done := make(chan struct{})
	c.running = done
	c.mu.Unlock()
	// the deferred update also releases waiters when ping panics; recovery happens upstream.
	ready := false
	defer func() {
		c.mu.Lock()
		c.ready, c.checked, c.running = ready, time.Now(), nil
		c.mu.Unlock()
		close(done)
	}()
	// waiters share this result, so the caller's disconnect must not fail their checks.
	pingCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readinessTimeout)
	defer cancel()
	ready = c.ping(pingCtx) == nil
	return ready
}
