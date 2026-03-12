package bytelimiter

import (
	"sync"
	"time"
)

// ByteLimiter implements a simple byte-based semaphore with optional blocking
// and best-effort non-blocking acquisition helpers.
type ByteLimiter struct {
	max    int
	mu     sync.Mutex
	used   int
	closed bool
	notify chan struct{}
}

// New returns a new ByteLimiter allowing up to max bytes in flight.
// When max <= 0 the limiter is disabled and nil is returned.
func New(max int) *ByteLimiter {
	if max <= 0 {
		return nil
	}
	return &ByteLimiter{
		max:    max,
		notify: make(chan struct{}),
	}
}

// Acquire blocks until n additional bytes can be reserved.
func (b *ByteLimiter) Acquire(n int) {
	_ = b.WaitAcquire(n, nil, -1)
}

// TryAcquire attempts to reserve n bytes without blocking.
// It returns true on success and false if the limit would be exceeded.
func (b *ByteLimiter) TryAcquire(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	if b.used+n > b.max {
		return false
	}
	b.used += n
	return true
}

// WaitAcquire blocks until n bytes can be reserved, the limiter is closed,
// the optional done channel fires, or the timeout elapses.
// Use timeout < 0 to wait indefinitely.
func (b *ByteLimiter) WaitAcquire(n int, done <-chan struct{}, timeout time.Duration) bool {
	if b == nil {
		return true
	}
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		timerC = timer.C
		defer timer.Stop()
	}
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return false
		}
		if b.used+n <= b.max {
			b.used += n
			b.mu.Unlock()
			return true
		}
		notify := b.notify
		b.mu.Unlock()

		select {
		case <-notify:
		case <-done:
			return false
		case <-timerC:
			return false
		}
	}
}

// Release frees n bytes that were previously reserved.
func (b *ByteLimiter) Release(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.signalLocked()
	b.mu.Unlock()
}

// Close resets the limiter and wakes any waiters.
func (b *ByteLimiter) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	b.used = 0
	b.signalLocked()
	b.mu.Unlock()
}

// Used reports the current number of reserved bytes.
func (b *ByteLimiter) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Capacity returns the configured maximum number of bytes.
func (b *ByteLimiter) Capacity() int {
	if b == nil {
		return 0
	}
	return b.max
}

func (b *ByteLimiter) signalLocked() {
	if b.notify != nil {
		close(b.notify)
	}
	if !b.closed {
		b.notify = make(chan struct{})
	} else {
		b.notify = nil
	}
}
