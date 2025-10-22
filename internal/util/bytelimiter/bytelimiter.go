package bytelimiter

import "sync"

// ByteLimiter implements a simple byte-based semaphore with optional blocking
// and best-effort non-blocking acquisition helpers.
type ByteLimiter struct {
	max  int
	mu   sync.Mutex
	cond *sync.Cond
	used int
}

// New returns a new ByteLimiter allowing up to max bytes in flight.
// When max <= 0 the limiter is disabled and nil is returned.
func New(max int) *ByteLimiter {
	if max <= 0 {
		return nil
	}
	bl := &ByteLimiter{max: max}
	bl.cond = sync.NewCond(&bl.mu)
	return bl
}

// Acquire blocks until n additional bytes can be reserved.
func (b *ByteLimiter) Acquire(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.used+n > b.max {
		b.cond.Wait()
	}
	b.used += n
}

// TryAcquire attempts to reserve n bytes without blocking.
// It returns true on success and false if the limit would be exceeded.
func (b *ByteLimiter) TryAcquire(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.max {
		return false
	}
	b.used += n
	return true
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
	b.mu.Unlock()
	b.cond.Broadcast()
}

// Close resets the limiter and wakes any waiters.
func (b *ByteLimiter) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used = 0
	b.mu.Unlock()
	b.cond.Broadcast()
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
