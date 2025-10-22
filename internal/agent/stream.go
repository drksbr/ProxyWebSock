package agent

import (
	"net"
	"sync"
)

type agentStream struct {
	id        string
	conn      net.Conn
	limiter   *byteLimiter
	closed    chan struct{}
	closeOnce sync.Once
}

func newAgentStream(id string, conn net.Conn, maxInFlight int) *agentStream {
	return &agentStream{
		id:      id,
		conn:    conn,
		limiter: newByteLimiter(maxInFlight),
		closed:  make(chan struct{}),
	}
}

func (s *agentStream) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.conn.Close()
		if s.limiter != nil {
			s.limiter.Close()
		}
	})
}

func (s *agentStream) acquire(n int) {
	if s.limiter != nil {
		s.limiter.Acquire(n)
	}
}

func (s *agentStream) release(n int) {
	if s.limiter != nil {
		s.limiter.Release(n)
	}
}

type byteLimiter struct {
	max  int
	mu   sync.Mutex
	cond *sync.Cond
	used int
}

func newByteLimiter(max int) *byteLimiter {
	if max <= 0 {
		return nil
	}
	l := &byteLimiter{max: max}
	l.cond = sync.NewCond(&l.mu)
	return l
}

func (b *byteLimiter) Acquire(n int) {
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

func (b *byteLimiter) Release(n int) {
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

func (b *byteLimiter) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.used = 0
	b.mu.Unlock()
	b.cond.Broadcast()
}
