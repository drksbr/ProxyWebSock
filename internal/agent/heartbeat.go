package agent

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

const (
	heartbeatInterval = 10 * time.Second
	heartbeatTimeout  = 25 * time.Second
)

type heartbeatState struct {
	seq atomic.Uint64

	mu                  sync.Mutex
	pending             map[uint64]time.Time
	scheduled           map[uint64]time.Time
	lastRTT             time.Duration
	jitter              time.Duration
	consecutiveFailures int
	lastAck             time.Time
	lastSent            time.Time
	lastError           string
	lastErrorAt         time.Time
	lastSendDelay       time.Duration
	cpuPercent          float64
	rssBytes            uint64
	goroutines          int
}

func newHeartbeatState() *heartbeatState {
	return &heartbeatState{
		pending:   make(map[uint64]time.Time),
		scheduled: make(map[uint64]time.Time),
	}
}

func (h *heartbeatState) nextPayload(now time.Time) *protocol.HeartbeatPayload {
	seq := h.seq.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()

	payload := &protocol.HeartbeatPayload{
		Sequence: seq,
		Mode:     protocol.HeartbeatModePing,
	}
	if stats := h.statsSnapshotLocked(); stats != nil {
		payload.Stats = stats
	}
	h.scheduled[seq] = now
	return payload
}

func (h *heartbeatState) markSent(seq uint64, sentAt time.Time) {
	h.mu.Lock()
	if sentAt.IsZero() {
		sentAt = time.Now()
	}
	if scheduledAt, ok := h.scheduled[seq]; ok {
		delete(h.scheduled, seq)
		delay := sentAt.Sub(scheduledAt)
		if delay < 0 {
			delay = 0
		}
		h.lastSendDelay = delay
	}
	h.pending[seq] = sentAt
	h.lastSent = sentAt
	h.mu.Unlock()
}

func (h *heartbeatState) markSendFailure() {
	h.mu.Lock()
	h.consecutiveFailures++
	h.mu.Unlock()
}

func (h *heartbeatState) handleAck(seq uint64, ackTime time.Time) {
	h.mu.Lock()
	sentAt, ok := h.pending[seq]
	if ok {
		delete(h.pending, seq)
	}
	if !ok {
		h.mu.Unlock()
		return
	}
	rtt := ackTime.Sub(sentAt)
	if rtt < 0 {
		rtt = time.Since(sentAt)
	}
	if rtt < 0 {
		rtt = 0
	}

	if h.lastRTT == 0 {
		h.lastRTT = rtt
	} else {
		delta := rtt - h.lastRTT
		if delta < 0 {
			delta = -delta
		}
		h.jitter = (3*h.jitter + delta) / 4
		h.lastRTT = (3*h.lastRTT + rtt) / 4
	}

	h.consecutiveFailures = 0
	h.lastAck = ackTime
	h.mu.Unlock()
}

func (h *heartbeatState) expirePending(now time.Time) {
	h.mu.Lock()
	for seq, scheduledAt := range h.scheduled {
		if now.Sub(scheduledAt) > heartbeatTimeout {
			delete(h.scheduled, seq)
			h.consecutiveFailures++
		}
	}
	for seq, sentAt := range h.pending {
		if now.Sub(sentAt) > heartbeatTimeout {
			delete(h.pending, seq)
			h.consecutiveFailures++
		}
	}
	h.mu.Unlock()
}

func (h *heartbeatState) recordError(message string) {
	if message == "" {
		return
	}
	h.mu.Lock()
	h.lastError = message
	h.lastErrorAt = time.Now()
	h.mu.Unlock()
}

func (h *heartbeatState) updateResources(cpu float64, rss uint64, goroutines int) {
	h.mu.Lock()
	h.cpuPercent = cpu
	h.rssBytes = rss
	h.goroutines = goroutines
	h.mu.Unlock()
}

func (h *heartbeatState) statsSnapshotLocked() *protocol.HeartbeatStats {
	if h.lastRTT == 0 && h.jitter == 0 && h.consecutiveFailures == 0 && h.lastError == "" &&
		len(h.pending) == 0 && h.lastSendDelay == 0 && h.cpuPercent == 0 && h.rssBytes == 0 && h.goroutines == 0 {
		return nil
	}
	stats := &protocol.HeartbeatStats{
		RTTMillis:           durationToMillis(h.lastRTT),
		JitterMillis:        durationToMillis(h.jitter),
		ConsecutiveFailures: h.consecutiveFailures,
	}
	if h.lastError != "" {
		stats.LastError = h.lastError
		if !h.lastErrorAt.IsZero() {
			stats.LastErrorAt = h.lastErrorAt.UnixNano()
		}
	}
	if pending := len(h.pending); pending > 0 {
		stats.Pending = pending
	}
	if delay := durationToMillis(h.lastSendDelay); delay > 0 {
		stats.SendDelayMillis = delay
	}
	if h.cpuPercent > 0 {
		stats.CPUPercent = h.cpuPercent
	}
	if h.rssBytes > 0 {
		stats.RSSBytes = h.rssBytes
	}
	if h.goroutines > 0 {
		stats.Goroutines = h.goroutines
	}
	return stats
}

func durationToMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}
