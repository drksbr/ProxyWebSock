package relay

import (
	"sync"
	"time"
)

const defaultDiagnosticHistoryLimit = 40

type diagnosticHistory struct {
	mu     sync.RWMutex
	limit  int
	events []statusDiagnosticEvent
}

func newDiagnosticHistory(limit int) *diagnosticHistory {
	if limit <= 0 {
		limit = defaultDiagnosticHistoryLimit
	}
	return &diagnosticHistory{
		limit:  limit,
		events: make([]statusDiagnosticEvent, 0, limit),
	}
}

func (h *diagnosticHistory) add(event statusDiagnosticEvent) {
	if h == nil {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.events) >= h.limit {
		copy(h.events, h.events[1:])
		h.events[len(h.events)-1] = event
		return
	}
	h.events = append(h.events, event)
}

func (h *diagnosticHistory) list() []statusDiagnosticEvent {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.events) == 0 {
		return nil
	}
	result := make([]statusDiagnosticEvent, len(h.events))
	copy(result, h.events)
	return result
}
