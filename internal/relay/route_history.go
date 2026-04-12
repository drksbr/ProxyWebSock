package relay

import (
	"sync"
	"time"
)

const defaultRouteHistoryLimit = 80

type routeHistory struct {
	mu     sync.RWMutex
	limit  int
	events []statusRouteEvent
}

func newRouteHistory(limit int) *routeHistory {
	if limit <= 0 {
		limit = defaultRouteHistoryLimit
	}
	return &routeHistory{
		limit:  limit,
		events: make([]statusRouteEvent, 0, limit),
	}
}

func (h *routeHistory) add(event statusRouteEvent) {
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

func (h *routeHistory) list() []statusRouteEvent {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.events) == 0 {
		return nil
	}
	result := make([]statusRouteEvent, len(h.events))
	copy(result, h.events)
	return result
}

func (s *relayServer) recordRouteOutcome(protocol, target string, principal proxyPrincipal, decision routeDecision, err error) {
	if s == nil {
		return
	}
	event := statusRouteEvent{
		Timestamp:      time.Now(),
		Protocol:       protocol,
		Target:         target,
		PrincipalType:  decision.PrincipalType,
		PrincipalName:  decision.PrincipalName,
		GroupID:        decision.GroupID,
		GroupName:      decision.GroupName,
		ProfileID:      decision.ProfileID,
		ProfileName:    decision.ProfileName,
		AgentID:        decision.AgentID,
		AgentName:      decision.AgentName,
		CandidateCount: decision.CandidateCount,
		SelectedStatus: decision.SelectedStatus,
		ReasonCode:     decision.ReasonCode,
		Message:        decision.Reason,
	}
	if event.PrincipalType == "" {
		event.PrincipalType = string(principal.Kind)
	}
	if event.PrincipalName == "" {
		switch principal.Kind {
		case proxyPrincipalAgent:
			event.PrincipalName = principal.AgentID
		case proxyPrincipalUser:
			event.PrincipalName = principal.Username
		}
	}
	if err != nil {
		event.Outcome = "failed"
		event.Message = err.Error()
		if re, ok := err.(*routeError); ok {
			if re.reasonCode != "" {
				event.ReasonCode = re.reasonCode
			}
			if re.groupID != "" {
				event.GroupID = re.groupID
			}
			if re.groupName != "" {
				event.GroupName = re.groupName
			}
			if re.profileID != "" {
				event.ProfileID = re.profileID
			}
			if re.profileName != "" {
				event.ProfileName = re.profileName
			}
			if re.candidateCount > 0 {
				event.CandidateCount = re.candidateCount
			}
		} else if event.ReasonCode == "" {
			event.ReasonCode = "internal_error"
		}
		s.stats.routeFailures.Add(1)
	} else {
		event.Outcome = "selected"
		if event.ReasonCode == "" {
			event.ReasonCode = "route_selected"
		}
		s.stats.routeDecisions.Add(1)
	}
	if s.routeHistory != nil {
		s.routeHistory.add(event)
	}
}
