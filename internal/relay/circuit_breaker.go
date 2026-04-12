package relay

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type circuitBreakerState string

const (
	circuitBreakerClosed   circuitBreakerState = "closed"
	circuitBreakerOpen     circuitBreakerState = "open"
	circuitBreakerHalfOpen circuitBreakerState = "half-open"
)

const defaultCircuitBreakerFailures = 3
const defaultCircuitBreakerCooldown = 30 * time.Second
const defaultCircuitBreakerStatusLimit = 12

type circuitBreakerRegistry struct {
	mu               sync.Mutex
	failureThreshold int
	cooldown         time.Duration
	breakers         map[string]*destinationCircuitBreaker
}

type destinationCircuitBreaker struct {
	GroupID             string
	GroupName           string
	Target              string
	State               circuitBreakerState
	ConsecutiveFailures int
	LastError           string
	LastFailureAt       time.Time
	OpenUntil           time.Time
	ProbeInFlight       bool
}

type circuitBreakerSnapshot struct {
	GroupID             string
	GroupName           string
	Target              string
	State               string
	ConsecutiveFailures int
	LastError           string
	LastFailureAt       time.Time
	OpenUntil           time.Time
	ProbeInFlight       bool
}

func newCircuitBreakerRegistry(failureThreshold int, cooldown time.Duration) *circuitBreakerRegistry {
	if failureThreshold <= 0 {
		failureThreshold = defaultCircuitBreakerFailures
	}
	if cooldown <= 0 {
		cooldown = defaultCircuitBreakerCooldown
	}
	return &circuitBreakerRegistry{
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
		breakers:         make(map[string]*destinationCircuitBreaker),
	}
}

func (r *circuitBreakerRegistry) Allow(groupID, groupName, target string, now time.Time) (circuitBreakerSnapshot, bool) {
	if r == nil {
		return circuitBreakerSnapshot{}, true
	}
	key := circuitBreakerKey(groupID, target)
	r.mu.Lock()
	defer r.mu.Unlock()
	breaker, ok := r.breakers[key]
	if !ok {
		return circuitBreakerSnapshot{}, true
	}
	breaker.GroupName = firstNonEmpty(strings.TrimSpace(groupName), breaker.GroupName)
	switch breaker.State {
	case circuitBreakerOpen:
		if now.Before(breaker.OpenUntil) {
			return breaker.snapshot(), false
		}
		breaker.State = circuitBreakerHalfOpen
		breaker.ProbeInFlight = true
		return breaker.snapshot(), true
	case circuitBreakerHalfOpen:
		if breaker.ProbeInFlight {
			return breaker.snapshot(), false
		}
		breaker.ProbeInFlight = true
		return breaker.snapshot(), true
	default:
		return breaker.snapshot(), true
	}
}

func (r *circuitBreakerRegistry) RecordSuccess(groupID, groupName, target string, now time.Time) circuitBreakerSnapshot {
	if r == nil {
		return circuitBreakerSnapshot{}
	}
	key := circuitBreakerKey(groupID, target)
	r.mu.Lock()
	defer r.mu.Unlock()
	breaker, ok := r.breakers[key]
	if !ok {
		return circuitBreakerSnapshot{
			GroupID:   strings.TrimSpace(groupID),
			GroupName: strings.TrimSpace(groupName),
			Target:    strings.TrimSpace(target),
			State:     string(circuitBreakerClosed),
		}
	}
	breaker.GroupName = firstNonEmpty(strings.TrimSpace(groupName), breaker.GroupName)
	snapshot := circuitBreakerSnapshot{
		GroupID:   breaker.GroupID,
		GroupName: breaker.GroupName,
		Target:    breaker.Target,
		State:     string(circuitBreakerClosed),
	}
	delete(r.breakers, key)
	return snapshot
}

func (r *circuitBreakerRegistry) RecordFailure(groupID, groupName, target, lastError string, now time.Time) circuitBreakerSnapshot {
	if r == nil {
		return circuitBreakerSnapshot{}
	}
	groupID = strings.TrimSpace(groupID)
	target = strings.TrimSpace(target)
	if groupID == "" || target == "" {
		return circuitBreakerSnapshot{}
	}
	key := circuitBreakerKey(groupID, target)
	r.mu.Lock()
	defer r.mu.Unlock()
	breaker, ok := r.breakers[key]
	if !ok {
		breaker = &destinationCircuitBreaker{
			GroupID: groupID,
			Target:  target,
			State:   circuitBreakerClosed,
		}
		r.breakers[key] = breaker
	}
	breaker.GroupName = firstNonEmpty(strings.TrimSpace(groupName), breaker.GroupName)
	breaker.LastError = strings.TrimSpace(lastError)
	breaker.LastFailureAt = now

	switch breaker.State {
	case circuitBreakerHalfOpen:
		breaker.State = circuitBreakerOpen
		breaker.OpenUntil = now.Add(r.cooldown)
		breaker.ProbeInFlight = false
		breaker.ConsecutiveFailures = r.failureThreshold
	case circuitBreakerOpen:
		breaker.OpenUntil = now.Add(r.cooldown)
		breaker.ProbeInFlight = false
		if breaker.ConsecutiveFailures < r.failureThreshold {
			breaker.ConsecutiveFailures = r.failureThreshold
		}
	default:
		breaker.ConsecutiveFailures++
		if breaker.ConsecutiveFailures >= r.failureThreshold {
			breaker.State = circuitBreakerOpen
			breaker.OpenUntil = now.Add(r.cooldown)
			breaker.ProbeInFlight = false
		}
	}
	return breaker.snapshot()
}

func (r *circuitBreakerRegistry) Snapshot(groupID, target string) (circuitBreakerSnapshot, bool) {
	if r == nil {
		return circuitBreakerSnapshot{}, false
	}
	key := circuitBreakerKey(groupID, target)
	r.mu.Lock()
	defer r.mu.Unlock()
	breaker, ok := r.breakers[key]
	if !ok {
		return circuitBreakerSnapshot{}, false
	}
	if breaker.State == circuitBreakerOpen && time.Now().After(breaker.OpenUntil) && !breaker.ProbeInFlight {
		breaker.State = circuitBreakerHalfOpen
	}
	return breaker.snapshot(), true
}

func (r *circuitBreakerRegistry) ActiveSnapshots(limit int) []circuitBreakerSnapshot {
	if r == nil {
		return nil
	}
	if limit <= 0 {
		limit = defaultCircuitBreakerStatusLimit
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshots := make([]circuitBreakerSnapshot, 0, len(r.breakers))
	for key, breaker := range r.breakers {
		if breaker.State == circuitBreakerClosed && breaker.ConsecutiveFailures == 0 {
			delete(r.breakers, key)
			continue
		}
		if breaker.State == circuitBreakerOpen && now.After(breaker.OpenUntil) && !breaker.ProbeInFlight {
			breaker.State = circuitBreakerHalfOpen
		}
		snapshots = append(snapshots, breaker.snapshot())
	}
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].State == snapshots[j].State {
			if snapshots[i].LastFailureAt.Equal(snapshots[j].LastFailureAt) {
				return snapshots[i].Target < snapshots[j].Target
			}
			return snapshots[i].LastFailureAt.After(snapshots[j].LastFailureAt)
		}
		if snapshots[i].State == string(circuitBreakerOpen) {
			return true
		}
		if snapshots[j].State == string(circuitBreakerOpen) {
			return false
		}
		return snapshots[i].State < snapshots[j].State
	})
	if len(snapshots) > limit {
		snapshots = snapshots[:limit]
	}
	return snapshots
}

func circuitBreakerKey(groupID, target string) string {
	return fmt.Sprintf("%s|%s", strings.TrimSpace(groupID), strings.TrimSpace(target))
}

func (b *destinationCircuitBreaker) snapshot() circuitBreakerSnapshot {
	if b == nil {
		return circuitBreakerSnapshot{}
	}
	return circuitBreakerSnapshot{
		GroupID:             b.GroupID,
		GroupName:           b.GroupName,
		Target:              b.Target,
		State:               string(b.State),
		ConsecutiveFailures: b.ConsecutiveFailures,
		LastError:           b.LastError,
		LastFailureAt:       b.LastFailureAt,
		OpenUntil:           b.OpenUntil,
		ProbeInFlight:       b.ProbeInFlight,
	}
}

func (s *relayServer) allowRouteTarget(groupID, groupName, target string) (circuitBreakerSnapshot, bool) {
	if s == nil || s.breakers == nil {
		return circuitBreakerSnapshot{}, true
	}
	if strings.TrimSpace(groupID) == "" || strings.TrimSpace(target) == "" {
		return circuitBreakerSnapshot{}, true
	}
	return s.breakers.Allow(groupID, groupName, target, time.Now())
}

func (s *relayServer) recordDestinationCircuitOutcome(groupID, groupName, target string, err error) circuitBreakerSnapshot {
	if s == nil || s.breakers == nil {
		return circuitBreakerSnapshot{}
	}
	groupID = strings.TrimSpace(groupID)
	target = strings.TrimSpace(target)
	if groupID == "" || target == "" {
		return circuitBreakerSnapshot{}
	}
	if err == nil {
		return s.breakers.RecordSuccess(groupID, groupName, target, time.Now())
	}
	return s.breakers.RecordFailure(groupID, groupName, target, err.Error(), time.Now())
}
