package relay

import (
	"testing"
	"time"
)

func TestCircuitBreakerRegistryTransitions(t *testing.T) {
	now := time.Now().UTC()
	registry := newCircuitBreakerRegistry(2, 5*time.Second)

	if _, allowed := registry.Allow("group-1", "Hospital A", "aghuse:443", now); !allowed {
		t.Fatal("expected initial request to be allowed")
	}

	snapshot := registry.RecordFailure("group-1", "Hospital A", "aghuse:443", "dial failed", now)
	if snapshot.State != string(circuitBreakerClosed) || snapshot.ConsecutiveFailures != 1 {
		t.Fatalf("unexpected first failure snapshot: %+v", snapshot)
	}

	snapshot = registry.RecordFailure("group-1", "Hospital A", "aghuse:443", "dial failed", now.Add(time.Second))
	if snapshot.State != string(circuitBreakerOpen) {
		t.Fatalf("expected breaker to open: %+v", snapshot)
	}
	if _, allowed := registry.Allow("group-1", "Hospital A", "aghuse:443", now.Add(2*time.Second)); allowed {
		t.Fatal("expected open breaker to block")
	}

	snapshot, allowed := registry.Allow("group-1", "Hospital A", "aghuse:443", now.Add(6*time.Second))
	if !allowed || snapshot.State != string(circuitBreakerHalfOpen) || !snapshot.ProbeInFlight {
		t.Fatalf("expected half-open probe to be allowed: allowed=%v snapshot=%+v", allowed, snapshot)
	}

	if _, allowed := registry.Allow("group-1", "Hospital A", "aghuse:443", now.Add(6*time.Second)); allowed {
		t.Fatal("expected concurrent half-open request to be blocked")
	}

	snapshot = registry.RecordSuccess("group-1", "Hospital A", "aghuse:443", now.Add(7*time.Second))
	if snapshot.State != string(circuitBreakerClosed) {
		t.Fatalf("expected breaker to close after successful probe: %+v", snapshot)
	}
	if _, ok := registry.Snapshot("group-1", "aghuse:443"); ok {
		t.Fatal("expected closed breaker to be evicted")
	}
}

func TestCircuitBreakerRegistryReopensOnFailedProbe(t *testing.T) {
	now := time.Now().UTC()
	registry := newCircuitBreakerRegistry(1, 10*time.Second)

	registry.RecordFailure("group-1", "Hospital A", "sis:8443", "dial failed", now)
	if _, allowed := registry.Allow("group-1", "Hospital A", "sis:8443", now.Add(5*time.Second)); allowed {
		t.Fatal("expected breaker to remain open during cooldown")
	}

	snapshot, allowed := registry.Allow("group-1", "Hospital A", "sis:8443", now.Add(11*time.Second))
	if !allowed || snapshot.State != string(circuitBreakerHalfOpen) {
		t.Fatalf("expected half-open state after cooldown: allowed=%v snapshot=%+v", allowed, snapshot)
	}

	snapshot = registry.RecordFailure("group-1", "Hospital A", "sis:8443", "probe failed", now.Add(11*time.Second))
	if snapshot.State != string(circuitBreakerOpen) {
		t.Fatalf("expected failed probe to reopen breaker: %+v", snapshot)
	}
	if !snapshot.OpenUntil.After(now.Add(11 * time.Second)) {
		t.Fatalf("expected cooldown to be extended: %+v", snapshot)
	}
}
