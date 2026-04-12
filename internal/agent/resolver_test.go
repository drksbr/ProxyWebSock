package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialResolverCachesNegativeLookups(t *testing.T) {
	t.Parallel()

	resolver := newDialResolver(dialResolverConfig{
		PositiveTTL:         50 * time.Millisecond,
		NegativeTTL:         40 * time.Millisecond,
		StaleTTL:            0,
		RefreshBeforeExpiry: 10 * time.Millisecond,
		RefreshTimeout:      20 * time.Millisecond,
	})

	var lookups atomic.Int32
	resolver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, errors.New("dns unavailable")
	}

	if _, err := resolver.resolvePlan(context.Background(), "svc.local", ""); err == nil || !strings.Contains(err.Error(), "dns unavailable") {
		t.Fatalf("expected original resolver error, got %v", err)
	}
	if _, err := resolver.resolvePlan(context.Background(), "svc.local", ""); err == nil || !strings.Contains(err.Error(), "cached negative answer") {
		t.Fatalf("expected cached negative answer, got %v", err)
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("expected a single upstream lookup, got %d", got)
	}
}

func TestDialResolverServesStaleCacheWhileRefreshing(t *testing.T) {
	t.Parallel()

	resolver := newDialResolver(dialResolverConfig{
		PositiveTTL:         20 * time.Millisecond,
		NegativeTTL:         20 * time.Millisecond,
		StaleTTL:            150 * time.Millisecond,
		RefreshBeforeExpiry: 5 * time.Millisecond,
		RefreshTimeout:      50 * time.Millisecond,
	})

	var lookups atomic.Int32
	var phase atomic.Int32
	resolver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if phase.Load() == 0 {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil
	}

	plan, err := resolver.resolvePlan(context.Background(), "svc.local", "")
	if err != nil {
		t.Fatalf("initial resolve failed: %v", err)
	}
	if plan.source != "dns" || len(plan.addresses) != 1 || plan.addresses[0] != "10.0.0.1" {
		t.Fatalf("unexpected initial plan: %+v", plan)
	}

	phase.Store(1)
	time.Sleep(30 * time.Millisecond)

	plan, err = resolver.resolvePlan(context.Background(), "svc.local", "")
	if err != nil {
		t.Fatalf("stale resolve failed: %v", err)
	}
	if plan.source != "dns-stale-cache" || len(plan.addresses) != 1 || plan.addresses[0] != "10.0.0.1" {
		t.Fatalf("expected stale cached answer, got %+v", plan)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		plan, err = resolver.resolvePlan(context.Background(), "svc.local", "")
		if err == nil && len(plan.addresses) == 1 && plan.addresses[0] == "10.0.0.2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background refresh did not publish new address, last plan=%+v err=%v lookups=%d", plan, err, lookups.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := lookups.Load(); got < 2 {
		t.Fatalf("expected at least two upstream lookups, got %d", got)
	}
}

func TestDialResolverReordersAddressesByDialOutcome(t *testing.T) {
	t.Parallel()

	resolver := newDialResolver(dialResolverConfig{
		PositiveTTL:         time.Minute,
		NegativeTTL:         time.Second,
		StaleTTL:            time.Minute,
		RefreshBeforeExpiry: 5 * time.Second,
		RefreshTimeout:      time.Second,
	})

	host := normalizeDNSHost("svc.local")
	resolver.storePositiveCache(host, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})

	resolver.recordDialFailure(host, "10.0.0.1")
	addresses, _, err, _ := resolver.lookupCache(host)
	if err != nil {
		t.Fatalf("lookup after failure failed: %v", err)
	}
	if len(addresses) != 3 || addresses[0] != "10.0.0.2" {
		t.Fatalf("expected failed address to be demoted, got %v", addresses)
	}

	resolver.recordDialSuccess(host, "10.0.0.3")
	addresses, _, err, _ = resolver.lookupCache(host)
	if err != nil {
		t.Fatalf("lookup after success failed: %v", err)
	}
	if len(addresses) != 3 || addresses[0] != "10.0.0.3" {
		t.Fatalf("expected successful address to be promoted, got %v", addresses)
	}
}

func TestDialResolverSoakUnderDNSInstability(t *testing.T) {
	resolver := newDialResolver(dialResolverConfig{
		PositiveTTL:         15 * time.Millisecond,
		NegativeTTL:         10 * time.Millisecond,
		StaleTTL:            300 * time.Millisecond,
		RefreshBeforeExpiry: 5 * time.Millisecond,
		RefreshTimeout:      20 * time.Millisecond,
	})

	var failLookup atomic.Bool
	var lookups atomic.Int32
	resolver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if failLookup.Load() {
			return nil, errors.New("dns timeout")
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}

	plan, err := resolver.resolvePlan(context.Background(), "sis.internal", "")
	if err != nil {
		t.Fatalf("warm resolve failed: %v", err)
	}
	if len(plan.addresses) != 1 || plan.addresses[0] != "10.0.0.1" {
		t.Fatalf("unexpected warm plan: %+v", plan)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go func() {
		ticker := time.NewTicker(8 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				failLookup.Store(!failLookup.Load())
			}
		}
	}()

	var staleHits atomic.Int32
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				plan, err := resolver.resolvePlan(context.Background(), "sis.internal", "")
				if err != nil {
					errCh <- err
					return
				}
				if plan.source == "dns-stale-cache" {
					staleHits.Add(1)
				}
				if len(plan.addresses) != 1 || plan.addresses[0] != "10.0.0.1" {
					errCh <- errors.New("unexpected address plan during instability")
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("unexpected resolver failure under instability: %v", err)
		}
	}
	if staleHits.Load() == 0 {
		t.Fatal("expected at least one stale cache hit during DNS instability")
	}
	if lookups.Load() < 2 {
		t.Fatalf("expected repeated upstream lookups, got %d", lookups.Load())
	}
}
