package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type dialResolverConfig struct {
	PositiveTTL         time.Duration
	NegativeTTL         time.Duration
	StaleTTL            time.Duration
	RefreshBeforeExpiry time.Duration
	RefreshTimeout      time.Duration
}

type dialResolver struct {
	cfg      dialResolverConfig
	resolver *net.Resolver
	dialer   net.Dialer
	lookup   func(context.Context, string) ([]netip.Addr, error)
	dial     func(context.Context, string, string) (net.Conn, error)

	mu    sync.Mutex
	cache map[string]*dnsCacheEntry
}

type dnsCacheEntry struct {
	addresses    []string
	expiresAt    time.Time
	staleUntil   time.Time
	refreshAfter time.Time
	negativeErr  string
	refreshing   bool
	next         int
}

type dialPlan struct {
	addresses []string
	source    string
	cacheKey  string
}

func newDialResolver(cfg dialResolverConfig) *dialResolver {
	if cfg.PositiveTTL <= 0 {
		cfg.PositiveTTL = 30 * time.Second
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 5 * time.Second
	}
	if cfg.StaleTTL < 0 {
		cfg.StaleTTL = 0
	}
	cfg.RefreshBeforeExpiry = normalizeRefreshAhead(cfg.PositiveTTL, cfg.RefreshBeforeExpiry)
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = 3 * time.Second
	}
	r := &dialResolver{
		cfg:      cfg,
		resolver: net.DefaultResolver,
		dialer: net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		cache: make(map[string]*dnsCacheEntry),
	}
	r.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return r.resolver.LookupNetIP(ctx, "ip", host)
	}
	r.dial = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return r.dialer.DialContext(ctx, network, address)
	}
	return r
}

func (a *agent) dialTarget(ctx context.Context, host string, port uint16, overrideAddress string) (net.Conn, string, string, error) {
	if a.resolver == nil {
		a.resolver = newDialResolver(a.opts.resolverConfig())
	}
	return a.resolver.dialContext(ctx, host, port, overrideAddress)
}

func (r *dialResolver) dialContext(ctx context.Context, host string, port uint16, overrideAddress string) (net.Conn, string, string, error) {
	plan, err := r.resolvePlan(ctx, host, overrideAddress)
	if err != nil {
		return nil, "", "", err
	}
	if len(plan.addresses) == 0 {
		return nil, "", "", fmt.Errorf("no dial address resolved for %s", host)
	}
	portText := strconv.Itoa(int(port))
	var lastErr error
	for _, address := range plan.addresses {
		target := net.JoinHostPort(address, portText)
		conn, err := r.dial(ctx, "tcp", target)
		if err == nil {
			r.recordDialSuccess(plan.cacheKey, address)
			return conn, target, plan.source, nil
		}
		r.recordDialFailure(plan.cacheKey, address)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dial address available for %s", host)
	}
	return nil, "", plan.source, lastErr
}

func (r *dialResolver) resolvePlan(ctx context.Context, host string, overrideAddress string) (dialPlan, error) {
	if overrideAddress != "" {
		ip := net.ParseIP(strings.TrimSpace(overrideAddress))
		if ip == nil {
			return dialPlan{}, fmt.Errorf("invalid override address %q", overrideAddress)
		}
		return dialPlan{
			addresses: []string{ip.String()},
			source:    "override",
		}, nil
	}

	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return dialPlan{
			addresses: []string{ip.String()},
			source:    "literal",
		}, nil
	}

	cacheKey := normalizeDNSHost(host)
	cached, source, err, refresh := r.lookupCache(cacheKey)
	if err != nil {
		return dialPlan{}, err
	}
	if refresh {
		go r.refreshCache(cacheKey)
	}
	if len(cached) > 0 {
		return dialPlan{
			addresses: cached,
			source:    source,
			cacheKey:  cacheKey,
		}, nil
	}

	addresses, err := r.lookupHostAddresses(ctx, cacheKey)
	if err != nil {
		r.storeNegativeCache(cacheKey, err)
		return dialPlan{}, fmt.Errorf("resolve %s: %w", cacheKey, err)
	}
	if len(addresses) == 0 {
		err = fmt.Errorf("empty answer")
		r.storeNegativeCache(cacheKey, err)
		return dialPlan{}, fmt.Errorf("resolve %s: %w", cacheKey, err)
	}
	r.storePositiveCache(cacheKey, addresses)
	return dialPlan{
		addresses: addresses,
		source:    "dns",
		cacheKey:  cacheKey,
	}, nil
}

func (r *dialResolver) lookupCache(host string) ([]string, string, error, bool) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[host]
	if !ok {
		return nil, "", nil, false
	}
	if entry.negativeErr != "" {
		if now.Before(entry.expiresAt) {
			return nil, "dns-negative-cache", fmt.Errorf("resolve %s: cached negative answer: %s", host, entry.negativeErr), false
		}
		delete(r.cache, host)
		return nil, "", nil, false
	}
	if len(entry.addresses) == 0 || now.After(entry.staleUntil) {
		delete(r.cache, host)
		return nil, "", nil, false
	}
	start := entry.next % len(entry.addresses)
	addresses := make([]string, 0, len(entry.addresses))
	addresses = append(addresses, entry.addresses[start:]...)
	addresses = append(addresses, entry.addresses[:start]...)
	entry.next = (start + 1) % len(entry.addresses)
	refresh := false
	source := "dns-cache"
	if !now.Before(entry.expiresAt) {
		source = "dns-stale-cache"
	}
	if r.shouldRefreshLocked(entry, now) {
		entry.refreshing = true
		entry.refreshAfter = now.Add(r.cfg.NegativeTTL)
		refresh = true
	}
	return addresses, source, nil, refresh
}

func (r *dialResolver) storePositiveCache(host string, addresses []string) {
	if host == "" || len(addresses) == 0 {
		return
	}
	copied := append([]string(nil), addresses...)
	now := time.Now()
	expiresAt := now.Add(r.cfg.PositiveTTL)
	r.mu.Lock()
	r.cache[host] = &dnsCacheEntry{
		addresses:    copied,
		expiresAt:    expiresAt,
		staleUntil:   expiresAt.Add(r.cfg.StaleTTL),
		refreshAfter: expiresAt.Add(-r.cfg.RefreshBeforeExpiry),
	}
	r.mu.Unlock()
}

func (r *dialResolver) storeNegativeCache(host string, err error) {
	if host == "" || err == nil {
		return
	}
	r.mu.Lock()
	r.cache[host] = &dnsCacheEntry{
		expiresAt:   time.Now().Add(r.cfg.NegativeTTL),
		negativeErr: err.Error(),
	}
	r.mu.Unlock()
}

func (r *dialResolver) refreshCache(host string) {
	if host == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.RefreshTimeout)
	defer cancel()
	addresses, err := r.lookupHostAddresses(ctx, host)
	if err != nil || len(addresses) == 0 {
		r.finishRefresh(host)
		return
	}
	r.storePositiveCache(host, addresses)
}

func (r *dialResolver) finishRefresh(host string) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[host]
	if !ok {
		return
	}
	entry.refreshing = false
	entry.refreshAfter = now.Add(r.cfg.NegativeTTL)
}

func (r *dialResolver) lookupHostAddresses(ctx context.Context, host string) ([]string, error) {
	if r.lookup == nil {
		r.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return r.resolver.LookupNetIP(ctx, "ip", host)
		}
	}
	ips, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	return uniqueDialAddresses(ips), nil
}

func (r *dialResolver) shouldRefreshLocked(entry *dnsCacheEntry, now time.Time) bool {
	if entry == nil || entry.refreshing {
		return false
	}
	if !entry.refreshAfter.IsZero() && now.Before(entry.refreshAfter) {
		return false
	}
	if !now.Before(entry.expiresAt) {
		return true
	}
	return !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt.Add(-r.cfg.RefreshBeforeExpiry))
}

func (r *dialResolver) recordDialSuccess(host string, address string) {
	r.reorderAddress(host, address, true)
}

func (r *dialResolver) recordDialFailure(host string, address string) {
	r.reorderAddress(host, address, false)
}

func (r *dialResolver) reorderAddress(host string, address string, success bool) {
	if host == "" || address == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[host]
	if !ok || entry.negativeErr != "" || len(entry.addresses) < 2 {
		return
	}
	index := -1
	for i, current := range entry.addresses {
		if current == address {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if success {
		if index == 0 {
			entry.next = 0
			return
		}
		selected := entry.addresses[index]
		copy(entry.addresses[1:index+1], entry.addresses[0:index])
		entry.addresses[0] = selected
		entry.next = 0
		return
	}
	if index == len(entry.addresses)-1 {
		return
	}
	failed := entry.addresses[index]
	copy(entry.addresses[index:], entry.addresses[index+1:])
	entry.addresses[len(entry.addresses)-1] = failed
	if entry.next >= len(entry.addresses) {
		entry.next = 0
	}
}

func uniqueDialAddresses(ips []netip.Addr) []string {
	if len(ips) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ips))
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		address := ip.String()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result
}

func normalizeDNSHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
