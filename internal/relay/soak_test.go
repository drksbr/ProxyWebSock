package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

func TestRouteResolutionSoakDuringAgentReconnectStorm(t *testing.T) {
	server := newTestRoutingServer(t)
	server.metrics = &relayMetrics{
		activeStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "test_intratun_active_streams",
			Help: "Test-only active streams gauge.",
		}),
	}
	seedSoakRouteAccess(t, server)

	principal, err := server.authenticateProxyPrincipal(context.Background(), "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}

	session1, ok := server.lookupAgent("agente01")
	if !ok {
		t.Fatal("expected agente01 to be connected")
	}
	session2, ok := server.lookupAgent("agente02")
	if !ok {
		t.Fatal("expected agente02 to be connected")
	}

	stormCtx, cancelStorm := context.WithCancel(context.Background())
	defer cancelStorm()

	var stormTransitions atomic.Int32
	go func() {
		ticker := time.NewTicker(4 * time.Millisecond)
		defer ticker.Stop()

		states := [][]string{
			{"agente01", "agente02"},
			{"agente01"},
			{"agente02"},
			{},
		}
		index := 0
		for {
			select {
			case <-stormCtx.Done():
				return
			case <-ticker.C:
				server.agents.Delete("agente01")
				server.agents.Delete("agente02")
				for _, agentID := range states[index] {
					switch agentID {
					case "agente01":
						server.agents.Store(agentID, session1)
					case "agente02":
						server.agents.Store(agentID, session2)
					}
				}
				stormTransitions.Add(1)
				index = (index + 1) % len(states)
			}
		}
	}()

	var routeCount atomic.Int32
	var disconnectCount atomic.Int32
	var agent1Count atomic.Int32
	var agent2Count atomic.Int32
	var streamID atomic.Uint64

	errCh := make(chan error, 32)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 60; j++ {
				session, decision, err := server.resolveRouteForPrincipal(context.Background(), principal, "aghuse.saude.ba.gov.br", 443)
				if err != nil {
					routeErr, ok := err.(*routeError)
					if ok && routeErr.reasonCode == "group_agents_disconnected" {
						disconnectCount.Add(1)
						time.Sleep(time.Millisecond)
						continue
					}
					errCh <- err
					return
				}
				if session == nil {
					errCh <- fmt.Errorf("route resolved without agent session")
					return
				}
				if decision.AgentID != session.id {
					errCh <- fmt.Errorf("routing decision picked %q but session was %q", decision.AgentID, session.id)
					return
				}

				switch session.id {
				case "agente01":
					agent1Count.Add(1)
				case "agente02":
					agent2Count.Add(1)
				default:
					errCh <- fmt.Errorf("unexpected agent selected: %s", session.id)
					return
				}

				id := streamID.Add(1)
				if err := session.registerStream(&relayStream{
					id:            id,
					targetHost:    "aghuse.saude.ba.gov.br",
					targetPort:    443,
					principalType: string(principal.Kind),
					principalName: principal.Username,
					groupID:       decision.GroupID,
					groupName:     decision.GroupName,
					profileID:     decision.ProfileID,
					profileName:   decision.ProfileName,
					createdAt:     time.Now(),
				}); err != nil {
					errCh <- err
					return
				}
				time.Sleep(time.Millisecond)
				session.removeStream(id)
				routeCount.Add(1)
			}
		}()
	}

	wg.Wait()
	cancelStorm()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("unexpected soak failure: %v", err)
		}
	}

	if stormTransitions.Load() == 0 {
		t.Fatal("expected reconnect storm transitions to occur")
	}
	if routeCount.Load() == 0 {
		t.Fatal("expected at least one successful route during soak")
	}
	if disconnectCount.Load() == 0 {
		t.Fatal("expected at least one disconnected-group error during reconnect storm")
	}
	if agent1Count.Load() == 0 || agent2Count.Load() == 0 {
		t.Fatalf("expected both agents to serve traffic, got agente01=%d agente02=%d", agent1Count.Load(), agent2Count.Load())
	}
}

func TestRouteResolutionSoakDuringAgentRestart(t *testing.T) {
	store := controlplane.NewMemoryStore()
	server := newSoakRoutingServer(store)
	seedSoakRouteAccess(t, server)
	attachSoakAgents(server, 2)

	principal, err := server.authenticateProxyPrincipal(context.Background(), "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}

	restartCtx, cancelRestart := context.WithCancel(context.Background())
	defer cancelRestart()

	var restarts atomic.Int32
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()

		mode := 0
		for {
			select {
			case <-restartCtx.Done():
				return
			case <-ticker.C:
				server.agents.Delete("agente01")
				server.agents.Delete("agente02")
				time.Sleep(time.Millisecond)
				attachSoakAgents(server, mode)
				mode = (mode + 1) % 4
				restarts.Add(1)
			}
		}
	}()

	metrics := runRouteResolutionSoak(&routeSoakConfig{
		targetHost:  "aghuse.saude.ba.gov.br",
		targetPort:  443,
		principal:   principal,
		serverFn:    func() *relayServer { return server },
		iterations:  64,
		concurrency: 18,
		streamHold:  time.Millisecond,
	})
	cancelRestart()

	if metrics.err != nil {
		t.Fatalf("unexpected agent restart soak failure: %v", metrics.err)
	}
	if restarts.Load() == 0 {
		t.Fatal("expected at least one agent restart cycle")
	}

	status := server.collectStatus(nil)
	if status.Metrics.RouteDecisions != metrics.successes.Load() {
		t.Fatalf("unexpected route decision count: status=%d soak=%d", status.Metrics.RouteDecisions, metrics.successes.Load())
	}
	if status.Metrics.RouteFailures != metrics.failures.Load() {
		t.Fatalf("unexpected route failure count: status=%d soak=%d", status.Metrics.RouteFailures, metrics.failures.Load())
	}
	if status.Metrics.ActiveStreams != 0 {
		t.Fatalf("expected no leaked active streams after agent restart soak, got %d", status.Metrics.ActiveStreams)
	}
	if metrics.agent1Selections.Load() == 0 || metrics.agent2Selections.Load() == 0 {
		t.Fatalf("expected both agents to serve traffic after restarts, got agente01=%d agente02=%d", metrics.agent1Selections.Load(), metrics.agent2Selections.Load())
	}
	if metrics.failures.Load() == 0 {
		t.Fatal("expected at least one route failure during agent restart soak")
	}
}

func TestRouteResolutionSoakDuringRelayRestart(t *testing.T) {
	store := controlplane.NewMemoryStore()
	initialServer := newSoakRoutingServer(store)
	seedSoakRouteAccess(t, initialServer)
	attachSoakAgents(initialServer, 2)

	principal, err := initialServer.authenticateProxyPrincipal(context.Background(), "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}

	var current atomic.Pointer[relayServer]
	current.Store(initialServer)

	var restarts atomic.Int32
	var unavailable atomic.Int32
	var aggregatedRouteDecisions atomic.Int64
	var aggregatedRouteFailures atomic.Int64
	restartErrCh := make(chan error, 1)

	restartCtx, cancelRestart := context.WithCancel(context.Background())
	defer cancelRestart()

	go func() {
		ticker := time.NewTicker(12 * time.Millisecond)
		defer ticker.Stop()

		mode := 0
		for {
			select {
			case <-restartCtx.Done():
				return
			case <-ticker.C:
				retired := current.Swap(nil)
				unavailable.Add(1)
				time.Sleep(8 * time.Millisecond)
				if retired != nil {
					status := retired.collectStatus(nil)
					aggregatedRouteDecisions.Add(status.Metrics.RouteDecisions)
					aggregatedRouteFailures.Add(status.Metrics.RouteFailures)
					if status.Metrics.ActiveStreams != 0 {
						select {
						case restartErrCh <- fmt.Errorf("retired relay leaked %d active streams", status.Metrics.ActiveStreams):
						default:
						}
						return
					}
				}

				next := newSoakRoutingServer(store)
				mode = (mode + 1) % 4
				if mode != 3 {
					attachSoakAgents(next, mode)
				}
				current.Store(next)
				restarts.Add(1)
			}
		}
	}()

	metrics := runRouteResolutionSoak(&routeSoakConfig{
		targetHost:  "aghuse.saude.ba.gov.br",
		targetPort:  443,
		principal:   principal,
		serverFn:    func() *relayServer { return current.Load() },
		iterations:  64,
		concurrency: 16,
		streamHold:  time.Millisecond,
	})
	cancelRestart()
	time.Sleep(8 * time.Millisecond)

	finalServer := current.Swap(nil)
	if finalServer != nil {
		status := finalServer.collectStatus(nil)
		aggregatedRouteDecisions.Add(status.Metrics.RouteDecisions)
		aggregatedRouteFailures.Add(status.Metrics.RouteFailures)
		if status.Metrics.ActiveStreams != 0 {
			t.Fatalf("expected final relay to end with zero active streams, got %d", status.Metrics.ActiveStreams)
		}
	}

	if metrics.err != nil {
		t.Fatalf("unexpected relay restart soak failure: %v", metrics.err)
	}
	select {
	case err := <-restartErrCh:
		t.Fatalf("unexpected relay restart housekeeping failure: %v", err)
	default:
	}
	if restarts.Load() == 0 {
		t.Fatal("expected at least one relay restart")
	}
	if unavailable.Load() == 0 || metrics.unavailableHits.Load() == 0 {
		t.Fatalf("expected unavailable windows during relay restarts, got restart_windows=%d hits=%d", unavailable.Load(), metrics.unavailableHits.Load())
	}
	if metrics.successes.Load() == 0 {
		t.Fatal("expected successful routes during relay restart soak")
	}
	if metrics.failures.Load() == 0 {
		t.Fatal("expected route failures during relay restart soak")
	}
	if aggregatedRouteDecisions.Load() != metrics.successes.Load() {
		t.Fatalf("unexpected aggregated route decisions: captured=%d soak=%d", aggregatedRouteDecisions.Load(), metrics.successes.Load())
	}
	if aggregatedRouteFailures.Load() != metrics.failures.Load() {
		t.Fatalf("unexpected aggregated route failures: captured=%d soak=%d", aggregatedRouteFailures.Load(), metrics.failures.Load())
	}
	if metrics.agent1Selections.Load() == 0 || metrics.agent2Selections.Load() == 0 {
		t.Fatalf("expected both agents to serve traffic across relay restarts, got agente01=%d agente02=%d", metrics.agent1Selections.Load(), metrics.agent2Selections.Load())
	}
}

type routeSoakConfig struct {
	targetHost  string
	targetPort  int
	principal   proxyPrincipal
	serverFn    func() *relayServer
	iterations  int
	concurrency int
	streamHold  time.Duration
}

type routeSoakMetrics struct {
	successes        atomic.Int64
	failures         atomic.Int64
	unavailableHits  atomic.Int64
	agent1Selections atomic.Int64
	agent2Selections atomic.Int64
	err              error
}

func runRouteResolutionSoak(cfg *routeSoakConfig) *routeSoakMetrics {
	metrics := &routeSoakMetrics{}
	if cfg == nil || cfg.serverFn == nil {
		metrics.err = fmt.Errorf("missing soak config")
		return metrics
	}

	var streamID atomic.Uint64
	errCh := make(chan error, cfg.concurrency)
	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < cfg.iterations; j++ {
				server := cfg.serverFn()
				if server == nil {
					metrics.unavailableHits.Add(1)
					time.Sleep(time.Millisecond)
					continue
				}

				session, decision, err := server.resolveRouteForPrincipal(context.Background(), cfg.principal, cfg.targetHost, cfg.targetPort)
				if err != nil {
					server.recordRouteOutcome("soak", fmt.Sprintf("%s:%d", cfg.targetHost, cfg.targetPort), cfg.principal, routeDecision{}, err)
					metrics.failures.Add(1)
					routeErr, ok := err.(*routeError)
					if ok && routeErr.reasonCode == "group_agents_disconnected" {
						time.Sleep(time.Millisecond)
						continue
					}
					errCh <- err
					return
				}
				if session == nil {
					errCh <- fmt.Errorf("route resolved without agent session")
					return
				}
				if decision.AgentID != session.id {
					errCh <- fmt.Errorf("routing decision picked %q but session was %q", decision.AgentID, session.id)
					return
				}

				switch session.id {
				case "agente01":
					metrics.agent1Selections.Add(1)
				case "agente02":
					metrics.agent2Selections.Add(1)
				default:
					errCh <- fmt.Errorf("unexpected agent selected: %s", session.id)
					return
				}

				id := streamID.Add(1)
				if err := session.registerStream(&relayStream{
					id:            id,
					targetHost:    cfg.targetHost,
					targetPort:    cfg.targetPort,
					principalType: string(cfg.principal.Kind),
					principalName: cfg.principal.Username,
					groupID:       decision.GroupID,
					groupName:     decision.GroupName,
					profileID:     decision.ProfileID,
					profileName:   decision.ProfileName,
					createdAt:     time.Now(),
				}); err != nil {
					errCh <- err
					return
				}
				time.Sleep(cfg.streamHold)
				session.removeStream(id)
				server.recordRouteOutcome("soak", fmt.Sprintf("%s:%d", cfg.targetHost, cfg.targetPort), cfg.principal, decision, nil)
				metrics.successes.Add(1)
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			metrics.err = err
			return metrics
		}
	}
	return metrics
}

func newSoakRoutingServer(store controlplane.Store) *relayServer {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &relayServer{
		logger: logger,
		opts: &relayOptions{
			proxyListen:      ":8080",
			secureListen:     ":443",
			socksListen:      ":1080",
			breakerFailures:  1,
			breakerCooldown:  time.Second,
			streamQueueDepth: 64,
		},
		metrics: &relayMetrics{
			activeStreams: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "test_intratun_active_streams",
				Help: "Test-only active streams gauge.",
			}),
		},
		control: store,
		agentDirectory: map[string]*agentRecord{
			"agente01": {
				Login:          "agente01",
				Password:       "secret-01",
				Identification: "Agente 01",
				Location:       "Hospital Centro",
			},
			"agente02": {
				Login:          "agente02",
				Password:       "secret-02",
				Identification: "Agente 02",
				Location:       "Hospital Centro",
			},
		},
		routeHistory:   newRouteHistory(256),
		diagnosticRuns: newDiagnosticHistory(64),
		breakers:       newCircuitBreakerRegistry(1, time.Second),
	}
}

func attachSoakAgents(server *relayServer, mode int) {
	if server == nil {
		return
	}
	type agentSeed struct {
		id             string
		identification string
		location       string
	}
	var seeds []agentSeed
	switch mode % 4 {
	case 0:
		seeds = []agentSeed{{id: "agente01", identification: "Agente 01", location: "Hospital Centro"}}
	case 1:
		seeds = []agentSeed{{id: "agente02", identification: "Agente 02", location: "Hospital Centro"}}
	case 2:
		seeds = []agentSeed{
			{id: "agente01", identification: "Agente 01", location: "Hospital Centro"},
			{id: "agente02", identification: "Agente 02", location: "Hospital Centro"},
		}
	default:
		seeds = nil
	}
	for _, seed := range seeds {
		server.agents.Store(seed.id, &relayAgentSession{
			server:         server,
			logger:         server.logger,
			id:             seed.id,
			identification: seed.identification,
			location:       seed.location,
			connectedAt:    time.Now().UTC(),
			controlQueue:   make(chan outboundMessage, 1),
			dataQueue:      make(chan outboundMessage, 1),
			shutdown:       make(chan struct{}),
			diagnostics:    make(map[uint64]chan protocol.DiagnosticResponse),
			streams:        make(map[uint64]*relayStream),
		})
	}
}

func seedSoakRouteAccess(t *testing.T, server *relayServer) {
	t.Helper()
	ctx := context.Background()

	passwordHash, err := controlplane.HashPassword("segredo-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := server.control.UpsertUser(ctx, controlplane.User{
		ID:           "user-1",
		Username:     "operador",
		PasswordHash: passwordHash,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := server.control.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:   "group-1",
		Name: "Hospital Centro",
		Slug: "hospital-centro",
	}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := server.control.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID:  "group-1",
		AgentID:  "agente01",
		Enabled:  true,
		Priority: 10,
		Weight:   1,
	}); err != nil {
		t.Fatalf("seed membership 1: %v", err)
	}
	if _, err := server.control.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID:  "group-1",
		AgentID:  "agente02",
		Enabled:  true,
		Priority: 10,
		Weight:   1,
	}); err != nil {
		t.Fatalf("seed membership 2: %v", err)
	}
	if _, err := server.control.UpsertDestinationProfile(ctx, controlplane.DestinationProfile{
		ID:             "profile-1",
		Name:           "AGHUse",
		Slug:           "aghuse",
		Host:           "aghuse.saude.ba.gov.br",
		Port:           443,
		ProtocolHint:   "https",
		DefaultGroupID: "group-1",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if _, err := server.control.UpsertAccessGrant(ctx, controlplane.AccessGrant{
		ID:                   "grant-1",
		UserID:               "user-1",
		DestinationProfileID: "profile-1",
		AccessMode:           "profile",
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}
