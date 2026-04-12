package relay

import (
	"context"
	"testing"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestAuthenticateAndResolveUserRoute_SelectsLeastLoadedAgent(t *testing.T) {
	server := newTestRoutingServer(t)
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

	principal, err := server.authenticateProxyPrincipal(ctx, "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}
	session, decision, err := server.resolveRouteForPrincipal(ctx, principal, "aghuse.saude.ba.gov.br", 443)
	if err != nil {
		t.Fatalf("resolve route: %v", err)
	}
	if session.id != "agente02" {
		t.Fatalf("expected least loaded agent agente02, got %s", session.id)
	}
	if decision.GroupID != "group-1" || decision.ProfileID != "profile-1" {
		t.Fatalf("unexpected routing decision: %+v", decision)
	}
	if decision.ReasonCode != "user_profile_grant" || decision.AgentID != "agente02" || decision.CandidateCount != 2 {
		t.Fatalf("unexpected structured routing decision: %+v", decision)
	}
}

func TestResolveUserRoute_DeniesTargetOutsideGrantedProfile(t *testing.T) {
	server := newTestRoutingServer(t)
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

	principal, err := server.authenticateProxyPrincipal(ctx, "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}
	_, _, err = server.resolveRouteForPrincipal(ctx, principal, "erp.interno.local", 443)
	if err == nil {
		t.Fatal("expected route resolution to fail for ungranted target")
	}
	if routeHTTPStatus(err) != 403 {
		t.Fatalf("expected 403, got %d", routeHTTPStatus(err))
	}
	if re, ok := err.(*routeError); !ok || re.reasonCode != "target_not_granted" {
		t.Fatalf("unexpected route error: %#v", err)
	}
}

func TestAuthenticateProxyPrincipal_FallsBackToLegacyAgentCredentials(t *testing.T) {
	server := newTestRoutingServer(t)

	principal, err := server.authenticateProxyPrincipal(context.Background(), "agente01", "secret-01")
	if err != nil {
		t.Fatalf("authenticate agent principal: %v", err)
	}
	if principal.Kind != proxyPrincipalAgent || principal.AgentID != "agente01" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestResolveUserRoute_BlockedByDestinationCircuitBreaker(t *testing.T) {
	server := newTestRoutingServer(t)
	server.breakers = newCircuitBreakerRegistry(1, time.Minute)
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
		GroupID: "group-1",
		AgentID: "agente01",
		Enabled: true,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if _, err := server.control.UpsertDestinationProfile(ctx, controlplane.DestinationProfile{
		ID:             "profile-1",
		Name:           "AGHUse",
		Slug:           "aghuse",
		Host:           "aghuse.saude.ba.gov.br",
		Port:           443,
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

	server.breakers.RecordFailure("group-1", "Hospital Centro", "aghuse.saude.ba.gov.br:443", "dial timeout", time.Now().UTC())

	principal, err := server.authenticateProxyPrincipal(ctx, "operador", "segredo-123")
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}
	_, _, err = server.resolveRouteForPrincipal(ctx, principal, "aghuse.saude.ba.gov.br", 443)
	if err == nil {
		t.Fatal("expected circuit breaker to block route")
	}
	re, ok := err.(*routeError)
	if !ok || re.reasonCode != "destination_circuit_open" {
		t.Fatalf("unexpected route error: %#v", err)
	}
}

func TestRecordRouteOutcomeStoresRecentEvents(t *testing.T) {
	server := newTestRoutingServer(t)
	server.routeHistory = newRouteHistory(2)

	server.recordRouteOutcome("http-connect", "a:443", proxyPrincipal{
		Kind:     proxyPrincipalUser,
		Username: "operador",
	}, routeDecision{
		PrincipalType:  "user",
		PrincipalName:  "operador",
		ReasonCode:     "user_profile_grant",
		Reason:         "profile matched",
		AgentID:        "agente02",
		AgentName:      "Agente 02",
		CandidateCount: 2,
	}, nil)
	server.recordRouteOutcome("http-connect", "b:443", proxyPrincipal{
		Kind:     proxyPrincipalUser,
		Username: "operador",
	}, routeDecision{}, &routeError{
		reasonCode: "group_agents_disconnected",
		message:    "no connected agents",
	})
	server.recordRouteOutcome("socks5", "c:443", proxyPrincipal{
		Kind:     proxyPrincipalAgent,
		AgentID:  "agente01",
		Username: "agente01",
	}, routeDecision{
		PrincipalType: "agent",
		PrincipalName: "agente01",
		ReasonCode:    "legacy_agent_direct",
		Reason:        "legacy direct",
	}, nil)

	events := server.routeHistory.list()
	if len(events) != 2 {
		t.Fatalf("expected bounded route history of 2 events, got %d", len(events))
	}
	if events[0].ReasonCode != "group_agents_disconnected" || events[0].Outcome != "failed" {
		t.Fatalf("unexpected first retained event: %+v", events[0])
	}
	if events[1].ReasonCode != "legacy_agent_direct" || events[1].Outcome != "selected" {
		t.Fatalf("unexpected second retained event: %+v", events[1])
	}
	if server.stats.routeDecisions.Load() != 2 || server.stats.routeFailures.Load() != 1 {
		t.Fatalf("unexpected route counters: decisions=%d failures=%d", server.stats.routeDecisions.Load(), server.stats.routeFailures.Load())
	}
}

func newTestRoutingServer(t *testing.T) *relayServer {
	t.Helper()
	server := newTestControlPlaneServer(t)
	server.agentDirectory = map[string]*agentRecord{
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
	}

	now := time.Now()
	session1 := &relayAgentSession{
		server:       server,
		id:           "agente01",
		connectedAt:  now,
		controlQueue: make(chan outboundMessage, 1),
		dataQueue:    make(chan outboundMessage, 1),
		streams: map[uint64]*relayStream{
			1: {createdAt: now.Add(-2 * time.Minute), targetHost: "a", targetPort: 80},
			2: {createdAt: now.Add(-1 * time.Minute), targetHost: "b", targetPort: 80},
		},
	}
	session2 := &relayAgentSession{
		server:       server,
		id:           "agente02",
		connectedAt:  now,
		controlQueue: make(chan outboundMessage, 1),
		dataQueue:    make(chan outboundMessage, 1),
		streams:      make(map[uint64]*relayStream),
	}
	server.agents.Store("agente01", session1)
	server.agents.Store("agente02", session2)
	return server
}
