package relay

import (
	"context"
	"testing"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestEnforceStreamQuotasRejectsUserAtLimit(t *testing.T) {
	server := newTestRoutingServer(t)
	server.opts = &relayOptions{userStreamQuota: 1}

	session, _ := server.lookupAgent("agente01")
	stream := newRelayStream(999, session, streamProtoHTTP, nil, nil, "aghuse.saude.ba.gov.br", 443, 1, nil)
	stream.setRouting(routeDecision{
		PrincipalType: string(proxyPrincipalUser),
		PrincipalName: "operador",
		GroupID:       "group-1",
		GroupName:     "Hospital Centro",
	})
	session.streamsMu.Lock()
	session.streams[stream.id] = stream
	session.streamsMu.Unlock()
	defer func() {
		session.streamsMu.Lock()
		delete(session.streams, stream.id)
		session.streamsMu.Unlock()
	}()

	err := server.enforceStreamQuotas(proxyPrincipal{
		Kind:     proxyPrincipalUser,
		Username: "operador",
	}, routeDecision{
		PrincipalType: string(proxyPrincipalUser),
		PrincipalName: "operador",
		GroupID:       "group-1",
		GroupName:     "Hospital Centro",
	})
	if err == nil {
		t.Fatal("expected user quota error")
	}
	re, ok := err.(*routeError)
	if !ok || re.reasonCode != "user_stream_quota_exceeded" {
		t.Fatalf("unexpected quota error: %#v", err)
	}
}

func TestSelectAgentForGroupSkipsAgentAtQuota(t *testing.T) {
	server := newTestControlPlaneServer(t)
	server.opts = &relayOptions{agentStreamQuota: 1}
	server.agentDirectory = map[string]*agentRecord{
		"agente01": {Login: "agente01", Password: "secret-01", Identification: "Agente 01"},
		"agente02": {Login: "agente02", Password: "secret-02", Identification: "Agente 02"},
	}

	ctx := context.Background()
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
		Priority: 1,
	}); err != nil {
		t.Fatalf("seed membership 1: %v", err)
	}
	if _, err := server.control.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID:  "group-1",
		AgentID:  "agente02",
		Enabled:  true,
		Priority: 10,
	}); err != nil {
		t.Fatalf("seed membership 2: %v", err)
	}

	now := time.Now()
	session1 := &relayAgentSession{
		server:       server,
		id:           "agente01",
		connectedAt:  now,
		controlQueue: make(chan outboundMessage, 1),
		dataQueue:    make(chan outboundMessage, 1),
		streams:      make(map[uint64]*relayStream),
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

	seed := newRelayStream(1, session1, streamProtoHTTP, nil, nil, "seed.internal", 443, 1, nil)
	seed.setRouting(routeDecision{
		PrincipalType: string(proxyPrincipalUser),
		PrincipalName: "operador",
		GroupID:       "group-1",
		GroupName:     "Hospital Centro",
	})
	session1.streamsMu.Lock()
	session1.streams[seed.id] = seed
	session1.streamsMu.Unlock()
	defer func() {
		session1.streamsMu.Lock()
		delete(session1.streams, seed.id)
		session1.streamsMu.Unlock()
	}()

	selection, err := server.selectAgentForGroup(context.Background(), userRouteCandidate{
		GroupID:    "group-1",
		GroupName:  "Hospital Centro",
		ReasonCode: "user_group_grant",
		Reason:     "test",
	}, "aghuse.saude.ba.gov.br", 443)
	if err != nil {
		t.Fatalf("select agent: %v", err)
	}
	if selection.Membership.AgentID != "agente02" {
		t.Fatalf("expected quota fallback to agente02, got %s", selection.Membership.AgentID)
	}
}
