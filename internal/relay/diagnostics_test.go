package relay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
	"github.com/drksbr/ProxyWebSock/internal/protocol"
)

func TestRelayAgentSessionRunDiagnostic(t *testing.T) {
	server := &relayServer{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	session := &relayAgentSession{
		server:       server,
		logger:       server.logger,
		id:           "agente01",
		controlQueue: make(chan outboundMessage, 1),
		shutdown:     make(chan struct{}),
		diagnostics:  make(map[uint64]chan protocol.DiagnosticResponse),
	}

	go func() {
		msg := <-session.controlQueue
		header, body, err := protocol.ParsePacket(msg.packet)
		if err != nil {
			t.Errorf("parse packet: %v", err)
			return
		}
		req, err := protocol.DecodeDiagnosticRequestPacket(header, body)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.Host != "aghuse.saude.ba.gov.br" || req.Port != 443 {
			t.Errorf("unexpected request: %#v", req)
			return
		}
		session.handleDiagnosticResponse(protocol.DiagnosticResponse{
			RequestID:  req.RequestID,
			StartedAt:  time.Now().Add(-50 * time.Millisecond).UnixNano(),
			FinishedAt: time.Now().UnixNano(),
			Steps: []protocol.DiagnosticStepResult{
				{
					Step:             "resolve",
					Success:          true,
					ResolutionSource: "override",
					Addresses:        []string{"10.0.0.1"},
				},
			},
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := session.runDiagnostic(ctx, protocol.DiagnosticRequest{
		RequestID: 77,
		Host:      "aghuse.saude.ba.gov.br",
		Port:      443,
	})
	if err != nil {
		t.Fatalf("run diagnostic: %v", err)
	}
	if resp.RequestID != 77 {
		t.Fatalf("unexpected request id: %d", resp.RequestID)
	}
	if len(resp.Steps) != 1 || resp.Steps[0].ResolutionSource != "override" {
		t.Fatalf("unexpected diagnostic response: %#v", resp)
	}
}

func TestHandleDiagnosticsAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := &relayServer{
		logger: logger,
		opts: &relayOptions{
			dialTimeoutMs: 8000,
		},
		control:        controlplane.NewMemoryStore(),
		diagnosticRuns: newDiagnosticHistory(10),
		dnsOverrides: &dnsOverrideStore{
			entries: map[string]dnsOverrideEntry{
				normalizeOverrideHost("aghuse.saude.ba.gov.br"): {
					Host:    "aghuse.saude.ba.gov.br",
					Address: "10.0.0.1",
				},
			},
		},
	}
	session := &relayAgentSession{
		server:         server,
		logger:         logger,
		id:             "agente01",
		identification: "Hospital A",
		controlQueue:   make(chan outboundMessage, 1),
		shutdown:       make(chan struct{}),
		diagnostics:    make(map[uint64]chan protocol.DiagnosticResponse),
	}
	server.agents.Store("agente01", session)

	go func() {
		msg := <-session.controlQueue
		header, body, err := protocol.ParsePacket(msg.packet)
		if err != nil {
			t.Errorf("parse packet: %v", err)
			return
		}
		req, err := protocol.DecodeDiagnosticRequestPacket(header, body)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.OverrideAddress != "10.0.0.1" {
			t.Errorf("expected override address, got %q", req.OverrideAddress)
			return
		}
		session.handleDiagnosticResponse(protocol.DiagnosticResponse{
			RequestID:  req.RequestID,
			StartedAt:  time.Now().Add(-120 * time.Millisecond).UnixNano(),
			FinishedAt: time.Now().UnixNano(),
			Steps: []protocol.DiagnosticStepResult{
				{
					Step:             "resolve",
					Success:          true,
					DurationMillis:   2,
					ResolutionSource: "override",
					Addresses:        []string{"10.0.0.1"},
					Message:          "1 endereco resolvido",
				},
				{
					Step:            "dial",
					Success:         true,
					DurationMillis:  20,
					SelectedAddress: "10.0.0.1:443",
					Message:         "tcp connect ok",
				},
			},
		})
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/diagnostics", strings.NewReader(`{
		"agentId":"agente01",
		"host":"aghuse.saude.ba.gov.br",
		"port":443,
		"tlsEnabled":true,
		"timeoutMs":5000
	}`))
	rec := httptest.NewRecorder()

	server.handleDiagnosticsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp diagnosticAPIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AgentName != "Hospital A" {
		t.Fatalf("unexpected agent name: %q", resp.AgentName)
	}
	if resp.OverrideAddress != "10.0.0.1" {
		t.Fatalf("unexpected override address: %q", resp.OverrideAddress)
	}
	if len(resp.Steps) != 2 {
		t.Fatalf("unexpected steps: %#v", resp.Steps)
	}
	if resp.Steps[0].ResolutionSource != "override" {
		t.Fatalf("unexpected resolution source: %#v", resp.Steps[0])
	}
	status := server.collectStatus(nil)
	if len(status.DiagnosticEvents) != 1 {
		t.Fatalf("expected one diagnostic event, got %d", len(status.DiagnosticEvents))
	}
	if status.DiagnosticEvents[0].Mode != "agent" {
		t.Fatalf("unexpected diagnostic mode: %#v", status.DiagnosticEvents[0])
	}
	if len(status.AuditEvents) != 1 || status.AuditEvents[0].Category != "diagnostic" {
		t.Fatalf("unexpected audit events: %+v", status.AuditEvents)
	}
}

func TestHandleDiagnosticsAPIGroupSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	if _, err := store.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:   "group-1",
		Name: "Hospital Salvador",
		Slug: "hospital-salvador",
	}); err != nil {
		t.Fatalf("upsert group: %v", err)
	}
	if _, err := store.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID: "group-1",
		AgentID: "agente01",
		Enabled: true,
	}); err != nil {
		t.Fatalf("upsert membership: %v", err)
	}

	server := &relayServer{
		logger:         logger,
		control:        store,
		diagnosticRuns: newDiagnosticHistory(10),
		breakers:       newCircuitBreakerRegistry(1, time.Minute),
		opts: &relayOptions{
			dialTimeoutMs: 8000,
		},
	}
	server.breakers.RecordFailure("group-1", "Hospital Salvador", "sis.internal:8443", "dial failed", time.Now().UTC())
	session := &relayAgentSession{
		server:         server,
		logger:         logger,
		id:             "agente01",
		identification: "Hospital A",
		controlQueue:   make(chan outboundMessage, 1),
		shutdown:       make(chan struct{}),
		diagnostics:    make(map[uint64]chan protocol.DiagnosticResponse),
	}
	server.agents.Store("agente01", session)

	go func() {
		msg := <-session.controlQueue
		header, body, err := protocol.ParsePacket(msg.packet)
		if err != nil {
			t.Errorf("parse packet: %v", err)
			return
		}
		req, err := protocol.DecodeDiagnosticRequestPacket(header, body)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.Host != "sis.internal" || req.Port != 8443 {
			t.Errorf("unexpected diagnostic target: %#v", req)
			return
		}
		session.handleDiagnosticResponse(protocol.DiagnosticResponse{
			RequestID:  req.RequestID,
			StartedAt:  time.Now().Add(-40 * time.Millisecond).UnixNano(),
			FinishedAt: time.Now().UnixNano(),
			Steps: []protocol.DiagnosticStepResult{
				{
					Step:            "dial",
					Success:         true,
					DurationMillis:  12,
					SelectedAddress: "10.10.0.9:8443",
					Message:         "tcp connect ok",
				},
			},
		})
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/diagnostics", strings.NewReader(`{
		"groupId":"group-1",
		"host":"sis.internal",
		"port":8443,
		"tlsEnabled":false
	}`))
	rec := httptest.NewRecorder()

	server.handleDiagnosticsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp diagnosticAPIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Mode != "group" || resp.GroupName != "Hospital Salvador" {
		t.Fatalf("unexpected response routing: %#v", resp)
	}
	if resp.AgentID != "agente01" {
		t.Fatalf("unexpected selected agent: %#v", resp)
	}
	status := server.collectStatus(nil)
	if len(status.Support.ActiveBreakers) != 0 {
		t.Fatalf("expected successful diagnostic probe to close breaker, got %+v", status.Support.ActiveBreakers)
	}
}

func TestHandleDiagnosticsAPIProfileSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := controlplane.NewMemoryStore()
	ctx := context.Background()
	if _, err := store.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:   "group-1",
		Name: "Hospital Salvador",
		Slug: "hospital-salvador",
	}); err != nil {
		t.Fatalf("upsert group: %v", err)
	}
	if _, err := store.UpsertAgentMembership(ctx, controlplane.AgentMembership{
		GroupID: "group-1",
		AgentID: "agente01",
		Enabled: true,
	}); err != nil {
		t.Fatalf("upsert membership: %v", err)
	}
	if _, err := store.UpsertDestinationProfile(ctx, controlplane.DestinationProfile{
		ID:             "profile-1",
		Name:           "AGHUse",
		Slug:           "aghuse",
		Host:           "aghuse.saude.ba.gov.br",
		Port:           443,
		DefaultGroupID: "group-1",
		ProtocolHint:   "https",
	}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}

	server := &relayServer{
		logger:         logger,
		control:        store,
		diagnosticRuns: newDiagnosticHistory(10),
		opts: &relayOptions{
			dialTimeoutMs: 8000,
		},
	}
	session := &relayAgentSession{
		server:         server,
		logger:         logger,
		id:             "agente01",
		identification: "Hospital A",
		controlQueue:   make(chan outboundMessage, 1),
		shutdown:       make(chan struct{}),
		diagnostics:    make(map[uint64]chan protocol.DiagnosticResponse),
	}
	server.agents.Store("agente01", session)

	go func() {
		msg := <-session.controlQueue
		header, body, err := protocol.ParsePacket(msg.packet)
		if err != nil {
			t.Errorf("parse packet: %v", err)
			return
		}
		req, err := protocol.DecodeDiagnosticRequestPacket(header, body)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if req.Host != "aghuse.saude.ba.gov.br" || req.Port != 443 {
			t.Errorf("unexpected profile target: %#v", req)
			return
		}
		session.handleDiagnosticResponse(protocol.DiagnosticResponse{
			RequestID:  req.RequestID,
			StartedAt:  time.Now().Add(-60 * time.Millisecond).UnixNano(),
			FinishedAt: time.Now().UnixNano(),
			Steps: []protocol.DiagnosticStepResult{
				{
					Step:             "resolve",
					Success:          true,
					DurationMillis:   3,
					ResolutionSource: "dns",
					Addresses:        []string{"10.0.0.5"},
				},
			},
		})
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/diagnostics", strings.NewReader(`{
		"profileId":"profile-1",
		"tlsEnabled":true
	}`))
	rec := httptest.NewRecorder()

	server.handleDiagnosticsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp diagnosticAPIResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Mode != "profile" || resp.ProfileName != "AGHUse" {
		t.Fatalf("unexpected profile response: %#v", resp)
	}
	if resp.GroupID != "group-1" || resp.Host != "aghuse.saude.ba.gov.br" {
		t.Fatalf("unexpected resolved profile target: %#v", resp)
	}
}
