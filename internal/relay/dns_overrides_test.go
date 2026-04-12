package relay

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestDNSOverrideStorePersistsEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-overrides.yaml")
	store, err := newDNSOverrideStore(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Set("AGHUSE.saude.ba.gov.br", "10.0.0.1"); err != nil {
		t.Fatalf("set override: %v", err)
	}

	reloaded, err := newDNSOverrideStore(path)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	entry, ok := reloaded.Resolve("aghuse.saude.ba.gov.br")
	if !ok {
		t.Fatal("expected override after reload")
	}
	if entry.Address != "10.0.0.1" {
		t.Fatalf("unexpected address: %s", entry.Address)
	}
	if entry.Host != "aghuse.saude.ba.gov.br" {
		t.Fatalf("unexpected host normalization: %s", entry.Host)
	}
}

func TestBuildDialRequestUsesOverride(t *testing.T) {
	store, err := newDNSOverrideStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, err := store.Set("aghuse.saude.ba.gov.br", "10.0.0.1"); err != nil {
		t.Fatalf("set override: %v", err)
	}
	server := &relayServer{dnsOverrides: store}
	req := server.buildDialRequest(99, "aghuse.saude.ba.gov.br", 443)
	if req.OverrideAddress != "10.0.0.1" {
		t.Fatalf("unexpected override address: %s", req.OverrideAddress)
	}
}

func TestHandleDNSOverridesAPI(t *testing.T) {
	store, err := newDNSOverrideStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	server := &relayServer{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		dnsOverrides: store,
		control:      controlplane.NewMemoryStore(),
	}

	body := strings.NewReader(`{"host":"aghuse.saude.ba.gov.br","address":"10.0.0.1"}`)
	postReq := httptest.NewRequest(http.MethodPost, "/api/dns-overrides", body)
	postRec := httptest.NewRecorder()
	server.handleDNSOverridesAPI(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("unexpected post status: %d", postRec.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/dns-overrides", nil)
	listRec := httptest.NewRecorder()
	server.handleDNSOverridesAPI(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("unexpected get status: %d", listRec.Code)
	}
	var payload struct {
		Overrides []dnsOverrideEntry `json:"overrides"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(payload.Overrides) != 1 || payload.Overrides[0].Address != "10.0.0.1" {
		t.Fatalf("unexpected overrides payload: %+v", payload.Overrides)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/dns-overrides/aghuse.saude.ba.gov.br", nil)
	deleteRec := httptest.NewRecorder()
	server.handleDNSOverridesAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("unexpected delete status: %d", deleteRec.Code)
	}

	events, err := server.control.ListAuditEvents(postReq.Context(), 10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("unexpected audit event count: %d", len(events))
	}
	if events[0].Action != "deleted" || events[1].Action != "created" {
		t.Fatalf("unexpected audit events: %+v", events)
	}
}
