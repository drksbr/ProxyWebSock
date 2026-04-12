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

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestAgentGroupsAPI_CRUD(t *testing.T) {
	server := newTestControlPlaneServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/agent-groups", strings.NewReader(`{
		"name":"Hospital Salvador",
		"slug":"hospital-salvador",
		"description":"Rede principal",
		"routingMode":"health-first"
	}`))
	createRec := httptest.NewRecorder()
	server.handleAgentGroupsAPI(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created statusAgentGroup
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created group: %v", err)
	}
	if created.ID == "" || created.Name != "Hospital Salvador" {
		t.Fatalf("unexpected created group: %+v", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/control-plane/agent-groups", nil)
	listRec := httptest.NewRecorder()
	server.handleAgentGroupsAPI(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRec.Code, listRec.Body.String())
	}

	var listed struct {
		Groups []statusAgentGroup `json:"groups"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode group list: %v", err)
	}
	if len(listed.Groups) != 2 {
		t.Fatalf("expected 2 groups including legacy, got %d", len(listed.Groups))
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/api/control-plane/agent-groups/"+created.ID, strings.NewReader(`{
		"name":"Hospital Salvador Norte",
		"slug":"hospital-salvador",
		"description":"Rede principal atualizada",
		"routingMode":"latency-first"
	}`))
	updateRec := httptest.NewRecorder()
	server.handleAgentGroupsAPI(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}

	var updated statusAgentGroup
	if err := json.NewDecoder(updateRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated group: %v", err)
	}
	if updated.Name != "Hospital Salvador Norte" || updated.RoutingMode != "latency-first" {
		t.Fatalf("unexpected updated group: %+v", updated)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/agent-groups/"+created.ID, nil)
	deleteRec := httptest.NewRecorder()
	server.handleAgentGroupsAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	events, err := server.control.ListAuditEvents(context.Background(), 10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 audit events, got %d", len(events))
	}
	if events[0].Action != "deleted" || events[0].ResourceType != "agent_group" {
		t.Fatalf("unexpected latest audit event: %+v", events[0])
	}
}

func TestAgentGroupsAPI_RejectsDeletingLegacyGroup(t *testing.T) {
	server := newTestControlPlaneServer(t)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/agent-groups/"+legacyAgentGroupID, nil)
	deleteRec := httptest.NewRecorder()
	server.handleAgentGroupsAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestDestinationProfilesAPI_CRUDAndValidation(t *testing.T) {
	server := newTestControlPlaneServer(t)
	ctx := context.Background()
	if _, err := server.control.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:          "group-1",
		Name:        "Hospital Interior",
		Slug:        "hospital-interior",
		RoutingMode: "health-first",
	}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	invalidReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/destination-profiles", strings.NewReader(`{
		"name":"AGHUse",
		"slug":"aghuse",
		"host":"aghuse.saude.ba.gov.br",
		"port":443,
		"protocolHint":"https",
		"defaultGroupId":"missing-group"
	}`))
	invalidRec := httptest.NewRecorder()
	server.handleDestinationProfilesAPI(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", invalidRec.Code, invalidRec.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/destination-profiles", strings.NewReader(`{
		"name":"AGHUse",
		"slug":"aghuse",
		"host":"aghuse.saude.ba.gov.br",
		"port":443,
		"protocolHint":"https",
		"defaultGroupId":"group-1",
		"notes":"Aplicacao hospitalar"
	}`))
	createRec := httptest.NewRecorder()
	server.handleDestinationProfilesAPI(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created statusDestinationProfile
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created profile: %v", err)
	}
	if created.ID == "" || created.DefaultGroupName != "Hospital Interior" {
		t.Fatalf("unexpected created profile: %+v", created)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/api/control-plane/destination-profiles/"+created.ID, strings.NewReader(`{
		"name":"AGHUse Produção",
		"slug":"aghuse",
		"host":"aghuse.saude.ba.gov.br",
		"port":8443,
		"protocolHint":"https",
		"defaultGroupId":"group-1",
		"notes":"Endpoint principal"
	}`))
	updateRec := httptest.NewRecorder()
	server.handleDestinationProfilesAPI(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}

	var updated statusDestinationProfile
	if err := json.NewDecoder(updateRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated profile: %v", err)
	}
	if updated.Port != 8443 || updated.Name != "AGHUse Produção" {
		t.Fatalf("unexpected updated profile: %+v", updated)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/destination-profiles/"+created.ID, nil)
	deleteRec := httptest.NewRecorder()
	server.handleDestinationProfilesAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func newTestControlPlaneServer(t *testing.T) *relayServer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := controlplane.NewMemoryStore()
	agents := map[string]*agentRecord{
		"agente01": {
			Login:    "agente01",
			Password: "secret",
		},
	}
	if err := bootstrapLegacyControlPlane(context.Background(), store, agents); err != nil {
		t.Fatalf("bootstrap legacy control plane: %v", err)
	}
	return &relayServer{
		logger:         logger,
		control:        store,
		agentDirectory: agents,
	}
}
