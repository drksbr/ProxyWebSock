package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestUsersAPI_CRUD(t *testing.T) {
	server := newTestControlPlaneServer(t)

	createReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/users", strings.NewReader(`{
		"username":"operador",
		"password":"segredo-123",
		"status":"active",
		"role":"operator"
	}`))
	createRec := httptest.NewRecorder()
	server.handleUsersAPI(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created controlPlaneUser
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}
	if created.ID == "" || created.Role != "operator" {
		t.Fatalf("unexpected created user: %+v", created)
	}

	stored, ok, err := server.control.GetUser(context.Background(), created.ID)
	if err != nil || !ok {
		t.Fatalf("expected persisted user, ok=%v err=%v", ok, err)
	}
	if !controlplane.VerifyPassword(stored.PasswordHash, "segredo-123") {
		t.Fatal("expected bcrypt password hash to verify")
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/api/control-plane/users/"+created.ID, strings.NewReader(`{
		"username":"operador-2",
		"status":"disabled",
		"role":"admin"
	}`))
	updateRec := httptest.NewRecorder()
	server.handleUsersAPI(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/users/"+created.ID, nil)
	deleteRec := httptest.NewRecorder()
	server.handleUsersAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestAgentMembershipsAPI_CRUD(t *testing.T) {
	server := newTestControlPlaneServer(t)
	ctx := context.Background()
	if _, err := server.control.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:   "group-1",
		Name: "Hospital Centro",
		Slug: "hospital-centro",
	}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/agent-memberships", strings.NewReader(`{
		"groupId":"group-1",
		"agentId":"agente01",
		"priority":10,
		"weight":3,
		"enabled":true
	}`))
	createRec := httptest.NewRecorder()
	server.handleAgentMembershipsAPI(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created controlPlaneMembership
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created membership: %v", err)
	}
	if created.GroupName != "Hospital Centro" || created.AgentID != "agente01" {
		t.Fatalf("unexpected membership payload: %+v", created)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/agent-memberships/group-1/agente01", nil)
	deleteRec := httptest.NewRecorder()
	server.handleAgentMembershipsAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestAccessGrantsAPI_CRUD(t *testing.T) {
	server := newTestControlPlaneServer(t)
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

	createReq := httptest.NewRequest(http.MethodPost, "/api/control-plane/access-grants", strings.NewReader(`{
		"userId":"user-1",
		"destinationProfileId":"profile-1",
		"accessMode":"profile"
	}`))
	createRec := httptest.NewRecorder()
	server.handleAccessGrantsAPI(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	var created controlPlaneAccessGrant
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created grant: %v", err)
	}
	if created.ID == "" || created.Username != "operador" || created.DestinationProfileName != "AGHUse" {
		t.Fatalf("unexpected access grant payload: %+v", created)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/control-plane/access-grants/"+created.ID, nil)
	deleteRec := httptest.NewRecorder()
	server.handleAccessGrantsAPI(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}
}

func TestUsersAPI_AutoConfigMetadata(t *testing.T) {
	server := newTestControlPlaneServer(t)
	server.opts = &relayOptions{
		proxyListen:      ":8080",
		socksListen:      ":1080",
		autoconfigSecret: "user-pac-secret",
	}
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

	req := httptest.NewRequest(http.MethodGet, "https://relay.example.com/api/control-plane/users/user-1/autoconfig", nil)
	rec := httptest.NewRecorder()
	server.handleUsersAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload userAutoConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode autoconfig payload: %v", err)
	}
	if !strings.Contains(payload.PACURL, "/autoconfig/users/user-1.pac?token=") {
		t.Fatalf("unexpected pac url: %s", payload.PACURL)
	}
	if len(payload.ProfileHosts) != 1 || payload.ProfileHosts[0] != "aghuse.saude.ba.gov.br:443" {
		t.Fatalf("unexpected profile hosts: %+v", payload.ProfileHosts)
	}
}
