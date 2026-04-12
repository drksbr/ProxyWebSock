package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestUserAutoConfigTokenRoundTrip(t *testing.T) {
	token := mintUserAutoConfigToken("secret-key", "user-1")
	if token == "" {
		t.Fatal("expected token")
	}
	if !verifyUserAutoConfigToken("secret-key", "user-1", token) {
		t.Fatal("expected token verification to succeed")
	}
	if verifyUserAutoConfigToken("other-key", "user-1", token) {
		t.Fatal("expected token verification to fail with different secret")
	}
}

func TestHandleUserAutoConfigReturnsScopedPAC(t *testing.T) {
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

	token := mintUserAutoConfigToken(server.userAutoConfigSecret(), "user-1")
	req := httptest.NewRequest(http.MethodGet, "https://relay.example.com/autoconfig/users/user-1.pac?token="+token, nil)
	rec := httptest.NewRecorder()
	server.handleAutoConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `host === "aghuse.saude.ba.gov.br"`) {
		t.Fatalf("expected scoped PAC rule, got %s", body)
	}
	if !strings.Contains(body, `SOCKS5 relay.example.com:1080; PROXY relay.example.com:8080; DIRECT`) {
		t.Fatalf("expected proxy chain in pac, got %s", body)
	}
}
