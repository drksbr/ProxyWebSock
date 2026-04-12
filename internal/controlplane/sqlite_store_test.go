package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreRoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controlplane.db")
	ctx := context.Background()

	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("new sqlite store: %v", err)
	}
	passwordHash, err := HashPassword("secret-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if _, err := store.UpsertUser(ctx, User{
		ID:           "user-1",
		Username:     "operator",
		PasswordHash: passwordHash,
	}); err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if _, err := store.UpsertAgentGroup(ctx, AgentGroup{
		ID:   "group-1",
		Name: "Hospital Salvador",
		Slug: "hospital-salvador",
	}); err != nil {
		t.Fatalf("upsert group: %v", err)
	}
	if _, err := store.UpsertAgentMembership(ctx, AgentMembership{
		GroupID: "group-1",
		AgentID: "agente01",
		Enabled: true,
	}); err != nil {
		t.Fatalf("upsert membership: %v", err)
	}
	if _, err := store.UpsertDestinationProfile(ctx, DestinationProfile{
		ID:             "profile-1",
		Name:           "AGHUse",
		Slug:           "aghuse",
		Host:           "aghuse.saude.ba.gov.br",
		Port:           443,
		ProtocolHint:   "https",
		DefaultGroupID: "group-1",
	}); err != nil {
		t.Fatalf("upsert destination profile: %v", err)
	}
	if _, err := store.UpsertAccessGrant(ctx, AccessGrant{
		ID:                   "grant-1",
		UserID:               "user-1",
		DestinationProfileID: "profile-1",
		AccessMode:           "profile",
	}); err != nil {
		t.Fatalf("upsert access grant: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close sqlite store: %v", err)
	}

	reloaded, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reload sqlite store: %v", err)
	}
	defer reloaded.Close()

	user, ok, err := reloaded.GetUserByUsername(ctx, "operator")
	if err != nil {
		t.Fatalf("get user by username: %v", err)
	}
	if !ok || user.Status != UserStatusActive || user.Role != UserRoleUser {
		t.Fatalf("unexpected persisted user: %+v", user)
	}

	group, ok, err := reloaded.GetAgentGroupBySlug(ctx, "hospital-salvador")
	if err != nil {
		t.Fatalf("get agent group by slug: %v", err)
	}
	if !ok || group.RoutingMode != "health-first" {
		t.Fatalf("unexpected persisted group: %+v", group)
	}

	memberships, err := reloaded.ListAgentMembershipsByAgent(ctx, "agente01")
	if err != nil {
		t.Fatalf("list memberships by agent: %v", err)
	}
	if len(memberships) != 1 || memberships[0].Weight != 1 {
		t.Fatalf("unexpected memberships: %+v", memberships)
	}

	profile, ok, err := reloaded.GetDestinationProfileBySlug(ctx, "aghuse")
	if err != nil {
		t.Fatalf("get destination profile by slug: %v", err)
	}
	if !ok || profile.DefaultGroupID != "group-1" {
		t.Fatalf("unexpected persisted profile: %+v", profile)
	}

	grants, err := reloaded.ListAccessGrantsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list access grants by user: %v", err)
	}
	if len(grants) != 1 || grants[0].DestinationProfileID != "profile-1" {
		t.Fatalf("unexpected grants: %+v", grants)
	}

	event, err := reloaded.AppendAuditEvent(ctx, AuditEvent{
		Category:     "control_plane",
		Action:       "create",
		ActorType:    "dashboard_user",
		ActorName:    "admin",
		ResourceType: "user",
		ResourceID:   "user-1",
		ResourceName: "operator",
		Metadata: map[string]string{
			"username": "operator",
		},
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	if err := reloaded.Close(); err != nil {
		t.Fatalf("close reloaded sqlite store: %v", err)
	}

	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen sqlite store: %v", err)
	}
	defer reopened.Close()

	events, err := reopened.ListAuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("unexpected audit event count: %d", len(events))
	}
	if events[0].ID != event.ID || events[0].Metadata["username"] != "operator" {
		t.Fatalf("unexpected persisted audit event: %+v", events[0])
	}
}
