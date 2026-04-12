package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStoreUserRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	passwordHash, err := HashPassword("secret-123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user, err := store.UpsertUser(ctx, User{
		ID:           "user-1",
		Username:     "Admin",
		PasswordHash: passwordHash,
		Status:       UserStatusActive,
		Role:         UserRoleAdmin,
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	if user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}

	got, ok, err := store.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("get by username: %v", err)
	}
	if !ok {
		t.Fatal("expected user by username")
	}
	if got.ID != "user-1" {
		t.Fatalf("unexpected user id: %s", got.ID)
	}
}

func TestMemoryStoreAgentMembershipsByAgent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

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

	memberships, err := store.ListAgentMembershipsByAgent(ctx, "agente01")
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 1 {
		t.Fatalf("unexpected memberships len: %d", len(memberships))
	}
	if memberships[0].GroupID != "group-1" {
		t.Fatalf("unexpected group id: %s", memberships[0].GroupID)
	}
}

func TestMemoryStoreDestinationAndGrantRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if _, err := store.UpsertDestinationProfile(ctx, DestinationProfile{
		ID:           "dest-1",
		Name:         "AGHUse",
		Slug:         "aghuse",
		Host:         "aghuse.saude.ba.gov.br",
		Port:         443,
		ProtocolHint: "https",
	}); err != nil {
		t.Fatalf("upsert destination: %v", err)
	}
	if _, err := store.UpsertAccessGrant(ctx, AccessGrant{
		ID:                   "grant-1",
		UserID:               "user-1",
		DestinationProfileID: "dest-1",
		AccessMode:           "profile",
	}); err != nil {
		t.Fatalf("upsert access grant: %v", err)
	}

	profile, ok, err := store.GetDestinationProfileBySlug(ctx, "aghuse")
	if err != nil {
		t.Fatalf("get destination: %v", err)
	}
	if !ok || profile.Host != "aghuse.saude.ba.gov.br" {
		t.Fatalf("unexpected destination profile: %+v", profile)
	}

	grants, err := store.ListAccessGrantsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 1 || grants[0].DestinationProfileID != "dest-1" {
		t.Fatalf("unexpected grants: %+v", grants)
	}
}

func TestMemoryStoreAuditEventsNewestFirst(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	first, err := store.AppendAuditEvent(ctx, AuditEvent{
		Category:     "control_plane",
		Action:       "create",
		ResourceType: "user",
		ResourceID:   "user-1",
		ResourceName: "operator",
		CreatedAt:    time.Now().Add(-time.Minute).UTC(),
		Metadata: map[string]string{
			"username": "operator",
		},
	})
	if err != nil {
		t.Fatalf("append first audit event: %v", err)
	}
	second, err := store.AppendAuditEvent(ctx, AuditEvent{
		Category:     "diagnostic",
		Action:       "run",
		ResourceType: "diagnostic",
		ResourceID:   "aghuse.saude.ba.gov.br:443",
		Outcome:      "failed",
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("append second audit event: %v", err)
	}

	events, err := store.ListAuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("unexpected audit event count: %d", len(events))
	}
	if events[0].ID != second.ID || events[1].ID != first.ID {
		t.Fatalf("unexpected audit order: %+v", events)
	}
	if events[1].Metadata["username"] != "operator" {
		t.Fatalf("unexpected audit metadata: %+v", events[1].Metadata)
	}
}
