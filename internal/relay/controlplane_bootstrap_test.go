package relay

import (
	"context"
	"testing"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

func TestBootstrapLegacyControlPlane(t *testing.T) {
	store := controlplane.NewMemoryStore()
	agents := map[string]*agentRecord{
		"agente01": {Login: "agente01"},
		"agente02": {Login: "agente02"},
	}

	if err := bootstrapLegacyControlPlane(context.Background(), store, agents); err != nil {
		t.Fatalf("bootstrap control plane: %v", err)
	}

	group, ok, err := store.GetAgentGroupBySlug(context.Background(), legacyAgentGroupSlug)
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if !ok {
		t.Fatal("expected legacy agent group")
	}
	if group.ID != legacyAgentGroupID {
		t.Fatalf("unexpected group id: %s", group.ID)
	}

	memberships, err := store.ListAgentMemberships(context.Background())
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("unexpected membership count: %d", len(memberships))
	}
}
