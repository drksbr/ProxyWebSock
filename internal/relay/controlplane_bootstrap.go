package relay

import (
	"context"
	"fmt"
	"sort"

	"github.com/drksbr/ProxyWebSock/internal/controlplane"
)

const (
	legacyAgentGroupID   = "legacy-all-agents"
	legacyAgentGroupSlug = "legacy-all-agents"
)

func bootstrapLegacyControlPlane(ctx context.Context, store controlplane.Store, agents map[string]*agentRecord) error {
	if store == nil {
		return nil
	}
	if _, err := store.UpsertAgentGroup(ctx, controlplane.AgentGroup{
		ID:          legacyAgentGroupID,
		Name:        "Legacy All Agents",
		Slug:        legacyAgentGroupSlug,
		Description: "Auto-generated compatibility group populated from the static relay agent configuration.",
		RoutingMode: "legacy",
	}); err != nil {
		return fmt.Errorf("upsert legacy group: %w", err)
	}

	agentIDs := make([]string, 0, len(agents))
	for agentID := range agents {
		agentIDs = append(agentIDs, agentID)
	}
	sort.Strings(agentIDs)

	for _, agentID := range agentIDs {
		if _, err := store.UpsertAgentMembership(ctx, controlplane.AgentMembership{
			GroupID:  legacyAgentGroupID,
			AgentID:  agentID,
			Enabled:  true,
			Priority: 100,
			Weight:   1,
		}); err != nil {
			return fmt.Errorf("upsert legacy membership for %s: %w", agentID, err)
		}
	}
	return nil
}
