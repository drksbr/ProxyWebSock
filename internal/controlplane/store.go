package controlplane

import "context"

type Store interface {
	UpsertUser(ctx context.Context, user User) (User, error)
	GetUser(ctx context.Context, id string) (User, bool, error)
	GetUserByUsername(ctx context.Context, username string) (User, bool, error)
	ListUsers(ctx context.Context) ([]User, error)
	DeleteUser(ctx context.Context, id string) error

	UpsertAgentGroup(ctx context.Context, group AgentGroup) (AgentGroup, error)
	GetAgentGroup(ctx context.Context, id string) (AgentGroup, bool, error)
	GetAgentGroupBySlug(ctx context.Context, slug string) (AgentGroup, bool, error)
	ListAgentGroups(ctx context.Context) ([]AgentGroup, error)
	DeleteAgentGroup(ctx context.Context, id string) error

	UpsertAgentMembership(ctx context.Context, membership AgentMembership) (AgentMembership, error)
	ListAgentMemberships(ctx context.Context) ([]AgentMembership, error)
	ListAgentMembershipsByAgent(ctx context.Context, agentID string) ([]AgentMembership, error)
	DeleteAgentMembership(ctx context.Context, groupID, agentID string) error

	UpsertDestinationProfile(ctx context.Context, profile DestinationProfile) (DestinationProfile, error)
	GetDestinationProfile(ctx context.Context, id string) (DestinationProfile, bool, error)
	GetDestinationProfileBySlug(ctx context.Context, slug string) (DestinationProfile, bool, error)
	ListDestinationProfiles(ctx context.Context) ([]DestinationProfile, error)
	DeleteDestinationProfile(ctx context.Context, id string) error

	UpsertAccessGrant(ctx context.Context, grant AccessGrant) (AccessGrant, error)
	GetAccessGrant(ctx context.Context, id string) (AccessGrant, bool, error)
	ListAccessGrants(ctx context.Context) ([]AccessGrant, error)
	ListAccessGrantsByUser(ctx context.Context, userID string) ([]AccessGrant, error)
	DeleteAccessGrant(ctx context.Context, id string) error

	AppendAuditEvent(ctx context.Context, event AuditEvent) (AuditEvent, error)
	ListAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error)
}
