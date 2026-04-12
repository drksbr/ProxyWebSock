package controlplane

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryStore struct {
	mu sync.RWMutex

	users                map[string]User
	userIDsByUsername    map[string]string
	agentGroups          map[string]AgentGroup
	agentGroupIDsBySlug  map[string]string
	agentMemberships     map[string]AgentMembership
	destinationProfiles  map[string]DestinationProfile
	destinationIDsBySlug map[string]string
	accessGrants         map[string]AccessGrant
	auditEvents          []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:                make(map[string]User),
		userIDsByUsername:    make(map[string]string),
		agentGroups:          make(map[string]AgentGroup),
		agentGroupIDsBySlug:  make(map[string]string),
		agentMemberships:     make(map[string]AgentMembership),
		destinationProfiles:  make(map[string]DestinationProfile),
		destinationIDsBySlug: make(map[string]string),
		accessGrants:         make(map[string]AccessGrant),
		auditEvents:          make([]AuditEvent, 0, 64),
	}
}

func (s *MemoryStore) UpsertUser(_ context.Context, user User) (User, error) {
	var err error
	user, err = prepareUser(user)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	usernameKey := normalizeKey(user.Username)

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.users[user.ID]
	if exists {
		if current.CreatedAt.IsZero() {
			current.CreatedAt = now
		}
		user.CreatedAt = current.CreatedAt
		if oldUsername := normalizeKey(current.Username); oldUsername != usernameKey {
			delete(s.userIDsByUsername, oldUsername)
		}
	} else if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}
	s.users[user.ID] = user
	s.userIDsByUsername[usernameKey] = user.ID
	return user, nil
}

func (s *MemoryStore) GetUser(_ context.Context, id string) (User, bool, error) {
	if strings.TrimSpace(id) == "" {
		return User{}, false, nil
	}
	s.mu.RLock()
	user, ok := s.users[id]
	s.mu.RUnlock()
	return user, ok, nil
}

func (s *MemoryStore) GetUserByUsername(_ context.Context, username string) (User, bool, error) {
	key := normalizeKey(username)
	if key == "" {
		return User{}, false, nil
	}
	s.mu.RLock()
	id, ok := s.userIDsByUsername[key]
	if !ok {
		s.mu.RUnlock()
		return User{}, false, nil
	}
	user := s.users[id]
	s.mu.RUnlock()
	return user, true, nil
}

func (s *MemoryStore) ListUsers(_ context.Context) ([]User, error) {
	s.mu.RLock()
	users := make([]User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	s.mu.RUnlock()
	sort.Slice(users, func(i, j int) bool {
		return users[i].Username < users[j].Username
	})
	return users, nil
}

func (s *MemoryStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	if user, ok := s.users[id]; ok {
		delete(s.users, id)
		delete(s.userIDsByUsername, normalizeKey(user.Username))
	}
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) UpsertAgentGroup(_ context.Context, group AgentGroup) (AgentGroup, error) {
	var err error
	group, err = prepareAgentGroup(group)
	if err != nil {
		return AgentGroup{}, err
	}
	now := time.Now().UTC()
	slugKey := normalizeKey(group.Slug)

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.agentGroups[group.ID]
	if exists {
		if current.CreatedAt.IsZero() {
			current.CreatedAt = now
		}
		group.CreatedAt = current.CreatedAt
		if oldSlug := normalizeKey(current.Slug); oldSlug != slugKey {
			delete(s.agentGroupIDsBySlug, oldSlug)
		}
	} else if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}
	s.agentGroups[group.ID] = group
	s.agentGroupIDsBySlug[slugKey] = group.ID
	return group, nil
}

func (s *MemoryStore) GetAgentGroup(_ context.Context, id string) (AgentGroup, bool, error) {
	if strings.TrimSpace(id) == "" {
		return AgentGroup{}, false, nil
	}
	s.mu.RLock()
	group, ok := s.agentGroups[id]
	s.mu.RUnlock()
	return group, ok, nil
}

func (s *MemoryStore) GetAgentGroupBySlug(_ context.Context, slug string) (AgentGroup, bool, error) {
	key := normalizeKey(slug)
	if key == "" {
		return AgentGroup{}, false, nil
	}
	s.mu.RLock()
	id, ok := s.agentGroupIDsBySlug[key]
	if !ok {
		s.mu.RUnlock()
		return AgentGroup{}, false, nil
	}
	group := s.agentGroups[id]
	s.mu.RUnlock()
	return group, true, nil
}

func (s *MemoryStore) ListAgentGroups(_ context.Context) ([]AgentGroup, error) {
	s.mu.RLock()
	groups := make([]AgentGroup, 0, len(s.agentGroups))
	for _, group := range s.agentGroups {
		groups = append(groups, group)
	}
	s.mu.RUnlock()
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Slug < groups[j].Slug
	})
	return groups, nil
}

func (s *MemoryStore) DeleteAgentGroup(_ context.Context, id string) error {
	s.mu.Lock()
	if group, ok := s.agentGroups[id]; ok {
		delete(s.agentGroups, id)
		delete(s.agentGroupIDsBySlug, normalizeKey(group.Slug))
		for key, membership := range s.agentMemberships {
			if membership.GroupID == id {
				delete(s.agentMemberships, key)
			}
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) UpsertAgentMembership(_ context.Context, membership AgentMembership) (AgentMembership, error) {
	var err error
	membership, err = prepareAgentMembership(membership)
	if err != nil {
		return AgentMembership{}, err
	}
	now := time.Now().UTC()
	key := membershipKey(membership.GroupID, membership.AgentID)

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.agentMemberships[key]
	if exists {
		if current.CreatedAt.IsZero() {
			current.CreatedAt = now
		}
		membership.CreatedAt = current.CreatedAt
	} else if membership.CreatedAt.IsZero() {
		membership.CreatedAt = now
	}
	if membership.UpdatedAt.IsZero() {
		membership.UpdatedAt = now
	}
	s.agentMemberships[key] = membership
	return membership, nil
}

func (s *MemoryStore) ListAgentMemberships(_ context.Context) ([]AgentMembership, error) {
	s.mu.RLock()
	memberships := make([]AgentMembership, 0, len(s.agentMemberships))
	for _, membership := range s.agentMemberships {
		memberships = append(memberships, membership)
	}
	s.mu.RUnlock()
	sort.Slice(memberships, func(i, j int) bool {
		if memberships[i].GroupID == memberships[j].GroupID {
			return memberships[i].AgentID < memberships[j].AgentID
		}
		return memberships[i].GroupID < memberships[j].GroupID
	})
	return memberships, nil
}

func (s *MemoryStore) ListAgentMembershipsByAgent(_ context.Context, agentID string) ([]AgentMembership, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, nil
	}
	s.mu.RLock()
	memberships := make([]AgentMembership, 0, len(s.agentMemberships))
	for _, membership := range s.agentMemberships {
		if membership.AgentID == agentID {
			memberships = append(memberships, membership)
		}
	}
	s.mu.RUnlock()
	sort.Slice(memberships, func(i, j int) bool {
		return memberships[i].GroupID < memberships[j].GroupID
	})
	return memberships, nil
}

func (s *MemoryStore) DeleteAgentMembership(_ context.Context, groupID, agentID string) error {
	s.mu.Lock()
	delete(s.agentMemberships, membershipKey(groupID, agentID))
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) UpsertDestinationProfile(_ context.Context, profile DestinationProfile) (DestinationProfile, error) {
	var err error
	profile, err = prepareDestinationProfile(profile)
	if err != nil {
		return DestinationProfile{}, err
	}
	now := time.Now().UTC()
	slugKey := normalizeKey(profile.Slug)

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.destinationProfiles[profile.ID]
	if exists {
		if current.CreatedAt.IsZero() {
			current.CreatedAt = now
		}
		profile.CreatedAt = current.CreatedAt
		if oldSlug := normalizeKey(current.Slug); oldSlug != slugKey {
			delete(s.destinationIDsBySlug, oldSlug)
		}
	} else if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}
	s.destinationProfiles[profile.ID] = profile
	s.destinationIDsBySlug[slugKey] = profile.ID
	return profile, nil
}

func (s *MemoryStore) GetDestinationProfile(_ context.Context, id string) (DestinationProfile, bool, error) {
	if strings.TrimSpace(id) == "" {
		return DestinationProfile{}, false, nil
	}
	s.mu.RLock()
	profile, ok := s.destinationProfiles[id]
	s.mu.RUnlock()
	return profile, ok, nil
}

func (s *MemoryStore) GetDestinationProfileBySlug(_ context.Context, slug string) (DestinationProfile, bool, error) {
	key := normalizeKey(slug)
	if key == "" {
		return DestinationProfile{}, false, nil
	}
	s.mu.RLock()
	id, ok := s.destinationIDsBySlug[key]
	if !ok {
		s.mu.RUnlock()
		return DestinationProfile{}, false, nil
	}
	profile := s.destinationProfiles[id]
	s.mu.RUnlock()
	return profile, true, nil
}

func (s *MemoryStore) ListDestinationProfiles(_ context.Context) ([]DestinationProfile, error) {
	s.mu.RLock()
	profiles := make([]DestinationProfile, 0, len(s.destinationProfiles))
	for _, profile := range s.destinationProfiles {
		profiles = append(profiles, profile)
	}
	s.mu.RUnlock()
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Slug < profiles[j].Slug
	})
	return profiles, nil
}

func (s *MemoryStore) DeleteDestinationProfile(_ context.Context, id string) error {
	s.mu.Lock()
	if profile, ok := s.destinationProfiles[id]; ok {
		delete(s.destinationProfiles, id)
		delete(s.destinationIDsBySlug, normalizeKey(profile.Slug))
	}
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) UpsertAccessGrant(_ context.Context, grant AccessGrant) (AccessGrant, error) {
	var err error
	grant, err = prepareAccessGrant(grant)
	if err != nil {
		return AccessGrant{}, err
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.accessGrants[grant.ID]
	if exists {
		if current.CreatedAt.IsZero() {
			current.CreatedAt = now
		}
		grant.CreatedAt = current.CreatedAt
	} else if grant.CreatedAt.IsZero() {
		grant.CreatedAt = now
	}
	if grant.UpdatedAt.IsZero() {
		grant.UpdatedAt = now
	}
	s.accessGrants[grant.ID] = grant
	return grant, nil
}

func (s *MemoryStore) GetAccessGrant(_ context.Context, id string) (AccessGrant, bool, error) {
	if strings.TrimSpace(id) == "" {
		return AccessGrant{}, false, nil
	}
	s.mu.RLock()
	grant, ok := s.accessGrants[id]
	s.mu.RUnlock()
	return grant, ok, nil
}

func (s *MemoryStore) ListAccessGrants(_ context.Context) ([]AccessGrant, error) {
	s.mu.RLock()
	grants := make([]AccessGrant, 0, len(s.accessGrants))
	for _, grant := range s.accessGrants {
		grants = append(grants, grant)
	}
	s.mu.RUnlock()
	sort.Slice(grants, func(i, j int) bool {
		return grants[i].ID < grants[j].ID
	})
	return grants, nil
}

func (s *MemoryStore) ListAccessGrantsByUser(_ context.Context, userID string) ([]AccessGrant, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	s.mu.RLock()
	grants := make([]AccessGrant, 0, len(s.accessGrants))
	for _, grant := range s.accessGrants {
		if grant.UserID == userID {
			grants = append(grants, grant)
		}
	}
	s.mu.RUnlock()
	sort.Slice(grants, func(i, j int) bool {
		return grants[i].ID < grants[j].ID
	})
	return grants, nil
}

func (s *MemoryStore) DeleteAccessGrant(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.accessGrants, id)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) AppendAuditEvent(_ context.Context, event AuditEvent) (AuditEvent, error) {
	prepared, err := prepareAuditEvent(event)
	if err != nil {
		return AuditEvent{}, err
	}

	s.mu.Lock()
	s.auditEvents = append(s.auditEvents, cloneAuditEvent(prepared))
	s.mu.Unlock()
	return cloneAuditEvent(prepared), nil
}

func (s *MemoryStore) ListAuditEvents(_ context.Context, limit int) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.auditEvents) {
		limit = len(s.auditEvents)
	}
	events := make([]AuditEvent, 0, limit)
	for i := len(s.auditEvents) - 1; i >= 0 && len(events) < limit; i-- {
		events = append(events, cloneAuditEvent(s.auditEvents[i]))
	}
	return events, nil
}

func cloneAuditEvent(event AuditEvent) AuditEvent {
	cloned := event
	if len(event.Metadata) == 0 {
		cloned.Metadata = nil
		return cloned
	}
	cloned.Metadata = make(map[string]string, len(event.Metadata))
	for key, value := range event.Metadata {
		cloned.Metadata[key] = value
	}
	return cloned
}
