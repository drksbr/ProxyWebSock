package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create sqlite dir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &SQLiteStore{db: db}
	if err := store.init(context.Background(), path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) init(ctx context.Context, path string) error {
	pragmas := []string{
		`PRAGMA foreign_keys = ON;`,
		`PRAGMA busy_timeout = 5000;`,
	}
	if path != ":memory:" {
		pragmas = append(pragmas, `PRAGMA journal_mode = WAL;`)
	}
	for _, pragma := range pragmas {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("init sqlite pragma %q: %w", pragma, err)
		}
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS agent_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL,
			routing_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS agent_memberships (
			group_id TEXT NOT NULL,
			agent_id TEXT NOT NULL,
			priority INTEGER NOT NULL,
			weight INTEGER NOT NULL,
			enabled INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (group_id, agent_id),
			FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS destination_profiles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol_hint TEXT NOT NULL,
			default_group_id TEXT NOT NULL,
			notes TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS access_grants (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			destination_profile_id TEXT NOT NULL,
			access_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id TEXT PRIMARY KEY,
			category TEXT NOT NULL,
			action TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			actor_name TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			resource_name TEXT NOT NULL,
			outcome TEXT NOT NULL,
			message TEXT NOT NULL,
			remote_addr TEXT NOT NULL,
			metadata_json TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS audit_events_created_at_idx
			ON audit_events(created_at DESC);`,
	}
	for _, stmt := range schema {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("init sqlite schema: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) UpsertUser(ctx context.Context, user User) (User, error) {
	var err error
	user, err = prepareUser(user)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, status, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			username = excluded.username,
			password_hash = excluded.password_hash,
			status = excluded.status,
			role = excluded.role,
			created_at = users.created_at,
			updated_at = excluded.updated_at
	`, user.ID, user.Username, user.PasswordHash, string(user.Status), string(user.Role), toUnixNanos(user.CreatedAt), toUnixNanos(user.UpdatedAt))
	if err != nil {
		return User{}, fmt.Errorf("upsert user: %w", err)
	}
	got, ok, err := s.GetUser(ctx, user.ID)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, fmt.Errorf("user %s missing after upsert", user.ID)
	}
	return got, nil
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (User, bool, error) {
	if strings.TrimSpace(id) == "" {
		return User{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, status, role, created_at, updated_at
		FROM users
		WHERE id = ?
	`, id)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("get user: %w", err)
	}
	return user, true, nil
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (User, bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, status, role, created_at, updated_at
		FROM users
		WHERE lower(username) = lower(?)
	`, username)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("get user by username: %w", err)
	}
	return user, true, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, password_hash, status, role, created_at, updated_at
		FROM users
		ORDER BY username
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertAgentGroup(ctx context.Context, group AgentGroup) (AgentGroup, error) {
	var err error
	group, err = prepareAgentGroup(group)
	if err != nil {
		return AgentGroup{}, err
	}
	now := time.Now().UTC()
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	if group.UpdatedAt.IsZero() {
		group.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO agent_groups (id, name, slug, description, routing_mode, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			slug = excluded.slug,
			description = excluded.description,
			routing_mode = excluded.routing_mode,
			created_at = agent_groups.created_at,
			updated_at = excluded.updated_at
	`, group.ID, group.Name, group.Slug, group.Description, group.RoutingMode, toUnixNanos(group.CreatedAt), toUnixNanos(group.UpdatedAt))
	if err != nil {
		return AgentGroup{}, fmt.Errorf("upsert agent group: %w", err)
	}
	got, ok, err := s.GetAgentGroup(ctx, group.ID)
	if err != nil {
		return AgentGroup{}, err
	}
	if !ok {
		return AgentGroup{}, fmt.Errorf("agent group %s missing after upsert", group.ID)
	}
	return got, nil
}

func (s *SQLiteStore) GetAgentGroup(ctx context.Context, id string) (AgentGroup, bool, error) {
	if strings.TrimSpace(id) == "" {
		return AgentGroup{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, description, routing_mode, created_at, updated_at
		FROM agent_groups
		WHERE id = ?
	`, id)
	group, err := scanAgentGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentGroup{}, false, nil
	}
	if err != nil {
		return AgentGroup{}, false, fmt.Errorf("get agent group: %w", err)
	}
	return group, true, nil
}

func (s *SQLiteStore) GetAgentGroupBySlug(ctx context.Context, slug string) (AgentGroup, bool, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return AgentGroup{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, description, routing_mode, created_at, updated_at
		FROM agent_groups
		WHERE lower(slug) = lower(?)
	`, slug)
	group, err := scanAgentGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentGroup{}, false, nil
	}
	if err != nil {
		return AgentGroup{}, false, fmt.Errorf("get agent group by slug: %w", err)
	}
	return group, true, nil
}

func (s *SQLiteStore) ListAgentGroups(ctx context.Context) ([]AgentGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, slug, description, routing_mode, created_at, updated_at
		FROM agent_groups
		ORDER BY slug
	`)
	if err != nil {
		return nil, fmt.Errorf("list agent groups: %w", err)
	}
	defer rows.Close()
	groups := make([]AgentGroup, 0)
	for rows.Next() {
		group, err := scanAgentGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent group: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent groups: %w", err)
	}
	return groups, nil
}

func (s *SQLiteStore) DeleteAgentGroup(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete agent group: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_memberships WHERE group_id = ?`, id); err != nil {
		return fmt.Errorf("delete group memberships: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_groups WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete agent group: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) UpsertAgentMembership(ctx context.Context, membership AgentMembership) (AgentMembership, error) {
	var err error
	membership, err = prepareAgentMembership(membership)
	if err != nil {
		return AgentMembership{}, err
	}
	now := time.Now().UTC()
	if membership.CreatedAt.IsZero() {
		membership.CreatedAt = now
	}
	if membership.UpdatedAt.IsZero() {
		membership.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO agent_memberships (group_id, agent_id, priority, weight, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(group_id, agent_id) DO UPDATE SET
			priority = excluded.priority,
			weight = excluded.weight,
			enabled = excluded.enabled,
			created_at = agent_memberships.created_at,
			updated_at = excluded.updated_at
	`, membership.GroupID, membership.AgentID, membership.Priority, membership.Weight, boolToInt(membership.Enabled), toUnixNanos(membership.CreatedAt), toUnixNanos(membership.UpdatedAt))
	if err != nil {
		return AgentMembership{}, fmt.Errorf("upsert agent membership: %w", err)
	}
	return membership, nil
}

func (s *SQLiteStore) ListAgentMemberships(ctx context.Context) ([]AgentMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT group_id, agent_id, priority, weight, enabled, created_at, updated_at
		FROM agent_memberships
		ORDER BY group_id, agent_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list agent memberships: %w", err)
	}
	defer rows.Close()
	memberships := make([]AgentMembership, 0)
	for rows.Next() {
		membership, err := scanAgentMembership(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent membership: %w", err)
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent memberships: %w", err)
	}
	return memberships, nil
}

func (s *SQLiteStore) ListAgentMembershipsByAgent(ctx context.Context, agentID string) ([]AgentMembership, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT group_id, agent_id, priority, weight, enabled, created_at, updated_at
		FROM agent_memberships
		WHERE agent_id = ?
		ORDER BY group_id
	`, agentID)
	if err != nil {
		return nil, fmt.Errorf("list agent memberships by agent: %w", err)
	}
	defer rows.Close()
	memberships := make([]AgentMembership, 0)
	for rows.Next() {
		membership, err := scanAgentMembership(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent membership: %w", err)
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent memberships by agent: %w", err)
	}
	return memberships, nil
}

func (s *SQLiteStore) DeleteAgentMembership(ctx context.Context, groupID, agentID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM agent_memberships
		WHERE group_id = ? AND agent_id = ?
	`, groupID, agentID)
	if err != nil {
		return fmt.Errorf("delete agent membership: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertDestinationProfile(ctx context.Context, profile DestinationProfile) (DestinationProfile, error) {
	var err error
	profile, err = prepareDestinationProfile(profile)
	if err != nil {
		return DestinationProfile{}, err
	}
	now := time.Now().UTC()
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = now
	}
	if profile.UpdatedAt.IsZero() {
		profile.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO destination_profiles (id, name, slug, host, port, protocol_hint, default_group_id, notes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			slug = excluded.slug,
			host = excluded.host,
			port = excluded.port,
			protocol_hint = excluded.protocol_hint,
			default_group_id = excluded.default_group_id,
			notes = excluded.notes,
			created_at = destination_profiles.created_at,
			updated_at = excluded.updated_at
	`, profile.ID, profile.Name, profile.Slug, profile.Host, profile.Port, profile.ProtocolHint, profile.DefaultGroupID, profile.Notes, toUnixNanos(profile.CreatedAt), toUnixNanos(profile.UpdatedAt))
	if err != nil {
		return DestinationProfile{}, fmt.Errorf("upsert destination profile: %w", err)
	}
	got, ok, err := s.GetDestinationProfile(ctx, profile.ID)
	if err != nil {
		return DestinationProfile{}, err
	}
	if !ok {
		return DestinationProfile{}, fmt.Errorf("destination profile %s missing after upsert", profile.ID)
	}
	return got, nil
}

func (s *SQLiteStore) GetDestinationProfile(ctx context.Context, id string) (DestinationProfile, bool, error) {
	if strings.TrimSpace(id) == "" {
		return DestinationProfile{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, host, port, protocol_hint, default_group_id, notes, created_at, updated_at
		FROM destination_profiles
		WHERE id = ?
	`, id)
	profile, err := scanDestinationProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DestinationProfile{}, false, nil
	}
	if err != nil {
		return DestinationProfile{}, false, fmt.Errorf("get destination profile: %w", err)
	}
	return profile, true, nil
}

func (s *SQLiteStore) GetDestinationProfileBySlug(ctx context.Context, slug string) (DestinationProfile, bool, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return DestinationProfile{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, slug, host, port, protocol_hint, default_group_id, notes, created_at, updated_at
		FROM destination_profiles
		WHERE lower(slug) = lower(?)
	`, slug)
	profile, err := scanDestinationProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DestinationProfile{}, false, nil
	}
	if err != nil {
		return DestinationProfile{}, false, fmt.Errorf("get destination profile by slug: %w", err)
	}
	return profile, true, nil
}

func (s *SQLiteStore) ListDestinationProfiles(ctx context.Context) ([]DestinationProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, slug, host, port, protocol_hint, default_group_id, notes, created_at, updated_at
		FROM destination_profiles
		ORDER BY slug
	`)
	if err != nil {
		return nil, fmt.Errorf("list destination profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]DestinationProfile, 0)
	for rows.Next() {
		profile, err := scanDestinationProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan destination profile: %w", err)
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate destination profiles: %w", err)
	}
	return profiles, nil
}

func (s *SQLiteStore) DeleteDestinationProfile(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM destination_profiles WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete destination profile: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpsertAccessGrant(ctx context.Context, grant AccessGrant) (AccessGrant, error) {
	var err error
	grant, err = prepareAccessGrant(grant)
	if err != nil {
		return AccessGrant{}, err
	}
	now := time.Now().UTC()
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = now
	}
	if grant.UpdatedAt.IsZero() {
		grant.UpdatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO access_grants (id, user_id, group_id, destination_profile_id, access_mode, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			group_id = excluded.group_id,
			destination_profile_id = excluded.destination_profile_id,
			access_mode = excluded.access_mode,
			created_at = access_grants.created_at,
			updated_at = excluded.updated_at
	`, grant.ID, grant.UserID, grant.GroupID, grant.DestinationProfileID, grant.AccessMode, toUnixNanos(grant.CreatedAt), toUnixNanos(grant.UpdatedAt))
	if err != nil {
		return AccessGrant{}, fmt.Errorf("upsert access grant: %w", err)
	}
	got, ok, err := s.GetAccessGrant(ctx, grant.ID)
	if err != nil {
		return AccessGrant{}, err
	}
	if !ok {
		return AccessGrant{}, fmt.Errorf("access grant %s missing after upsert", grant.ID)
	}
	return got, nil
}

func (s *SQLiteStore) GetAccessGrant(ctx context.Context, id string) (AccessGrant, bool, error) {
	if strings.TrimSpace(id) == "" {
		return AccessGrant{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, group_id, destination_profile_id, access_mode, created_at, updated_at
		FROM access_grants
		WHERE id = ?
	`, id)
	grant, err := scanAccessGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessGrant{}, false, nil
	}
	if err != nil {
		return AccessGrant{}, false, fmt.Errorf("get access grant: %w", err)
	}
	return grant, true, nil
}

func (s *SQLiteStore) ListAccessGrants(ctx context.Context) ([]AccessGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, group_id, destination_profile_id, access_mode, created_at, updated_at
		FROM access_grants
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list access grants: %w", err)
	}
	defer rows.Close()
	grants := make([]AccessGrant, 0)
	for rows.Next() {
		grant, err := scanAccessGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan access grant: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access grants: %w", err)
	}
	return grants, nil
}

func (s *SQLiteStore) ListAccessGrantsByUser(ctx context.Context, userID string) ([]AccessGrant, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, group_id, destination_profile_id, access_mode, created_at, updated_at
		FROM access_grants
		WHERE user_id = ?
		ORDER BY id
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list access grants by user: %w", err)
	}
	defer rows.Close()
	grants := make([]AccessGrant, 0)
	for rows.Next() {
		grant, err := scanAccessGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan access grant: %w", err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access grants by user: %w", err)
	}
	return grants, nil
}

func (s *SQLiteStore) DeleteAccessGrant(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_grants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete access grant: %w", err)
	}
	return nil
}

func (s *SQLiteStore) AppendAuditEvent(ctx context.Context, event AuditEvent) (AuditEvent, error) {
	prepared, err := prepareAuditEvent(event)
	if err != nil {
		return AuditEvent{}, err
	}
	metadataJSON, err := json.Marshal(prepared.Metadata)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("marshal audit metadata: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			id, category, action, actor_type, actor_id, actor_name,
			resource_type, resource_id, resource_name,
			outcome, message, remote_addr, metadata_json, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, prepared.ID, prepared.Category, prepared.Action, prepared.ActorType, prepared.ActorID, prepared.ActorName, prepared.ResourceType, prepared.ResourceID, prepared.ResourceName, prepared.Outcome, prepared.Message, prepared.RemoteAddr, string(metadataJSON), toUnixNanos(prepared.CreatedAt))
	if err != nil {
		return AuditEvent{}, fmt.Errorf("append audit event: %w", err)
	}
	return cloneAuditEvent(prepared), nil
}

func (s *SQLiteStore) ListAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	query := `
		SELECT id, category, action, actor_type, actor_id, actor_name,
		       resource_type, resource_id, resource_name,
		       outcome, message, remote_addr, metadata_json, created_at
		FROM audit_events
		ORDER BY created_at DESC, id DESC
	`
	var (
		rows *sql.Rows
		err  error
	)
	if limit > 0 {
		rows, err = s.db.QueryContext(ctx, query+` LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, query)
	}
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	events := make([]AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(scanner rowScanner) (User, error) {
	var user User
	var status, role string
	var createdAt, updatedAt int64
	if err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash, &status, &role, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	user.Status = UserStatus(status)
	user.Role = UserRole(role)
	user.CreatedAt = fromUnixNanos(createdAt)
	user.UpdatedAt = fromUnixNanos(updatedAt)
	return user, nil
}

func scanAgentGroup(scanner rowScanner) (AgentGroup, error) {
	var group AgentGroup
	var createdAt, updatedAt int64
	if err := scanner.Scan(&group.ID, &group.Name, &group.Slug, &group.Description, &group.RoutingMode, &createdAt, &updatedAt); err != nil {
		return AgentGroup{}, err
	}
	group.CreatedAt = fromUnixNanos(createdAt)
	group.UpdatedAt = fromUnixNanos(updatedAt)
	return group, nil
}

func scanAgentMembership(scanner rowScanner) (AgentMembership, error) {
	var membership AgentMembership
	var enabled int
	var createdAt, updatedAt int64
	if err := scanner.Scan(&membership.GroupID, &membership.AgentID, &membership.Priority, &membership.Weight, &enabled, &createdAt, &updatedAt); err != nil {
		return AgentMembership{}, err
	}
	membership.Enabled = enabled != 0
	membership.CreatedAt = fromUnixNanos(createdAt)
	membership.UpdatedAt = fromUnixNanos(updatedAt)
	return membership, nil
}

func scanDestinationProfile(scanner rowScanner) (DestinationProfile, error) {
	var profile DestinationProfile
	var createdAt, updatedAt int64
	if err := scanner.Scan(&profile.ID, &profile.Name, &profile.Slug, &profile.Host, &profile.Port, &profile.ProtocolHint, &profile.DefaultGroupID, &profile.Notes, &createdAt, &updatedAt); err != nil {
		return DestinationProfile{}, err
	}
	profile.CreatedAt = fromUnixNanos(createdAt)
	profile.UpdatedAt = fromUnixNanos(updatedAt)
	return profile, nil
}

func scanAccessGrant(scanner rowScanner) (AccessGrant, error) {
	var grant AccessGrant
	var createdAt, updatedAt int64
	if err := scanner.Scan(&grant.ID, &grant.UserID, &grant.GroupID, &grant.DestinationProfileID, &grant.AccessMode, &createdAt, &updatedAt); err != nil {
		return AccessGrant{}, err
	}
	grant.CreatedAt = fromUnixNanos(createdAt)
	grant.UpdatedAt = fromUnixNanos(updatedAt)
	return grant, nil
}

func scanAuditEvent(scanner rowScanner) (AuditEvent, error) {
	var event AuditEvent
	var (
		metadataJSON string
		createdAt    int64
	)
	if err := scanner.Scan(
		&event.ID,
		&event.Category,
		&event.Action,
		&event.ActorType,
		&event.ActorID,
		&event.ActorName,
		&event.ResourceType,
		&event.ResourceID,
		&event.ResourceName,
		&event.Outcome,
		&event.Message,
		&event.RemoteAddr,
		&metadataJSON,
		&createdAt,
	); err != nil {
		return AuditEvent{}, err
	}
	event.CreatedAt = fromUnixNanos(createdAt)
	if strings.TrimSpace(metadataJSON) != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &event.Metadata); err != nil {
			return AuditEvent{}, fmt.Errorf("decode audit metadata: %w", err)
		}
	}
	return event, nil
}

func toUnixNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixNano()
}

func fromUnixNanos(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v).UTC()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
