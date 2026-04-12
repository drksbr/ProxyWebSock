package controlplane

import "time"

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

type UserRole string

const (
	UserRoleAdmin    UserRole = "admin"
	UserRoleOperator UserRole = "operator"
	UserRoleUser     UserRole = "user"
)

type User struct {
	ID           string
	Username     string
	PasswordHash string
	Status       UserStatus
	Role         UserRole
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AgentGroup struct {
	ID          string
	Name        string
	Slug        string
	Description string
	RoutingMode string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AgentMembership struct {
	AgentID   string
	GroupID   string
	Priority  int
	Weight    int
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type DestinationProfile struct {
	ID             string
	Name           string
	Slug           string
	Host           string
	Port           int
	ProtocolHint   string
	DefaultGroupID string
	Notes          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type AccessGrant struct {
	ID                   string
	UserID               string
	GroupID              string
	DestinationProfileID string
	AccessMode           string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type AuditEvent struct {
	ID           string
	Category     string
	Action       string
	ActorType    string
	ActorID      string
	ActorName    string
	ResourceType string
	ResourceID   string
	ResourceName string
	Outcome      string
	Message      string
	RemoteAddr   string
	Metadata     map[string]string
	CreatedAt    time.Time
}
