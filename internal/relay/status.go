package relay

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/version"
)

type statusPayload struct {
	GeneratedAt         time.Time                  `json:"generatedAt"`
	ProxyAddr           string                     `json:"proxyAddr"`
	SecureAddr          string                     `json:"secureAddr"`
	SocksAddr           string                     `json:"socksAddr"`
	ACMEHosts           []string                   `json:"acmeHosts"`
	DNSOverrides        []statusDNSOverride        `json:"dnsOverrides,omitempty"`
	AgentGroups         []statusAgentGroup         `json:"agentGroups,omitempty"`
	DestinationProfiles []statusDestinationProfile `json:"destinationProfiles,omitempty"`
	Support             statusSupportSnapshot      `json:"support"`
	AuditEvents         []statusAuditEvent         `json:"auditEvents,omitempty"`
	RouteEvents         []statusRouteEvent         `json:"routeEvents,omitempty"`
	DiagnosticEvents    []statusDiagnosticEvent    `json:"diagnosticEvents,omitempty"`
	Downloads           []statusDownload           `json:"downloads,omitempty"`
	UpdateCatalog       []statusUpdateCatalogEntry `json:"updateCatalog,omitempty"`
	Agents              []statusAgent              `json:"agents"`
	Metrics             statusMetrics              `json:"metrics"`
	Resources           resourceSnapshot           `json:"resources"`
	BackendVersion      string                     `json:"backendVersion"`
}

type statusView struct {
	Bootstrap template.JS
}

type statusMetrics struct {
	AgentsConnected int   `json:"agentsConnected"`
	ActiveStreams   int   `json:"activeStreams"`
	BytesUp         int64 `json:"bytesUp"`
	BytesDown       int64 `json:"bytesDown"`
	DialErrors      int64 `json:"dialErrors"`
	AuthFailures    int64 `json:"authFailures"`
	RouteDecisions  int64 `json:"routeDecisions"`
	RouteFailures   int64 `json:"routeFailures"`
}

type statusDownload struct {
	Label    string `json:"label"`
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
	URL      string `json:"url"`
	FileName string `json:"fileName"`
	Version  string `json:"version,omitempty"`
}

type statusDNSOverride struct {
	Host      string    `json:"host"`
	Address   string    `json:"address"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

type statusAgentGroup struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Slug               string    `json:"slug"`
	Description        string    `json:"description,omitempty"`
	RoutingMode        string    `json:"routingMode,omitempty"`
	MemberCount        int       `json:"memberCount,omitempty"`
	EnabledMemberCount int       `json:"enabledMemberCount,omitempty"`
	Legacy             bool      `json:"legacy,omitempty"`
	CreatedAt          time.Time `json:"createdAt,omitempty"`
	UpdatedAt          time.Time `json:"updatedAt,omitempty"`
}

type statusDestinationProfile struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Slug             string    `json:"slug"`
	Host             string    `json:"host"`
	Port             int       `json:"port"`
	ProtocolHint     string    `json:"protocolHint,omitempty"`
	DefaultGroupID   string    `json:"defaultGroupId,omitempty"`
	DefaultGroupName string    `json:"defaultGroupName,omitempty"`
	Notes            string    `json:"notes,omitempty"`
	CreatedAt        time.Time `json:"createdAt,omitempty"`
	UpdatedAt        time.Time `json:"updatedAt,omitempty"`
}

type statusSupportSnapshot struct {
	TotalFailures      int                    `json:"totalFailures"`
	RouteFailures      int                    `json:"routeFailures"`
	DiagnosticFailures int                    `json:"diagnosticFailures"`
	ActiveBreakers     []statusCircuitBreaker `json:"activeBreakers,omitempty"`
	Quotas             statusQuotaSnapshot    `json:"quotas"`
	TopDestinations    []statusSupportBucket  `json:"topDestinations,omitempty"`
	TopPrincipals      []statusSupportBucket  `json:"topPrincipals,omitempty"`
	TopAgents          []statusSupportBucket  `json:"topAgents,omitempty"`
}

type statusSupportBucket struct {
	Key      string    `json:"key"`
	Label    string    `json:"label"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"lastSeen,omitempty"`
	Sources  []string  `json:"sources,omitempty"`
}

type statusCircuitBreaker struct {
	GroupID             string    `json:"groupId,omitempty"`
	GroupName           string    `json:"groupName,omitempty"`
	Target              string    `json:"target"`
	State               string    `json:"state"`
	ConsecutiveFailures int       `json:"consecutiveFailures,omitempty"`
	LastError           string    `json:"lastError,omitempty"`
	LastFailureAt       time.Time `json:"lastFailureAt,omitempty"`
	OpenUntil           time.Time `json:"openUntil,omitempty"`
	ProbeInFlight       bool      `json:"probeInFlight,omitempty"`
}

type statusQuotaSnapshot struct {
	UserStreamLimit  int                  `json:"userStreamLimit,omitempty"`
	GroupStreamLimit int                  `json:"groupStreamLimit,omitempty"`
	AgentStreamLimit int                  `json:"agentStreamLimit,omitempty"`
	Users            []statusQuotaCounter `json:"users,omitempty"`
	Groups           []statusQuotaCounter `json:"groups,omitempty"`
	Agents           []statusQuotaCounter `json:"agents,omitempty"`
}

type statusQuotaCounter struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Count     int    `json:"count"`
	Limit     int    `json:"limit,omitempty"`
	Saturated bool   `json:"saturated,omitempty"`
}

type statusAuditEvent struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	Category     string            `json:"category"`
	Action       string            `json:"action"`
	ActorType    string            `json:"actorType,omitempty"`
	ActorID      string            `json:"actorId,omitempty"`
	ActorName    string            `json:"actorName,omitempty"`
	ResourceType string            `json:"resourceType,omitempty"`
	ResourceID   string            `json:"resourceId,omitempty"`
	ResourceName string            `json:"resourceName,omitempty"`
	Outcome      string            `json:"outcome,omitempty"`
	Message      string            `json:"message,omitempty"`
	RemoteAddr   string            `json:"remoteAddr,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type statusRouteEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Protocol       string    `json:"protocol"`
	Outcome        string    `json:"outcome"`
	ReasonCode     string    `json:"reasonCode,omitempty"`
	Message        string    `json:"message,omitempty"`
	Target         string    `json:"target"`
	PrincipalType  string    `json:"principalType,omitempty"`
	PrincipalName  string    `json:"principalName,omitempty"`
	GroupID        string    `json:"groupId,omitempty"`
	GroupName      string    `json:"groupName,omitempty"`
	ProfileID      string    `json:"profileId,omitempty"`
	ProfileName    string    `json:"profileName,omitempty"`
	AgentID        string    `json:"agentId,omitempty"`
	AgentName      string    `json:"agentName,omitempty"`
	CandidateCount int       `json:"candidateCount,omitempty"`
	SelectedStatus string    `json:"selectedStatus,omitempty"`
}

type statusDiagnosticEvent struct {
	Timestamp       time.Time              `json:"timestamp"`
	Mode            string                 `json:"mode,omitempty"`
	Outcome         string                 `json:"outcome"`
	Host            string                 `json:"host"`
	Port            int                    `json:"port"`
	Target          string                 `json:"target"`
	AgentID         string                 `json:"agentId,omitempty"`
	AgentName       string                 `json:"agentName,omitempty"`
	GroupID         string                 `json:"groupId,omitempty"`
	GroupName       string                 `json:"groupName,omitempty"`
	ProfileID       string                 `json:"profileId,omitempty"`
	ProfileName     string                 `json:"profileName,omitempty"`
	OverrideAddress string                 `json:"overrideAddress,omitempty"`
	ReasonCode      string                 `json:"reasonCode,omitempty"`
	Message         string                 `json:"message,omitempty"`
	SelectedStatus  string                 `json:"selectedStatus,omitempty"`
	CandidateCount  int                    `json:"candidateCount,omitempty"`
	StartedAt       time.Time              `json:"startedAt,omitempty"`
	FinishedAt      time.Time              `json:"finishedAt,omitempty"`
	DurationMillis  int64                  `json:"durationMillis,omitempty"`
	Steps           []statusDiagnosticStep `json:"steps,omitempty"`
}

type statusDiagnosticStep struct {
	Step             string   `json:"step"`
	Success          bool     `json:"success"`
	DurationMillis   uint32   `json:"durationMillis,omitempty"`
	Message          string   `json:"message,omitempty"`
	ResolutionSource string   `json:"resolutionSource,omitempty"`
	Addresses        []string `json:"addresses,omitempty"`
	SelectedAddress  string   `json:"selectedAddress,omitempty"`
	TLSServerName    string   `json:"tlsServerName,omitempty"`
	TLSVersion       string   `json:"tlsVersion,omitempty"`
	TLSCipherSuite   string   `json:"tlsCipherSuite,omitempty"`
	TLSPeerNames     []string `json:"tlsPeerNames,omitempty"`
}

type statusAgent struct {
	ID                       string         `json:"id"`
	Identification           string         `json:"identification"`
	Location                 string         `json:"location"`
	Status                   string         `json:"status"`
	Remote                   string         `json:"remote,omitempty"`
	ConnectedAt              time.Time      `json:"connectedAt,omitempty"`
	LastHeartbeatAt          time.Time      `json:"lastHeartbeatAt,omitempty"`
	LatencyMillis            float64        `json:"latencyMillis,omitempty"`
	JitterMillis             float64        `json:"jitterMillis,omitempty"`
	HeartbeatSendDelayMillis float64        `json:"heartbeatSendDelayMillis,omitempty"`
	HeartbeatSeq             uint64         `json:"heartbeatSeq,omitempty"`
	HeartbeatFailures        int            `json:"heartbeatFailures,omitempty"`
	HeartbeatPending         int            `json:"heartbeatPending,omitempty"`
	ErrorCount               int64          `json:"errorCount,omitempty"`
	LastError                string         `json:"lastError,omitempty"`
	LastErrorAt              time.Time      `json:"lastErrorAt,omitempty"`
	ACL                      []string       `json:"acl,omitempty"`
	RelayControlQueueDepth   int            `json:"relayControlQueueDepth,omitempty"`
	RelayDataQueueDepth      int            `json:"relayDataQueueDepth,omitempty"`
	AgentControlQueueDepth   int            `json:"agentControlQueueDepth,omitempty"`
	AgentDataQueueDepth      int            `json:"agentDataQueueDepth,omitempty"`
	AgentCPUPercent          *float64       `json:"agentCpuPercent,omitempty"`
	AgentRSSBytes            *uint64        `json:"agentRssBytes,omitempty"`
	AgentGoroutines          *int           `json:"agentGoroutines,omitempty"`
	GOOS                     string         `json:"goos,omitempty"`
	GOARCH                   string         `json:"goarch,omitempty"`
	CurrentVersion           string         `json:"currentVersion,omitempty"`
	DesiredVersion           string         `json:"desiredVersion,omitempty"`
	PinnedVersion            string         `json:"pinnedVersion,omitempty"`
	UpdateTrack              string         `json:"updateTrack,omitempty"`
	LastUpdateCheckAt        time.Time      `json:"lastUpdateCheckAt,omitempty"`
	Streams                  []statusStream `json:"streams"`
	AutoConfig               string         `json:"autoConfig,omitempty"`
}

type statusStream struct {
	StreamID            string    `json:"streamId"`
	Target              string    `json:"target"`
	ResolvedTarget      string    `json:"resolvedTarget,omitempty"`
	ResolutionSource    string    `json:"resolutionSource,omitempty"`
	PrincipalType       string    `json:"principalType,omitempty"`
	PrincipalName       string    `json:"principalName,omitempty"`
	GroupID             string    `json:"groupId,omitempty"`
	GroupName           string    `json:"groupName,omitempty"`
	ProfileID           string    `json:"profileId,omitempty"`
	ProfileName         string    `json:"profileName,omitempty"`
	RouteReasonCode     string    `json:"routeReasonCode,omitempty"`
	RouteReason         string    `json:"routeReason,omitempty"`
	Protocol            string    `json:"protocol"`
	CreatedAt           time.Time `json:"createdAt"`
	BytesUp             int64     `json:"bytesUp"`
	BytesDown           int64     `json:"bytesDown"`
	PendingClientBytes  int64     `json:"pendingClientBytes,omitempty"`
	PendingClientChunks int       `json:"pendingClientChunks,omitempty"`
	ClientBacklogLimit  int       `json:"clientBacklogLimit,omitempty"`
}

func (s *relayServer) collectStatus(r *http.Request) statusPayload {
	agentGroups, destinationProfiles := s.collectControlPlaneStatus()
	agentsByID := make(map[string]statusAgent, len(s.agentDirectory))
	for id, record := range s.agentDirectory {
		agent := statusAgent{
			ID:             id,
			Identification: record.Identification,
			Location:       record.Location,
			Status:         "disconnected",
		}
		if len(record.ACLPatterns) > 0 {
			agent.ACL = append(agent.ACL, record.ACLPatterns...)
		}
		if r != nil {
			agent.AutoConfig = s.autoConfigURL(r, id)
		}
		if s.updateManager != nil {
			deployment := s.updateManager.deploymentStatus(id, "", "")
			agent.GOOS = deployment.GOOS
			agent.GOARCH = deployment.GOARCH
			agent.CurrentVersion = deployment.CurrentVersion
			agent.DesiredVersion = deployment.DesiredVersion
			agent.PinnedVersion = deployment.PinnedVersion
			agent.UpdateTrack = deployment.Track
			agent.LastUpdateCheckAt = deployment.LastCheckAt
		}
		agentsByID[id] = agent
	}

	s.agents.Range(func(_, value any) bool {
		if session, ok := value.(*relayAgentSession); ok {
			snapshot := session.snapshot()
			base, exists := agentsByID[snapshot.ID]
			if exists && len(snapshot.ACL) == 0 {
				snapshot.ACL = base.ACL
			}
			if snapshot.AutoConfig == "" && r != nil {
				snapshot.AutoConfig = s.autoConfigURL(r, snapshot.ID)
			}
			if s.updateManager != nil {
				deployment := s.updateManager.deploymentStatus(snapshot.ID, snapshot.GOOS, snapshot.GOARCH)
				if snapshot.CurrentVersion == "" {
					snapshot.CurrentVersion = deployment.CurrentVersion
				}
				if snapshot.GOOS == "" {
					snapshot.GOOS = deployment.GOOS
				}
				if snapshot.GOARCH == "" {
					snapshot.GOARCH = deployment.GOARCH
				}
				snapshot.DesiredVersion = deployment.DesiredVersion
				snapshot.PinnedVersion = deployment.PinnedVersion
				snapshot.UpdateTrack = deployment.Track
				snapshot.LastUpdateCheckAt = deployment.LastCheckAt
			}
			agentsByID[snapshot.ID] = snapshot
		}
		return true
	})

	agents := make([]statusAgent, 0, len(agentsByID))
	totalStreams := 0
	connectedCount := 0
	for id, agent := range agentsByID {
		if agent.ID == "" {
			agent.ID = id
		}
		if agent.AutoConfig == "" && r != nil {
			agent.AutoConfig = s.autoConfigURL(r, agent.ID)
		}
		if agent.Status == "" {
			agent.Status = "connected"
		}
		if agent.Status != "disconnected" {
			connectedCount++
			totalStreams += len(agent.Streams)
		}
		agents = append(agents, agent)
	}

	sort.Slice(agents, func(i, j int) bool {
		return agents[i].ID < agents[j].ID
	})

	resources := resourceSnapshot{}
	if s.resources != nil {
		const historyLimit = 7 * 24 * 60
		resources = s.resources.snapshot(historyLimit)
	}

	routeEvents := func() []statusRouteEvent {
		if s.routeHistory == nil {
			return nil
		}
		return s.routeHistory.list()
	}()
	diagnosticEvents := func() []statusDiagnosticEvent {
		if s.diagnosticRuns == nil {
			return nil
		}
		return s.diagnosticRuns.list()
	}()

	activeBreakers := s.collectCircuitBreakerStatus()
	quotaStatus := s.collectQuotaStatus()

	return statusPayload{
		GeneratedAt: time.Now(),
		ProxyAddr:   s.opts.proxyListen,
		SecureAddr:  s.opts.secureListen,
		SocksAddr:   s.opts.socksListen,
		ACMEHosts:   append([]string(nil), s.opts.acmeHosts...),
		DNSOverrides: func() []statusDNSOverride {
			if s.dnsOverrides == nil {
				return nil
			}
			entries := s.dnsOverrides.List()
			if len(entries) == 0 {
				return nil
			}
			result := make([]statusDNSOverride, 0, len(entries))
			for _, entry := range entries {
				result = append(result, statusDNSOverride{
					Host:      entry.Host,
					Address:   entry.Address,
					UpdatedAt: entry.UpdatedAt,
				})
			}
			return result
		}(),
		AgentGroups:         agentGroups,
		DestinationProfiles: destinationProfiles,
		Support:             buildSupportSnapshot(routeEvents, diagnosticEvents, activeBreakers, quotaStatus),
		AuditEvents:         s.collectAuditStatus(),
		RouteEvents:         routeEvents,
		DiagnosticEvents:    diagnosticEvents,
		Downloads:           s.availableDashboardDownloads(r),
		UpdateCatalog: func() []statusUpdateCatalogEntry {
			if s.updateManager == nil {
				return nil
			}
			return s.updateManager.catalogEntries()
		}(),
		Agents: agents,
		Metrics: statusMetrics{
			AgentsConnected: connectedCount,
			ActiveStreams:   totalStreams,
			BytesUp:         s.stats.bytesUp.Load(),
			BytesDown:       s.stats.bytesDown.Load(),
			DialErrors:      s.stats.dialErrors.Load(),
			AuthFailures:    s.stats.authFailures.Load(),
			RouteDecisions:  s.stats.routeDecisions.Load(),
			RouteFailures:   s.stats.routeFailures.Load(),
		},
		Resources:      resources,
		BackendVersion: version.Version,
	}
}

func (s *relayServer) collectControlPlaneStatus() ([]statusAgentGroup, []statusDestinationProfile) {
	if s.control == nil {
		return nil, nil
	}
	ctx := context.Background()
	groups, err := s.listStatusAgentGroups(ctx)
	if err != nil {
		s.logger.Warn("collect agent groups failed", "error", err)
	}
	profiles, err := s.listStatusDestinationProfiles(ctx)
	if err != nil {
		s.logger.Warn("collect destination profiles failed", "error", err)
	}
	return groups, profiles
}

func (s *relayServer) collectAuditStatus() []statusAuditEvent {
	if s.control == nil {
		return nil
	}
	events, err := s.control.ListAuditEvents(context.Background(), defaultAuditEventLimit)
	if err != nil {
		s.logger.Warn("collect audit events failed", "error", err)
		return nil
	}
	if len(events) == 0 {
		return nil
	}
	result := make([]statusAuditEvent, 0, len(events))
	for _, event := range events {
		result = append(result, statusAuditEvent{
			ID:           event.ID,
			Timestamp:    event.CreatedAt,
			Category:     event.Category,
			Action:       event.Action,
			ActorType:    event.ActorType,
			ActorID:      event.ActorID,
			ActorName:    event.ActorName,
			ResourceType: event.ResourceType,
			ResourceID:   event.ResourceID,
			ResourceName: event.ResourceName,
			Outcome:      event.Outcome,
			Message:      event.Message,
			RemoteAddr:   event.RemoteAddr,
			Metadata:     event.Metadata,
		})
	}
	return result
}

func (s *relayServer) collectCircuitBreakerStatus() []statusCircuitBreaker {
	if s == nil || s.breakers == nil {
		return nil
	}
	snapshots := s.breakers.ActiveSnapshots(defaultCircuitBreakerStatusLimit)
	if len(snapshots) == 0 {
		return nil
	}
	result := make([]statusCircuitBreaker, 0, len(snapshots))
	for _, snapshot := range snapshots {
		result = append(result, statusCircuitBreaker{
			GroupID:             snapshot.GroupID,
			GroupName:           snapshot.GroupName,
			Target:              snapshot.Target,
			State:               snapshot.State,
			ConsecutiveFailures: snapshot.ConsecutiveFailures,
			LastError:           snapshot.LastError,
			LastFailureAt:       snapshot.LastFailureAt,
			OpenUntil:           snapshot.OpenUntil,
			ProbeInFlight:       snapshot.ProbeInFlight,
		})
	}
	return result
}

func (s *relayServer) collectQuotaStatus() statusQuotaSnapshot {
	snapshot := statusQuotaSnapshot{}
	if s == nil || s.opts == nil {
		return snapshot
	}
	snapshot.UserStreamLimit = s.opts.userStreamQuota
	snapshot.GroupStreamLimit = s.opts.groupStreamQuota
	snapshot.AgentStreamLimit = s.opts.agentStreamQuota
	usage := s.collectQuotaUsage()
	snapshot.Users = quotaCountersForStatus(usage.Users, s.opts.userStreamQuota, defaultQuotaStatusLimit)
	snapshot.Groups = quotaCountersForStatus(usage.Groups, s.opts.groupStreamQuota, defaultQuotaStatusLimit)
	snapshot.Agents = quotaCountersForStatus(usage.Agents, s.opts.agentStreamQuota, defaultQuotaStatusLimit)
	return snapshot
}

func (s *relayServer) autoConfigURL(r *http.Request, agentID string) string {
	record, ok := s.agentDirectory[agentID]
	if !ok {
		return ""
	}
	if s.opts.socksListen == "" {
		return ""
	}
	scheme := "https"
	if r != nil && r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s://%s/autoconfig/%s.pac?token=%s", scheme, host, url.PathEscape(agentID), url.QueryEscape(record.Password))
}

func generatePAC(agentID, token, socksHost, socksPort, proxyHost, proxyPort string) string {
	socksEntry := fmt.Sprintf("SOCKS5 %s:%s@%s:%s", agentID, token, socksHost, socksPort)
	proxyEntry := fmt.Sprintf("PROXY %s:%s", proxyHost, proxyPort)
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host)) {
    return "DIRECT";
  }
  return "%s; %s; DIRECT";
}
`, socksEntry, proxyEntry)
}

func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		if idx := strings.LastIndex(hostport, "]"); idx != -1 {
			return hostport[:idx+1]
		}
	}
	if strings.Contains(hostport, ":") {
		host, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return host
		}
	}
	return hostport
}

func portFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}
