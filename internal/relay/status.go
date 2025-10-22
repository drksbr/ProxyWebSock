package relay

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type statusPayload struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	ProxyAddr   string           `json:"proxyAddr"`
	SecureAddr  string           `json:"secureAddr"`
	SocksAddr   string           `json:"socksAddr"`
	ACMEHosts   []string         `json:"acmeHosts"`
	Agents      []statusAgent    `json:"agents"`
	Metrics     statusMetrics    `json:"metrics"`
	Resources   resourceSnapshot `json:"resources"`
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
	AgentCPUPercent          float64        `json:"agentCpuPercent,omitempty"`
	AgentRSSBytes            uint64         `json:"agentRssBytes,omitempty"`
	AgentGoroutines          int            `json:"agentGoroutines,omitempty"`
	Streams                  []statusStream `json:"streams"`
	AutoConfig               string         `json:"autoConfig,omitempty"`
}

type statusStream struct {
	StreamID  string    `json:"streamId"`
	Target    string    `json:"target"`
	Protocol  string    `json:"protocol"`
	CreatedAt time.Time `json:"createdAt"`
	BytesUp   int64     `json:"bytesUp"`
	BytesDown int64     `json:"bytesDown"`
}

func (s *relayServer) collectStatus(r *http.Request) statusPayload {
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

	return statusPayload{
		GeneratedAt: time.Now(),
		ProxyAddr:   s.opts.proxyListen,
		SecureAddr:  s.opts.secureListen,
		SocksAddr:   s.opts.socksListen,
		ACMEHosts:   append([]string(nil), s.opts.acmeHosts...),
		Agents:      agents,
		Metrics: statusMetrics{
			AgentsConnected: connectedCount,
			ActiveStreams:   totalStreams,
			BytesUp:         s.stats.bytesUp.Load(),
			BytesDown:       s.stats.bytesDown.Load(),
			DialErrors:      s.stats.dialErrors.Load(),
			AuthFailures:    s.stats.authFailures.Load(),
		},
		Resources: resources,
	}
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
