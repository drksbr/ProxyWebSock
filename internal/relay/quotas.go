package relay

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const defaultQuotaStatusLimit = 8

type quotaCounter struct {
	Key   string
	Label string
	Count int
}

type quotaUsageSnapshot struct {
	Users  map[string]quotaCounter
	Groups map[string]quotaCounter
	Agents map[string]quotaCounter
}

func (s *relayServer) collectQuotaUsage() quotaUsageSnapshot {
	usage := quotaUsageSnapshot{
		Users:  make(map[string]quotaCounter),
		Groups: make(map[string]quotaCounter),
		Agents: make(map[string]quotaCounter),
	}
	if s == nil {
		return usage
	}
	s.agents.Range(func(_, value any) bool {
		session, ok := value.(*relayAgentSession)
		if !ok || session == nil {
			return true
		}
		agentLabel := session.displayName()
		session.streamsMu.RLock()
		for _, stream := range session.streams {
			if stream == nil {
				continue
			}
			meta := stream.quotaMeta()
			incrementQuotaCounter(usage.Agents, session.id, agentLabel)
			if meta.PrincipalType == string(proxyPrincipalUser) && strings.TrimSpace(meta.PrincipalName) != "" {
				incrementQuotaCounter(usage.Users, meta.PrincipalName, meta.PrincipalName)
			}
			if strings.TrimSpace(meta.GroupID) != "" {
				incrementQuotaCounter(usage.Groups, meta.GroupID, firstNonEmpty(meta.GroupName, meta.GroupID))
			}
		}
		session.streamsMu.RUnlock()
		return true
	})
	return usage
}

func incrementQuotaCounter(counters map[string]quotaCounter, key, label string) {
	key = strings.TrimSpace(key)
	label = strings.TrimSpace(label)
	if key == "" {
		return
	}
	counter := counters[key]
	counter.Key = key
	if counter.Label == "" {
		counter.Label = firstNonEmpty(label, key)
	}
	counter.Count++
	counters[key] = counter
}

func quotaCount(counters map[string]quotaCounter, key string) int {
	counter, ok := counters[strings.TrimSpace(key)]
	if !ok {
		return 0
	}
	return counter.Count
}

func (s *relayServer) filterAgentByQuota(membershipAgentID string, usage quotaUsageSnapshot) bool {
	if s == nil || s.opts == nil || s.opts.agentStreamQuota <= 0 {
		return false
	}
	return quotaCount(usage.Agents, membershipAgentID) >= s.opts.agentStreamQuota
}

func (s *relayServer) enforceStreamQuotas(principal proxyPrincipal, decision routeDecision) error {
	if s == nil || s.opts == nil {
		return nil
	}
	usage := s.collectQuotaUsage()
	if s.opts.userStreamQuota > 0 && principal.Kind == proxyPrincipalUser {
		current := quotaCount(usage.Users, principal.Username)
		if current >= s.opts.userStreamQuota {
			return &routeError{
				httpStatus:  http.StatusTooManyRequests,
				socksReply:  0x01,
				reasonCode:  "user_stream_quota_exceeded",
				message:     fmt.Sprintf("user %q reached the concurrent stream quota (%d)", principal.Username, s.opts.userStreamQuota),
				groupID:     decision.GroupID,
				groupName:   decision.GroupName,
				profileID:   decision.ProfileID,
				profileName: decision.ProfileName,
			}
		}
	}
	if s.opts.groupStreamQuota > 0 && strings.TrimSpace(decision.GroupID) != "" {
		current := quotaCount(usage.Groups, decision.GroupID)
		if current >= s.opts.groupStreamQuota {
			return &routeError{
				httpStatus:     http.StatusTooManyRequests,
				socksReply:     0x01,
				reasonCode:     "group_stream_quota_exceeded",
				message:        fmt.Sprintf("group %q reached the concurrent stream quota (%d)", firstNonEmpty(decision.GroupName, decision.GroupID), s.opts.groupStreamQuota),
				groupID:        decision.GroupID,
				groupName:      decision.GroupName,
				profileID:      decision.ProfileID,
				profileName:    decision.ProfileName,
				candidateCount: decision.CandidateCount,
			}
		}
	}
	if s.opts.agentStreamQuota > 0 && strings.TrimSpace(decision.AgentID) != "" && strings.TrimSpace(decision.GroupID) == "" {
		current := quotaCount(usage.Agents, decision.AgentID)
		if current >= s.opts.agentStreamQuota {
			return &routeError{
				httpStatus: http.StatusTooManyRequests,
				socksReply: 0x01,
				reasonCode: "agent_stream_quota_exceeded",
				message:    fmt.Sprintf("agent %q reached the concurrent stream quota (%d)", firstNonEmpty(decision.AgentName, decision.AgentID), s.opts.agentStreamQuota),
			}
		}
	}
	return nil
}

func quotaCountersForStatus(counters map[string]quotaCounter, limitValue int, limit int) []statusQuotaCounter {
	if len(counters) == 0 {
		return nil
	}
	items := make([]statusQuotaCounter, 0, len(counters))
	for _, counter := range counters {
		items = append(items, statusQuotaCounter{
			Key:       counter.Key,
			Label:     counter.Label,
			Count:     counter.Count,
			Limit:     limitValue,
			Saturated: limitValue > 0 && counter.Count >= limitValue,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}
