package relay

import (
	"sort"
	"strings"
	"time"
)

const supportBreakdownLimit = 8

type supportBucketAccumulator struct {
	key      string
	label    string
	count    int
	lastSeen time.Time
	sources  map[string]struct{}
}

func buildSupportSnapshot(routeEvents []statusRouteEvent, diagnosticEvents []statusDiagnosticEvent, activeBreakers []statusCircuitBreaker, quotas statusQuotaSnapshot) statusSupportSnapshot {
	snapshot := statusSupportSnapshot{}
	destinations := make(map[string]*supportBucketAccumulator)
	principals := make(map[string]*supportBucketAccumulator)
	agents := make(map[string]*supportBucketAccumulator)

	for _, event := range routeEvents {
		if !strings.EqualFold(event.Outcome, "failed") {
			continue
		}
		snapshot.RouteFailures++
		addSupportBucket(destinations, event.Target, event.Target, "route", event.Timestamp)
		principalLabel := firstNonEmpty(strings.TrimSpace(event.PrincipalName), strings.TrimSpace(event.PrincipalType))
		addSupportBucket(principals, principalLabel, principalLabel, "route", event.Timestamp)
		agentLabel := firstNonEmpty(strings.TrimSpace(event.AgentName), strings.TrimSpace(event.AgentID))
		addSupportBucket(agents, agentLabel, agentLabel, "route", event.Timestamp)
	}

	for _, event := range diagnosticEvents {
		if !strings.EqualFold(event.Outcome, "failed") {
			continue
		}
		snapshot.DiagnosticFailures++
		addSupportBucket(destinations, event.Target, event.Target, "diagnostic", event.Timestamp)
		agentLabel := firstNonEmpty(strings.TrimSpace(event.AgentName), strings.TrimSpace(event.AgentID))
		addSupportBucket(agents, agentLabel, agentLabel, "diagnostic", event.Timestamp)
	}

	snapshot.TotalFailures = snapshot.RouteFailures + snapshot.DiagnosticFailures
	snapshot.ActiveBreakers = append(snapshot.ActiveBreakers, activeBreakers...)
	snapshot.Quotas = quotas
	snapshot.TopDestinations = finalizeSupportBuckets(destinations, supportBreakdownLimit)
	snapshot.TopPrincipals = finalizeSupportBuckets(principals, supportBreakdownLimit)
	snapshot.TopAgents = finalizeSupportBuckets(agents, supportBreakdownLimit)
	return snapshot
}

func addSupportBucket(buckets map[string]*supportBucketAccumulator, key, label, source string, seenAt time.Time) {
	key = strings.TrimSpace(key)
	label = strings.TrimSpace(label)
	source = strings.TrimSpace(source)
	if key == "" || label == "" || key == "-" || label == "-" {
		return
	}
	bucket, ok := buckets[key]
	if !ok {
		bucket = &supportBucketAccumulator{
			key:     key,
			label:   label,
			sources: make(map[string]struct{}, 2),
		}
		buckets[key] = bucket
	}
	bucket.count++
	if seenAt.After(bucket.lastSeen) {
		bucket.lastSeen = seenAt
	}
	if source != "" {
		bucket.sources[source] = struct{}{}
	}
}

func finalizeSupportBuckets(buckets map[string]*supportBucketAccumulator, limit int) []statusSupportBucket {
	if len(buckets) == 0 {
		return nil
	}
	items := make([]statusSupportBucket, 0, len(buckets))
	for _, bucket := range buckets {
		sources := make([]string, 0, len(bucket.sources))
		for source := range bucket.sources {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		items = append(items, statusSupportBucket{
			Key:      bucket.key,
			Label:    bucket.label,
			Count:    bucket.count,
			LastSeen: bucket.lastSeen,
			Sources:  sources,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			if items[i].LastSeen.Equal(items[j].LastSeen) {
				return items[i].Label < items[j].Label
			}
			return items[i].LastSeen.After(items[j].LastSeen)
		}
		return items[i].Count > items[j].Count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}
