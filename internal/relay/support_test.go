package relay

import (
	"testing"
	"time"
)

func TestBuildSupportSnapshot(t *testing.T) {
	now := time.Now().UTC()
	snapshot := buildSupportSnapshot(
		[]statusRouteEvent{
			{
				Timestamp:     now.Add(-3 * time.Minute),
				Outcome:       "failed",
				Target:        "aghuse.saude.ba.gov.br:443",
				PrincipalName: "operador",
				AgentID:       "agente01",
				AgentName:     "Hospital A",
			},
			{
				Timestamp: now.Add(-2 * time.Minute),
				Outcome:   "selected",
				Target:    "ok.internal:443",
			},
			{
				Timestamp:     now.Add(-time.Minute),
				Outcome:       "failed",
				Target:        "aghuse.saude.ba.gov.br:443",
				PrincipalName: "operador",
				AgentID:       "agente02",
				AgentName:     "Hospital B",
			},
		},
		[]statusDiagnosticEvent{
			{
				Timestamp: now,
				Outcome:   "failed",
				Target:    "sis.internal:8443",
				AgentID:   "agente01",
				AgentName: "Hospital A",
			},
		},
		[]statusCircuitBreaker{
			{
				GroupID:   "group-1",
				GroupName: "Hospital A",
				Target:    "aghuse.saude.ba.gov.br:443",
				State:     "open",
			},
		},
		statusQuotaSnapshot{
			UserStreamLimit:  10,
			GroupStreamLimit: 20,
			AgentStreamLimit: 5,
			Users: []statusQuotaCounter{
				{Key: "operador", Label: "operador", Count: 2, Limit: 10},
			},
		},
	)

	if snapshot.TotalFailures != 3 {
		t.Fatalf("unexpected total failures: %d", snapshot.TotalFailures)
	}
	if snapshot.RouteFailures != 2 || snapshot.DiagnosticFailures != 1 {
		t.Fatalf("unexpected failure counters: %+v", snapshot)
	}
	if len(snapshot.TopDestinations) != 2 || snapshot.TopDestinations[0].Label != "aghuse.saude.ba.gov.br:443" || snapshot.TopDestinations[0].Count != 2 {
		t.Fatalf("unexpected destination breakdown: %+v", snapshot.TopDestinations)
	}
	if len(snapshot.TopPrincipals) != 1 || snapshot.TopPrincipals[0].Label != "operador" || snapshot.TopPrincipals[0].Count != 2 {
		t.Fatalf("unexpected principal breakdown: %+v", snapshot.TopPrincipals)
	}
	if len(snapshot.TopAgents) != 2 || snapshot.TopAgents[0].Label != "Hospital A" || snapshot.TopAgents[0].Count != 2 {
		t.Fatalf("unexpected agent breakdown: %+v", snapshot.TopAgents)
	}
	if len(snapshot.TopAgents[0].Sources) != 2 {
		t.Fatalf("unexpected agent sources: %+v", snapshot.TopAgents[0])
	}
	if len(snapshot.ActiveBreakers) != 1 || snapshot.ActiveBreakers[0].State != "open" {
		t.Fatalf("unexpected active breakers: %+v", snapshot.ActiveBreakers)
	}
	if snapshot.Quotas.UserStreamLimit != 10 || len(snapshot.Quotas.Users) != 1 {
		t.Fatalf("unexpected quotas snapshot: %+v", snapshot.Quotas)
	}
}
