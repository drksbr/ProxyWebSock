package main

import "github.com/prometheus/client_golang/prometheus"

type relayMetrics struct {
	agentsConnected prometheus.Gauge
	activeStreams   prometheus.Gauge
	bytesUpstream   prometheus.Counter
	bytesDownstream prometheus.Counter
	dialErrors      prometheus.Counter
	authFailures    prometheus.Counter
}

func newRelayMetrics() *relayMetrics {
	m := &relayMetrics{
		agentsConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "intratun_agents_connected",
			Help: "Number of agents currently connected",
		}),
		activeStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "intratun_active_streams",
			Help: "Number of active HTTP CONNECT tunnels",
		}),
		bytesUpstream: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "intratun_bytes_upstream_total",
			Help: "Total bytes sent from clients to agents",
		}),
		bytesDownstream: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "intratun_bytes_downstream_total",
			Help: "Total bytes sent from agents to clients",
		}),
		dialErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "intratun_dial_errors_total",
			Help: "Number of dial failures on agent instructions",
		}),
		authFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "intratun_auth_failures_total",
			Help: "Number of failed authentication attempts",
		}),
	}

	prometheus.MustRegister(
		m.agentsConnected,
		m.activeStreams,
		m.bytesUpstream,
		m.bytesDownstream,
		m.dialErrors,
		m.authFailures,
	)

	return m
}
