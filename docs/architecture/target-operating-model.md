# Target Operating Model

## Status
Draft

## Why This Exists
The current product already solves the core reverse-tunnel problem, but it still behaves mostly like a "relay + named agent" tool. The target state is a multi-tenant intranet access platform where:

- end users authenticate as users, not as agents;
- the relay chooses the best agent automatically from a healthy pool;
- DNS behavior is explicit and supportable;
- operators can diagnose routing and connectivity from the dashboard;
- rolling upgrades and relay failover become normal operational paths.

This document defines the architecture we want the roadmap to converge toward.

## Product Principles

- Keep the data plane simple, binary, bounded, and observable.
- Move operational complexity into an explicit control plane.
- Treat DNS, routing, and destination policy as first-class product features.
- Prefer compatibility gates and phased rollout over big-bang upgrades.
- Optimize for supportability as much as raw throughput.

## System Domains

### 1. Data Plane
The data plane is responsible for moving user traffic with low overhead and predictable backpressure.

Core responsibilities:

- proxy ingress: HTTP CONNECT and SOCKS5;
- relay-agent transport over versioned binary packets;
- stream lifecycle, windows, buffering, and close codes;
- agent-side dialing and remote DNS resolution;
- per-stream metrics and bounded resource usage.

Properties we want:

- binary framing only;
- numeric stream identifiers;
- adaptive batching and window tuning;
- no unbounded per-stream or per-agent memory growth;
- strong telemetry around dial, resolve, write, and close paths.

### 2. Control Plane
The control plane owns configuration and policy.

Core responsibilities:

- users, roles, and access tokens;
- agent groups and group membership;
- destination profiles and routing policies;
- DNS overrides and future DNS policies;
- deployment orchestration and rollout rules;
- audit logs and operational changes.

Properties we want:

- persistent state store;
- explicit APIs for dashboard and automation;
- compatibility with a future stateless relay fleet.

### 3. Routing Plane
The routing plane decides which agent should serve a connection.

Decision inputs:

- authenticated user or service principal;
- requested destination or destination profile;
- agent group membership;
- agent health and heartbeat freshness;
- current queue depth and active stream load;
- optional routing constraints such as site, tags, or capabilities.

Desired outputs:

- selected agent;
- resolution source used for the dial;
- reason codes for routing decisions;
- observable selection metrics for operators.

### 4. Operations Plane
The operations plane is what makes the platform practical in production.

Core responsibilities:

- connectivity diagnostics;
- SLO tracking and alerting;
- canary and batch deployment rollout;
- rollback triggers;
- relay health and failover readiness;
- incident forensics through logs, metrics, and audit events.

## Identity Model

### Agent Identity
Agents remain machine identities.

- long-lived credentials or certificates;
- bound to a site, tags, and capabilities;
- never reused as end-user credentials;
- can be rotated independently of user access.

### User Identity
Users become separate actors in the system.

- proxy access is granted to users or user groups;
- users target destination profiles or agent groups;
- relay maps the request to an agent automatically;
- future auth providers can include local users, API tokens, and OIDC.

## Destination Model
Destinations should stop being implicit `host:port` strings only.

Target model:

- raw destinations: ad hoc `host:port`;
- destination profiles: named application entries with hostname, port, protocol hints, and notes;
- destination policies: ACL/routing rules and optional DNS override behavior.

This is required for a usable dashboard and for support teams to operate the platform without memorizing infrastructure details.

## DNS Model

The platform must support three explicit resolution sources:

- literal IP: the user requested an IP directly;
- agent DNS: the agent resolved the name from its local environment;
- relay override: the control plane forced a specific IP for a hostname.

Future DNS model:

- hostname exact-match overrides;
- wildcard overrides;
- per-group overrides;
- cache with TTL and negative caching;
- diagnostics showing query result, source, and chosen address.

## Persistence Model

The target persistence split is:

- relational store for users, groups, policies, overrides, and audit events;
- optional ephemeral cache for hot routing and diagnostics data;
- object/filesystem storage only for release artifacts and static assets.

Near term:

- SQLite is acceptable for single-relay installations.

Medium term:

- Postgres becomes the default for HA or multi-relay deployments.

## Availability Model

Target state:

- relays are stateless or near-stateless;
- shared control-plane storage backs all relay instances;
- agents reconnect automatically to any healthy relay;
- load balancer or DNS distributes user traffic across relays;
- sticky behavior is used only where necessary, never as the primary correctness mechanism.

## Supportability Model

Operators should be able to answer these questions directly from the product:

- Which agent served this connection?
- Which IP was dialed?
- Was DNS local, cached, or overridden?
- Why was this agent selected instead of another?
- What failed: auth, ACL, DNS, TCP dial, TLS, or stream transport?
- What changed recently that could explain the incident?

## Upgrade Model

The target upgrade strategy is:

- protocol capability negotiation during registration;
- rolling relay deployment without forcing all agents to update immediately;
- staged agent rollout by canary, batch, and rollback;
- control-plane schema migrations that are forward-compatible.

## SLO Targets

The roadmap should drive the platform toward measurable service objectives:

- relay-to-agent transport overhead stays bounded under high concurrency;
- p95 dial setup remains stable under load;
- relay restarts do not require manual user-side reconfiguration;
- config and override changes are visible in seconds, not minutes;
- operators can diagnose a failed destination without host shell access.

## Migration Principles

- preserve current proxy modes while new user/group routing is introduced;
- keep single-agent workflows working during the transition;
- prefer additive schema/API changes;
- support mixed capability windows whenever protocol or control-plane changes are introduced.
