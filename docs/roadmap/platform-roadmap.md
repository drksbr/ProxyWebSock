# Platform Roadmap

## Status
Active

## Scope
This roadmap covers the next major improvements needed to make ProxyWebSock more performant, stable, scalable, and practical for end users and operators.

It intentionally spans both product and platform work:

- transport and performance;
- routing and multi-agent selection;
- user-facing access model;
- diagnostics and supportability;
- deployment and availability;
- control-plane persistence and multi-relay readiness.

## Planning Assumptions

- The recently introduced binary packet transport and dashboard DNS overrides are treated as Phase 0 foundations.
- Work should be delivered in compatibility-preserving slices wherever possible.
- "Finished" means code, tests, observability, docs, and rollback strategy exist.

## Current Repository State (2026-03-26)

- Phase 0 foundations are materially in place: binary relay-agent transport, numeric stream IDs, bounded stream backpressure, remote DNS resolution, and dashboard-managed exact DNS overrides.
- Phase 1 is substantially delivered for single-relay deployments: relay users, agent groups, memberships, destination profiles, access grants, SQLite-backed control-plane persistence, group-based routing, and user-scoped PAC generation are already live.
- Phase 2 is in progress: routing reason codes, active diagnostics (`resolve`, `dial`, `tls`), append-only persisted audit events, dashboard-wide filtering, and recent failure breakdowns by destination, principal, and agent are now available.
- Phase 3 has started: destination circuit breakers, concurrent stream quotas, agent-side DNS cache hardening, and repeatable soak/chaos harnesses for DNS instability plus explicit agent/relay restarts now exist in the traffic path and validation suite.
- The largest remaining gaps are now in transport hardening, broader high-concurrency/perf validation, version negotiation, and multi-relay correctness.

## Next Execution Sequence

1. Phase 3 continuation: tune transport adaptively with better frame/window metrics and small-packet batching.
2. Phase 3 validation continuation: widen the soak/chaos harness from restart recovery into longer high-concurrency runs with reconnect storms and throughput sampling.
3. Phase 4 groundwork: introduce protocol capability negotiation so relay and agents can be upgraded without lockstep rollout.
4. Phase 5 continuation: keep SQLite as the single-node baseline while isolating relay state that must move to a shared store for multi-relay support.
5. Phase 6 onboarding improvements: convert the richer supportability model into simpler end-user and operator setup flows.

## Phase 0: Foundations

### Status
Mostly delivered

### Delivered or underway

- binary relay-agent packet protocol;
- numeric stream IDs;
- bounded backpressure per stream;
- agent-side DNS resolution with relay-provided hostname override;
- dashboard management for exact hostname-to-IP overrides.

### Exit criteria

- soak tests cover the new transport;
- close codes and routing metadata are visible in metrics/status;
- rolling upgrade strategy is documented.

## Phase 1: Access and Routing Foundation

### Status
Substantially delivered in single-relay mode

### Objective
Decouple end-user access from agent identity and make routing agent-aware instead of user-pinned.

### Epics

1. User identity and proxy credentials
2. Agent groups and group membership
3. Routing engine and selection policy
4. Destination profiles
5. Control-plane persistence for the new entities
6. Dashboard flows for group-based access

### Deliverables

- separate user credentials from agent credentials;
- group-based agent pools;
- relay selection of the best healthy agent in a group;
- named destination profiles instead of raw host memorization only;
- audit trail for routing and access changes.

### Current implementation note

The repository now contains the full single-relay foundation slice:

- control-plane domain models and CRUD APIs;
- in-memory and SQLite store implementations;
- relay bootstrap of a compatibility `legacy-all-agents` group from the current static agent config;
- relay-side user authentication with legacy agent-auth fallback;
- group-based routing and destination profile resolution;
- dashboard flows for users, groups, memberships, destination profiles, access grants, and user-scoped PAC generation.

### Success metrics

- at least one user can access a destination without knowing a specific agent ID;
- p95 routing decision time remains negligible compared with dial time;
- operator can explain which group and agent served a request.

### Dependencies

- persistent config store abstraction;
- new control-plane APIs;
- migration path from existing agent-based auth.

### Risks

- accidental privilege escalation if auth and routing are introduced together without clear policy checks;
- configuration drift during migration from YAML-only flows.

## Phase 2: Diagnostics and Supportability

### Status
In progress

### Objective
Make incidents explainable from the dashboard and APIs.

### Epics

1. Connectivity diagnostics runner
2. DNS explainability and dial traces
3. Routing reason codes
4. Audit/event history
5. Operator-focused stream/error views

### Deliverables

- "resolve host", "dial TCP", and "probe TLS" diagnostics;
- visibility into which DNS source and IP were used;
- timeline of config and rollout changes;
- searchable failure breakdown by destination, agent, and user.

### Current implementation note

The repository currently includes:

- active diagnostics runnable by explicit agent, auto-selected group, or destination profile;
- routing reason codes and recent route history in `status.json` and the dashboard;
- recent in-memory diagnostic history for operator feedback;
- append-only persisted audit events for control-plane mutations, DNS overrides, deployment changes, and diagnostic executions.

### Success metrics

- first-line support can diagnose common reachability failures without logging into relay or agent hosts;
- p95 time-to-identify root cause drops materially.

### Dependencies

- Phase 1 routing metadata;
- event storage or at least append-only audit persistence.

## Phase 3: Performance and Resilience

### Objective
Tune the transport and routing path for sustained high concurrency.

### Status
Started

### Epics

1. Adaptive frame/window tuning
2. Small-packet coalescing and batching
3. DNS cache improvements with TTL and negative cache
4. Multi-address dial retry policy
5. Circuit breakers by destination/group
6. Rate limiting and quotas
7. Load and chaos test harness

### Deliverables

- adaptive transport settings;
- retry-on-next-address for DNS answers;
- fresh/stale/negative DNS cache behavior on the agent;
- circuit breaker state reflected in diagnostics;
- explicit quotas for user, group, and agent;
- repeatable soak and chaos tests.

### Current implementation note

Phase 3 now includes:

- destination circuit breakers by `group + destination`;
- concurrent stream quotas for relay user, group, and connected agent;
- agent-side DNS cache hardening with configurable fresh TTL, negative TTL, stale-answer reuse during refresh, and address reordering based on dial success/failure.
- repeatable soak/chaos tests for agent-side DNS instability, relay routing during agent reconnect storms, explicit agent restarts, and relay restarts with captured route/failure metrics, runnable through `make soak`.

### Success metrics

- stable memory growth under sustained load;
- lower syscall/message overhead for small transfers;
- fewer user-visible failures during transient intranet DNS or target outages.

### Dependencies

- transport metrics with enough detail to tune safely;
- diagnostic event model from Phase 2.

## Phase 4: Deployments and Safe Evolution

### Objective
Make upgrades boring.

### Epics

1. Protocol capability negotiation
2. Relay/agent compatibility matrix
3. Canary and batch rollout engine
4. Automatic rollback triggers
5. Version-aware dashboard controls

### Deliverables

- mixed-version relay/agent support window;
- canary rollout policies;
- rollback on heartbeat degradation or error spikes;
- deployment events and health gates shown in the dashboard.

### Success metrics

- relay upgrades no longer require synchronized agent upgrades;
- failed rollout can be stopped and reversed without manual host intervention.

### Dependencies

- richer deployment metadata;
- routing and health metrics from prior phases.

## Phase 5: Control Plane Persistence and HA

### Objective
Move from single-relay operational simplicity toward multi-relay correctness.

### Status
Started / SQLite single-node mode delivered

### Epics

1. Storage abstraction and relational schema
2. SQLite single-node mode
3. Postgres multi-node mode
4. Shared config/event store
5. Relay statelessness cleanup
6. Multi-relay registration and failover behavior

### Deliverables

- persistent control-plane store;
- relay instances reading the same config and overrides;
- agent reconnect strategy validated across multiple relays;
- HA runbooks and deployment examples.

### Success metrics

- relay replacement or restart does not imply config loss;
- multiple relays can serve the same tenant safely.

### Dependencies

- Phase 1 entities fully modeled;
- audit/event model stable enough to persist.

## Phase 6: End-User Experience and Enterprise Access

### Objective
Make the platform easier to consume without deep proxy expertise.

### Epics

1. Access profiles for common internal systems
2. One-click client setup flows
3. PAC/profile generation by group or application
4. Local desktop helper or lightweight client
5. OIDC and external auth providers
6. RBAC in the dashboard

### Deliverables

- named application access entries;
- simplified onboarding flow for browsers and CLI users;
- identity provider integration;
- operator/admin role separation.

### Success metrics

- fewer manual proxy configuration mistakes;
- less dependence on sharing raw hostnames and ports;
- lower operational friction for enterprise rollout.

### Dependencies

- Phase 1 user/group model;
- stable control-plane persistence.

## Phase 7: Large-Scale Operations

### Objective
Prepare the system for high-cardinality workloads and formal operations.

### Epics

1. Long-term analytics store
2. Capacity planning dashboards
3. Per-tenant quotas and billing hooks
4. Multi-region relay strategy
5. Disaster recovery and backup procedures

### Deliverables

- long-term connection and error analytics;
- capacity guidance per relay and per agent group;
- backup/restore validation for control-plane state.

### Success metrics

- capacity limits are visible before incidents happen;
- recovery procedures are tested, not theoretical.

## Cross-Cutting Workstreams

These should run across all phases:

- observability and SLO instrumentation;
- docs and runbooks;
- backward compatibility gates;
- security review for auth, RBAC, and auditing;
- load, race, and failure testing.

## Execution Order

Recommended order:

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5
6. Phase 6
7. Phase 7

The key reason is that diagnostics and routing clarity should exist before aggressive scaling or HA work, otherwise the product becomes harder to operate as it grows.

## Immediate Next Step

Start with the specification in `docs/specs/phase-1-access-routing.md`.

That phase unlocks the product model required for nearly every later improvement:

- user access independent from agents;
- routing logic instead of manual agent selection;
- persistent control-plane entities that future HA work can build on.
