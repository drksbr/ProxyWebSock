# Phase 1 Specification: Access and Routing Foundation

## Status
Substantially delivered in single-relay mode

## Purpose
Phase 1 is the first major control-plane expansion after the transport refactor. Its goal is to change the product from "pick an agent and proxy through it" into "authenticate as a user and let the relay route through the right agent group."

This phase is foundational. Later work on diagnostics, HA, and enterprise auth depends on it.

## Problem Statement

Today:

- end users authenticate with agent credentials;
- access is effectively pinned to a specific agent;
- there is no first-class concept of group, application profile, or routing policy;
- DNS overrides exist, but they are not yet attached to a broader routing model;
- operators must think in infrastructure terms instead of product terms.

This does not scale well when many agents represent the same logical network or service boundary.

## Goals

- introduce end-user credentials independent from agent credentials;
- introduce agent groups as the primary routing pool;
- allow relay-side automatic agent selection within a group;
- introduce destination profiles for common internal systems;
- persist the new control-plane model outside static YAML alone;
- keep existing single-agent workflows operable during migration.

## Non-Goals

- OIDC and enterprise IdP integration;
- multi-relay HA;
- full audit/event history retention;
- wildcard DNS overrides;
- desktop helper/client delivery.

Those belong to later phases.

## User Stories

- As an operator, I can define a group such as `salvador-hospital-network` and attach many agents to it.
- As an operator, I can define a destination profile such as `AGHUse` pointing to `aghuse.saude.ba.gov.br:443`.
- As an end user, I authenticate with my own proxy credential and access the destination profile without knowing which agent will serve it.
- As an operator, I can see which agent was chosen and why.
- As an operator, I can migrate gradually without breaking existing agent-auth proxy access.

## Control-Plane Entities

### User

Represents a human or service principal allowed to use the proxy.

Suggested fields:

- `id`
- `username`
- `password_hash` or token hash
- `status`
- `role`
- `created_at`
- `updated_at`

### Agent Group

Represents a logical intranet access boundary.

Suggested fields:

- `id`
- `name`
- `slug`
- `description`
- `routing_mode`
- `created_at`
- `updated_at`

### Agent Membership

Associates an agent with a group.

Suggested fields:

- `agent_id`
- `group_id`
- `priority`
- `weight`
- `enabled`
- `created_at`
- `updated_at`

### Destination Profile

Represents a named internal application or destination.

Suggested fields:

- `id`
- `name`
- `slug`
- `host`
- `port`
- `protocol_hint`
- `default_group_id`
- `notes`
- `created_at`
- `updated_at`

### User Access Grant

Defines what a user can access.

Suggested fields:

- `user_id`
- `group_id` and/or `destination_profile_id`
- `access_mode`
- `created_at`
- `updated_at`

## Initial Persistence Strategy

Phase 1 should introduce a storage abstraction with two concrete modes:

- in-memory or YAML-backed compatibility mode for tests and transition;
- SQLite-backed mode for real deployments.

The key requirement is to stop hard-wiring all future control-plane entities into static files only.

## Routing Model

### Request Inputs

- authenticated user identity;
- proxy request target `host:port`;
- optional destination profile selection if explicit profile routing is added;
- available healthy agents in one or more groups.

### Routing Steps

1. Authenticate the user.
2. Resolve which groups or destination profiles the user may access.
3. Determine the effective destination.
4. Build the candidate agent set from the allowed group.
5. Filter out unhealthy or disabled agents.
6. Score remaining agents.
7. Select the highest-ranked agent.
8. Record routing decision metadata.

### Scoring Inputs

Initial scoring should use:

- heartbeat freshness;
- degradation state;
- active stream count;
- control/data queue depth;
- latency/jitter;
- optional static priority or weight.

### Required Output Metadata

Every routed connection should record:

- chosen `group_id`;
- chosen `agent_id`;
- candidate count;
- routing score or reason summary;
- destination hostname and port;
- resolution source and resolved IP when available.

## Backward Compatibility

Phase 1 must preserve the current model during rollout.

Compatibility rules:

- existing agent credential auth for proxy ingress remains available behind a compatibility mode;
- existing YAML agent definitions remain supported;
- a relay can operate with both old and new access models during migration;
- dashboard must clearly distinguish user access entries from raw agent credentials.

## Dashboard Changes

Phase 1 dashboard additions:

- user management section;
- agent groups section;
- group membership editor;
- destination profiles section;
- routing view showing which agents belong to which groups;
- per-connection or per-stream view showing chosen agent and routing reason.

Existing DNS override UX should remain and later attach to destination/group context.

## Proxy/Auth Changes

### HTTP CONNECT

Current behavior:

- username/password identify an agent.

Phase 1 behavior:

- username/password identify a user or service principal;
- relay resolves user access and routes to an agent group automatically.

### SOCKS5

Current behavior:

- username/password identify an agent.

Phase 1 behavior:

- same as HTTP CONNECT: user credentials terminate at the relay;
- relay chooses the target agent.

## Proposed Implementation Slices

### Slice 1: Storage Abstraction

- add interfaces for users, groups, memberships, profiles, and grants;
- add SQLite implementation;
- wire relay startup to load the store.

Current repository status:

- store interface exists;
- in-memory implementation exists;
- relay bootstraps a compatibility legacy group from current agent config;
- SQLite-backed implementation exists and is wired into relay startup;
- dashboard and relay APIs already support CRUD for users, groups, memberships, destination profiles, and access grants.

### Slice 2: User Authentication

- add user credential validation path at proxy ingress;
- keep agent-auth compatibility path behind explicit fallback logic.

Current repository status:

- relay HTTP CONNECT and SOCKS5 now accept relay user credentials;
- if user auth does not match, relay still accepts legacy agent credentials for compatibility;
- disabled users are rejected before routing.
- dashboard can generate signed user-scoped PAC URLs without exposing agent tokens.

### Slice 3: Agent Groups

- allow group membership to be assigned to agents;
- surface group membership in dashboard and status API.

Current repository status:

- dashboard/API CRUD for agent memberships exists;
- the relay uses those memberships to build the candidate agent set for a granted group.

### Slice 4: Routing Engine

- centralize selection logic in a routing service;
- return routing metadata along with selected session.

Current repository status:

- profile grants route by exact `host:port` match and use the profile's default group unless the grant overrides it;
- group-only grants allow direct access within the selected agent ACLs;
- the relay prefers profile-specific grants over generic ones and selects the connected agent with the best current score.
- user PAC generation mirrors those grants: profile-based grants produce scoped PAC rules, while group-only grants fall back to catch-all proxying.
- recent routing events now persist in an in-memory ring buffer and expose structured reason codes in `status.json` and the dashboard.

### Slice 5: Destination Profiles

- add profile CRUD;
- map users or groups to destination profiles.

### Slice 6: Dashboard and APIs

- add CRUD APIs for users, groups, memberships, profiles, and grants;
- add operator views for routing state.

Current repository status:

- CRUD for users, groups, memberships, destination profiles, and access grants is available via dashboard and authenticated relay APIs.
- the dashboard now includes an active diagnostic workflow that can target a connected agent, an agent group with relay-side auto-selection, or a destination profile, and reports remote DNS resolution, TCP dial success, TLS probe metadata, and recent diagnostic history.
- append-only audit events are now persisted for control-plane changes, deployment changes, DNS overrides, and diagnostic runs, giving the dashboard a durable operator timeline alongside the routing/diagnostic ring buffers.
- the dashboard now also exposes a support snapshot with recent failure breakdowns by destination, principal, and agent, plus a shared search/failure filter across audit, routing, and diagnostic timelines.
- the relay now applies an in-memory circuit breaker per group+destination, fed by dial and diagnostic failures/successes, and the dashboard exposes active breaker state with cooldown/last-error visibility.
- the relay now also enforces concurrent stream quotas per user, group, and agent, and the dashboard exposes current usage/saturation in the same support snapshot.

### Slice 7: Migration Controls

- add compatibility flags;
- add docs and operational migration steps.

## Acceptance Criteria

- a relay can authenticate a non-agent user at proxy ingress;
- a user can access a destination profile without specifying an agent ID;
- at least two agents can serve the same group and the relay selects between them;
- status/dashboard expose selected group and agent for active streams;
- SQLite mode persists users, groups, and profiles across restart;
- existing agent-auth mode still works when compatibility mode is enabled;
- tests cover routing selection, fallback, and permission failures.

## Test Strategy

- unit tests for routing score and selection;
- integration tests for proxy auth and group-based routing;
- migration tests ensuring compatibility mode works;
- dashboard/API tests for CRUD flows;
- dashboard/API tests for active diagnostics;
- soak test with multiple agents in the same group and repeated selection under load.

## Rollout Plan

1. Land storage abstraction and schema with no traffic-path changes.
2. Add dashboard/API CRUD for groups and profiles.
3. Add user auth path behind feature flag.
4. Add routing engine and group-based selection behind feature flag.
5. Run internal canary with mixed old/new access modes.
6. Make new access model the default for fresh installs.

Current repository status:

- slices 1 through 6 are materially implemented in single-relay mode;
- rollout controls, compatibility flags, and migration UX are still pending;
- the next roadmap sequence now shifts from Phase 1 feature delivery to Phase 3 transport tuning and extended high-concurrency validation, followed by rolling-upgrade safety.

## Open Questions

- Should destination profiles be required for user routing, or can raw host access coexist permanently?
- Should one user be allowed to target multiple groups directly, or should everything route through named profiles?
- Should compatibility mode stay indefinitely, or be deprecated after a fixed number of releases?
- Do we want static weighted routing in Phase 1, or health-based routing only?

## Out of Phase but Closely Related

- OIDC login and external IdPs;
- RBAC beyond a minimal role model;
- relay HA and shared Postgres deployments;
- wildcard/group-scoped DNS overrides;
- long-term audit log retention.
