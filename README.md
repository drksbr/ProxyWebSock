# ProxyWebSock

ProxyWebSock lets you surface private intranet applications to the public internet without poking inbound firewall holes. It builds a reverse tunnel over WebSockets between a cloud‑facing **relay** and one or more inside-the-network **agents**, then exposes both HTTP CONNECT and SOCKS5 proxies for browsers and tooling.

---

![Proxy dashboard overview](https://github.com/drksbr/ProxyWebSock/raw/main/screenshot1.png)
![Proxy metrics chart](https://github.com/drksbr/ProxyWebSock/raw/main/screenshot2.png)

---

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [Getting Started](#getting-started)
- [Command Reference](#command-reference)
- [Dashboard & Monitoring](#dashboard--monitoring)
- [Advanced Topics](#advanced-topics)
- [Roadmap Ideas](#roadmap-ideas)
- [Support](#support)

---

## Architecture

```text
Browser ──────┐
CLI tools ────┼─HTTP CONNECT / SOCKS5────┐
              │                          │
              │                      ┌───▼─────────────────────────┐
              │                      │ Relay (public)              │
              │                      │ - HTTPS + ACME              │
              │                      │ - WebSocket /tunnel         │
              │                      │ - HTTP CONNECT proxy        │
              │                      │ - SOCKS5 proxy              │
              │                      │ - Dashboard & metrics       │
              │                      └───▲──────────────┬──────────┘
              │                          │              │
              └──────────────────────────┼──────────────┘
                                         │
                               WebSocket tunnel (WSS)
                                         │
                                   ┌─────▼───────┐
                                   │ Agent(s)    │
                                   │ - outbound only HTTPS/WSS
                                   │ - TCP dial into intranet
                                   └─────────────┘
```

_The agent maintains a persistent WSS tunnel, multiplexing traffic via compact binary packets with numeric stream IDs, bounded backpressure and remote DNS resolution inside the intranet. The relay can also inject dashboard-managed hostname overrides (for example `aghuse.saude.ba.gov.br -> 10.0.0.1`) that take precedence over the agent's local DNS. Successful lookups stay in a short-lived fresh cache, expired answers can be reused briefly while the agent refreshes them, and failed lookups enter a short negative cache to avoid lookup storms._

---

## Features

- **Single binary** (Go 1.23) powered by Cobra with `relay` and `agent` subcommands.
- **Reverse tunnel over WebSockets**: only outbound HTTPS/WSS is required from the intranet.
- **Dual proxies**:
  - HTTP CONNECT (Basic Auth).
  - SOCKS5 with username/password (same credentials).
- **Remote DNS aware dialing** with fresh/stale/negative cache behavior on the agent, multi-address retry ordering, and relay-managed host-to-IP overrides.
- **Agent ACLs** via regex host:port filters.
- **Automatic TLS** on relay using Let’s Encrypt (ACME HTTP-01).
- **Per-agent PAC files** for quick browser configuration.
- **Dashboard** (Tailwind + Chart.js) showing live metrics, resource graphs, stream inventory – auto-refreshes every 3 s.
- **Active diagnostics from the dashboard**: resolve hostnames, test TCP reachability, and probe TLS by selected agent, auto-selected group, or destination profile.
- **Persisted audit timeline**: control-plane edits, DNS overrides, deployment target changes, and diagnostic runs are stored in the control-plane DB and surfaced in the dashboard/status API.
- **Prometheus metrics** at `/metrics` covering bytes transferred, dial/auth errors, agents connected, etc.
- **Graceful shutdown** on SIGINT/SIGTERM across all listeners.
- **Docker & Compose** examples with optional Caddy front-end.

---

## Getting Started

### Prerequisites

- Go 1.23+
- Public domain pointing to the relay host (for ACME)
- Outbound HTTPS/WSS allowed from the intranet host running the agent

### Build

```bash
make build        # builds web assets and the Go binary
```

Other useful targets:

```bash
make lint         # golangci-lint with revive/staticcheck/gocritic
make test         # go test ./...
make race         # go test -race ./...
make soak         # targeted soak/chaos harness for DNS instability plus agent/relay restart scenarios
make bench        # go test -bench=.
make fuzz         # go test ./internal/protocol -fuzz=FuzzDecodeDataPacket
make cover        # coverage report (build/coverage.out)
make release      # versioned cross-platform artifacts in build/releases/<version>
make release-bin  # colocated update binaries in ./bin for relay auto-update
```

### Run the Relay

```bash
./intratun relay \
  --proxy-listen=:8080 \
  --secure-listen=:443 \
  --socks-listen=:1080 \
  --agent-config=config/agents.example.yaml \
  --dashboard-user=admin \
  --dashboard-pass=change-me \
  --acl-allow='^.*:443$' \
  --acme-host=relay.example.com \
  --acme-email=ops@example.com \
  --acme-cache=/var/lib/intratun/acme \
  --acme-http=:80
```

This exposes:

- `https://relay.example.com/tunnel` – agent WebSocket endpoint (WSS).
- `https://relay.example.com/` – real-time dashboard with metrics/charts.
- `https://relay.example.com/status.json` – JSON data feed.
- `http://relay.example.com:8080` – HTTP CONNECT proxy (Basic auth).
- `relay.example.com:1080` – SOCKS5 proxy (username/password).

### Run the Agent

```bash
./intratun agent \
  --relay=wss://relay.example.com/tunnel \
  --id=myagent \
  --token=supersecret \
  --dial-timeout-ms=5000 \
  --max-frame=32768
```

The agent reconnects automatically with exponential backoff and resolves DNS inside the private network.

---

## Configuration Reference

Configuration obeys **env > file > flags**. Both commands accept `--config` (YAML). Environment variables override file entries and finally CLI flags provide defaults.

### Global

| Variable                    | Purpose                                | Default    |
| --------------------------- | -------------------------------------- | ---------- |
| `INTRATUN_ENV`              | Environment name (log field)           | empty      |
| `INTRATUN_SERVICE_NAME`     | Service name for logs/tracing          | `intratun` |
| `INTRATUN_LOG_LEVEL`        | `debug`, `info`, `warn`, `error`       | `info`     |
| `INTRATUN_JSON_LOGS`        | `true` for JSON logs                   | `false`    |
| `INTRATUN_PID_FILE`         | Path for PID file                      | empty      |
| `INTRATUN_TRACE_ENABLED`    | Enable OpenTelemetry tracing           | `false`    |
| `INTRATUN_TRACE_EXPORTER`   | `stdout`, `otlp-grpc`, `otlp-http`     | `stdout`   |
| `INTRATUN_TRACE_ENDPOINT`   | Exporter endpoint (`host:port` or URL) | empty      |
| `INTRATUN_TRACE_INSECURE`   | Disable TLS for OTLP exporters         | `false`    |

### Agent

| Variable                              | Notes                                  |
| ------------------------------------- | -------------------------------------- |
| `INTRATUN_AGENT_CONFIG`               | YAML config path                       |
| `INTRATUN_AGENT_RELAY`                | Relay WSS endpoint                     |
| `INTRATUN_AGENT_ID` / `TOKEN`         | Credentials                            |
| `INTRATUN_AGENT_DIAL_TIMEOUT_MS`      | TCP dial timeout (ms)                  |
| `INTRATUN_AGENT_DNS_CACHE_TTL`        | Fresh DNS cache TTL (e.g. `30s`)       |
| `INTRATUN_AGENT_DNS_NEGATIVE_TTL`     | Negative DNS cache TTL (e.g. `5s`)     |
| `INTRATUN_AGENT_DNS_STALE_TTL`        | How long stale DNS answers may be reused while refreshing |
| `INTRATUN_AGENT_DNS_REFRESH_AHEAD`    | Background refresh lead time before DNS expiry |
| `INTRATUN_AGENT_READ_BUFFER`          | Stream read buffer bytes               |
| `INTRATUN_AGENT_WRITE_BUFFER`         | WebSocket write buffer bytes           |
| `INTRATUN_AGENT_MAX_FRAME`            | Max payload per frame                  |
| `INTRATUN_AGENT_MAX_INFLIGHT`         | Per-stream inflight bytes              |
| `INTRATUN_AGENT_QUEUE_DEPTH`          | Per-stream queue depth                 |
| `INTRATUN_AGENT_RECONNECT_MIN/MAX`    | Durations (e.g. `2s`, `30s`)           |
| `INTRATUN_AGENT_UPDATE_MANIFEST`      | Remote JSON manifest/deployment endpoint for agent updates |
| `INTRATUN_AGENT_UPDATE_INTERVAL`      | Check interval (e.g. `30m`)            |
| `INTRATUN_AGENT_UPDATE_TIMEOUT`       | Download/check timeout                 |

### Relay

| Variable                                   | Notes                                    |
| ------------------------------------------ | ---------------------------------------- |
| `INTRATUN_RELAY_CONFIG`                    | YAML config path                         |
| `INTRATUN_RELAY_PROXY_LISTEN`              | HTTP CONNECT listener                    |
| `INTRATUN_RELAY_SECURE_LISTEN`             | HTTPS listener                           |
| `INTRATUN_RELAY_SOCKS_LISTEN`              | SOCKS5 listener                          |
| `INTRATUN_RELAY_AGENT_CONFIG`              | Agents definition YAML                   |
| `INTRATUN_RELAY_DASHBOARD_USER` / `PASS`   | Basic auth for dashboard and downloads   |
| `INTRATUN_RELAY_ACL_ALLOW`                 | Comma/space separated regex list         |
| `INTRATUN_RELAY_CONTROL_PLANE_DB`          | SQLite file for users/groups/profiles/grants (`:memory:` disables persistence) |
| `INTRATUN_RELAY_DNS_OVERRIDES_FILE`        | YAML file persisted by dashboard host overrides |
| `INTRATUN_RELAY_AUTOCONFIG_SECRET`         | HMAC secret for user-scoped PAC URLs (falls back to dashboard password) |
| `INTRATUN_RELAY_BREAKER_FAILURES`          | Consecutive failures before opening a destination circuit breaker |
| `INTRATUN_RELAY_BREAKER_COOLDOWN`          | Cooldown before a half-open circuit breaker probe |
| `INTRATUN_RELAY_USER_STREAM_QUOTA`         | Max concurrent active streams per relay user (`0` disables) |
| `INTRATUN_RELAY_GROUP_STREAM_QUOTA`        | Max concurrent active streams per group (`0` disables) |
| `INTRATUN_RELAY_AGENT_STREAM_QUOTA`        | Max concurrent active streams per connected agent (`0` disables) |
| `INTRATUN_RELAY_MAX_FRAME`                 | Max frame payload size                   |
| `INTRATUN_RELAY_MAX_INFLIGHT`              | Client backlog limit bytes               |
| `INTRATUN_RELAY_STREAM_QUEUE_DEPTH`        | Client write queue depth                 |
| `INTRATUN_RELAY_WS_IDLE`                   | WebSocket idle timeout (`45s`)           |
| `INTRATUN_RELAY_DIAL_TIMEOUT_MS`           | Dial acknowledgement timeout             |
| `INTRATUN_RELAY_ACME_HOSTS` / `EMAIL`      | ACME config                              |
| `INTRATUN_RELAY_ACME_CACHE` / `ACME_HTTP`  | ACME cache/HTTP-01 endpoint              |
| `INTRATUN_RELAY_UPDATES_DIR`               | Directory served at `/updates/`          |
| `INTRATUN_RELAY_STREAM_ID_MODE`            | `counter` (default), `uint64`, `uuid` or `cuid` compatibility aliases |

Sample YAML snippets live in `config/`.

---

## Command Reference

### Relay Flags

| Flag                                                            | Description                                      |
| --------------------------------------------------------------- | ------------------------------------------------ |
| `--proxy-listen`                                                | HTTP CONNECT listener (`:8080` default)          |
| `--secure-listen`                                               | HTTPS listener for `/tunnel`, dashboard, metrics |
| `--socks-listen`                                                | Optional SOCKS5 listener                         |
| `--agent-config`                                                | YAML file with allowed agents                    |
| `--dashboard-user` / `--dashboard-pass`                         | Basic auth for dashboard, `status.json`, downloads |
| `--acl-allow`                                                   | Regex ACL for `host:port` destinations           |
| `--control-plane-db`                                            | SQLite database for control-plane state          |
| `--autoconfig-secret`                                           | HMAC secret used to mint user-scoped PAC URLs    |
| `--breaker-failures` / `--breaker-cooldown`                     | Destination circuit breaker threshold/cooldown   |
| `--user-stream-quota` / `--group-stream-quota` / `--agent-stream-quota` | Concurrent stream quotas                 |
| `--acme-host` / `--acme-email` / `--acme-cache` / `--acme-http` | Let’s Encrypt settings                           |
| `--max-frame`                                                   | Max payload chunk per frame                      |
| `--max-inflight`                                                | Per-stream queued bytes toward clients           |
| `--stream-queue-depth`                                          | Per-stream client queue length                   |
| `--ws-idle`                                                     | WebSocket idle timeout                           |
| `--dial-timeout-ms`                                             | Agent dial acknowledgement timeout               |
| `--updates-dir`                                                 | Optional directory for colocated agent binaries  |

### Agent Flags

| Flag                         | Description                       |
| ---------------------------- | --------------------------------- |
| `--relay`                    | WSS endpoint of the relay         |
| `--id` / `--token`           | Agent credential pair             |
| `--dial-timeout-ms`          | TCP dial timeout                  |
| `--dns-cache-ttl` / `--dns-negative-ttl` / `--dns-stale-ttl` / `--dns-refresh-ahead` | Agent-side DNS cache tuning |
| `--max-frame`                | Max chunk size to relay           |
| `--read-buf` / `--write-buf` | Socket and WebSocket buffer sizes |
| `--max-inflight`             | Per-stream backpressure limit     |
| `--update-manifest`          | Update manifest/deployment URL, `auto`, or `off` |
| `--update-interval`          | Periodic update check interval    |
| `--update-timeout`           | Manifest/download timeout         |

### Automatic Agent Updates

Automatic agent updates are enabled by default. In `auto` mode, the agent derives an authenticated deployment endpoint from the relay:

```text
https://<relay-host>/updates/agent/manifest
```

Set `--update-manifest=off` to disable it. The agent polls that HTTP endpoint with its own credentials and platform metadata, downloads the requested binary over HTTP(S), verifies the `sha256`, and syncs to the desired version. That sync can be an upgrade or a downgrade.

Example manifest:

```json
{
  "version": "0.1.1+build.70.abcd123",
  "url": "https://relay.example.com/updates/bin/0.1.1+build.70.abcd123/linux/amd64",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Example agent:

```bash
./intratun agent \
  --relay=wss://relay.example.com/tunnel \
  --id=myagent \
  --token=supersecret
```

Notes:

- If you want to override the default path, use `--update-manifest=https://...`.
- By default the relay generates the manifest itself and looks for agent binaries in the same directory as the relay executable.
- The dashboard can now pin a specific version per agent, reset the agent back to `latest`, and force an immediate update check when the tunnel is connected.
- Even if the relay/agent WebSocket protocol is unhealthy, the agent still applies remote deployments through the HTTP update endpoint on its next poll cycle.
- Versioned release directories such as `build/releases/<version>/intratun-<goos>-<goarch>` are discovered automatically, which enables remote downgrade.
- `--updates-dir` overrides that directory when you want to keep release artifacts elsewhere.
- `make release-bin` builds the artifact names that the relay auto-update endpoint already expects and writes `SHA256SUMS`.
- The Docker image now bakes those release binaries into `/var/lib/intratun/updates`, so dashboard downloads work without mounting `./bin`.
- The manifest is expected to be served over HTTP(S).
- Windows self-update is supported through a staged helper restart flow.

### Docker Compose

The repository now ships with `docker-compose.yaml` tuned for relay throughput on Linux hosts:

- `network_mode: host` to avoid Docker NAT on the proxy and SOCKS5 path.
- `nofile` raised to `1048576`.
- ACME cache persisted in a named volume.
- A small `relay-acme-init` service fixes the ACME volume ownership for the relay `nonroot` user before startup.
- The Docker image itself already contains the release binaries in `/var/lib/intratun/updates`, so dashboard downloads and auto-update work out of the box.
- Dashboard auth required through `INTRATUN_DASHBOARD_USER` / `INTRATUN_DASHBOARD_PASS`.
- The Docker build compiles the update artifacts in separate steps to reduce peak disk usage during cross-builds.

Start it with:

```bash
docker compose up -d --build
```

If you already created the `relay-acme` volume before this fix and the logs show `permission denied` or `acme/autocert: missing certificate`, repair it once and recreate the relay:

```bash
docker compose down
docker compose run --rm relay-acme-init
docker compose up -d --build --force-recreate
```

If the Docker host already exhausted builder storage and the image build fails with `no space left on device`, clean old BuildKit layers once before rebuilding:

```bash
docker builder prune -af
docker compose up -d --build --force-recreate
```

## Observability

- Structured logs now include `service`, `component`, `trace_id`, and `span_id`. Use `INTRATUN_LOG_LEVEL` / `INTRATUN_JSON_LOGS` for formatting.
- Enable tracing with `INTRATUN_TRACE_ENABLED=true` (default exporter prints OTLP spans to stdout). Point `INTRATUN_TRACE_EXPORTER` to future OTLP exporters when available.
- Prometheus metrics remain exposed on the relay at `/metrics`.

## Dashboard & Monitoring

- Visit `https://relay.example.com/` for:
  - Live summary counters.
  - CPU/RSS graphs covering the last seven days (sampled every minute).
  - Connected agents, active streams, PAC download links.
  - Control-plane CRUD for users, groups, memberships, destination profiles, and grants backed by SQLite.
  - Dashboard-managed DNS overrides that supersede the agent-side local resolver.
  - User-scoped PAC generation with signed URLs and profile-aware routing rules.
  - Stream metadata showing principal, group, profile, and route reason chosen by the relay.
  - Recent routing history with structured reason codes for selected and failed routes.
  - Active connectivity diagnostics via selected agent, auto-selected group, or destination profile, including remote DNS result, chosen IP, TCP dial outcome, TLS handshake details, and recent run history.
  - Shared support filter plus recent failure breakdowns by destino, principal, and agente across routing/diagnostic histories.
  - Concurrent stream quota snapshot for usuários, grupos e agentes, including current saturation.
  - Active destination circuit breakers by grupo+destino, including state, cooldown, and last error.
  - Persisted audit timeline for control-plane changes, deployments, DNS overrides, and diagnostic executions.
  - Per-agent deployment controls for forced update, downgrade, and reset to latest.
  - Download buttons for agent ZIP artifacts served directly by the relay.
- `https://relay.example.com/status.json` provides the raw data; think of it as the REST-ish back-end for the dashboard.
- The dashboard, `status.json`, static assets, and agent ZIP downloads can be protected with HTTP Basic auth via `--dashboard-user` / `--dashboard-pass`.
- `https://relay.example.com/metrics` exposes Prometheus metrics (`intratun_bytes_*`, `intratun_agents_connected`, etc.).

For browser setup:

- HTTP CONNECT: configure proxy `relay.example.com:8080` with Basic auth using either `username:password` (relay user) or the legacy `agentId:token` compatibility mode.
- SOCKS5: use the same relay user credential model or legacy agent credential, and keep “Remote DNS” enabled in the browser so intranet hostnames resolve via the agent.
- User PAC links generated by the dashboard do not embed credentials; they only describe when to use the relay. Proxy authentication still happens separately in the browser/system.

---

## Advanced Topics

- **Access Control:** Define agents in YAML via `--agent-config` and tighten ACLs for each relay instance. Future work may scope ACLs per agent.
- **Scaling Agents:** The WebSocket protocol multiplexes streams with `streamId`, so a single agent connection can handle many simultaneous tunnels.
- **High Availability:** Run multiple relays behind a load balancer; agents reconnect on failure, and browsers will retry the proxy automatically.
- **Extensibility:** The binary packet protocol is versioned and leaves room for new message types (e.g., SOCKS5 UDP associate, mTLS, credit systems, audit trails).

---

## Roadmap Ideas

The active planning documents now live in:

- `docs/architecture/target-operating-model.md`
- `docs/roadmap/platform-roadmap.md`
- `docs/specs/phase-1-access-routing.md`

Planned themes include:

- group-based routing and user credentials independent from agents;
- diagnostics and auditability from the dashboard;
- adaptive transport tuning and stronger resilience controls;
- protocol compatibility negotiation and safer rollouts;
- persistent control-plane storage and multi-relay readiness;
- enterprise auth, RBAC, and improved end-user onboarding.

Got ideas? Issues and PRs are welcome.

---

## Support

- Repo: [github.com/drksbr/ProxyWebSock](https://github.com/drksbr/ProxyWebSock)
- Issues: please open tickets on GitHub with logs and environment details.

---

Created by [Isaac Diniz](https://github.com/drksbr/).  
Made with love ❤️
