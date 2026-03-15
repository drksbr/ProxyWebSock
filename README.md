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

_The agent maintains a persistent WSS tunnel, multiplexing traffic via JSON frames (`register`, `dial`, `write`, `close`, `err`). Destination DNS queries happen inside the intranet, so TLS handshakes preserve SNI end-to-end._

---

## Features

- **Single binary** (Go 1.23) powered by Cobra with `relay` and `agent` subcommands.
- **Reverse tunnel over WebSockets**: only outbound HTTPS/WSS is required from the intranet.
- **Dual proxies**:
  - HTTP CONNECT (Basic Auth).
  - SOCKS5 with username/password (same credentials).
- **Agent ACLs** via regex host:port filters.
- **Automatic TLS** on relay using Let’s Encrypt (ACME HTTP-01).
- **Per-agent PAC files** for quick browser configuration.
- **Dashboard** (Tailwind + Chart.js) showing live metrics, resource graphs, stream inventory – auto-refreshes every 3 s.
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
make bench        # go test -bench=.
make fuzz         # go test ./internal/protocol -fuzz=FuzzDecodeBinaryFrame
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
| `INTRATUN_AGENT_READ_BUFFER`          | Stream read buffer bytes               |
| `INTRATUN_AGENT_WRITE_BUFFER`         | WebSocket write buffer bytes           |
| `INTRATUN_AGENT_MAX_FRAME`            | Max payload per frame                  |
| `INTRATUN_AGENT_MAX_INFLIGHT`         | Per-stream inflight bytes              |
| `INTRATUN_AGENT_QUEUE_DEPTH`          | Per-stream queue depth                 |
| `INTRATUN_AGENT_RECONNECT_MIN/MAX`    | Durations (e.g. `2s`, `30s`)           |
| `INTRATUN_AGENT_UPDATE_MANIFEST`      | Remote JSON manifest for agent updates |
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
| `INTRATUN_RELAY_MAX_FRAME`                 | Max frame payload size                   |
| `INTRATUN_RELAY_MAX_INFLIGHT`              | Client backlog limit bytes               |
| `INTRATUN_RELAY_STREAM_QUEUE_DEPTH`        | Client write queue depth                 |
| `INTRATUN_RELAY_WS_IDLE`                   | WebSocket idle timeout (`45s`)           |
| `INTRATUN_RELAY_DIAL_TIMEOUT_MS`           | Dial acknowledgement timeout             |
| `INTRATUN_RELAY_ACME_HOSTS` / `EMAIL`      | ACME config                              |
| `INTRATUN_RELAY_ACME_CACHE` / `ACME_HTTP`  | ACME cache/HTTP-01 endpoint              |
| `INTRATUN_RELAY_UPDATES_DIR`               | Directory served at `/updates/`          |
| `INTRATUN_RELAY_STREAM_ID_MODE`            | `uuid` (default) or `cuid`               |

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
| `--max-frame`                | Max chunk size to relay           |
| `--read-buf` / `--write-buf` | Socket and WebSocket buffer sizes |
| `--max-inflight`             | Per-stream backpressure limit     |
| `--update-manifest`          | Update manifest URL, `auto`, or `off` |
| `--update-interval`          | Periodic update check interval    |
| `--update-timeout`           | Manifest/download timeout         |

### Automatic Agent Updates

Automatic agent updates are now enabled by default. If no manifest URL is configured, the agent derives a conventional manifest URL from the relay:

```text
https://<relay-host>/updates/manifest-<goos>-<goarch>.json
```

Set `--update-manifest=off` to disable it. On a newer version, the agent downloads the new binary, verifies the `sha256`, atomically replaces the current executable, and re-execs itself.

Example manifest:

```json
{
  "version": "0.1.1+build.70.abcd123",
  "url": "https://relay.example.com/updates/bin/linux/amd64",
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
- `--updates-dir` overrides that directory when you want to keep release artifacts elsewhere.
- `make release-bin` builds the artifact names that the relay auto-update endpoint already expects and writes `SHA256SUMS`.
- The Docker image now bakes those release binaries into `/var/lib/intratun/updates`, so dashboard downloads work without mounting `./bin`.
- The manifest is expected to be served over HTTP(S).
- Windows self-update is not supported yet.

### Docker Compose

The repository now ships with `docker-compose.yaml` tuned for relay throughput on Linux hosts:

- `network_mode: host` to avoid Docker NAT on the proxy and SOCKS5 path.
- `nofile` raised to `1048576`.
- ACME cache persisted in a named volume.
- A small `relay-acme-init` service fixes the ACME volume ownership for the relay `nonroot` user before startup.
- The Docker image itself already contains the release binaries in `/var/lib/intratun/updates`, so dashboard downloads and auto-update work out of the box.
- Dashboard auth required through `INTRATUN_DASHBOARD_USER` / `INTRATUN_DASHBOARD_PASS`.

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

## Observability

- Structured logs now include `service`, `component`, `trace_id`, and `span_id`. Use `INTRATUN_LOG_LEVEL` / `INTRATUN_JSON_LOGS` for formatting.
- Enable tracing with `INTRATUN_TRACE_ENABLED=true` (default exporter prints OTLP spans to stdout). Point `INTRATUN_TRACE_EXPORTER` to future OTLP exporters when available.
- Prometheus metrics remain exposed on the relay at `/metrics`.

## Dashboard & Monitoring

- Visit `https://relay.example.com/` for:
  - Live summary counters.
  - CPU/RSS graphs covering the last seven days (sampled every minute).
  - Connected agents, active streams, PAC download links.
  - Download buttons for agent ZIP artifacts served directly by the relay.
- `https://relay.example.com/status.json` provides the raw data; think of it as the REST-ish back-end for the dashboard.
- The dashboard, `status.json`, static assets, and agent ZIP downloads can be protected with HTTP Basic auth via `--dashboard-user` / `--dashboard-pass`.
- `https://relay.example.com/metrics` exposes Prometheus metrics (`intratun_bytes_*`, `intratun_agents_connected`, etc.).

For browser setup:

- HTTP CONNECT: configure proxy `relay.example.com:8080` with Basic auth (`agentId:token`).
- SOCKS5: leverage the PAC link (e.g., `https://relay.example.com/autoconfig/myagent.pac?token=...`) and enable “Remote DNS” in the browser so intranet hostnames resolve via the agent.

---

## Advanced Topics

- **Access Control:** Define agents in YAML via `--agent-config` and tighten ACLs for each relay instance. Future work may scope ACLs per agent.
- **Scaling Agents:** The WebSocket protocol multiplexes streams with `streamId`, so a single agent connection can handle many simultaneous tunnels.
- **High Availability:** Run multiple relays behind a load balancer; agents reconnect on failure, and browsers will retry the proxy automatically.
- **Extensibility:** The JSON frame protocol was designed with room for new message types (e.g., SOCKS5 UDP associate, mTLS, credit systems, audit trails).

---

## Roadmap Ideas

- SOCKS5 UDP support.
- mTLS between relay and agents.
- Dynamic per-agent ACLs & rate limiting.
- Pluggable auth providers (OIDC, API tokens).
- Persistent stream/connection analytics store.

Got ideas? Issues and PRs are welcome!

---

## Support

- Repo: [github.com/drksbr/ProxyWebSock](https://github.com/drksbr/ProxyWebSock)
- Issues: please open tickets on GitHub with logs and environment details.

---

Created by [Isaac Diniz](https://github.com/drksbr/).  
Made with love ❤️
