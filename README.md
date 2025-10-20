# ProxyWebSock

ProxyWebSock lets you surface private intranet applications to the public internet without poking inbound firewall holes. It builds a reverse tunnel over WebSockets between a cloud‑facing **relay** and one or more inside-the-network **agents**, then exposes both HTTP CONNECT and SOCKS5 proxies for browsers and tooling.

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

- **Single binary** (Go 1.22) powered by Cobra with `relay` and `agent` subcommands.
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

- Go 1.22+
- Public domain pointing to the relay host (for ACME)
- Outbound HTTPS/WSS allowed from the intranet host running the agent

### Build

```bash
go build -o intratun ./cmd/intratun
```

### Run the Relay

```bash
./intratun relay \
  --proxy-listen=:8080 \
  --secure-listen=:443 \
  --socks-listen=:1080 \
  --agents=myagent:supersecret \
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

## Command Reference

### Relay Flags

| Flag                                                            | Description                                      |
| --------------------------------------------------------------- | ------------------------------------------------ |
| `--proxy-listen`                                                | HTTP CONNECT listener (`:8080` default)          |
| `--secure-listen`                                               | HTTPS listener for `/tunnel`, dashboard, metrics |
| `--socks-listen`                                                | Optional SOCKS5 listener                         |
| `--agents`                                                      | Allowed credentials `agentId:token` (repeatable) |
| `--acl-allow`                                                   | Regex ACL for `host:port` destinations           |
| `--acme-host` / `--acme-email` / `--acme-cache` / `--acme-http` | Let’s Encrypt settings                           |
| `--max-frame`                                                   | Max payload chunk per frame                      |
| `--ws-idle`                                                     | WebSocket idle timeout                           |
| `--dial-timeout-ms`                                             | Agent dial acknowledgement timeout               |

### Agent Flags

| Flag                         | Description                       |
| ---------------------------- | --------------------------------- |
| `--relay`                    | WSS endpoint of the relay         |
| `--id` / `--token`           | Agent credential pair             |
| `--dial-timeout-ms`          | TCP dial timeout                  |
| `--max-frame`                | Max chunk size to relay           |
| `--read-buf` / `--write-buf` | Socket and WebSocket buffer sizes |
| `--max-inflight`             | Per-stream backpressure limit     |

---

![Proxy dashboard overview](https://github.com/drksbr/ProxyWebSock/raw/main/screenshot1.png)
![Proxy metrics chart](https://github.com/drksbr/ProxyWebSock/raw/main/screenshot2.png)

## Dashboard & Monitoring

- Visit `https://relay.example.com/` for:
  - Live summary counters.
  - CPU/RSS graphs covering the last seven days (sampled every minute).
  - Connected agents, active streams, PAC download links.
- `https://relay.example.com/status.json` provides the raw data; think of it as the REST-ish back-end for the dashboard.
- `https://relay.example.com/metrics` exposes Prometheus metrics (`intratun_bytes_*`, `intratun_agents_connected`, etc.).

For browser setup:

- HTTP CONNECT: configure proxy `relay.example.com:8080` with Basic auth (`agentId:token`).
- SOCKS5: leverage the PAC link (e.g., `https://relay.example.com/autoconfig/myagent.pac?token=...`) and enable “Remote DNS” in the browser so intranet hostnames resolve via the agent.

---

## Advanced Topics

- **Access Control:** Use multiple `--agents` entries and tighten ACLs for each relay instance. Future work may scope ACLs per agent.
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
