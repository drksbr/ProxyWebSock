# Contributing to ProxyWebSock

Thanks for the interest in improving ProxyWebSock! This document covers the workflow adopted after the observability/config modernization.

## Development Environment

- Go 1.23 (the Go toolchain may upgrade `go.mod` to the latest minor release automatically).
- Node.js + chosen package manager (default `bun`) for the dashboard assets.
- `golangci-lint` and `gotestsum` installed via `make tools`.

## Workflow

1. Fork the repository and create a feature branch off `main`.
2. Run through the local quality bar before opening a PR:

   ```bash
   make fmt vet lint test race cover
   make bench           # optional but helpful for performance-sensitive changes
   make fuzz            # exercises protocol decoding
   ```

3. If you add new exported APIs or behaviour, update the README and docstrings.
4. Keep commits focused; prefer small, reviewable changes. Reference the ADRs under `docs/adr/` when touching architecture decisions.
5. Ensure CI passes (GitHub Actions runs lint + tests + race + cross-build).

## Coding Guidelines

- Follow Effective Go and standard library naming patterns.
- Always wrap errors with `%w` and prefer `errors.Is/As` for matching.
- Avoid global state; inject dependencies where possible.
- Keep logs structured and meaningful; include `trace_id` for cross-cutting operations.
- Maintain the env > file > flags precedence when extending configuration.

## Reporting Issues

- Provide reproduction steps, expected vs actual behaviour, and environment details.
- For security reports, please avoid filing public issues—contact the maintainers directly.

Thanks for helping to make ProxyWebSock production-ready!
