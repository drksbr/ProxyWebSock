# ADR 0001: Observability Foundation

## Status
Accepted

## Context
The existing codebase emitted unstructured logs and relied solely on Prometheus metrics on the relay side. There was no consistent trace identifier across components, and no tracing integration. Operating the product in production requires consistent logging, metric, and tracing primitives.

## Decision
Introduce an internal `logger` package wrapping `slog` with default fields (`service`, `version`, `component`) and support for `trace_id` / `span_id`. Add a new `internal/observability` package that wires optional OpenTelemetry tracing via `stdout` exporter by default, controlled through the runtime options (`INTRATUN_TRACE_ENABLED`, `INTRATUN_TRACE_EXPORTER`). Each agent and relay stream now attaches stable identifiers to log entries.

## Consequences
- Structured logs now carry correlation identifiers simplifying incident response.
- Minimal tracing can be enabled without code changes once an OTLP collector is available.
- The logging indirection adds a lightweight abstraction but remains opt-in for tracing to limit runtime overhead when disabled.
