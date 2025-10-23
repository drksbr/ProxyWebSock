# ADR 0002: Configuration Layering

## Status
Accepted

## Context
Configuration was previously hard-coded through CLI flags only, leaving no support for Twelve-Factor style environment overrides or declarative files. Operational environments need consistent precedence (`env > file > flags`) and validation.

## Decision
Add a lightweight `internal/config` helper that loads optional YAML files and environment variables. Each command (`agent`, `relay`) consumes the loader before validation so that command-line arguments remain the lowest precedence fallback. New environment variables (`INTRATUN_AGENT_*`, `INTRATUN_RELAY_*`) provide operational control without touching deployment scripts.

## Consequences
- Operations can manage configuration centrally (ConfigMaps, secrets) while retaining CLI fallback.
- Validation is still centralised inside option structs.
- Slightly more startup logic, but the decoupling removes flag sprawl and aligns with 12-factor expectations.
