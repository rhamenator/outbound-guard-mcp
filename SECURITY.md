# Security policy

## Supported code

This repository is an extraction in progress. It does not yet release a runnable outbound guard. Security fixes will target the current `main` branch once implementation begins. The experimental source baseline is in the `codex/outbound-guard` branch of `request-guard-mcp`.

An MCP server can enforce policy only for requests routed through its tools. Host-level network controls are required for whole-agent egress restrictions. The security model and exact supported transports will be documented before a stable release.

## Report a vulnerability

Use GitHub's private vulnerability reporting from the repository Security tab. If unavailable, email rich@yourfoxprodeveloper.com with the repository name, affected revision, impact, reproduction steps, and proposed mitigation. Do not open a public issue for an unpatched vulnerability or include real credentials or personal data. Expect acknowledgment within seven days.
