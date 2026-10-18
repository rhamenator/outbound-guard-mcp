# Security policy

## Supported code

Security fixes target the current `main` branch. The server is an advisory guard; it cannot intercept actions an MCP client routes elsewhere. Local stdio is the recommended transport. The optional HTTP POST endpoint needs token authentication for non-loopback binding, TLS termination, and network controls.

## Report a vulnerability

Use GitHub's private vulnerability reporting from the repository Security tab. If unavailable, email rich@yourfoxprodeveloper.com with the repository name, affected revision, impact, reproduction steps, and proposed mitigation. Do not open a public issue for an unpatched vulnerability or include real credentials or personal data. Expect acknowledgment within seven days.

See [the security model](docs/security.md) for supported boundaries and limitations.
