# Extraction and production-readiness plan

The release gates are in [QUALITY_BAR.md](QUALITY_BAR.md).

Source baseline: `request-guard-mcp` branch `codex/outbound-guard`, commit `4284678`. Its six tools, schemas, and egress design are an experimental implementation, not a completed standalone product.

1. Extract a focused MCP server with stdio first and only required dependencies. Keep `guarded_fetch` atomic. Port request policy, secret scanning, pinned DNS, redirect validation, budgets, response limits, and redacted audit. Preserve stable rule codes and JSON tool results.
2. Test policy with controlled DNS/HTTP fixtures: mixed public and private answers, rebinding, IPv4/IPv6 ranges, proxies, redirects, credential forwarding, slow streams, decompression bombs, malformed framing, size caps, and concurrent budget reservations. Prove blocked requests never open forbidden sockets.
3. Test MCP initialize, tools, resources, prompts, errors, and advertised transports using an official client probe, then run Codex, Claude Code, and Cursor setup smoke tests. Document copyable configuration and permissions.
4. Add CI, CodeQL, dependency review, release packaging, GPL notice, threat model, security policy, contribution guidance, and owner release-readiness review. Before an official pre-1.0 candidate, declare supported platforms, provide and qualify an installer or recognized package for each, verify checksums and available provenance, and record the owner's exact-candidate decision. Independent human review is optional here and its absence must be disclosed. Do not represent a SKILL.md as an enforcement mechanism or publish stable v1/latest through this candidate process.

The sibling `runtime-guard-mcp` covers advisory filesystem, command, budget, and output checks. It stays independent. The original `request-guard-mcp` remains an inbound classifier and may retain or retire its experimental egress branch once this server is ready.
