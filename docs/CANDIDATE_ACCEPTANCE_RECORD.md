# Exact-candidate owner review record

Status: **template only; no candidate approved**. Copy this record into [issue #65](https://github.com/rhamenator/outbound-guard-mcp/issues/65) for one immutable candidate. Keep every evidence link and the owner's decision in that issue. A new executable, installer, supported platform, or buyer-facing claim requires a new review. Passing CI, a provenance attestation, or this completed template is not owner acceptance.

## Candidate identity

- Source commit and proposed prerelease version (below 1.0):
- Exact installer/package names, SHA-256 hashes, and provenance verification links:
- Exact supported OS, architecture, distribution, MCP transport, and client versions:
- Buyer-facing README, registry, skill, and release-note revisions reviewed:

## Gate evidence and remaining limits

For each row, link a passing exact-candidate record or describe the unresolved gap. Earlier experimental evidence is context, not a substitute for an exact-candidate check.

| Gate | Exact-candidate evidence or unresolved gap |
| --- | --- |
| Core egress policy and documented enforcement boundary | |
| MCP protocol and supported-client compatibility | |
| Controlled HTTP/DNS adversarial, malformed-protocol, resource and fail-closed testing | |
| Each supported platform's clean install, guarded call, applicable upgrade, uninstall and residue | |
| Artifact hashes, provenance, dependencies, license, documentation and claims | |

- Residual risks, including accepted malformed 204 tails, traffic sent through other tools, and untested client or platform paths:
- Independent human review performed? If absent, state **none** explicitly:
- Separate AI Scraping Defense repository gates: record as **open** here unless each repository has its own exact evidence and acceptance. Outbound Guard results do not close them.

## Owner decision

- Owner identity and review date:
- Exact candidate commit and artifact hashes accepted:
- Explicit residual-risk acceptance or rejection, with reasons:
- Decision: **approve official prerelease candidate / reject / defer** (select one and remove the others):

Do not publish an official pre-1.0 candidate until the owner explicitly approves the exact candidate and its residual risks in issue #65. Do not publish a stable v1/latest under this process. An unsigned installer must be labeled unsigned; commercial Windows/macOS signing or notarization may be deferred only while every declared platform still meets its package and lifecycle gate.
