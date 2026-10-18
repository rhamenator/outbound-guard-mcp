# Outbound Guard release quality bar

Status: acceptance criteria, not a claim of completion. A stable release requires each gate to have a passing test or durable review record linked from a release issue. No gate may be waived silently.

## 1. Core egress boundary

- A `guarded_fetch` call applies URL, method, header, body, DNS, connection, redirect, and response policy in one operation. A preview tool is never an authorization token.
- Only HTTP(S) on operator-approved ports is accepted. URL normalization rejects ambiguous addresses and userinfo. Every DNS answer is checked, and the connection uses a validated answer with the original hostname for Host, SNI, and certificate validation. Ambient proxies and credentials are disabled unless explicitly configured by the operator.
- Every redirect repeats all policy checks; cross-origin credentials are never forwarded. Request budgets account for redirects atomically. Policy and network failures fail closed in enforce mode.
- Hard caps cover request bytes, response wire and decoded bytes, expansion ratio, headers, redirect count, concurrent calls, DNS/connect/first-byte/idle/total time, and audit retention. Cancellation releases sockets and reservations.
- Known secrets are blocked before a socket opens; heuristic entropy is a warning with documented false positives. Response text remains untrusted, with provenance and quarantine behavior explicit.

## 2. Interoperability

- Implement the [MCP 2026-07-28 protocol](https://modelcontextprotocol.io/specification/2026-07-28) on every advertised transport, including required per-request `_meta` and deterministic tool ordering. Negotiate older revisions only where the compatibility matrix and tested clients require it.
- Stdio is the first supported transport. Add remote Streamable HTTP only with full request, header, cancellation, origin, authorization, and streaming conformance; a JSON-RPC POST alone must not be called Streamable HTTP.
- Official SDK/Inspector probes and fresh-install smoke tests pass for supported Codex, Claude Code, and Cursor versions. Copyable configs specify permissions, environment variables, and expected first tool result.

## 3. Adversarial evidence

- Controlled DNS and HTTP fixtures test private/mixed answers, rebinding, redirects, proxy bypass, TLS hostname mismatch, secret-bearing headers and bodies, slow drip, delayed first byte, oversized/encoded bodies, malformed framing, CSS-hidden links, and prompt-injection payloads. Tests assert no forbidden socket opens and no secret appears in logs or results.
- Fuzz or property tests cover URL parsing, IP ranges, framing boundaries, and schema inputs. Concurrency and resource tests prove bounded memory, file descriptors, and budget correctness.
- A threat model maps each promised protection to the exact code path and test. Limits and bypass routes are plainly documented, especially traffic sent via other tools.

## 4. Product finish

- Minimal justified dependencies, pinned CI actions, dependency review, CodeQL, reproducible package installation, checksums, GPL-3.0-or-later license/notice, changelog, versioning, security disclosure, support and contribution guides, and machine-readable registry metadata.
- Structured decisions have stable rule codes, remediation, correlation IDs, redacted audit events, and examples for both allow and deny cases. Configuration has schema validation and safe defaults; startup rejects invalid settings with useful errors.
- A release candidate passes the repository's human release-readiness review. Only then may documentation call the server production-ready or publish a stable tag.

Runtime Guard is a separate advisory server. It may share conventions and tests, but Outbound Guard must install and operate without it or Request Guard.
