# Changelog

## Unreleased — experimental 0.1.0 development

No stable release is approved by this changelog. Candidate archives identify the exact source commit in their provenance. The [release checklist](docs/RELEASE_CHECKLIST.md) and [tracking issue #65](https://github.com/rhamenator/outbound-guard-mcp/issues/65) retain open gates.

### Implemented

- Independently installable GPL-3.0-or-later Rust MCP stdio server, with a companion instructional skill. Enforcement covers only traffic executed by `guarded_fetch`.
- Atomic allowlisted GET/HEAD, special-use address denial, validation of all retained DNS answers and pinned connections, absolute DNS names, TLS hostname verification and optional operator-controlled extra CA.
- Redirect and encoded-response denial, bounded text/JSON responses, conservative leading-HTML quarantine, local call budgets, heuristic URL-secret checks and redacted bounded audit resources.
- Legacy MCP 2025-06-18 initialization, tool/output schemas, resources, structured denials and cooperative cancellation. Modern revision support remains unfinished.
- Bounded stdio frame size, ten-second partial-frame ingestion deadline and three-second reply write/flush deadline. Timeout can terminate a session with an incomplete transport frame; clients must discard it and reconnect.
- Standalone help/version/startup configuration diagnostics; installed candidate packaging with source, provenance, checksums, locked dependency inventory and shipped upstream notices. Skill ZIP contains only instructions and GPL license.

GET media-type parameters are restricted to one optional UTF-8 charset declaration; conflicting, duplicate, unknown or malformed parameters are denied without response body text.

HTTP now uses async total/read timers behind the synchronous API, preventing a pending read from extending the ten-second HTTP budget to the next idle timeout. Tokio becomes direct without adding a locked package or version; raw wire/pre-parse header bounds remain unfinished.

### Verification added

- Controlled route-free DNS/HTTP fixtures, malformed framing/schema corpora, deterministic IP/framing properties, process-resource probes, official SDK cancellation and Inspector compatibility checks.
- Stalled and continuously fed partial input; unread, normally draining and abruptly disconnected output clients. These are finite test cases, not complete protocol or resource certification.

### Remaining before stable release

Full protocol/client conformance, remaining resource and security acceptance criteria, broader adversarial review, registry metadata, cross-host reproducibility/signing, dependency/license review and exact-candidate human approval. Historical client probes and another repository's tests do not close these gates.
