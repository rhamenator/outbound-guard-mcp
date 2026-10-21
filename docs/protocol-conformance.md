# Stdio protocol conformance evidence

Status: implemented and tested revision-specific surface; independent release review and real-client matrix remain open in issue #65. MCP transport remains **stdio only**. HTTP/1 in network-limit documentation refers to guarded outbound requests, not a remote MCP transport.

## Supported paths

Modern `2026-07-28` requests carry `params._meta` with `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`. Client identity is optional. Version/capability/identity types are validated on every request; no previous discovery/handshake is required. Metadata is descriptive, never authorization. Missing metadata after a modern opener is rejected; an explicit `initialize` can select legacy behavior. Per-request capabilities are not inherited from earlier calls.

`server/discover` advertises modern support and only tools/resources. Successful modern replies carry `resultType: complete` and server identity metadata. Cacheable discovery/list/read replies use private scope and zero TTL. Listings are deterministic, single-page, and reject cursors this server never issued. Unsupported versions return `-32022` with requested/supported versions; malformed parameters use `-32602`. Modern resource lookup failures do not reuse legacy `-32002`. Invalid/unreadable modern IDs are omitted from errors rather than serialized as null. Unknown methods fail without dispatch.

Legacy `2025-06-18` initialization remains supported, including its existing request gating, output shape and errors. Modern calls can coexist with that process but do not use its capabilities or handshake as permission. Request IDs preserve string/numeric distinction; integer-valued numeric forms compare without floating-point rounding or expanding exponents. Numeric normalization uses bounded frame-sized digits and a checked signed 64-bit decimal scale; representations exceeding that scale are rejected. String IDs are preferable for application identifiers beyond a client's numeric precision.

The server emits no server-to-client requests and does not request sampling, roots or elicitation. It does not create multi-round-trip state. If retry fields are supplied, their shapes are checked and unknown content is ignored; they cannot authorize egress or alter policy. No ongoing update/list-change capability is advertised. Subscription requests receive an empty accepted-filter acknowledgement followed by immediate graceful completion; no resource URI is fetched and no subscription is retained. Cancellation of guarded fetches remains cooperative and redacted.

## Evidence matrix

| Area | Executable evidence |
| --- | --- |
| Stateless discovery/tools, metadata/version/ID errors, result types, deterministic listings, private caching, invalid-request no-dispatch, legacy coexistence, parse/size errors and subscription acknowledgement/closure | `tools/modern_stdio_probe.py` plus Rust request/ID regressions |
| Typed IDs and exact numeric cancellation matching | Rust numeric normalization cases and controlled stdio cancellation with request ID `1.0` cancelled as `1`; string `"1"` stays distinct |
| Modern/legacy official clients | Locked development-only SDK 2.3.1 pinned modern and SDK 1.32.1 legacy run the same shared abort/audit/recovery/schema/GET/HEAD scenario |
| Inspector negotiation | Inspector 2.11.0 explicit legacy, automatic modern discovery, pinned modern, strict tool/schema, denial, audit and child-environment checks |
| Installed artifact | Candidate packaging repeats modern wire, Inspector, resource and both SDK network probes against the exact extracted optimized build |

Inspector's CLI `initialize` command reports connection metadata even for a modern connection; it does not imply a modern wire handshake. The historical CLI did not expose a direct `server/discover` command; raw wire and SDK checks verify that method without relying on a CLI method alias. Earlier pinned-modern refusal/fallback evidence in historical documents predates this implementation.

Current tests do not constitute exhaustive formal certification, all optional extensions, a remote transport, every client UI, or another repository's conformance. Cursor authentication and final-candidate Codex/Claude/Cursor tests remain release work. Deprecated/optional logging, completion, tasks, ongoing subscriptions and elicitation features are not advertised as available.

## Authoritative references

- [Stdio framing, metadata and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Base messages and metadata](https://modelcontextprotocol.io/specification/2026-07-28/basic)
- [Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning), [discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover), [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions), [multi-round-trip requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)

## Independent implementation review, 2026-10-21

The separate Request Guard maintenance chat performed a read-only review of main `42b9984` against the modern stdio/base/schema requirements and legacy initialization. Scope: metadata, errors/results/discovery, subscription acknowledgement/closure, cancellation and framing. This is a separate reviewer of this implementation, not third-party certification or human release approval.

Finding: a zero-capacity input handoff could leave the stdin reader blocked on ordinary request B while fetch A ran, preventing observation of a later cancellation for A. The correction allows eight queued frames plus one reader-held frame, keeping allocation bounded while allowing that interleaving. At queue saturation, input backpressure remains; this finite queue is not an unlimited control-priority channel. The protocol acceptance gate stays open for final review, client UI cancellation and saturation policy.

Regression evidence: raw wire (string and numeric IDs) and both official SDK clients queue an ordinary request before aborting the live fetch. No reply is permitted for the cancelled fetch; audit, peer closure, recovery and ID reuse are checked. `tools/protocol_id_probe.py` adds 251 deterministic numeric-ID cases against Python Decimal rather than copying Rust normalization logic; accepted integer IDs retain their exact value, fractional IDs omit the invalid ID from the error, and no fetch is dispatched. CI and candidate installation run the corpus without new dependencies or network access.

## Saturation admission update

[Bounded admission and control priority](cancellation-priority.md) supersedes the earlier read-ahead saturation limitation: no ordinary admission send blocks the reader. Eight busy replies are retained before fail-closed connection termination. Requests rejected with correlated `-32000` / `MCP_INPUT_BUSY` errors are not executed; clients should drain outstanding replies before retrying. Error replies can overtake admitted responses. Client-side cancellation omissions, incomplete frames and cooperative network cancellation remain distinct limitations.
