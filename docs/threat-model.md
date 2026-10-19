# Current egress threat model

This document maps the **implemented** stdio `guarded_fetch` GET/HEAD boundary to its tests. It describes the experimental `main` branch as of 2026-10-19. [QUALITY_BAR.md](QUALITY_BAR.md) is the stable-release acceptance list; an entry here is not a waiver of an open gate.

## Assets and boundaries

- The operator's approved host list, local network, metadata services, secrets in the agent context, agent time and memory, and content the model may trust are at risk.
- An autonomous agent supplies tool arguments. An external host, its DNS answers, TLS endpoint, headers, redirects, and body are untrusted. Local proxy variables may be hostile or accidental. A caller may send malformed or oversized MCP frames.
- The enforcement boundary is one `tools/call` to this server. The server cannot see or govern traffic sent through a browser, shell, another MCP server, or any other agent tool. The companion skill can guide tool choice but cannot enforce it.
- A valid MCP call passes from `src/main.rs::handle` to `src/lib.rs::guarded_fetch`. Validation and reservation run before DNS, then a pinned HTTP client connects, and the response is bounded before any `body_text` is returned. A blocked call returns stable `rule` and `remediation` fields; it does not return a partial body.

## Implemented controls and evidence

| Threat | Current code path | Reproducible evidence and limit |
| --- | --- | --- |
| SSRF through literals, private IPs, mixed DNS answers, or ambiguous URLs | `validate_with_reservation`, `valid_dns_name`, `public_ip`, `public_v4`, `public_v6` in `src/lib.rs` | `tools/netns_adversarial_probe.py` denies private/mixed IPv4 and IPv6 answers before any HTTP hit. Unit tests cover additional address and URL cases. The matrix is finite; URL/IP property and fuzz tests remain open. |
| DNS rebinding between calls or DNS substitution after validation | `SystemResolver` and `guarded_fetch` use `resolve_to_addrs` with the original host | The route-free probe changes an A answer between two calls in one MCP process; the second is denied with no second HTTP hit. SNI is observed as the original hostname. Reconnect within one call and a trusted-certificate hostname mismatch remain unproven. |
| Ambient proxy or credential forwarding | `Client::builder().no_proxy()`, no custom header/body fields in `validate_with_reservation` | The route-free probe sets dead `HTTP_PROXY` and `ALL_PROXY` values yet reaches the pinned fixture. The schema rejects unknown fields. This does not govern credentials or traffic from other tools. |
| URL secret exfiltration | `has_known_secret` and `high_entropy_segment` before `reserve_egress_call` and DNS | Six synthetic URL markers are denied before DNS/HTTP and absent from MCP output and stderr in the route-free probe. Detection is heuristic, incomplete, and limited to accepted URL input. Header/body exfiltration is not supported by this tool and has not been adversarially certified. |
| Recursive, cross-host, or private redirect traps | `Policy::none()` plus the redirection check in `guarded_fetch` | The route-free probe denies a redirect to private space, a self-loop, and a second approved host without following or resolving the destination. Redirect revalidation and atomic multi-hop budgeting are not implemented. |
| Slow first byte, byte drip, or late EOF | Reqwest connect/idle timeouts and `HTTP_TOTAL_TIMEOUT` checks in `guarded_fetch` | Controlled delayed-header, one-byte-per-second, and late-EOF fixtures deny without partial body. This is a total deadline and per-read idle timeout, not a sliding byte-rate detector. |
| Oversized, encoded, or malformed HTTP responses | Header count/byte checks, framing checks, encoding denial, and bounded read loop in `guarded_fetch` | The route-free probe covers 70 headers, a 24 KiB header, a 1 MiB parser header, conflicting framing, chunked overflow, and gzip/deflate bombs. The header cap is checked after Reqwest parsing; the current Hyper parser ceiling is dependency behavior, not a configured guard limit. Other encodings, wire-byte and expansion-ratio accounting, and concurrent resource limits remain open. |
| Hidden HTML links or indirect prompt injection | `supported_content_type` rejects declared HTML; `looks_like_html` blocks leading HTML signatures mislabeled as plain text; allowed responses set `untrusted_content: true` | The route-free probe denies declared HTML, a fake media type, and a leading hidden-link fragment labeled `text/plain`. It also demonstrates that JSON instruction-like text is returned unchanged. Prefixes and unrecognized tags can bypass the narrow HTML check; the marker does not sanitize or quarantine prompt injection. |
| MCP frame exhaustion and malformed RPC | `read_frame` and `handle` in `src/main.rs` | `tools/stdio_resource_probe.py` streams 160 MiB and 8 MiB hostile frames, checks bounded RSS and ping recovery. `tools/adversarial_stdio_probe.py` checks malformed messages and no secret echo. An indefinitely streaming frame can still consume CPU/time; full protocol and cancellation conformance remain open. |
| Excessive calls to one host | `CallBudget::reserve` and `reserve_egress_call` | Unit tests cover atomic per-host/minute and process/hour reservations; restart resets the budget. Concurrent live-client and multi-process budget behavior are not proven. |

## Client and release evidence

The [Codex CLI](client-codex-cli.md) and [Claude Code](client-claude-code.md) smoke tests demonstrate real client discovery, a blocked call, and approved GET/HEAD. [Inspector](../tools/inspector_smoke.py) and the [isolated socket probe](adversarial-netns.md) cover protocol and hostile fixture slices. No test here proves whole-agent egress coverage.

Cursor remains untested. An official Linux Cursor CLI package was inspected and run temporarily on this host, but `agent status` reported **Not logged in** and the MCP listing did not complete. No Cursor tool call was observed; the temporary package and test configuration were removed. A signed-in Cursor client must perform its own discovery, blocked-call, and approved-call smoke test before the client gate can close.

Other stable-release blockers include full MCP revision conformance, trusted TLS mismatch evidence, request and response resource/concurrency limits, broader secret handling, prompt-injection quarantine, redacted audit/correlation records, schema/property fuzzing, reproducible release artifacts, and human review. They remain tracked in [QUALITY_BAR.md](QUALITY_BAR.md).
