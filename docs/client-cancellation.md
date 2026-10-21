# Real-client cancellation and queue-saturation evidence

Status: experimental candidate observations, not release approval or universal client/UI certification.

## Scope and results, 2026-10-21

The optimized Linux x86_64 GNU archive candidate `ec96881e4ca9` has binary SHA-256 `93882fb0e55073efda897e7d3f020d6ebe2c4cb62009a70be72e622008ec9b19`. The production Rust implementation has not changed since that candidate. A transparent stdio bridge recorded only MCP method/ID/rule metadata. The real clients used their existing authenticated model services on the host; only the MCP child ran in a disposable route-free network namespace with controlled DNS/HTTP. No VM, public attack target, or runtime dependency was added.

| Client/version | Control tested | Matching MCP cancellation | Observed outcome |
| --- | --- | --- | --- |
| Claude Code 2.1.301 | Headless stream-JSON `interrupt` control request | Yes | Acknowledged interrupt, no cancelled-fetch reply, peer socket closed in about 1.01s while client remained live; subsequent guarded GET returned HTTP 200. |
| Codex CLI 0.151.0 | App-server `turn/interrupt` | No | The completed replay observed the fetch end via `EGRESS_RESPONSE_TOO_SLOW` at about 3.02s; recovery GET returned HTTP 200. Additional replays hit upstream HTTP 429 (one during recovery, another before the fixture started) and are inconclusive, not passing replays. |
| Cursor CLI 2026.10.19-6bbf2c4 | ACP `session/cancel` | No | Client reported a cancelled turn, but the fetch ended via `EGRESS_RESPONSE_TOO_SLOW` at about 3.01s; recovery GET, loopback denial and approved HEAD then passed. |

The socket timings are fixture-specific samples, not latency guarantees. For Codex and Cursor, a cancelled *agent turn* did not imply an MCP cancellation notification in these tested paths. The server continued its bounded request until its own policy ended it. This observation does not prove how every UI, other client version, transport or interrupt timing behaves. Desktop Stop buttons, terminal Escape keys, other DNS/TLS phases and saturated client-controlled queues remain separate tests. Do not claim prompt socket cancellation for these unverified paths.

Cursor was installed using the official HTTPS installer and the user completed browser login. The authenticated ACP client discovered the real MCP server. Its actual calls produced `EGRESS_INVALID_HOST` for loopback, and `EGRESS_ALLOWED` with HTTP 200 for controlled GET and HEAD. Private temporary MCP configuration and wire logs were removed after completed probes. Cursor may retain its own normal client history/settings; authentication remains installed for the user's other MCP chats.

The redacted [machine-readable record](evidence/client-cancellation-2026-10-21.json) distinguishes completed observations from inconclusive provider failures. No credentials or account identifiers are included.

## Reproduce an authenticated control-path observation

These optional **development** probes require Linux network namespaces, the source checkout, passwordless `sudo` for disposable network setup, an installed client, and existing normal client authentication. Model inference uses the client's account and may incur usage/cost. This is not a server-install or companion-skill requirement. No `sudo` is required for ordinary production stdio operation.

```bash
python3 tools/client_cancellation_probe.py claude /absolute/path/to/installed/outbound-guard-mcp
python3 tools/client_cancellation_probe.py codex /absolute/path/to/installed/outbound-guard-mcp
python3 tools/client_cancellation_probe.py cursor /absolute/path/to/installed/outbound-guard-mcp
```

Run one account-backed probe at a time when inference is throttled. The harness only approves the fixture's guarded-fetch permission, rejects other requested tool permissions, and uses an empty private workspace. It acknowledges the client's interrupt, observes the actual MCP wire behavior, checks peer closure while the client remains live, and attempts a recovery call. Cursor additionally exercises loopback denial and HEAD. A report with `matching_wire_cancellation: false` is an observed client limitation, **not a passing prompt-cancellation acceptance gate**. Provider errors must be recorded as inconclusive; do not equate them with a network guard defect. The harness removes its temporary namespace and private client/wire logs. Cleanup signals only PIDs belonging to that exact network namespace, never a host-wide process-name match.

## Historical queue saturation review (before the priority fix)

`test_saturated_cancellation` in the normal controlled network suite runs both protocol eras with one live fetch and nine ordinary requests, each carrying 60,000 padding bytes. Eight frames fill the channel; the ninth is reader-held, so a cancellation behind it cannot yet reach the control handler. In this fixture the fetch ends by its own slow-response rule. The test requires all nine queued replies, one correct audit decision, socket closure and a successful subsequent fetch; it checks sampled RSS below 64 MiB and descriptors below 64.

Debug samples were 8,792 KiB (legacy), 8,948 KiB (modern), and seven descriptors. These are finite sampled observations, **not proven upper bounds or OS process quotas**. Input frame bounds and queue capacity bound retained input, but saturation still delays control processing. The existing ten-second HTTP deadline and other phase/stream controls remain relevant even when clients omit cancellation. No claim is made that all queued work or process-wide memory/CPU has an aggregate deadline.

A separate Request Guard chat reviewed the new saturation test without edits/builds/VMs and found no actionable issue in this bounded interpretation. It specifically required that measured RSS/FD figures remain labeled samples. Strict control priority at queue saturation and client UI cancellation remain open in issue #65; this milestone adds evidence without silently waiving them.

## References

- [MCP stdio cancellation](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Codex app-server interruption](https://developers.openai.com/codex/app-server)
- [Cursor ACP control and MCP support](https://prod.cursor.com/docs/cli/acp)
- [Claude Agent SDK interrupt example](https://github.com/anthropics/claude-agent-sdk-python/blob/main/examples/streaming_mode.py)

The [current priority admission implementation](cancellation-priority.md) replaces the historical saturation behavior above. The dated client-control observations and JSON records remain historical evidence; they do not automatically certify a later release candidate or its client UI behavior.
