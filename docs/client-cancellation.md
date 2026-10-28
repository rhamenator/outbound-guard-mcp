# Real-client cancellation and queue-saturation evidence

Status: experimental candidate observations, not release approval or universal client/UI certification.

## Trusted-main Debian candidate replay, 2026-10-28

The independently rebuilt main candidate from source `8b76b439ca53`, with
signed GitHub build provenance, was extracted from the checksum-verified
archive and exercised through the
existing authenticated Claude Code 2.1.301, Codex CLI 0.151.0 and Cursor CLI
2026.10.19-6bbf2c4 clients. The executable SHA-256 is
`7bfe987a8b7a126488c3b17d4ec12ce57a5072f1a5ad6735f7ce62e1c8527407`.
Each client completed an explicit native skill path with a loopback denial and
controlled GET/HEAD successes. Each then completed a separate live-client
control-path replay and a successful recovery GET, loopback denial and HEAD.
The [redacted six-run record](evidence/native-client-replay-2026-10-28.json)
binds source, artifact, skill ZIP, executable, client versions and outcomes.

Claude delivered one matching MCP cancellation and the peer closed in 0.061s
without a cancelled tool reply. Codex and Cursor acknowledged their respective
turn controls but did not send MCP cancellation; their sockets closed after
the server's roughly three-second response deadline, with a bounded denial
reply. All three clients remained live. These observations cover explicit
skill and control API paths, not desktop/terminal Stop controls, native queue
saturation, automatic skill triggering, or traffic sent by other tools. The
broader hostile DNS/HTTP and release gates remain open. The Debian installer
itself is unsigned.

## Scope and results, 2026-10-21

The optimized Linux x86_64 GNU archive candidate `ec96881e4ca9` has binary SHA-256 `93882fb0e55073efda897e7d3f020d6ebe2c4cb62009a70be72e622008ec9b19`. A transparent stdio bridge recorded only MCP method/ID/rule metadata. The real clients used their existing authenticated model services on the host; only the MCP child ran in a disposable route-free network namespace with controlled DNS/HTTP. No VM, public attack target, or runtime dependency was added. Later source changes and candidate replays are recorded below and above this historical section.

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

## Fresh CI archive replay — 2026-10-22

All three authenticated control probes were rerun sequentially against a fresh extraction of the signed CI archive for source `5c937811120a865564240b693f8bf558fd909ab3`. The archive and skill ZIP passed their checksum manifest; executable SHA-256 was `6549e77a5b450c630a3909f43d9bdf2521f820ec599ad9528c5df8e74d9e8388`. See the [redacted replay record](evidence/client-cancellation-2026-10-22.json) for archive/skill hashes and CI/provenance links.

| Client/version | Wire cancellation | Sample socket closure after interrupt | Recovery |
| --- | --- | --- | --- |
| Claude Code 2.1.301 stream-JSON interrupt | Matching notification; cancelled reply suppressed | 0.061s | Guarded GET HTTP200 |
| Codex CLI0.151.0 app-server turn/interrupt | No notification; tool returned its own slow-response denial | 3.019s | Guarded GET HTTP200 |
| Cursor CLI2026.10.19-6bbf2c4 ACP session/cancel | No notification; tool returned its own slow-response denial | 3.015s | Guarded GET HTTP200; loopback denied; HEAD HTTP200 |

Each client acknowledged its control interrupt and remained live. These are single fixture-specific timing samples. The server's new cancellation handling does not make Codex or Cursor deliver notifications in those tested paths; their prompt-cancellation acceptance remains unmet. The fresh extraction and temporary MCP configuration exercise an installed archive, while normal existing account authentication is reused. Desktop/terminal controls, saturated client queues and all network phases remain untested by this client replay. Historical records above remain dated evidence; no later artifact or production-readiness approval is implied.

## TLS-patched installed archive replay — 2026-10-22

After the WebPKI/root advisory correction, all three control probes were rerun sequentially against a fresh extraction of source `174a2d0d3ba9393f6ffa35aa9e2db15330093509`'s signed CI archive. Its executable hash is `ca4912a67ab4e1c3509508fc7e9ac46824715e742d153f166431f74019770046`. The archive/skill checksum manifest passed, installed inventory identifies `rustls-webpki`0.103.16 and `webpki-roots`1.0.10, and the skill ZIP contains exactly the top-level skill's SKILL.md and GPL license with required frontmatter. The [redacted patched-candidate record](evidence/client-cancellation-2026-10-22-tls-patched.json) retains exact hashes and client results.

Claude Code2.1.301 emitted matching cancellation, suppressed the cancelled reply and closed its socket in0.061s; recovery GET returned200. Codex CLI0.151.0 still omitted cancellation and reached the guard's slow-response denial in3.014s, then recovered with GET200. Cursor CLI2026.10.19-6bbf2c4 likewise omitted cancellation and ended in3.015s; recovery GET200, loopback denial and HEAD200 passed. All acknowledged the client control interrupt and remained live; no provider failures occurred in these completed replays.

These are single control-path samples, not latency guarantees or desktop/terminal control coverage. Only Cursor ran the extra denial/HEAD sequence here. Existing authentication was reused, while MCP configuration and extraction were fresh. The historical pre-patch records above do not establish the patched binary's behavior; conversely, this replay does not waive remaining client/UI, implementation or human review gates. Older archives with the disclosed affected dependencies should be rebuilt, not selected merely because their historical tests passed.


## Replay after the framing harness candidate

The [2026-10-22 installed-candidate replay](evidence/client-cancellation-2026-10-22-frame-candidate.json) uses source23b9cdc6c350, binary SHA256 `9c12b359928f78f2f855e8c3cd4ae5137c40060e03155af34d30e6e28f73e8d1`, and a fresh checksum-verified CI archive extraction. The clean skill ZIP contains only SKILL.md and LICENSE; native skill activation was not tested. All three clients now ran recovery GET, loopback denial and HEAD200 controls through the same live client after interrupt acknowledgment.

Claude Code2.1.301 sent matching MCP cancellation, closed the fixture socket in0.061s and suppressed the cancelled reply. Codex CLI0.151.0 and Cursor CLI2026.10.19-6bbf2c4 acknowledged their control interrupts but sent no MCP cancellation; their calls ended with `EGRESS_RESPONSE_TOO_SLOW` in3.012s and2.994s respectively. Both then passed all three recovery/denial/HEAD controls. These remain missing client-cancellation delivery observations, not passing prompt-cancellation gates or server failures to honor a delivered notification.

The probe waits for Codex's recovery turn to complete and Cursor's prompt result before sending their next control sequence, then requires exact four-fetch/two-HTTP200 outcomes for every client. Only redacted metadata is retained; private configs/transcripts and owned namespaces are cleaned up. These are finite control-API samples, not desktop/terminal UI coverage, saturated queues, all network phases or stable-release approval. Older candidate results are not automatically transferred to this binary.

## RPC-fuzz candidate replay, 2026-10-23

The separately installed signed candidate from source `96ef82ca08f1` was replayed after its executable identity changed. [Exact package/binary/skill/client evidence](evidence/native-client-replay-2026-10-23.json) records the six successful probe runs and limitations. Claude Code2.1.301 delivered one matching MCP cancellation, suppressed the cancelled reply and closed the peer in0.061seconds. Codex CLI0.151.0 and Cursor2026.10.19-6bbf2c4 acknowledged their app-server/ACP turn controls but sent no MCP cancellation; each slow response closed under the server's own deadline in about3.02seconds and its denial reply remained present. These are not passing prompt-cancellation delivery cases. Each client remained live and completed recovery GET200, loopback denial and HEAD200.

Each also completed its explicit clean-ZIP skill workflow against this executable: Claude's native Skill invocation succeeded, Codex discovered the enabled installed skill and completed an explicit skill-input turn, and Cursor completed a native read of the installed project skill. All three then made the expected denial/GET/HEAD calls. These distinct observations establish the exercised explicit loading paths, not automatic triggering, adherence to every instruction or equivalent Skill-tool acknowledgments across clients.

The existing opt-in helper, controlled route-free DNS/HTTP fixtures and normal client authentication were reused. Only one client ran at a time. The archive/extracted binary hashes matched the exact CI-verified signed candidate; this records checksum binding to that evidence, not a separate local cryptographic attestation-verifier run. The ZIP still contains only top-level `outbound-guard/SKILL.md` and LICENSE. Private workspaces and owned fixture namespaces/processes were removed. Client authentication/configuration, skills and server runtime were unchanged. Desktop/terminal controls, native saturated queues and other release gates remain unproven.
