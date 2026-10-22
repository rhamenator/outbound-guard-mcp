# outbound-guard-mcp

Standalone outbound HTTP safety server for coding agents. **Experimental: the first runnable stdio server is not a production release.** The larger prototype lives on the [`codex/outbound-guard` branch of request-guard-mcp](https://github.com/rhamenator/request-guard-mcp/tree/codex/outbound-guard). This repository remains independently installable.

The current `guarded_fetch` call performs GET or HEAD only. It requires an exact DNS hostname in `OUTBOUND_GUARD_ALLOWED_HOSTS`, rejects every DNS answer if any is non-public, and pins the validated answer set for the connection. Ambient proxies are disabled. Raw ASCII control characters, userinfo, URL queries, fragments, nonstandard ports, request headers and bodies, redirects, encoded responses, declared HTML, leading HTML signatures mislabeled as plain text, ambiguous Content-Length framing, duplicate Content-Type or Content-Encoding fields, and transfer codings other than one plain `chunked` field are rejected. For GET, the response is limited to 256 KiB of UTF-8 content declared with an exact `text/plain` or `application/json` media type (no parameters or one optional `charset=utf-8` declaration, optionally double quoted and case insensitive; other, duplicate or malformed parameters are denied). Bodies labeled `application/json` must parse as one complete JSON value within the existing parser nesting limit; malformed, trailing, or excessively nested data returns `EGRESS_INVALID_JSON` without body text. HEAD and empty 204/205 responses do not require a JSON body. This checks syntax, not a JSON schema or prompt safety. Serialized HTTP requests have a conservative 4 KiB budget, checked before DNS; Unicode URL serialization can increase size. HTTP response stream reads, including framing, are capped at `max_return_bytes + 32 KiB`; headers are limited during parsing to 64 fields and a 16 KiB buffer including the status line. Response trailers are denied. Underlying TCP/TLS reads have a separate 1 MiB cap and writes 64 KiB; these count stream bytes, not IP headers, retransmissions or kernel buffers. The server retains at most 17 DNS answers and denies any set exceeding 16 before HTTP. DNS has a three-second caller deadline. HTTP/1 uses a three-second read timeout and a ten-second async total deadline spanning connect, TLS, headers and body. A pending network read is cancelled at the total deadline rather than waiting for its idle timer. Validated addresses are dialed directly, with the original hostname for Host/SNI and built-in root/hostname verification. DNS retains its separate three-second bound; these are separate phase budgets, not a ten-second whole-tool guarantee. Timer observation depends on runtime/OS scheduling. The OS resolver may allocate results internally before the iterator cap; that allocation is not controlled here. A timed-out OS lookup may continue in one background worker; further DNS attempts fail closed until it exits. An in-memory sliding window reserves at most 60 valid calls per host per minute and 1,000 calls per server process per hour before DNS; failed DNS or HTTP calls still consume a reservation, and restart resets these counters. Denials return structured rule and remediation fields. No allowlist means no egress. Invalid allowlist entries make the server fail at startup; the server never silently drops them.

```bash
export OUTBOUND_GUARD_ALLOWED_HOSTS=example.com,api.example.com
cargo run --locked
```

Configure an MCP client to launch the executable over stdio with this environment variable. Its first `tools/list` result advertises `guarded_fetch`. The client must send the actual request through this tool for its policy to apply. It cannot intercept traffic sent through unrelated tools or processes. The `ai-scraping-defense` projects may connect to it optionally, as they may connect to any MCP server.

## Optional operator CA certificate

For an approved HTTPS service using a private certificate authority, set the server environment variable `OUTBOUND_GUARD_EXTRA_CA_CERT` to an operator-controlled PEM certificate file. The server needs read permission on that regular file; it must contain exactly one certificate, be at most 64 KiB, and contain no private key. Invalid configuration stops startup. The certificate is loaded once; restart after changing it. It adds trust for all approved HTTPS hosts in that process, alongside the built-in roots, with hostname verification still required. Protect the file from modification by agents or untrusted users. The tool arguments cannot select a certificate. No client certificate authentication is implemented.

```bash
export OUTBOUND_GUARD_EXTRA_CA_CERT=/path/to/operator-ca.pem
```

## Audit decisions

Each completed `guarded_fetch` result includes a process-local `correlation_id` such as `egress-1`. Read `outbound-guard://logs/audit.json` through MCP `resources/read` to inspect the last 256 completed decisions in that server process. The resource is advertised by `resources/list`; it contains only correlation IDs, status, and rule codes. It stores no URLs, RPC IDs, request arguments, or response text. The oldest event is evicted at capacity. Any client attached to that server process can read this log; no extra credential or filesystem permission is needed. Restart clears the log and restarts the ID sequence. This is a volatile diagnostic log, without timestamps, persistence, subscriptions, or tamper resistance. It covers executed guarded calls, not protocol errors or traffic through other tools. An unavailable audit log blocks new guarded fetches before network execution; a failure recording a completed fetch suppresses its returned body but cannot undo that fetch.

Read the log using the same connected MCP session:

```json
{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"outbound-guard://logs/audit.json"}}
```

Each event has this shape:

```json
{"correlation_id":"egress-1","status":"BLOCKED","rule":"EGRESS_SECRET_DETECTED"}
```

## Install and verify a client connection


From a clone of this repository, install the binary independently of the source checkout:

```bash
cargo install --path . --locked
# Optional development smoke client; requires Node.js and npm.
npm ci --prefix tools/mcp-inspector-probe --ignore-scripts --no-audit --no-fund
python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)"
```

The smoke script uses the separately installed, lockfile-pinned official MCP Inspector CLI (no on-demand npx resolution) to verify `initialize`, strict `tools/list`, and a structured blocked `tools/call`. For an optional live GET and HEAD, run `python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)" --live https://postman-echo.com/get`; this sends requests to that external service. The October 2026 fresh-install check passed both calls. The script uses a temporary read-only Inspector server configuration to set the child environment and `protocolEra`. It verifies explicit legacy `2025-06-18`, automatic modern discovery, and pinned modern `2026-07-28`. Inspector 2.5.0 silently ignores an unsupported `--protocol-era` CLI option; that option must not be used as evidence of era selection. [Codex CLI 0.151.0](docs/client-codex-cli.md) and [Claude Code 2.1.301](docs/client-claude-code.md) smoke tests also verified blocked and allowed calls through real clients.

For the supported `2025-06-18` handshake, `initialize` requires a nonempty `protocolVersion`, an object `capabilities`, and `clientInfo` with nonempty string `name` and `version`. Malformed handshakes receive a JSON-RPC error. The server rejects tool requests before `initialize` and `notifications/initialized` complete, with JSON-RPC code `-32002`; `ping` remains available during setup. Repeating `initialize` on the same stdio session is rejected. Modern `2026-07-28` uses per-request metadata and `server/discover` instead of a handshake. Both paths are covered by the [conformance probes](docs/protocol-conformance.md); broader review and the final-client matrix remain release gates.

Set your MCP client's stdio command to `outbound-guard-mcp` and its server environment to `OUTBOUND_GUARD_ALLOWED_HOSTS=the.exact.host`. No application credential is needed for the current GET/HEAD tool. The operator controls the allowlist and any network access costs; the tool sends the URL to the approved remote host. Client configuration formats differ, so verify `tools/list` and a guarded call in the chosen client before relying on it. Codex CLI 0.151.0 and Claude Code 2.1.301 passed setup smoke tests; other versions and Cursor remain separate release gates. A client approval policy can block a tool call before the server receives it.

The HTTP/1 parser is configured with a 64-header/16 KiB buffer cap, and guarded stream counters bound request, response framing/body and TLS/TCP bytes. It does **not** yet enforce redirect revalidation, secret scanning in headers/bodies, trap detection, comprehensive HTML scrubbing, or all optional MCP extensions. Full revision conformance and client compatibility remain independent review gates. It does not expose those features as tools. These remain release gates in [QUALITY_BAR.md](docs/QUALITY_BAR.md). The returned plain text and JSON are untrusted data. The leading-signature check can miss HTML after a prose prefix or an unrecognized tag; JSON can carry instruction-like text; the `untrusted_content` marker is advisory, not a prompt-injection sanitizer.

Once input starts, each stdio frame must complete within 10 seconds. An idle client remains connected; a partial-frame timeout terminates the process without dispatching partial input. An executing fetch can delay input-deadline observation. Each reply has a separate three-second serialization/write/flush budget; a non-reading client causes process termination and may receive an incomplete transport frame, which must be discarded before reconnecting. Stdio input frames are capped at 64 KiB including any LF or CRLF delimiter; an EOF-terminated frame has no delimiter bytes. Exact-limit and fragmented-reader regressions are covered by the [framing tests](docs/adversarial-stdio.md#framing-boundaries-and-fragmentation). The [stdio resource probe](docs/adversarial-stdio.md) verifies recovery and bounded process memory for 160 MiB and 8 MiB hostile frames; the [isolated network probe](docs/adversarial-netns.md) records the current DNS and HTTP attack cases. The [threat model](docs/threat-model.md) maps current protections to code, evidence, and open gaps. These are partial release evidence.

The [companion skill](skills/outbound-guard/SKILL.md) tells a connected agent when and how to use the current tool. See [the extraction and verification plan](docs/PLAN.md). The project is GPL-3.0-or-later; see [LICENSE](LICENSE). Security reports follow [SECURITY.md](SECURITY.md).

## Candidate packaging

The [candidate packaging gate](docs/candidate-packaging.md) builds a Linux x86_64 archive with GPL license, project source, verified dependency source archives, and provenance, plus a skill-only ZIP and SHA-256 checksums. It verifies the installed optimized executable with MCP, Inspector, and isolated hostile fixtures. These remain experimental local artifacts pending the release quality bar and human review.

Each server process permits one active `guarded_fetch`, spanning validation, budget reservation, DNS, TLS, and response reading. Concurrent Rust library callers receive audited `EGRESS_CONCURRENCY_LIMIT` denials before budget reservation or network work; retry after the active call completes. Fetch execution remains sequential; one bounded input-reader thread can process cancellation notifications while a fetch is active. The limit does not coordinate separate processes or bound a client’s input queue. A completed or failed fetch releases the permit.

The [generated address-policy tests](docs/ip-policy.md#generated-policy-regression-evidence) compare IPv4/IPv6 decisions with a separate CIDR oracle and test forbidden answers at every DNS-answer position, without external network access. Run `cargo test --locked --test ip_policy_properties` to replay the fixed corpus.

URL secret signatures include the six documented GitHub token prefixes (`ghp_`, `gho_`, `github_pat_`, `ghu_`, `ghs_`, `ghr_`) followed by at least 20 ASCII letters, digits, underscores, or hyphens. Detection is conservative shape matching, not credential validation: synthetic or harmless lookalikes may be blocked, while shorter, transformed, unrecognized, or split secrets may pass. Do not send credentials through this tool.

The isolated Linux network probe also runs its repeated-call workloads under a test-only 64-file-descriptor limit and checks RSS high-water below 128 MiB. It requires util-linux `prlimit` and readable `/proc` process metrics; see [resource evidence and limitations](docs/adversarial-netns.md#repeated-call-descriptor-and-memory-evidence). These test thresholds are not production server settings.

Custom stdio clients must send MCP parameters as JSON objects. Optional `_meta` must also be an object; request `progressToken` values may be strings or numbers. Malformed shapes are rejected before tool dispatch, and invalid initialized-notification metadata does not complete the handshake. Valid extension metadata is accepted without being reflected in tool output. Progress notifications remain unsupported. Cancellation handling is described below.

Candidate server archives include a [dependency inventory and shipped notices](docs/dependencies.md#candidate-inventory-and-notices), with crate archive hashes checked against Cargo.lock. This supports review of the transitive graph; it does not certify dependency safety or license compatibility.

### Cooperative cancellation

Rust callers can use `guarded_fetch_cancellable(args, allowed_hosts, &AtomicBool)`, with a fresh shared flag per call. Set the flag to `true` from another thread to request cancellation. Observed cancellation returns audited `EGRESS_CANCELLED` without partial body text and releases the active-fetch permit. The DNS waiter checks cancellation at 25 ms intervals; scheduler delays can increase observation time. Native OS resolver work may continue after cancellation, retaining the single-worker gate until it exits. Pending HTTP I/O also checks cancellation at 25 ms intervals by retaining one total-deadline future across receive slices; cancellation drops that future and its runtime, closing pending sockets. This includes silent header/body waits and remains subject to scheduling. A pre-cancelled call consumes no rate reservation; reservations already spent are not refunded. The normal `guarded_fetch` API is unchanged.

Stdio clients can now send a valid `notifications/cancelled` with the exact pending `tools/call` request ID. String and integer IDs are distinct. An observed cancellation is audited as `EGRESS_CANCELLED`, but the server sends no tool response for that cancelled request. Unknown, completed or malformed cancellations are ignored; `initialize` is never registered for cancellation. Reasons are discarded rather than logged. Cancellation races completion, so a response may already be in flight.

The input queue admits eight ordinary frames. When full, the reader queues a correlated `-32000` / `MCP_INPUT_BUSY` error instead of waiting, so a later cancellation can still be read. Rejected work is not executed and spends no budget or audit entry; wait for outstanding replies before retrying. Busy replies may arrive before earlier admitted replies: correlate by ID. At most eight busy replies are retained; further overload or an uncorrelatable overflow terminates the connection with a fixed diagnostic and cancels admitted fetches. EOF drains admitted work. Pending DNS/network operations still observe cancellation cooperatively, not as an OS-level interrupt. See [admission/cancellation evidence](docs/cancellation-priority.md).

### Structured decision contract

`tools/list` advertises an `outputSchema` with separate `SAFE` and `BLOCKED` branches. Blocked results contain only status, rule, remediation and an optional correlation ID (audit failure can occur before allocation); fetched URLs and bodies are forbidden in that branch. Allowed results require the normalized URL, HTTP status, body text, correlation ID and `untrusted_content: true`. `SAFE` means egress policy passed, not that HTTP succeeded or content is trustworthy. The official SDK probe validates real allow/block results and rejects malformed result mutations. This uses the existing [MCP 2025-06-18 output-schema mechanism](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#output-schema); newer protocol conformance remains open.

### Slow-transfer policy

After response headers, a three-second grace period allows short small responses to finish. Longer responses must deliver at least 1,500 bytes across the preceding three completed one-second buckets (500 bytes/second average). A fixed four-bucket counter detects slow drips even after an initial burst; `EGRESS_RESPONSE_TOO_SLOW` returns no partial body and is audited. Checks occur when async body reads complete, so the existing idle timeout can delay detection. Legitimate slow or small long-lived responses can be rejected; this narrow tool does not support streaming subscriptions. The ten-second request deadline and size limits still apply independently.

### Verify an installation

```sh
outbound-guard-mcp --help
outbound-guard-mcp --version
outbound-guard-mcp --check-config
```

`--check-config` validates the configured exact-host allowlist and optional CA file, then exits. Its JSON reports `valid`, `scope: "startup"`, the deduplicated `allowed_host_count`, and `network_checked: false`. Empty configuration is valid and denies all egress. No hostnames, certificate contents or file paths are printed. Invalid configuration exits nonzero with a fixed diagnostic. Help/version work even with invalid configuration. Unknown or combined arguments fail rather than starting stdio. Launch the MCP server **without arguments** in client configuration. This check does not establish destination reachability, TLS interoperability, MCP client setup or production readiness; those need the documented client/fixture tests. `tools/cli_smoke.py` tests these commands in CI and against the installed candidate.

### Provider token signatures

The URL scanner also blocks GitLab’s documented token prefixes and the PyPI `pypi-` prefix followed by at least 20 ASCII alphanumeric, underscore or hyphen characters. This reuses the existing signature scanner before budget reservation and DNS. It is conservative shape matching, not credential validation: token-like public text may be rejected, shorter or custom-prefix secrets may escape signatures, and the entropy heuristic is not complete exfiltration detection. GitLab administrators can customize personal-token prefixes. See the [provider corpus and sources](docs/adversarial-netns.md#gitlab-and-pypi-token-signatures).

### Mislabeled HTML fragments

The leading-HTML signature check also covers common fragment roots such as div/span containers, forms, inputs, images, metadata/link elements, embedded objects, templates, noscript and paragraphs. A plain-text response beginning with these tags is denied as EGRESS_HTML_MISLABELED without returning its body. Matching is case-insensitive and requires a tag boundary. This is a bounded leading-signature heuristic, not DOM rendering, CSS visibility analysis, a complete HTML parser or prompt-injection sanitization. Markup later in plain text and HTML strings inside valid JSON can remain untrusted output.

### Absolute DNS lookups

The system resolver receives an absolute hostname (a terminal dot is added only to its lookup input), preventing search-domain/ndots expansion from choosing a different name. The approved hostname in the URL, HTTP Host and TLS SNI stays unchanged, and every returned address still passes policy before connection pinning. Controlled Linux tests use a hostile search suffix and ndots:5 and require zero suffixed queries. This does not replace trust in the operating system resolver/hosts configuration, certify every platform resolver, or add DNSSEC validation.

### HEAD behavior

`guarded_fetch` with `method: "HEAD"` returns the guarded URL and HTTP status with empty `body_text`; it does not return arbitrary response headers. Since no representation body is read, the GET media-type and JSON-body requirements do not apply. Header count/size, ambiguous framing/metadata, encoding, redirect, DNS and timeout policies still apply. A successful HEAD does not authorize a subsequent GET or establish that its content is safe. Controlled tests and the official SDK verify the method actually sent, empty-body results and hostile header/redirect/timeouts.

### Credential-free requests

The current tool does not support authenticated sessions or cookie persistence. Controlled same-process GET/HEAD tests verify that Set-Cookie and a Basic authentication challenge do not produce Cookie, Authorization, Proxy-Authorization, provider-token or Referer headers on later calls, retries, or redirect traffic. Four synthetic credential environment variables are also checked for request/result/audit isolation. A returned HTTP 401 can still be a SAFE policy decision with untrusted text; it does not mean authentication succeeded. See the [credential-isolation evidence and scope](docs/adversarial-netns.md#credential-isolation-across-calls).

Release preparation is tracked in the [evidence checklist](docs/RELEASE_CHECKLIST.md), [unreleased changelog](CHANGELOG.md), and [issue #65](https://github.com/rhamenator/outbound-guard-mcp/issues/65). Passing individual probes does not approve a stable release.

The synchronous Rust library API must be called outside an existing Tokio runtime (use a blocking worker when embedding in async software). Calls made inside a runtime return `EGRESS_CLIENT_FAILURE` before validation or network work rather than panicking.

Modern custom clients must include protocol version `2026-07-28` and a client-capabilities object in every request’s `_meta`; ordinary MCP clients manage this themselves. Modern results are typed, discovery/list/read caches are private with zero TTL, and unsupported versions receive structured negotiation errors. Metadata identity is not authorization. See the [implemented surface and limits](docs/protocol-conformance.md).

Real-client control-path evidence: Claude Code 2.1.301 emitted MCP cancellation in the tested stream-control path; Codex CLI 0.151.0 app-server and Cursor CLI 2026.10.19-6bbf2c4 ACP cancellation did not. Their fetches ended at the server's own deadline. Agent-turn cancellation is therefore not a guarantee of immediate network cancellation. See the [client/cancellation evidence](docs/client-cancellation.md). Desktop buttons and terminal keys remain unverified. Ordinary queue saturation no longer blocks the reader; extreme overload terminates the connection rather than retaining unbounded work.

For release engineering, [compare independently built candidates offline](docs/candidate-packaging.md#independent-candidate-comparison). The first local/CI comparison detected a compiler and executable mismatch; this gate remains open.

Source builds select Rust/Cargo 1.99.1 through `rust-toolchain.toml`; the minimum supported compiler remains 1.89 and is tested separately. Candidate packaging rejects a selected compiler/Cargo version that differs from the exact build pin. See [compiler evidence](docs/candidate-packaging.md#compilerbuild-evidence).

For independent native rebuilds, use the [digest-pinned candidate builder](docs/candidate-packaging.md#pinned-native-candidate-builder). It requires Docker during packaging; installed server binaries do not require Docker.

A timed-out OS DNS lookup may continue after the three-second tool DNS deadline. While that single lookup is still running, `EGRESS_DNS_BUSY` denies new lookups for every host; wait before retrying and do not bypass the guard. Spent budgets remain counted. [Live resolver-stall tests](docs/adversarial-netns.md#live-os-dns-worker-exhaustion-and-recovery) check one-worker retention, no extra DNS/HTTP, late-result discard and recovery in both protocol modes.

The [silent TLS cancellation fixture](docs/adversarial-netns.md#cancellation-during-a-silent-tls-handshake) receives a ClientHello but sends no handshake response. Both protocol modes must close the socket promptly after MCP cancellation, suppress the cancelled reply and recover. This does not certify every network state or make a client send cancellation notifications.

### Optional Linux deployment quotas

See [process limits and recovery](docs/linux-deployment-limits.md) for a tested user-systemd/cgroup-v2 probe and stdio wrapper. OS limits can disconnect a client before structured errors; audit and rate state reset on restart. This optional deployment recipe does not change the experimental release status.
