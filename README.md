# outbound-guard-mcp

Standalone outbound HTTP safety server for coding agents. **Experimental: the first runnable stdio server is not a production release.** The larger prototype lives on the [`codex/outbound-guard` branch of request-guard-mcp](https://github.com/rhamenator/request-guard-mcp/tree/codex/outbound-guard). This repository remains independently installable.

The current `guarded_fetch` call performs GET or HEAD only. It requires an exact DNS hostname in `OUTBOUND_GUARD_ALLOWED_HOSTS`, rejects every DNS answer if any is non-public, and pins the validated answer set for the connection. Ambient proxies are disabled. Raw ASCII control characters, userinfo, URL queries, fragments, nonstandard ports, request headers and bodies, redirects, encoded responses, declared HTML, leading HTML signatures mislabeled as plain text, ambiguous Content-Length framing, duplicate Content-Type or Content-Encoding fields, and transfer codings other than one plain `chunked` field are rejected. The response is limited to 256 KiB of UTF-8 content declared with an exact `text/plain` or `application/json` media type (optional parameters are accepted). Bodies labeled `application/json` must parse as one complete JSON value within the existing parser nesting limit; malformed, trailing, or excessively nested data returns `EGRESS_INVALID_JSON` without body text. HEAD and empty 204/205 responses do not require a JSON body. This checks syntax, not a JSON schema or prompt safety. The server retains at most 17 DNS answers and denies any set exceeding 16 before HTTP. DNS has a three-second caller deadline. HTTP operations have a three-second idle timeout; body reads also have a ten-second elapsed deadline after the request starts, checked between reads. A single blocked read can extend the elapsed time by up to the idle timeout. The OS resolver may allocate results internally before the iterator cap; that allocation is not controlled here. A timed-out OS lookup may continue in one background worker; further DNS attempts fail closed until it exits. An in-memory sliding window reserves at most 60 valid calls per host per minute and 1,000 calls per server process per hour before DNS; failed DNS or HTTP calls still consume a reservation, and restart resets these counters. Denials return structured rule and remediation fields. No allowlist means no egress. Invalid allowlist entries make the server fail at startup; the server never silently drops them.

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
python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)"
```

The smoke script uses the pinned official MCP Inspector CLI to verify `initialize`, strict `tools/list`, and a structured blocked `tools/call`. For an optional live GET and HEAD, run `python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)" --live https://postman-echo.com/get`; this sends requests to that external service. The October 2026 fresh-install check passed both calls. The script passes `OUTBOUND_GUARD_ALLOWED_HOSTS` to the Inspector's spawned server with `-e`; exporting it only in the Inspector's parent shell did not configure the child in this test. [Codex CLI 0.151.0](docs/client-codex-cli.md) and [Claude Code 2.1.301](docs/client-claude-code.md) smoke tests also verified blocked and allowed calls through real clients.

For the supported `2025-06-18` handshake, `initialize` requires a nonempty `protocolVersion`, an object `capabilities`, and `clientInfo` with nonempty string `name` and `version`. Malformed handshakes receive a JSON-RPC error. The server rejects tool requests before `initialize` and `notifications/initialized` complete, with JSON-RPC code `-32002`; `ping` remains available during setup. Repeating `initialize` on the same stdio session is rejected. The newer protocol remains release work.

Set your MCP client's stdio command to `outbound-guard-mcp` and its server environment to `OUTBOUND_GUARD_ALLOWED_HOSTS=the.exact.host`. No application credential is needed for the current GET/HEAD tool. The operator controls the allowlist and any network access costs; the tool sends the URL to the approved remote host. Client configuration formats differ, so verify `tools/list` and a guarded call in the chosen client before relying on it. Codex CLI 0.151.0 and Claude Code 2.1.301 passed setup smoke tests; other versions and Cursor remain separate release gates. A client approval policy can block a tool call before the server receives it.

The initial server rejects responses with more than 64 headers or 16 KiB of parsed header names and values; that check occurs after the HTTP library parses headers. The current pinned HTTP/1 parser rejects a 1 MiB header in CI, but Outbound Guard does not configure the parser ceiling itself. It does **not** yet enforce redirect revalidation, secret scanning in headers/bodies, trap detection, comprehensive HTML scrubbing, or full MCP 2026-07-28 conformance. It does not expose those features as tools. These remain release gates in [QUALITY_BAR.md](docs/QUALITY_BAR.md). The returned plain text and JSON are untrusted data. The leading-signature check can miss HTML after a prose prefix or an unrecognized tag; JSON can carry instruction-like text; the `untrusted_content` marker is advisory, not a prompt-injection sanitizer.

Stdio input frames are capped at 64 KiB. The [stdio resource probe](docs/adversarial-stdio.md) verifies recovery and bounded process memory for 160 MiB and 8 MiB hostile frames; the [isolated network probe](docs/adversarial-netns.md) records the current DNS and HTTP attack cases. The [threat model](docs/threat-model.md) maps current protections to code, evidence, and open gaps. These are partial release evidence.

The [companion skill](skills/outbound-guard/SKILL.md) tells a connected agent when and how to use the current tool. See [the extraction and verification plan](docs/PLAN.md). The project is GPL-3.0-or-later; see [LICENSE](LICENSE). Security reports follow [SECURITY.md](SECURITY.md).

## Candidate packaging

The [candidate packaging gate](docs/candidate-packaging.md) builds a Linux x86_64 archive with GPL license, project source, and provenance, plus a skill-only ZIP and SHA-256 checksums. It verifies the installed optimized executable with MCP, Inspector, and isolated hostile fixtures. These remain experimental local artifacts pending the release quality bar and human review.

Each server process permits one active `guarded_fetch`, spanning validation, budget reservation, DNS, TLS, and response reading. Concurrent Rust library callers receive audited `EGRESS_CONCURRENCY_LIMIT` denials before budget reservation or network work; retry after the active call completes. Stdio dispatch remains sequential, so queued stdio messages are handled after the current call. The limit does not coordinate separate processes or bound a client’s input queue. A completed or failed fetch releases the permit.

The [generated address-policy tests](docs/ip-policy.md#generated-policy-regression-evidence) compare IPv4/IPv6 decisions with a separate CIDR oracle and test forbidden answers at every DNS-answer position, without external network access. Run `cargo test --locked --test ip_policy_properties` to replay the fixed corpus.

URL secret signatures include the six documented GitHub token prefixes (`ghp_`, `gho_`, `github_pat_`, `ghu_`, `ghs_`, `ghr_`) followed by at least 20 ASCII letters, digits, underscores, or hyphens. Detection is conservative shape matching, not credential validation: synthetic or harmless lookalikes may be blocked, while shorter, transformed, unrecognized, or split secrets may pass. Do not send credentials through this tool.
