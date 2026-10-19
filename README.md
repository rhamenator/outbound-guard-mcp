# outbound-guard-mcp

Standalone outbound HTTP safety server for coding agents. **Experimental: the first runnable stdio server is not a production release.** The larger prototype lives on the [`codex/outbound-guard` branch of request-guard-mcp](https://github.com/rhamenator/request-guard-mcp/tree/codex/outbound-guard). This repository remains independently installable.

The current `guarded_fetch` call performs GET or HEAD only. It requires an exact DNS hostname in `OUTBOUND_GUARD_ALLOWED_HOSTS`, rejects every DNS answer if any is non-public, and pins the validated answer set for the connection. Ambient proxies are disabled. Userinfo, URL queries, fragments, nonstandard ports, request headers and bodies, redirects, encoded responses, HTML, and ambiguous Content-Length framing are rejected. The response is limited to 256 KiB of UTF-8 plain text or JSON. DNS has a three-second caller deadline. HTTP operations have a three-second idle timeout; body reads also have a ten-second elapsed deadline after the request starts, checked between reads. A single blocked read can extend the elapsed time by up to the idle timeout. A timed-out OS lookup may continue in one background worker; further DNS attempts fail closed until it exits. An in-memory sliding window reserves at most 60 valid calls per host per minute and 1,000 calls per server process per hour before DNS; failed DNS or HTTP calls still consume a reservation, and restart resets these counters. Denials return structured rule and remediation fields. No allowlist means no egress. Invalid allowlist entries make the server fail at startup; the server never silently drops them.

```bash
export OUTBOUND_GUARD_ALLOWED_HOSTS=example.com,api.example.com
cargo run --locked
```

Configure an MCP client to launch the executable over stdio with this environment variable. Its first `tools/list` result advertises `guarded_fetch`. The client must send the actual request through this tool for its policy to apply. It cannot intercept traffic sent through unrelated tools or processes. The `ai-scraping-defense` projects may connect to it optionally, as they may connect to any MCP server.

## Install and verify a client connection

From a clone of this repository, install the binary independently of the source checkout:

```bash
cargo install --path . --locked
python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)"
```

The smoke script uses the pinned official MCP Inspector CLI to verify `initialize`, strict `tools/list`, and a structured blocked `tools/call`. For an optional live GET and HEAD, run `python3 tools/inspector_smoke.py "$(command -v outbound-guard-mcp)" --live https://postman-echo.com/get`; this sends requests to that external service. The October 2026 fresh-install check passed both calls. The script passes `OUTBOUND_GUARD_ALLOWED_HOSTS` to the Inspector's spawned server with `-e`; exporting it only in the Inspector's parent shell did not configure the child in this test.

Set your MCP client's stdio command to `outbound-guard-mcp` and its server environment to `OUTBOUND_GUARD_ALLOWED_HOSTS=the.exact.host`. No application credential is needed for the current GET/HEAD tool. The operator controls the allowlist and any network access costs; the tool sends the URL to the approved remote host. Client configuration formats differ, so verify `tools/list` and a guarded call in the chosen client before relying on it. Codex, Claude Code, and Cursor setup checks remain separate release gates.

The initial server does **not** yet enforce a response header size cap, redirect revalidation, secret scanning in headers/bodies, trap detection, HTML scrubbing, or full MCP 2026-07-28 conformance. It does not expose those features as tools. These remain release gates in [QUALITY_BAR.md](docs/QUALITY_BAR.md). The returned plain text and JSON are untrusted data.

Stdio input frames are capped at 64 KiB. The [stdio resource probe](docs/adversarial-stdio.md) verifies recovery and bounded process memory for 160 MiB and 8 MiB hostile frames; the [isolated network probe](docs/adversarial-netns.md) records the current DNS and HTTP attack cases. These are partial release evidence.

The [companion skill](skills/outbound-guard/SKILL.md) tells a connected agent when and how to use the current tool. See [the extraction and verification plan](docs/PLAN.md). The project is GPL-3.0-or-later; see [LICENSE](LICENSE). Security reports follow [SECURITY.md](SECURITY.md).
