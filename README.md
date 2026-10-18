# outbound-guard-mcp

Standalone outbound HTTP safety server for coding agents. **Experimental: the first runnable stdio server is not a production release.** The larger prototype lives on the [`codex/outbound-guard` branch of request-guard-mcp](https://github.com/rhamenator/request-guard-mcp/tree/codex/outbound-guard). This repository remains independently installable.

The current `guarded_fetch` call performs GET or HEAD only. It requires an exact DNS hostname in `OUTBOUND_GUARD_ALLOWED_HOSTS`, rejects every DNS answer if any is non-public, and pins the validated answer set for the connection. Ambient proxies are disabled. Userinfo, URL queries, fragments, nonstandard ports, request headers and bodies, redirects, encoded responses, and HTML are rejected. The response is limited to 256 KiB of UTF-8 plain text or JSON. DNS has a three-second caller deadline and HTTP has a ten-second timeout after resolution. A timed-out OS lookup may continue in one background worker; further DNS attempts fail closed until it exits. Denials return structured rule and remediation fields. No allowlist means no egress. Invalid allowlist entries make the server fail at startup; the server never silently drops them.

```bash
export OUTBOUND_GUARD_ALLOWED_HOSTS=example.com,api.example.com
cargo run --locked
```

Configure an MCP client to launch the executable over stdio with this environment variable. Its first `tools/list` result advertises `guarded_fetch`. The client must send the actual request through this tool for its policy to apply. It cannot intercept traffic sent through unrelated tools or processes. The `ai-scraping-defense` projects may connect to it optionally, as they may connect to any MCP server.

The initial server does **not** yet enforce a response header size cap, budgets, redirect revalidation, secret scanning in headers/bodies, trap detection, HTML scrubbing, or full MCP 2026-07-28 conformance. It does not expose those features as tools. These remain release gates in [QUALITY_BAR.md](docs/QUALITY_BAR.md). The returned plain text and JSON are untrusted data.

The [companion skill](skills/outbound-guard/SKILL.md) tells a connected agent when and how to use the current tool. See [the extraction and verification plan](docs/PLAN.md). The project is GPL-3.0-or-later; see [LICENSE](LICENSE). Security reports follow [SECURITY.md](SECURITY.md).
