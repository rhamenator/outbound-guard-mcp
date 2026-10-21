# Claude Code client smoke test

On 2026-10-19, Claude Code 2.1.301 connected to the built Outbound Guard server over stdio. A private temporary MCP configuration exposed only `guarded_fetch` to a restricted, non-persistent Claude Code session. No normal Claude Code configuration was changed, and the temporary configuration and session output were removed after the test.

The real client discovered and called `mcp__outbound_guard__guarded_fetch`. A loopback URL returned `EGRESS_INVALID_HOST` with `BLOCKED`. With only `postman-echo.com` allowlisted, GET and HEAD calls to `https://postman-echo.com/get` each returned `EGRESS_ALLOWED` and HTTP 200. The public echo endpoint may change or become unavailable.

For a normal installation, install the binary with `cargo install --path . --locked` and create an MCP configuration for Claude Code such as:

```json
{
  "mcpServers": {
    "outbound_guard": {
      "command": "outbound-guard-mcp",
      "args": [],
      "env": {"OUTBOUND_GUARD_ALLOWED_HOSTS": "postman-echo.com"}
    }
  }
}
```

Load that file with `claude --mcp-config <path-to-config> --strict-mcp-config`, then ask Claude Code to call `guarded_fetch` with a loopback URL before trying an approved host. The test used `--restricted`, `--allowedTools mcp__outbound_guard__guarded_fetch`, and `--permission-mode dontAsk`; it did not bypass client permissions. The tool needs no application credential, but the approved destination sees the URL and may impose its own network or usage costs. Replace the example host with exact operator-approved hosts and retain the client's normal tool approval policy.

This proves discovery, a structured denial, and approved GET/HEAD through the tested Claude Code version. It does not prove that Claude Code routes other HTTP tools through Outbound Guard or that other versions and clients behave the same way. Cursor and remaining release criteria are tracked in [QUALITY_BAR.md](QUALITY_BAR.md).

## Corrected candidate replay, 2026-10-21

Fresh archive candidate `ec96881e4ca9` (after the independent cancellation review correction) passed discovery and three actual tool calls: loopback returned `EGRESS_INVALID_HOST`; approved GET and HEAD returned `EGRESS_ALLOWED` with HTTP 200. [Redacted machine-readable evidence](evidence/client-smoke-2026-10-21.json) records the binary/package/skill checksums, exact client versions, arguments, permissions and remaining gaps. The extracted binary and client configuration lived outside the checkout. A temporary OpenSnitch rule applied only to that executable and was removed after replay. Initial Claude calls before firewall authorization failed closed with `EGRESS_NETWORK_FAILURE`; those are not counted as passing allow cases.

Claude Code 2.1.301 used `--restricted --strict-mcp-config --allowedTools mcp__outbound_guard__guarded_fetch --tools "" --permission-mode dontAsk --no-session-persistence`. The client retained its existing authentication; temporary configuration exposed no other MCP server or built-in tool.

This is candidate evidence, not final stable-release certification. Client UI cancellation, authenticated Cursor and the other quality-bar gates remain open.
