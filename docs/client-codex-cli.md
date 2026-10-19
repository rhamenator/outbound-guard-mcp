# Codex CLI client smoke test

On 2026-10-19, Codex CLI 0.151.0 connected to a fresh `cargo +stable install --offline --path . --locked --root <private-test-root>` build of Outbound Guard over stdio. The install, Codex configuration, and Codex session lived in a private temporary directory and were removed after the test. No repository file or normal Codex configuration was changed.

The real client made three `guarded_fetch` calls. A loopback URL returned structured `EGRESS_INVALID_HOST` with `BLOCKED`. With only `postman-echo.com` allowlisted, a GET and a HEAD to `https://postman-echo.com/get` each returned `EGRESS_ALLOWED` and HTTP 200. Official MCP Inspector 2.5.0 also passed initialize, tools/list, blocked tools/call, and live GET/HEAD against the freshly installed binary. The test used a public echo service; network availability and its response may change.

To configure a normal Codex CLI installation after installing the binary:

```bash
codex mcp add --env OUTBOUND_GUARD_ALLOWED_HOSTS=postman-echo.com outbound-guard -- outbound-guard-mcp
codex mcp get outbound-guard
```

Then ask Codex to call `guarded_fetch` with `https://postman-echo.com/get` and approve the MCP tool call if prompted. The client must actually use this tool for its policy to apply. Change the allowlist to the exact hostnames you trust. The example requires outgoing HTTPS access and sends the request URL to the echo service; it needs no application credential. Remove the example server with `codex mcp remove outbound-guard` when it is no longer needed.

The headless `codex exec` test with approval policy `never` saw the tool but refused to call it: `MCP tool call requires approval, but approval policy is never`. For this isolated smoke test only, a separate Codex run used an approval bypass in the private temporary workspace to exercise the server. That bypass is not a recommended user configuration. The test host's OpenSnitch firewall also had a path-specific allow rule for the development binary but initially blocked the newly installed binary. A temporary rule for the exact fresh-install path was loaded for the live tests, then removed and the firewall reloaded. A host firewall may likewise need an operator-approved rule for the installed executable.

This proves the tested Codex CLI version can register and call the standalone server and receive both structured denials and allowed GET/HEAD results. It does not prove that Codex routes every external request through this MCP tool, that other Codex versions behave identically, or that Claude Code and Cursor pass their own client setup gates. The full release criteria remain in [QUALITY_BAR.md](QUALITY_BAR.md).
