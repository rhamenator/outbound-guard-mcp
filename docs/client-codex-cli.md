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

## Corrected candidate replay, 2026-10-21

Fresh archive candidate `ec96881e4ca9` (after the independent cancellation review correction) passed discovery and three actual tool calls: loopback returned `EGRESS_INVALID_HOST`; approved GET and HEAD returned `EGRESS_ALLOWED` with HTTP 200. [Redacted machine-readable evidence](evidence/client-smoke-2026-10-21.json) records the binary/package/skill checksums, exact client versions, arguments, permissions and remaining gaps. The extracted binary and client configuration lived outside the checkout. A temporary OpenSnitch rule applied only to that executable and was removed after replay. Initial Claude calls before firewall authorization failed closed with `EGRESS_NETWORK_FAILURE`; those are not counted as passing allow cases.

Codex CLI 0.151.0 used an isolated ephemeral session with a read-only sandbox and `approval_policy = "never"`. The single configured tool had an explicit `tools.guarded_fetch.approval_mode = "approve"` policy; no approval or sandbox bypass was needed. This is a narrow test authorization, not a recommendation to approve unrelated tools. Normal user configuration and authentication were not modified.

This is candidate evidence, not final stable-release certification. Client UI cancellation, authenticated Cursor and the other quality-bar gates remain open.

The [2026-10-21 control-path cancellation review](client-cancellation.md) records actual wire behavior separately from agent-turn interruption and deadline recovery. It does not certify desktop or terminal UI controls.
