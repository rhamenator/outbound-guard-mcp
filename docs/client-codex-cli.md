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

## Native companion-skill loading, 2026-10-22

Codex CLI 0.151.0 discovered the exact clean ZIP installed in a temporary project's `.agents/skills/outbound-guard` directory. Its app-server `skills/list` returned the enabled skill at that installed path without discovery errors. The probe supplied `$outbound-guard` and an explicit `skill` input item to `turn/start`; the turn completed successfully after three actual MCP calls: loopback GET denied with `EGRESS_INVALID_HOST`, approved GET and HEAD each allowed with HTTP 200. [Machine-readable evidence](evidence/codex-skill-activation-2026-10-22.json) identifies the tested archive, ZIP, installed skill and binary hashes.

This uses the native interfaces described in the [official OpenAI app-server documentation](https://learn.chatgpt.com/docs/app-server#skills) and the [repository skill location](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills). To repeat against a separately installed binary and inspected companion ZIP:

```bash
python3 tools/client_cancellation_probe.py codex /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

The opt-in probe requires an authenticated Codex CLI and passwordless sudo for its disposable, route-free network namespace. Model inference uses the normal account and may incur usage. Only the server and controlled DNS/HTTP fixtures run in the namespace; the client retains its normal inference connectivity. The isolated client uses a read-only sandbox, ephemeral thread and explicit approval for `guarded_fetch`; normal client configuration and credentials are not modified. Temporary files and owned fixture processes are removed afterward.

The observed native discovery, accepted skill input and completed MCP workflow establish this explicit loading path. They do not prove automatic trigger reliability, model adherence to every instruction, a separate native file-read event, desktop/terminal controls, or prompt socket cancellation. The companion skill grants no enforcement over other tools. No skill contents changed in this test.

The [2026-10-23 exact-candidate replay](client-cancellation.md#rpc-fuzz-candidate-replay-2026-10-23) repeats the explicit installed-skill workflow, denial/GET/HEAD and client-control cancellation observations against the changed RPC-fuzz candidate. It preserves the client-specific cancellation limitations.
