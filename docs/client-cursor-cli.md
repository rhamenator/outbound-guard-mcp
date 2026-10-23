# Cursor CLI client evidence

On 2026-10-21, Cursor CLI `2026.10.19-6bbf2c4` was installed from the official HTTPS installer, and the user completed its browser login. Authenticated ACP sessions discovered the independently installed optimized Outbound Guard candidate `ec96881e4ca9` through stdio. Controlled GET and HEAD returned `EGRESS_ALLOWED` / HTTP 200; loopback returned `EGRESS_INVALID_HOST`. The [machine-readable record](evidence/client-cancellation-2026-10-21.json) pins the binary and observations.

The CLI's ACP `session/cancel` acknowledged a cancelled agent turn but did **not** emit MCP `notifications/cancelled` in this tested version/path. The fetch continued until `EGRESS_RESPONSE_TOO_SLOW` around three seconds, then a subsequent guarded fetch succeeded. This is a documented client gap, not a prompt-cancellation pass. The [full review](client-cancellation.md) describes methodology and remaining desktop/terminal UI coverage.

## Configure a normal installation

Install Cursor CLI using its [official installation instructions](https://prod.cursor.com/docs/cli/installation), then run `agent login` and complete the browser flow if not authenticated. Do not paste account tokens into project files. Cursor service/account usage may incur costs independently of this GPL server.

After installing Outbound Guard, create a project-local `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "outbound_guard": {
      "command": "outbound-guard-mcp",
      "args": [],
      "env": { "OUTBOUND_GUARD_ALLOWED_HOSTS": "postman-echo.com" }
    }
  }
}
```

From that project directory, run `agent mcp enable outbound_guard` and `agent mcp list-tools outbound_guard`. The command runs relative to the current project; do not assume a workspace flag on an unrelated invocation changes MCP command discovery. Check that only `guarded_fetch` is advertised. Ask the client to call a loopback URL first, then the exact approved hostname using GET and HEAD. Retain normal per-tool permission prompts. The public echo example requires outgoing HTTPS, sends the destination the request URL and may change or become unavailable. Replace it with exact hosts you trust.

Only actual `guarded_fetch` traffic is enforced. Installing the companion skill or registering the server does not intercept other Cursor tools or processes. Root/network-namespace permissions are solely requirements of the development fixture harness, not of a normal installation. Final release-candidate/client UI tests and the other quality-bar gates remain open.


## Native companion-skill read and workflow

Cursor CLI 2026.10.19-6bbf2c4 loaded the exact clean ZIP's SKILL.md from a private project's `.cursor/skills/outbound-guard/` directory on 2026-10-22. A named-skill request produced a completed native read of that installed file, observed through merged ACP tool-call updates. The subsequent MCP calls produced loopback denial, approved GET200 and HEAD200, in exact order. [Redacted evidence](evidence/cursor-skill-activation-2026-10-22.json) records binary/ZIP/SKILL.md hashes; no private transcript is retained.

Project placement follows the [official Cursor skills documentation](https://cursor.com/docs/skills). Install the ZIP's `outbound-guard/` folder under the project's `.cursor/skills/`; configure the separately installed MCP server and approved hosts as above. The probe uses existing normal client authentication and an owned route-free DNS/HTTP fixture namespace. Native reading is observed separately from Claude's named Skill-tool acknowledgment; these are different client mechanisms.

```sh
python3 tools/client_cancellation_probe.py cursor /absolute/path/to/outbound-guard-mcp /absolute/path/to/outbound-guard-skill.zip
```

This optional authenticated probe requires the disposable-namespace sudo setup documented in the cancellation guide; ordinary MCP/skill use requires no sudo. Model inference can incur normal account usage. Only two expected ZIP files are installed, and private config/transcript/skill state is removed afterward. One initial harness setup failed before inference because the skill directory already created `.cursor/`; directory creation is now idempotent within the owned workspace.

This check covers an explicit named request and completed native file read. Automatic trigger reliability, IDE UI/menu behavior, Codex loading and cancellation delivery remain separate gaps. Skill guidance does not intercept traffic sent through other tools.

The [2026-10-23 exact-candidate replay](client-cancellation.md#rpc-fuzz-candidate-replay-2026-10-23) repeats the explicit installed-skill workflow, denial/GET/HEAD and client-control cancellation observations against the changed RPC-fuzz candidate. It preserves the client-specific cancellation limitations.
