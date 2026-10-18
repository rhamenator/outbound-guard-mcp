# outbound-guard-mcp

Standalone outbound HTTP safety server for coding agents. **Extraction in progress; no runnable MCP server is released from this repository yet.** The current experimental implementation lives on the [`codex/outbound-guard` branch of request-guard-mcp](https://github.com/rhamenator/request-guard-mcp/tree/codex/outbound-guard). This repository will become the independent egress product after security and protocol validation.

The intended boundary is one guarded HTTP request per `guarded_fetch` call: URL and DNS validation, pinned connection, outbound secret checks, request budgets, response size and time limits, redirect validation, and quarantining suspicious content. It cannot intercept traffic sent through unrelated tools or processes. The `ai-scraping-defense` projects may connect to it optionally, as they may connect to any MCP server.

The [companion skill](skills/outbound-guard/SKILL.md) tells a connected agent when and how to use the guard; it is a draft until the server is runnable. See [the extraction and verification plan](docs/PLAN.md). The project is GPL-3.0-or-later; see [LICENSE](LICENSE). Security reports follow [SECURITY.md](SECURITY.md).
