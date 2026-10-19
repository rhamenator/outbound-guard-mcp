# Stdio adversarial probe

Run after `cargo build --locked`:

```bash
python3 tools/adversarial_stdio_probe.py target/debug/outbound-guard-mcp
```

The stdlib-only probe launches the actual server with no egress allowlist and sends 12 newline-delimited frames. It checks malformed JSON and JSON-RPC versions, notifications with no ID, a tool call with no ID, loopback URL denial, a synthetic credential marker, an unknown method, an oversized frame followed by a valid request, initialization, and a non-object request. It asserts the exact reply count and IDs, stable denial/error codes, continued framing after the oversized input, and no secret-marker echo. CI runs this probe after building the binary.

This is process-level protocol evidence with **no network traffic**. It does not test DNS rebinding, forbidden socket opens, hostile HTTP servers, sustained load, real client compatibility, or the remaining release gates in [QUALITY_BAR.md](QUALITY_BAR.md). Those need separate controlled fixtures and client probes.
