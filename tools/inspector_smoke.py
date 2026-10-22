#!/usr/bin/env python3
"""Probe the installed stdio server through the official MCP Inspector CLI."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


INSPECTOR = "@modelcontextprotocol/inspector@2.11.0"


def call(binary, method, *options, allowed_host=None, expected_exit=0, protocol_era="legacy"):
    # Inspector 2.5.0 accepts era only as a per-server config field. Its CLI
    # allows unknown options, so --protocol-era silently failed to select it.
    with tempfile.TemporaryDirectory(prefix="guard-inspector-") as directory:
        config = Path(directory) / "mcp.json"
        config.write_text(json.dumps({"mcpServers":{"guard":{
            "command":binary, "protocolEra":protocol_era,
            "env":{"OUTBOUND_GUARD_ALLOWED_HOSTS":allowed_host or ""}}}}))
        command = ["npx", "--yes", INSPECTOR, "--cli", "--config", str(config),
                   "--server", "guard", "--method", method, "--format", "json", *options]
        env = {key:value for key,value in os.environ.items() if not key.startswith("OUTBOUND_GUARD_")}
        env["npm_config_ignore_scripts"] = "true"
        # Fail registry fetches with an actionable npm error before the probe's
        # process deadline, rather than hiding resolution stalls in a timeout.
        env["npm_config_fetch_timeout"] = "15000"
        env["npm_config_fetch_retries"] = "1"
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode != expected_exit:
        raise AssertionError(
            f"Inspector {protocol_era} {method} exited {result.returncode}, expected {expected_exit}: "
            + result.stderr[-1000:] + result.stdout[-1000:]
        )
    if result.stdout.strip():
        return json.loads(result.stdout)
    # Connection/negotiation failures are CLI JSON diagnostics on stderr;
    # child startup diagnostics may precede the final structured error line.
    for line in reversed(result.stderr.splitlines()):
        try:
            diagnostic = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(diagnostic, dict) and "error" in diagnostic:
            return diagnostic
    raise AssertionError("Inspector returned no structured result or error")


def modern_eras(binary):
    for era in ("auto", "modern"):
        def probe(method, *options, **kwargs):
            return call(binary, method, *options, protocol_era=era, **kwargs)
        initialized = probe("initialize")["result"]  # CLI reports the connected era; no modern wire initialize.
        assert initialized["protocolVersion"] == "2026-07-28"
        assert initialized["serverInfo"]["name"] == "outbound-guard-mcp"
        tools = probe("tools/list", "--strict")["result"]["tools"]
        assert [tool["name"] for tool in tools] == ["guarded_fetch"]
        assert tools[0]["outputSchema"]["type"] == "object"
        blocked = probe("tools/call", "--tool-name", "guarded_fetch", "--tool-args-json",
                        '{"url":"http://127.0.0.1/"}', expected_exit=5)["result"]
        assert blocked["isError"] is True and blocked["structuredContent"]["rule"] == "EGRESS_INVALID_HOST"
        audit = probe("resources/read", "--uri", "outbound-guard://logs/audit.json")["result"]
        assert json.loads(audit["contents"][0]["text"])["events"] == []
        print(f"Inspector 2.11.0 {era}: modern 2026-07-28 negotiation, strict tools, blocked call and audit passed")
    invalid_config = call(binary, "tools/list", allowed_host="invalid_host", expected_exit=1)
    assert "error" in invalid_config and "result" not in invalid_config
    print("Inspector child environment: invalid configured allowlist prevented startup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="absolute path to a built or installed server binary")
    parser.add_argument("--live", metavar="HTTPS_URL", help="optional approved JSON endpoint for real GET and HEAD")
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    initialized = call(binary, "initialize")["result"]
    assert initialized["protocolVersion"] == "2025-06-18"
    assert initialized["serverInfo"]["name"] == "outbound-guard-mcp"
    assert "tools" in initialized["capabilities"]
    listed = call(binary, "tools/list", "--strict")["result"]["tools"]
    assert [tool["name"] for tool in listed] == ["guarded_fetch"]
    assert listed[0]["inputSchema"]["required"] == ["url"]
    assert listed[0]["outputSchema"]["type"] == "object"
    assert len(listed[0]["outputSchema"]["oneOf"]) == 2
    blocked = call(
        binary, "tools/call", "--tool-name", "guarded_fetch", "--tool-args-json",
        '{"url":"http://127.0.0.1/"}', expected_exit=5,
    )["result"]
    assert blocked["isError"] is True
    assert blocked["structuredContent"]["rule"] == "EGRESS_INVALID_HOST"
    assert blocked["structuredContent"]["correlation_id"] == "egress-1"
    uri = "outbound-guard://logs/audit.json"
    resources = call(binary, "resources/list")["result"]["resources"]
    assert [resource["uri"] for resource in resources] == [uri]
    contents = call(binary, "resources/read", "--uri", uri)["result"]["contents"][0]
    assert contents["mimeType"] == "application/json"
    assert json.loads(contents["text"]) == {"capacity": 256, "scope": "process", "events": []}
    # Each Inspector CLI invocation starts a fresh stdio process, hence an empty log.
    print("Inspector 2.11.0: initialize, strict tools/list, blocked call, audit resource list/read passed")
    modern_eras(binary)
    if args.live:
        url = urlsplit(args.live)
        if url.scheme != "https" or not url.hostname or url.port not in (None, 443) or url.query or url.fragment:
            parser.error("--live requires an HTTPS URL on port 443 without query or fragment")
        for method in ("GET", "HEAD"):
            request = {"url": args.live, "method": method}
            fetched = call(
                binary, "tools/call", "--tool-name", "guarded_fetch",
                "--tool-args-json", json.dumps(request), allowed_host=url.hostname,
            )["result"]["structuredContent"]
            assert fetched["status"] == "SAFE" and fetched["status_code"] == 200
            assert fetched["untrusted_content"] is True
            if method == "HEAD":
                assert fetched["body_text"] == ""
        print("Inspector 2.11.0: approved GET and HEAD passed")


if __name__ == "__main__":
    main()
