#!/usr/bin/env python3
"""Probe the installed stdio server through the official MCP Inspector CLI."""

import argparse
import json
import os
import subprocess
from urllib.parse import urlsplit


INSPECTOR = "@modelcontextprotocol/inspector@2.5.0"


def call(binary, method, *options, allowed_host=None, expected_exit=0):
    command = [
        "npx", "--yes", INSPECTOR, "--cli", binary,
    ]
    if allowed_host is not None:
        command += ["-e", "OUTBOUND_GUARD_ALLOWED_HOSTS=" + allowed_host]
    command += ["--method", method, "--format", "json", "--protocol-era", "legacy"]
    command += list(options)
    env = os.environ.copy()
    env.pop("OUTBOUND_GUARD_ALLOWED_HOSTS", None)
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode != expected_exit:
        raise AssertionError(
            f"Inspector {method} exited {result.returncode}, expected {expected_exit}: "
            + result.stderr[-1000:]
        )
    return json.loads(result.stdout)


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
    print("Inspector 2.5.0: initialize, strict tools/list, blocked call, audit resource list/read passed")
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
        print("Inspector 2.5.0: approved GET and HEAD passed")


if __name__ == "__main__":
    main()
