#!/usr/bin/env python3
"""Bounded, network-free adversarial probe for the built stdio MCP server."""

import json
import os
import subprocess
import sys


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: adversarial_stdio_probe.py PATH_TO_SERVER")
    marker = "AKIAABCDEFGHIJKLMNOP"  # synthetic token, never a real credential
    messages = [
        b"{\n",  # malformed JSON
        frame({"jsonrpc": "1.0", "method": "notifications/initialized"}),
        frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        frame({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "https://example.com/"}}}),
        frame({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        frame({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "http://127.0.0.1/"}}}),
        frame({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "https://example.com/" + marker}}}),
        frame({"jsonrpc": "2.0", "id": 4, "method": "unknown/method"}),
        b"x" * 65537 + b"\n",  # oversized frame must be drained
        frame({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
        frame({"jsonrpc": "2.0", "id": 6, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        frame({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "stdio-probe", "version": "1.0"},
        }}),
        frame({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "http://127.0.0.1/"}}}),
        frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        frame({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "http://127.0.0.1/"}}}),
        frame({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "guarded_fetch", "arguments": {"url": "https://example.com/" + marker}}}),
        frame([]),
    ]
    env = os.environ.copy()
    env.pop("OUTBOUND_GUARD_ALLOWED_HOSTS", None)
    result = subprocess.run(
        [sys.argv[1]], input=b"".join(messages), capture_output=True,
        env=env, timeout=10, check=True,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == 14, f"expected 14 replies, got {len(replies)}"
    assert [reply["id"] for reply in replies] == [None, None, 1, 2, 3, 4, None, 5, 6, 7, 8, 9, 10, None]
    assert replies[0]["error"]["code"] == -32700
    assert replies[1]["error"]["code"] == -32600
    assert replies[2]["result"] == {}
    assert replies[3]["error"]["code"] == -32002
    assert replies[4]["error"]["code"] == -32002
    assert replies[5]["error"]["code"] == -32002
    assert replies[6]["error"]["code"] == -32600
    assert replies[7]["result"] == {}
    assert replies[8]["error"]["code"] == -32602
    assert replies[9]["result"]["protocolVersion"] == "2025-06-18"
    assert replies[10]["error"]["code"] == -32002
    assert replies[11]["result"]["structuredContent"]["rule"] == "EGRESS_INVALID_HOST"
    assert replies[12]["result"]["structuredContent"]["rule"] == "EGRESS_SECRET_DETECTED"
    assert replies[13]["error"]["code"] == -32600
    assert marker.encode() not in result.stdout + result.stderr
    print("stdio adversarial probe: 17 frames, 14 expected replies, no network or secret echo")


if __name__ == "__main__":
    main()
