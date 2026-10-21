#!/usr/bin/env python3
"""Bounded, network-free adversarial probe for the built stdio MCP server."""

import json
from stdio_exchange import run as paced_run, exchange
import os
import subprocess
import sys


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def audit_probe(binary, env, marker):
    uri = "outbound-guard://logs/audit.json"
    messages = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "audit-probe", "version": "1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    messages += [{"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {
        "name": "guarded_fetch", "arguments": {"url": "https://example.com/" + marker}}}
        for index in range(1, 301)]
    messages += [
        {"jsonrpc": "2.0", "id": 301, "method": "resources/list"},
        {"jsonrpc": "2.0", "id": 302, "method": "resources/read", "params": {"uri": uri}},
        {"jsonrpc": "2.0", "id": 303, "method": "resources/read", "params": {"uri": marker}},
        {"jsonrpc": "2.0", "id": 304, "method": "resources/read"},
    ]
    result = paced_run([binary], input=b"".join(map(frame, messages)),
                            capture_output=True, env=env, timeout=10, check=True)
    assert marker.encode() not in result.stdout + result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == 305
    assert replies[0]["result"]["capabilities"]["resources"] == {}
    decisions = [reply["result"]["structuredContent"] for reply in replies[1:301]]
    assert [value["correlation_id"] for value in decisions] == [f"egress-{n}" for n in range(1, 301)]
    assert all(value["rule"] == "EGRESS_SECRET_DETECTED" for value in decisions)
    assert replies[301]["result"]["resources"][0]["uri"] == uri
    contents = replies[302]["result"]["contents"][0]
    assert contents["uri"] == uri and contents["mimeType"] == "application/json"
    audit = json.loads(contents["text"])
    assert audit["capacity"] == 256 and audit["scope"] == "process"
    assert audit["events"] == [{key: value[key] for key in ("correlation_id", "status", "rule")}
                               for value in decisions[-256:]]
    assert replies[303]["error"]["code"] == -32002
    assert replies[304]["error"]["code"] == -32602
    assert len(contents["text"]) < 40000
    print("audit probe: 300 correlated denials, 256 redacted events retained, unknown/missing URIs rejected")


def metadata_probe(binary, env, marker):
    messages = [{"jsonrpc":"2.0", "id":0, "method":"initialize", "params":{
        "protocolVersion":"2025-06-18", "capabilities":{},
        "clientInfo":{"name":"metadata-probe", "version":"1"}}}]
    for meta in (None, [], marker):
        messages.append({"jsonrpc":"2.0", "method":"notifications/initialized", "params":{"_meta":meta}})
    messages += [{"jsonrpc":"2.0", "id":1, "method":"tools/list"},
                 {"jsonrpc":"2.0", "method":"notifications/initialized"}]
    expected = [(0,None), (1,-32002)]
    bad_params = [[], {"_meta":None}, {"_meta":[]}, {"_meta":marker}]
    bad_params += [{"_meta":{"progressToken":token}} for token in (None, True, {}, [])]
    for params in bad_params:
        for method in ("ping", "tools/list", "tools/call"):
            id_ = 10 + len(expected)
            if isinstance(params, dict):
                params = dict(params, name="guarded_fetch", arguments={"url":"http://127.0.0.1/"})
            messages.append({"jsonrpc":"2.0", "id":id_, "method":method,"params":params})
            expected.append((id_,-32602))
    for index, token in enumerate(("progress", 0, -1, 1.5), 100):
        messages.append({"jsonrpc":"2.0", "id":index,"method":"ping",
            "params":{"_meta":{"progressToken":token,"example/custom":[marker,None]}}})
        expected.append((index,None))
    messages.append({"jsonrpc":"2.0", "id":104,"method":"resources/read",
        "params":{"uri":"outbound-guard://logs/audit.json"}})
    expected.append((104,None))
    result = paced_run([binary],input=b"".join(map(frame,messages)),capture_output=True,
                            env=env,timeout=10,check=True)
    assert not result.stderr and marker.encode() not in result.stdout
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == len(expected)
    for reply,(id_,code) in zip(replies,expected):
        assert reply["id"] == id_, reply
        if code is None:
            assert "result" in reply and "error" not in reply, reply
        else:
            assert reply.get("error", {}).get("code") == code and "result" not in reply, reply
    audit = json.loads(replies[-1]["result"]["contents"][0]["text"])
    assert audit["events"] == [], "malformed metadata dispatched a tool"
    print("metadata probe: 24 malformed requests correlated/rejected, invalid initialized metadata "
          "did not advance handshake, four valid extension/progress-token cases accepted, no tool audit or marker echo")


def framing_boundary_probe(binary, env):
    limit = 64 * 1024
    def ping(id_, length, ending):
        body = frame({"jsonrpc":"2.0", "id":id_, "method":"ping"})[:-1]
        return body + b" " * (length - len(body) - len(ending)) + ending
    decisions = 0
    for ending in (b"\n", b"\r\n", b""):
        # A separate process for EOF-only frames: no following bytes can delimit them.
        for length in (limit - 1, limit, limit + 1):
            payload = ping(1, length, ending)
            if ending:
                payload += frame({"jsonrpc":"2.0", "id":2, "method":"ping"})
            result = subprocess.run([binary], input=payload, capture_output=True,
                                    env=env, timeout=10, check=True)
            assert not result.stderr
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(replies) == (2 if ending else 1), replies
            if length <= limit:
                assert replies[0] == {"jsonrpc":"2.0", "id":1, "result":{}}, replies
            else:
                assert replies[0]["id"] is None
                assert replies[0]["error"]["code"] == -32600
                assert replies[0]["error"]["message"] == "Request too large"
            if ending:
                assert replies[1] == {"jsonrpc":"2.0", "id":2, "result":{}}, replies
            decisions += len(replies)
    # Invalid UTF-8 and raw controls inside JSON strings must fail parsing, with
    # no byte echo and with the following valid request still synchronized.
    invalid = [b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\x00", b"\r"]
    payload = b"".join(b'{"jsonrpc":"2.0","id":1,"method":"' + value + b'"}\n' +
                       frame({"jsonrpc":"2.0", "id":100 + index, "method":"ping"})
                       for index, value in enumerate(invalid))
    result = paced_run([binary], input=payload, capture_output=True, env=env,
                            timeout=10, check=True)
    assert not result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == 2 * len(invalid)
    for index in range(len(invalid)):
        assert replies[2 * index]["id"] is None
        assert replies[2 * index]["error"] == {"code":-32700, "message":"Parse error"}
        assert replies[2 * index + 1] == {"jsonrpc":"2.0", "id":100 + index, "result":{}}
    print(f"framing boundary probe: {decisions + len(replies)} replies; LF/CRLF/EOF byte limits, "
          "invalid UTF-8/control rejection and subsequent ping recovery passed")


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
    result = paced_run(
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
    audit_probe(sys.argv[1], env, marker)
    metadata_probe(sys.argv[1], env, marker)
    framing_boundary_probe(sys.argv[1], env)


if __name__ == "__main__":
    main()
