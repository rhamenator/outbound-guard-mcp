#!/usr/bin/env python3
"""Socket-level guarded_fetch checks inside a disposable, route-free network namespace."""
import gzip
import http.server
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

PUBLIC_FIXTURE = "11.0.0.1"  # Locally assigned only in the disposable namespace.
RECORDS = {
    "allowed.test": [PUBLIC_FIXTURE],
    "rebind.test": [PUBLIC_FIXTURE],
    "mixed.test": [PUBLIC_FIXTURE, "127.0.0.1"],
    "private.test": ["127.0.0.1"],
}


class DNS(socketserver.BaseRequestHandler):
    rebind_a_queries = 0
    queries = 0

    def handle(self):
        data, sock = self.request
        if len(data) < 17:
            return
        offset = 12
        labels = []
        while offset < len(data) and data[offset]:
            length = data[offset]
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", "ignore"))
            offset += length
        if offset + 5 > len(data):
            return
        name = ".".join(labels).lower()
        type(self).queries += 1
        question = data[12:offset + 5]
        qtype = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        addresses = RECORDS.get(name, []) if qtype == 1 else []
        if name == "rebind.test" and qtype == 1:
            type(self).rebind_a_queries += 1
            addresses = [PUBLIC_FIXTURE] if self.rebind_a_queries == 1 else ["127.0.0.1"]
        flags = 0x8180 if name in RECORDS else 0x8183
        header = data[:2] + struct.pack("!HHHHH", flags, 1, len(addresses), 0, 0)
        answers = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) +
                           socket.inet_aton(address) for address in addresses)
        sock.sendto(header + question + answers, self.client_address)


class HTTP(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.hits.append(self.path)
        if self.path == "/delayed":
            time.sleep(11)
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if self.path == "/drip":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "20")
            self.end_headers()
            for _ in range(20):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
                time.sleep(1)
            return
        if self.path == "/late-eof":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            for _ in range(10):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break
                time.sleep(1)
            time.sleep(0.5)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://private.test/plain")
            self.end_headers()
            return
        if self.path == "/conflict-framing":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"2\r\nok\r\n0\r\n\r\n")
            return
        if self.path == "/duplicate-length":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/chunked-large":
            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            body = b"x" * 70000
            self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
            return
        if self.path == "/encoded":
            body = gzip.compress(b"fixture-ok")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
        elif self.path == "/large":
            body = b"x" * 70000
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"fixture-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass


def call(binary, host, path):
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "guarded_fetch", "arguments":
                          {"url": f"http://{host}/{path}", "max_return_bytes": 65536}}}
    env = os.environ.copy()
    env["OUTBOUND_GUARD_ALLOWED_HOSTS"] = ",".join(RECORDS)
    # A working direct request proves these ambient proxy variables were ignored.
    env["HTTP_PROXY"] = "http://127.0.0.1:9"
    env["http_proxy"] = "http://127.0.0.1:9"
    env["ALL_PROXY"] = "http://127.0.0.1:9"
    env["all_proxy"] = "http://127.0.0.1:9"
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    result = subprocess.run([binary], input=json.dumps(request) + "\n", text=True,
                            capture_output=True, timeout=20, env=env, check=True)
    if result.stderr:
        raise AssertionError(f"server emitted stderr: {result.stderr[:200]}")
    lines = result.stdout.splitlines()
    assert len(lines) == 1, lines
    return json.loads(lines[0])["result"]["structuredContent"]


def main(binary):
    dns = socketserver.ThreadingUDPServer(("127.0.0.1", 53), DNS)
    http_server = http.server.ThreadingHTTPServer((PUBLIC_FIXTURE, 80), HTTP)
    http_server.daemon_threads = True
    for server in (dns, http_server):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cases = [
            ("private.test", "plain", "EGRESS_FORBIDDEN_ADDRESS", []),
            ("mixed.test", "plain", "EGRESS_FORBIDDEN_ADDRESS", []),
            ("allowed.test", "plain", "EGRESS_ALLOWED", ["/plain"]),
            ("allowed.test", "redirect", "EGRESS_REDIRECT_DENIED", ["/plain", "/redirect"]),
            ("allowed.test", "encoded", "EGRESS_ENCODED_RESPONSE", ["/plain", "/redirect", "/encoded"]),
            ("allowed.test", "large", "EGRESS_RESPONSE_LIMIT", ["/plain", "/redirect", "/encoded", "/large"]),
            ("rebind.test", "plain", "EGRESS_ALLOWED", ["/plain", "/redirect", "/encoded", "/large", "/plain"]),
        ]
        for host, path, rule, hits in cases:
            decision = call(binary, host, path)
            assert decision["rule"] == rule, (host, path, decision)
            assert HTTP.hits == hits, (host, path, HTTP.hits)
            if rule == "EGRESS_ALLOWED":
                assert decision["body_text"] == "fixture-ok"
        assert DNS.rebind_a_queries >= 1
        marker = "AKIAABCDEFGHIJKLMNOP"  # Synthetic AWS-shaped token.
        before_queries, before_hits = DNS.queries, len(HTTP.hits)
        secret_decision = call(binary, "allowed.test", marker)
        assert secret_decision["rule"] == "EGRESS_SECRET_DETECTED", secret_decision
        assert marker not in json.dumps(secret_decision)
        assert (DNS.queries, len(HTTP.hits)) == (before_queries, before_hits)
        framing_results = {}
        for path, accepted_rules in (
            ("conflict-framing", {"EGRESS_INVALID_FRAMING", "EGRESS_NETWORK_FAILURE"}),
            ("duplicate-length", {"EGRESS_INVALID_FRAMING", "EGRESS_NETWORK_FAILURE"}),
            ("chunked-large", {"EGRESS_RESPONSE_LIMIT"}),
        ):
            decision = call(binary, "allowed.test", path)
            assert decision["rule"] in accepted_rules, (path, decision)
            assert "body_text" not in decision, (path, decision)
            assert HTTP.hits[-1] == f"/{path}"
            framing_results[path] = decision["rule"]
        for path, rule in (("delayed", "EGRESS_NETWORK_FAILURE"),
                           ("drip", "EGRESS_RESPONSE_TIMEOUT"),
                           ("late-eof", "EGRESS_RESPONSE_TIMEOUT")):
            started = time.monotonic()
            decision = call(binary, "allowed.test", path)
            elapsed = time.monotonic() - started
            assert decision["rule"] == rule, (path, decision)
            assert "body_text" not in decision, (path, decision)
            assert elapsed < 16, (path, elapsed)
            assert HTTP.hits[-1] == f"/{path}"
        print(f"netns adversarial probe: 14 MCP decisions; private/mixed DNS and synthetic secret opened no HTTP socket; "
              f"ambient proxy ignored; rebind A queries={DNS.rebind_a_queries}; framing={framing_results}")
    finally:
        dns.shutdown()
        http_server.shutdown()
        dns.server_close()
        http_server.server_close()


if __name__ == "__main__":
    main(sys.argv[1])
