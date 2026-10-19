#!/usr/bin/env python3
"""Socket-level guarded_fetch checks inside a disposable, route-free network namespace."""
import gzip
import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib

PUBLIC_FIXTURE = "11.0.0.1"  # Locally assigned only in the disposable namespace.
RECORDS = {
    "allowed.test": [PUBLIC_FIXTURE],
    "rebind.test": [PUBLIC_FIXTURE],
    "mixed.test": [PUBLIC_FIXTURE, "127.0.0.1"],
    "private.test": ["127.0.0.1"],
    "metadata.test": ["169.254.169.254"],
    "carrier.test": ["100.64.0.1"],
    "documentation.test": ["192.0.2.1"],
    "v6-loopback.test": [],
    "v6-mapped.test": [],
    "v6-private.test": [],
    "v6-documentation.test": [],
    "v6-transition.test": [],
    "mixed-v6.test": [PUBLIC_FIXTURE],
}
V6_RECORDS = {
    "v6-loopback.test": ["::1"],
    "v6-mapped.test": ["::ffff:127.0.0.1"],
    "v6-private.test": ["fc00::1"],
    "v6-documentation.test": ["2001:db8::1"],
    "v6-transition.test": ["2002::1"],
    "mixed-v6.test": ["::1"],
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
        addresses = (RECORDS.get(name, []) if qtype == 1 else
                     V6_RECORDS.get(name, []) if qtype == 28 else [])
        if name == "rebind.test" and qtype == 1:
            type(self).rebind_a_queries += 1
            addresses = [PUBLIC_FIXTURE] if self.rebind_a_queries == 1 else ["127.0.0.1"]
        flags = 0x8180 if name in RECORDS else 0x8183
        header = data[:2] + struct.pack("!HHHHH", flags, 1, len(addresses), 0, 0)
        answers = b"".join(
            b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, 4 if qtype == 1 else 16) +
            socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, address)
            for address in addresses
        )
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
        if self.path in ("/many-headers", "/oversized-header", "/parser-limit"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            if self.path == "/many-headers":
                for index in range(70):
                    self.send_header(f"X-Fixture-{index}", "ok")
            elif self.path == "/parser-limit":
                self.send_header("X-Fixture-Large", "x" * (1024 * 1024))
            else:
                self.send_header("X-Fixture-Large", "x" * (24 * 1024))
            self.send_header("Content-Length", "2")
            self.end_headers()
            try:
                self.wfile.write(b"ok")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if self.path == "/encoded":
            body = gzip.compress(b"fixture-ok")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
        elif self.path in ("/gzip-bomb", "/deflate-bomb"):
            plain = b"x" * (8 * 1024 * 1024)
            body = gzip.compress(plain) if self.path == "/gzip-bomb" else zlib.compress(plain)
            assert len(body) < 16 * 1024
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip" if self.path == "/gzip-bomb" else "deflate")
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


class QuietTLSHTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *_args):
        # Expected when the client rejects the ephemeral test certificate.
        pass


def test_tls(binary):
    with tempfile.TemporaryDirectory(prefix="outbound-guard-tls-") as folder:
        cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=wrong.test"],
            capture_output=True, check=True, timeout=10,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        seen_sni = []
        context.set_servername_callback(lambda _socket, name, _context: seen_sni.append(name))
        server = QuietTLSHTTP((PUBLIC_FIXTURE, 443), HTTP)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            before_hits = len(HTTP.hits)
            decision = call(binary, "allowed.test", "plain", scheme="https")
            assert decision["rule"] == "EGRESS_NETWORK_FAILURE", decision
            assert seen_sni == ["allowed.test"], seen_sni
            assert len(HTTP.hits) == before_hits, HTTP.hits
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def call(binary, host, path, scheme="http"):
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "guarded_fetch", "arguments":
                          {"url": f"{scheme}://{host}/{path}", "max_return_bytes": 65536}}}
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
        forbidden_hosts = (
            "metadata.test", "carrier.test", "documentation.test",
            "v6-loopback.test", "v6-mapped.test", "v6-private.test",
            "v6-documentation.test", "v6-transition.test", "mixed-v6.test",
        )
        for host in forbidden_hosts:
            decision = call(binary, host, "plain")
            assert decision["rule"] == "EGRESS_FORBIDDEN_ADDRESS", (host, decision)
            assert not HTTP.hits, (host, HTTP.hits)
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
        assert DNS.rebind_a_queries == 1, DNS.rebind_a_queries
        before_hits = len(HTTP.hits)
        rebound = call(binary, "rebind.test", "plain")
        assert rebound["rule"] == "EGRESS_FORBIDDEN_ADDRESS", rebound
        assert DNS.rebind_a_queries == 2, DNS.rebind_a_queries
        assert len(HTTP.hits) == before_hits, HTTP.hits
        test_tls(binary)
        for path in ("gzip-bomb", "deflate-bomb"):
            decision = call(binary, "allowed.test", path)
            assert decision["rule"] == "EGRESS_ENCODED_RESPONSE", (path, decision)
            assert "body_text" not in decision, (path, decision)
            assert HTTP.hits[-1] == f"/{path}"
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
            ("many-headers", {"EGRESS_RESPONSE_HEADERS_LIMIT"}),
            ("oversized-header", {"EGRESS_RESPONSE_HEADERS_LIMIT", "EGRESS_NETWORK_FAILURE"}),
            ("parser-limit", {"EGRESS_NETWORK_FAILURE"}),
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
        print(f"netns adversarial probe: 30 MCP decisions; forbidden DNS, rebinding, and synthetic secret opened no HTTP socket; TLS SNI preserved; "
              f"ambient proxy ignored; rebind A queries={DNS.rebind_a_queries}; framing={framing_results}")
    finally:
        dns.shutdown()
        http_server.shutdown()
        dns.server_close()
        http_server.server_close()


if __name__ == "__main__":
    main(sys.argv[1])
