#!/usr/bin/env python3
"""Inspect the retained native HTTP protocol-upgrade denial capture."""

import hashlib
from pathlib import Path

from verify_native_header_limit_pcap import rows, server_payload


PATHS = ["/plain", "/switch-protocols", "/upgrade-header-200",
         "/connection-upgrade-200", "/plain"]


def verify(path: Path, digest: str) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture outside fixture size limit"
    assert hashlib.sha256(data).hexdigest() == digest, "capture SHA-256 mismatch"
    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert len(syns) == 5 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 11 and all(ip == "127.0.0.1" and port == "53"
                                      for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names
    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in PATHS], requests
    expected = {
        "/switch-protocols": (b"HTTP/1.1 101 Switching Protocols", b"Connection: Upgrade", b"Upgrade: websocket"),
        "/upgrade-header-200": (b"HTTP/1.1 200 OK", b"Upgrade: websocket"),
        "/connection-upgrade-200": (b"HTTP/1.1 200 OK", b"Connection: keep-alive, UpGrAdE"),
    }
    for uri, markers in expected.items():
        streams = [stream for _, request_uri, stream in requests if request_uri == uri]
        assert len(streams) == 1, (uri, streams)
        payload = server_payload(path, streams[0])
        headers, separator, body = payload.partition(b"\r\n\r\n")
        assert separator and headers.startswith(markers[0]), (uri, payload[:100])
        assert all(marker in headers.split(b"\r\n") for marker in markers[1:]), uri
        assert body == (b"" if uri == "/switch-protocols" else b"ok"), (uri, body)
    addresses = {item for ipv4, ipv6 in rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": digest, "tcp_syn_count": len(syns),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "upgrade_response_paths": list(expected),
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}
