#!/usr/bin/env python3
"""Inspect the retained native repeated HTTP 103 flood capture."""

import hashlib
from pathlib import Path

from verify_native_header_limit_pcap import rows, server_payload


PATHS = ["/plain"] + ["/interim-header-flood"] * 4 + ["/plain"]
HEAD = b"HTTP/1.1 103 Early Hints\r\nLink: </" + b"x" * 1024 + b">\r\n\r\n"


def verify(path: Path, digest: str) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture outside fixture size limit"
    assert hashlib.sha256(data).hexdigest() == digest, "capture SHA-256 mismatch"
    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert len(syns) == 6 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 13 and all(ip == "127.0.0.1" and port == "53"
                                      for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names
    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in PATHS], requests
    counts = []
    for host, uri, stream in requests:
        if uri != "/interim-header-flood":
            continue
        payload = server_payload(path, stream)
        assert len(payload) % len(HEAD) == 0 and payload == HEAD * (len(payload) // len(HEAD)), stream
        count = len(payload) // len(HEAD)
        assert count >= 64, (stream, count)
        counts.append(count)
    assert len(counts) == 4, counts
    addresses = {item for ipv4, ipv6 in rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": digest, "tcp_syn_count": len(syns),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "interim_head_counts": counts, "interim_head_bytes": len(HEAD),
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}
