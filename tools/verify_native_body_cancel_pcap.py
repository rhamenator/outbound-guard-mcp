#!/usr/bin/env python3
"""Check partial-body cancellation timing in retained native fixture packets."""

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from verify_native_cancel_pcap import rows


PATHS = ["/cancel-drip", "/plain", "/head-ok"]


def verify(path: Path, digest: str, client: str) -> dict:
    assert client in ("codex", "claude")
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture outside fixture size limit"
    assert hashlib.sha256(data).hexdigest() == digest, "capture SHA-256 mismatch"
    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "tcp.dstport", "tcp.stream")
    assert syns == [["11.0.0.1", "80", str(i)] for i in range(3)], syns
    requests = rows(path, "http.request", "tcp.stream", "http.request.method",
                    "http.request.uri", "frame.time_epoch")
    assert len(requests) == 3, requests
    assert [[stream, method, uri] for stream, method, uri, _ in requests] == [
        ["0", "GET", PATHS[0]], ["1", "GET", PATHS[1]],
        ["2", "HEAD", PATHS[2]]], requests
    responses = rows(path, "http.response", "tcp.stream", "http.response.code")
    assert responses == [["1", "200"], ["2", "200"]], responses
    assert not rows(path, "tcp.stream == 0 && tcp.analysis.retransmission", "frame.number")
    segments = rows(path, "tcp.stream == 0 && tcp.srcport == 80 && tcp.len > 0",
                    "tcp.payload", "frame.time_epoch")
    assert len(segments) >= 2, segments
    wire = b"".join(bytes.fromhex(payload) for payload, _ in segments)
    assert wire.startswith(b"HTTP/1.0 200 OK\r\n"), wire[:32]
    head, separator, body = wire.partition(b"\r\n\r\n")
    assert separator and b"\r\nContent-Length: 20" in head, head
    assert 1 <= len(body) < 20 and body == b"x" * len(body), body
    closes = rows(path, "tcp.stream == 0 && tcp.dstport == 80 && "
                  "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.time_epoch")
    assert closes, "held socket lacks client close"
    close_time = min(Decimal(value[0]) for value in closes)
    request_to_close = close_time - Decimal(requests[0][3])
    first_body_to_close = close_time - Decimal(segments[1][1])
    lower, upper = ((Decimal("2.75"), Decimal("3.25")) if client == "codex"
                    else (Decimal(0), Decimal("0.25")))
    assert lower < request_to_close < upper, (client, request_to_close)
    assert lower < first_body_to_close < upper, (client, first_body_to_close)
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 7 and all(ip == "127.0.0.1" and port == "53"
                                     for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert names == {"allowed.test", "1.0.0.11.in-addr.arpa"}, names
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses == {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": digest, "tcp_syn_count": len(syns), "http_requests": PATHS,
            "http_methods": ["GET", "GET", "HEAD"], "complete_http_statuses": [200, 200],
            "held_response_status_line": "HTTP/1.0 200 OK",
            "held_response_declared_bytes": 20, "held_response_observed_body_bytes": len(body),
            "request_to_client_close_seconds": float(request_to_close.quantize(Decimal("0.000001"))),
            "first_body_byte_to_client_close_seconds": float(first_body_to_close.quantize(Decimal("0.000001"))),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "ip_destinations": sorted(addresses),
            "scope": "fixture network namespace TCP/HTTP/DNS only; MCP cancellation delivery is not visible"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=("codex", "claude"))
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="outbound-body-cancel-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.client), sort_keys=True))


if __name__ == "__main__":
    main()
