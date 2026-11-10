#!/usr/bin/env python3
"""Independently inspect retained three-cycle native cancellation TCP captures."""

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


PATHS = ["/cancel-silent-headers-long", "/plain"] * 3 + ["/head-ok"]
METHODS = ["GET"] * 6 + ["HEAD"]


def rows(path: Path, display_filter: str, *fields: str) -> list[list[str]]:
    command = ["tshark", "-n", "-r", str(path), "-Y", display_filter,
               "-T", "fields", "-E", "separator=;"]
    for field in fields:
        command.extend(("-e", field))
    output = subprocess.check_output(command, text=True, timeout=15)
    return [line.split(";") for line in output.splitlines()]


def verify(path: Path, digest: str, client: str) -> dict:
    assert client in ("codex", "claude")
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture outside fixture size limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "tcp.dstport", "tcp.stream")
    assert len(syns) == 7 and all(ip == "11.0.0.1" and port == "80"
                                  for ip, port, _ in syns), syns
    requests = rows(path, "http.request", "tcp.stream", "http.request.method",
                    "http.request.uri", "frame.time_epoch")
    assert len(requests) == 7, requests
    assert [method for _, method, _, _ in requests] == METHODS, requests
    assert [uri for _, _, uri, _ in requests] == PATHS, requests
    assert len({stream for stream, _, _, _ in requests}) == 7, requests
    assert [stream for _, _, stream in syns] == [stream for stream, _, _, _ in requests]

    responses = rows(path, "http.response", "tcp.stream", "http.response.code")
    assert responses == [[stream, "200"] for stream, _, _, _ in
                         [*requests[1:6:2], requests[6]]], responses
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 15 and all(ip == "127.0.0.1" and port == "53"
                                      for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert names == {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    elapsed = []
    for stream, _, uri, request_time in requests[::2][:3]:
        assert uri == "/cancel-silent-headers-long"
        assert not rows(path, f"tcp.stream == {stream} && tcp.srcport == 80 && tcp.len > 0",
                        "frame.number"), stream
        closes = rows(path, f"tcp.stream == {stream} && tcp.dstport == 80 && "
                      "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.time_epoch")
        assert closes, stream
        duration = min(Decimal(value[0]) for value in closes) - Decimal(request_time)
        lower, upper = ((Decimal("2.75"), Decimal("3.25")) if client == "codex"
                        else (Decimal(0), Decimal("0.25")))
        assert lower < duration < upper, (client, stream, duration)
        elapsed.append(float(duration.quantize(Decimal("0.000001"))))

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses == {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "http_requests": PATHS,
            "http_methods": METHODS, "http_statuses": [200] * 4,
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "held_request_to_client_close_seconds": elapsed,
            "ip_destinations": sorted(addresses),
            "scope": "fixture network namespace TCP/HTTP/DNS only; MCP cancellation delivery is not visible in this capture"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=("codex", "claude"))
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-cancel-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.client), sort_keys=True))


if __name__ == "__main__":
    main()
