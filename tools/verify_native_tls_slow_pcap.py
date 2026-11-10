#!/usr/bin/env python3
"""Independently inspect a retained route-free native TLS slow-HTTP capture."""

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def rows(path: Path, display_filter: str, *fields: str) -> list[list[str]]:
    command = ["tshark", "-n", "-r", str(path), "-Y", display_filter,
               "-T", "fields", "-E", "separator=;"]
    for field in fields:
        command.extend(("-e", field))
    output = subprocess.check_output(command, text=True, timeout=15)
    return [line.split(";") for line in output.splitlines()]


def verify(path: Path, digest: str) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert len(syns) == 4 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "443")}, syns

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {
        "allowed.test", "1.0.0.11.in-addr.arpa", "2.0.0.11.in-addr.arpa"}, names

    hellos = rows(path, "tls.handshake.type == 1 && tcp.dstport == 443",
                  "tls.handshake.extensions_server_name", "tcp.stream")
    assert len(hellos) == 4 and all(host == "allowed.test" for host, _ in hellos), hellos
    streams = [stream for _, stream in hellos]
    assert len(set(streams)) == 4, streams

    closed = {}
    elapsed = {}
    for path_name, stream in zip(("/drip", "/delayed"), streams[1:3]):
        server_hellos = rows(path, f"tcp.stream == {stream} && tls.handshake.type == 2",
                             "frame.time_epoch")
        assert len(server_hellos) == 1, (path_name, server_hellos)
        hello_time = Decimal(server_hellos[0][0])
        request_packets = rows(
            path, f"tcp.stream == {stream} && tcp.dstport == 443 && tcp.len >= 100",
            "frame.time_epoch", "tcp.len")
        requests = [Decimal(timestamp) for timestamp, _ in request_packets
                    if Decimal(timestamp) > hello_time]
        assert len(requests) == 1, (path_name, request_packets)
        client_fin_or_reset = rows(
            path, f"tcp.stream == {stream} && tcp.dstport == 443 && "
                  "(tcp.flags.fin == 1 || tcp.flags.reset == 1)",
            "frame.number", "frame.time_epoch")
        assert client_fin_or_reset, (path_name, stream)
        first_close = min(Decimal(timestamp) for _, timestamp in client_fin_or_reset)
        duration = first_close - requests[0]
        # The drip fixture sends one encrypted body byte each second; its
        # four-second rate window differs from the three-second first-byte wait.
        limit = Decimal("4.25") if path_name == "/drip" else Decimal("3.25")
        assert Decimal(0) < duration <= limit, (path_name, duration, limit)
        elapsed[path_name] = float(duration.quantize(Decimal("0.000001")))
        closed[path_name] = True

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "tls_sni": [host for host, _ in hellos],
            "timed_out_streams_client_closed": closed,
            "request_to_client_close_seconds": elapsed, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only; encrypted request paths are inferred from the ordered fixture log"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-tls-slow-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
