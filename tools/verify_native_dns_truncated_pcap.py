#!/usr/bin/env python3
"""Independently inspect a retained native truncated-DNS fixture capture."""

import argparse
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

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "dns.qry.type",
                   "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53"
                           for _, _, ip, port in queries), queries
    truncated_queries = [qtype for name, qtype, _, _ in queries if name == "truncated.test"]
    assert len(truncated_queries) >= 2 and set(truncated_queries) == {"1", "28"}, truncated_queries

    responses = rows(path, 'dns.flags.response == 1 && dns.qry.name == "truncated.test" && !icmp && !icmpv6',
                     "dns.qry.type", "dns.flags.truncated", "dns.count.answers",
                     "ip.src", "udp.srcport")
    assert len(responses) == len(truncated_queries), (responses, truncated_queries)
    assert {row[0] for row in responses} == {"1", "28"}, responses
    assert all(row[1:] == ["True", "0", "127.0.0.1", "53"] for row in responses), responses

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    connections = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    assert connections.count(("11.0.0.1", "80")) == 2, connections
    assert connections.count(("127.0.0.1", "53")) == 1, connections
    assert set(connections) <= {("11.0.0.1", "80"), ("127.0.0.1", "53")}, connections
    dns_tcp_resets = rows(path, "tcp.srcport == 53 && tcp.flags.reset == 1",
                          "ip.src", "ip.dst")
    assert dns_tcp_resets == [["127.0.0.1", "127.0.0.1"]], dns_tcp_resets
    assert not rows(path, "dns && tcp.port == 53", "frame.number"), "unexpected TCP DNS payload"

    requests = rows(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"], ["allowed.test", "/plain"]], requests
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "truncated_dns_query_types": sorted(truncated_queries),
            "truncated_dns_responses": responses,
            "tcp_dns_fallback_syn_count": connections.count(("127.0.0.1", "53")),
            "tcp_dns_fallback_refused": True,
            "tcp_syn_destinations": [f"{ip}:{port}" for ip, port in connections],
            "approved_http_requests": requests, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-dns-truncated-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
