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


def verify(path: Path, digest: str, scenario: str = "refused") -> dict:
    assert scenario in ("refused", "private-answer", "mixed-v6")
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    name = {"refused": "truncated.test", "private-answer": "truncated-private.test",
            "mixed-v6": "truncated-mixed-v6.test"}[scenario]
    queries = rows(path, "dns.flags.response == 0 && udp.dstport == 53", "dns.qry.name", "dns.qry.type",
                   "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53"
                           for _, _, ip, port in queries), queries
    truncated_queries = [qtype for queried, qtype, _, _ in queries if queried == name]
    assert len(truncated_queries) >= 2 and set(truncated_queries) == {"1", "28"}, truncated_queries

    responses = rows(path, f'dns.flags.response == 1 && dns.qry.name == "{name}" && udp.srcport == 53 && !icmp && !icmpv6',
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
    tcp_answers = []
    if scenario == "refused":
        assert dns_tcp_resets == [["127.0.0.1", "127.0.0.1"]], dns_tcp_resets
        assert not rows(path, "dns && tcp.port == 53", "frame.number"), "unexpected TCP DNS payload"
    else:
        assert not dns_tcp_resets, dns_tcp_resets
        assert rows(path, "dns && tcp.dstport == 53", "frame.number"), "missing TCP DNS query"
        tcp_answers = rows(path, f'dns.flags.response == 1 && dns.qry.name == "{name}" && tcp.srcport == 53',
                           "dns.qry.type", "dns.a", "dns.aaaa", "dns.count.answers", "dns.flags.truncated")
        expected = ([["1", "127.0.0.1", "", "1", "False"], ["28", "", "", "0", "False"]]
                    if scenario == "private-answer" else
                    [["1", "11.0.0.1", "", "1", "False"], ["28", "", "::1", "1", "False"]])
        assert tcp_answers == expected, tcp_answers

    requests = rows(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"], ["allowed.test", "/plain"]], requests
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "scenario": scenario,
            "truncated_dns_query_types": sorted(truncated_queries),
            "truncated_dns_responses": responses,
            "tcp_dns_fallback_syn_count": connections.count(("127.0.0.1", "53")),
            "tcp_dns_fallback_refused": scenario == "refused",
            "tcp_dns_answers": tcp_answers,
            "tcp_syn_destinations": [f"{ip}:{port}" for ip, port in connections],
            "approved_http_requests": requests, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--scenario", choices=("refused", "private-answer", "mixed-v6"), default="refused")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-dns-truncated-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.scenario), sort_keys=True))


if __name__ == "__main__":
    main()
