#!/usr/bin/env python3
"""Independently verify retained native twenty-answer DNS cap fixture traffic."""

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
    return [line.split(";") for line in subprocess.check_output(
        command, text=True, timeout=15).splitlines()]


def verify(path: Path, digest: str, boundary: bool = False) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    answer_counts = ({"dns-limit-16.test": 16, "dns-limit-17.test": 17}
                     if boundary else {"many-answers.test": 20})
    for name, count in answer_counts.items():
        answers = rows(path, f'dns.flags.response == 1 && dns.qry.name == "{name}" && dns.a',
                       "dns.a")
        expected = ",".join(f"11.0.0.{n}" for n in range(1, count + 1))
        assert answers == [[expected]], (name, answers)
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    names = {name for name, _, _ in queries}
    required_names = {"allowed.test", *answer_counts}
    assert required_names <= names <= required_names | {"1.0.0.11.in-addr.arpa"}, queries
    assert all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    expected_requests = ([('allowed.test', '/plain'), ('dns-limit-16.test', '/plain'),
                          ('allowed.test', '/plain')] if boundary
                         else [('allowed.test', '/plain')] * 2)
    assert syns == [["11.0.0.1", "", "80"]] * len(expected_requests), syns
    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == expected_requests, requests
    streams = [stream for _, _, stream in requests]
    assert len(set(streams)) == len(expected_requests), streams
    responses = rows(path, "http.response", "http.response.code", "tcp.stream")
    assert responses == [["200", stream] for stream in streams], responses
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses == {"11.0.0.1", "127.0.0.1"}, addresses
    result = {"sha256": actual, "dns_query_count": len(queries),
            "dns_names": sorted(names), "tcp_syn_count": len(syns),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "http_response_codes": [code for code, _ in responses],
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}
    if boundary:
        result["answer_counts"] = answer_counts
    else:
        result["answer_count"] = 20
        result["answers"] = [f"11.0.0.{n}" for n in range(1, 21)]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--boundary", action="store_true", help="verify exact 16/17 A-answer fixture")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-answer-limit-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.boundary), sort_keys=True))


if __name__ == "__main__":
    main()
