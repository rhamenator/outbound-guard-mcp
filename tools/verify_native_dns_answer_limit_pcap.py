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


def verify(path: Path, digest: str) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    expected_answers = [f"11.0.0.{n}" for n in range(1, 21)]
    answers = rows(path, 'dns.flags.response == 1 && dns.qry.name == "many-answers.test" && dns.a',
                   "dns.a")
    assert answers == [[",".join(expected_answers)]], answers
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    names = {name for name, _, _ in queries}
    assert {"allowed.test", "many-answers.test"} <= names <= {
        "allowed.test", "many-answers.test", "1.0.0.11.in-addr.arpa"}, queries
    assert all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert syns == [["11.0.0.1", "", "80"]] * 2, syns
    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", "/plain"), ("allowed.test", "/plain")], requests
    streams = [stream for _, _, stream in requests]
    assert len(set(streams)) == 2, streams
    responses = rows(path, "http.response", "http.response.code", "tcp.stream")
    assert responses == [["200", streams[0]], ["200", streams[1]]], responses
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses == {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "answer_count": len(expected_answers),
            "answers": expected_answers, "dns_query_count": len(queries),
            "dns_names": sorted(names), "tcp_syn_count": len(syns),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "http_response_codes": [code for code, _ in responses],
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-answer-limit-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
