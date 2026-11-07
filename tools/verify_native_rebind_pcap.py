#!/usr/bin/env python3
"""Independently check a retained native-client DNS rebinding fixture capture."""

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
    assert len(data) <= 1024 * 1024, "capture exceeds fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    destinations = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    assert len(destinations) == 3 and set(destinations) == {("11.0.0.1", "80")}, destinations

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 9 and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert {"allowed.test", "rebind.test"} <= names, names
    assert names <= {"allowed.test", "rebind.test", "1.0.0.11.in-addr.arpa"}, names
    rebind_queries = rows(path, 'dns.flags.response == 0 && dns.qry.name == "rebind.test" && dns.qry.type == 1',
                          "dns.qry.name")
    assert len(rebind_queries) == 2, rebind_queries
    rebind_answers = rows(path, 'dns.flags.response == 1 && dns.qry.name == "rebind.test" && dns.a', "dns.a")
    assert rebind_answers == [["11.0.0.1"], ["127.0.0.1"]], rebind_answers

    requests = rows(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"], ["rebind.test", "/plain"],
                        ["allowed.test", "/plain"]], requests

    all_destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in all_destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns),
            "tcp_syn_destinations": sorted(set(destinations)),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "rebind_a_answers": rebind_answers, "http_requests": requests,
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
