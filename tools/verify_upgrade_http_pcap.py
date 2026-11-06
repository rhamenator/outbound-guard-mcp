#!/usr/bin/env python3
"""Verify a retained same-container HTTP/DNS upgrade fixture capture."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def fields(path, display_filter, *names):
    command = ["tshark", "-n", "-r", str(path), "-Y", display_filter,
               "-T", "fields", "-E", "separator=;"]
    for name in names:
        command.extend(("-e", name))
    return [line.split(";") for line in subprocess.check_output(
        command, text=True, timeout=15).splitlines()]


def verify(path, expected_sha256):
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture bounds"
    digest = hashlib.sha256(data).hexdigest()
    assert digest == expected_sha256, "capture SHA-256 mismatch"
    # The local tshark AppArmor profile permits fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-upgrade-pcap-") as directory:
        readable = Path(directory) / "fixture.pcap"
        shutil.copyfile(path, readable)
        return verify_fields(readable, digest)


def verify_fields(path, digest):
    syns = fields(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst", "ipv6.dst", "tcp.dstport")
    tcp_destinations = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    assert len(tcp_destinations) == 2 and set(tcp_destinations) == {("11.0.0.1", "80")}, tcp_destinations
    queries = fields(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    a_names = [name for name, _, _ in fields(
        path, "dns.flags.response == 0 && dns.qry.type == 1", "dns.qry.name", "ip.dst", "udp.dstport")]
    assert a_names == ["allowed.test", "private.test", "allowed.test", "private.test"], a_names
    assert "unlisted.test" not in [name for name, _, _ in queries], queries
    requests = fields(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"], ["allowed.test", "/plain"]], requests
    addresses = {item for ipv4, ipv6 in fields(path, "ip || ipv6", "ip.dst", "ipv6.dst")
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": digest, "tcp_syn_count": len(syns), "dns_a_queries": a_names,
            "http_requests": requests, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    print(json.dumps(verify(args.pcap, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
