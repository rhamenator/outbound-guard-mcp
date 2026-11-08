#!/usr/bin/env python3
"""Independently inspect a retained native TLS hostname/DNS-flip fixture capture."""

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

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    connections = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    assert connections == [("11.0.0.2", "443"), ("11.0.0.1", "80")], connections

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert {"tls-handshake.test", "allowed.test"} <= names and names <= {
        "tls-handshake.test", "allowed.test", "1.0.0.11.in-addr.arpa",
        "2.0.0.11.in-addr.arpa"}, names
    answers = rows(path, 'dns.flags.response == 1 && dns.qry.name == "tls-handshake.test" && dns.a',
                   "dns.a")
    assert answers == [["11.0.0.2,11.0.0.1"], ["127.0.0.1"]], answers

    hellos = rows(path, "tls.handshake.type == 1 && tcp.dstport == 443",
                  "tls.handshake.extensions_server_name", "ip.dst")
    assert hellos == [["tls-handshake.test", "11.0.0.2"]], hellos
    requests = rows(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"]], requests

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "11.0.0.2", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_destinations": [f"{ip}:{port}" for ip, port in connections],
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "tls_host_a_answers": [answer[0] for answer in answers],
            "tls_client_hello": hellos[0], "approved_http_requests": requests,
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-tls-pinning-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
