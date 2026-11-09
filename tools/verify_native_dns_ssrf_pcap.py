#!/usr/bin/env python3
"""Recheck retained route-free native DNS, exfil, or EOF fixture captures with tshark."""

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


def verify(path: Path, digest: str, scenario: str = "dns-ssrf") -> dict:
    data = path.read_bytes()
    assert len(data) <= 1024 * 1024, "capture exceeds fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    destinations = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    expected_syns = 1 if scenario in ("eof-frame", "eof-active") else 3
    assert len(destinations) == expected_syns and set(destinations) == {("11.0.0.1", "80")}, destinations

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    if scenario == "dns-ssrf":
        assert {"allowed.test", "private.test", "alias-private.test", "mixed.test",
                "metadata.test", "loop-dns.test"} <= names, names
    else:
        assert "allowed.test" in names, names
        assert names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names
        if scenario == "synthetic-exfil":
            assert b"ghp_" not in data and b"exfil.test" not in data, "synthetic marker or exfil host in capture"
        else:
            assert b"private.test" not in data, "private target appeared in EOF capture"

    requests = rows(path, "http.request", "http.host", "http.request.uri")
    expected_requests = ([["allowed.test", "/cancel-silent-body"]] if scenario == "eof-active" else
                         [["allowed.test", "/plain"]] if scenario == "eof-frame" else
                         [["allowed.test", "/plain"], ["allowed.test", "/head-ok"],
                          ["allowed.test", "/plain"]])
    assert requests == expected_requests, requests

    active_close = None
    if scenario == "eof-active":
        request_frames = rows(path, "http.request", "frame.number", "tcp.stream")
        response_frames = rows(path, "tcp.srcport == 80 && tcp.len > 0", "frame.number", "tcp.stream")
        close_frames = rows(path, "tcp.dstport == 80 && (tcp.flags.fin == 1 || tcp.flags.reset == 1)",
                            "frame.number", "tcp.stream")
        assert len(request_frames) == 1 and len(response_frames) >= 1 and len(close_frames) == 1
        stream = request_frames[0][1]
        assert all(row[1] == stream for row in response_frames + close_frames)
        assert int(request_frames[0][0]) < int(response_frames[0][0]) < int(close_frames[0][0])
        active_close = {"response_data_before_client_close": True, "client_close_count": 1}

    destinations_all = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations_all for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "scenario": scenario, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "http_requests": requests,
            "ip_destinations": sorted(addresses), "active_close": active_close,
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--scenario", choices=("dns-ssrf", "synthetic-exfil", "eof-frame", "eof-active"), default="dns-ssrf")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.scenario), sort_keys=True))


if __name__ == "__main__":
    main()
