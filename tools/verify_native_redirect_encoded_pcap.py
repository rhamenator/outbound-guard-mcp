#!/usr/bin/env python3
"""Independently inspect a retained native redirect and encoded-body fixture capture."""

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
    assert len(syns) == 5 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", "/plain"), ("allowed.test", "/head-ok"),
        ("allowed.test", "/redirect"), ("allowed.test", "/gzip-bomb"),
        ("allowed.test", "/plain")], requests
    response_rows = rows(path, "http.response", "http.response.code", "http.location",
                         "http.content_encoding", "tcp.stream")
    assert len(response_rows) == 5, response_rows
    responses = {stream: (code, location, encoding)
                 for code, location, encoding, stream in response_rows}
    assert len(responses) == 5, response_rows
    assert [responses[stream][0] for _, _, stream in requests] == [
        "200", "200", "302", "200", "200"], responses
    redirect_stream = requests[2][2]
    gzip_stream = requests[3][2]
    assert responses[redirect_stream] == ("302", "http://private.test/plain", ""), responses
    assert responses[gzip_stream][0] == "200" and responses[gzip_stream][2] == "gzip", responses

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "http_requests": [(host, uri) for host, uri, _ in requests],
            "redirect_location": responses[redirect_stream][1],
            "encoded_response": responses[gzip_stream][2],
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-encoded-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
