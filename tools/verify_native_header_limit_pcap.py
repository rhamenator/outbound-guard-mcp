#!/usr/bin/env python3
"""Independently inspect a retained native oversized HTTP header capture."""

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


def server_payload(path: Path, stream: str) -> bytes:
    assert stream.isdecimal(), stream
    segments = rows(path, f"tcp.stream == {stream} && tcp.srcport == 80 && tcp.len > 0",
                    "tcp.payload")
    assert segments and all(len(row) == 1 and row[0] for row in segments), segments
    return b"".join(bytes.fromhex(segment) for [segment] in segments)


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
    assert len(queries) == 11 and all(ip == "127.0.0.1" and port == "53"
                                      for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    expected_paths = ["/plain", "/many-headers", "/oversized-header", "/parser-limit", "/plain"]
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in expected_paths], requests

    responses = {}
    for uri in ("/many-headers", "/oversized-header", "/parser-limit"):
        streams = {stream for _, request_uri, stream in requests if request_uri == uri}
        assert len(streams) == 1, (uri, streams)
        payload = server_payload(path, next(iter(streams)))
        assert payload.startswith(b"HTTP/1.0 200 OK\r\n"), uri
        assert payload.count(b"X-Fixture-Large: ") == (0 if uri == "/many-headers" else 1), uri
        if uri == "/many-headers":
            headers, separator, body = payload.partition(b"\r\n\r\n")
            assert separator and body == b"ok", uri
            fixture_lines = [line for line in headers.split(b"\r\n") if line.startswith(b"X-Fixture-")]
            assert fixture_lines == [f"X-Fixture-{index}: ok".encode()
                                     for index in range(70)], uri
            responses[uri] = len(fixture_lines)
        elif uri == "/oversized-header":
            headers, separator, body = payload.partition(b"\r\n\r\n")
            assert separator and body == b"ok", uri
            large = [line for line in headers.split(b"\r\n")
                     if line.startswith(b"X-Fixture-Large: ")]
            assert large == [b"X-Fixture-Large: " + b"x" * 24576], uri
            responses[uri] = 24576
        else:
            assert b"\r\n\r\n" not in payload and len(payload) == 128000, len(payload)
            prefix, marker, value = payload.partition(b"X-Fixture-Large: ")
            assert marker and prefix.startswith(b"HTTP/1.0 200 OK\r\n"), uri
            assert value and value == b"x" * len(value), uri
            responses[uri] = len(value)

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "http_requests": [(host, uri) for host, uri, _ in requests],
            "fixture_header_observations": responses, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-header-limit-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
