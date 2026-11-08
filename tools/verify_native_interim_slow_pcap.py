#!/usr/bin/env python3
"""Independently verify a retained native HTTP 103 slow-drip fixture capture."""

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
    assert len(syns) == 3 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    names = {name for name, _, _ in queries}
    assert queries and "allowed.test" in names and names <= {
        "allowed.test", "1.0.0.11.in-addr.arpa"}, queries
    assert all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", "/plain"), ("allowed.test", "/interim-slow-drip"),
        ("allowed.test", "/plain")], requests
    streams = [stream for _, _, stream in requests]
    assert len(set(streams)) == 3, streams

    responses = rows(path, "http.response", "http.response.code", "tcp.stream", "frame.time_epoch")
    assert [code for code, stream, _ in responses if stream == streams[0]] == ["200"], responses
    assert [code for code, stream, _ in responses if stream == streams[2]] == ["200"], responses
    interim = [float(timestamp) for code, stream, timestamp in responses
               if stream == streams[1] and code == "103"]
    assert len(interim) in range(20, 23), responses
    assert all(code == "103" for code, stream, _ in responses if stream == streams[1]), responses
    intervals = [right - left for left, right in zip(interim, interim[1:])]
    assert intervals and all(0.25 <= interval <= 0.9 for interval in intervals), intervals
    assert 9.4 <= interim[-1] - interim[0] <= 10.4, interim

    closes = rows(path, f"tcp.stream == {streams[1]} && tcp.dstport == 80 && "
                  "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.time_epoch")
    assert closes, "timed-out stream lacks client FIN/RST"
    close_seconds = float(closes[0][0]) - interim[0]
    assert 9.5 <= close_seconds <= 10.5, close_seconds

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "interim_103_count": len(interim),
            "interim_span_seconds": round(interim[-1] - interim[0], 3),
            "client_close_seconds_after_first_103": round(close_seconds, 3),
            "timed_out_stream_client_closed": True,
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-interim-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
