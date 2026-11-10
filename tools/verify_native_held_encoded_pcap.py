#!/usr/bin/env python3
"""Check a retained native-client capture of an incomplete held gzip response."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from verify_native_framing_http_pcap import rows, server_payload


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
    assert queries and all(ip == "127.0.0.1" and port == "53"
                           for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    expected_paths = ["/plain", "/encoded-body-hold", "/plain"]
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in expected_paths], requests
    for _, uri, approved_stream in requests:
        if uri == "/plain":
            approved = server_payload(path, approved_stream)
            approved_headers, separator, approved_body = approved.partition(b"\r\n\r\n")
            assert separator and approved_headers.startswith((b"HTTP/1.0 200 OK\r\n",
                                                               b"HTTP/1.1 200 OK\r\n"))
            assert approved_body == b"fixture-ok", approved_body
    streams = [stream for _, uri, stream in requests if uri == "/encoded-body-hold"]
    assert len(streams) == 1 and streams[0].isdecimal(), streams
    stream = streams[0]
    payload = server_payload(path, stream)
    headers, separator, body = payload.partition(b"\r\n\r\n")
    assert separator and headers.startswith((b"HTTP/1.0 200 OK\r\n",
                                             b"HTTP/1.1 200 OK\r\n")), headers
    lines = headers.split(b"\r\n")[1:]
    assert [line for line in lines if line.startswith(
        (b"Content-Encoding:", b"Content-Length:"))] == [
            b"Content-Encoding: gzip", b"Content-Length: 8388608"], lines
    assert body == b"\x1f\x8b\x08", body
    server_frames = rows(path, f"tcp.stream == {stream} && tcp.srcport == 80 && tcp.len > 0",
                         "frame.number")
    client_closes = rows(path, f"tcp.stream == {stream} && tcp.dstport == 80 && "
                               "(tcp.flags.fin == 1 || tcp.flags.reset == 1)",
                         "frame.number", "tcp.flags.fin", "tcp.flags.reset")
    assert server_frames and client_closes, (server_frames, client_closes)
    last_server_frame = max(int(number) for [number] in server_frames)
    assert any(int(number) > last_server_frame for number, _, _ in client_closes), client_closes

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns),
            "dns_query_count": len(queries), "dns_names": sorted(names),
            "http_requests": [(host, uri) for host, uri, _ in requests],
            "held_body_hex": body.hex(), "held_content_length": 8388608,
            "client_close_after_partial_response": True,
            "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-held-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
