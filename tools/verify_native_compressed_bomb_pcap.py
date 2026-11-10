#!/usr/bin/env python3
"""Independently check retained native gzip/deflate denial wire captures."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import zlib

from verify_native_framing_http_pcap import rows, server_payload


DECODED_BYTES = 8 * 1024 * 1024


def verify(path: Path, digest: str) -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert len(syns) == 4 and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns
    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == 9 and all(ip == "127.0.0.1" and port == "53"
                                     for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    expected_paths = ["/plain", "/gzip-bomb", "/deflate-bomb", "/plain"]
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in expected_paths], requests

    bombs = {}
    for uri, encoding, wbits in (("/gzip-bomb", b"gzip", 16 + zlib.MAX_WBITS),
                                 ("/deflate-bomb", b"deflate", zlib.MAX_WBITS)):
        streams = {stream for _, request_uri, stream in requests if request_uri == uri}
        assert len(streams) == 1, (uri, streams)
        payload = server_payload(path, next(iter(streams)))
        headers, separator, body = payload.partition(b"\r\n\r\n")
        assert separator and headers.startswith((b"HTTP/1.0 200 OK\r\n",
                                                 b"HTTP/1.1 200 OK\r\n")), uri
        lines = headers.split(b"\r\n")[1:]
        assert [line for line in lines if line.startswith(
            (b"Content-Encoding:", b"Content-Length:"))] == [
                b"Content-Encoding: " + encoding,
                b"Content-Length: " + str(len(body)).encode()], (uri, lines)
        assert 0 < len(body) < 16 * 1024, (uri, len(body))
        decoder = zlib.decompressobj(wbits)
        decoded = decoder.decompress(body, DECODED_BYTES + 1)
        assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, uri
        assert len(decoded) == DECODED_BYTES and set(decoded) == {ord("x")}, uri
        bombs[uri] = {"encoding": encoding.decode(), "wire_body_bytes": len(body),
                      "decoded_bytes": len(decoded)}

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "http_requests": [(host, uri) for host, uri, _ in requests],
            "bombs": bombs, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-bomb-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256), sort_keys=True))


if __name__ == "__main__":
    main()
