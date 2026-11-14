#!/usr/bin/env python3
"""Independently inspect a retained native conflicting HTTP framing capture."""

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


def verify(path: Path, digest: str, mode: str = "framing") -> dict:
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture limit"
    actual = hashlib.sha256(data).hexdigest()
    assert actual == digest, "capture SHA-256 mismatch"

    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "ipv6.dst", "tcp.dstport")
    assert len(syns) == (5 if mode in ("comma", "coding") else 6) and {(ipv4 or ipv6, port) for ipv4, ipv6, port in syns} == {
        ("11.0.0.1", "80")}, syns

    queries = rows(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert len(queries) == (11 if mode in ("comma", "coding") else 13) and all(ip == "127.0.0.1" and port == "53"
                                      for _, ip, port in queries), queries
    names = {name for name, _, _ in queries}
    assert "allowed.test" in names and names <= {"allowed.test", "1.0.0.11.in-addr.arpa"}, names

    requests = rows(path, "http.request", "http.host", "http.request.uri", "tcp.stream")
    expected_paths = (["/plain", "/http10-ok", "/http10-comma-length",
                       "/http11-partial-ok", "/http11-partial-comma-length", "/plain"]
                      if mode == "version" else
                      ["/plain", "/no-content-204", "/no-content-204-length",
                       "/no-content-204-chunked", "/reset-content-205", "/plain"]
                      if mode == "no-content" else
                      ["/plain", "/reset-content-205", "/reset-content-205-length",
                       "/reset-content-205-chunked", "/reset-content-205-close", "/plain"]
                      if mode == "reset-content" else
                      ["/plain", "/reset-content-205", "/reset-content-205-chunked-empty",
                       "/reset-content-205-multichunk", "/reset-content-205-close-multi", "/plain"]
                      if mode == "reset-content-variable" else
                      ["/plain", "/comma-length-equal", "/comma-length-conflict",
                       "/repeated-chunked-coding", "/plain"] if mode == "comma" else
                      ["/plain", "/coding-mutant-0", "/coding-mutant-3",
                       "/coding-mutant-5", "/plain"] if mode == "coding" else
                      ["/plain", "/obs-fold-length", "/obs-fold-encoding",
                       "/obs-fold-connection", "/obs-fold-extension", "/plain"]
                      if mode == "obs-fold" else
                      ["/plain", "/conflict-framing", "/duplicate-length",
                       "/stacked-transfer-coding", "/duplicate-transfer-coding", "/plain"])
    assert [(host, uri) for host, uri, _ in requests] == [
        ("allowed.test", uri) for uri in expected_paths], requests

    expected_metadata = {
        "/conflict-framing": ([b"Content-Length: 2", b"Transfer-Encoding: chunked"],
                              b"2\r\nok\r\n0\r\n\r\n"),
        "/duplicate-length": ([b"Content-Length: 2", b"Content-Length: 3"], b"ok"),
        "/stacked-transfer-coding": ([b"Transfer-Encoding: gzip, chunked"],
                                     b"2\r\nok\r\n0\r\n\r\n"),
        "/duplicate-transfer-coding": ([b"Transfer-Encoding: chunked"] * 2,
                                       b"2\r\nok\r\n0\r\n\r\n"),
    }
    if mode == "version":
        expected_metadata = {
            "/http10-ok": ([b"Content-Type: text/plain", b"Content-Length: 2"], b"ok"),
            "/http10-comma-length": ([b"Content-Type: text/plain", b"Content-Length: 2, 2"], b"ok"),
            "/http11-partial-ok": ([b"Content-Type: text/plain", b"Content-Length: 2"], b"ok"),
            "/http11-partial-comma-length": ([b"Content-Type: text/plain", b"Content-Length: 2, 2"], b"ok"),
        }
    elif mode == "no-content":
        expected_metadata = {
            "/no-content-204": ([b"Content-Type: text/plain"], b""),
            "/no-content-204-length": ([b"Content-Type: text/plain", b"Content-Length: 2"], b"ok"),
            "/no-content-204-chunked": ([b"Content-Type: text/plain", b"Transfer-Encoding: chunked"],
                                           b"2\r\nok\r\n0\r\n\r\n"),
            "/reset-content-205": ([b"Content-Type: text/plain", b"Content-Length: 0"], b""),
        }
    elif mode == "reset-content":
        expected_metadata = {
            "/reset-content-205": ([b"Content-Type: text/plain", b"Content-Length: 0"], b""),
            "/reset-content-205-length": ([b"Content-Type: text/plain", b"Content-Length: 2"], b"ok"),
            "/reset-content-205-chunked": ([b"Content-Type: text/plain", b"Transfer-Encoding: chunked"],
                                            b"2\r\nok\r\n0\r\n\r\n"),
            "/reset-content-205-close": ([b"Content-Type: text/plain", b"Connection: close"], b"ok"),
        }
    elif mode == "reset-content-variable":
        expected_metadata = {
            "/reset-content-205": ([b"Content-Type: text/plain", b"Content-Length: 0"], b""),
            "/reset-content-205-chunked-empty": ([b"Content-Type: text/plain", b"Transfer-Encoding: chunked"], b"0\r\n\r\n"),
            "/reset-content-205-multichunk": ([b"Content-Type: text/plain", b"Transfer-Encoding: chunked"], b"2\r\nab\r\n1\r\nc\r\n0\r\n\r\n"),
            "/reset-content-205-close-multi": ([b"Content-Type: text/plain", b"Connection: close"], b"abc"),
        }
    elif mode == "comma":
        expected_metadata = {
            "/comma-length-equal": ([b"Content-Length: 2, 2"], b"ok"),
            "/comma-length-conflict": ([b"Content-Length: 2, 3"], b"ok"),
            "/repeated-chunked-coding": ([b"Transfer-Encoding: chunked, chunked"],
                                          b"2\r\nok\r\n0\r\n\r\n"),
        }
    elif mode == "coding":
        expected_metadata = {
            "/coding-mutant-0": ([b"Transfer-Encoding: gzip72580, chunked"],
                                 b"2\r\nok\r\n0\r\n\r\n"),
            "/coding-mutant-3": ([b"Transfer-Encoding: chunked;param=70025"],
                                 b"2\r\nok\r\n0\r\n\r\n"),
            "/coding-mutant-5": ([b"Transfer-Encoding: chunked36027"],
                                 b"2\r\nok\r\n0\r\n\r\n"),
        }
    elif mode == "obs-fold":
        expected_metadata = {
            "/obs-fold-length": ([b"Content-Type: text/plain", b"Content-Length: 2",
                                  b" 3"], b"ok"),
            "/obs-fold-encoding": ([b"Content-Type: text/plain", b"Content-Encoding: identity",
                                    b" gzip", b"Content-Length: 2"], b"ok"),
            "/obs-fold-connection": ([b"Content-Type: text/plain", b"Connection: keep-alive,",
                                      b" Upgrade", b"Content-Length: 2"], b"ok"),
            "/obs-fold-extension": ([b"Content-Type: text/plain", b"X-Fixture: first",
                                     b" second", b"Content-Length: 2"], b"ok"),
        }
    verified = {}
    for uri, (expected_headers, expected_body) in expected_metadata.items():
        streams = {stream for _, request_uri, stream in requests if request_uri == uri}
        assert len(streams) == 1, (uri, streams)
        payload = server_payload(path, next(iter(streams)))
        headers, separator, body = payload.partition(b"\r\n\r\n")
        expected_status = (b"HTTP/1.0 200 OK" if uri.startswith("/http10-") else
                           b"HTTP/1.1 206 Partial Content" if uri.startswith("/http11-partial-") else
                           b"HTTP/1.1 204 No Content" if uri.startswith("/no-content-204") else
                           b"HTTP/1.1 205 Reset Content" if uri.startswith("/reset-content-205") else None)
        assert separator and (headers.startswith(expected_status + b"\r\n") if expected_status else
                              headers.startswith((b"HTTP/1.0 200 OK\r\n",
                                                  b"HTTP/1.1 200 OK\r\n"))), uri
        actual_headers = headers.split(b"\r\n")[1:]
        checked_headers = (actual_headers if mode in ("obs-fold", "version", "no-content", "reset-content", "reset-content-variable") else
                           [line for line in actual_headers if line.startswith(
                               (b"Content-Length:", b"Transfer-Encoding:"))])
        assert checked_headers == expected_headers, (uri, checked_headers)
        assert body == expected_body, (uri, body)
        verified[uri] = True

    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {item for ipv4, ipv6 in destinations
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    return {"sha256": actual, "tcp_syn_count": len(syns), "dns_query_count": len(queries),
            "dns_names": sorted(names), "http_requests": [(host, uri) for host, uri, _ in requests],
            "framing_metadata_and_body": verified, "ip_destinations": sorted(addresses),
            "scope": "fixture namespace only"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--mode", choices=("framing", "comma", "coding", "obs-fold", "version", "no-content", "reset-content", "reset-content-variable"), default="framing")
    args = parser.parse_args()
    # The local tshark AppArmor profile reads fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-framing-pcap-verify-") as directory:
        copy = Path(directory) / "fixture.pcap"
        shutil.copyfile(args.pcap, copy)
        print(json.dumps(verify(copy, args.sha256, args.mode), sort_keys=True))


if __name__ == "__main__":
    main()
