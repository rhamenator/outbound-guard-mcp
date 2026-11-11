#!/usr/bin/env python3
"""Verify a retained same-container HTTP/DNS upgrade fixture capture."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_native_framing_http_pcap import rows, server_payload


def fields(path, display_filter, *names):
    command = ["tshark", "-n", "-r", str(path), "-Y", display_filter,
               "-T", "fields", "-E", "separator=;"]
    for name in names:
        command.extend(("-e", name))
    return [line.split(";") for line in subprocess.check_output(
        command, text=True, timeout=15).splitlines()]


def verify(path, expected_sha256, scenario="dns"):
    assert scenario in ("dns", "redirect", "held-encoded", "version"), "unsupported capture scenario"
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024, "capture size outside fixture bounds"
    digest = hashlib.sha256(data).hexdigest()
    assert digest == expected_sha256, "capture SHA-256 mismatch"
    # The local tshark AppArmor profile permits fixture captures under /tmp.
    with tempfile.TemporaryDirectory(prefix="outbound-upgrade-pcap-") as directory:
        readable = Path(directory) / "fixture.pcap"
        shutil.copyfile(path, readable)
        return verify_fields(readable, digest, scenario)


def verify_fields(path, digest, scenario):
    syns = fields(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst", "ipv6.dst", "tcp.dstport")
    tcp_destinations = [(ipv4 or ipv6, port) for ipv4, ipv6, port in syns]
    syn_count_ok = len(tcp_destinations) == (2 if scenario == "dns" else 12 if scenario == "version" else 6)
    assert syn_count_ok and \
        set(tcp_destinations) == {("11.0.0.1", "80")}, tcp_destinations
    queries = fields(path, "dns.flags.response == 0", "dns.qry.name", "ip.dst", "udp.dstport")
    assert queries and all(ip == "127.0.0.1" and port == "53" for _, ip, port in queries), queries
    a_names = [name for name, _, _ in fields(
        path, "dns.flags.response == 0 && dns.qry.type == 1", "dns.qry.name", "ip.dst", "udp.dstport")]
    expected_a_names = (["allowed.test", "private.test"] * 2 if scenario == "dns"
                        else ["allowed.test"] * (12 if scenario == "version" else 6))
    assert a_names == expected_a_names, a_names
    if scenario == "version":
        answers = fields(path, "dns.flags.response == 1", "dns.qry.type", "dns.qry.name",
                         "dns.a", "dns.aaaa", "dns.flags.rcode", "dns.count.answers")
        assert answers == ([
            ["1", "allowed.test", "11.0.0.1", "", "0", "1"],
            ["28", "allowed.test", "", "", "0", "0"],
        ] * 12), answers
    forbidden_queries = {"unlisted.test"}
    if scenario == "redirect":
        forbidden_queries.add("private.test")
    assert not forbidden_queries & {name for name, _, _ in queries}, queries
    requests = fields(path, "http.request", "http.host", "http.request.uri")
    expected_requests = (["/plain"] * 2 if scenario == "dns"
                         else ["/plain", "/redirect", "/plain"] * 2
                         if scenario == "redirect" else
                         ["/plain", "/encoded-body-hold", "/plain"] * 2
                         if scenario == "held-encoded" else
                         ["/plain", "/http10-ok", "/http10-comma-length",
                          "/http11-partial-ok", "/http11-partial-comma-length", "/plain"] * 2)
    assert requests == [["allowed.test", uri] for uri in expected_requests], requests
    version_responses = 0
    if scenario == "version":
        streams = fields(path, "http.request", "http.request.uri", "tcp.stream")
        for uri, stream in streams:
            if uri.startswith("/http10-") or uri.startswith("/http11-partial-"):
                payload = server_payload(path, stream)
                headers, separator, body = payload.partition(b"\r\n\r\n")
                expected_status = (b"HTTP/1.0 200 OK" if uri.startswith("/http10-")
                                   else b"HTTP/1.1 206 Partial Content")
                expected_length = (b"2, 2" if uri.endswith("comma-length") else b"2")
                assert separator and headers == (expected_status + b"\r\nContent-Type: text/plain\r\nContent-Length: "
                                                 + expected_length) and body == b"ok", (uri, payload)
                version_responses += 1
        assert version_responses == 8, version_responses
    held_closes = 0
    if scenario == "held-encoded":
        streams = fields(path, "http.request", "http.request.uri", "tcp.stream")
        for uri, stream in streams:
            if uri != "/encoded-body-hold":
                continue
            payload = server_payload(path, stream)
            headers, separator, body = payload.partition(b"\r\n\r\n")
            assert separator and headers.startswith((b"HTTP/1.0 200 OK\r\n",
                                                     b"HTTP/1.1 200 OK\r\n"))
            lines = headers.split(b"\r\n")[1:]
            assert [line for line in lines if line.startswith(
                (b"Content-Encoding:", b"Content-Length:"))] == [
                    b"Content-Encoding: gzip", b"Content-Length: 8388608"], lines
            assert body == b"\x1f\x8b\x08", body
            server_frames = rows(path, f"tcp.stream == {stream} && tcp.srcport == 80 && tcp.len > 0",
                                 "frame.number")
            client_closes = rows(path, f"tcp.stream == {stream} && tcp.dstport == 80 && "
                                       "(tcp.flags.fin == 1 || tcp.flags.reset == 1)",
                                 "frame.number")
            assert server_frames and client_closes
            assert any(int(number) > max(int(item) for [item] in server_frames)
                       for [number] in client_closes)
            held_closes += 1
        assert held_closes == 2, held_closes
    addresses = {item for ipv4, ipv6 in fields(path, "ip || ipv6", "ip.dst", "ipv6.dst")
                 for item in (ipv4 or ipv6).split(",") if item}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}, addresses
    result = {"sha256": digest, "scenario": scenario, "tcp_syn_count": len(syns),
              "dns_a_queries": a_names, "http_requests": requests,
              "ip_destinations": sorted(addresses), "scope": "fixture namespace only"}
    if scenario == "held-encoded":
        result["held_client_close_after_partial_response_count"] = held_closes
    if scenario == "version":
        result["verified_raw_version_responses"] = version_responses
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("sha256")
    parser.add_argument("--scenario", choices=("dns", "redirect", "held-encoded", "version"), default="dns")
    args = parser.parse_args()
    print(json.dumps(verify(args.pcap, args.sha256, args.scenario), sort_keys=True))


if __name__ == "__main__":
    main()
