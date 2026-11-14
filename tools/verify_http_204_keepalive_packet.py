#!/usr/bin/env python3
"""Verify the focused direct-MCP 204 tail capture and connection retirement."""

from decimal import Decimal
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_native_framing_http_pcap import rows, server_payload
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/http-204-keepalive-packet-2026-11-14.json"
CAPTURE = ROOT / "tests/fixtures/packet-capture/direct-204-keepalive-tail-2026-11-14.pcap"
DIGEST = "10fe24a3e223365c806533ec6e71b8e6d319e3b6070b2748c0390ca1608f7234"
FIXTURE_BLOB = "57488c34207ef2a8c995447d0aecc8d25261028f"
FIXTURE_SHA256 = "8281d78b765a9fb2777cb692af665e067fbfa530bea8cd232e41e47d8b4afa91"
FIRST_RESPONSE = (b"HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n"
                  b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz")
PATHS = ["/no-content-204-keepalive-tail", "/plain"]


def one(path, display_filter, *fields):
    found = rows(path, display_filter, *fields)
    assert len(found) == 1 and all(found[0]), (display_filter, found)
    return found[0]


def analyze(path, digest):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                "ip.dst", "tcp.dstport", "tcp.stream")
    assert len(syns) == 2 and all(ip == "11.0.0.1" and port == "80"
                                   for ip, port, _ in syns), syns
    requests = rows(path, "http.request && tcp.dstport == 80", "frame.number",
                    "frame.time_relative", "tcp.stream", "http.request.uri")
    assert [row[3] for row in requests] == PATHS, requests
    assert len({row[2] for row in requests}) == 2
    assert [row[2] for row in requests] == [row[2] for row in syns]
    assert not rows(path, "tcp.flags.reset == 1", "frame.number")
    connections = []
    first_fin_seq = first_server_fin_seq = None
    for request_frame, request_time, stream, uri in requests:
        prefix = f"tcp.stream == {stream} && "
        syn_frame, _ = one(path, prefix + "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                           "frame.number", "frame.time_relative")
        client_data = rows(path, prefix + "tcp.dstport == 80 && tcp.len > 0",
                           "frame.number", "tcp.payload")
        assert len(client_data) == 1 and client_data[0][0] == request_frame, (uri, client_data)
        request_bytes = bytes.fromhex(client_data[0][1])
        assert request_bytes.startswith(f"GET {uri} HTTP/1.1\r\n".encode()), uri
        assert b"host: allowed.test\r\n" in request_bytes.lower(), uri
        assert b"connection: close\r\n" in request_bytes.lower(), uri
        data_frames = rows(path, prefix + "tcp.srcport == 80 && tcp.len > 0",
                           "frame.number", "frame.time_relative")
        assert data_frames, uri
        last_data_frame, last_data_time = data_frames[-1]
        client_fin, client_fin_time, client_fin_seq = one(
            path, prefix + "tcp.dstport == 80 && tcp.flags.fin == 1",
            "frame.number", "frame.time_relative", "tcp.seq")
        server_fin, server_fin_time, server_fin_seq = one(
            path, prefix + "tcp.srcport == 80 && tcp.flags.fin == 1",
            "frame.number", "frame.time_relative", "tcp.seq")
        assert int(syn_frame) < int(request_frame) < int(last_data_frame), uri
        assert Decimal(last_data_time) <= Decimal(client_fin_time), (uri, last_data_time, client_fin_time)
        connections.append({"path": uri, "stream": int(stream), "syn_frame": int(syn_frame),
                            "request_frame": int(request_frame),
                            "server_last_data_frame": int(last_data_frame),
                            "client_fin_frame": int(client_fin), "server_fin_frame": int(server_fin),
                            "server_data_to_client_fin_ms": float(
                                (Decimal(client_fin_time) - Decimal(last_data_time)) * 1000)})
        if uri == PATHS[0]:
            first_fin_seq, first_server_fin_seq = int(client_fin_seq), int(server_fin_seq)
            assert server_payload(path, stream) == FIRST_RESPONSE
            assert int(last_data_frame) < int(client_fin) < int(server_fin), uri
            assert Decimal(client_fin_time) - Decimal(last_data_time) <= Decimal("0.250"), uri
            assert Decimal(server_fin_time) >= Decimal(client_fin_time), uri
        else:
            response = server_payload(path, stream)
            head, separator, body = response.partition(b"\r\n\r\n")
            assert separator and head.startswith(b"HTTP/1.0 200 OK\r\n"), response
            assert b"Content-Length: 10\r\n" in head + b"\r\n", response
            assert body == b"fixture-ok", response
    first_stream = requests[0][2]
    last_first_frame, last_first_time, last_first_seq, last_first_ack = one(
        path, f"tcp.stream == {first_stream} && tcp.dstport == 80 && tcp.flags.ack == 1 && "
              "tcp.flags.fin == 0 && frame.number > " + str(connections[0]["server_fin_frame"]),
        "frame.number", "frame.time_relative", "tcp.seq", "tcp.ack")
    assert int(last_first_seq) == first_fin_seq + 1
    assert int(last_first_ack) == first_server_fin_seq + 1
    second_syn_frame, second_syn_time = one(
        path, f"tcp.stream == {requests[1][2]} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "frame.number", "frame.time_relative")
    assert int(last_first_frame) < int(second_syn_frame)
    assert Decimal(last_first_time) < Decimal(second_syn_time)
    return {"capture_sha256": digest, "paths": PATHS, "connections": connections,
            "second_syn_after_first_final_ack_ms": float(
                (Decimal(second_syn_time) - Decimal(last_first_time)) * 1000),
            "packet_scope": "fixture namespace TCP port 80 only"}


def main():
    record = json.loads(RECORD.read_text())
    assert record["source_main_sha"] == "c0d79accfbf3cb2c5c76775602e017316c95ea5f"
    assert record["fixture_git_blob"] == FIXTURE_BLOB
    fixture = subprocess.check_output(["git", "cat-file", "blob", FIXTURE_BLOB],
                                      cwd=ROOT, timeout=10)
    assert hashlib.sha256(fixture).hexdigest() == FIXTURE_SHA256 == record["fixture_sha256"]
    assert record["result"] == "passed" and record["capture_sha256"] == DIGEST
    assert record["capture_path"] == str(CAPTURE.relative_to(ROOT))
    assert 24 < CAPTURE.stat().st_size < 100_000
    assert record["log_path"] == "docs/evidence/http-204-keepalive-packet-2026-11-14.log.gz"
    log_path = ROOT / record["log_path"]
    assert log_path.stat().st_size < 100_000
    log = gzip.decompress(log_path.read_bytes())
    assert len(log) < 100_000
    assert hashlib.sha256(log).hexdigest() == record["log_sha256_uncompressed"]
    assert b"unframed 204 second-response tail without a close header" in log
    assert b"netns adversarial probe: 2256 MCP decisions;" in log
    with tempfile.TemporaryDirectory(prefix="outbound-204-keepalive-packet-") as directory:
        temporary = Path(directory) / "fixture.pcap"
        shutil.copyfile(CAPTURE, temporary)  # tshark AppArmor allows the private temp copy.
        original = analyze(temporary, DIGEST)
        assert original == record["analysis"]
        mutant = late_close(temporary.read_bytes(), {original["connections"][0]["client_fin_frame"]})
        temporary.write_bytes(mutant)
        try:
            analyze(temporary, hashlib.sha256(mutant).hexdigest())
        except AssertionError as error:
            assert PATHS[0] in str(error), error
        else:
            raise AssertionError("six-second late close passed the packet oracle")
    print("direct MCP 204 keepalive-tail packet isolation and late-close control passed")


if __name__ == "__main__":
    main()
