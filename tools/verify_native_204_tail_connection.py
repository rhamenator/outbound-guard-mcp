#!/usr/bin/env python3
"""Check that retained native HTTP 204 tails do not reach a later fetch socket."""

import hashlib
import json
from decimal import Decimal
from pathlib import Path
import shutil
import tempfile

from verify_native_framing_http_pcap import rows, verify as verify_framing
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/native-http-204-tail-connection-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
HASHES = {
    "claude": "5575e3358a472f8a90de42c708f45ccef70f914421700e3440d987d84aefbd65",
    "codex": "0c506f6db746cee2f2a2730e7d2cef291591f51f845242b79757326156365ac8",
}
PATHS = ["/plain", "/no-content-204-close-body",
         "/no-content-204-response-smuggle", "/plain"]
KEEPALIVE_PATHS = ["/plain", "/no-content-204-keepalive-tail",
                   "/no-content-204-explicit-keepalive-tail", "/plain"]


def one_event(path, display_filter, *fields):
    result = rows(path, display_filter, *fields)
    assert len(result) == 1 and all(value for value in result[0]), (display_filter, result)
    return result[0]


def analyze(path, digest, mode="no-content-tail"):
    assert mode in ("no-content-tail", "no-content-keepalive-tail")
    expected_paths = KEEPALIVE_PATHS if mode == "no-content-keepalive-tail" else PATHS
    verified = verify_framing(path, digest, mode)
    requests = rows(path, "http.request", "frame.number", "frame.time_relative",
                    "tcp.stream", "http.request.uri")
    assert [item[3] for item in requests] == expected_paths, requests
    streams = [item[2] for item in requests]
    assert len(streams) == len(set(streams)) == 4, streams
    result = []
    for index, (request_frame, request_time, stream, uri) in enumerate(requests):
        expr = f"tcp.stream == {stream}"
        syn_frame, syn_time = one_event(
            path, expr + " && tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 80",
            "frame.number", "frame.time_relative")
        client_data = rows(path, expr + " && tcp.dstport == 80 && tcp.len > 0",
                           "frame.number", "frame.time_relative")
        assert client_data == [[request_frame, request_time]], (uri, client_data)
        server_data = rows(path, expr + " && tcp.srcport == 80 && tcp.len > 0",
                           "frame.number", "frame.time_relative")
        assert server_data, (uri, server_data)
        last_data_frame, last_data_time = server_data[-1]
        close_frame, close_time = one_event(
            path, expr + " && tcp.dstport == 80 && "
                  "(tcp.flags.fin == 1 || tcp.flags.reset == 1)",
            "frame.number", "frame.time_relative")
        assert (int(syn_frame) < int(request_frame) < int(last_data_frame)
                < int(close_frame)), (uri, syn_frame, request_frame, last_data_frame, close_frame)
        delay = Decimal(close_time) - Decimal(last_data_time)
        assert Decimal(0) <= delay <= Decimal("0.250"), (uri, delay)
        entry = {"path": uri, "tcp_stream": int(stream),
                 "syn_frame": int(syn_frame), "request_frame": int(request_frame),
                 "server_last_data_frame": int(last_data_frame),
                 "client_close_frame": int(close_frame),
                 "server_data_to_client_close_ms": float(delay * 1000)}
        if index + 1 < len(requests):
            next_stream = streams[index + 1]
            next_syn_frame, next_syn_time = one_event(
                path, f"tcp.stream == {next_stream} && tcp.flags.syn == 1 && "
                      "tcp.flags.ack == 0 && tcp.dstport == 80",
                "frame.number", "frame.time_relative")
            assert int(close_frame) < int(next_syn_frame), (uri, close_frame, next_syn_frame)
            assert Decimal(close_time) < Decimal(next_syn_time), (uri, close_time, next_syn_time)
            entry["next_syn_after_close_ms"] = float(
                (Decimal(next_syn_time) - Decimal(close_time)) * 1000)
        result.append(entry)
    return {"capture_sha256": digest, "paths": expected_paths,
            "streams": result, "raw_response_verified": verified["framing_metadata_and_body"],
            "scope": "fixture namespace only"}


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["analysis_source_main_sha"] == "248ff22ce343de2976326af4e7fc9f091e5ab7af"
    assert record["tested_binary_main_sha"] == "7d66c584216fae55f787f29e2647a1ece733e592"
    assert record["tested_package_sha256"] == "5cff70ba7012ca7624827c1c6c5a95b55be1ba3b5f85677406812256f49918f7"
    assert record["prior_native_evidence"] == "docs/evidence/native-installed-http-204-tail-2026-11-14.json"
    assert record["result"] == "passed"
    assert set(record["cases"]) == set(HASHES)
    for client, entry in record["cases"].items():
        assert entry["client_version"] == ("Claude Code 2.1.323" if client == "claude" else
                                           "codex-cli 0.168.0")
        assert entry["capture_path"] == f"tests/fixtures/packet-capture/native-{client}-204-tail-2026-11-14.pcap"
        assert entry["capture_sha256"] == HASHES[client]
        assert entry["analysis"]["capture_sha256"] == HASHES[client]
        assert entry["analysis"]["paths"] == PATHS
        assert len(entry["analysis"]["streams"]) == 4


def main():
    record = json.loads(RECORD.read_text())
    verify_record(record)
    for client, entry in record["cases"].items():
        capture = (ROOT / entry["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
        data = capture.read_bytes()
        assert hashlib.sha256(data).hexdigest() == HASHES[client]
        with tempfile.TemporaryDirectory(prefix="outbound-204-tail-close-") as directory:
            path = Path(directory) / "fixture.pcap"
            shutil.copyfile(capture, path)
            assert analyze(path, HASHES[client]) == entry["analysis"]
            close_frames = {item["client_close_frame"] for item in entry["analysis"]["streams"][1:3]}
            assert len(close_frames) == 2
            mutation = late_close(data, close_frames)
            path.write_bytes(mutation)
            try:
                analyze(path, hashlib.sha256(mutation).hexdigest())
            except AssertionError as error:
                assert "/no-content-204-" in str(error), error
            else:
                raise AssertionError("late client closes passed the connection oracle")
    print("verified native HTTP 204 tail connection isolation and late-close controls")


if __name__ == "__main__":
    main()
