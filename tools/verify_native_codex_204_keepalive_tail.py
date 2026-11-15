#!/usr/bin/env python3
"""Recheck native Codex 204 keep-alive tail decisions and fixture TCP isolation."""

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_native_204_tail_connection import analyze
from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import rows
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/native-codex-204-keepalive-tail-2026-11-15.json"
CAPTURE_DIR = ROOT / "tests/fixtures/packet-capture"
PATHS = ["/plain", "/no-content-204-keepalive-tail",
         "/no-content-204-explicit-keepalive-tail", "/plain"]
CAPTURE_SHA256 = "13cf9faa5eb876542af699edf5b98bdde8a2cc62bba3b80492712ff1e40d8c88"
BINARY_SHA256 = "a9d9501749018ca47a07948be5f8c9fbffb5010b1de5a4e3079041a4f63bcd14"
SKILL_SHA256 = "fd92e70ba571cfd8cb14ad7fe2a934107d42a6bd578346d0308103a2be2d0d0e"


def check_capture(path, digest):
    result = analyze(path, digest, "no-content-keepalive-tail")
    assert result["paths"] == PATHS
    assert not rows(path, "tcp.flags.reset == 1", "frame.number")
    for stream in result["streams"][1:3]:
        number = stream["tcp_stream"]
        client_fin = rows(path, f"tcp.stream == {number} && tcp.dstport == 80 && tcp.flags.fin == 1",
                          "frame.number")
        server_fin = rows(path, f"tcp.stream == {number} && tcp.srcport == 80 && tcp.flags.fin == 1",
                          "frame.number")
        final_ack = rows(path, f"tcp.stream == {number} && tcp.dstport == 80 && "
                              f"tcp.flags.ack == 1 && frame.number > {server_fin[0][0]}",
                         "frame.number") if len(server_fin) == 1 else []
        assert (len(client_fin) == len(server_fin) == len(final_ack) == 1
                and int(client_fin[0][0]) == stream["client_close_frame"]
                and int(client_fin[0][0]) < int(server_fin[0][0]) < int(final_ack[0][0])), stream
    return result


def main():
    record = json.loads(RECORD.read_text())
    assert record["date_utc"] == "2026-11-15" and record["result"] == "passed_codex_only"
    assert record["source_main_sha"] == "6490e709dc822ada363685eb515ec75398aff11e"
    assert record["client_version"] == "codex-cli 0.168.0"
    assert record["client_probe_git_blob"] == "7aa06b0784fd69ecec24160658f8b7735b3da3c3"
    assert record["fixture_git_blob"] == "a66dd7b73cba61df80609397d40dfe435ff2f186"
    assert record["tested_binary_sha256"] == BINARY_SHA256
    assert record["skill_zip_sha256"] == SKILL_SHA256
    assert record["capture_sha256"] == CAPTURE_SHA256
    for key in ("client_probe_git_blob", "fixture_git_blob"):
        subprocess.check_output(["git", "cat-file", "blob", record[key]], cwd=ROOT, timeout=10)
    assert record["decisions"] == {
        "rules": ["EGRESS_ALLOWED"] * 4,
        "status_codes": [200, 204, 204, 200],
        "fixture_hits": PATHS,
        "http_methods": ["GET"] * 4,
    }
    assert record["skill"] == {
        "loaded": True, "discovered": True,
        "explicit_input_accepted": True, "turn_completed": True,
    }
    assert record["claude_attempt"]["counts_as_coverage"] is False
    packet = record["packet_summary"]
    assert packet["pcap_sha256"] == record["capture_sha256"]
    assert packet["tcp_syn_count"] == 4 and packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURE_DIR) and 24 < capture.stat().st_size < 100_000
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == record["capture_sha256"]
    log_path = (ROOT / record["log_path"]).resolve(strict=True)
    assert log_path.is_relative_to(ROOT / "docs/evidence") and log_path.stat().st_size < 100_000
    log = gzip.decompress(log_path.read_bytes())
    assert len(log) < 100_000 and hashlib.sha256(log).hexdigest() == record["log_sha256_uncompressed"]
    summary = json.loads(log.decode().splitlines()[-1])
    assert summary["binary_sha256"] == record["tested_binary_sha256"]
    assert summary["skill_zip_sha256"] == record["skill_zip_sha256"]
    assert {key: summary[key] for key in ("rules", "status_codes", "fixture_hits", "http_methods")} == record["decisions"]
    assert summary["packet_capture"] == packet
    with tempfile.TemporaryDirectory(prefix="outbound-native-204-keepalive-") as directory:
        temporary = Path(directory) / "fixture.pcap"  # tshark AppArmor permits the private copy.
        shutil.copyfile(capture, temporary)
        assert check_capture(temporary, record["capture_sha256"]) == record["analysis"]
        closes = {entry["client_close_frame"] for entry in record["analysis"]["streams"][1:3]}
        assert len(closes) == 2
        for mutation, label in ((late_close(data, closes), "late close"),
                                (forbidden_syn(data), "metadata SYN")):
            temporary.write_bytes(mutation)
            try:
                check_capture(temporary, hashlib.sha256(mutation).hexdigest())
            except AssertionError:
                pass
            else:
                raise AssertionError(f"{label} passed the native 204 oracle")
    print("native Codex 204 keep-alive tail packet isolation and negative controls passed")


if __name__ == "__main__":
    main()
