#!/usr/bin/env python3
"""Bind installed native HTTP 204 tail observations to retained fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import verify as verify_packets

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/native-installed-http-204-tail-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "7d66c584216fae55f787f29e2647a1ece733e592"
PACKAGE = "5cff70ba7012ca7624827c1c6c5a95b55be1ba3b5f85677406812256f49918f7"
SKILL = "fd92e70ba571cfd8cb14ad7fe2a934107d42a6bd578346d0308103a2be2d0d0e"
BINARY = "c5746a596aa33134e2381ed6ffebf3c98d396ef317607aebf47576cfb74ea35d"
CAPTURE_HASHES = {
    "claude": "5575e3358a472f8a90de42c708f45ccef70f914421700e3440d987d84aefbd65",
    "codex": "0c506f6db746cee2f2a2730e7d2cef291591f51f845242b79757326156365ac8",
}
RAW_LOG_HASHES = {
    "claude": "a4e51197af32f15abad3277b4e8589ce5a38dee3a25bced549a929dd680c765c",
    "codex": "daff881525c2782525ff4fecb22cd5f809c2bea6945c4f941033e89e70d6eac2",
}
PATHS = ["/plain", "/no-content-204-close-body",
         "/no-content-204-response-smuggle", "/plain"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade",
          "native_skill_and_guarded_calls", "unframed_204_tail_not_returned",
          "second_response_shape_not_returned", "fixture_namespace_tcp_syn_capture",
          "approved_recovery", "package_remove", "residue"]
HARNESS = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/debian_native_container_probe.py",
           "tools/netns_adversarial_probe.py", "tools/verify_native_framing_http_pcap.py"}


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["scenario"] == "installed-native-http-204-unframed-tail"
    assert record["result"] == "passed" and record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43634497792")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == "8d78b264cb441ac7637328de6d32e1e532c642e884bdfc2093aa8c8f344acc0b"
    assert record["package_sha256"] == PACKAGE and record["skill_zip_sha256"] == SKILL
    assert set(record["harness_sha256"]) == set(record["harness_git_blobs"]) == HARNESS
    for name, blob in record["harness_git_blobs"].items():
        source = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == record["harness_sha256"][name]
    assert set(record["cases"]) == set(CAPTURE_HASHES)
    for client, case in record["cases"].items():
        assert case["client_version"] == ("Claude Code 2.1.323" if client == "claude" else
                                          "codex-cli 0.168.0")
        assert case["native_skill_loaded"] is True
        assert (case["native_skill_invoked"] is True if client == "claude" else
                case["native_skill_discovered"] is True and
                case["explicit_skill_input_accepted"] is True and
                case["native_turn_completed"] is True)
        assert case["rules"] == ["EGRESS_ALLOWED"] * 4
        assert case["status_codes"] == [200, 204, 204, 200]
        assert case["fixture_hits"] == PATHS
        assert case["raw_log_sha256"] == RAW_LOG_HASHES[client]
        assert case["capture_path"] == f"tests/fixtures/packet-capture/native-{client}-204-tail-2026-11-14.pcap"
        assert case["capture_sha256"] == CAPTURE_HASHES[client]
        packet = case["packet_capture_summary"]
        assert packet["unexpected_tcp_connection_attempts"] == 0
        assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
        installed = case["installed_package"]
        assert installed["result"] == "passed" and installed["client"] == client
        assert installed["fixture_mode"] == "framing-http-204-tail-packet"
        assert installed["checks"] == CHECKS and installed["old_package"] is None
        assert installed["package"] == {
            "app_version": "0.1.0", "binary_sha256": BINARY,
            "package_sha256": PACKAGE, "revision": SOURCE,
            "version": "0.1.0~candidate.411+g7d66c584216f"}
        assert installed["skill_zip_sha256"] == SKILL
        resources = installed["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom_kill"] == 0
        assert case["packet_analysis"]["http_requests"] == [["allowed.test", p] for p in PATHS]


def rejects_packet_mutation(data, mutation):
    assert mutation != data
    with tempfile.TemporaryDirectory(prefix="outbound-204-tail-mutation-") as directory:
        path = Path(directory) / "fixture.pcap"
        path.write_bytes(mutation)
        try:
            verify_packets(path, hashlib.sha256(mutation).hexdigest(), "no-content-tail")
        except AssertionError:
            return
    raise AssertionError("semantic packet mutation passed after digest recomputation")


def main():
    record = json.loads(RECORD.read_text())
    verify_record(record)
    for client, case in record["cases"].items():
        capture = (ROOT / case["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
        data = capture.read_bytes()
        assert hashlib.sha256(data).hexdigest() == CAPTURE_HASHES[client]
        with tempfile.TemporaryDirectory(prefix="outbound-204-tail-") as directory:
            path = Path(directory) / "fixture.pcap"
            path.write_bytes(data)
            analyzed = verify_packets(path, CAPTURE_HASHES[client], "no-content-tail")
            assert json.loads(json.dumps(analyzed)) == case["packet_analysis"]
        rejects_packet_mutation(data, forbidden_syn(data))
        original = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz"
        changed = b"HTTP/1.1 201 OK\r\nContent-Length: 3\r\n\r\nxyz"
        assert data.count(original) == 1
        rejects_packet_mutation(data, data.replace(original, changed, 1))
    mutant = copy.deepcopy(record)
    mutant["cases"]["codex"]["status_codes"][2] = 200
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed 204 status passed record verifier")
    print("verified two installed native HTTP 204 tail workflows and packet captures")


if __name__ == "__main__":
    main()
