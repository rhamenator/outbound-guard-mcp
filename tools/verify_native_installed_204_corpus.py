#!/usr/bin/env python3
"""Recheck installed native-client HTTP 204 decisions and fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import verify as verify_packets

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/native-installed-http-204-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "d8ff7ffea94b5258106236f7cf1c89ad458f7b10"
PACKAGE = "70a508bce8e19d4f9190589b77b4d92e043e4057725106076d1fc1b64d890f9b"
BINARY = "c5746a596aa33134e2381ed6ffebf3c98d396ef317607aebf47576cfb74ea35d"
SKILL = "d3102510b37998f7a96245701c64f70751af28347b30f859c52e7eb29e435ee0"
CAPTURE_HASHES = {
    "claude": "324f119c77515a5d9b93949d280cf40876f772370eed6719fa8170ce9ab4140d",
    "codex": "b3437b07d7e8248ca7443cbe2d0a3fbc64f5b70204744bc2c6c37a75e6c4fc76",
}
RAW_LOG_HASHES = {
    "claude": "31283375d08643ebf49077f62877f104cc494b8b08e72b65b885f482b7b5dec5",
    "codex": "1d0101f18f323ab26563a49cd8c80b513f296111451468da2291bfae23973f11",
}
PATHS = ["/plain", "/no-content-204", "/no-content-204-length",
         "/no-content-204-chunked", "/reset-content-205", "/plain"]
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
         "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED", "EGRESS_ALLOWED"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade",
          "native_skill_and_guarded_calls", "clean_204_205_controls",
          "nonzero_length_204_denial", "chunked_204_denial",
          "no_denied_body_text", "fixture_namespace_tcp_syn_capture",
          "approved_recovery", "package_remove", "residue"]
HARNESS = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/debian_native_container_probe.py",
           "tools/netns_adversarial_probe.py", "tools/verify_native_framing_http_pcap.py"}


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["scenario"] == "installed-native-http-204-framing"
    assert record["result"] == "passed" and record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43618712952")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == "bf310184f2a518fbc98cddbe15f942faa2dba62586e3ea5e20062b3615502550"
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
        assert case["rules"] == RULES and case["status_codes"] == [200, 204, 205, 200]
        assert case["fixture_hits"] == PATHS
        assert case["raw_log_sha256"] == RAW_LOG_HASHES[client]
        assert case["capture_path"] == f"tests/fixtures/packet-capture/native-{client}-installed-204-2026-11-14.pcap"
        assert case["capture_sha256"] == CAPTURE_HASHES[client]
        assert case["packet_capture_summary"]["unexpected_tcp_connection_attempts"] == 0
        assert case["packet_capture_summary"]["tcp_syn_destinations"] == ["11.0.0.1:80"]
        installed = case["installed_package"]
        assert installed["result"] == "passed" and installed["client"] == client
        assert installed["fixture_mode"] == "framing-http-204-packet"
        assert installed["checks"] == CHECKS and installed["old_package"] is None
        assert installed["package"] == {
            "app_version": "0.1.0", "binary_sha256": BINARY,
            "package_sha256": PACKAGE, "revision": SOURCE,
            "version": "0.1.0~candidate.408+gd8ff7ffea94b"}
        assert installed["skill_zip_sha256"] == SKILL
        resources = installed["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom_kill"] == 0
        assert case["packet_analysis"]["http_requests"] == [["allowed.test", path] for path in PATHS]


def main():
    record = json.loads(RECORD.read_text())
    verify_record(record)
    for client, case in record["cases"].items():
        capture = (ROOT / case["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
        data = capture.read_bytes()
        assert hashlib.sha256(data).hexdigest() == CAPTURE_HASHES[client]
        with tempfile.TemporaryDirectory(prefix="outbound-installed-204-") as directory:
            target = Path(directory) / "fixture.pcap"
            target.write_bytes(data)
            analyzed = verify_packets(target, CAPTURE_HASHES[client], "no-content")
            assert json.loads(json.dumps(analyzed)) == case["packet_analysis"]
            mutant = forbidden_syn(data)
            target.write_bytes(mutant)
            try:
                verify_packets(target, hashlib.sha256(mutant).hexdigest(), "no-content")
            except AssertionError:
                pass
            else:
                raise AssertionError("forbidden SYN passed packet verifier")
    mutant = copy.deepcopy(record)
    mutant["cases"]["codex"]["rules"][2] = "EGRESS_ALLOWED"
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed 204 decision passed record verifier")
    print("verified two installed native HTTP 204 workflows and packet captures")


if __name__ == "__main__":
    main()
