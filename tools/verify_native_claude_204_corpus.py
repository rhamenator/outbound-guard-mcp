#!/usr/bin/env python3
"""Bind the current Claude HTTP 204 decisions to retained hostile fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-claude-current-204-pcap-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "5eaec39b50b9a9dbad78aa03d65994a79651fee4"
MANIFEST_SHA256 = "f7f3602ad386e7c03eb6dfe4f8b77862baa362fa860ff65ab13545b781fbedd7"
PACKAGE_SHA256 = "7efca9344aa5659aec6fb8c14df333434a375e58bc76a030a17e355c2fdcb344"
BINARY_SHA256 = "d3a9275325fda6f34c091909ff49349f79b438e5b81401d70f7fc2bffadd9706"
SKILL_SHA256 = "d3102510b37998f7a96245701c64f70751af28347b30f859c52e7eb29e435ee0"
INSTALLED_SKILL_SHA256 = "118b54a4ef0fa7308c3cf49ab7dc1d026c95ad01aadaaa03bd3dfa6be1741ce2"
CAPTURE_SHA256 = "6a9e0fd7e3807f9a89586f4a6f412aa0fb06439bbf7f281fcf3b64b82529d4c0"
RAW_LOG_SHA256 = "86368addd92c9e38e81f93408465605538397e2379512d81c134cb0b7ab90b16"
HARNESS = {
    "tools/client_cancellation_fixture.py": ("425a72487b6ebfa7debc492fc5899c3632671c1c", "44f8424d07618aece654c7d2dcbc481f6b4dbbeaf5f9bd9fc22b1a2284a33550"),
    "tools/client_cancellation_probe.py": ("0ca328f47b443608e743c99aec447030395be612", "8b61b71a1e4e2581d520e4b6294a24b32f3f1c8847af7294323d288af6562e2b"),
    "tools/client_wire_bridge.py": ("c66a04f6d83e605988fe3f64bcddff7b5cf7f391", "a00b1c09b912e08f339d559ac232e6e0637a1fa16b49a69cfa989e81705f4e22"),
    "tools/netns_adversarial_probe.py": ("4ddfc854ae3c84494754f3730a7f3e972a20618f", "56750b15b7900fb82f20d10e84e83b5e6b6960f4baec09048af7efe6031f5f4e"),
}
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
         "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED", "EGRESS_ALLOWED"]
PATHS = ["/plain", "/no-content-204", "/no-content-204-length",
         "/no-content-204-chunked", "/reset-content-205", "/plain"]


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43543592126")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == MANIFEST_SHA256
    assert record["client_version"] == "Claude Code 2.1.323"
    assert record["raw_log_sha256"] == RAW_LOG_SHA256
    assert record["harness_sha256"] == {name: digest for name, (_, digest) in HARNESS.items()}
    assert record["harness_git_blobs"] == {name: blob for name, (blob, _) in HARNESS.items()}
    for name, digest in record["harness_sha256"].items():
        blob = record["harness_git_blobs"][name]
        assert len(blob) == 40 and all(c in "0123456789abcdef" for c in blob)
        source = subprocess.check_output(["git", "cat-file", "blob", blob],
                                         cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    package = record["package"]
    assert package == {"version": "0.1.0~candidate.395+g5eaec39b50b9",
                       "revision": SOURCE, "package_sha256": PACKAGE_SHA256,
                       "binary_sha256": BINARY_SHA256}
    assert record["skill_zip_sha256"] == SKILL_SHA256
    native = record["native_client"]
    assert native["client"] == "claude" and native["framing_mode"] is True
    for field in ("native_skill_loaded", "native_skill_invoked",
                  "skill_tool_result_success", "native_project_source_observed"):
        assert native[field] is True, field
    assert native["installation_scope"] == "temporary project .claude/skills/outbound-guard"
    assert native["skill_zip_sha256"] == SKILL_SHA256
    assert native["installed_skill_sha256"] == INSTALLED_SKILL_SHA256
    assert native["binary_sha256"] == BINARY_SHA256
    assert native["http_methods"] == ["GET"] * 6
    assert native["rules"] == RULES
    assert native["status_codes"] == [200, 204, 205, 200]
    assert native["fixture_hits"] == PATHS
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-claude-current-204-2026-11-14.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    analysis = record["packet_analysis"]
    assert analysis["sha256"] == CAPTURE_SHA256
    assert analysis["http_requests"] == [["allowed.test", path] for path in PATHS]
    assert analysis["framing_metadata_and_body"] == {path: True for path in PATHS[1:5]}
    assert analysis["tcp_syn_count"] == 6 and analysis["dns_query_count"] == 13
    assert analysis["dns_names"] == ["1.0.0.11.in-addr.arpa", "allowed.test"]
    assert analysis["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-claude-204-verify-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        checked = json.loads(json.dumps(verify_packets(target, CAPTURE_SHA256, "no-content")))
        assert checked == record["packet_analysis"]
        mutant = forbidden_syn(data)
        target.write_bytes(mutant)
        try:
            verify_packets(target, hashlib.sha256(mutant).hexdigest(), "no-content")
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("checksum-corrected forbidden SYN passed packet verifier")
    mutant = copy.deepcopy(record)
    mutant["native_client"]["rules"][2] = "EGRESS_ALLOWED"
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("altered Claude denial passed record verifier")
    print("verified native Claude HTTP 204 denials, raw packets and negative controls")


if __name__ == "__main__":
    main()
