#!/usr/bin/env python3
"""Verify a changed-binary Debian upgrade and native Claude HTTP 205 replay."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-claude-upgrade-205-pcap-2026-11-14.json"
BASELINE = ROOT / "docs/evidence/http-205-content-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
OLD_SOURCE = "a4ff70c2613d83fbea9c2fd34d6f893af4b6dae2"
NEW_SOURCE = "954b3853af68aa37afe062e1918fa59e26022a43"
OLD_PACKAGE = "958ed96b0312ea2e0147cd96c788b6e442a0b40c038848552f4751ebda7ea3ff"
NEW_PACKAGE = "715601fd32d3f7269bb11c8fc28bffe30e92554805bb8021ef8acde61600e0f8"
OLD_BINARY = "d3a9275325fda6f34c091909ff49349f79b438e5b81401d70f7fc2bffadd9706"
NEW_BINARY = "743226888b3ae61375366778eea1e51f6ee1fecc737f36254270ddd333f26c58"
SKILL = "d3102510b37998f7a96245701c64f70751af28347b30f859c52e7eb29e435ee0"
CAPTURE = "16ee123db1e103ec925229d58b740add6661c24ca9ebd71527f5adafaef6ab35"
HARNESS = {
    "tools/client_cancellation_fixture.py": ("425a72487b6ebfa7debc492fc5899c3632671c1c", "44f8424d07618aece654c7d2dcbc481f6b4dbbeaf5f9bd9fc22b1a2284a33550"),
    "tools/client_cancellation_probe.py": ("5e897a9ab11f5aad07dbd65fdf938647250d10a2", "4aa7f89da1672b21d6391c7e5ea23027a3931b9f4b45867e9f15842b674ed279"),
    "tools/client_wire_bridge.py": ("c66a04f6d83e605988fe3f64bcddff7b5cf7f391", "a00b1c09b912e08f339d559ac232e6e0637a1fa16b49a69cfa989e81705f4e22"),
    "tools/debian_native_container_probe.py": ("67675113f9e96b85ea287e7868a1a0380c061f74", "e9f55c70330185136f3260af71280ad82ab023ba042731e05f1c583f5d0dd566"),
    "tools/netns_adversarial_probe.py": ("aa46aca9ed578fe0a4b73c7d5f17efd66546f946", "6382c8744a368a53d57033efcac64c4c73177cf39d0fe27e6a0dca5776bf7ccf"),
    "tools/verify_native_framing_http_pcap.py": ("e10a7f2b803b18e8f7f01390caa977f0b2a35645", "042a69c2bdddc1c77ff071a68221715768b8cc17bb07b6a0771029a2981a5aff"),
}
PATHS = ["/plain", "/reset-content-205", "/reset-content-205-length",
         "/reset-content-205-chunked", "/reset-content-205-close", "/plain"]
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
         "EGRESS_INVALID_FRAMING", "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED"]
CHECKS = ["checksum", "clean_dpkg_install", "package_upgrade",
          "old_package_launch_and_loopback_denial", "native_skill_and_guarded_calls",
          "nonzero_length_205_denial", "chunked_205_denial",
          "close_delimited_205_denial", "no_denied_body_text",
          "fixture_namespace_tcp_syn_capture", "approved_recovery",
          "package_remove", "residue"]


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["old_source_main_sha"] == OLD_SOURCE
    assert record["new_source_main_sha"] == NEW_SOURCE
    assert record["old_source_ci_run"].endswith("/43548601002")
    assert record["new_source_ci_run"].endswith("/43577512079")
    assert record["artifact_checksums_verified"] is True
    assert record["old_artifact_manifest_sha256"] == "8f2f17e4e7c91a92aa43287feeda57dadcfb2731972d0606bce004a99e2b5d01"
    assert record["new_artifact_manifest_sha256"] == "8c0e78cdbfb63bc534ea36743fd42f5afe43121213f6997a5c72acc5077b20a9"
    assert record["client_version"] == "Claude Code 2.1.323"
    assert record["raw_log_sha256"] == "2472e09665f470e03b9c9471b009beee7efe8386b2055917c626ace2b075682f"
    assert record["skill_zip_sha256"] == SKILL
    assert record["harness_git_blobs"] == {name: pair[0] for name, pair in HARNESS.items()}
    assert record["harness_sha256"] == {name: pair[1] for name, pair in HARNESS.items()}
    for name, (blob, digest) in HARNESS.items():
        source = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    baseline = json.loads(BASELINE.read_text())
    assert baseline["base_main_sha"] == OLD_SOURCE
    assert baseline["baseline_package_sha256"] == OLD_PACKAGE
    assert baseline["baseline_binary_sha256"] == OLD_BINARY
    assert baseline["baseline_body_text"][2:5] == ["ok"] * 3
    native = record["native_client"]
    assert native["client"] == "claude" and native["framing_mode"] is True
    for field in ("native_skill_loaded", "native_skill_invoked",
                  "skill_tool_result_success"):
        assert native[field] is True, field
    assert native["installation_scope"] == "temporary project .claude/skills/outbound-guard"
    assert native["binary_sha256"] == "c4cd5962c34d933d111d762c7fbf3c0d865ec4fc25ef79e26a5fa431640acf12"
    assert native["skill_zip_sha256"] == SKILL
    assert native["rules"] == RULES and native["http_methods"] == ["GET"] * 6
    assert native["status_codes"] == [200, 205, 200]
    assert native["fixture_hits"] == PATHS
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True and packet["pcap_sha256"] == CAPTURE
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    upgrade = record["installed_upgrade"]
    assert upgrade["result"] == "passed" and upgrade["client"] == "claude"
    assert upgrade["fixture_mode"] == "framing-http-205-packet"
    assert upgrade["checks"] == CHECKS
    assert upgrade["old_package"] == {
        "app_version": "0.1.0", "binary_sha256": OLD_BINARY,
        "package_sha256": OLD_PACKAGE, "revision": OLD_SOURCE,
        "version": "0.1.0~candidate.396+ga4ff70c2613d"}
    assert upgrade["package"] == {
        "app_version": "0.1.0", "binary_sha256": NEW_BINARY,
        "package_sha256": NEW_PACKAGE, "revision": NEW_SOURCE,
        "version": "0.1.0~candidate.401+g954b3853af68"}
    assert upgrade["skill_zip_sha256"] == SKILL
    resources = upgrade["container_resource_observation"]
    assert resources["memory_limit_mib"] == 128
    assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
    assert resources["memory_events"]["oom_kill"] == 0
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-claude-upgrade-205-2026-11-14.pcap"
    assert record["capture_sha256"] == CAPTURE
    assert record["packet_analysis"]["http_requests"] == [["allowed.test", path] for path in PATHS]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE
    with tempfile.TemporaryDirectory(prefix="outbound-claude-upgrade-205-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        checked = json.loads(json.dumps(verify_packets(target, CAPTURE, "reset-content")))
        assert checked == record["packet_analysis"]
        mutant = forbidden_syn(data)
        target.write_bytes(mutant)
        try:
            verify_packets(target, hashlib.sha256(mutant).hexdigest(), "reset-content")
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("forbidden SYN passed packet verifier")
    mutant = copy.deepcopy(record)
    mutant["installed_upgrade"]["checks"].remove("package_upgrade")
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("missing upgrade check passed record verifier")
    mutant = copy.deepcopy(record)
    mutant["native_client"]["rules"][2] = "EGRESS_ALLOWED"
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed native denial passed record verifier")
    print("verified changed-binary Claude HTTP 205 upgrade and fixture packets")


if __name__ == "__main__":
    main()
