#!/usr/bin/env python3
"""Bind native pre-fix HTTP 205 leakage and post-upgrade denials to packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_upgrade_http_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
RECORD = ROOT / "docs/evidence/native-205-two-phase-upgrade-2026-11-14.json"
OLD_SOURCE = "a4ff70c2613d83fbea9c2fd34d6f893af4b6dae2"
NEW_SOURCE = "954b3853af68aa37afe062e1918fa59e26022a43"
OLD_PACKAGE = "958ed96b0312ea2e0147cd96c788b6e442a0b40c038848552f4751ebda7ea3ff"
NEW_PACKAGE = "715601fd32d3f7269bb11c8fc28bffe30e92554805bb8021ef8acde61600e0f8"
OLD_BINARY = "d3a9275325fda6f34c091909ff49349f79b438e5b81401d70f7fc2bffadd9706"
NEW_BINARY = "743226888b3ae61375366778eea1e51f6ee1fecc737f36254270ddd333f26c58"
CAPTURE_SHA256 = {
    "claude": "c2dd3920460c567964072add5fa0284864d74b89f928c70990834cff5c7098fb",
    "codex": "b241aaad7c6ccfb2be7eae311f493a1617929a7e6ba3f2432603b76d8dd8e68e",
}
PATHS = ["/plain", "/reset-content-205", "/reset-content-205-length",
         "/reset-content-205-chunked", "/reset-content-205-close", "/plain"]
OLD_RULES = ["EGRESS_ALLOWED"] * 6
NEW_RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
             "EGRESS_INVALID_FRAMING", "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED"]
CHECKS = ["same_container", "unchanged_saved_client_config", "old_native_calls",
          "in_place_package_upgrade", "new_native_calls", "controlled_http_and_dns",
          "remove", "residue", "route_free_fixture", "pre_fix_native_205_body_leak",
          "post_fix_native_205_denial", "packet_capture_verified"]


def expected_decisions(rules, old):
    output = []
    for index, (path, rule) in enumerate(zip(PATHS, rules)):
        item = {"url": "http://allowed.test" + path, "rule": rule,
                "status": "SAFE" if rule == "EGRESS_ALLOWED" else "BLOCKED"}
        if index == 1:
            item["body_text"] = ""
        elif old and index in (2, 3, 4):
            item["body_text"] = "ok"
        output.append(item)
    return output


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["result"] == "passed" and record["scenario"] == "reset-content"
    assert (record["old_source_main_sha"], record["new_source_main_sha"]) == (OLD_SOURCE, NEW_SOURCE)
    assert record["old_source_ci_run"].endswith("/43548601002")
    assert record["new_source_ci_run"].endswith("/43577512079")
    assert record["artifact_checksums_verified"] is True
    assert record["old_artifact_manifest_sha256"] == "8f2f17e4e7c91a92aa43287feeda57dadcfb2731972d0606bce004a99e2b5d01"
    assert record["new_artifact_manifest_sha256"] == "8c0e78cdbfb63bc534ea36743fd42f5afe43121213f6997a5c72acc5077b20a9"
    assert set(record["cases"]) == {"claude", "codex"}
    assert set(record["harness_git_blobs"]) == set(record["harness_sha256"]) == {
        "tools/debian_same_container_native_http_upgrade.py", "tools/verify_upgrade_http_pcap.py",
        "tools/client_cancellation_fixture.py", "tools/netns_adversarial_probe.py"}
    for name, blob in record["harness_git_blobs"].items():
        source = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == record["harness_sha256"][name]
    for client, run in record["cases"].items():
        assert run["result"] == "passed" and run["scenario"] == "reset-content"
        assert run["native_client"] == client and run["platform"] == "Debian 12 amd64"
        assert run["client"].startswith("2.1.323" if client == "claude" else "codex-cli 0.168.0")
        assert run["old_package"]["revision"] == OLD_SOURCE
        assert run["new_package"]["revision"] == NEW_SOURCE
        assert run["old_package"]["package_sha256"] == OLD_PACKAGE
        assert run["new_package"]["package_sha256"] == NEW_PACKAGE
        assert run["old_package"]["binary_sha256"] == OLD_BINARY
        assert run["new_package"]["binary_sha256"] == NEW_BINARY
        assert run["old_installed"]["binary_sha256"] == OLD_BINARY
        assert run["new_installed"]["binary_sha256"] == NEW_BINARY
        assert run["before"] == expected_decisions(OLD_RULES, True)
        assert run["after"] == expected_decisions(NEW_RULES, False)
        assert run["fixture_http_hits"] == PATHS * 2
        assert run["fixture_dns_a_before"] == run["fixture_dns_a_after"] == ["allowed.test"] * 6
        assert run["checks"] == CHECKS
        assert len(run["saved_mcp_config_sha256"]) == 64
        assert run["packet_capture"]["sha256"] == CAPTURE_SHA256[client]
        assert run["packet_capture"]["verified_raw_reset_content_responses"] == 8
        assert run["pcap_path"] == f"tests/fixtures/packet-capture/native-{client}-205-two-phase-upgrade-2026-11-14.pcap"


def main():
    record = json.loads(RECORD.read_text())
    verify_record(record)
    for client, run in record["cases"].items():
        capture = (ROOT / run["pcap_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
        data = capture.read_bytes()
        assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256[client]
        with tempfile.TemporaryDirectory(prefix="outbound-205-upgrade-verify-") as directory:
            target = Path(directory) / "fixture.pcap"
            target.write_bytes(data)
            assert verify_packets(target, CAPTURE_SHA256[client], "reset-content") == run["packet_capture"]
            for mutant in (forbidden_syn(data),
                           data.replace(b"HTTP/1.1 205 Reset Content", b"HTTP/1.1 200 Reset Content", 1)):
                assert mutant != data
                target.write_bytes(mutant)
                try:
                    verify_packets(target, hashlib.sha256(mutant).hexdigest(), "reset-content")
                except AssertionError:
                    pass
                else:
                    raise AssertionError("changed packet passed the HTTP 205 oracle")
            answer = (b"\x07allowed\x04test\x00\x00\x01\x00\x01"
                      b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                      b"\x0b\x00\x00\x01")
            assert data.count(answer) == 12
            changed_dns = data.replace(answer, answer[:-4] + b"\x7f\x00\x00\x01", 1)
            target.write_bytes(changed_dns)
            try:
                verify_packets(target, hashlib.sha256(changed_dns).hexdigest(), "reset-content")
            except AssertionError as error:
                assert "127.0.0.1" in str(error), error
            else:
                raise AssertionError("private DNS answer passed the HTTP 205 oracle")
    mutant = copy.deepcopy(record)
    mutant["cases"]["claude"]["after"][2]["rule"] = "EGRESS_ALLOWED"
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed native denial passed the record verifier")
    print("verified native Claude and Codex two-phase HTTP 205 upgrade packets and decisions")


if __name__ == "__main__":
    main()
