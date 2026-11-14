#!/usr/bin/env python3
"""Bind the installed Codex HTTP 205 replay to package and fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_framing_http_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-installed-codex-205-pcap-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "692ff9d3bb858effc37fc0980fa4189c124fac75"
PACKAGE_SHA256 = "dd36ddbcdfa25b220e58844c77a4c905755dbee038e920dee617fdba4c8be605"
BINARY_SHA256 = "743226888b3ae61375366778eea1e51f6ee1fecc737f36254270ddd333f26c58"
SKILL_SHA256 = "d3102510b37998f7a96245701c64f70751af28347b30f859c52e7eb29e435ee0"
CAPTURE_SHA256 = "c8536d5ee807873aaf92cf5b7ab5292fd4a645f8c25118375ac46c4ce65a4c53"
HARNESS = {
    "tools/client_cancellation_fixture.py": ("425a72487b6ebfa7debc492fc5899c3632671c1c", "44f8424d07618aece654c7d2dcbc481f6b4dbbeaf5f9bd9fc22b1a2284a33550"),
    "tools/client_cancellation_probe.py": ("5e897a9ab11f5aad07dbd65fdf938647250d10a2", "4aa7f89da1672b21d6391c7e5ea23027a3931b9f4b45867e9f15842b674ed279"),
    "tools/client_wire_bridge.py": ("c66a04f6d83e605988fe3f64bcddff7b5cf7f391", "a00b1c09b912e08f339d559ac232e6e0637a1fa16b49a69cfa989e81705f4e22"),
    "tools/debian_native_container_probe.py": ("67675113f9e96b85ea287e7868a1a0380c061f74", "e9f55c70330185136f3260af71280ad82ab023ba042731e05f1c583f5d0dd566"),
    "tools/netns_adversarial_probe.py": ("aa46aca9ed578fe0a4b73c7d5f17efd66546f946", "6382c8744a368a53d57033efcac64c4c73177cf39d0fe27e6a0dca5776bf7ccf"),
    "tools/verify_native_framing_http_pcap.py": ("e10a7f2b803b18e8f7f01390caa977f0b2a35645", "042a69c2bdddc1c77ff071a68221715768b8cc17bb07b6a0771029a2981a5aff"),
}
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
         "EGRESS_INVALID_FRAMING", "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED"]
PATHS = ["/plain", "/reset-content-205", "/reset-content-205-length",
         "/reset-content-205-chunked", "/reset-content-205-close", "/plain"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade",
          "native_skill_and_guarded_calls", "nonzero_length_205_denial",
          "chunked_205_denial", "close_delimited_205_denial",
          "no_denied_body_text", "fixture_namespace_tcp_syn_capture",
          "approved_recovery", "package_remove", "residue"]


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43572962642")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == "00d47953c8822b9e2e19b5e2b6186479467ccfd2946b326c56f4936d797fa617"
    assert record["client_version"] == "Codex CLI 0.168.0"
    assert record["raw_log_sha256"] == "19772a432d4d71d85adc67f1e9a71b88cf69fbd702daad0764edb688b932e15d"
    assert record["skill_zip_sha256"] == SKILL_SHA256
    assert record["harness_git_blobs"] == {name: pair[0] for name, pair in HARNESS.items()}
    assert record["harness_sha256"] == {name: pair[1] for name, pair in HARNESS.items()}
    for name, (blob, digest) in HARNESS.items():
        source = subprocess.check_output(["git", "cat-file", "blob", blob], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    native = record["native_client"]
    assert native["client"] == "codex" and native["framing_mode"] is True
    for field in ("native_skill_loaded", "native_skill_discovered",
                  "explicit_skill_input_accepted", "native_turn_completed"):
        assert native[field] is True, field
    assert native["installation_scope"] == "temporary project .agents/skills/outbound-guard"
    # The native probe hashes its temporary wrapper; the package records installed binary bytes.
    assert native["binary_sha256"] == "3d4a3b325154e6ef4b505f26b4d5dfb5bbb3b1d74186e05ea1fa8bb545483a41"
    assert native["skill_zip_sha256"] == SKILL_SHA256
    assert native["rules"] == RULES and native["http_methods"] == ["GET"] * 6
    assert native["status_codes"] == [200, 205, 200]
    assert native["fixture_hits"] == PATHS
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    installed = record["installed_package"]
    assert installed["result"] == "passed" and installed["client"] == "codex"
    assert installed["fixture_mode"] == "framing-http-205-packet"
    assert installed["checks"] == CHECKS and installed["old_package"] is None
    assert installed["package"] == {
        "app_version": "0.1.0", "binary_sha256": BINARY_SHA256,
        "package_sha256": PACKAGE_SHA256, "revision": SOURCE,
        "version": "0.1.0~candidate.400+g692ff9d3bb85"}
    assert installed["skill_zip_sha256"] == SKILL_SHA256
    resources = installed["container_resource_observation"]
    assert resources["memory_limit_mib"] == 128
    assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
    assert resources["memory_events"]["oom_kill"] == 0
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-installed-codex-205-2026-11-14.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["http_requests"] == [["allowed.test", path] for path in PATHS]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-installed-codex-205-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        checked = json.loads(json.dumps(verify_packets(target, CAPTURE_SHA256, "reset-content")))
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
    mutant["native_client"]["rules"][2] = "EGRESS_ALLOWED"
    try:
        verify_record(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("altered Codex denial passed record verifier")
    print("verified installed Codex HTTP 205 package lifecycle, native decisions and packets")


if __name__ == "__main__":
    main()
