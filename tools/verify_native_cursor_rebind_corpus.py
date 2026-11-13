#!/usr/bin/env python3
"""Recheck current Cursor CLI rebinding decisions and retained fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_rebind_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-current-rebind-pcap-2026-11-13.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "97a4ef0eb818bbf3732b9876bc3a7d05a09adc2e"
MANIFEST_SHA256 = "272ddd122a390040ab49777b1cf786c0ddc008f3189ca191f2016c9368cfc509"
PACKAGE_SHA256 = "17ed9b45789c395f7bdde97f44c1bc8fbc2e62cecae4f7e62502aca1314ad242"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
CAPTURE_SHA256 = "a12ac9cb8fe1f4e208f20c51fdcdde8e074aa2ee91cc058e3401d2ffd4498479"
RAW_LOG_SHA256 = "270b9d2a421b730af4f63b21f7eab5081b86823145dce22f8ef6dd85a61e52a3"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}


def verify_record(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43405096244")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == MANIFEST_SHA256
    assert record["client_version"] == "Cursor CLI 2026.10.19-6bbf2c4"
    assert record["raw_log_sha256"] == RAW_LOG_SHA256
    assert set(record["harness_sha256"]) == SOURCES
    for name, digest in record["harness_sha256"].items():
        source = subprocess.check_output(["git", "show", f"{SOURCE}:{name}"],
                                         cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    package = record["package"]
    assert package["revision"] == SOURCE
    assert package["version"] == "0.1.0~candidate.380+g97a4ef0eb818"
    assert package["package_sha256"] == PACKAGE_SHA256
    assert package["binary_sha256"] == BINARY_SHA256
    native = record["native_client"]
    assert native["client"] == "cursor"
    assert native["native_skill_loaded"] is True
    assert native["native_project_read_completed"] is True
    assert native["native_project_source_observed"] is True
    assert native["installation_scope"] == "temporary project .cursor/skills/outbound-guard"
    assert native["skill_zip_sha256"] == SKILL_SHA256
    assert native["installed_skill_sha256"] == INSTALLED_SKILL_SHA256
    assert native["binary_sha256"] == BINARY_SHA256
    assert native["http_methods"] == ["GET"] * 4
    assert native["rules"] == ["EGRESS_ALLOWED", "EGRESS_ALLOWED",
                               "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"]
    assert native["status_codes"] == [200] * 3
    assert native["fixture_hits"] == ["/plain"] * 3
    assert native["rebind_mode"] is True
    assert native["rebind_a_queries"] == 2
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert packet["rebind_a_answers"] == ["11.0.0.1", "127.0.0.1"]
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-cursor-current-rebind-2026-11-13.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["rebind_a_answers"] == [["11.0.0.1"], ["127.0.0.1"]]
    assert record["packet_analysis"]["tcp_syn_count"] == 3
    assert record["packet_analysis"]["dns_query_count"] == 9


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-cursor-rebind-verify-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        analysis = json.loads(json.dumps(verify_packets(target, CAPTURE_SHA256)))
        assert analysis == record["packet_analysis"]
        mutant = forbidden_syn(data)
        target.write_bytes(mutant)
        try:
            verify_packets(target, hashlib.sha256(mutant).hexdigest())
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("checksum-corrected metadata SYN passed packet verifier")
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 4),
                         ("native_project_read_completed", False)):
        mutant = copy.deepcopy(record)
        mutant["native_client"][field] = value
        try:
            verify_record(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed Cursor record verifier")
    print("verified Cursor rebinding decisions, retained packets and negative controls")


if __name__ == "__main__":
    main()
