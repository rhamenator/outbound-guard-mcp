#!/usr/bin/env python3
"""Recheck current Cursor CLI synthetic-exfil decisions and fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_dns_ssrf_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-current-exfil-pcap-2026-11-13.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "9872a49c756a5ce0233192ba17c96d00d37b8a1e"
MANIFEST_SHA256 = "3eb1e6b8564ead7aa336541a47502c8735b9d63e3d8998153d82e6c77fb51db8"
PACKAGE_SHA256 = "35b2df084a98bbd2b4721006ab6f852eb499dd301304af8fd0d8bba08c2f3a2b"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
CAPTURE_SHA256 = "24fd605e2a2a76365bbfcdd41a2e86c6a26c7a60fd1cf4224be2edbefd074554"
RAW_LOG_SHA256 = "7fd18f2cdad59b7da4d2c4696f9b02d529d9ec4f34b87926e915fe15bd46f11e"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}
RULES = ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
         "EGRESS_SECRET_DETECTED", "EGRESS_INVALID_URL", "EGRESS_ALLOWED"]
HTTP_REQUESTS = [["allowed.test", "/plain"], ["allowed.test", "/head-ok"],
                 ["allowed.test", "/plain"]]


def verify_record(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43411634587")
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
    assert package["version"] == "0.1.0~candidate.381+g9872a49c756a"
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
    assert native["http_methods"] == ["GET", "GET", "HEAD", "GET", "GET", "GET"]
    assert native["rules"] == RULES
    assert native["status_codes"] == [200] * 3
    assert native["fixture_hits"] == ["/plain", "/head-ok", "/plain"]
    assert native["exfil_mode"] is True
    assert native["exfil_dns_queried"] is False
    assert native["synthetic_marker_echo"] is False
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert packet["exfil_dns_query_count"] == 0
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-cursor-current-exfil-2026-11-13.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["http_requests"] == HTTP_REQUESTS
    assert record["packet_analysis"]["dns_names"] == ["1.0.0.11.in-addr.arpa", "allowed.test"]
    assert record["packet_analysis"]["tcp_syn_count"] == 3
    assert record["packet_analysis"]["dns_query_count"] == 7
    assert record["packet_analysis"]["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-cursor-exfil-verify-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        assert verify_packets(target, CAPTURE_SHA256, "synthetic-exfil") == record["packet_analysis"]
        mutant = forbidden_syn(data)
        target.write_bytes(mutant)
        try:
            verify_packets(target, hashlib.sha256(mutant).hexdigest(), "synthetic-exfil")
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("checksum-corrected metadata SYN passed packet verifier")
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 6),
                         ("native_project_read_completed", False)):
        mutant = copy.deepcopy(record)
        mutant["native_client"][field] = value
        try:
            verify_record(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed Cursor record verifier")
    print("verified Cursor synthetic-exfil decisions, retained packets and negative controls")


if __name__ == "__main__":
    main()
