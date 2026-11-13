#!/usr/bin/env python3
"""Recheck current Cursor CLI DNS/SSRF skill evidence and fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_dns_ssrf_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-current-dns-ssrf-pcap-2026-11-13.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "224fa1777069cb48015290c51760871a8b4d4ac3"
MANIFEST_SHA256 = "39886f2a84c1b871688188f9e024a6f12c1621be86298833cde23ec149a53420"
PACKAGE_SHA256 = "142b265bed51adc76eb7379429a635c98778ab22e82e0f27ca63e08cce2a7507"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
CAPTURE_SHA256 = "60469c6ccee7fae8b6de0fbb9c8a9589e3a5c0a6c2d8a59d16757ecd34105d2d"
RAW_LOG_SHA256 = "4b188a0c048d85d077d0e9fa6492fbb253bbe742c5c23c6ec0f0fe331d4dde39"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}
RULES = ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED"] + [
    "EGRESS_FORBIDDEN_ADDRESS"] * 4 + ["EGRESS_DNS_FAILURE", "EGRESS_ALLOWED"]
DNS_NAMES = ["alias-private.test", "loop-dns.test", "metadata.test", "mixed.test", "private.test"]
HTTP_REQUESTS = [["allowed.test", "/plain"], ["allowed.test", "/head-ok"],
                 ["allowed.test", "/plain"]]


def verify_record(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43396005087")
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
    assert package["version"] == "0.1.0~candidate.379+g224fa1777069"
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
    assert native["http_methods"] == ["GET", "GET", "HEAD"] + ["GET"] * 6
    assert native["rules"] == RULES
    assert native["status_codes"] == [200, 200, 200]
    assert native["forbidden_dns_names"] == DNS_NAMES
    assert native["fixture_hits"] == ["/plain", "/head-ok", "/plain"]
    assert native["packet_capture"]["raw_pcap_retained"] is True
    assert native["packet_capture"]["pcap_sha256"] == CAPTURE_SHA256
    assert native["packet_capture"]["unexpected_tcp_connection_attempts"] == 0
    assert native["packet_capture"]["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-cursor-current-dns-ssrf-2026-11-13.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["sha256"] == CAPTURE_SHA256
    assert record["packet_analysis"]["http_requests"] == HTTP_REQUESTS
    assert record["packet_analysis"]["tcp_syn_count"] == 3
    assert record["packet_analysis"]["dns_query_count"] == 17
    assert record["packet_analysis"]["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-cursor-dns-verify-") as directory:
        target = Path(directory) / "fixture.pcap"
        target.write_bytes(data)
        assert verify_packets(target, CAPTURE_SHA256, "dns-ssrf") == record["packet_analysis"]
        mutant = forbidden_syn(data)
        target.write_bytes(mutant)
        try:
            verify_packets(target, hashlib.sha256(mutant).hexdigest(), "dns-ssrf")
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("checksum-corrected metadata SYN passed packet verifier")
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 9),
                         ("native_project_read_completed", False)):
        mutant = copy.deepcopy(record)
        mutant["native_client"][field] = value
        try:
            verify_record(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed Cursor record verifier")
    print("verified Cursor DNS/SSRF decisions, retained packets and negative controls")


if __name__ == "__main__":
    main()
