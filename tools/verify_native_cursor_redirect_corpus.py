#!/usr/bin/env python3
"""Recheck current Cursor CLI redirect/encoded-response decisions and packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_redirect_encoded_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-current-redirect-encoded-pcap-2026-11-13.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "efd8b99abdef75392747ab17f8cb0e0621c3bbe9"
MANIFEST_SHA256 = "7d5846dacdcf643114dcbcf6d46b1143264a06b8124e715bbef882e4295a90ef"
PACKAGE_SHA256 = "b9a89c033ecf69b589f849cdc7d0d851bc69251aa0b76fe6328391becd607b1b"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
CAPTURE_SHA256 = "da6242174ec5337345007ca4bf80fddc9e6674df991357aad0248d2cdcf8c045"
RAW_LOG_SHA256 = "5a56b505883506a8e80930f36b350f7b068529e5808f45f050c8cdc5be69631b"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}
RULES = ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
         "EGRESS_REDIRECT_DENIED", "EGRESS_ENCODED_RESPONSE", "EGRESS_ALLOWED"]
HTTP_REQUESTS = [["allowed.test", "/plain"], ["allowed.test", "/head-ok"],
                 ["allowed.test", "/redirect"], ["allowed.test", "/gzip-bomb"],
                 ["allowed.test", "/plain"]]


def verify_record(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43420147980")
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
    assert package["version"] == "0.1.0~candidate.382+gefd8b99abdef"
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
    assert native["fixture_hits"] == ["/plain", "/head-ok", "/redirect", "/gzip-bomb", "/plain"]
    assert native["attack_mode"] is True
    assert native["bomb_mode"] is False
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert packet["redirect_private_dns_query_count"] == 0
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-cursor-current-redirect-encoded-2026-11-13.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    analysis = record["packet_analysis"]
    assert analysis["sha256"] == CAPTURE_SHA256
    assert analysis["http_requests"] == HTTP_REQUESTS
    assert analysis["redirect_location"] == "http://private.test/plain"
    assert analysis["encoded_response"] == "gzip"
    assert analysis["tcp_syn_count"] == 5
    assert analysis["dns_query_count"] == 11
    assert analysis["dns_names"] == ["1.0.0.11.in-addr.arpa", "allowed.test"]
    assert analysis["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-cursor-redirect-verify-") as directory:
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
    print("verified Cursor redirect and encoded-response decisions, packets and negative controls")


if __name__ == "__main__":
    main()
