#!/usr/bin/env python3
"""Recheck current Cursor HTTP 103 slow-drip denial and retained fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_interim_slow_pcap import verify as verify_packets


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-interim-slow-pcap-2026-11-13.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "770acd12e26b885a7a5164f0bf7753e641c6ea16"
MANIFEST_SHA256 = "670de235aff70b97c5da97c7b33b7ec79b21dc9bc14766b74f34f95637d15819"
PACKAGE_SHA256 = "63d74554a6ba4f60fdfb0a3825f8d0d744f7723914c37b9c1e5a967fc827cb6a"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
CAPTURE_SHA256 = "08eb9decca29644ee887a533c68bc9d773e8ef8d34a59a8ce65c0d0f4c9107c5"
RAW_LOG_SHA256 = "d8b61b29cb670415464c5b11be02f2ae15e3a24cdd61471647b53394b6cb531d"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}
RULES = ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TIMEOUT", "EGRESS_ALLOWED"]
PATHS = ["/plain", "/interim-slow-drip", "/plain"]


def verify_record(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43495622859")
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
    assert package["version"] == "0.1.0~candidate.390+g770acd12e26b"
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
    assert native["http_methods"] == ["GET"] * 3
    assert native["rules"] == RULES
    assert native["status_codes"] == [200] * 2
    assert native["fixture_hits"] == PATHS
    assert native["upgrade_mode"] is True and native["interim_slow_mode"] is True
    packet = native["packet_capture"]
    assert packet["raw_pcap_retained"] is True
    assert packet["pcap_sha256"] == CAPTURE_SHA256
    assert packet["unexpected_tcp_connection_attempts"] == 0
    assert packet["tcp_syn_destinations"] == ["11.0.0.1:80"]
    assert record["capture_path"] == "tests/fixtures/packet-capture/native-cursor-interim-slow-2026-11-13.pcap"
    assert record["capture_sha256"] == CAPTURE_SHA256
    analysis = record["packet_analysis"]
    assert analysis["sha256"] == CAPTURE_SHA256
    assert analysis["http_requests"] == [["allowed.test", path] for path in PATHS]
    assert analysis["interim_103_count"] == 21
    assert analysis["timed_out_stream_client_closed"] is True
    assert 9.5 <= analysis["client_close_seconds_after_first_103"] <= 10.5
    assert analysis["tcp_syn_count"] == 3
    assert analysis["dns_query_count"] == 7
    assert analysis["dns_names"] == ["1.0.0.11.in-addr.arpa", "allowed.test"]
    assert analysis["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify_record(record)
    capture = (ROOT / record["capture_path"]).resolve(strict=True)
    assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
    data = capture.read_bytes()
    assert hashlib.sha256(data).hexdigest() == CAPTURE_SHA256
    with tempfile.TemporaryDirectory(prefix="outbound-cursor-interim-slow-verify-") as directory:
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
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 3),
                         ("native_project_read_completed", False)):
        mutant = copy.deepcopy(record)
        mutant["native_client"][field] = value
        try:
            verify_record(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed Cursor record verifier")
    print("verified Cursor interim slow-drip denial, packets and negative controls")


if __name__ == "__main__":
    main()
