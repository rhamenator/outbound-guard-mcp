#!/usr/bin/env python3
"""Bind current installed native TLS/DNS denials to retained fixture packets."""

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import checksum, forbidden_syn
from verify_native_tls_pinning_pcap import verify as verify_packets

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/native-installed-current-tls-pinning-2026-11-14.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
SOURCE = "79468137872e353e963d5a9d0d62cdce85a5e13e"
PACKAGE = "a0ebf7f05a6dbdead0df2b49423916e89458df6833778263992068de55869165"
BINARY = "c5746a596aa33134e2381ed6ffebf3c98d396ef317607aebf47576cfb74ea35d"
SKILL = "d3102510b37998f7a96245701c64f70751af28347b30f859c52e7eb29e435ee0"
CAPTURE_HASHES = {
    "claude": "287ca2003c75bb5e279fca5a661f5c0014b58511674cb0c38ebca1fbea530e37",
    "codex": "a99ed689985d01eae30e1fce7707bbab744535987bb06f566d493aaa94411a05",
}
RAW_LOG_HASHES = {
    "claude": "da224f9cceefeaaa3108bf5708c71faa1569e3b60a36092bdf2f933ea02516f1",
    "codex": "70a77a6924f21579d198dd9a99d086c72da993843d68ecb35a296220f7868f6a",
}
RULES = ["EGRESS_NETWORK_FAILURE", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
          "tls_hostname_denial", "private_dns_flip_denial", "wrong_host_sni_capture",
          "no_tls_fallback_capture", "fixture_namespace_tcp_syn_capture", "approved_recovery",
          "package_remove", "residue"]
HARNESS = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/debian_native_container_probe.py",
           "tools/netns_adversarial_probe.py", "tools/verify_native_tls_pinning_pcap.py"}
PRIVATE_DNS_ANSWER = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
                      b"\x7f\x00\x00\x01")


def change_one_transport_payload(data: bytes, old: bytes, new: bytes, protocol: int) -> bytes:
    """Change one fixture payload and repair its TCP/UDP checksum."""
    assert len(old) == len(new)
    assert data[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack_from("<I", data, 20)[0] == 276
    changed = bytearray(data)
    offset = 24
    count = 0
    while offset < len(changed):
        _, _, captured, original = struct.unpack_from("<IIII", changed, offset)
        assert captured == original
        start, end = offset + 16, offset + 16 + captured
        frame = changed[start:end]
        ip = 20  # Linux SLL2 link header
        if frame[ip] >> 4 == 4 and frame[ip + 9] == protocol:
            ihl = (frame[ip] & 15) * 4
            transport = ip + ihl
            segment_end = ip + int.from_bytes(frame[ip + 2:ip + 4], "big")
            segment = bytearray(frame[transport:segment_end])
            header_length = ((segment[12] >> 4) * 4) if protocol == 6 else 8
            match = segment.find(old, header_length)
            if match >= 0:
                assert count == 0, "mutation matched multiple packets"
                segment[match:match + len(old)] = new
                check_offset = 16 if protocol == 6 else 6
                segment[check_offset:check_offset + 2] = b"\0\0"
                pseudo = (frame[ip + 12:ip + 20] + bytes((0, protocol))
                          + len(segment).to_bytes(2, "big"))
                value = checksum(pseudo + segment)
                if protocol == 17 and value == 0:
                    value = 0xffff
                segment[check_offset:check_offset + 2] = value.to_bytes(2, "big")
                assert checksum(pseudo + segment) == 0
                frame[transport:segment_end] = segment
                changed[start:end] = frame
                count += 1
        offset = end
    assert count == 1, "fixture payload mutation target missing"
    return bytes(changed)


def verify_record(record):
    assert record["date_utc"] == "2026-11-14"
    assert record["scenario"] == "installed-native-tls-hostname-and-dns-flip"
    assert record["result"] == "passed" and record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43623206726")
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == "155128ad1e4a78ae4902c7f243c7adcc0d6db6800462f8f51fd4bf74809b9efc"
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
        assert case["rules"] == RULES and case["status_codes"] == [200]
        assert case["fixture_hits"] == ["/plain"]
        assert case["tls_handshake_a_queries"] == 2
        assert case["tls_sni"] == [["11.0.0.2", "tls-handshake.test"]]
        assert case["raw_log_sha256"] == RAW_LOG_HASHES[client]
        assert case["capture_path"] == f"tests/fixtures/packet-capture/native-{client}-installed-tls-pinning-2026-11-14.pcap"
        assert case["capture_sha256"] == CAPTURE_HASHES[client]
        assert case["packet_capture_summary"]["unexpected_tcp_connection_attempts"] == 0
        assert case["packet_capture_summary"]["tcp_syn_destinations"] == ["11.0.0.1:80", "11.0.0.2:443"]
        installed = case["installed_package"]
        assert installed["result"] == "passed" and installed["client"] == client
        assert installed["fixture_mode"] == "tls-handshake-packet"
        assert installed["checks"] == CHECKS and installed["old_package"] is None
        assert installed["package"] == {
            "app_version": "0.1.0", "binary_sha256": BINARY,
            "package_sha256": PACKAGE, "revision": SOURCE,
            "version": "0.1.0~candidate.409+g79468137872e"}
        assert installed["skill_zip_sha256"] == SKILL
        resources = installed["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom_kill"] == 0
        server = installed["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64
        assert server["max_sampled_rss_kib"] > 0
        analysis = case["packet_analysis"]
        assert analysis["tls_host_a_answers"] == ["11.0.0.2,11.0.0.1", "127.0.0.1"]
        assert analysis["tls_client_hello"] == ["tls-handshake.test", "11.0.0.2"]
        assert analysis["approved_http_requests"] == [["allowed.test", "/plain"]]


def main():
    record = json.loads(RECORD.read_text())
    verify_record(record)
    for client, case in record["cases"].items():
        capture = (ROOT / case["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture.stat().st_size <= 1024 * 1024
        data = capture.read_bytes()
        assert hashlib.sha256(data).hexdigest() == CAPTURE_HASHES[client]
        with tempfile.TemporaryDirectory(prefix="outbound-installed-tls-") as directory:
            target = Path(directory) / "fixture.pcap"
            target.write_bytes(data)
            assert verify_packets(target, CAPTURE_HASHES[client]) == case["packet_analysis"]
            mutants = (
                (forbidden_syn(data), "169.254.169.254"),
                (change_one_transport_payload(data, b"tls-handshake.test",
                                              b"tls-handshakf.test", 6), "tls-handshakf.test"),
                (change_one_transport_payload(data, PRIVATE_DNS_ANSWER,
                                              PRIVATE_DNS_ANSWER[:-4] + b"\x0b\x00\x00\x02", 17),
                 "['11.0.0.2']"),
            )
            for mutant, expected_error in mutants:
                target.write_bytes(mutant)
                try:
                    verify_packets(target, hashlib.sha256(mutant).hexdigest())
                except AssertionError as error:
                    assert expected_error in str(error), error
                else:
                    raise AssertionError("checksum-corrected TLS/DNS packet mutant passed")
    altered = copy.deepcopy(record)
    altered["cases"]["codex"]["rules"][1] = "EGRESS_ALLOWED"
    try:
        verify_record(altered)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed private-DNS denial passed record verifier")
    print("verified installed native TLS pinning decisions and packet negative controls")


if __name__ == "__main__":
    main()
