#!/usr/bin/env python3
"""Recheck current-package native malformed-chunk captures and a wire mutation."""

import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import checksum, forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-current-malformed-http-2026-11-11.json"
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_READ_FAILURE",
         "EGRESS_READ_FAILURE", "EGRESS_ALLOWED"]
HITS = ["/plain", "/head-ok", "/chunked-bad-size",
        "/chunked-truncated", "/plain"]
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "malformed_chunk_bodies", "ip_destinations", "scope")


def change_bad_chunk(data: bytes) -> bytes:
    """Make the invalid chunk digit valid and repair that TCP segment checksum."""
    assert data[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack_from("<I", data, 20)[0] == 276
    changed = bytearray(data)
    offset = 24
    found = 0
    while offset < len(changed):
        _, _, captured, original = struct.unpack_from("<IIII", changed, offset)
        assert captured == original
        start, end = offset + 16, offset + 16 + captured
        frame = changed[start:end]
        ip = 20  # Linux SLL2 header
        if frame[ip] >> 4 == 4 and frame[ip + 9] == 6:
            tcp = ip + (frame[ip] & 15) * 4
            tcp_len = (frame[tcp + 12] >> 4) * 4
            payload = tcp + tcp_len
            needle = b"2\r\nok\r\nZ\r\n"
            at = frame.find(needle, payload)
            if at >= 0:
                assert frame[tcp:tcp + 2] == b"\x00\x50"
                frame[at + len(needle) - 3] = ord("0")
                segment = frame[tcp:]
                segment[16:18] = b"\0\0"
                pseudo = frame[ip + 12:ip + 20] + b"\0\x06" + len(segment).to_bytes(2, "big")
                segment[16:18] = checksum(pseudo + segment).to_bytes(2, "big")
                assert checksum(pseudo + segment) == 0
                frame[tcp:] = segment
                changed[start:end] = frame
                found += 1
        offset = end
    assert found == 1, found
    return bytes(changed)


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed"
    assert evidence["source_base"] == "0456105251691f2a11892f5bef65ef5b4592eb38"
    assert evidence["trusted_main_package_ci_run"] == 42990714476
    manifest = ROOT / evidence["ci_sha256sums_path"]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == evidence["ci_sha256sums_sha256"]
    lines = manifest.read_text().splitlines()
    assert f'{evidence["package_sha256"]}  {evidence["package_name"]}' in lines
    assert f'{evidence["skill_zip_sha256"]}  {evidence["skill_name"]}' in lines
    required_sources = {"tools/debian_native_container_probe.py",
                        "tools/client_cancellation_probe.py",
                        "tools/verify_native_malformed_http_pcap.py"}
    assert set(evidence["harness_sha256"]) == required_sources
    for filename, digest in evidence["harness_sha256"].items():
        source = subprocess.check_output(["git", "show", f'{evidence["source_base"]}:{filename}'],
                                         cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, filename
    assert set(evidence["runs"]) == {"claude", "codex"}
    captures = set()
    for client, run in evidence["runs"].items():
        assert run["client_version"] == ("2.1.319 (Claude Code)" if client == "claude"
                                          else "codex-cli 0.151.0")
        assert run["fixture_mode"] == "malformed-http-packet"
        assert run["rules"] == RULES and run["fixture_hits"] == HITS
        assert run["native_skill_loaded"] is True
        assert run["native_skill_invoked"] is True or run["explicit_skill_input_accepted"] is True
        assert run["checks"] == ["checksum", "clean_dpkg_install", "no_upgrade",
            "native_skill_and_guarded_calls", "bad_chunk_size_denial",
            "truncated_chunk_denial", "fixture_namespace_tcp_syn_capture",
            "approved_recovery", "package_remove", "residue"]
        assert run["package"]["revision"] == evidence["source_base"]
        assert run["package"]["package_sha256"] == evidence["package_sha256"]
        assert run["package"]["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
        assert run["installed_skill_sha256"] == "1fcd127c7c8f0624ae98258688e084c83efc4d00dfb4303d77ba26e950b48712"
        capture = (ROOT / run["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        captures.add(capture)
        digest = run["capture_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert hashlib.sha256(capture.read_bytes()).hexdigest() == digest
        assert run["packet_capture"]["pcap_sha256"] == digest
        assert run["packet_capture"]["raw_pcap_retained"] is True
        assert run["packet_capture"]["unexpected_tcp_connection_attempts"] == 0
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_malformed_http_pcap.py"),
             str(capture), digest], text=True, timeout=25))
        assert all(checked[key] == run["independent_packet_verification"][key] for key in FIELDS)
        assert checked["tcp_syn_count"] == 5
        assert checked["malformed_chunk_bodies"] == {
            "/chunked-bad-size": True, "/chunked-truncated": True}
        container = run["container_resource_observation"]
        assert container["memory_limit_mib"] == 128
        assert 0 < container["memory_peak_bytes"] < 128 * 1024 * 1024
        assert container["memory_events"]["oom"] == container["memory_events"]["oom_kill"] == 0
        server = run["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
        if client == "claude":
            for name, mutant, expected in (
                ("fixed-chunk", change_bad_chunk(capture.read_bytes()), "body"),
                ("forbidden-syn", forbidden_syn(capture.read_bytes()), "169.254.169.254")):
                with tempfile.TemporaryDirectory(prefix="outbound-malformed-mutant-") as directory:
                    target = Path(directory) / f"{name}.pcap"
                    target.write_bytes(mutant)
                    result = subprocess.run(
                        ["python3", str(ROOT / "tools/verify_native_malformed_http_pcap.py"),
                         str(target), hashlib.sha256(mutant).hexdigest()],
                        capture_output=True, text=True, timeout=25)
                    assert result.returncode != 0 and expected in result.stderr, (name, result.stderr)
    assert len(captures) == 2
    print(json.dumps({"capture_count": len(captures), "verified_clients": sorted(evidence["runs"])}))


if __name__ == "__main__":
    main()
