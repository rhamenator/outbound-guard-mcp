#!/usr/bin/env python3
"""Recheck current-package native compressed-bomb denials and wire captures."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_bomb_oracle_negative_controls import (
    corrupt_deflate_checksum, corrupt_gzip, wrong_deflate_length,
)


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-current-compressed-bombs-2026-11-11.json"
VERIFIER = ROOT / "tools/verify_native_compressed_bomb_pcap.py"
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "bombs", "ip_destinations", "scope")
RULES = ["EGRESS_ALLOWED", "EGRESS_ENCODED_RESPONSE",
         "EGRESS_ENCODED_RESPONSE", "EGRESS_ALLOWED"]
HITS = ["/plain", "/gzip-bomb", "/deflate-bomb", "/plain"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade",
          "native_skill_and_guarded_calls", "gzip_bomb_denial", "deflate_bomb_denial",
          "no_denied_body_text", "fixture_namespace_tcp_syn_capture",
          "approved_recovery", "package_remove", "residue"]


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
                        "tools/verify_native_compressed_bomb_pcap.py"}
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
        assert run["fixture_mode"] == "compressed-bombs-packet"
        assert run["rules"] == RULES and run["fixture_hits"] == HITS
        assert run["checks"] == CHECKS and run["native_skill_loaded"] is True
        assert run["native_skill_invoked"] is True or run["explicit_skill_input_accepted"] is True
        assert run["package"]["revision"] == evidence["source_base"]
        assert run["package"]["package_sha256"] == evidence["package_sha256"]
        assert run["package"]["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
        assert run["installed_skill_sha256"] == "1fcd127c7c8f0624ae98258688e084c83efc4d00dfb4303d77ba26e950b48712"
        capture = (ROOT / run["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        captures.add(capture)
        source = capture.read_bytes()
        digest = run["capture_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert hashlib.sha256(source).hexdigest() == digest
        assert run["packet_capture"]["pcap_sha256"] == digest
        assert run["packet_capture"]["raw_pcap_retained"] is True
        assert run["packet_capture"]["unexpected_tcp_connection_attempts"] == 0
        checked = json.loads(subprocess.check_output(
            ["python3", str(VERIFIER), str(capture), digest], text=True, timeout=25))
        assert all(checked[key] == run["independent_packet_verification"][key] for key in FIELDS)
        assert checked["tcp_syn_count"] == 4 and checked["dns_query_count"] == 9
        assert set(checked["bombs"]) == {"/gzip-bomb", "/deflate-bomb"}
        for bomb in checked["bombs"].values():
            assert bomb["decoded_bytes"] == 8 * 1024 * 1024
            assert 0 < bomb["wire_body_bytes"] < 16 * 1024
        container = run["container_resource_observation"]
        assert container["memory_limit_mib"] == 128
        assert 0 < container["memory_peak_bytes"] < 128 * 1024 * 1024
        assert container["memory_events"]["oom"] == container["memory_events"]["oom_kill"] == 0
        server = run["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
        for name, mutant, expected in (
            ("forbidden-syn", forbidden_syn(source), "169.254.169.254"),
            ("gzip-method", corrupt_gzip(source), "unknown compression method"),
            ("deflate-checksum", corrupt_deflate_checksum(source), "incorrect data check"),
            ("deflate-length", wrong_deflate_length(source), "Content-Length: 8162"),
        ):
            with tempfile.TemporaryDirectory(prefix="outbound-current-bomb-mutant-") as directory:
                target = Path(directory) / f"{name}.pcap"
                target.write_bytes(mutant)
                rejected = subprocess.run(
                    ["python3", str(VERIFIER), str(target), hashlib.sha256(mutant).hexdigest()],
                    capture_output=True, text=True, timeout=25)
                assert rejected.returncode != 0 and expected in rejected.stderr, (client, name, rejected.stderr)
    assert len(captures) == 2
    print(json.dumps({"capture_count": len(captures),
                      "verified_clients": sorted(evidence["runs"])}, sort_keys=True))


if __name__ == "__main__":
    main()
