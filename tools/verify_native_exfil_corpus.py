#!/usr/bin/env python3
"""Recheck retained native synthetic-exfiltration captures in CI."""

import json
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EXPECTED_RULES = [
    "EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
    "EGRESS_SECRET_DETECTED", "EGRESS_INVALID_URL", "EGRESS_ALLOWED",
]
FIELDS = ("sha256", "scenario", "tcp_syn_count", "dns_query_count",
          "dns_names", "http_requests", "ip_destinations", "scope")


def main() -> None:
    captures = set()
    cases = (
        ("claude-upgrade", "native-claude-exfil-upgrade-pcap-2026-11-07.json"),
        ("codex-upgrade", "native-codex-exfil-upgrade-pcap-2026-11-07.json"),
        ("claude-current", "native-claude-exfil-current-2026-11-09.json"),
        ("claude-current-package", "native-claude-exfil-current-2026-11-11.json"),
        ("codex-current-package", "native-codex-exfil-current-2026-11-11.json"),
    )
    for client, filename in cases:
        evidence = ROOT / "docs/evidence" / filename
        run = json.loads(evidence.read_text())
        assert run["result"] == "passed" and run["fixture_mode"] == "synthetic-exfil-packet"
        assert run["rules"] == EXPECTED_RULES
        assert run["fixture_hits"] == ["/plain", "/head-ok", "/plain"]
        assert run["exfil_dns_queried"] is False and run["synthetic_marker_echo"] is False
        assert run["packet_capture"]["raw_pcap_retained"] is True
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT), relative
        assert capture not in captures, capture
        captures.add(capture)
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        assert run["packet_capture"]["pcap_sha256"] == digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_dns_ssrf_pcap.py"),
             str(capture), digest, "--scenario", "synthetic-exfil"],
            text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == run["packet_verifier"][field], (client, field)
        if client.endswith("current-package"):
            expected_version = ("2.1.319 (Claude Code)" if client.startswith("claude")
                                else "codex-cli 0.151.0")
            assert run["client_version"] == expected_version
            assert run["source_base"] == "0456105251691f2a11892f5bef65ef5b4592eb38"
            assert run["trusted_main_package_ci_run"] == 42990714476
            for filename, field in (("tools/debian_native_container_probe.py", "harness_sha256"),
                                    ("tools/client_cancellation_probe.py", "client_probe_sha256")):
                historical = subprocess.check_output(
                    ["git", "show", f'{run["source_base"]}:{filename}'], cwd=ROOT, timeout=10)
                assert hashlib.sha256(historical).hexdigest() == run[field], (client, filename)
            assert run["package"]["revision"] == run["source_base"]
            # The client's binary_sha256 is its temporary launch wrapper;
            # package_info separately checks the installed executable bytes.
            assert run["package"]["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
            assert run["installed_skill_sha256"] == "1fcd127c7c8f0624ae98258688e084c83efc4d00dfb4303d77ba26e950b48712"
            assert run["native_skill_loaded"] is True
            assert (run["native_skill_invoked"] is True or
                    run["explicit_skill_input_accepted"] is True)
            assert run["checks"] == ["checksum", "clean_dpkg_install", "no_upgrade",
                "native_skill_and_guarded_calls", "loopback_denial", "secret_path_denial",
                "unicode_lookalike_denial", "no_exfil_dns_or_marker_echo",
                "fixture_namespace_tcp_syn_capture", "approved_recovery", "package_remove", "residue"]
            manifest = ROOT / run["ci_sha256sums_path"]
            assert hashlib.sha256(manifest.read_bytes()).hexdigest() == run["ci_sha256sums_sha256"]
            lines = manifest.read_text().splitlines()
            assert f'{run["package"]["package_sha256"]}  {run["package_name"]}' in lines
            assert f'{run["skill_zip_sha256"]}  {run["skill_name"]}' in lines
            container = run["container_resource_observation"]
            assert container["memory_limit_mib"] == 128
            assert container["memory_peak_bytes"] < 128 * 1024 * 1024
            assert 0 < container["pids_peak"] <= 64
            assert container["memory_events"]["oom"] == 0
            assert container["memory_events"]["oom_kill"] == 0
            server = run["server_resource_observation"]
            assert server["sample_interval_ms"] == 50 and server["samples"] > 0
            assert 0 < server["max_sampled_fd"] <= 64
            # Recomputing the digest must not hide a forbidden destination.
            mutant = forbidden_syn(capture.read_bytes())
            with tempfile.TemporaryDirectory(prefix="outbound-exfil-mutant-") as directory:
                path = Path(directory) / "forbidden-syn.pcap"
                path.write_bytes(mutant)
                rejected = subprocess.run(["python3", str(ROOT / "tools/verify_native_dns_ssrf_pcap.py"),
                    str(path), hashlib.sha256(mutant).hexdigest(), "--scenario", "synthetic-exfil"],
                    capture_output=True, text=True, timeout=25)
                assert rejected.returncode != 0 and "169.254.169.254" in rejected.stderr
    assert len(captures) == len(cases)
    print(json.dumps({"verified_clients": [client for client, _ in cases],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
