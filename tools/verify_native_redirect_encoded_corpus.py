#!/usr/bin/env python3
"""Bind native redirect/encoding decisions to retained packet evidence."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence"
RULES = ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
         "EGRESS_REDIRECT_DENIED", "EGRESS_ENCODED_RESPONSE", "EGRESS_ALLOWED"]
HITS = ["/plain", "/head-ok", "/redirect", "/gzip-bomb", "/plain"]
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "redirect_location", "encoded_response",
          "ip_destinations", "scope")


def check_capture(run: dict, path_key: str, digest_key: str, packet_key: str) -> Path:
    path = (ROOT / run[path_key]).resolve(strict=True)
    assert path.is_relative_to(CAPTURES), path
    digest = run[digest_key]
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    checked = json.loads(subprocess.check_output(
        ["python3", str(ROOT / "tools/verify_native_redirect_encoded_pcap.py"),
         str(path), digest], text=True, timeout=25))
    assert all(checked[key] == run[packet_key][key] for key in FIELDS)
    assert checked["redirect_location"] == "http://private.test/plain"
    assert checked["encoded_response"] == "gzip"
    assert checked["tcp_syn_count"] == 5
    return path


def main() -> None:
    seen = set()
    for client in ("claude", "codex"):
        old = json.loads((EVIDENCE / f"native-{client}-redirect-encoded-upgrade-pcap-2026-11-07.json").read_text())
        assert old["result"] == "passed" and old["fixture_mode"] == "redirect-encoded-packet"
        assert old["rules"] == RULES and old["fixture_hits"] == HITS
        assert old["packet_capture"]["redirect_private_dns_query_count"] == 0
        assert old["packet_capture"]["pcap_sha256"] == old["pcap_sha256"]
        path = check_capture(old, "pcap_path", "pcap_sha256", "packet_verifier")
        assert path not in seen
        seen.add(path)

    current = json.loads((EVIDENCE / "native-current-redirect-encoded-2026-11-11.json").read_text())
    assert current["result"] == "passed"
    assert current["source_base"] == "0456105251691f2a11892f5bef65ef5b4592eb38"
    assert current["trusted_main_package_ci_run"] == 42990714476
    manifest = ROOT / current["ci_sha256sums_path"]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == current["ci_sha256sums_sha256"]
    lines = manifest.read_text().splitlines()
    assert f'{current["package_sha256"]}  {current["package_name"]}' in lines
    assert f'{current["skill_zip_sha256"]}  {current["skill_name"]}' in lines
    for filename, digest in current["harness_sha256"].items():
        assert filename in {"tools/debian_native_container_probe.py",
                            "tools/client_cancellation_probe.py",
                            "tools/verify_native_redirect_encoded_pcap.py"}
        source = subprocess.check_output(["git", "show", f'{current["source_base"]}:{filename}'],
                                         cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, filename
    for client, run in current["runs"].items():
        assert client in {"claude", "codex"}
        assert run["client_version"] == ("2.1.319 (Claude Code)" if client == "claude"
                                          else "codex-cli 0.151.0")
        assert run["fixture_mode"] == "redirect-encoded-packet"
        assert run["rules"] == RULES and run["fixture_hits"] == HITS
        assert run["native_skill_loaded"] is True
        assert run["native_skill_invoked"] is True or run["explicit_skill_input_accepted"] is True
        assert run["checks"] == ["checksum", "clean_dpkg_install", "no_upgrade",
            "native_skill_and_guarded_calls", "loopback_denial", "redirect_denial",
            "encoded_response_denial", "fixture_namespace_tcp_syn_capture",
            "approved_recovery", "package_remove", "residue"]
        assert run["package"]["revision"] == current["source_base"]
        assert run["package"]["package_sha256"] == current["package_sha256"]
        assert run["package"]["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
        assert run["installed_skill_sha256"] == "1fcd127c7c8f0624ae98258688e084c83efc4d00dfb4303d77ba26e950b48712"
        assert run["packet_capture"]["pcap_sha256"] == run["capture_sha256"]
        assert run["packet_capture"]["raw_pcap_retained"] is True
        assert run["packet_capture"]["redirect_private_dns_query_count"] == 0
        assert run["packet_capture"]["unexpected_tcp_connection_attempts"] == 0
        container = run["container_resource_observation"]
        assert container["memory_limit_mib"] == 128
        assert 0 < container["memory_peak_bytes"] < 128 * 1024 * 1024
        assert container["memory_events"]["oom"] == container["memory_events"]["oom_kill"] == 0
        server = run["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
        path = check_capture(run, "capture_path", "capture_sha256", "independent_packet_verification")
        assert path not in seen
        seen.add(path)
        if client == "claude":
            mutant = forbidden_syn(path.read_bytes())
            with tempfile.TemporaryDirectory(prefix="outbound-redirect-mutant-") as directory:
                target = Path(directory) / "forbidden-syn.pcap"
                target.write_bytes(mutant)
                rejected = subprocess.run(
                    ["python3", str(ROOT / "tools/verify_native_redirect_encoded_pcap.py"),
                     str(target), hashlib.sha256(mutant).hexdigest()],
                    capture_output=True, text=True, timeout=25)
                assert rejected.returncode != 0 and "169.254.169.254" in rejected.stderr
    assert len(seen) == 4
    print(json.dumps({"verified_clients": ["claude-upgrade", "codex-upgrade",
                                          "claude-current", "codex-current"],
                      "capture_count": len(seen)}, sort_keys=True))


if __name__ == "__main__":
    main()
