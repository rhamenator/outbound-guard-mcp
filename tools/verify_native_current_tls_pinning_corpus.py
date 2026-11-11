#!/usr/bin/env python3
"""Recheck current-package native TLS pinning decisions and fixture captures."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_tls_pinning_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-current-tls-pinning-2026-11-11.json"
SOURCE = "0456105251691f2a11892f5bef65ef5b4592eb38"
PACKAGE = "5f5d9354e7e09df17259144438f9732815ad6c9d874441b5902a419caa3ba952"
SKILL = "70810e2d3ac510838678bd54baf7fbfe6c6188917b497a4c67a83606d5bab9de"
BINARY = "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
RULES = ["EGRESS_NETWORK_FAILURE", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"]
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
          "tls_hostname_denial", "private_dns_flip_denial", "wrong_host_sni_capture",
          "no_tls_fallback_capture", "fixture_namespace_tcp_syn_capture", "approved_recovery",
          "package_remove", "residue"]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed"
    assert evidence["package_source_commit"] == SOURCE
    assert evidence["package_ci_run"] == 42990714476
    assert evidence["package_sha256"] == PACKAGE and evidence["skill_zip_sha256"] == SKILL
    manifest = ROOT / evidence["manifest_path"]
    assert sha(manifest) == evidence["manifest_sha256"]
    lines = manifest.read_text().splitlines()
    assert any(line.startswith(PACKAGE + "  outbound-guard-mcp_0.1.0~candidate.356+")
               for line in lines)
    assert any(line.startswith(SKILL + "  outbound-guard-skill-045610525169.zip")
               for line in lines)
    assert set(evidence["harness_sha256"]) == {
        "tools/debian_native_container_probe.py", "tools/client_cancellation_probe.py",
        "tools/verify_native_tls_pinning_pcap.py"}
    for name, digest in evidence["harness_sha256"].items():
        assert sha(ROOT / name) == digest, name
    assert set(evidence["runs"]) == {"claude", "codex"}
    captures = set()
    for client, run in evidence["runs"].items():
        native, install = run["native"], run["install"]
        assert install["result"] == "passed" and install["fixture_mode"] == "tls-handshake-packet"
        assert install["client"] == native["client"] == client
        assert install["platform"] == "Debian 12 amd64 container joined to route-free fixture namespace"
        assert install["checks"] == CHECKS
        assert install["old_package"] is None
        assert install["skill_zip_sha256"] == native["skill_zip_sha256"] == SKILL
        assert install["package"]["revision"] == SOURCE
        assert install["package"]["package_sha256"] == PACKAGE
        assert install["package"]["binary_sha256"] == BINARY
        assert len(native["binary_sha256"]) == 64  # Native bridge wrapper, not installed executable.
        assert evidence["client_versions_observed_after_runs"][client] == (
            "2.1.319 (Claude Code)" if client == "claude" else "codex-cli 0.151.0")
        assert native["rules"] == RULES and native["fixture_hits"] == ["/plain"]
        assert native["native_skill_loaded"] is True
        assert native["native_skill_invoked"] is True or native["explicit_skill_input_accepted"] is True
        assert native["packet_capture"]["raw_pcap_retained"] is True
        assert native["packet_capture"]["pcap_sha256"] == run["capture_sha256"]
        assert native["packet_capture"]["unexpected_tcp_connection_attempts"] == 0
        resources = install["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom"] == resources["memory_events"]["oom_kill"] == 0
        server = install["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
        capture = (ROOT / run["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        assert capture.name == f"native-{client}-tls-pinning-current-2026-11-11.pcap"
        captures.add(capture)
        assert sha(capture) == run["capture_sha256"]
        with tempfile.TemporaryDirectory(prefix="outbound-current-tls-pinning-") as directory:
            copy = Path(directory) / "fixture.pcap"
            shutil.copyfile(capture, copy)
            checked = verify(copy, run["capture_sha256"])
            assert checked == run["independent_packet_verification"]
            assert checked["tcp_syn_destinations"] == ["11.0.0.2:443", "11.0.0.1:80"]
            assert checked["tls_client_hello"] == ["tls-handshake.test", "11.0.0.2"]
            assert checked["tls_host_a_answers"] == ["11.0.0.2,11.0.0.1", "127.0.0.1"]
            mutant = forbidden_syn(capture.read_bytes())
            copy.write_bytes(mutant)
            try:
                verify(copy, hashlib.sha256(mutant).hexdigest())
            except AssertionError as error:
                assert "169.254.169.254" in str(error), error
            else:
                raise AssertionError("metadata-address SYN passed packet oracle")
    assert len(captures) == 2
    print(json.dumps({"capture_count": len(captures), "verified_clients": sorted(evidence["runs"])},
                     sort_keys=True))


if __name__ == "__main__":
    main()
