#!/usr/bin/env python3
"""Bind four installed native active-proxy decisions to retained fixture packets."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_native_active_proxy_pcap import verify
from verify_native_body_cancel_pcap_negative_controls import forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-current-active-proxy-pcap-2026-11-11.json"
SOURCE = "530195841dfad8bf83af2fe7e70f1988afdf1456"
PACKAGE = "b74c04a405a0e4feb14e9475e284dbe17b7df4dd9400f06ea5e756c27a47f0d6"
SKILL = "70810e2d3ac510838678bd54baf7fbfe6c6188917b497a4c67a83606d5bab9de"
BINARY = "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
FLOW = [{"method": "GET", "host": "allowed.test", "path": "/proxy-control"}]
RULES = {
    "tls": ["EGRESS_NETWORK_FAILURE", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"],
    "exfil": ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
              "EGRESS_SECRET_DETECTED", "EGRESS_INVALID_URL", "EGRESS_ALLOWED"],
}
HITS = {
    "tls": ["/proxy-control", "/plain"],
    "exfil": ["/proxy-control", "/plain", "/head-ok", "/plain"],
}
CHECKS = {
    "tls": ["checksum", "clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
            "tls_hostname_denial", "private_dns_flip_denial", "active_proxy_positive_control_only",
            "fixture_namespace_proxy_packet_capture", "approved_recovery", "package_remove", "residue"],
    "exfil": ["checksum", "clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
              "loopback_denial", "secret_path_denial", "unicode_lookalike_denial",
              "no_exfil_dns_or_marker_echo", "active_proxy_positive_control_only",
              "fixture_namespace_proxy_packet_capture", "approved_recovery", "package_remove", "residue"],
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed" and evidence["package_source_commit"] == SOURCE
    assert evidence["package_ci_run"] == 43092168167
    assert evidence["package_sha256"] == PACKAGE and evidence["skill_zip_sha256"] == SKILL
    assert evidence["proxy_trap"] == "http://127.0.0.1:3128"
    manifest = ROOT / evidence["manifest_path"]
    assert sha(manifest) == evidence["manifest_sha256"]
    lines = manifest.read_text().splitlines()
    assert any(line.startswith(PACKAGE + "  outbound-guard-mcp_0.1.0~candidate.369+")
               for line in lines)
    assert any(line.startswith(SKILL + "  outbound-guard-skill-530195841dfa.zip")
               for line in lines)
    assert evidence["harness_source_commit"] == SOURCE
    subprocess.run(["git", "merge-base", "--is-ancestor", SOURCE,
                    "refs/remotes/origin/main"], cwd=ROOT, timeout=10, check=True)
    assert set(evidence["harness_sha256"]) == {
        "tools/debian_native_container_probe.py", "tools/client_cancellation_probe.py",
        "tools/mitmproxy_flow_probe.py"}
    for name, digest in evidence["harness_sha256"].items():
        source = subprocess.check_output(["git", "show", f"{SOURCE}:{name}"], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    assert set(evidence["runs"]) == {"claude-tls", "claude-exfil", "codex-tls", "codex-exfil"}
    captures = set()
    for key, run in evidence["runs"].items():
        client, mode = key.split("-")
        native, install = run["native"], run["install"]
        assert run["mode"] == mode and install["result"] == "passed"
        assert install["fixture_mode"] == ("tls-active-proxy" if mode == "tls"
                                           else "synthetic-exfil-active-proxy")
        assert install["client"] == native["client"] == client
        assert install["checks"] == CHECKS[mode] and install["old_package"] is None
        assert install["proxy_environment_verified_in_container"] is True
        assert install["package"]["revision"] == SOURCE
        assert install["package"]["package_sha256"] == PACKAGE
        assert install["package"]["binary_sha256"] == BINARY
        assert native["skill_zip_sha256"] == install["skill_zip_sha256"] == SKILL
        assert evidence["client_versions_observed_after_runs"][client] == (
            "2.1.319 (Claude Code)" if client == "claude" else "codex-cli 0.151.0")
        assert native["native_skill_loaded"] is True
        assert native["native_skill_invoked"] is True or native["explicit_skill_input_accepted"] is True
        assert native["rules"] == RULES[mode] and native["fixture_hits"] == HITS[mode]
        assert native["proxy_flows"] == FLOW
        assert native["exfil_dns_queried"] is (False if mode == "exfil" else None)
        assert native["synthetic_marker_echo"] is (False if mode == "exfil" else None)
        packet = native["packet_capture"]
        assert packet["raw_pcap_retained"] is True and packet["pcap_sha256"] == run["capture_sha256"]
        assert packet["unexpected_ip_destinations"] == packet["unexpected_tcp_connection_attempts"] == 0
        resources = install["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom"] == resources["memory_events"]["oom_kill"] == 0
        server = install["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
        capture = (ROOT / run["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        assert capture.name == f"native-current-active-proxy-{key}-2026-11-11.pcap"
        captures.add(capture)
        assert sha(capture) == run["capture_sha256"]
        with tempfile.TemporaryDirectory(prefix="outbound-current-proxy-") as directory:
            copy = Path(directory) / "fixture.pcap"
            shutil.copyfile(capture, copy)
            checked = verify(copy, run["capture_sha256"], mode)
            assert checked == run["independent_packet_verification"]
            assert checked["proxy_http_requests"] == [["GET", "allowed.test",
                                                         "http://allowed.test/proxy-control"]]
            assert checked["direct_tcp_syn_count"] == (3 if mode == "tls" else 4)
            mutant = forbidden_syn(capture.read_bytes())
            copy.write_bytes(mutant)
            try:
                verify(copy, hashlib.sha256(mutant).hexdigest(), mode)
            except AssertionError as error:
                assert "169.254.169.254" in str(error), error
            else:
                raise AssertionError("metadata-address SYN passed active-proxy packet oracle")
    assert len(captures) == 4
    print(json.dumps({"capture_count": len(captures), "verified_runs": sorted(evidence["runs"]),
                      "checksum_corrected_metadata_syn_mutations_rejected": 4}, sort_keys=True))


if __name__ == "__main__":
    main()
