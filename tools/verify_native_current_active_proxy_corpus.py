#!/usr/bin/env python3
"""Recheck current-package native active-proxy run identities and decisions."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-current-active-proxy-2026-11-11.json"
SOURCE = "0456105251691f2a11892f5bef65ef5b4592eb38"
PACKAGE = "5f5d9354e7e09df17259144438f9732815ad6c9d874441b5902a419caa3ba952"
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
            "approved_recovery", "package_remove", "residue"],
    "exfil": ["checksum", "clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
              "loopback_denial", "secret_path_denial", "unicode_lookalike_denial",
              "no_exfil_dns_or_marker_echo", "active_proxy_positive_control_only",
              "approved_recovery", "package_remove", "residue"],
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed" and evidence["source_commit"] == SOURCE
    assert evidence["trusted_main_package_ci_run"] == 42990714476
    assert evidence["package_sha256"] == PACKAGE and evidence["skill_zip_sha256"] == SKILL
    assert evidence["proxy_trap"] == "http://127.0.0.1:3128"
    assert evidence["mitmdump_version_observed_after_runs"] == "8.1.1"
    manifest = ROOT / evidence["manifest_path"]
    assert sha(manifest) == evidence["manifest_sha256"]
    lines = manifest.read_text().splitlines()
    assert any(line.startswith(PACKAGE + "  outbound-guard-mcp_0.1.0~candidate.356+")
               for line in lines)
    assert any(line.startswith(SKILL + "  outbound-guard-skill-045610525169.zip")
               for line in lines)
    assert set(evidence["harness_sha256"]) == {
        "tools/debian_native_container_probe.py", "tools/client_cancellation_probe.py",
        "tools/mitmproxy_flow_probe.py"}
    for filename, digest in evidence["harness_sha256"].items():
        assert sha(ROOT / filename) == digest, filename
    assert set(evidence["runs"]) == {"claude-tls", "claude-exfil", "codex-tls", "codex-exfil"}
    for key, run in evidence["runs"].items():
        client, mode = key.split("-")
        native, install = run["native"], run["install"]
        assert run["mode"] == mode
        assert install["result"] == "passed"
        assert install["fixture_mode"] == ("tls-active-proxy" if mode == "tls"
                                           else "synthetic-exfil-active-proxy")
        assert install["client"] == native["client"] == client
        assert install["platform"] == "Debian 12 amd64 container joined to route-free fixture namespace"
        assert install["old_package"] is None and install["checks"] == CHECKS[mode]
        assert install["proxy_environment_verified_in_container"] is True
        assert install["package"]["revision"] == SOURCE
        assert install["package"]["package_sha256"] == PACKAGE
        assert install["package"]["binary_sha256"] == BINARY
        assert install["skill_zip_sha256"] == native["skill_zip_sha256"] == SKILL
        assert evidence["client_versions_observed_after_runs"][client] == (
            "2.1.319 (Claude Code)" if client == "claude" else "codex-cli 0.151.0")
        assert native["active_proxy_mode"] is True
        assert native["tls_mode"] is (mode == "tls")
        assert native["exfil_mode"] is (mode == "exfil")
        assert native["native_skill_loaded"] is True
        assert native["native_skill_invoked"] is True or native["explicit_skill_input_accepted"] is True
        assert native["rules"] == RULES[mode] and native["fixture_hits"] == HITS[mode]
        assert native["proxy_flows"] == FLOW
        assert native["exfil_dns_queried"] is (False if mode == "exfil" else None)
        assert native["synthetic_marker_echo"] is (False if mode == "exfil" else None)
        resources = install["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom"] == resources["memory_events"]["oom_kill"] == 0
        server = install["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
    print(json.dumps({"verified_runs": sorted(evidence["runs"]),
                      "positive_proxy_flows_per_run": 1}, sort_keys=True))


if __name__ == "__main__":
    main()
