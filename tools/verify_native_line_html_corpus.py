#!/usr/bin/env python3
"""Check the retained native line-leading HTML replay record and its source."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-client-debian-line-html-quarantine-2026-11-13.json"
PACKAGE_REVISION = "09332b6f5b14ee46568e071a38c770a2832d41e4"
HARNESS_REVISION = "eef19b09ef2eeca6070b030baeb4ee8d96d9866a"
MANIFEST_SHA256 = "e7b96a886c7ad4eb0b97fbd8666b3a1120fda73567cbfbfc0fc77fd7e4418d49"
PACKAGE_SHA256 = "0998f7acc07526ab65356f06245c04a1437d63dc9cadfe7cabc27aa50cc1cc7e"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
RAW_LOG_SHA256 = {
    "claude": "04d9de3a846708e3a8cea2d3d413b4ff522f43696ed324b5cccfb59fcab28624",
    "codex": "338fdf837a377199d608625bc68d8cd29e3dc44a0cae072e32466446cb6cf480",
}
PATHS = ["/plain", "/html-mislabeled", "/html-root-div", "/html-formfeed",
         "/html-line-hidden", "/plain-angle-text", "/plain"]
RULES = ["EGRESS_ALLOWED"] + ["EGRESS_HTML_MISLABELED"] * 4 + ["EGRESS_ALLOWED"] * 2
CHECKS = ["checksum", "clean_dpkg_install", "no_upgrade",
          "native_skill_and_guarded_calls", "mislabeled_hidden_html_denial",
          "mislabeled_root_html_denial", "mislabeled_formfeed_html_denial",
          "mislabeled_line_html_denial", "ordinary_angle_text_allowed",
          "approved_recovery", "package_remove", "residue"]
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/debian_native_container_probe.py", "tools/netns_adversarial_probe.py"}


def verify(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["trusted_main_sha"] == PACKAGE_REVISION
    assert record["trusted_main_ci"].endswith("/43368588221")
    assert record["harness_source_sha"] == HARNESS_REVISION
    assert record["artifact_checksums_verified"] is True
    assert record["artifact_manifest_sha256"] == MANIFEST_SHA256
    assert record["client_versions"] == {"claude": "2.1.323", "codex": "0.168.0"}
    assert set(record["harness_sha256"]) == SOURCES
    for name, digest in record["harness_sha256"].items():
        source = subprocess.check_output(
            ["git", "show", f"{HARNESS_REVISION}:{name}"], cwd=ROOT, timeout=10)
        assert hashlib.sha256(source).hexdigest() == digest, name
    assert set(record["runs"]) == {"claude", "codex"}
    packages = set()
    skills = set()
    for client, run in record["runs"].items():
        native = run["native_client"]
        package = run["package_probe"]
        assert native["client"] == package["client"] == client
        assert native["native_skill_loaded"] is True
        if client == "claude":
            assert native["native_skill_invoked"] is True
        else:
            assert native["native_skill_discovered"] is True
            assert native["native_turn_completed"] is True
        assert native["http_methods"] == ["GET"] * 7
        assert native["fixture_hits"] == PATHS
        assert native["rules"] == RULES
        assert native["status_codes"] == [200] * 3
        assert native["url_classes"] == ["allowed_plain"] + ["other"] * 5 + ["allowed_plain"]
        assert run["raw_log_sha256"] == RAW_LOG_SHA256[client]
        assert package["result"] == "passed" and package["fixture_mode"] == "html-quarantine"
        assert package["checks"] == CHECKS and package["old_package"] is None
        assert package["platform"] == "Debian 12 amd64 container joined to route-free fixture namespace"
        assert package["package"]["revision"] == PACKAGE_REVISION
        assert package["package"]["version"] == "0.1.0~candidate.376+g09332b6f5b14"
        assert package["package"]["binary_sha256"] == BINARY_SHA256
        assert package["package"]["package_sha256"] == PACKAGE_SHA256
        assert package["skill_zip_sha256"] == SKILL_SHA256
        packages.add(package["package"]["package_sha256"])
        skills.add(package["skill_zip_sha256"])
        resources = package["container_resource_observation"]
        assert resources["memory_limit_mib"] == 128
        assert 0 < resources["memory_peak_bytes"] < 128 * 1024 * 1024
        assert resources["memory_events"]["oom"] == resources["memory_events"]["oom_kill"] == 0
        server = package["server_resource_observation"]
        assert server["sample_interval_ms"] == 50 and server["samples"] > 0
        assert 0 < server["max_sampled_fd"] <= 64 and server["max_sampled_rss_kib"] > 0
    assert len(packages) == len(skills) == 1


def main():
    record = json.loads(EVIDENCE.read_text())
    verify(record)
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 7),
                         ("fixture_hits", PATHS[:-1] + ["/should-not-hit"])):
        mutant = copy.deepcopy(record)
        mutant["runs"]["codex"]["native_client"][field] = value
        try:
            verify(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed the retained-record verifier")
    mutant = copy.deepcopy(record)
    mutant["runs"]["claude"]["package_probe"]["package"]["package_sha256"] = "0" * 64
    try:
        verify(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("altered package digest passed the retained-record verifier")
    print("verified native line-leading HTML decisions, package lifecycle and source hashes")


if __name__ == "__main__":
    main()
