#!/usr/bin/env python3
"""Check the retained Cursor CLI line-leading HTML skill replay record."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-line-html-quarantine-2026-11-13.json"
SOURCE = "3294ae95a5fe7ded7255df653780555fe61d2670"
MANIFEST_SHA256 = "7960b641bc5ffb28bccc9295d911aa0cfbfbe10bffa0a4e29fdbb4ec65869e84"
PACKAGE_SHA256 = "d7a6934d6b9c140cd9c340d672018fec34f9174831f035a7e858279db3e72833"
BINARY_SHA256 = "3a7a346425d17b5c4dfeba21605375034690208fd22d6484bb26b3d74679dc7b"
SKILL_SHA256 = "ebb3345c1ce2751d9182970bbfa7a10d334b29a06dbe295f1de8459b117fbdd5"
INSTALLED_SKILL_SHA256 = "7e1c42b01dcd35c934dc76b06974cdc9461344dc54b8f93b9dea81dd7abcb1ab"
RAW_LOG_SHA256 = "77fb34426b6130ff1ae67750eec6b99d6f90560d0d7c45a69e67a68db3ab4858"
SOURCES = {"tools/client_cancellation_fixture.py", "tools/client_cancellation_probe.py",
           "tools/client_wire_bridge.py", "tools/netns_adversarial_probe.py"}
PATHS = ["/plain", "/html-mislabeled", "/html-root-div", "/html-formfeed",
         "/html-line-hidden", "/plain-angle-text", "/plain"]
RULES = ["EGRESS_ALLOWED"] + ["EGRESS_HTML_MISLABELED"] * 4 + ["EGRESS_ALLOWED"] * 2


def verify(record):
    assert record["date_utc"] == "2026-11-13"
    assert record["source_main_sha"] == SOURCE
    assert record["source_ci_run"].endswith("/43381810891")
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
    assert package["version"] == "0.1.0~candidate.378+g3294ae95a5fe"
    assert package["package_sha256"] == PACKAGE_SHA256
    assert package["binary_sha256"] == BINARY_SHA256
    native = record["native_client"]
    assert native["client"] == "cursor"
    assert native["native_skill_loaded"] is True
    assert native["native_project_read_completed"] is True
    assert native["native_project_source_observed"] is True
    assert native["installation_scope"] == "temporary project .cursor/skills/outbound-guard"
    assert native["builtin_tools"] == ["observed native read"]
    assert native["skill_zip_sha256"] == SKILL_SHA256
    assert native["installed_skill_sha256"] == INSTALLED_SKILL_SHA256
    assert native["binary_sha256"] == BINARY_SHA256
    assert native["http_methods"] == ["GET"] * 7
    assert native["fixture_hits"] == PATHS
    assert native["rules"] == RULES
    assert native["status_codes"] == [200] * 3
    assert native["url_classes"] == ["allowed_plain"] + ["other"] * 5 + ["allowed_plain"]


def main():
    record = json.loads(EVIDENCE.read_text())
    verify(record)
    for field, value in (("rules", ["EGRESS_ALLOWED"] * 7),
                         ("fixture_hits", PATHS[:-1] + ["/should-not-hit"]),
                         ("native_project_read_completed", False)):
        mutant = copy.deepcopy(record)
        mutant["native_client"][field] = value
        try:
            verify(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"altered {field} passed the Cursor record verifier")
    print("verified Cursor CLI skill read and seven guarded HTML decisions")


if __name__ == "__main__":
    main()
