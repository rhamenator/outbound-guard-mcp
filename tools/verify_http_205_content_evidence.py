#!/usr/bin/env python3
"""Check the retained direct-MCP HTTP 205 regression record and fixture identity."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/http-205-content-2026-11-14.json"
SOURCE_SHA256 = "96d733d41271b279b6b5f9015891b00437f1e13ba499c22f698ea1c3f2f6d246"
FIXTURE_SHA256 = "6382c8744a368a53d57033efcac64c4c73177cf39d0fe27e6a0dca5776bf7ccf"


def verify(record):
    assert record["base_main_sha"] == "a4ff70c2613d83fbea9c2fd34d6f893af4b6dae2"
    assert record["baseline_ci_run"].endswith("/43548601002")
    assert record["baseline_artifact_checksums_verified"] is True
    assert record["baseline_package_sha256"] == "958ed96b0312ea2e0147cd96c788b6e442a0b40c038848552f4751ebda7ea3ff"
    assert record["baseline_binary_sha256"] == "d3a9275325fda6f34c091909ff49349f79b438e5b81401d70f7fc2bffadd9706"
    assert record["updated_source_sha256"] == SOURCE_SHA256
    assert record["fixture_sha256"] == FIXTURE_SHA256
    assert hashlib.sha256((ROOT / "src/lib.rs").read_bytes()).hexdigest() == SOURCE_SHA256
    assert hashlib.sha256((ROOT / "tools/netns_adversarial_probe.py").read_bytes()).hexdigest() == FIXTURE_SHA256
    assert record["paths"] == ["/reset-content-205", "/reset-content-205-chunked-empty",
                               "/reset-content-205-length", "/reset-content-205-chunked",
                               "/reset-content-205-close", "/plain"]
    assert record["baseline_rules"] == ["EGRESS_ALLOWED"] * 6
    assert record["baseline_body_text"] == ["", "", "ok", "ok", "ok", "fixture-ok"]
    assert record["updated_rules"] == ["EGRESS_ALLOWED", "EGRESS_ALLOWED",
                                       "EGRESS_INVALID_FRAMING", "EGRESS_INVALID_FRAMING",
                                       "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED"]
    assert record["updated_body_text"] == ["", "", None, None, None, "fixture-ok"]
    assert record["updated_full_probe_decisions"] == 2256
    assert record["network_scope"] == "route-free controlled DNS/HTTP namespace; no retained packet capture"


def main():
    record = json.loads(RECORD.read_text())
    verify(record)
    mutant = json.loads(json.dumps(record))
    mutant["updated_rules"][2] = "EGRESS_ALLOWED"
    try:
        verify(mutant)
    except AssertionError:
        pass
    else:
        raise AssertionError("changed HTTP 205 decision passed evidence check")
    print("verified HTTP 205 regression record, fixture identity and decision negative control")


if __name__ == "__main__":
    main()
