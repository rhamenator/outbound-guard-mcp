#!/usr/bin/env python3
"""Recheck retained installed-SDK minute-window reset logs and their limits."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/installed-sdk-rate-reset-2026-11-06.json"
RESOURCE_PREFIX = "SDK_INSTALLED_RESOURCE="
RESET_MARKER = "same-process host windows reset after 61 seconds with DNS/HTTP recovery"
DENIAL_MARKER = "60 spent host slots and 60 DNS failures each followed by SDK EGRESS_RATE_LIMIT without DNS/HTTP"


def verify_run(run: dict, data: bytes, package_sha256: str) -> None:
    assert hashlib.sha256(data).hexdigest() == run["log_sha256"], run["log"]
    lines = data.decode("utf-8").splitlines()
    resources = [json.loads(line[len(RESOURCE_PREFIX):]) for line in lines
                 if line.startswith(RESOURCE_PREFIX)]
    assert len(resources) == 1, run["log"]
    assert resources[0] == {key: run[key] for key in resources[0]}, run["log"]
    assert resources[0]["package_sha256"] == package_sha256
    assert run["package_sha256"] == package_sha256
    assert run["full_namespace_suite_decisions"] == 2671
    sdk_lines = [line for line in lines if line.startswith("official SDK 2.3.1 overload:")]
    assert len(sdk_lines) == 1, run["log"]
    assert DENIAL_MARKER in sdk_lines[0], "rate denials missing"
    assert RESET_MARKER in sdk_lines[0], "minute-window reset missing"
    assert resources[0]["server_fd_soft_limit"] == 64
    assert 0 < resources[0]["max_sampled_server_fd"] <= 64
    assert resources[0]["container_oom_events"] == 0


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["tested_package_source"] == "673048435ce976212bb1c78d2f9c0b6e06ce3817"
    assert len(record["runs"]) == 2
    for index, run in enumerate(record["runs"], 1):
        assert run["log"] == f"installed-sdk-rate-reset-2026-11-06-run{index}.log"
        data = (EVIDENCE.parent / run["log"]).read_bytes()
        verify_run(run, data, record["tested_package_sha256"])
        # A matching recomputed digest must not turn a removed reset into evidence.
        assert data.count(RESET_MARKER.encode()) == 1
        altered = data.replace(RESET_MARKER.encode(), b"minute window remained blocked")
        mutant = dict(run, log_sha256=hashlib.sha256(altered).hexdigest())
        try:
            verify_run(mutant, altered, record["tested_package_sha256"])
        except AssertionError as error:
            assert str(error) == "minute-window reset missing", error
        else:
            raise AssertionError("removed minute-window reset passed evidence oracle")
    print(json.dumps({"verified_installed_runs": 2,
                      "recomputed_digest_reset_mutations_rejected": 2}, sort_keys=True))


if __name__ == "__main__":
    main()
