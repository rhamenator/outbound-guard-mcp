#!/usr/bin/env python3
"""Recheck installed-package SDK budget-burst logs and retained CI manifest."""

import hashlib
import json
from pathlib import Path
import re

from verify_sdk_concurrent_budget_corpus import MARKER


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/sdk-concurrent-budget-installed-2026-11-11.json"


def verify_run(run: dict, data: bytes, record: dict) -> None:
    assert hashlib.sha256(data).hexdigest() == run["sha256"], run["log"]
    text = data.decode("utf-8")
    matches = MARKER.findall(text)
    assert len(matches) == 1, "budget-boundary marker missing"
    assert tuple(map(int, matches[0])) == (
        run["burst_allowed"], run["burst_rate_denied"], run["burst_input_busy"])
    assert (run["burst_allowed"], run["burst_rate_denied"], run["burst_input_busy"]) == (8, 1, 7)
    assert f'netns adversarial probe: {run["suite_decisions"]} MCP decisions' in text
    for prefix in ("SDK_INSTALLED_RESOURCE=", "SDK_HOUR_RESOURCE="):
        lines = [line for line in text.splitlines() if line.startswith(prefix)]
        assert len(lines) == 1, prefix
        resource = json.loads(lines[0][len(prefix):])
        assert resource["package_sha256"] == record["package_sha256"]
        assert resource["installed_binary_sha256"] == record["installed_binary_sha256"]
        assert resource["server_fd_soft_limit"] == 64
        assert 0 < resource["max_sampled_server_fd"] <= 64
        assert resource["container_oom_events"] == 0
        assert resource["container_memory_peak_bytes"] < 128 * 1024 * 1024
        assert 0 < resource["container_pids_peak"] <= 64
        if prefix == "SDK_HOUR_RESOURCE=":
            assert resource["server_vm_hwm_kib"] == run["server_vm_hwm_kib"]
            assert resource["container_memory_peak_bytes"] == run["container_memory_peak_bytes"]
            assert resource["container_pids_peak"] == run["container_pids_peak"]


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["result"] == "passed"
    assert record["source_commit"] == "3211c1c1a587291d70647c877e036ca81c2848ca"
    assert record["source_ci_run"] == 42976396612
    manifest = ROOT / record["ci_sha256sums_path"]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == record["ci_sha256sums_sha256"]
    assert f'{record["package_sha256"]}  {record["package_name"]}' in manifest.read_text().splitlines()
    assert len(record["runs"]) == 2
    for index, run in enumerate(record["runs"], 1):
        assert run["log"] == f"sdk-concurrent-budget-installed-2026-11-11-run{index}.log"
        data = (EVIDENCE.parent / run["log"]).read_bytes()
        verify_run(run, data, record)
        changed = data.replace(b"exactly 60 approved A/AAAA queries and HTTP hits",
                               b"exactly 61 approved A/AAAA queries and HTTP hits")
        assert changed != data
        mutant = dict(run, sha256=hashlib.sha256(changed).hexdigest())
        try:
            verify_run(mutant, changed, record)
        except AssertionError as error:
            assert str(error) == "budget-boundary marker missing", error
        else:
            raise AssertionError("altered installed HTTP/DNS count passed evidence oracle")
    print(json.dumps({"installed_runs": 2, "recomputed_digest_mutations_rejected": 2},
                     sort_keys=True))


if __name__ == "__main__":
    main()
