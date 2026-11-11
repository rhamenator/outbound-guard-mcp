#!/usr/bin/env python3
"""Bind two-process SDK fixture claims to retained development/package logs."""

import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/sdk-two-process-budget-2026-11-11.json"
MARKER = ("official SDK 2.3.1 two-process host-budget scope: 120 approvals "
          "(60 per process), two independent rate denials; exactly 120 A/AAAA "
          "queries and HTTP hits; no shared rate window")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_run(run: dict, data: bytes, record: dict) -> None:
    assert digest(data) == run["sha256"], run["log"]
    text = data.decode("utf-8")
    assert text.count(MARKER) == 1, "two-process marker missing or changed"
    assert f'netns adversarial probe: {run["suite_decisions"]} MCP decisions' in text
    assert "Traceback" not in text and "AssertionError" not in text
    if run["kind"] == "installed":
        resources = re.findall(r"^SDK_HOUR_RESOURCE=(\{.*\})$", text, re.M)
        assert len(resources) == 1
        resource = json.loads(resources[0])
        assert resource["package_sha256"] == record["package_sha256"]
        assert resource["installed_binary_sha256"] == record["installed_binary_sha256"]
        assert resource["server_fd_soft_limit"] == 64
        assert 0 < resource["max_sampled_server_fd"] <= 64
        assert resource["container_memory_peak_bytes"] < 128 * 1024 * 1024
        assert 0 < resource["container_pids_peak"] <= 64
        assert resource["container_oom_events"] == 0
    else:
        assert run["kind"] == "development"
        assert "SDK_HOUR_RESOURCE=" not in text


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["result"] == "passed"
    source = ROOT / "tools/mcp-sdk-probe/two_process_budget_modern.mjs"
    assert digest(source.read_bytes()) == record["sdk_probe_sha256"]
    manifest = ROOT / record["ci_sha256sums_path"]
    assert digest(manifest.read_bytes()) == record["ci_sha256sums_sha256"]
    assert f'{record["package_sha256"]}  {record["package_name"]}' in manifest.read_text().splitlines()
    assert [run["kind"] for run in record["runs"]] == ["development", "installed"]
    for run in record["runs"]:
        data = (EVIDENCE.parent / run["log"]).read_bytes()
        verify_run(run, data, record)
        changed = data.replace(b"exactly 120 A/AAAA queries and HTTP hits",
                               b"exactly 121 A/AAAA queries and HTTP hits")
        assert changed != data
        mutant = dict(run, sha256=digest(changed))
        try:
            verify_run(mutant, changed, record)
        except AssertionError as error:
            assert str(error) == "two-process marker missing or changed", error
        else:
            raise AssertionError("recomputed-digest changed-count mutant passed")
    print(json.dumps({"runs": 2, "recomputed_digest_mutations_rejected": 2}, sort_keys=True))


if __name__ == "__main__":
    main()
