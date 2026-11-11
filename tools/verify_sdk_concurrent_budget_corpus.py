#!/usr/bin/env python3
"""Bind the official-SDK per-host burst evidence to two retained fixture logs."""

import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/sdk-concurrent-budget-2026-11-11.json"
MARKER = re.compile(
    r"official SDK 2\.3\.1 per-host boundary burst: 52 serial allowed, "
    r"16 concurrent submissions \((\d+) allowed, (\d+) rate denied, (\d+) input busy\), "
    r"serial fill to 60 and final rate denial; exactly 60 approved A/AAAA queries and HTTP hits"
)


def verify_run(run: dict, data: bytes) -> None:
    assert hashlib.sha256(data).hexdigest() == run["sha256"], run["log"]
    text = data.decode("utf-8")
    matches = MARKER.findall(text)
    assert len(matches) == 1, "budget-boundary marker missing"
    allowed, denied, busy = map(int, matches[0])
    assert (allowed, denied, busy) == (
        run["burst_allowed"], run["burst_rate_denied"], run["burst_input_busy"])
    assert allowed == 8 and allowed + denied + busy == 16
    assert (run["approved_dns_a_queries"], run["approved_dns_aaaa_queries"],
            run["approved_http_hits"]) == (60, 60, 60)
    assert "netns adversarial probe: 3457 MCP decisions" in text


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["result"] == "passed" and len(record["runs"]) == 2
    for name, digest in record["probe_source_sha256"].items():
        # The harness acquired a later two-process case. Bind the original
        # observation to the retained exact-main source instead of rewriting
        # the historical digest to match a different script.
        data = (subprocess.check_output(["git", "show", f'{record["probe_commit"]}:{name}'], cwd=ROOT)
                if name == "tools/netns_adversarial_probe.py" else (ROOT / name).read_bytes())
        assert hashlib.sha256(data).hexdigest() == digest, name
    for index, run in enumerate(record["runs"], 1):
        assert run["log"] == f"sdk-concurrent-budget-2026-11-11-run{index}.log"
        data = (EVIDENCE.parent / run["log"]).read_bytes()
        verify_run(run, data)
        changed = data.replace(b"exactly 60 approved A/AAAA queries and HTTP hits",
                               b"exactly 61 approved A/AAAA queries and HTTP hits")
        assert changed != data
        mutant = dict(run, sha256=hashlib.sha256(changed).hexdigest())
        try:
            verify_run(mutant, changed)
        except AssertionError as error:
            assert str(error) == "budget-boundary marker missing", error
        else:
            raise AssertionError("altered HTTP/DNS count passed the evidence oracle")
    print(json.dumps({"verified_runs": 2, "recomputed_digest_mutations_rejected": 2},
                     sort_keys=True))


if __name__ == "__main__":
    main()
