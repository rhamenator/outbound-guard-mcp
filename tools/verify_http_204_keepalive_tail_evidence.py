#!/usr/bin/env python3
"""Bind the retained route-free 204 keepalive-tail log to its narrow claims."""

import gzip
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/http-204-keepalive-tail-2026-11-14.json"
LINE = ("unframed 204 second-response tail without a close header: empty body, "
        "fixture-observed client EOF within one second, approved recovery")


def check_log(log, record):
    assert hashlib.sha256(log).hexdigest() == record["log_sha256_uncompressed"]
    lines = log.decode("utf-8").splitlines()
    assert lines.count(LINE) == 1
    assert sum(line.startswith("netns adversarial probe: 2256 MCP decisions;")
               for line in lines) == 1
    assert not any("Traceback" in line or "AssertionError" in line for line in lines)


def main():
    record = json.loads(RECORD.read_text())
    assert record["date_utc"] == "2026-11-14" and record["result"] == "passed"
    assert record["source_main_sha"] == "e787df30b95d3457de3b00702ea306ca871196b4"
    assert hashlib.sha256((ROOT / "tools/netns_adversarial_probe.py").read_bytes()).hexdigest() == record["fixture_sha256"]
    assert record["observations"]["paths"] == ["/no-content-204-keepalive-tail", "/plain"]
    assert record["observations"]["first_decision"] == {"rule": "EGRESS_ALLOWED", "status_code": 204, "body_text": ""}
    assert record["observations"]["second_decision"] == {"rule": "EGRESS_ALLOWED", "status_code": 200, "body_text": "fixture-ok"}
    assert record["observations"]["fixture_observed_client_eof_within_seconds"] == 1
    assert record["observations"]["full_suite_mcp_decisions"] == 2256
    path = (ROOT / record["log_path"]).resolve(strict=True)
    assert path.is_relative_to(ROOT / "docs/evidence") and path.stat().st_size < 100_000
    log = gzip.decompress(path.read_bytes())
    check_log(log, record)
    try:
        check_log(log.replace(LINE.encode(), b"fixture did not observe client EOF"),
                  {**record, "log_sha256_uncompressed": hashlib.sha256(log.replace(
                      LINE.encode(), b"fixture did not observe client EOF")).hexdigest()})
    except AssertionError:
        pass
    else:
        raise AssertionError("altered close observation passed the evidence oracle")
    print("retained route-free 204 keepalive-tail close evidence passed")


if __name__ == "__main__":
    main()
