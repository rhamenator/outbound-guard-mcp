#!/usr/bin/env python3
"""Bind the explicit keep-alive 204 tail observation to its retained run."""

import gzip
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "docs/evidence/http-204-explicit-keepalive-tail-2026-11-15.json"
LINE = ("unframed 204 second-response tail with explicit keep-alive: empty body, "
        "fixture-observed client EOF within one second, approved recovery")


def check_log(log, digest):
    assert hashlib.sha256(log).hexdigest() == digest
    lines = log.decode("utf-8").splitlines()
    assert lines.count(LINE) == 1
    assert sum(line.startswith("netns adversarial probe: 2256 MCP decisions;")
               for line in lines) == 1
    assert not any("Traceback" in line or "AssertionError" in line for line in lines)


def main():
    record = json.loads(RECORD.read_text())
    assert record["date_utc"] == "2026-11-15" and record["result"] == "passed"
    assert record["source_main_sha"] == "4c2866fa74d8047792bf70440ad5f0cb37e04542"
    fixture = subprocess.check_output(
        ["git", "cat-file", "blob", record["fixture_git_blob"]], cwd=ROOT, timeout=10)
    assert hashlib.sha256(fixture).hexdigest() == record["fixture_sha256"]
    assert record["observations"]["paths"] == [
        "/no-content-204-explicit-keepalive-tail", "/plain"]
    assert record["observations"]["first_decision"] == {
        "rule": "EGRESS_ALLOWED", "status_code": 204, "body_text": ""}
    assert record["observations"]["second_decision"] == {
        "rule": "EGRESS_ALLOWED", "status_code": 200, "body_text": "fixture-ok"}
    assert record["observations"]["fixture_observed_client_eof_within_seconds"] == 1
    assert record["observations"]["full_suite_mcp_decisions"] == 2256
    path = (ROOT / record["log_path"]).resolve(strict=True)
    assert path.is_relative_to(ROOT / "docs/evidence") and path.stat().st_size < 100_000
    log = gzip.decompress(path.read_bytes())
    assert len(log) < 100_000
    check_log(log, record["log_sha256_uncompressed"])
    mutant = log.replace(LINE.encode(), b"fixture did not observe client EOF")
    try:
        check_log(mutant, hashlib.sha256(mutant).hexdigest())
    except AssertionError:
        pass
    else:
        raise AssertionError("altered explicit keep-alive observation passed")
    print("retained explicit keep-alive 204 tail evidence passed")


if __name__ == "__main__":
    main()
