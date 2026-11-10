#!/usr/bin/env python3
"""Check the retained route-free HTTP version/status fixture run."""

import ast
import gzip
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/raw-http-version-netns-2026-11-10.json"
ARCHIVE_SHA256 = "60c8d144fe9ae2dd00898d8abe0bca515a1861167d1100d99fa352706d9b0a5e"
RAW_SHA256 = "24675b03cee6739739ca8cc659887584f85c843e21aa9120667a02ac94e9f8aa"
RULES = {
    "http10-ok": "EGRESS_ALLOWED",
    "http11-partial-ok": "EGRESS_ALLOWED",
    "http10-comma-length": "EGRESS_INVALID_FRAMING",
    "http11-partial-comma-length": "EGRESS_INVALID_FRAMING",
}


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["expected_rules"] == RULES
    assert evidence["suite_mcp_decisions"] == 2252
    assert evidence["log_gzip_sha256"] == ARCHIVE_SHA256
    assert evidence["log_sha256"] == RAW_SHA256
    relative = Path(evidence["log"])
    assert not relative.is_absolute() and ".." not in relative.parts
    archive = (ROOT / relative).read_bytes()
    assert hashlib.sha256(archive).hexdigest() == ARCHIVE_SHA256
    log = gzip.decompress(archive)
    assert len(log) < 65536 and hashlib.sha256(log).hexdigest() == RAW_SHA256
    lines = log.decode().splitlines()
    assert ("raw HTTP version/status fixture: HTTP/1.0 200 and HTTP/1.1 206 allowed "
            "with body ok; comma-length variants denied without body; exact hits passed") in lines
    assert lines[-1].startswith("netns adversarial probe: 2252 MCP decisions;")
    observed = ast.literal_eval(lines[-1].split("framing=", 1)[1])
    assert {path: observed[path] for path in RULES} == RULES
    print("verified retained route-free HTTP version/status decisions")


if __name__ == "__main__":
    main()
