#!/usr/bin/env python3
"""Recheck retained native DNS rebinding captures for one trusted-main package."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/exact-main-native-rebind-2026-11-09.json"
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["result"] == "passed"
    assert record["source_commit"] == "7c935757721f0db0262b241fb36ac608f6919160"
    assert record["source_ci_run"] == 42620813730
    assert record["package"]["unsigned"] is True
    assert record["package"]["installed_binary_sha256"] == record["upgrade_from"]["installed_binary_sha256"]
    for field in (record["package"]["sha256"], record["skill_zip"]["sha256"]):
        assert re.fullmatch(r"[0-9a-f]{64}", field)
    assert set(record["clients"]) == {"codex", "claude"}

    captures = set()
    for client, evidence in sorted(record["clients"].items()):
        assert evidence["rules"] == ["EGRESS_ALLOWED", "EGRESS_ALLOWED",
                                     "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"]
        assert evidence["http_hits"] == ["/plain"] * 3
        assert evidence["private_answer_http_hit"] is False
        assert evidence["clean_install_upgrade_remove_residue"] == "passed"
        capture = (ROOT / evidence["packet_capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT) and capture not in captures
        captures.add(capture)
        digest = evidence["packet_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        observed = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_rebind_pcap.py"),
             str(capture), digest], text=True, timeout=25))
        assert observed == evidence["packet_verifier"], client
    assert len(captures) == 2
    print(json.dumps({"source_commit": record["source_commit"],
                      "verified_clients": sorted(record["clients"]),
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
