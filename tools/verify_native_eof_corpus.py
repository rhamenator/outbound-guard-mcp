#!/usr/bin/env python3
"""Bind the retained Codex EOF capture to its native replay evidence."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-codex-missing-lf-eof-pcap-2026-11-09.json"
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"


def main() -> None:
    run = json.loads(EVIDENCE.read_text())
    assert run["result"] == "passed" and run["observations"]["server_rejected_missing_lf"]
    assert run["observations"]["native_mcp_tool_starts_through_turn_completion"] == 2
    assert run["observations"]["incomplete_frame_reply"] is False
    assert run["observations"]["private_dns_queries"] == 0
    assert run["packet_capture"]["raw_pcap_retained"] is True
    relative = Path(run["pcap_path"])
    capture = (ROOT / relative).resolve(strict=True)
    assert capture.is_relative_to(CAPTURE_ROOT), relative
    digest = run["pcap_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
    assert run["packet_capture"]["pcap_sha256"] == digest
    checked = json.loads(subprocess.check_output(
        ["python3", str(ROOT / "tools/verify_native_dns_ssrf_pcap.py"),
         str(capture), digest, "--scenario", "eof-frame"], text=True, timeout=25))
    for field in ("scenario", "tcp_syn_count", "dns_query_count", "dns_names",
                  "http_requests", "ip_destinations", "scope"):
        assert checked[field] == run["packet_verifier"][field], field
    assert checked["sha256"] == digest
    assert checked["http_requests"] == run["packet_capture"]["eof_approved_http_requests"]
    assert checked["tcp_syn_count"] == run["packet_capture"]["tcp_syn_count"]
    print(json.dumps({"verified_capture": str(relative), "sha256": digest}, sort_keys=True))


if __name__ == "__main__":
    main()
