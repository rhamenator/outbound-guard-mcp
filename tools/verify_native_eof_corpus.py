#!/usr/bin/env python3
"""Bind separate retained Codex and Claude EOF captures to their replay evidence."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
CASES = (
    ("codex", "native-codex-missing-lf-eof-pcap-2026-11-09.json",
     "native_mcp_tool_starts_through_turn_completion"),
    ("claude", "native-claude-missing-lf-eof-pcap-2026-11-09.json",
     "native_guarded_tool_use_ids_through_result"),
)


def main() -> None:
    captures = set()
    for client, filename, call_count_field in CASES:
        run = json.loads((ROOT / "docs/evidence" / filename).read_text())
        assert run["client"].startswith("Codex CLI" if client == "codex" else "Claude Code")
        prior_path = (ROOT / run["prior_package_replay"]).resolve(strict=True)
        assert prior_path.is_relative_to(ROOT / "docs/evidence"), prior_path
        prior = json.loads(prior_path.read_text())
        assert prior["result"] == "passed"
        assert prior["candidate"]["binary_sha256"] == run["server_binary_sha256"]
        assert prior["candidate"]["skill_zip_sha256"] == run["skill_zip_sha256"]
        assert run["result"] == "passed" and run["observations"]["server_rejected_missing_lf"]
        assert run["observations"][call_count_field] == 2
        assert run["observations"]["incomplete_frame_reply"] is False
        assert run["observations"]["private_dns_queries"] == 0
        assert run["packet_capture"]["raw_pcap_retained"] is True
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT) and capture not in captures, relative
        captures.add(capture)
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        assert run["packet_capture"]["pcap_sha256"] == digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_dns_ssrf_pcap.py"),
             str(capture), digest, "--scenario", "eof-frame"], text=True, timeout=25))
        for field in ("scenario", "tcp_syn_count", "dns_query_count", "dns_names",
                      "http_requests", "ip_destinations", "scope"):
            assert checked[field] == run["packet_verifier"][field], (client, field)
        assert checked["sha256"] == digest
        assert checked["http_requests"] == run["packet_capture"]["eof_approved_http_requests"]
        assert checked["tcp_syn_count"] == run["packet_capture"]["tcp_syn_count"]
    assert len(captures) == len(CASES)
    print(json.dumps({"verified_clients": [client for client, _, _ in CASES],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
