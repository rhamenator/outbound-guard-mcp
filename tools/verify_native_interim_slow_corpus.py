#!/usr/bin/env python3
"""Recheck both retained native HTTP 103 slow-drip packet captures in CI."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-client-http-interim-slow-pcap-2026-11-08.json"
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "interim_103_count", "interim_span_seconds",
          "client_close_seconds_after_first_103", "timed_out_stream_client_closed",
          "ip_destinations")


def main() -> None:
    document = json.loads(EVIDENCE.read_text())
    assert document["result"] == "passed"
    assert set(document["runs"]) == {"claude", "codex"}
    captures = set()
    for client in ("claude", "codex"):
        run = document["runs"][client]
        assert run["result"] == "passed"
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TIMEOUT", "EGRESS_ALLOWED"]
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT), relative
        assert capture not in captures, capture
        captures.add(capture)
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_interim_slow_pcap.py"),
             str(capture), digest], text=True, timeout=25))
        recorded = run["packet_verifier"]
        for field in FIELDS:
            assert checked[field] == recorded[field], (client, field)
        assert run["packet_capture"]["pcap_sha256"] == digest
        assert run["packet_capture"]["raw_pcap_retained"] is True
    print(json.dumps({"verified_clients": ["claude", "codex"],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
