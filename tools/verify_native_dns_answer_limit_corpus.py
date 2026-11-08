#!/usr/bin/env python3
"""Recheck both retained native DNS-answer-limit captures in CI."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-client-dns-answer-limit-pcap-2026-11-08.json"
FIELDS = ("sha256", "answer_count", "answers", "dns_query_count", "dns_names",
          "tcp_syn_count", "http_requests", "http_response_codes", "ip_destinations")


def main() -> None:
    document = json.loads(EVIDENCE.read_text())
    assert document["result"] == "passed"
    assert set(document["runs"]) == {"claude", "codex"}
    captures = set()
    for client in ("claude", "codex"):
        run = document["runs"][client]
        assert run["result"] == "passed"
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_DNS_ANSWER_LIMIT", "EGRESS_ALLOWED"]
        assert run["fixture_hits"] == ["/plain", "/plain"]
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT), relative
        assert capture not in captures, capture
        captures.add(capture)
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_dns_answer_limit_pcap.py"),
             str(capture), digest], text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == run["packet_verifier"][field], (client, field)
        assert run["packet_capture"]["pcap_sha256"] == digest
        assert run["packet_capture"]["raw_pcap_retained"] is True
    print(json.dumps({"verified_clients": ["claude", "codex"],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
