#!/usr/bin/env python3
"""Recheck retained native exact DNS answer-cap captures and evidence in CI."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-client-dns-answer-boundary-pcap-2026-11-09.json"
FIELDS = ("sha256", "answer_counts", "dns_query_count", "dns_names", "tcp_syn_count",
          "http_requests", "http_response_codes", "ip_destinations", "scope")


def main() -> None:
    document = json.loads(EVIDENCE.read_text())
    assert document["result"] == "passed"
    assert set(document["runs"]) == {"claude", "codex"}
    captures = set()
    for client in ("claude", "codex"):
        run = document["runs"][client]
        assert run["result"] == "passed" and run["fixture_mode"] == "dns-answer-boundary-packet"
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_ALLOWED",
                                "EGRESS_DNS_ANSWER_LIMIT", "EGRESS_ALLOWED"]
        assert run["fixture_hits"] == ["/plain"] * 3
        assert run["packet_capture"]["raw_pcap_retained"] is True
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT), relative
        assert capture not in captures, capture
        captures.add(capture)
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        assert run["packet_capture"]["pcap_sha256"] == digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_dns_answer_limit_pcap.py"),
             str(capture), digest, "--boundary"], text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == run["packet_verifier"][field], (client, field)
    assert len(captures) == 2
    print(json.dumps({"verified_clients": ["claude", "codex"],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
