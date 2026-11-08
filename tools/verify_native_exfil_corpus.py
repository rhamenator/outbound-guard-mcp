#!/usr/bin/env python3
"""Recheck both retained native synthetic-exfiltration upgrade captures in CI."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EXPECTED_RULES = [
    "EGRESS_INVALID_HOST", "EGRESS_ALLOWED", "EGRESS_ALLOWED",
    "EGRESS_SECRET_DETECTED", "EGRESS_INVALID_URL", "EGRESS_ALLOWED",
]
FIELDS = ("sha256", "scenario", "tcp_syn_count", "dns_query_count",
          "dns_names", "http_requests", "ip_destinations", "scope")


def main() -> None:
    captures = set()
    for client in ("claude", "codex"):
        evidence = ROOT / "docs/evidence" / f"native-{client}-exfil-upgrade-pcap-2026-11-07.json"
        run = json.loads(evidence.read_text())
        assert run["result"] == "passed" and run["fixture_mode"] == "synthetic-exfil-packet"
        assert run["rules"] == EXPECTED_RULES
        assert run["fixture_hits"] == ["/plain", "/head-ok", "/plain"]
        assert run["exfil_dns_queried"] is False and run["synthetic_marker_echo"] is False
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
            ["python3", str(ROOT / "tools/verify_native_dns_ssrf_pcap.py"),
             str(capture), digest, "--scenario", "synthetic-exfil"],
            text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == run["packet_verifier"][field], (client, field)
    assert len(captures) == 2
    print(json.dumps({"verified_clients": ["claude", "codex"],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
