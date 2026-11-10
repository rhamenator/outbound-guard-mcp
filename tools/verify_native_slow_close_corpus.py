#!/usr/bin/env python3
"""Bind both retained native slow-HTTP captures to the close-deadline oracle."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "timed_out_streams_client_closed", "ip_destinations",
          "request_to_client_close_seconds", "scope")


def main() -> None:
    for client in ("codex", "claude"):
        evidence = json.loads((ROOT / f"docs/evidence/native-{client}-slow-upgrade-pcap-2026-11-07.json").read_text())
        assert evidence["result"] == "passed"
        assert evidence["rules"] == ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TOO_SLOW",
                                     "EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"]
        expected = f"tests/fixtures/packet-capture/native-{client}-slow-upgrade-2026-11-07.pcap"
        assert evidence["pcap_path"] == expected
        capture = ROOT / expected
        digest = evidence["pcap_sha256"]
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_slow_http_pcap.py"),
             str(capture), digest], text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == evidence["packet_verifier"][field], (client, field)
        assert evidence["packet_capture"]["pcap_sha256"] == digest
        assert evidence["packet_capture"]["request_to_client_close_seconds"] == checked["request_to_client_close_seconds"]
    print("verified native Codex and Claude slow-close captures")


if __name__ == "__main__":
    main()
