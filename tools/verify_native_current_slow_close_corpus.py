#!/usr/bin/env python3
"""Recheck native current-package slow-close packets and bound evidence in CI."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-current-slow-close-2026-11-10.json"
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
FIELDS = ("sha256", "tcp_syn_count", "dns_query_count", "dns_names",
          "http_requests", "timed_out_streams_client_closed", "ip_destinations",
          "request_to_client_close_seconds", "scope")


def main() -> None:
    document = json.loads(EVIDENCE.read_text())
    assert document["result"] == "passed"
    assert document["source_sha"] == "0f83d50a41071aeb1d0ad6c6ec1472dd4efbf619"
    assert set(document["runs"]) == {"codex", "claude"}
    captures = set()
    for client in ("codex", "claude"):
        run = document["runs"][client]
        assert run["result"] == "passed" and run["client"] == client
        assert run["package"]["revision"] == document["source_sha"]
        assert run["package"]["package_sha256"] == document["package_sha256"]
        assert run["skill_zip_sha256"] == document["skill_zip_sha256"]
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TOO_SLOW",
                                "EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"]
        assert {"clean_dpkg_install", "no_upgrade", "native_skill_and_guarded_calls",
                "slow_drip_denial", "delayed_first_byte_denial", "approved_recovery",
                "package_remove", "residue"} <= set(run["checks"])
        expected = f"tests/fixtures/packet-capture/native-{client}-slow-close-current-2026-11-10.pcap"
        assert run["pcap_path"] == expected
        capture = (ROOT / expected).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT) and capture not in captures
        captures.add(capture)
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_slow_http_pcap.py"),
             str(capture), run["pcap_sha256"]], text=True, timeout=25))
        for field in FIELDS:
            assert checked[field] == run["packet_verifier"][field], (client, field)
        assert run["packet_capture"]["pcap_sha256"] == run["pcap_sha256"]
        assert run["fixture_hits"] == ["/plain", "/drip", "/delayed", "/plain"]
    print("verified current-package native Codex and Claude slow-close captures")


if __name__ == "__main__":
    main()
