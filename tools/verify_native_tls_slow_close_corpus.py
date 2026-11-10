#!/usr/bin/env python3
"""Bind native TLS slow-close evidence to both retained packet captures."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs/evidence/native-client-tls-slow-pcap-2026-11-08.json"
ORACLE = ROOT / "docs/evidence/native-tls-slow-close-oracle-2026-11-10.json"


def main() -> None:
    source = json.loads(SOURCE.read_text())
    oracle = json.loads(ORACLE.read_text())
    assert oracle["source_evidence"] == SOURCE.relative_to(ROOT).as_posix()
    for client in ("codex", "claude"):
        run = source["runs"][client]
        record = oracle["clients"][client]
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TOO_SLOW",
                                "EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"]
        assert run["fixture_hits"] == ["/plain", "/drip", "/delayed", "/plain"]
        assert record["capture"] == run["pcap_path"]
        assert record["sha256"] == run["pcap_sha256"] == run["packet_capture"]["pcap_sha256"]
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_tls_slow_pcap.py"),
             str(ROOT / record["capture"]), record["sha256"]], text=True, timeout=25))
        for field, expected in run["independent_pcap_verifier"].items():
            assert checked[field] == expected, (client, field)
        assert checked["request_to_client_close_seconds"] == record["request_to_client_close_seconds"]
        assert checked["timed_out_streams_client_closed"] == {"/drip": True, "/delayed": True}
        assert checked["tls_sni"] == ["allowed.test"] * 4
        assert checked["tcp_syn_count"] == 4
        assert checked["ip_destinations"] == ["11.0.0.1", "127.0.0.1"]
    print("verified native Codex and Claude TLS slow-close captures")


if __name__ == "__main__":
    main()
