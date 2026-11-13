#!/usr/bin/env python3
"""Recheck the retained Cursor ACP control capture and altered-wire controls."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from verify_native_body_cancel_pcap import PATHS, verify
from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_native_cancel_pcap import rows
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-cursor-current-body-control-pcap-2026-11-13.json"


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["source_main_sha"] == "1cc67494d4a610696b4e651e1a893130766fe174"
    assert evidence["source_ci_run"].endswith("/43354585953")
    assert evidence["harness_source_sha"] == "2963e329d31ef41e7747ab4a418b1891125b87da"
    assert evidence["package_sha256"] == "d025319c4c5c97ac769bfbab2ce45316a52656b5079068b512f8aa70d3b5d57d"
    assert evidence["client_version"] == "Cursor CLI 2026.10.19-6bbf2c4"
    for name, digest in evidence["harness_sha256"].items():
        historical = subprocess.check_output(
            ["git", "show", f"{evidence['harness_source_sha']}:{name}"], cwd=ROOT, timeout=10)
        assert hashlib.sha256(historical).hexdigest() == digest, name
    capture = ROOT / evidence["capture"]
    assert capture.is_relative_to(ROOT / "tests/fixtures/packet-capture")
    data = capture.read_bytes()
    assert len(data) == evidence["pcap_bytes"]
    result = evidence["native_client_control_result"]
    assert result["client"] == "cursor" and result["live_client"]
    assert result["binary_sha256"] == evidence["binary_sha256"]
    assert result["cancel_phase"] == "body" and result["cancel_cycles"] == 1
    assert result["control_path"] == "ACP session/cancel"
    assert result["client_control_acknowledged"] and result["socket_closed"]
    assert result["recovery_allowed"] and result["cancel_notifications"] == 0
    assert not result["matching_wire_cancellation"] and result["cancelled_fetch_replied"]
    assert result["rules"] == ["EGRESS_RESPONSE_TOO_SLOW", "EGRESS_ALLOWED",
                               "EGRESS_INVALID_HOST", "EGRESS_ALLOWED"]
    assert result["fixture_paths"] == PATHS
    assert result["packet_capture"]["pcap_sha256"] == evidence["pcap_sha256"]
    assert result["packet_capture"]["raw_pcap_retained"]

    with tempfile.TemporaryDirectory(prefix="outbound-cursor-body-negative-") as directory:
        mutant_path = Path(directory) / "mutant.pcap"
        mutant_path.write_bytes(data)
        assert verify(mutant_path, evidence["pcap_sha256"], "cursor") == evidence["packet_analysis"]
        frames = {int(number) for number, in rows(
            mutant_path, "tcp.stream == 0 && tcp.dstport == 80 && "
            "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.number")}
        assert frames
        for mutant, expected in ((late_close(data, frames), "cursor"),
                                 (forbidden_syn(data), "169.254.169.254")):
            mutant_path.write_bytes(mutant)
            try:
                verify(mutant_path, hashlib.sha256(mutant).hexdigest(), "cursor")
            except AssertionError as error:
                assert expected in str(error), error
            else:
                raise AssertionError("altered Cursor capture passed wire oracle")
    print("verified Cursor ACP body-control capture and altered-wire controls")


if __name__ == "__main__":
    main()
