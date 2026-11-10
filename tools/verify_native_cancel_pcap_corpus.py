#!/usr/bin/env python3
"""Verify retained native cancellation packets against the recorded client results."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_native_cancel_pcap import PATHS, verify


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-three-cancellation-pcap-2026-11-10.json"
HARNESS_MAIN_SHA = "9d2f89b9229a7dc36d4856afd2ad0e47eaa97de9"


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["source_main_sha"] == "224ef474135b5298dd8a4d6656ee7d797ef55ea6"
    assert evidence["source_ci_run"].endswith("/42838977522")
    assert evidence["package_sha256"] == "aceca10372aba3824847c2a140c85ac0b5b860a9b32433dd373f257249cd6d11"
    assert evidence["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
    for name, digest in evidence["harness_sha256"].items():
        # The recorded package predates this capture harness. Verify the
        # harness bytes from the merged evidence commit, not the evolving tree.
        historical = subprocess.check_output(
            ["git", "show", f"{HARNESS_MAIN_SHA}:{name}"], cwd=ROOT, timeout=10)
        assert hashlib.sha256(historical).hexdigest() == digest, name
    images = set()
    for client in ("codex", "claude"):
        run = evidence["runs"][client]
        control = run["client_control_result"]
        capture = ROOT / run["capture"]
        assert capture.is_relative_to(ROOT / "tests/fixtures/packet-capture")
        assert run["result"] == "passed"
        assert "fixture_namespace_control_packet_capture" in run["checks"]
        assert run["pcap_bytes"] == capture.stat().st_size
        assert control["packet_capture"]["pcap_sha256"] == run["pcap_sha256"]
        assert control["packet_capture"]["raw_pcap_retained"]
        assert control["packet_capture"]["bytes"] == run["pcap_bytes"]
        assert control["client"] == client and control["cancel_phase"] == "headers"
        assert control["cancel_cycles"] == 3 and control["fixture_paths"] == PATHS
        assert control["live_client"] and control["client_control_acknowledged"]
        assert control["socket_closed"] and control["recovery_allowed"]
        assert run["container_resource_observation"]["memory_events"]["oom_kill"] == 0
        assert run["container_resource_observation"]["memory_limit_mib"] == 128
        assert run["server_resource_observation"]["samples"] > 0
        images.add(run["image_id"])
        if client == "claude":
            assert run["client_version"] == "Claude Code 2.1.319"
            assert control["matching_wire_cancellation"] and control["cancel_notifications"] == 3
            assert not control["cancelled_fetch_replied"]
        else:
            assert run["client_version"] == "codex-cli 0.151.0"
            assert not control["matching_wire_cancellation"] and control["cancel_notifications"] == 0
            assert control["cancelled_fetch_replied"]
        with tempfile.TemporaryDirectory(prefix="outbound-cancel-corpus-") as directory:
            copy = Path(directory) / "fixture.pcap"
            shutil.copyfile(capture, copy)
            assert verify(copy, run["pcap_sha256"], client) == run["packet_analysis"]
    assert len(images) == 1 and next(iter(images)).startswith("sha256:")
    print("verified retained native three-cycle cancellation packet corpus")


if __name__ == "__main__":
    main()
