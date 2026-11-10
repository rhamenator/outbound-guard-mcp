#!/usr/bin/env python3
"""Check exact-source native three-cycle interruption evidence and its limits."""

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-current-three-cancellation-2026-11-10.json"
PATHS = ["/cancel-silent-headers-long", "/plain"] * 3 + ["/head-ok"]
BASE_CHECKS = {"checksum", "clean_dpkg_install", "no_upgrade",
               "native_client_control_and_guarded_calls", "client_interrupt_acknowledged",
               "repeated_same_process_cancel_recovery_cycles", "approved_recovery",
               "package_remove", "residue"}


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["source_main_sha"] == "224ef474135b5298dd8a4d6656ee7d797ef55ea6"
    assert evidence["source_ci_run"].endswith("/42838977522")
    assert evidence["package_version"] == "0.1.0~candidate.340+g224ef474135b"
    assert evidence["package_sha256"] == "aceca10372aba3824847c2a140c85ac0b5b860a9b32433dd373f257249cd6d11"
    assert evidence["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
    assert evidence["skill_zip_sha256"] == "b0cfcb1f8503d2181c2fd75112533c1f36fe3972ccfb65081a08c89a1402dd29"
    for name, digest in evidence["harness_sha256"].items():
        # Verify the immutable bytes actually used by this recorded main build.
        historical = subprocess.check_output(
            ["git", "show", f"{evidence['source_main_sha']}:{name}"], cwd=ROOT, timeout=10)
        assert hashlib.sha256(historical).hexdigest() == digest, name
    image_ids = set()
    for client in ("codex", "claude"):
        run = evidence["runs"][client]
        result = run["client_control_result"]
        assert run["client_version"] == ("codex-cli 0.151.0" if client == "codex"
                                         else "Claude Code 2.1.319")
        assert run["result"] == "passed" and BASE_CHECKS <= set(run["checks"])
        # The control probe receives a generated bridge wrapper, so this
        # per-client hash is not the installed package executable hash.
        assert result["client"] == client and len(result["binary_sha256"]) == 64
        assert result["cancel_phase"] == "headers" and result["cancel_cycles"] == 3
        assert result["live_client"] and result["client_control_acknowledged"]
        assert result["socket_closed"] and result["recovery_allowed"]
        assert result["fetches"] == 8 and result["fixture_paths"] == PATHS
        assert result["http_methods"] == ["GET"] * 7 + ["HEAD"]
        assert result["status_codes"] == [200] * 4
        close_times = result["socket_closed_after_each_seconds"]
        assert len(close_times) == 3 and all(0 < duration < 4 for duration in close_times)
        assert run["container_resource_observation"]["memory_limit_mib"] == 128
        assert run["container_resource_observation"]["memory_events"]["oom_kill"] == 0
        assert run["server_resource_observation"]["samples"] > 0
        assert run["server_resource_observation"]["max_sampled_fd"] > 3
        assert run["image_id"].startswith("sha256:")
        image_ids.add(run["image_id"])
        if client == "claude":
            assert "matching_mcp_cancel_and_socket_close" in run["checks"]
            assert result["control_path"] == "stream-json interrupt"
            assert result["matching_wire_cancellation"] and result["cancel_notifications"] == 3
            assert not result["cancelled_fetch_replied"]
            assert all(duration < 0.25 for duration in close_times)
            assert result["rules"] == ["EGRESS_ALLOWED"] * 3 + ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED"]
        else:
            assert "missing_mcp_cancel_server_timeout_and_socket_close" in run["checks"]
            assert result["control_path"] == "app-server turn/interrupt"
            assert not result["matching_wire_cancellation"] and result["cancel_notifications"] == 0
            assert result["cancelled_fetch_replied"]
            assert all(2.5 < duration < 3.5 for duration in close_times)
            assert result["rules"] == (["EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"] * 3 +
                                       ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED"])
    assert len(image_ids) == 1
    print("verified native three-cycle interruption and Codex delivery gap")


if __name__ == "__main__":
    main()
