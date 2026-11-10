#!/usr/bin/env python3
"""Recheck fresh exact-main installed-client TLS slow-close evidence."""

import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-current-tls-slow-close-2026-11-10.json"
CHECKS = {"checksum", "clean_dpkg_install", "native_skill_and_guarded_calls",
          "trusted_tls_handshake", "tls_sni_preserved", "tls_slow_drip_denial",
          "tls_delayed_first_byte_denial", "tls_client_hello_capture",
          "timed_out_tcp_streams_closed", "fixture_namespace_tcp_syn_capture",
          "approved_recovery", "package_remove", "residue"}


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["source_main_sha"] == "224ef474135b5298dd8a4d6656ee7d797ef55ea6"
    assert evidence["source_ci_run"].endswith("/42838977522")
    assert evidence["package_version"] == "0.1.0~candidate.340+g224ef474135b"
    assert evidence["package_sha256"] == "aceca10372aba3824847c2a140c85ac0b5b860a9b32433dd373f257249cd6d11"
    assert evidence["installed_binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
    assert evidence["skill_zip_sha256"] == "b0cfcb1f8503d2181c2fd75112533c1f36fe3972ccfb65081a08c89a1402dd29"
    assert evidence["oracle_limits_seconds"] == {"/drip": 4.25, "/delayed": 3.25}
    for name, digest in evidence["harness_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    for client in ("codex", "claude"):
        run = evidence["runs"][client]
        assert run["client_version"] == ("codex-cli 0.151.0" if client == "codex"
                                         else "Claude Code 2.1.319")
        assert run["result"] == "passed" and run["fixture_mode"] == "tls-slow-http-packet"
        assert run["native_skill_loaded"] is True
        client_fields = ("native_skill_discovered", "explicit_skill_input_accepted",
                         "native_turn_completed") if client == "codex" else (
                             "native_skill_invoked", "skill_tool_result_success")
        assert all(run[field] is True for field in client_fields), client
        assert CHECKS <= set(run["checks"])
        assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_RESPONSE_TOO_SLOW",
                                "EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"]
        assert run["fixture_hits"] == ["/plain", "/drip", "/delayed", "/plain"]
        assert run["tls_sni"] == [["11.0.0.1", "allowed.test"]] * 4
        assert run["container_resource_observation"]["memory_limit_mib"] == 128
        assert run["server_resource_observation"]["max_sampled_fd"] >= 4
        expected = f"tests/fixtures/packet-capture/native-{client}-tls-slow-current-2026-11-10.pcap"
        assert run["capture"] == expected
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / "tools/verify_native_tls_slow_pcap.py"),
             str(ROOT / expected), run["pcap_sha256"]], text=True, timeout=25))
        assert checked == run["packet_verifier"], client
        assert checked["request_to_client_close_seconds"]["/drip"] <= 4.25
        assert checked["request_to_client_close_seconds"]["/delayed"] <= 3.25
    print("verified fresh exact-main Codex and Claude TLS slow-close captures")


if __name__ == "__main__":
    main()
