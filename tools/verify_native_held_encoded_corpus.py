#!/usr/bin/env python3
"""Bind the separate native held-response captures to their replay evidence."""

import json
from pathlib import Path
import re
import shutil
import tempfile

from verify_native_held_encoded_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = (
    ("native-held-encoded-pcap-2026-11-10.json", "", False),
    ("native-held-encoded-upgrade-pcap-2026-11-10.json", "-upgrade", True),
)


def main() -> None:
    captures = set()
    baseline = None
    for filename, suffix, upgrade in EVIDENCE:
        evidence = json.loads((ROOT / "docs/evidence" / filename).read_text())
        assert evidence["result"] == "passed"
        assert set(evidence["clients"]) == {"claude", "codex"}
        for name, run in evidence["clients"].items():
            assert run["native_client_version"].startswith(
                "Claude Code" if name == "claude" else "Codex CLI")
            if upgrade:
                assert baseline is not None
                assert run["new_package"]["revision"] == evidence["new_source_commit"]
                assert run["old_package"]["revision"] == evidence["old_source_commit"]
                assert run["old_package"] == baseline["clients"][name]["package"]
                assert run["skill_zip_sha256"] == baseline["clients"][name]["skill_zip_sha256"]
                assert run["new_package"]["binary_sha256"] != run["old_package"]["binary_sha256"]
                assert "package_upgrade" in run["probe_checks"]
                assert "old_package_launch_and_loopback_denial" in run["probe_checks"]
            else:
                assert run["package"]["revision"] == evidence["source_commit"]
                assert "no_upgrade" in run["probe_checks"]
            assert run["native_rules"] == ["EGRESS_ALLOWED", "EGRESS_ENCODED_RESPONSE",
                                           "EGRESS_ALLOWED"]
            assert run["native_http_methods"] == ["GET"] * 3
            assert run["native_fixture_hits"] == ["/plain", "/encoded-body-hold", "/plain"]
            assert run["native_approved_status_codes"] == [200, 200]
            assert run["native_held_socket_closed"] is True
            assert all(check in run["probe_checks"] for check in (
                "checksum", "clean_dpkg_install", "held_gzip_header_denial",
                "peer_observed_socket_close", "approved_recovery", "no_denied_body_text",
                "fixture_namespace_tcp_syn_capture", "package_remove", "residue"))
            relative = Path(run["pcap_path"])
            capture = (ROOT / relative).resolve(strict=True)
            assert capture.is_relative_to(CAPTURES) and capture not in captures, relative
            captures.add(capture)
            assert relative.name == f"native-{name}-held-encoded{suffix}-2026-11-10.pcap"
            digest = run["pcap_sha256"]
            assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
            with tempfile.TemporaryDirectory(prefix="outbound-held-corpus-") as directory:
                copy = Path(directory) / "fixture.pcap"
                shutil.copyfile(capture, copy)
                checked = verify(copy, digest)
            assert json.loads(json.dumps(checked)) == run["packet_verifier"], name
        if not upgrade:
            baseline = evidence
    assert len(captures) == 4
    print(json.dumps({"verified_clients": ["claude", "codex"],
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
