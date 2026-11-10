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
EVIDENCE = ROOT / "docs/evidence/native-held-encoded-pcap-2026-11-10.json"


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed"
    assert set(evidence["clients"]) == {"claude", "codex"}
    captures = set()
    for name, run in evidence["clients"].items():
        assert run["native_client_version"].startswith(
            "Claude Code" if name == "claude" else "Codex CLI")
        assert run["package"]["revision"] == evidence["source_commit"]
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
        assert relative.name == f"native-{name}-held-encoded-2026-11-10.pcap"
        digest = run["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        with tempfile.TemporaryDirectory(prefix="outbound-held-corpus-") as directory:
            copy = Path(directory) / "fixture.pcap"
            shutil.copyfile(capture, copy)
            checked = verify(copy, digest)
        assert json.loads(json.dumps(checked)) == run["packet_verifier"], name
    assert len(captures) == 2
    print(json.dumps({"verified_clients": sorted(evidence["clients"]),
                      "capture_count": len(captures)}, sort_keys=True))


if __name__ == "__main__":
    main()
