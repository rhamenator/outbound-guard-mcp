#!/usr/bin/env python3
"""Bind native before/after HTTP version decisions to retained packet bytes."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_upgrade_http_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-version-two-phase-upgrade-2026-11-11.json"
OLD_SHA = "902b02272c559f34bfa9df32a8c824a9c0bf3d96"
NEW_SHA = "894e1024c6e5048838102f2f70b842fb65b4bab1"
OLD_PACKAGE = "499f7d96e86c27a67209257363f9ae25301a7f066a1d8149b0f84285992907f9"
NEW_PACKAGE = "934647f2cf8e4482d297b0f0c77018db46b213597b01a0f4c169f3d64b2641b0"
PATHS = ["/plain", "/http10-ok", "/http10-comma-length",
         "/http11-partial-ok", "/http11-partial-comma-length", "/plain"]
RULES = ["EGRESS_ALLOWED", "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING",
         "EGRESS_ALLOWED", "EGRESS_INVALID_FRAMING", "EGRESS_ALLOWED"]
EXPECTED = [{"url": "http://allowed.test" + path, "rule": rule,
             "status": "SAFE" if rule == "EGRESS_ALLOWED" else "BLOCKED"}
            for path, rule in zip(PATHS, RULES)]


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed" and evidence["scenario"] == "version"
    assert (evidence["old_source_commit"], evidence["new_source_commit"]) == (OLD_SHA, NEW_SHA)
    assert set(evidence["cases"]) == {"claude", "codex"}
    captures = set()
    for client, run in evidence["cases"].items():
        assert run["result"] == "passed" and run["scenario"] == "version"
        assert run["native_client"] == client and run["platform"] == "Debian 12 amd64"
        assert run["client"].startswith("2.1.319" if client == "claude" else "codex-cli 0.151.0")
        assert run["old_package"]["revision"] == OLD_SHA
        assert run["new_package"]["revision"] == NEW_SHA
        assert run["old_package"]["package_sha256"] == OLD_PACKAGE
        assert run["new_package"]["package_sha256"] == NEW_PACKAGE
        assert run["old_package"]["binary_sha256"] == run["new_package"]["binary_sha256"]
        assert run["old_installed"]["binary_sha256"] == run["old_package"]["binary_sha256"]
        assert run["new_installed"]["binary_sha256"] == run["new_package"]["binary_sha256"]
        assert run["old_installed"]["version"] == run["old_package"]["version"]
        assert run["new_installed"]["version"] == run["new_package"]["version"]
        assert run["before"] == run["after"] == EXPECTED
        assert run["fixture_http_hits"] == PATHS * 2
        assert run["fixture_dns_a_before"] == run["fixture_dns_a_after"] == ["allowed.test"] * 6
        assert all(check in run["checks"] for check in (
            "same_container", "unchanged_saved_client_config", "old_native_calls",
            "in_place_package_upgrade", "new_native_calls", "controlled_http_and_dns",
            "remove", "residue", "route_free_fixture", "packet_capture_verified"))
        relative = Path(run["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        captures.add(capture)
        assert relative.name == f"native-{client}-version-two-phase-2026-11-11.pcap"
        digest = run["packet_capture"]["sha256"]
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        checked = verify(capture, digest, "version")
        assert checked == run["packet_capture"] and checked["verified_raw_version_responses"] == 8

    # Recomputing the capture digest cannot conceal a changed status line.
    original = CAPTURES / "native-claude-version-two-phase-2026-11-11.pcap"
    data = original.read_bytes()
    assert data.count(b"HTTP/1.1 206 Partial Content") == 4  # loopback tap sees both directions twice
    changed = data.replace(b"HTTP/1.1 206 Partial Content", b"HTTP/1.1 200 Partial Content")
    with tempfile.TemporaryDirectory(prefix="outbound-version-upgrade-mutant-") as directory:
        mutant = Path(directory) / "mutant.pcap"
        mutant.write_bytes(changed)
        try:
            verify(mutant, hashlib.sha256(changed).hexdigest(), "version")
        except AssertionError:
            pass
        else:
            raise AssertionError("altered HTTP status passed packet oracle")
    print(json.dumps({"verified_captures": len(captures),
                      "semantic_status_mutation_rejected": True}, sort_keys=True))


if __name__ == "__main__":
    main()
