#!/usr/bin/env python3
"""Bind native before/after upgrade decisions to four held-response wire captures."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_upgrade_http_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = ROOT / "docs/evidence/native-held-encoded-two-phase-upgrade-2026-11-10.json"
NEW_SOURCE = "b59bc2cf65e641bf27abb511ea047f6a2767d86a"
NEW_PACKAGE_SHA = "6ca8c0d5b4033819727f017a38daf4fbf8a4f1191c31205680be811b76a62f42"
OLD = {
    "adjacent": ("cf9f758a12cf1462fd2110f2c3f2a998ec9501d2",
                 "67ca44c41b1cd47e7be8ee4d5dab0aa122d8320d555015fbee2f3962c2690335", False),
    "changed": ("ba75a5645e56acc67bd51f1b492468629a204672",
                "7c248b6495e880c54540199ff4c7a26f3494da28ebeb40d8e68fac80e379382e", True),
}
EXPECTED = [
    {"url": "http://allowed.test/plain", "rule": "EGRESS_ALLOWED", "status": "SAFE"},
    {"url": "http://allowed.test/encoded-body-hold", "rule": "EGRESS_ENCODED_RESPONSE",
     "status": "BLOCKED"},
    {"url": "http://allowed.test/plain", "rule": "EGRESS_ALLOWED", "status": "SAFE"},
]


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed"
    assert evidence["new_source_commit"] == NEW_SOURCE
    assert set(evidence["cases"]) == set(OLD)
    captures = set()
    for variant, (source, package_sha, changed_binary) in OLD.items():
        group = evidence["cases"][variant]
        assert set(group) == {"claude", "codex"}
        for client, run in group.items():
            assert run["result"] == "passed" and run["scenario"] == "held-encoded"
            assert run["native_client"] == client
            assert run["client"].startswith("2.1.319" if client == "claude" else "codex-cli 0.151.0")
            assert run["old_package"]["revision"] == source
            assert run["old_package"]["package_sha256"] == package_sha
            assert run["new_package"]["revision"] == NEW_SOURCE
            assert run["new_package"]["package_sha256"] == NEW_PACKAGE_SHA
            assert (run["old_package"]["binary_sha256"] !=
                    run["new_package"]["binary_sha256"]) == changed_binary
            assert run["old_installed"]["binary_sha256"] == run["old_package"]["binary_sha256"]
            assert run["new_installed"]["binary_sha256"] == run["new_package"]["binary_sha256"]
            assert run["old_installed"]["version"] == run["old_package"]["version"]
            assert run["new_installed"]["version"] == run["new_package"]["version"]
            assert run["before"] == run["after"] == EXPECTED
            assert run["fixture_http_hits"] == ["/plain", "/encoded-body-hold", "/plain"] * 2
            assert run["fixture_dns_a_before"] == run["fixture_dns_a_after"] == ["allowed.test"] * 3
            assert all(check in run["checks"] for check in (
                "same_container", "unchanged_saved_client_config", "old_native_calls",
                "in_place_package_upgrade", "new_native_calls", "controlled_http_and_dns",
                "remove", "residue", "route_free_fixture", "packet_capture_verified"))
            relative = Path(run["pcap_path"])
            capture = (ROOT / relative).resolve(strict=True)
            assert capture.is_relative_to(CAPTURES) and capture not in captures, relative
            captures.add(capture)
            assert relative.name == f"native-{client}-held-two-phase-{variant}-2026-11-10.pcap"
            digest = run["packet_capture"]["sha256"]
            assert len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
            checked = verify(capture, digest, "held-encoded")
            assert checked == run["packet_capture"]
    assert len(captures) == 4

    # A recomputed digest must not make an altered gzip prefix pass the wire oracle.
    original = CAPTURES / "native-claude-held-two-phase-adjacent-2026-11-10.pcap"
    data = original.read_bytes()
    assert data.count(b"\x1f\x8b\x08") == 2
    changed = data.replace(b"\x1f\x8b\x08", b"\x1f\x8b\x09", 1)
    with tempfile.TemporaryDirectory(prefix="outbound-two-phase-oracle-") as directory:
        mutant = Path(directory) / "mutant.pcap"
        mutant.write_bytes(changed)
        try:
            verify(mutant, hashlib.sha256(changed).hexdigest(), "held-encoded")
        except AssertionError:
            pass
        else:
            raise AssertionError("altered held-response packet passed semantic oracle")
    print(json.dumps({"capture_count": len(captures), "variants": sorted(OLD),
                      "semantic_mutation_rejected": True}, sort_keys=True))


if __name__ == "__main__":
    main()
