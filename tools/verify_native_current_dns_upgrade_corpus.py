#!/usr/bin/env python3
"""Bind current-package native upgrade decisions to retained DNS and HTTP wire evidence."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn
from verify_upgrade_http_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-current-dns-upgrade-2026-11-11.json"
CAPTURES = ROOT / "tests/fixtures/packet-capture"
OLD = "ba75a5645e56acc67bd51f1b492468629a204672"
NEW = "0456105251691f2a11892f5bef65ef5b4592eb38"
OLD_PACKAGE = "7c248b6495e880c54540199ff4c7a26f3494da28ebeb40d8e68fac80e379382e"
NEW_PACKAGE = "5f5d9354e7e09df17259144438f9732815ad6c9d874441b5902a419caa3ba952"
OLD_BINARY = "c851e78a2ad2b0bb4ba9bc19917ef24bf9033c92f7a2d79a3b694db667d7a901"
NEW_BINARY = "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
DECISIONS = [
    {"url": "http://allowed.test/plain", "rule": "EGRESS_ALLOWED", "status": "SAFE"},
    {"url": "http://private.test/plain", "rule": "EGRESS_FORBIDDEN_ADDRESS", "status": "BLOCKED"},
    {"url": "http://unlisted.test/plain", "rule": "EGRESS_HOST_NOT_ALLOWED", "status": "BLOCKED"},
]
CHECKS = ["same_container", "unchanged_saved_client_config", "old_native_calls",
          "in_place_package_upgrade", "new_native_calls", "controlled_http_and_dns",
          "remove", "residue", "route_free_fixture", "packet_capture_verified"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence["result"] == "passed"
    assert (evidence["old_source_commit"], evidence["new_source_commit"]) == (OLD, NEW)
    for prefix, package_digest, revision in (("old", OLD_PACKAGE, OLD),
                                             ("new", NEW_PACKAGE, NEW)):
        manifest = ROOT / evidence[f"{prefix}_manifest_path"]
        assert digest(manifest) == evidence[f"{prefix}_manifest_sha256"]
        assert any(line.startswith(package_digest + "  outbound-guard-mcp_0.1.0~candidate.")
                   and revision[:12] in line for line in manifest.read_text().splitlines())
    assert set(evidence["harness_sha256"]) == {
        "tools/debian_same_container_native_http_upgrade.py",
        "tools/verify_upgrade_http_pcap.py", "tools/client_cancellation_fixture.py"}
    for name, expected in evidence["harness_sha256"].items():
        assert digest(ROOT / name) == expected, name
    assert set(evidence["runs"]) == {"claude", "codex"}
    captures = set()
    for client, run in evidence["runs"].items():
        assert run["result"] == "passed" and run["scenario"] == "dns"
        assert run["platform"] == "Debian 12 amd64" and run["native_client"] == client
        assert run["client"] == ("2.1.319 (Claude Code)" if client == "claude"
                                 else "codex-cli 0.151.0")
        assert run["checks"] == CHECKS
        assert run["before"] == run["after"] == DECISIONS
        assert run["fixture_http_hits"] == ["/plain", "/plain"]
        assert run["fixture_dns_a_before"] == run["fixture_dns_a_after"] == [
            "allowed.test", "private.test"]
        assert run["fixture_dns_all"] == (["allowed.test", "allowed.test",
                                            "private.test", "private.test"] * 2)
        assert len(run["saved_mcp_config_sha256"]) == 64
        for prefix, revision, package_digest, binary in (("old", OLD, OLD_PACKAGE, OLD_BINARY),
                                                         ("new", NEW, NEW_PACKAGE, NEW_BINARY)):
            package = run[f"{prefix}_package"]
            installed = run[f"{prefix}_installed"]
            assert package["revision"] == revision
            assert package["package_sha256"] == package_digest
            assert package["binary_sha256"] == installed["binary_sha256"] == binary
            assert package["version"] == installed["version"]
        capture = (ROOT / run["capture_path"]).resolve(strict=True)
        assert capture.is_relative_to(CAPTURES) and capture not in captures
        assert capture.name == f"native-{client}-current-dns-upgrade-2026-11-11.pcap"
        captures.add(capture)
        expected = run["packet_capture"]
        checked = verify(capture, expected["sha256"], "dns")
        assert checked == expected and checked["tcp_syn_count"] == 2
        mutant = forbidden_syn(capture.read_bytes())
        with tempfile.TemporaryDirectory(prefix="outbound-current-dns-upgrade-mutant-") as directory:
            path = Path(directory) / "forbidden-syn.pcap"
            path.write_bytes(mutant)
            try:
                verify(path, hashlib.sha256(mutant).hexdigest(), "dns")
            except AssertionError as error:
                assert "169.254.169.254" in str(error), error
            else:
                raise AssertionError("metadata-address SYN passed packet oracle")
    assert len(captures) == 2
    print(json.dumps({"capture_count": len(captures), "verified_clients": sorted(evidence["runs"])},
                     sort_keys=True))


if __name__ == "__main__":
    main()
