#!/usr/bin/env python3
"""Check adjacent and changed-binary operator configuration upgrade records."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CERT = ROOT / "tests/fixtures/certs/isrg-root-x1.pem"
CASES = (
    ("debian-saved-operator-config-upgrade-2026-11-10.json",
     "0f83d50a41071aeb1d0ad6c6ec1472dd4efbf619",
     "aae78aa8f43e9af5887b9c08839f8f1b9f590124", False),
    ("debian-changed-binary-operator-config-upgrade-2026-11-10.json",
     "ba75a5645e56acc67bd51f1b492468629a204672",
     "7dcc6122c37ab31e80708d001f17f2ee0b0bf43b", True),
)


def verify(name: str, old_revision: str, new_revision: str, changed_binary: bool) -> None:
    record = json.loads((ROOT / "docs/evidence" / name).read_text())
    assert record["result"] == "passed" and record["platform"] == "Debian 12 amd64"
    assert record["public_ca_fixture"] == str(CERT.relative_to(ROOT))
    assert record["old"]["revision"] == old_revision
    assert record["new"]["revision"] == new_revision
    assert record["old"]["version"] != record["new"]["version"]
    assert record["old"]["package_sha256"] != record["new"]["package_sha256"]
    assert (record["old"]["binary_sha256"] != record["new"]["binary_sha256"]) == changed_binary
    assert ("changed_executable_bytes" in record["checks"]) == changed_binary
    cert_hash = hashlib.sha256(CERT.read_bytes()).hexdigest()
    assert cert_hash == record["saved_config"]["ca_sha256"]
    settings = ("OUTBOUND_GUARD_ALLOWED_HOSTS=upgrade-allowed.test\n"
                "OUTBOUND_GUARD_EXTRA_CA_CERT=/opt/operator/ca.pem\n")
    assert hashlib.sha256(settings.encode()).hexdigest() == record["saved_config"]["settings_sha256"]
    expected = {"allowed_host_count": 1, "network_checked": False,
                "scope": "startup", "valid": True}
    assert record["saved_config"]["old_check"] == expected
    assert record["saved_config"]["new_check"] == expected
    assert [event["rule"] for event in record["policy_decisions"]] == [
        "EGRESS_DNS_FAILURE", "EGRESS_HOST_NOT_ALLOWED"]
    assert {"old_install", "new_upgrade", "installed_binary_bytes", "remove", "residue",
            "old_and_new_operator_allowlist_and_audit",
            "saved_operator_allowlist_and_ca_valid_before_and_after_upgrade",
            "operator_files_preserved_after_remove"} <= set(record["checks"])
    if changed_binary:
        prior = ROOT / record["old_package_prior_evidence"]
        assert prior == ROOT / "docs/evidence/native-held-encoded-two-phase-upgrade-2026-11-10.json"
        earlier = json.loads(prior.read_text())
        for client in ("claude", "codex"):
            assert earlier["cases"]["changed"][client]["old_package"] == record["old"]


def main() -> None:
    for case in CASES:
        verify(*case)
    print("verified adjacent and changed-binary operator settings records and public CA fixture")


if __name__ == "__main__":
    main()
