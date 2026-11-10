#!/usr/bin/env python3
"""Check the retained adjacent-package operator configuration continuity record."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/debian-saved-operator-config-upgrade-2026-11-10.json"
CERT = ROOT / "tests/fixtures/certs/isrg-root-x1.pem"


def main() -> None:
    record = json.loads(EVIDENCE.read_text())
    assert record["result"] == "passed" and record["platform"] == "Debian 12 amd64"
    assert record["public_ca_fixture"] == str(CERT.relative_to(ROOT))
    assert record["old"]["revision"] == "0f83d50a41071aeb1d0ad6c6ec1472dd4efbf619"
    assert record["new"]["revision"] == "aae78aa8f43e9af5887b9c08839f8f1b9f590124"
    assert record["old"]["version"] != record["new"]["version"]
    assert record["old"]["package_sha256"] != record["new"]["package_sha256"]
    assert record["old"]["binary_sha256"] == record["new"]["binary_sha256"]
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
    print("verified saved operator configuration upgrade record and public CA fixture")


if __name__ == "__main__":
    main()
