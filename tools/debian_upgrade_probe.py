#!/usr/bin/env python3
"""Replay a version-to-version Debian package upgrade in disposable Bookworm."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

from package_candidate import BUILDER_IMAGE


def package_info(path, expected_hash):
    assert re.fullmatch(r"[0-9a-f]{64}", expected_hash), "expected a SHA-256 digest"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash, "package digest mismatch"
    fields = {}
    for name in ("Package", "Version", "Architecture"):
        fields[name] = subprocess.check_output(["dpkg-deb", "--field", str(path), name], text=True).strip()
    assert fields["Package"] == "outbound-guard-mcp" and fields["Architecture"] == "amd64"
    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(path)])
    with tarfile.open(fileobj=io.BytesIO(payload)) as tar:
        member = tar.getmember("./usr/share/doc/outbound-guard-mcp/provenance.json")
        provenance = json.load(tar.extractfile(member))
        assert provenance["candidate"] is True and provenance["stable_release"] is False
        binary = tar.getmember("./usr/bin/outbound-guard-mcp")
        assert binary.isfile() and binary.mode == 0o755
        assert hashlib.sha256(tar.extractfile(binary).read()).hexdigest() == provenance["binary_sha256"]
    return {"version": fields["Version"], "app_version": provenance["version"],
            "revision": provenance["revision"],
            "binary_sha256": provenance["binary_sha256"], "package_sha256": expected_hash}


def policy_decisions(text):
    replies = [json.loads(line) for line in text.splitlines()]
    assert [reply.get("id") for reply in replies] == [1, 2, 3, 4], replies
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    results = [reply["result"] for reply in replies[1:3]]
    assert all(result["isError"] is True for result in results)
    events = [{key: result["structuredContent"][key]
               for key in ("correlation_id", "status", "rule")} for result in results]
    assert [event["rule"] for event in events] == ["EGRESS_DNS_FAILURE", "EGRESS_HOST_NOT_ALLOWED"], events
    assert all("body_text" not in result["structuredContent"] for result in results)
    audit = json.loads(replies[3]["result"]["contents"][0]["text"])
    assert audit["events"] == events, audit
    assert "upgrade-allowed.test" not in json.dumps(audit)
    assert "upgrade-blocked.test" not in json.dumps(audit)
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--new-sha256", required=True)
    parser.add_argument("--check-policy-compat", action="store_true",
                        help="Check the same operator allowlist and redacted audit before and after upgrade")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    old, new = args.old.resolve(), args.new.resolve()
    before = package_info(old, args.old_sha256)
    after = package_info(new, args.new_sha256)
    assert before["revision"] != after["revision"], "distinct source revisions required"
    subprocess.run(["dpkg", "--compare-versions", before["version"], "lt", after["version"]], check=True)
    script = r'''set -eu
grep -q '^VERSION_ID="12"$' /etc/os-release
dpkg -i /old.deb
test "$(dpkg-query -W -f '${Version}' outbound-guard-mcp)" = "$OLD_VERSION"
test "$(/usr/bin/outbound-guard-mcp --version)" = "outbound-guard-mcp $OLD_APP_VERSION"
test "$(sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1)" = "$OLD_BINARY_SHA256"
if [ "$CHECK_POLICY_COMPAT" = 1 ]; then
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deb-policy-upgrade","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://upgrade-allowed.test/plain"}}}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://upgrade-blocked.test/plain"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"outbound-guard://logs/audit.json"}}' \
    | OUTBOUND_GUARD_ALLOWED_HOSTS=upgrade-allowed.test /usr/bin/outbound-guard-mcp > /tmp/policy-old.jsonl
fi
dpkg -i /new.deb
test "$(dpkg-query -W -f '${Version}' outbound-guard-mcp)" = "$NEW_VERSION"
test "$(/usr/bin/outbound-guard-mcp --version)" = "outbound-guard-mcp $NEW_APP_VERSION"
test "$(sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1)" = "$NEW_BINARY_SHA256"
if [ "$CHECK_POLICY_COMPAT" = 1 ]; then
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deb-policy-upgrade","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://upgrade-allowed.test/plain"}}}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://upgrade-blocked.test/plain"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"outbound-guard://logs/audit.json"}}' \
    | OUTBOUND_GUARD_ALLOWED_HOSTS=upgrade-allowed.test /usr/bin/outbound-guard-mcp > /tmp/policy-new.jsonl
fi
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deb-upgrade","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}}' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://allowed.test/café"}}}' | /usr/bin/outbound-guard-mcp > /tmp/replies
grep -q '"guarded_fetch"' /tmp/replies
grep -q '"EGRESS_INVALID_HOST"' /tmp/replies
grep -q '"EGRESS_INVALID_URL"' /tmp/replies
grep -q '"isError":true' /tmp/replies
dpkg -r outbound-guard-mcp
test ! -e /usr/bin/outbound-guard-mcp
test ! -d /usr/share/doc/outbound-guard-mcp
if dpkg-query -W outbound-guard-mcp >/dev/null 2>&1; then exit 1; fi
test ! -e /etc/outbound-guard-mcp
if [ "$CHECK_POLICY_COMPAT" = 1 ]; then
  printf 'POLICY_OLD='; base64 -w0 /tmp/policy-old.jsonl; printf '\n'
  printf 'POLICY_NEW='; base64 -w0 /tmp/policy-new.jsonl; printf '\n'
fi
'''
    output = subprocess.check_output(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "64",
                        "--mount", f"type=bind,src={old},dst=/old.deb,readonly",
                        "--mount", f"type=bind,src={new},dst=/new.deb,readonly",
                        "--env", f"OLD_VERSION={before['version']}",
                        "--env", f"NEW_VERSION={after['version']}",
                        "--env", f"OLD_APP_VERSION={before['app_version']}",
                        "--env", f"NEW_APP_VERSION={after['app_version']}",
                        "--env", f"OLD_BINARY_SHA256={before['binary_sha256']}",
                        "--env", f"NEW_BINARY_SHA256={after['binary_sha256']}",
                        "--env", f"CHECK_POLICY_COMPAT={int(args.check_policy_compat)}",
                        BUILDER_IMAGE, "sh", "-ec", script], text=True, timeout=90)
    if args.check_policy_compat:
        encoded = {}
        for name in ("OLD", "NEW"):
            match = re.search(rf"^POLICY_{name}=([A-Za-z0-9+/=]+)$", output, re.M)
            assert match, f"missing {name} policy probe output"
            encoded[name] = base64.b64decode(match.group(1), validate=True).decode("utf-8")
        old_decisions = policy_decisions(encoded["OLD"])
        new_decisions = policy_decisions(encoded["NEW"])
        assert old_decisions == new_decisions, (old_decisions, new_decisions)
    result = {"result": "passed", "platform": "Debian 12 amd64", "old": before, "new": after,
              "checks": ["old_install", "new_upgrade", "installed_binary_bytes", "mcp_discovery", "loopback_denial", "non_ascii_url_denial",
                         "remove", "residue"]}
    if args.check_policy_compat:
        result["checks"].append("old_and_new_operator_allowlist_and_audit")
        result["policy_decisions"] = old_decisions
    if args.output:
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
