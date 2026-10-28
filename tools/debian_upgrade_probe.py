#!/usr/bin/env python3
"""Replay a version-to-version Debian package upgrade in disposable Bookworm."""
import argparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--new-sha256", required=True)
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
dpkg -i /new.deb
test "$(dpkg-query -W -f '${Version}' outbound-guard-mcp)" = "$NEW_VERSION"
test "$(/usr/bin/outbound-guard-mcp --version)" = "outbound-guard-mcp $NEW_APP_VERSION"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deb-upgrade","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}}' | /usr/bin/outbound-guard-mcp > /tmp/replies
grep -q '"guarded_fetch"' /tmp/replies
grep -q '"EGRESS_INVALID_HOST"' /tmp/replies
grep -q '"isError":true' /tmp/replies
dpkg -r outbound-guard-mcp
test ! -e /usr/bin/outbound-guard-mcp
test ! -d /usr/share/doc/outbound-guard-mcp
if dpkg-query -W outbound-guard-mcp >/dev/null 2>&1; then exit 1; fi
test ! -e /etc/outbound-guard-mcp
'''
    subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "64",
                    "--mount", f"type=bind,src={old},dst=/old.deb,readonly",
                    "--mount", f"type=bind,src={new},dst=/new.deb,readonly",
                    "--env", f"OLD_VERSION={before['version']}",
                    "--env", f"NEW_VERSION={after['version']}",
                    "--env", f"OLD_APP_VERSION={before['app_version']}",
                    "--env", f"NEW_APP_VERSION={after['app_version']}",
                    BUILDER_IMAGE, "sh", "-ec", script], check=True, timeout=90)
    result = {"result": "passed", "platform": "Debian 12 amd64", "old": before, "new": after,
              "checks": ["old_install", "new_upgrade", "mcp_discovery", "loopback_denial",
                         "remove", "residue"]}
    if args.output:
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
