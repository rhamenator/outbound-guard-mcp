#!/usr/bin/env python3
"""Replay one saved native Claude MCP configuration across an in-place Debian upgrade.

The server container has no network; the two calls prove policy ordering and
client/server continuity, not successful HTTP transport or host-client isolation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from debian_upgrade_probe import package_info
from package_candidate import BUILDER_IMAGE


PROMPT = ("Use ONLY outbound_guard guarded_fetch. First GET "
          "http://upgrade-allowed.test/plain once, then GET "
          "http://upgrade-blocked.test/plain once. Do not use any other tools "
          "or retry. Report the actual tool results.")
URLS = ["http://upgrade-allowed.test/plain", "http://upgrade-blocked.test/plain"]
RULES = ["EGRESS_DNS_FAILURE", "EGRESS_HOST_NOT_ALLOWED"]
TOOL = "mcp__outbound_guard__guarded_fetch"


def command(*args, timeout=30):
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def installed(container, expected):
    version = command("docker", "exec", container, "dpkg-query", "-W", "-f=${Version}", "outbound-guard-mcp")
    binary = command("docker", "exec", container, "sha256sum", "/usr/bin/outbound-guard-mcp").split()[0]
    app = command("docker", "exec", container, "/usr/bin/outbound-guard-mcp", "--version")
    assert (version, binary, app) == (expected["version"], expected["binary_sha256"],
                                      "outbound-guard-mcp " + expected["app_version"])
    return {"version": version, "binary_sha256": binary}


def replay(config, output):
    with output.open("w") as stream:
        completed = subprocess.run(["claude", "-p", "--restricted", "--strict-mcp-config",
                        "--mcp-config", str(config), "--allowedTools", TOOL,
                        "--tools", "", "--permission-mode", "dontAsk",
                        "--no-session-persistence", "--output-format", "stream-json",
                        "--verbose", PROMPT], stdout=stream, stderr=subprocess.PIPE,
                       text=True, check=True, timeout=100)
    uses = []
    replies = {}
    for line in output.read_text().splitlines():
        event = json.loads(line)
        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                uses.append(block)
            elif block.get("type") == "tool_result":
                replies[block["tool_use_id"]] = block
    assert len(uses) == 2, {"uses": uses,
                            "events": [json.loads(line).get("type") for line in output.read_text().splitlines()],
                            "stderr": completed.stderr[-1000:]}
    assert [use["name"] for use in uses] == [TOOL, TOOL], uses
    assert [use["input"].get("url") for use in uses] == URLS, uses
    assert all(use["input"].get("method", "GET") == "GET" for use in uses), uses
    rules = []
    for use in uses:
        reply = replies[use["id"]]
        assert reply.get("is_error") is True, reply
        content = reply["content"]
        if isinstance(content, list):
            content = content[0]["text"]
        rules.append(json.loads(content)["rule"])
    assert rules == RULES, rules
    return {"client": command("claude", "--version"), "tools": [TOOL, TOOL],
            "urls": URLS, "methods": ["GET", "GET"], "rules": rules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--new-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old = package_info(args.old.resolve(strict=True), args.old_sha256)
    new = package_info(args.new.resolve(strict=True), args.new_sha256)
    assert old["revision"] != new["revision"]
    subprocess.run(["dpkg", "--compare-versions", old["version"], "lt", new["version"]], check=True)
    container = "outbound-native-upgrade-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="outbound-native-upgrade-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        docker = shutil.which("docker")
        assert docker, "Docker executable not found on PATH"
        config = root / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {"outbound_guard": {
            "command": docker,
            "args": ["exec", "-i", "--env",
                     "OUTBOUND_GUARD_ALLOWED_HOSTS=upgrade-allowed.test",
                     container, "/usr/bin/outbound-guard-mcp"]}}}))
        config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
        image = command("docker", "image", "inspect", BUILDER_IMAGE, "--format", "{{.Id}}")
        started = False
        try:
            command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "none",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "64",
                    "--cpus", "1", "--mount", f"type=bind,src={args.old.resolve()},dst=/old.deb,readonly",
                    "--mount", f"type=bind,src={args.new.resolve()},dst=/new.deb,readonly",
                    "--name", container, BUILDER_IMAGE, "sleep", "infinity")
            started = True
            assert command("docker", "exec", container, "sh", "-c", ". /etc/os-release; echo $VERSION_ID") == "12"
            assert command("docker", "exec", container, "dpkg", "--print-architecture") == "amd64"
            command("docker", "exec", container, "dpkg", "-i", "/old.deb")
            old_installed = installed(container, old)
            before = replay(config, root / "before.jsonl")
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_hash
            command("docker", "exec", container, "dpkg", "-i", "/new.deb")
            new_installed = installed(container, new)
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_hash
            after = replay(config, root / "after.jsonl")
            assert before == after
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_hash
            command("docker", "exec", container, "dpkg", "-r", "outbound-guard-mcp")
            command("docker", "exec", container, "sh", "-ec",
                    "test ! -e /usr/bin/outbound-guard-mcp; "
                    "test ! -d /usr/share/doc/outbound-guard-mcp; "
                    "test ! -e /etc/outbound-guard-mcp; "
                    "! dpkg-query -W outbound-guard-mcp >/dev/null 2>&1")
            result = {"result": "passed", "platform": "Debian 12 amd64",
                      "container_image_id": image, "old_package": old,
                      "new_package": new, "old_installed": old_installed,
                      "new_installed": new_installed, "saved_mcp_config_sha256": config_hash,
                      "before": before, "after": after,
                      "checks": ["same_container", "unchanged_saved_client_config",
                                 "old_native_client_calls", "in_place_package_upgrade",
                                 "new_native_client_calls", "remove", "residue"],
                      "limits": ["network-disabled server: no successful HTTP or controlled DNS fixture",
                                 "host client traffic and other tools not covered",
                                 "experimental unsigned packages; no official candidate approval"]}
            args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
            print(json.dumps(result, sort_keys=True))
        finally:
            if started:
                subprocess.run(["docker", "stop", "-t", "5", container], check=True,
                               stdout=subprocess.DEVNULL, timeout=20)
                assert not command("docker", "ps", "-aq", "--filter", f"name=^{container}$")


if __name__ == "__main__":
    main()
