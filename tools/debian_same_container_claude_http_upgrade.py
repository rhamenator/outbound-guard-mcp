#!/usr/bin/env python3
"""Replay native Claude allowed HTTP and DNS denials across one Debian upgrade.

The fixture runs inside the disposable server container's route-free network
namespace. This is an opt-in local probe requiring passwordless sudo for
nsenter; it never contacts an external test target.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

from debian_same_container_native_upgrade import command, installed
from debian_upgrade_probe import package_info
from package_candidate import BUILDER_IMAGE


URLS = ["http://allowed.test/plain", "http://private.test/plain",
        "http://unlisted.test/plain"]
RULES = ["EGRESS_ALLOWED", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_HOST_NOT_ALLOWED"]
PROMPT = ("Use ONLY outbound_guard guarded_fetch. Make exactly three GET calls, "
          "in order: " + ", ".join(URLS) + ". Do not use any other tools or "
          "retry. Report the actual tool results.")
TOOL = "mcp__outbound_guard__guarded_fetch"


def replay(config, output):
    with output.open("w") as stream:
        subprocess.run(["claude", "-p", "--restricted", "--strict-mcp-config",
                        "--mcp-config", str(config), "--allowedTools", TOOL,
                        "--tools", "", "--permission-mode", "dontAsk",
                        "--no-session-persistence", "--output-format", "stream-json",
                        "--verbose", PROMPT], stdout=stream, stderr=subprocess.PIPE,
                       text=True, check=True, timeout=100)
    uses, replies = [], {}
    for line in output.read_text().splitlines():
        event = json.loads(line)
        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "tool_use":
                uses.append(block)
            elif block.get("type") == "tool_result":
                replies[block["tool_use_id"]] = block
    assert len(uses) == 3 and [use["name"] for use in uses] == [TOOL] * 3, uses
    assert [use["input"].get("url") for use in uses] == URLS, uses
    assert all(use["input"].get("method", "GET") == "GET" for use in uses), uses
    decisions = []
    for index, use in enumerate(uses):
        reply = replies[use["id"]]
        content = reply["content"]
        if isinstance(content, list):
            content = content[0]["text"]
        decision = json.loads(content)
        assert decision["rule"] == RULES[index], decision
        assert decision["status"] == ("SAFE" if index == 0 else "BLOCKED"), decision
        assert bool(reply.get("is_error", False)) == (index != 0), reply
        if index == 0:
            assert decision["body_text"] == "fixture-ok", decision
        else:
            assert "body_text" not in decision, decision
        decisions.append({"url": URLS[index], "rule": decision["rule"],
                          "status": decision["status"]})
    return decisions


def fixture_state(root, expected_hits, previous_dns_count):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            hits = json.loads((root / "hits.json").read_text())
            dns_a = json.loads((root / "dns-a.json").read_text())
            dns_all = json.loads((root / "dns-all.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.05)
            continue
        phase_dns = dns_a[previous_dns_count:]
        if len(hits) == expected_hits and {"allowed.test", "private.test"} <= set(phase_dns):
            assert hits == ["/plain"] * expected_hits, hits
            assert "unlisted.test" not in dns_all, dns_all
            return {"hits": hits, "dns_a": phase_dns, "dns_all": dns_all}
        time.sleep(0.05)
    raise AssertionError("fixture did not observe the expected HTTP and DNS activity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--new-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old_path, new_path = args.old.resolve(strict=True), args.new.resolve(strict=True)
    old = package_info(old_path, args.old_sha256)
    new = package_info(new_path, args.new_sha256)
    assert old["revision"] != new["revision"]
    subprocess.run(["dpkg", "--compare-versions", old["version"], "lt", new["version"]], check=True)
    docker = shutil.which("docker")
    assert docker, "Docker executable not found on PATH"
    container = "outbound-http-upgrade-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="outbound-http-upgrade-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        fixture_root = root / "fixture"
        fixture_root.mkdir()
        config = root / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {"outbound_guard": {
            "command": docker,
            "args": ["exec", "-i", "--env",
                     "OUTBOUND_GUARD_ALLOWED_HOSTS=allowed.test,private.test",
                     container, "/usr/bin/outbound-guard-mcp"]}}}))
        config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
        image_id = command("docker", "image", "inspect", BUILDER_IMAGE,
                           "--format", "{{.Id}}")
        started = False
        fixture = None
        try:
            command("docker", "run", "-d", "--rm", "--pull", "never", "--network", "none",
                    "--dns", "127.0.0.1", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--memory", "512m",
                    "--memory-swap", "512m", "--pids-limit", "64", "--cpus", "1",
                    "--mount", f"type=bind,src={old_path},dst=/old.deb,readonly",
                    "--mount", f"type=bind,src={new_path},dst=/new.deb,readonly",
                    "--name", container, BUILDER_IMAGE, "sleep", "infinity")
            started = True
            assert command("docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", container) == "none"
            pid = int(command("docker", "inspect", "-f", "{{.State.Pid}}", container))
            assert pid > 1
            assert command("docker", "exec", container, "sh", "-c",
                           ". /etc/os-release; echo $VERSION_ID") == "12"
            assert command("docker", "exec", container, "dpkg", "--print-architecture") == "amd64"
            assert "nameserver 127.0.0.1" in command("docker", "exec", container,
                                                      "cat", "/etc/resolv.conf")
            subprocess.run(["sudo", "-n", "nsenter", "-t", str(pid), "-n", "ip",
                            "addr", "add", "11.0.0.1/32", "dev", "lo"], check=True)
            subprocess.run(["sudo", "-n", "nsenter", "-t", str(pid), "-n", "ip",
                            "link", "set", "lo", "up"], check=True)
            routes = command("sudo", "-n", "nsenter", "-t", str(pid), "-n", "ip", "route")
            assert not routes, f"fixture namespace has a non-local route: {routes}"
            fixture_script = Path(__file__).with_name("client_cancellation_fixture.py").resolve()
            with (root / "fixture.stderr").open("w") as stderr:
                fixture = subprocess.Popen(["sudo", "-n", "nsenter", "-t", str(pid), "-n",
                                            "python3", str(fixture_script), str(fixture_root)],
                                           stdout=subprocess.DEVNULL, stderr=stderr,
                                           start_new_session=True)
            deadline = time.monotonic() + 5
            while not (fixture_root / "ready").exists():
                assert fixture.poll() is None and time.monotonic() < deadline, \
                    "controlled DNS/HTTP fixture failed to start"
                time.sleep(0.05)
            command("docker", "exec", container, "dpkg", "-i", "/old.deb")
            old_installed = installed(container, old)
            before = replay(config, root / "before.jsonl")
            old_fixture = fixture_state(fixture_root, 1, 0)
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            command("docker", "exec", container, "dpkg", "-i", "/new.deb")
            new_installed = installed(container, new)
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            after = replay(config, root / "after.jsonl")
            new_fixture = fixture_state(fixture_root, 2, len(old_fixture["dns_a"]))
            assert before == after
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            command("docker", "exec", container, "dpkg", "-r", "outbound-guard-mcp")
            command("docker", "exec", container, "sh", "-ec",
                    "test ! -e /usr/bin/outbound-guard-mcp; "
                    "test ! -d /usr/share/doc/outbound-guard-mcp; "
                    "test ! -e /etc/outbound-guard-mcp; "
                    "! dpkg-query -W outbound-guard-mcp >/dev/null 2>&1")
            result = {"result": "passed", "platform": "Debian 12 amd64",
                      "client": command("claude", "--version"), "image_id": image_id,
                      "old_package": old, "new_package": new,
                      "old_installed": old_installed, "new_installed": new_installed,
                      "saved_mcp_config_sha256": config_sha,
                      "before": before, "after": after,
                      "fixture_http_hits": new_fixture["hits"],
                      "fixture_dns_a_before": old_fixture["dns_a"],
                      "fixture_dns_a_after": new_fixture["dns_a"],
                      "fixture_dns_all": new_fixture["dns_all"],
                      "checks": ["same_container", "unchanged_saved_client_config",
                                 "old_native_calls", "in_place_package_upgrade",
                                 "new_native_calls", "controlled_http_and_dns",
                                 "remove", "residue", "route_free_fixture"],
                      "limits": ["finite local DNS/HTTP fixture; no packet capture or universal socket proof",
                                 "no TLS or host-client/other-tool traffic coverage",
                                 "unsigned experimental packages, not an approved candidate"]}
        finally:
            if fixture is not None:
                subprocess.run(["sudo", "-n", "/bin/kill", "-TERM", "--",
                                str(-fixture.pid)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
                try:
                    fixture.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "/bin/kill", "-KILL", "--",
                                    str(-fixture.pid)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False)
                    fixture.wait(timeout=4)
            if started:
                subprocess.run(["docker", "stop", "-t", "5", container], check=True,
                               stdout=subprocess.DEVNULL, timeout=20)
                assert not command("docker", "ps", "-aq", "--filter", f"name=^{container}$")
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
