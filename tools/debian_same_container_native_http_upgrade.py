#!/usr/bin/env python3
"""Replay a native client HTTP and DNS policy across one Debian upgrade.

The fixture runs inside the disposable server container's route-free network
namespace. This is an opt-in local probe requiring passwordless sudo for
nsenter; it never contacts an external test target.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

from verify_upgrade_http_pcap import verify as verify_capture

from debian_same_container_native_upgrade import command, installed
from debian_upgrade_probe import package_info
from package_candidate import BUILDER_IMAGE


SCENARIOS = {
    "dns": (["http://allowed.test/plain", "http://private.test/plain",
             "http://unlisted.test/plain"],
            ["EGRESS_ALLOWED", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_HOST_NOT_ALLOWED"],
            ["/plain"]),
    "redirect": (["http://allowed.test/plain", "http://allowed.test/redirect",
                  "http://allowed.test/plain"],
                 ["EGRESS_ALLOWED", "EGRESS_REDIRECT_DENIED", "EGRESS_ALLOWED"],
                 ["/plain", "/redirect", "/plain"]),
}
TOOL = "mcp__outbound_guard__guarded_fetch"


def replay_claude(config, output, urls, rules, prompt):
    with output.open("w") as stream:
        subprocess.run(["claude", "-p", "--restricted", "--strict-mcp-config",
                        "--mcp-config", str(config), "--allowedTools", TOOL,
                        "--tools", "", "--permission-mode", "dontAsk",
                        "--no-session-persistence", "--output-format", "stream-json",
                        "--verbose", prompt], stdout=stream, stderr=subprocess.PIPE,
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
    assert [use["input"].get("url") for use in uses] == urls, uses
    assert all(use["input"].get("method", "GET") == "GET" for use in uses), uses
    decisions = []
    for index, use in enumerate(uses):
        reply = replies[use["id"]]
        content = reply["content"]
        if isinstance(content, list):
            content = content[0]["text"]
        decision = json.loads(content)
        allowed = rules[index] == "EGRESS_ALLOWED"
        assert decision["rule"] == rules[index], decision
        assert decision["status"] == ("SAFE" if allowed else "BLOCKED"), decision
        assert bool(reply.get("is_error", False)) == (not allowed), reply
        if allowed:
            assert decision["body_text"] == "fixture-ok", decision
        else:
            assert "body_text" not in decision, decision
        decisions.append({"url": urls[index], "rule": decision["rule"],
                          "status": decision["status"]})
    return decisions


def replay_codex(root, output, urls, rules, prompt):
    env = dict(os.environ, CODEX_HOME=str(root))
    with output.open("w") as stream:
        subprocess.run(["codex", "exec", "--ephemeral", "--skip-git-repo-check",
                        "--dangerously-bypass-approvals-and-sandbox", "--json",
                        "-C", str(root), prompt], env=env, stdout=stream,
                       stderr=subprocess.PIPE, text=True, check=True, timeout=100)
    events = [json.loads(line) for line in output.read_text().splitlines()]
    assert any(event.get("type") == "turn.completed" for event in events), "Codex turn did not finish"
    assert not any(event.get("type") == "turn.failed" for event in events), "Codex turn failed"
    completed = [event["item"] for event in events if event.get("type") == "item.completed"]
    unexpected = [item["type"] for item in completed
                  if item["type"] not in ("agent_message", "error", "mcp_tool_call")]
    assert not unexpected, f"Codex used other tools: {unexpected}"
    calls = [item for item in completed if item["type"] == "mcp_tool_call"]
    assert len(calls) == 3, f"Codex made {len(calls)} MCP calls, expected three"
    assert [(call["server"], call["tool"]) for call in calls] == [
        ("outbound_guard", "guarded_fetch")] * 3, calls
    assert [call["arguments"].get("url") for call in calls] == urls, calls
    assert all(call["arguments"].get("method", "GET") == "GET" for call in calls), calls
    assert all(call.get("error") is None for call in calls), calls
    decisions = [call["result"]["structured_content"] for call in calls]
    assert [decision["rule"] for decision in decisions] == rules, decisions
    for decision, rule in zip(decisions, rules):
        allowed = rule == "EGRESS_ALLOWED"
        assert decision["status"] == ("SAFE" if allowed else "BLOCKED"), decision
        if allowed:
            assert decision.get("body_text") == "fixture-ok", decision
        else:
            assert "body_text" not in decision, decision
    return [{"url": urls[index], "rule": decision["rule"], "status": decision["status"]}
            for index, decision in enumerate(decisions)]


def replay(client, root, config, phase, urls, rules, prompt):
    output = root / f"{phase}.jsonl"
    return (replay_claude(config, output, urls, rules, prompt) if client == "claude"
            else replay_codex(root, output, urls, rules, prompt))


def saved_config(client, root, docker, container):
    args = ["exec", "-i", "--env", "OUTBOUND_GUARD_ALLOWED_HOSTS=allowed.test,private.test",
            container, "/usr/bin/outbound-guard-mcp"]
    if client == "claude":
        config = root / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {"outbound_guard": {
            "command": docker, "args": args}}}))
        return config
    original_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    auth = original_home / "auth.json"
    if auth.is_file():
        (root / "auth.json").symlink_to(auth)
    env = dict(os.environ, CODEX_HOME=str(root))
    subprocess.run(["codex", "mcp", "add", "outbound_guard", "--", docker, *args],
                   env=env, capture_output=True, text=True, check=True, timeout=30)
    config = root / "config.toml"
    config.write_text(config.read_text() +
                      f'\n[projects.{json.dumps(str(root))}]\ntrust_level = "trusted"\n')
    return config


def fixture_state(root, expected_hits, previous_dns_count, scenario):
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
        expected_dns = (["allowed.test", "private.test"] if scenario == "dns"
                        else ["allowed.test"] * 3)
        if hits == expected_hits and phase_dns == expected_dns:
            assert "unlisted.test" not in dns_all and \
                (scenario != "redirect" or "private.test" not in dns_all), dns_all
            return {"hits": hits, "dns_a": phase_dns, "dns_all": dns_all}
        time.sleep(0.05)
    raise AssertionError("fixture did not observe the expected HTTP and DNS activity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("claude", "codex"), default="claude")
    parser.add_argument("--scenario", choices=tuple(SCENARIOS), default="dns")
    parser.add_argument("--allow-codex-approval-bypass", action="store_true",
                        help="Opt in to Codex's unsafe approval bypass from a private test cwd; host access remains")
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--new-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture", type=Path,
                        help="Retain and verify a fixture-namespace packet capture")
    args = parser.parse_args()
    assert not args.capture or args.scenario == "dns", \
        "the retained pcap verifier currently covers the DNS scenario only"
    urls, rules, phase_hits = SCENARIOS[args.scenario]
    prompt = ("Use ONLY outbound_guard guarded_fetch. Make exactly three GET calls, "
              "in order: " + ", ".join(urls) + ". Do not use any other tools or "
              "retry. Report the actual tool results.")
    assert args.client != "codex" or args.allow_codex_approval_bypass, \
        "Codex native MCP calls require explicit approval-bypass opt-in for this isolated probe"
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
        config = saved_config(args.client, root, docker, container)
        config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
        image_id = command("docker", "image", "inspect", BUILDER_IMAGE,
                           "--format", "{{.Id}}")
        started = False
        fixture = None
        packet_capture = None
        tcpdump_pid = None
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
            if args.capture:
                assert shutil.which("tcpdump") and shutil.which("tshark") and shutil.which("aa-exec")
                capture_tmp = root / "fixture.pcap"
                packet_capture = subprocess.Popen(
                    ["sudo", "-n", "nsenter", "-t", str(pid), "-n", "tcpdump",
                     "-Z", "root", "-i", "any", "-U", "-w", str(capture_tmp)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                deadline = time.monotonic() + 5
                while not capture_tmp.exists() or capture_tmp.stat().st_size < 24:
                    assert packet_capture.poll() is None and time.monotonic() < deadline, \
                        "fixture packet capture failed to start"
                    time.sleep(0.05)
                while tcpdump_pid is None:
                    matches = []
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit():
                            continue
                        try:
                            if (entry / "comm").read_text().strip() == "tcpdump" and \
                                    str(capture_tmp) in (entry / "cmdline").read_bytes().decode(errors="replace"):
                                matches.append(int(entry.name))
                        except (OSError, ProcessLookupError):
                            continue
                    assert len(matches) <= 1 and packet_capture.poll() is None and time.monotonic() < deadline, \
                        "fixture packet capture PID not found"
                    tcpdump_pid = matches[0] if matches else None
                    time.sleep(0.05)
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
            before = replay(args.client, root, config, "before", urls, rules, prompt)
            old_fixture = fixture_state(fixture_root, phase_hits, 0, args.scenario)
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            command("docker", "exec", container, "dpkg", "-i", "/new.deb")
            new_installed = installed(container, new)
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            after = replay(args.client, root, config, "after", urls, rules, prompt)
            new_fixture = fixture_state(fixture_root, phase_hits * 2,
                                        len(old_fixture["dns_a"]), args.scenario)
            assert before == after
            assert hashlib.sha256(config.read_bytes()).hexdigest() == config_sha
            command("docker", "exec", container, "dpkg", "-r", "outbound-guard-mcp")
            command("docker", "exec", container, "sh", "-ec",
                    "test ! -e /usr/bin/outbound-guard-mcp; "
                    "test ! -d /usr/share/doc/outbound-guard-mcp; "
                    "test ! -e /etc/outbound-guard-mcp; "
                    "! dpkg-query -W outbound-guard-mcp >/dev/null 2>&1")
            capture_result = None
            if packet_capture:
                assert packet_capture.poll() is None and tcpdump_pid is not None
                subprocess.run(["sudo", "-n", "aa-exec", "-p", "tcpdump",
                                "/usr/bin/kill", "-INT", str(tcpdump_pid)], check=True)
                packet_capture.wait(timeout=5)
                data = subprocess.check_output(["sudo", "-n", "cat", str(capture_tmp)])
                args.capture.parent.mkdir(parents=True, exist_ok=True)
                args.capture.write_bytes(data)
                capture_result = verify_capture(args.capture, hashlib.sha256(data).hexdigest())
            result = {"result": "passed", "platform": "Debian 12 amd64",
                      "scenario": args.scenario,
                      "native_client": args.client,
                      "client": command(args.client, "--version"), "image_id": image_id,
                      "old_package": old, "new_package": new,
                      "old_installed": old_installed, "new_installed": new_installed,
                      "saved_mcp_config_sha256": config_sha,
                      "before": before, "after": after,
                      "fixture_http_hits": new_fixture["hits"],
                      "fixture_dns_a_before": old_fixture["dns_a"],
                      "fixture_dns_a_after": new_fixture["dns_a"],
                      "fixture_dns_all": new_fixture["dns_all"],
                      "packet_capture": capture_result,
                      "checks": ["same_container", "unchanged_saved_client_config",
                                 "old_native_calls", "in_place_package_upgrade",
                                 "new_native_calls", "controlled_http_and_dns",
                                 "remove", "residue", "route_free_fixture"] +
                                (["packet_capture_verified"] if capture_result else []),
                      "limits": ["finite local DNS/HTTP fixture; fixture-namespace capture is not universal socket proof" if capture_result else "finite local DNS/HTTP fixture; no packet capture or universal socket proof",
                                 "no TLS or host-client/other-tool traffic coverage",
                                 "Codex approval bypass ran from private test cwd but retained host access" if args.client == "codex" else "Claude native tool availability is model dependent",
                                 "unsigned experimental packages, not an approved candidate"] +
                                (["redirects are denied by current policy; this does not test safe redirect following"]
                                 if args.scenario == "redirect" else [])}
        finally:
            if packet_capture is not None and packet_capture.poll() is None:
                capture_target = str(tcpdump_pid) if tcpdump_pid is not None else str(-packet_capture.pid)
                subprocess.run(["sudo", "-n", "aa-exec", "-p", "tcpdump",
                                "/usr/bin/kill", "-TERM", "--", capture_target], check=False)
                try:
                    packet_capture.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "aa-exec", "-p", "tcpdump",
                                    "/usr/bin/kill", "-KILL", "--", capture_target], check=False)
                    packet_capture.wait(timeout=4)
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
