#!/usr/bin/env python3
"""Run a native client against an installed Debian 12 package in a route-free fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
import shutil
import time

from debian_upgrade_probe import package_info
from package_candidate import BUILDER_IMAGE


BRIDGE = r'''#!/usr/bin/env bash
set -euo pipefail
namespace=$(ip netns identify $$)
[[ $namespace == outbound-client-cancel-* ]]
container=outbound-native-$BASHPID
package=__PACKAGE__
old_package=__OLD_PACKAGE__
state=__STATE__
expected_binary=__BINARY_SHA__
expected_version=__VERSION__
old_binary=__OLD_BINARY_SHA__
old_version=__OLD_VERSION__
old_app_version=__OLD_APP_VERSION__
app_version=__APP_VERSION__
sample_resources=__SAMPLE_RESOURCES__
printf '%s\n' "$container" > "$state"
old_mount=()
if [[ -n $old_package ]]; then old_mount=(--mount "type=bind,src=$old_package,dst=/old.deb,readonly"); fi
docker run -d --rm --pull never --network none --dns 127.0.0.1 \
  --cap-add SYS_ADMIN --security-opt no-new-privileges \
  --memory __MEMORY_MIB__m --memory-swap __MEMORY_MIB__m --pids-limit 64 --cpus 1 \
  --mount "type=bind,src=/run/netns/$namespace,dst=/run/fixture-netns,readonly" \
  --mount "type=bind,src=$package,dst=/candidate.deb,readonly" \
  "${old_mount[@]}" \
  --name "$container" __IMAGE__ sleep infinity >/dev/null
docker exec "$container" sh -ec 'grep -q '\''^VERSION_ID="12"$'\'' /etc/os-release; test "$(dpkg --print-architecture)" = amd64'
if [[ -n $old_package ]]; then
  docker exec "$container" dpkg -i /old.deb >&2
  [[ $(docker exec "$container" dpkg-query -W -f='${Version}' outbound-guard-mcp) == "$old_version" ]]
  [[ $(docker exec "$container" sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1) == "$old_binary" ]]
  [[ $(docker exec "$container" /usr/bin/outbound-guard-mcp --version) == "outbound-guard-mcp $old_app_version" ]]
  docker exec "$container" sh -ec '
    printf "%s\n" '\''{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"pre-upgrade-smoke","version":"1"}}}'\'' '\''{"jsonrpc":"2.0","method":"notifications/initialized"}'\'' '\''{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"guarded_fetch","arguments":{"url":"http://127.0.0.1/"}}}'\'' | /usr/bin/outbound-guard-mcp' > "$state.old-replies"
  python3 - "$state.old-replies" <<'PY'
import json, sys
replies = [json.loads(line) for line in open(sys.argv[1], encoding='utf-8')]
assert len(replies) == 2 and [reply['id'] for reply in replies] == [1, 2], replies
assert replies[0].get('result', {}).get('protocolVersion'), replies[0]
assert replies[1].get('result', {}).get('isError') is True, replies[1]
assert 'EGRESS_INVALID_HOST' in json.dumps(replies[1]), replies[1]
PY
fi
docker exec "$container" dpkg -i /candidate.deb >&2
[[ $(docker exec "$container" dpkg-query -W -f='${Version}' outbound-guard-mcp) == "$expected_version" ]]
[[ $(docker exec "$container" sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1) == "$expected_binary" ]]
[[ $(docker exec "$container" /usr/bin/outbound-guard-mcp --version) == "outbound-guard-mcp $app_version" ]]
cert_env=()
if [[ -n ${OUTBOUND_GUARD_EXTRA_CA_CERT:-} ]]; then
  docker cp "$OUTBOUND_GUARD_EXTRA_CA_CERT" "$container:/tmp/fixture-ca.pem" >/dev/null
  cert_env=(--env OUTBOUND_GUARD_EXTRA_CA_CERT=/tmp/fixture-ca.pem)
fi
proxy_env=()
if [[ -n ${HTTP_PROXY:-} ]]; then
  [[ $HTTP_PROXY == http://127.0.0.1:3128 && ${http_proxy:-} == "$HTTP_PROXY" ]]
  [[ ${HTTPS_PROXY:-} == "$HTTP_PROXY" && ${https_proxy:-} == "$HTTP_PROXY" ]]
  [[ ${ALL_PROXY:-} == "$HTTP_PROXY" && ${all_proxy:-} == "$HTTP_PROXY" ]]
  [[ ${NO_PROXY+x} && -z $NO_PROXY && ${no_proxy+x} && -z $no_proxy ]]
  proxy_env=(--env "HTTP_PROXY=$HTTP_PROXY" --env "http_proxy=$http_proxy"
             --env "HTTPS_PROXY=$HTTPS_PROXY" --env "https_proxy=$https_proxy"
             --env "ALL_PROXY=$ALL_PROXY" --env "all_proxy=$all_proxy"
             --env NO_PROXY= --env no_proxy=)
  docker exec "${proxy_env[@]}" "$container" sh -ec '
    test "$HTTP_PROXY" = http://127.0.0.1:3128
    test "$http_proxy" = "$HTTP_PROXY" && test "$HTTPS_PROXY" = "$HTTP_PROXY"
    test "$https_proxy" = "$HTTP_PROXY" && test "$ALL_PROXY" = "$HTTP_PROXY"
    test "$all_proxy" = "$HTTP_PROXY"
    test "${NO_PROXY+x}" = x && test -z "$NO_PROXY"
    test "${no_proxy+x}" = x && test -z "$no_proxy"'
  printf 'verified\n' > "$state.proxy-verified"
fi
if [[ $sample_resources == 1 ]]; then
  docker cp __MONITOR_PATH__ "$container:/tmp/resource-monitor.sh" >/dev/null
  docker exec -d "$container" sh /tmp/resource-monitor.sh
fi
docker exec -i --env OUTBOUND_GUARD_ALLOWED_HOSTS="$OUTBOUND_GUARD_ALLOWED_HOSTS" \
  "${cert_env[@]}" "${proxy_env[@]}" \
  "$container" sh -ec '
    if [ -n "${HTTP_PROXY:-}" ]; then
      test "$HTTP_PROXY" = http://127.0.0.1:3128
      test "$http_proxy" = "$HTTP_PROXY" && test "$HTTPS_PROXY" = "$HTTP_PROXY"
      test "$https_proxy" = "$HTTP_PROXY" && test "$ALL_PROXY" = "$HTTP_PROXY"
      test "$all_proxy" = "$HTTP_PROXY"
      test "${NO_PROXY+x}" = x && test -z "$NO_PROXY"
      test "${no_proxy+x}" = x && test -z "$no_proxy"
      printf "proxy environment verified inside container\\n" >&2
    fi
    exec nsenter --net=/run/fixture-netns /usr/bin/outbound-guard-mcp'
'''

RESOURCE_MONITOR = r'''#!/bin/sh
max_fd=0
max_rss_kib=0
samples=0
while [ ! -e /tmp/resource-monitor.stop ]; do
  for pid in $(pidof outbound-guard-mcp 2>/dev/null); do
    [ -r "/proc/$pid/status" ] || continue
    fd=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    rss_kib=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null)
    [ -n "$rss_kib" ] || continue
    [ "$fd" -le "$max_fd" ] || max_fd=$fd
    [ "$rss_kib" -le "$max_rss_kib" ] || max_rss_kib=$rss_kib
    samples=$((samples + 1))
  done
  sleep 0.05
done
printf '%s %s %s\n' "$max_fd" "$max_rss_kib" "$samples" > /tmp/resource-monitor.summary
'''


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=("claude", "codex"))
    parser.add_argument("package", type=Path)
    parser.add_argument("package_sha256")
    parser.add_argument("skill_zip", type=Path)
    parser.add_argument("skill_sha256")
    parser.add_argument("--old-package", type=Path)
    parser.add_argument("--old-sha256")
    parser.add_argument("--fixture-mode", choices=("tls", "tls-active-proxy", "tls-handshake-packet", "tls-slow-http", "tls-slow-http-packet", "slow-http", "slow-http-packet", "connect-blackhole", "connect-blackhole-packet", "dns-answer-limit", "dns-answer-limit-packet", "malformed-http", "malformed-http-packet", "framing-http", "framing-http-packet", "framing-http-comma", "framing-http-coding", "framing-http-obs-fold", "redirect-encoded", "redirect-encoded-packet", "http-upgrade", "http-upgrade-headers", "http-interim-flood", "http-interim-repeat", "http-interim-slow", "http-interim-slow-packet", "html-quarantine", "queue-saturation", "dns-ssrf", "dns-ssrf-packet", "dns-truncated", "dns-truncated-packet", "dns-tcp-private", "dns-tcp-private-packet", "dns-tcp-mixed-v6", "dns-tcp-mixed-v6-packet", "dns-rebind", "dns-rebind-packet", "pinned-fallback-packet", "synthetic-exfil", "synthetic-exfil-packet", "synthetic-exfil-active-proxy", "argument-injection", "response-body-limit", "response-body-limit-packet", "response-header-limit", "response-header-limit-packet", "malformed-mcp-frame", "json-injection", "json-duplicate", "client-control-cancellation", "client-control-header-cancellation", "client-control-repeated-cancellation"), default="tls")
    parser.add_argument("--container-memory-mib", type=int, choices=(128, 256, 512), default=512,
                        help="Debian server container memory and swap limit (default: 512 MiB)")
    parser.add_argument("--sample-server-resources", action="store_true",
                        help="Sample server file descriptors and RSS during native calls")
    parser.add_argument("--cancel-cycles", type=int, choices=(2, 3), default=2,
                        help="Cycles for client-control-repeated-cancellation (default: 2)")
    args = parser.parse_args()
    package = args.package.resolve(strict=True)
    skill = args.skill_zip.resolve(strict=True)
    info = package_info(package, args.package_sha256)
    assert (args.old_package is None) == (args.old_sha256 is None), "old package and digest must be paired"
    old_package = args.old_package.resolve(strict=True) if args.old_package else None
    old_info = package_info(old_package, args.old_sha256) if old_package else None
    if old_info:
        assert old_info["revision"] != info["revision"], "upgrade requires distinct source revisions"
        subprocess.run(["dpkg", "--compare-versions", old_info["version"], "lt", info["version"]], check=True)
    timeout_seconds = int(os.environ.get("OUTBOUND_GUARD_NATIVE_TIMEOUT_SECONDS", "180"))
    assert 1 <= timeout_seconds <= 180, "native timeout outside supported range"
    assert len(args.skill_sha256) == 64 and sha256(skill) == args.skill_sha256, "skill ZIP digest mismatch"
    control = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(package)])
    listing = subprocess.check_output(["tar", "-tf", "-"], input=control, text=False).decode().splitlines()
    assert listing == ["./", "./control"], "unexpected package maintainer script"
    if old_package:
        old_control = subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(old_package)])
        old_listing = subprocess.check_output(["tar", "-tf", "-"], input=old_control).decode().splitlines()
        assert old_listing == ["./", "./control"], "unexpected old package maintainer script"
    image_id = subprocess.check_output(["docker", "image", "inspect", BUILDER_IMAGE, "--format", "{{.Id}}"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="outbound-debian-native-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        wrapper = root / "bridge.sh"
        monitor = root / "resource-monitor.sh"
        monitor.write_text(RESOURCE_MONITOR)
        state = root / "container"
        source = BRIDGE
        for old, new in (("__PACKAGE__", shlex.quote(str(package))),
                         ("__OLD_PACKAGE__", shlex.quote(str(old_package)) if old_package else "''"),
                         ("__STATE__", shlex.quote(str(state))),
                         ("__BINARY_SHA__", shlex.quote(info["binary_sha256"])),
                         ("__VERSION__", shlex.quote(info["version"])),
                         ("__OLD_BINARY_SHA__", shlex.quote(old_info["binary_sha256"]) if old_info else "''"),
                         ("__OLD_VERSION__", shlex.quote(old_info["version"]) if old_info else "''"),
                         ("__OLD_APP_VERSION__", shlex.quote(old_info["app_version"]) if old_info else "''"),
                         ("__APP_VERSION__", shlex.quote(info["app_version"])),
                         ("__MEMORY_MIB__", str(args.container_memory_mib)),
                         ("__SAMPLE_RESOURCES__", "1" if args.sample_server_resources else "0"),
                         ("__MONITOR_PATH__", shlex.quote(str(monitor))),
                         ("__IMAGE__", shlex.quote(BUILDER_IMAGE))):
            source = source.replace(old, new)
        wrapper.write_text(source)
        wrapper.chmod(0o700)
        env = os.environ.copy()
        for mode_name in ("OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE", "OUTBOUND_GUARD_CLIENT_TLS_SLOW", "OUTBOUND_GUARD_CLIENT_SLOW_HTTP", "OUTBOUND_GUARD_CLIENT_CONNECT_BLACKHOLE", "OUTBOUND_GUARD_CLIENT_DNS_ANSWER_LIMIT",
                          "OUTBOUND_GUARD_CLIENT_MALFORMED", "OUTBOUND_GUARD_CLIENT_FRAMING", "OUTBOUND_GUARD_CLIENT_TRAPS",
                          "OUTBOUND_GUARD_CLIENT_DNS_SSRF", "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED", "OUTBOUND_GUARD_CLIENT_PACKET_CAPTURE", "OUTBOUND_GUARD_CLIENT_REBIND", "OUTBOUND_GUARD_CLIENT_PINNED_FALLBACK",
                          "OUTBOUND_GUARD_CLIENT_EXFIL", "OUTBOUND_GUARD_CLIENT_ARGUMENT_INJECTION",
                          "OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT", "OUTBOUND_GUARD_CLIENT_HEADER_LIMIT",
                          "OUTBOUND_GUARD_CLIENT_FRAME_MUTATION", "OUTBOUND_GUARD_CLIENT_JSON_INJECTION",
                          "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE", "OUTBOUND_GUARD_CLIENT_HTML_QUARANTINE", "OUTBOUND_GUARD_CLIENT_QUEUE_SATURATION", "OUTBOUND_GUARD_CLIENT_ACTIVE_PROXY", "OUTBOUND_GUARD_CLIENT_CANCEL_PHASE",
                          "OUTBOUND_GUARD_CLIENT_CANCEL_CYCLES"):
            env.pop(mode_name, None)
        if args.fixture_mode in ("tls-active-proxy", "synthetic-exfil-active-proxy"):
            env["OUTBOUND_GUARD_CLIENT_ACTIVE_PROXY"] = "1"
        if args.fixture_mode in ("client-control-header-cancellation", "client-control-repeated-cancellation"):
            env["OUTBOUND_GUARD_CLIENT_CANCEL_PHASE"] = "headers"
        if args.fixture_mode == "client-control-repeated-cancellation":
            env["OUTBOUND_GUARD_CLIENT_CANCEL_CYCLES"] = str(args.cancel_cycles)
        if args.fixture_mode in ("dns-ssrf-packet", "dns-truncated-packet", "dns-tcp-private-packet", "dns-tcp-mixed-v6-packet", "dns-rebind-packet", "dns-answer-limit-packet", "pinned-fallback-packet", "synthetic-exfil-packet", "redirect-encoded-packet", "slow-http-packet", "connect-blackhole-packet", "tls-handshake-packet", "tls-slow-http-packet", "malformed-http-packet", "framing-http-packet", "response-body-limit-packet", "response-header-limit-packet", "http-interim-slow-packet"):
            env["OUTBOUND_GUARD_CLIENT_PACKET_CAPTURE"] = "1"
        mode_variable = {"tls": "OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE",
             "tls-active-proxy": "OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE",
             "tls-handshake-packet": "OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE",
             "tls-slow-http": "OUTBOUND_GUARD_CLIENT_TLS_SLOW",
             "tls-slow-http-packet": "OUTBOUND_GUARD_CLIENT_TLS_SLOW",
             "slow-http": "OUTBOUND_GUARD_CLIENT_SLOW_HTTP",
             "slow-http-packet": "OUTBOUND_GUARD_CLIENT_SLOW_HTTP",
             "connect-blackhole": "OUTBOUND_GUARD_CLIENT_CONNECT_BLACKHOLE",
             "connect-blackhole-packet": "OUTBOUND_GUARD_CLIENT_CONNECT_BLACKHOLE",
             "dns-answer-limit": "OUTBOUND_GUARD_CLIENT_DNS_ANSWER_LIMIT",
             "dns-answer-limit-packet": "OUTBOUND_GUARD_CLIENT_DNS_ANSWER_LIMIT",
             "malformed-http": "OUTBOUND_GUARD_CLIENT_MALFORMED",
             "malformed-http-packet": "OUTBOUND_GUARD_CLIENT_MALFORMED",
             "framing-http": "OUTBOUND_GUARD_CLIENT_FRAMING",
             "framing-http-packet": "OUTBOUND_GUARD_CLIENT_FRAMING",
             "framing-http-comma": "OUTBOUND_GUARD_CLIENT_FRAMING",
             "framing-http-coding": "OUTBOUND_GUARD_CLIENT_FRAMING",
             "framing-http-obs-fold": "OUTBOUND_GUARD_CLIENT_FRAMING",
             "redirect-encoded": "OUTBOUND_GUARD_CLIENT_TRAPS",
             "redirect-encoded-packet": "OUTBOUND_GUARD_CLIENT_TRAPS",
             "http-upgrade": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "http-upgrade-headers": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "http-interim-flood": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "http-interim-repeat": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "http-interim-slow": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "http-interim-slow-packet": "OUTBOUND_GUARD_CLIENT_HTTP_UPGRADE",
             "html-quarantine": "OUTBOUND_GUARD_CLIENT_HTML_QUARANTINE",
             "queue-saturation": "OUTBOUND_GUARD_CLIENT_QUEUE_SATURATION",
             "dns-ssrf": "OUTBOUND_GUARD_CLIENT_DNS_SSRF",
             "dns-ssrf-packet": "OUTBOUND_GUARD_CLIENT_DNS_SSRF",
             "dns-truncated": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-truncated-packet": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-tcp-private": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-tcp-private-packet": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-tcp-mixed-v6": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-tcp-mixed-v6-packet": "OUTBOUND_GUARD_CLIENT_DNS_TRUNCATED",
             "dns-rebind": "OUTBOUND_GUARD_CLIENT_REBIND",
             "dns-rebind-packet": "OUTBOUND_GUARD_CLIENT_REBIND",
             "pinned-fallback-packet": "OUTBOUND_GUARD_CLIENT_PINNED_FALLBACK",
             "synthetic-exfil": "OUTBOUND_GUARD_CLIENT_EXFIL",
             "synthetic-exfil-packet": "OUTBOUND_GUARD_CLIENT_EXFIL",
             "synthetic-exfil-active-proxy": "OUTBOUND_GUARD_CLIENT_EXFIL",
             "argument-injection": "OUTBOUND_GUARD_CLIENT_ARGUMENT_INJECTION",
             "response-body-limit": "OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT",
             "response-body-limit-packet": "OUTBOUND_GUARD_CLIENT_RESPONSE_LIMIT",
             "response-header-limit": "OUTBOUND_GUARD_CLIENT_HEADER_LIMIT",
             "response-header-limit-packet": "OUTBOUND_GUARD_CLIENT_HEADER_LIMIT",
             "malformed-mcp-frame": "OUTBOUND_GUARD_CLIENT_FRAME_MUTATION",
             "json-injection": "OUTBOUND_GUARD_CLIENT_JSON_INJECTION",
             "json-duplicate": "OUTBOUND_GUARD_CLIENT_JSON_INJECTION"}.get(args.fixture_mode)
        if mode_variable:
            env[mode_variable] = ("comma" if args.fixture_mode == "framing-http-comma" else
                                  "coding" if args.fixture_mode == "framing-http-coding" else
                                  "private" if args.fixture_mode in ("dns-tcp-private", "dns-tcp-private-packet") else
                                  "mixed-v6" if args.fixture_mode in ("dns-tcp-mixed-v6", "dns-tcp-mixed-v6-packet") else
                                  "obs-fold" if args.fixture_mode == "framing-http-obs-fold" else
                                  "duplicate" if args.fixture_mode == "json-duplicate" else
                                  "interim" if args.fixture_mode == "http-interim-flood" else "1")
            if args.fixture_mode == "http-upgrade-headers":
                env[mode_variable] = "headers"
            elif args.fixture_mode == "http-interim-repeat":
                env[mode_variable] = "interim-repeat"
            elif args.fixture_mode in ("http-interim-slow", "http-interim-slow-packet"):
                env[mode_variable] = "interim-slow"
        process = None
        success = False
        try:
            with (root / "harness.stdout").open("w+") as output:
                command = ["python3", str(Path(__file__).with_name("client_cancellation_probe.py")),
                           args.client, str(wrapper)]
                if args.fixture_mode not in ("client-control-cancellation", "client-control-header-cancellation", "client-control-repeated-cancellation"):
                    command.append(str(skill))
                process = subprocess.Popen(command, env=env, stdout=output,
                                           start_new_session=True)
                try:
                    returncode = process.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        namespace = f"outbound-client-cancel-{process.pid}"
                        pids = subprocess.run(["sudo", "-n", "ip", "netns", "pids", namespace],
                                              capture_output=True, text=True).stdout.split()
                        for pid in pids:
                            subprocess.run(["sudo", "-n", "kill", "-TERM", pid], check=False)
                        subprocess.run(["sudo", "-n", "ip", "netns", "delete", namespace], check=False)
                        subprocess.run(["sudo", "-n", "rm", "-rf", "--", "/etc/netns/" + namespace], check=False)
                        output.seek(0)
                        for line in output:
                            if line.startswith("ROOT="):
                                fixture_root = Path(line.removeprefix("ROOT=").strip())
                                if fixture_root.parent == Path("/tmp") and fixture_root.name.startswith("outbound-cancel-"):
                                    shutil.rmtree(fixture_root, ignore_errors=True)
                                break
                    raise RuntimeError("native client probe timed out; fixture cleanup attempted")
                output.seek(0)
                harness_output = output.read()
                print(harness_output, end="")
                if returncode:
                    raise subprocess.CalledProcessError(returncode, process.args)
                if args.fixture_mode in ("tls-active-proxy", "synthetic-exfil-active-proxy"):
                    assert (root / "container.proxy-verified").read_text() == "verified\n", \
                        "proxy variables were not verified inside the Debian container"
                control_result = None
                if args.fixture_mode in ("client-control-cancellation", "client-control-header-cancellation", "client-control-repeated-cancellation"):
                    control_result = json.loads(harness_output.splitlines()[-1])
                    assert control_result["cancel_phase"] == ("body" if args.fixture_mode == "client-control-cancellation" else "headers")
                    assert control_result["cancel_cycles"] == (args.cancel_cycles if args.fixture_mode == "client-control-repeated-cancellation" else 1)
                    assert control_result["live_client"] and control_result["client_control_acknowledged"]
                    assert control_result["socket_closed"] and control_result["recovery_allowed"]
                    if args.fixture_mode == "client-control-repeated-cancellation":
                        assert control_result["fetches"] == 2 * args.cancel_cycles + 2
                        assert control_result["fixture_paths"] == ["/cancel-silent-headers-long", "/plain"] * args.cancel_cycles + ["/head-ok"]
                        if args.client == "claude":
                            assert control_result["cancel_notifications"] == args.cancel_cycles
                            assert control_result["matching_wire_cancellation"]
                        else:
                            assert control_result["cancel_notifications"] == 0
                            assert control_result["rules"] == ["EGRESS_NETWORK_FAILURE", "EGRESS_ALLOWED"] * args.cancel_cycles + ["EGRESS_INVALID_HOST", "EGRESS_ALLOWED"]
                    if control_result["matching_wire_cancellation"]:
                        assert not control_result["cancelled_fetch_replied"]
                    else:
                        assert control_result["cancelled_fetch_replied"]
                        expected_rule = ("EGRESS_NETWORK_FAILURE" if args.fixture_mode != "client-control-cancellation"
                                         else "EGRESS_RESPONSE_TOO_SLOW")
                        assert control_result["rules"][0] == expected_rule
                        if args.fixture_mode != "client-control-cancellation":
                            assert all(elapsed < 8 for elapsed in control_result["socket_closed_after_each_seconds"])
            assert state.exists(), "Debian container was not started"
            if old_info:
                assert (root / "container.old-replies").exists(), "old package MCP smoke was not run"
            container = state.read_text().strip()
            assert container.startswith("outbound-native-"), "invalid container identity"
            server_resources = None
            if args.sample_server_resources:
                subprocess.run(["docker", "exec", container, "touch", "/tmp/resource-monitor.stop"], check=True)
                for _ in range(40):
                    sample = subprocess.run(["docker", "exec", container, "cat", "/tmp/resource-monitor.summary"],
                                            capture_output=True, text=True)
                    if sample.returncode == 0:
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("server resource monitor did not finish")
                max_fd, max_rss_kib, samples = map(int, sample.stdout.split())
                assert samples > 0 and max_fd > 0 and max_rss_kib > 0, sample.stdout
                if args.fixture_mode in ("slow-http", "slow-http-packet"):
                    assert max_fd > 3, "slow HTTP socket was not observed by resource sampler"
                server_resources = {"sample_interval_ms": 50, "samples": samples,
                                    "max_sampled_fd": max_fd, "max_sampled_rss_kib": max_rss_kib,
                                    "scope": "Finite sampled server observations; sampling can miss transient peaks."}
            cgroup = subprocess.check_output(
                ["docker", "exec", container, "sh", "-ec",
                 "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.peak /sys/fs/cgroup/pids.peak; "
                 "cat /sys/fs/cgroup/memory.events"], text=True).splitlines()
            memory_max, memory_peak, pids_peak = map(int, cgroup[:3])
            memory_events = dict(line.split() for line in cgroup[3:])
            memory_events = {key: int(value) for key, value in memory_events.items()}
            assert memory_max == args.container_memory_mib * 1024 * 1024
            assert 0 < memory_peak < memory_max, (memory_peak, memory_max)
            assert 0 < pids_peak <= 64, pids_peak
            assert memory_events["oom"] == 0 and memory_events["oom_kill"] == 0, memory_events
            subprocess.run(["docker", "exec", container, "sh", "-ec",
                            "pidof outbound-guard-mcp | xargs -r kill -TERM || true"], check=True)
            subprocess.run(["docker", "exec", container, "dpkg", "-r", "outbound-guard-mcp"],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["docker", "exec", container, "sh", "-ec",
                            "test ! -e /usr/bin/outbound-guard-mcp; "
                            "test ! -d /usr/share/doc/outbound-guard-mcp; "
                            "test ! -e /etc/outbound-guard-mcp; "
                            "! dpkg-query -W outbound-guard-mcp >/dev/null 2>&1"], check=True)
            success = True
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if state.exists():
                container = state.read_text().strip()
                if re.fullmatch(r"outbound-native-\d+", container):
                    for attempt in range(10):
                        subprocess.run(["docker", "stop", "-t", "1", container],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        present = subprocess.run(["docker", "container", "inspect", container],
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                        if not present and attempt >= (1 if success else 4):
                            break
                        time.sleep(0.5)
                    else:
                        raise RuntimeError("owned Debian probe container remained after cleanup")
    cancellation_checks = (["client_interrupt_acknowledged",
                            "matching_mcp_cancel_and_socket_close" if control_result["matching_wire_cancellation"]
                            else "missing_mcp_cancel_server_timeout_and_socket_close",
                            *(["repeated_same_process_cancel_recovery_cycles"] if control_result["cancel_cycles"] > 1 else [])]
                           if control_result else [])
    print(json.dumps({"result": "passed", "client": args.client,
                      "platform": "Debian 12 amd64 container joined to route-free fixture namespace",
                      "container_resource_observation": {
                          "memory_limit_mib": args.container_memory_mib,
                          "memory_peak_bytes": memory_peak, "pids_peak": pids_peak,
                          "memory_events": memory_events,
                          "scope": "Container cgroup high-water marks include setup and helper processes; not server-only RSS or FD peaks."},
                      "server_resource_observation": server_resources,
                      "proxy_environment_verified_in_container": args.fixture_mode in ("tls-active-proxy", "synthetic-exfil-active-proxy"),
                      "client_control_result": control_result,
                      "image_id": image_id, "package": info, "old_package": old_info,
                      "skill_zip_sha256": args.skill_sha256, "fixture_mode": args.fixture_mode,
                      "checks": ["checksum", "clean_dpkg_install", "package_upgrade" if old_info else "no_upgrade",
                                 *(["old_package_launch_and_loopback_denial"] if old_info else []),
                                 "native_client_control_and_guarded_calls" if control_result else "native_skill_and_guarded_calls",
                                 *(cancellation_checks if control_result else {"tls": ["tls_hostname_denial", "private_dns_flip_denial"],
                                    "tls-handshake-packet": ["tls_hostname_denial", "private_dns_flip_denial", "wrong_host_sni_capture", "no_tls_fallback_capture", "fixture_namespace_tcp_syn_capture"],
                                    "slow-http": ["slow_drip_denial", "delayed_first_byte_denial"],
                                    "connect-blackhole": ["dropped_syn_connect_denial", "shared_connect_deadline_no_fallback", "approved_recovery_after_timeout"],
                                    "connect-blackhole-packet": ["dropped_syn_connect_denial", "shared_connect_deadline_no_fallback", "approved_recovery_after_timeout", "fixture_namespace_no_fallback_capture"],
                                    "dns-answer-limit": ["twenty_public_dns_answers_denied_before_http", "approved_recovery_after_dns_denial"],
                                    "dns-answer-limit-packet": ["twenty_public_dns_answers_denied_before_http", "approved_recovery_after_dns_denial", "no_extra_tcp_connection_capture"],
                                    "tls-slow-http": ["trusted_tls_handshake", "tls_sni_preserved", "tls_slow_drip_denial", "tls_delayed_first_byte_denial"],
                                    "tls-slow-http-packet": ["trusted_tls_handshake", "tls_sni_preserved", "tls_slow_drip_denial", "tls_delayed_first_byte_denial", "tls_client_hello_capture", "timed_out_tcp_streams_closed", "fixture_namespace_tcp_syn_capture"],
                                    "slow-http-packet": ["slow_drip_denial", "delayed_first_byte_denial",
                                                         "timed_out_tcp_streams_closed", "fixture_namespace_tcp_syn_capture"],
                                    "malformed-http": ["bad_chunk_size_denial", "truncated_chunk_denial"],
                                    "malformed-http-packet": ["bad_chunk_size_denial", "truncated_chunk_denial",
                                                              "fixture_namespace_tcp_syn_capture"],
                                    "framing-http": ["conflicting_length_transfer_denial", "duplicate_length_denial", "stacked_transfer_denial", "duplicate_transfer_denial"],
                                    "framing-http-packet": ["conflicting_length_transfer_denial", "duplicate_length_denial", "stacked_transfer_denial", "duplicate_transfer_denial", "fixture_namespace_tcp_syn_capture"],
                                    "framing-http-comma": ["equal_comma_length_denial", "conflicting_comma_length_denial", "repeated_chunked_coding_denial"],
                                    "framing-http-coding": ["seeded_stacked_coding_denial", "seeded_parameterized_coding_denial", "seeded_unknown_coding_denial"],
                                    "framing-http-obs-fold": ["folded_length_denial", "folded_encoding_denial", "folded_connection_denial", "folded_extension_denial", "no_denied_body_text"],
                                    "redirect-encoded": ["loopback_denial", "redirect_denial", "encoded_response_denial"],
                                    "redirect-encoded-packet": ["loopback_denial", "redirect_denial", "encoded_response_denial",
                                                                "fixture_namespace_tcp_syn_capture"],
                                    "http-upgrade": ["http_101_upgrade_denial"],
                                    "http-upgrade-headers": ["http_101_upgrade_denial", "http_200_upgrade_header_denial", "http_200_connection_upgrade_denial"],
                                    "http-interim-flood": ["aggregate_103_wire_budget_denial"],
                                    "http-interim-repeat": ["four_sequential_103_wire_budget_denials", "approved_recovery_after_repeated_denial"],
                                    "http-interim-slow": ["small_103_slow_drip_total_deadline_denial", "approved_recovery_after_timeout"],
                                    "http-interim-slow-packet": ["small_103_slow_drip_total_deadline_denial", "approved_recovery_after_timeout", "timed_out_tcp_stream_closed", "fixture_namespace_tcp_syn_capture"],
                                    "html-quarantine": ["mislabeled_hidden_html_denial", "mislabeled_root_html_denial", "mislabeled_formfeed_html_denial", "ordinary_angle_text_allowed"],
                                    "queue-saturation": ["bridge_injected_busy_denial", "priority_cancellation_and_socket_close", "native_client_guarded_recovery"],
                                    "dns-truncated": ["truncated_udp_dns_denial", "approved_recovery_after_dns_failure"],
                                    "dns-truncated-packet": ["truncated_udp_dns_denial", "approved_recovery_after_dns_failure", "fixture_namespace_tcp_syn_capture"],
                                    "dns-tcp-private": ["truncated_udp_private_tcp_dns_denial", "approved_recovery_after_forbidden_address"],
                                    "dns-tcp-private-packet": ["truncated_udp_private_tcp_dns_denial", "approved_recovery_after_forbidden_address", "fixture_namespace_tcp_syn_capture"],
                                    "dns-tcp-mixed-v6": ["truncated_udp_mixed_v6_tcp_dns_denial", "approved_recovery_after_forbidden_address"],
                                    "dns-tcp-mixed-v6-packet": ["truncated_udp_mixed_v6_tcp_dns_denial", "approved_recovery_after_forbidden_address", "fixture_namespace_tcp_syn_capture"],
                                    "dns-ssrf": ["loopback_denial", "private_dns_denial", "alias_private_denial",
                                                 "mixed_dns_denial", "metadata_dns_denial", "resolver_failure_denial"],
                                    "dns-ssrf-packet": ["loopback_denial", "private_dns_denial", "alias_private_denial",
                                                        "mixed_dns_denial", "metadata_dns_denial", "resolver_failure_denial",
                                                        "fixture_namespace_tcp_syn_capture"],
                                    "tls-active-proxy": ["tls_hostname_denial", "private_dns_flip_denial", "active_proxy_positive_control_only"],
                                    "dns-rebind": ["first_public_answer_allowed", "second_private_answer_denied"],
                                    "dns-rebind-packet": ["first_public_answer_allowed", "second_private_answer_denied", "fixture_namespace_tcp_syn_capture"],
                                    "pinned-fallback-packet": ["first_validated_address_refused", "second_pinned_address_allowed", "no_dns_retry", "fixture_namespace_tcp_syn_capture"],
                                    "synthetic-exfil": ["loopback_denial", "secret_path_denial",
                                                        "unicode_lookalike_denial", "no_exfil_dns_or_marker_echo"],
                                    "synthetic-exfil-packet": ["loopback_denial", "secret_path_denial",
                                                               "unicode_lookalike_denial", "no_exfil_dns_or_marker_echo",
                                                               "fixture_namespace_tcp_syn_capture"],
                                    "synthetic-exfil-active-proxy": ["loopback_denial", "secret_path_denial",
                                                                     "unicode_lookalike_denial", "no_exfil_dns_or_marker_echo",
                                                                     "active_proxy_positive_control_only"],
                                    "argument-injection": ["synthetic_header_denial", "synthetic_body_denial",
                                                           "no_marker_echo_or_denied_http_hit"],
                                    "response-body-limit": ["fixed_length_body_denial", "chunked_body_denial",
                                                            "no_denied_body_text"],
                                    "response-body-limit-packet": ["fixed_length_body_denial", "chunked_body_denial",
                                                                   "no_denied_body_text", "fixture_namespace_tcp_syn_capture"],
                                    "response-header-limit": ["excess_header_count_denial", "oversized_header_denial",
                                                              "parser_header_limit_denial", "no_denied_body_text"],
                                    "response-header-limit-packet": ["excess_header_count_denial", "oversized_header_denial",
                                                                     "parser_header_limit_denial", "no_denied_body_text",
                                                                     "fixture_namespace_tcp_syn_capture"],
                                    "malformed-mcp-frame": ["malformed_frame_parse_error", "no_forbidden_dns_or_http"],
                                    "json-injection": ["instruction_response_denial", "no_instruction_echo"],
                                    "json-duplicate": ["duplicate_key_json_denial", "no_instruction_echo"]}
                                   [args.fixture_mode]),
                                 "approved_recovery",
                                 "package_remove", "residue"]}, sort_keys=True))


if __name__ == "__main__":
    main()
