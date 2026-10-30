#!/usr/bin/env python3
"""Run a native client against an installed Debian 12 package in a route-free fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import shutil

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
printf '%s\n' "$container" > "$state"
old_mount=()
if [[ -n $old_package ]]; then old_mount=(--mount "type=bind,src=$old_package,dst=/old.deb,readonly"); fi
docker run -d --rm --pull never --network none --dns 127.0.0.1 \
  --cap-add SYS_ADMIN --security-opt no-new-privileges \
  --memory 512m --memory-swap 512m --pids-limit 64 --cpus 1 \
  --mount "type=bind,src=/run/netns/$namespace,dst=/run/fixture-netns,readonly" \
  --mount "type=bind,src=$package,dst=/candidate.deb,readonly" \
  "${old_mount[@]}" \
  --name "$container" __IMAGE__ sleep infinity >/dev/null
docker exec "$container" sh -ec 'grep -q '\''^VERSION_ID="12"$'\'' /etc/os-release; test "$(dpkg --print-architecture)" = amd64'
if [[ -n $old_package ]]; then
  docker exec "$container" dpkg -i /old.deb >&2
  [[ $(docker exec "$container" dpkg-query -W -f='${Version}' outbound-guard-mcp) == "$old_version" ]]
  [[ $(docker exec "$container" sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1) == "$old_binary" ]]
fi
docker exec "$container" dpkg -i /candidate.deb >&2
[[ $(docker exec "$container" dpkg-query -W -f='${Version}' outbound-guard-mcp) == "$expected_version" ]]
[[ $(docker exec "$container" sha256sum /usr/bin/outbound-guard-mcp | cut -d' ' -f1) == "$expected_binary" ]]
docker cp "$OUTBOUND_GUARD_EXTRA_CA_CERT" "$container:/tmp/fixture-ca.pem" >/dev/null
docker exec -i --env OUTBOUND_GUARD_ALLOWED_HOSTS="$OUTBOUND_GUARD_ALLOWED_HOSTS" \
  --env OUTBOUND_GUARD_EXTRA_CA_CERT=/tmp/fixture-ca.pem \
  "$container" nsenter --net=/run/fixture-netns /usr/bin/outbound-guard-mcp
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
        state = root / "container"
        source = BRIDGE
        for old, new in (("__PACKAGE__", shlex.quote(str(package))),
                         ("__OLD_PACKAGE__", shlex.quote(str(old_package)) if old_package else "''"),
                         ("__STATE__", shlex.quote(str(state))),
                         ("__BINARY_SHA__", shlex.quote(info["binary_sha256"])),
                         ("__VERSION__", shlex.quote(info["version"])),
                         ("__OLD_BINARY_SHA__", shlex.quote(old_info["binary_sha256"]) if old_info else "''"),
                         ("__OLD_VERSION__", shlex.quote(old_info["version"]) if old_info else "''"),
                         ("__IMAGE__", shlex.quote(BUILDER_IMAGE))):
            source = source.replace(old, new)
        wrapper.write_text(source)
        wrapper.chmod(0o700)
        env = os.environ.copy()
        env["OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE"] = "1"
        try:
            with (root / "harness.stdout").open("w+") as output:
                process = subprocess.Popen(["python3", str(Path(__file__).with_name("client_cancellation_probe.py")),
                                            args.client, str(wrapper), str(skill)], env=env, stdout=output)
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
                print(output.read(), end="")
                if returncode:
                    raise subprocess.CalledProcessError(returncode, process.args)
            assert state.exists(), "Debian container was not started"
            container = state.read_text().strip()
            assert container.startswith("outbound-native-"), "invalid container identity"
            subprocess.run(["docker", "exec", container, "sh", "-ec",
                            "pidof outbound-guard-mcp | xargs -r kill -TERM || true"], check=True)
            subprocess.run(["docker", "exec", container, "dpkg", "-r", "outbound-guard-mcp"],
                           check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["docker", "exec", container, "sh", "-ec",
                            "test ! -e /usr/bin/outbound-guard-mcp; "
                            "test ! -d /usr/share/doc/outbound-guard-mcp; "
                            "test ! -e /etc/outbound-guard-mcp; "
                            "! dpkg-query -W outbound-guard-mcp >/dev/null 2>&1"], check=True)
        finally:
            if state.exists():
                container = state.read_text().strip()
                if container.startswith("outbound-native-"):
                    subprocess.run(["docker", "stop", "-t", "1", container],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(json.dumps({"result": "passed", "client": args.client,
                      "platform": "Debian 12 amd64 container joined to route-free fixture namespace",
                      "image_id": image_id, "package": info, "old_package": old_info,
                      "skill_zip_sha256": args.skill_sha256,
                      "checks": ["checksum", "clean_dpkg_install", "package_upgrade" if old_info else "no_upgrade",
                                 "native_skill_and_guarded_calls",
                                 "tls_hostname_denial", "private_dns_flip_denial", "approved_recovery",
                                 "package_remove", "residue"]}, sort_keys=True))


if __name__ == "__main__":
    main()
