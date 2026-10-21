#!/usr/bin/env bash
# Rootless host policy remains unchanged; sudo is confined to a disposable netns.
set -euo pipefail
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
binary=${1:-"$repo_dir/target/debug/outbound-guard-mcp"}
cancel_probe=${2:-"$(dirname "$binary")/examples/cancel_fetch_probe"}
ns="outbound-guard-probe-$$"
cleanup() {
  sudo -n ip netns delete "$ns" 2>/dev/null || true
  sudo -n rm -rf -- "/etc/netns/$ns"
}
trap cleanup EXIT
sudo -n ip netns add "$ns"
sudo -n ip -n "$ns" link set lo up
sudo -n ip -n "$ns" address add 11.0.0.1/32 dev lo
sudo -n install -d -m 755 "/etc/netns/$ns"
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' | sudo -n tee "/etc/netns/$ns/resolv.conf" >/dev/null
sudo -n ip netns exec "$ns" python3 "$repo_dir/tools/netns_adversarial_probe.py" "$(realpath "$binary")" "$(realpath "$cancel_probe")"
