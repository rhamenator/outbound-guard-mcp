#!/usr/bin/env bash
# Replay native guarded calls from a checksum-verified .deb staged in a private root.
set -euo pipefail

if (( $# != 5 )) || [[ "$1" != claude && "$1" != codex ]]; then
  echo "usage: $0 claude|codex DEB DEB_SHA256 SKILL_ZIP SKILL_SHA256" >&2
  exit 2
fi
client=$1
deb=$(realpath -- "$2")
deb_hash=$3
skill=$(realpath -- "$4")
skill_hash=$5
[[ $deb_hash =~ ^[0-9a-f]{64}$ && $skill_hash =~ ^[0-9a-f]{64}$ ]]
[[ $(sha256sum -- "$deb" | cut -d' ' -f1) == "$deb_hash" ]]
[[ $(sha256sum -- "$skill" | cut -d' ' -f1) == "$skill_hash" ]]
[[ $(dpkg-deb --field "$deb" Package) == outbound-guard-mcp ]]
[[ $(dpkg-deb --field "$deb" Architecture) == amd64 ]]
[[ $(dpkg-deb --ctrl-tarfile "$deb" | tar -tf -) == $'./\n./control' ]]

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
stage=$(mktemp -d -t outbound-deb-native-XXXXXXXX)
cleanup() { sudo -n rm -rf -- "$stage"; }
trap cleanup EXIT

# This stages only the package in an alternate dpkg database. Runtime libraries
# come from the host; the separate Debian 12 container gate tests dependencies.
sudo -n dpkg --root="$stage" --force-depends -i "$deb" >/dev/null
binary="$stage/usr/bin/outbound-guard-mcp"
test -x "$binary"
[[ $(sudo -n dpkg-query --admindir="$stage/var/lib/dpkg" -W -f='${Status}' outbound-guard-mcp) == 'install ok installed' ]]
payload_hash=$(dpkg-deb --fsys-tarfile "$deb" | tar -xOf - ./usr/bin/outbound-guard-mcp | sha256sum | cut -d' ' -f1)
[[ $(sha256sum "$binary" | cut -d' ' -f1) == "$payload_hash" ]]

OUTBOUND_GUARD_CLIENT_TLS_HANDSHAKE=1 OUTBOUND_GUARD_CLIENT_ACTIVE_PROXY=1 \
  python3 "$script_dir/client_cancellation_probe.py" "$client" "$binary" "$skill"

sudo -n dpkg --root="$stage" --force-depends -r outbound-guard-mcp >/dev/null
test ! -e "$binary"
test ! -d "$stage/usr/share/doc/outbound-guard-mcp"
test ! -e "$stage/etc/outbound-guard-mcp"
if sudo -n dpkg-query --admindir="$stage/var/lib/dpkg" -W outbound-guard-mcp >/dev/null 2>&1; then
  echo 'package residue in alternate dpkg database' >&2
  exit 1
fi
echo "staged package replay: $client install, native guarded calls, removal and residue checks passed"
