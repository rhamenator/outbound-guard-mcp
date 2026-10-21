#!/usr/bin/env python3
"""Build and verify local Linux x86_64 candidate artifacts; never publish a release."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile


REPO = Path(__file__).resolve().parent.parent
INPUTS = ["Cargo.toml", "Cargo.lock", "src", "tests", "README.md", "LICENSE", "SECURITY.md",
          "skills", "tools", "docs", "rust-toolchain.toml"]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installed_smoke(binary, version):
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "candidate-install", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "guarded_fetch", "arguments": {"url": "http://127.0.0.1/"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {
            "uri": "outbound-guard://logs/audit.json"}},
    ]
    env = {key: value for key, value in os.environ.items() if not key.startswith("OUTBOUND_GUARD_")}
    result = subprocess.run([str(binary)], input="".join(json.dumps(m) + "\n" for m in messages),
                            text=True, capture_output=True, env=env, timeout=15, check=True,
                            cwd=binary.parent)
    assert not result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert [reply["id"] for reply in replies] == [1, 2, 3, 4]
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert replies[0]["result"]["serverInfo"] == {"name": "outbound-guard-mcp", "version": version}
    assert [tool["name"] for tool in replies[1]["result"]["tools"]] == ["guarded_fetch"]
    decision = replies[2]["result"]["structuredContent"]
    assert decision["rule"] == "EGRESS_INVALID_HOST" and replies[2]["result"]["isError"] is True
    audit = json.loads(replies[3]["result"]["contents"][0]["text"])
    assert audit["events"] == [{key: decision[key] for key in ("correlation_id", "status", "rule")}]
    subprocess.run([sys.executable, str(REPO / "tools/adversarial_stdio_probe.py"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=30)
    subprocess.run(["bash", str(REPO / "tools/netns_adversarial_probe.sh"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=180)
    subprocess.run([sys.executable, str(REPO / "tools/inspector_smoke.py"), str(binary)],
                   cwd=binary.parent, env=env, check=True, timeout=180)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("this candidate gate currently supports Linux x86_64 only")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *INPUTS], cwd=REPO, check=True)
    revision = git("rev-parse", "HEAD").decode().strip()
    epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
    version = tomllib.loads(git("show", f"{revision}:Cargo.toml").decode())["package"]["version"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = git("archive", "--format=tar.gz", "--prefix=source/", revision, "--",
        "Cargo.toml", "Cargo.lock", "src", "tests", "rust-toolchain.toml", "LICENSE", "README.md",
        "SECURITY.md", "tools", "docs", "skills")
    # Build from the committed snapshot, excluding untracked build.rs or Cargo config.
    with tempfile.TemporaryDirectory(prefix="outbound-guard-source-") as folder:
        with tarfile.open(fileobj=io.BytesIO(source)) as tar:
            for entry in tar:
                parts = PurePosixPath(entry.name).parts
                assert parts and parts[0] == "source" and ".." not in parts
                destination = Path(folder).joinpath(*parts)
                if entry.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    assert entry.isfile(), "source snapshot must contain only files and directories"
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(tar.extractfile(entry).read())
                    destination.chmod(entry.mode & 0o777)
        subprocess.run(["nice", "-n", "10", "cargo", "build", "--release", "--locked", "-j", "2",
                        "--target", "x86_64-unknown-linux-gnu", "--target-dir", str(REPO / "target")],
                       cwd=Path(folder) / "source", check=True)
        binary = (REPO / "target/x86_64-unknown-linux-gnu/release/outbound-guard-mcp").read_bytes()
    root = f"outbound-guard-mcp-{version}-candidate.{revision[:12]}-linux-x86_64"
    files = {"bin/outbound-guard-mcp": binary}
    files.update({name: git("show", f"{revision}:{name}") for name in ("README.md", "LICENSE", "SECURITY.md")})
    files["source.tar.gz"] = source
    files["provenance.json"] = (json.dumps({"revision": revision, "version": version,
        "candidate": True, "stable_release": False, "platform": "linux-x86_64",
        "license": "GPL-3.0-or-later", "binary_sha256": digest(binary)}, sort_keys=True) + "\n").encode()
    archive = output / (root + ".tar.gz")
    with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as tar:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(root + "/" + name)
                entry.size, entry.mtime = len(data), epoch
                entry.mode = 0o755 if name.startswith("bin/") else 0o644
                tar.addfile(entry, io.BytesIO(data))
    skill = git("show", f"{revision}:skills/outbound-guard/SKILL.md")
    frontmatter = skill.decode().split("---", 2)[1]
    assert "\nname: outbound-guard\n" in frontmatter and "\ndescription:" in frontmatter
    assert b"/home/rich/" not in skill and b"experimental" in skill.lower()
    skill_zip = output / f"outbound-guard-skill-{revision[:12]}.zip"
    with zipfile.ZipFile(skill_zip, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in (("SKILL.md", skill), ("LICENSE", files["LICENSE"])):
            entry = zipfile.ZipInfo("outbound-guard/" + name, (1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            zipped.writestr(entry, data)
    checksums = {path.name: digest(path.read_bytes()) for path in (archive, skill_zip)}
    (output / "SHA256SUMS").write_text("".join(f"{sha}  {name}\n" for name, sha in checksums.items()))
    with zipfile.ZipFile(skill_zip) as zipped:
        assert zipped.namelist() == ["outbound-guard/SKILL.md", "outbound-guard/LICENSE"]
        assert zipped.testzip() is None
    # Extract only the known executable, never arbitrary archive paths or links.
    with tempfile.TemporaryDirectory(prefix="outbound-guard-install-") as folder:
        installed = Path(folder) / "outbound-guard-mcp"
        with tarfile.open(archive) as tar:
            assert sorted(tar.getnames()) == sorted(root + "/" + name for name in files)
            member = tar.getmember(root + "/bin/outbound-guard-mcp")
            assert member.isfile() and member.mode == 0o755
            installed.write_bytes(tar.extractfile(member).read())
        assert digest(installed.read_bytes()) == digest(binary)
        installed.chmod(0o755)
        installed_smoke(installed, version)
    for name, sha in checksums.items():
        assert digest((output / name).read_bytes()) == sha
    print(f"candidate verified: {archive.name}; skill ZIP has SKILL.md and GPL license; checksums, installed MCP/Inspector, and hostile fixtures passed")


if __name__ == "__main__":
    main()
