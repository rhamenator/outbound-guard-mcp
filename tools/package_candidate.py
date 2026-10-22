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
INPUTS = ["Cargo.toml", "Cargo.lock", "src", "tests", "examples", "README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md",
          "skills", "tools", "docs", "rust-toolchain.toml"]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def installed_smoke(binary, version, cancellation_probe):
    subprocess.run([sys.executable, str(REPO / "tools/cli_smoke.py"), str(binary), version],
                   cwd=binary.parent, check=True, timeout=60)
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
    subprocess.run([sys.executable, str(REPO / "tools/stdio_resource_probe.py"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=50)
    subprocess.run([sys.executable, str(REPO / "tools/modern_stdio_probe.py"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=30)
    subprocess.run([sys.executable, str(REPO / "tools/protocol_id_probe.py"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=30)
    subprocess.run([sys.executable, str(REPO / "tools/stdio_mutation_probe.py"), str(binary)],
                   cwd=REPO, env=env, check=True, timeout=70)
    probe_env = env.copy()
    if "OUTBOUND_GUARD_TEST_SDK_DIR" in os.environ:
        probe_env["OUTBOUND_GUARD_TEST_SDK_DIR"] = os.environ["OUTBOUND_GUARD_TEST_SDK_DIR"]
    subprocess.run(["bash", str(REPO / "tools/netns_adversarial_probe.sh"), str(binary), str(cancellation_probe)],
                   cwd=REPO, env=probe_env, check=True, timeout=180)
    subprocess.run([sys.executable, str(REPO / "tools/inspector_smoke.py"), str(binary)],
                   cwd=binary.parent, env=env, check=True, timeout=180)


def dependency_files(source_root):
    """Inventory resolved normal/build crates, with their shipped notices."""
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", "x86_64-unknown-linux-gnu"], cwd=source_root))
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    packages = {package["id"]: package for package in metadata["packages"]}
    root = metadata["resolve"]["root"]
    selected, pending = set(), [root]
    while pending:
        id_ = pending.pop()
        if id_ in selected:
            continue
        selected.add(id_)
        pending.extend(dep["pkg"] for dep in nodes[id_]["deps"]
                       if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
    lock = tomllib.loads((source_root / "Cargo.lock").read_text())
    locked = {(item["name"], item["version"], item.get("source")): item
              for item in lock["package"]}
    files, inventory = {}, []
    for id_ in sorted(selected - {root}, key=lambda id_: (packages[id_]["name"], packages[id_]["version"])):
        package = packages[id_]
        name, version, source = (package[key] for key in ("name", "version", "source"))
        assert source == "registry+https://github.com/rust-lang/crates.io-index", "review non-registry dependency"
        checksum = locked[(name, version, source)]["checksum"]
        crate = Path(package["manifest_path"]).parent.resolve()
        cached = crate.parents[2] / "cache" / crate.parent.name / f"{name}-{version}.crate"
        with cached.open("rb") as downloaded:
            assert hashlib.file_digest(downloaded, "sha256").hexdigest() == checksum, "registry archive checksum mismatch"
        notices = {path for path in crate.iterdir()
                   if path.name.lower().startswith(("license", "copying", "notice")) and path.is_file()}
        if package.get("license_file"):
            notices.add(Path(package["license_file"]))
        names = []
        for path in sorted(notices):
            assert not path.is_symlink() and path.resolve().is_relative_to(crate), "unsafe notice path"
            assert path.is_file() and path.stat().st_size <= 1024 * 1024, "unbounded notice file"
            relative = path.relative_to(crate).as_posix()
            data = path.read_bytes()
            with tarfile.open(cached) as downloaded:
                member = downloaded.getmember(f"{name}-{version}/{relative}")
                assert member.isfile() and member.size == len(data), "notice archive entry mismatch"
                assert downloaded.extractfile(member).read() == data, "notice content differs from locked archive"
            destination = f"third-party/{name}-{version}/{relative}"
            files[destination] = data
            names.append(destination)
        assert names and package.get("license"), f"review missing license metadata/notices for {name}"
        inventory.append({"name": name, "version": version, "source": source,
                          "checksum_sha256": checksum, "license_expression": package["license"],
                          "features": sorted(nodes[id_]["features"]), "notice_files": names})
    files["dependency-inventory.json"] = (json.dumps({"schema_version": 1,
        "target": "x86_64-unknown-linux-gnu", "scope": "resolved normal and build dependencies",
        "packages": inventory}, indent=2, sort_keys=True) + "\n").encode()
    print(f"dependency inventory: {len(inventory)} locked crates with checksum-verified shipped notices")
    return files


def reject_build_overrides(environ):
    """Fail before running tools; report names, never sensitive override values."""
    explicit = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTDOC",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP",
                "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTFLAGS",
                "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"}
    blocked = sorted(key for key, value in environ.items() if value and (
        key in explicit or key.startswith("CARGO_PROFILE_") or
        (key.startswith("CARGO_TARGET_") and key.endswith(("_LINKER", "_RUNNER", "_RUSTFLAGS")))))
    if blocked:
        raise RuntimeError("Candidate build rejects compiler overrides: " + ", ".join(blocked))


def build_evidence(source_root, source):
    return {"target": "x86_64-unknown-linux-gnu", "profile": "release", "locked": True,
            "jobs": 2, "toolchain_channel": tomllib.loads((source_root / "rust-toolchain.toml").read_text())["toolchain"]["channel"],
            "rustc_verbose_version": subprocess.check_output(["rustc", "-vV"], cwd=source_root).decode().strip(),
            "cargo_version": subprocess.check_output(["cargo", "--version"], cwd=source_root).decode().strip(),
            "cargo_lock_sha256": digest((source_root / "Cargo.lock").read_bytes()),
            "source_archive_sha256": digest(source),
            "environment_policy": "reject explicit compiler/wrapper/profile/target-linker overrides; not hermetic"}


def verify_build_compiler(evidence):
    """Do not package a compiler selected by an overriding rustup environment."""
    channel = evidence['toolchain_channel']
    if (len(channel.split('.')) != 3 or not all(part.isdigit() for part in channel.split('.')) or
            f'release: {channel}' not in evidence['rustc_verbose_version'].splitlines() or
            not evidence['cargo_version'].startswith(f'cargo {channel} ')):
        raise RuntimeError('Candidate compiler/Cargo must match the exact version in rust-toolchain.toml')


PATH_REMAPPING = {"source": "/build/source", "cargo_home": "/build/cargo", "target": "/build/target"}
BUILDER_IMAGE = "docker.io/library/rust@sha256:8c8b26057f8ba46c755d934453b7abc40e88b1cd51d654a6d15c115564793edd"


def container_command(source_root, target_dir, cache_dir, uid, gid, compiler):
    """No caller environment, credentials, Docker socket or home in the builder."""
    return ['docker', 'run', '--rm', '--platform', 'linux/amd64',
            '--user', f'{uid}:{gid}', '--cpus', '2', '--memory', '4g', '--memory-swap', '4g',
            '--pids-limit', '256', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
            '--mount', f'type=bind,source={source_root},target=/build/source,readonly',
            '--mount', f'type=bind,source={target_dir},target=/build/target',
            '--mount', f'type=bind,source={cache_dir},target=/build/cargo',
            '--workdir', '/build/source', '--env', 'CARGO_HOME=/build/cargo',
            '--env', 'RUSTUP_HOME=/usr/local/rustup', '--env', 'CARGO_BUILD_JOBS=2',
            '--env', f'RUSTUP_TOOLCHAIN={compiler}-x86_64-unknown-linux-gnu',
            '--env', 'LC_ALL=C', '--env', 'TZ=UTC',
            '--env', f'EXPECTED_RUST_VERSION={compiler}',
            '--env', 'CARGO_ENCODED_RUSTFLAGS=' + '\x1f'.join(
                f'--remap-path-prefix={path}={path}' for path in PATH_REMAPPING.values()),
            BUILDER_IMAGE, 'sh', '-ec',
            'rustc -vV > /build/target/rustc-version.txt\n'
            'cargo --version > /build/target/cargo-version.txt\n'
            'grep -Fqx "release: $EXPECTED_RUST_VERSION" /build/target/rustc-version.txt\n'
            'case "$(cat /build/target/cargo-version.txt)" in "cargo $EXPECTED_RUST_VERSION "*) ;; *) exit 1 ;; esac\n'
            'cc --version > /build/target/cc-version.txt\n'
            'ldd --version > /build/target/libc-version.txt\n'
            'exec nice -n 10 cargo build --release --locked --bins --examples -j 2 '
            '--target x86_64-unknown-linux-gnu --target-dir /build/target']


def candidate_build_env(source_root, target_dir, environ):
    """Only internally chosen path flags; encoded arguments also support spaces."""
    reject_build_overrides(environ)
    cargo_home = Path(environ.get('CARGO_HOME') or Path.home() / '.cargo').expanduser()
    if not cargo_home.is_absolute():
        cargo_home = source_root / cargo_home
    paths = {'source': source_root, 'cargo_home': cargo_home, 'target': target_dir}
    result = dict(environ)
    result['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(
        f'--remap-path-prefix={path.resolve()}={PATH_REMAPPING[name]}' for name, path in paths.items())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument('--container-build', action='store_true', help='build in the digest-pinned Linux amd64 native builder (requires Docker)')
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("this candidate gate currently supports Linux x86_64 only")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *INPUTS], cwd=REPO, check=True)
    revision = git("rev-parse", "HEAD").decode().strip()
    epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
    version = tomllib.loads(git("show", f"{revision}:Cargo.toml").decode())["package"]["version"]
    reject_build_overrides(os.environ)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = git("archive", "--format=tar.gz", "--prefix=source/", revision, "--",
        "Cargo.toml", "Cargo.lock", "src", "tests", "examples", "rust-toolchain.toml", "LICENSE", "README.md", "CHANGELOG.md",
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
        source_root = Path(folder) / 'source'
        evidence = build_evidence(source_root, source)
        evidence['path_remapping'] = PATH_REMAPPING
        target_dir = REPO / 'target'
        if args.container_build:
            target_dir = REPO / 'target/candidate-container'
            cache_dir = REPO / 'target/candidate-container-cargo'
            for directory in (target_dir, cache_dir):
                directory.mkdir(parents=True, exist_ok=True)
            # The temporary export must be traversable by a rootless/remapped builder.
            Path(folder).chmod(0o755)
            subprocess.run(container_command(source_root, target_dir, cache_dir, os.getuid(), os.getgid(),
                                             evidence['toolchain_channel']), check=True)
            evidence.update(rustc_verbose_version=(target_dir / 'rustc-version.txt').read_text().strip(),
                            cargo_version=(target_dir / 'cargo-version.txt').read_text().strip())
            evidence['native_builder'] = {'image': BUILDER_IMAGE, 'platform': 'linux/amd64',
                'cc_version': (target_dir / 'cc-version.txt').read_text().splitlines()[0],
                'libc_version': (target_dir / 'libc-version.txt').read_text().splitlines()[0]}
            verify_build_compiler(evidence)
        else:
            verify_build_compiler(evidence)
            build_env = candidate_build_env(source_root, target_dir, os.environ)
            subprocess.run(["nice", "-n", "10", "cargo", "build", "--release", "--locked", "--bins", "--examples", "-j", "2",
                            "--target", "x86_64-unknown-linux-gnu", "--target-dir", str(target_dir)],
                           cwd=source_root, env=build_env, check=True)
        binary = (target_dir / "x86_64-unknown-linux-gnu/release/outbound-guard-mcp").read_bytes()
        cancellation_probe = target_dir / "x86_64-unknown-linux-gnu/release/examples/cancel_fetch_probe"
        dependencies = dependency_files(Path(folder) / "source")
    root = f"outbound-guard-mcp-{version}-candidate.{revision[:12]}-linux-x86_64"
    files = {"bin/outbound-guard-mcp": binary, **dependencies}
    files.update({name: git("show", f"{revision}:{name}") for name in ("README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md")})
    files["source.tar.gz"] = source
    files["provenance.json"] = (json.dumps({"revision": revision, "version": version,
        "candidate": True, "stable_release": False, "platform": "linux-x86_64",
        "license": "GPL-3.0-or-later", "binary_sha256": digest(binary), "build": evidence}, sort_keys=True) + "\n").encode()
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
            for name, data in dependencies.items():
                entry = tar.getmember(root + "/" + name)
                assert entry.isfile() and tar.extractfile(entry).read() == data, "dependency asset changed in package"
        assert digest(installed.read_bytes()) == digest(binary)
        installed.chmod(0o755)
        installed_smoke(installed, version, cancellation_probe)
    for name, sha in checksums.items():
        assert digest((output / name).read_bytes()) == sha
    print(f"candidate verified: {archive.name}; skill ZIP has SKILL.md and GPL license; checksums, installed MCP/Inspector, and hostile fixtures passed")


if __name__ == "__main__":
    main()
