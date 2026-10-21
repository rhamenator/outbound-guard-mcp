#!/usr/bin/env python3
"""Compare independent candidate builds offline; never execute or extract their files."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


LIMIT = 64 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def members(data):
    """Bound decompression and reject duplicate paths, links and special files."""
    result, total, root = {}, 0, None
    with tarfile.open(fileobj=io.BytesIO(data), mode='r|*') as archive:
        for index, entry in enumerate(archive):
            if index >= 4096:
                raise ValueError('archive member limit')
            parts = PurePosixPath(entry.name).parts
            if not parts or entry.name.startswith('/') or '..' in parts:
                raise ValueError('unsafe archive path')
            root = root or parts[0]
            if parts[0] != root:
                raise ValueError('multiple archive roots')
            if entry.isdir():
                continue
            if not entry.isfile() or len(parts) < 2:
                raise ValueError('unsupported archive member')
            name = '/'.join(parts[1:])
            total += entry.size
            if name in result or entry.size < 0 or total > LIMIT:
                raise ValueError('duplicate member or archive size limit')
            result[name] = archive.extractfile(entry).read()
    return result


def inspect(path):
    if path.stat().st_size > LIMIT:
        raise ValueError('candidate size limit')
    data = path.read_bytes()
    files = members(data)
    provenance = json.loads(files['provenance.json'])
    build = provenance['build']
    source = members(files['source.tar.gz'])
    if (provenance['binary_sha256'] != digest(files['bin/outbound-guard-mcp']) or
            build['source_archive_sha256'] != digest(files['source.tar.gz']) or
            build['cargo_lock_sha256'] != digest(source['Cargo.lock'])):
        raise ValueError('candidate content does not match provenance')
    # Normalize archive headers/root/revision differences, retaining every source byte.
    manifest = {name: digest(value) for name, value in sorted(source.items())}
    return {
        'archive_sha256': digest(data), 'revision': provenance['revision'],
        'source_files_sha256': digest(json.dumps(manifest, sort_keys=True).encode()),
        'binary_sha256': provenance['binary_sha256'],
        'settings': {key: build[key] for key in (
            'target', 'profile', 'locked', 'jobs', 'toolchain_channel',
            'rustc_verbose_version', 'cargo_version', 'cargo_lock_sha256')},
        'package': {key: provenance[key] for key in (
            'version', 'platform', 'license', 'candidate', 'stable_release')},
    }


def compare(left, right):
    fields = ('source_files_sha256', 'settings', 'package', 'binary_sha256')
    differences = [field for field in fields if left[field] != right[field]]
    return {'matching': not differences, 'differences': differences,
            'left': left, 'right': right,
            'limits': 'Byte comparison only; no signature, publisher identity, independent-host attestation or release approval.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    args = parser.parse_args()
    try:
        report = compare(inspect(args.left), inspect(args.right))
    except (ValueError, KeyError, TypeError, OSError, EOFError, tarfile.TarError):
        print(json.dumps({'matching': False, 'error': 'Invalid candidate archive or provenance'}))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report['matching'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
