#!/usr/bin/env python3
"""Verify a retained libFuzzer corpus archive against its campaign report."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


def verify(archive_path: Path, report_path: Path, max_member_bytes: int) -> dict:
    assert 1 <= max_member_bytes <= 262144, "unsupported corpus member limit"
    report = json.loads(report_path.read_text())
    expected = report["corpus"]
    assert isinstance(expected, dict) and expected, "empty corpus report"
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in expected.values())
    found = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        assert members and members[0].name == "corpus" and members[0].isdir()
        for member in members[1:]:
            assert member.isfile() and member.name.startswith("corpus/"), member.name
            name = member.name.removeprefix("corpus/")
            assert name and "/" not in name and name not in found, member.name
            assert member.size <= max_member_bytes, member.name
            stream = archive.extractfile(member)
            assert stream is not None
            found[name] = hashlib.sha256(stream.read()).hexdigest()
    assert found == expected, "archive corpus and report differ"
    return {"verified_files": len(found),
            "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--max-member-bytes", type=int, required=True,
                        help="Target's documented maximum input size")
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.report, args.max_member_bytes), sort_keys=True))


if __name__ == "__main__":
    main()
