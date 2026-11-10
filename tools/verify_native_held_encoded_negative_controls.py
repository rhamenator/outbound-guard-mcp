#!/usr/bin/env python3
"""Ensure the held-response packet verifier rejects integrity and wire mutations."""

import hashlib
from pathlib import Path
import tempfile

from verify_native_held_encoded_pcap import verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "tests/fixtures/packet-capture/native-claude-held-encoded-2026-11-10.pcap"
DIGEST = "44ba9cc9a0fa6150b9cef5131e539c3349d82e66590d5a11b274741b2706cedf"


def denied(path: Path, digest: str) -> None:
    try:
        verify(path, digest)
    except AssertionError:
        return
    raise AssertionError("altered held-response capture passed")


def main() -> None:
    data = CAPTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    with tempfile.TemporaryDirectory(prefix="outbound-held-oracle-") as directory:
        path = Path(directory) / "mutant.pcap"
        path.write_bytes(data)
        denied(path, "0" * 64)
        assert data.count(b"\x1f\x8b\x08") == 1
        changed = data.replace(b"\x1f\x8b\x08", b"\x1f\x8b\x09", 1)
        path.write_bytes(changed)
        denied(path, hashlib.sha256(changed).hexdigest())
    print("held-response digest and semantic mutation rejected")


if __name__ == "__main__":
    main()
