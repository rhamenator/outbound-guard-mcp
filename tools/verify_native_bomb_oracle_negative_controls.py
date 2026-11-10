#!/usr/bin/env python3
"""Prove the retained bomb wire oracle rejects altered content and destinations."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools/verify_native_compressed_bomb_pcap.py"


def off_fixture_syn(source: bytes) -> bytes:
    data = bytearray(source)
    assert struct.unpack_from("<IHHIIII", data, 0) == (
        0xA1B2C3D4, 2, 4, 0, 0, 262144, 276), "unexpected pcap format"
    offset = 24
    while offset + 16 <= len(data):
        _, _, captured, original = struct.unpack_from("<IIII", data, offset)
        start = offset + 16
        frame = data[start:start + captured]
        assert len(frame) == captured and original >= captured
        # Linux cooked v2 (20 bytes), then IPv4 and TCP. No packet is sent.
        if (len(frame) >= 60 and frame[20] >> 4 == 4 and frame[29] == 6):
            ip_header_length = (frame[20] & 15) * 4
            tcp = 20 + ip_header_length
            if len(frame) >= tcp + 20 and frame[tcp + 13] & 2 and not frame[tcp + 13] & 16:
                assert frame[36:40] == b"\x0b\x00\x00\x01", "source SYN is not fixture-bound"
                data[start + 36:start + 40] = bytes((169, 254, 169, 254))
                return bytes(data)
        offset = start + captured
    raise AssertionError("no fixture TCP SYN to mutate")


def corrupt_gzip(source: bytes) -> bytes:
    marker = b"\x1f\x8b\x08"
    assert source.count(marker) == 1, "expected one captured gzip stream"
    data = bytearray(source)
    data[data.index(marker) + 2] = 9  # Invalid gzip compression method.
    return bytes(data)


def rejection(path: Path, digest: str, expected_error: str) -> None:
    completed = subprocess.run(
        ["python3", str(VERIFIER), str(path), digest], capture_output=True,
        text=True, timeout=25, check=False)
    assert completed.returncode != 0 and expected_error in completed.stderr, (
        path.name, completed.returncode, completed.stderr[-400:])


def main() -> None:
    results = []
    with tempfile.TemporaryDirectory(prefix="outbound-bomb-oracle-negative-") as temporary:
        directory = Path(temporary)
        for client in ("claude", "codex"):
            evidence = json.loads((ROOT / "docs/evidence" /
                                   f"native-{client}-bombs-http-pcap-2026-11-10.json").read_text())
            capture = (ROOT / evidence["pcap_path"]).resolve(strict=True)
            assert capture.is_relative_to(ROOT / "tests/fixtures/packet-capture")
            source = capture.read_bytes()
            assert hashlib.sha256(source).hexdigest() == evidence["pcap_sha256"]
            rejection(capture, "0" * 64, "capture SHA-256 mismatch")
            for name, mutant, error in (
                ("off_fixture_syn", off_fixture_syn(source), "169.254.169.254"),
                ("corrupt_gzip", corrupt_gzip(source), "unknown compression method"),
            ):
                altered = directory / f"{client}-{name}.pcap"
                altered.write_bytes(mutant)
                assert altered.read_bytes() != source
                # Supply the altered digest so the wire oracle, not the hash gate,
                # must reject this mutation.
                rejection(altered, hashlib.sha256(mutant).hexdigest(), error)
            results.append({"client": client,
                            "rejected": ["wrong_digest", "off_fixture_syn", "corrupt_gzip"]})
    print(json.dumps({"negative_controls": results}, sort_keys=True))


if __name__ == "__main__":
    main()
