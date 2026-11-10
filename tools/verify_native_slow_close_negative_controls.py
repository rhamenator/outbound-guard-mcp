#!/usr/bin/env python3
"""Require the slow-close oracle to reject a valid-digest late socket close."""

import hashlib
from pathlib import Path
import struct
import tempfile

from verify_native_slow_http_pcap import rows, verify


ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "tests/fixtures/packet-capture/native-codex-slow-upgrade-2026-11-07.pcap"
DIGEST = "24fcd70d536665781ce85633e17cf944094a827891757822965b2c87be6fbc19"


def late_close(data: bytes, frames: set[int]) -> bytes:
    assert data[:4] == b"\xd4\xc3\xb2\xa1"  # little-endian classic pcap
    changed = bytearray(data)
    offset = 24
    frame = 0
    while offset < len(changed):
        frame += 1
        seconds, _, captured, _ = struct.unpack_from("<IIII", changed, offset)
        if frame in frames:
            struct.pack_into("<I", changed, offset, seconds + 6)
        offset += 16 + captured
    assert offset == len(changed) and frame >= max(frames)
    return bytes(changed)


def main() -> None:
    data = CAPTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    with tempfile.TemporaryDirectory(prefix="outbound-slow-close-negative-") as directory:
        capture = Path(directory) / "mutant.pcap"
        capture.write_bytes(data)
        close_frames = {int(number) for number, in rows(
            capture, "tcp.stream == 1 && tcp.dstport == 80 && "
                     "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.number")}
        assert len(close_frames) >= 1, close_frames
        changed = late_close(data, close_frames)
        capture.write_bytes(changed)
        try:
            verify(capture, hashlib.sha256(changed).hexdigest())
        except AssertionError as error:
            assert "'/drip'" in str(error), error
        else:
            raise AssertionError("late client close passed the packet oracle")
    print("late client close rejected with recomputed capture digest")


if __name__ == "__main__":
    main()
