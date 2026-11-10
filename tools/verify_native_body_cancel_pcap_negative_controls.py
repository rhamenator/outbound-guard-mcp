#!/usr/bin/env python3
"""Recomputed capture digests cannot conceal a late close or forbidden socket."""

import hashlib
import json
from pathlib import Path
import struct
import tempfile

from verify_native_body_cancel_pcap import verify
from verify_native_cancel_pcap import rows
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-body-cancellation-pcap-2026-11-10.json"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def forbidden_syn(data: bytes) -> bytes:
    """Retarget one valid fixture SYN to the metadata address, fixing checksums."""
    assert data[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack_from("<I", data, 20)[0] == 276
    changed = bytearray(data)
    offset = 24
    mutated = False
    while offset < len(changed):
        _, _, captured, original = struct.unpack_from("<IIII", changed, offset)
        assert captured == original
        start, end = offset + 16, offset + 16 + captured
        frame = changed[start:end]
        ip = 20  # Linux SLL2 link header
        if (frame[ip] >> 4 == 4 and frame[ip + 9] == 6
                and frame[ip + 16:ip + 20] == b"\x0b\x00\x00\x01"):
            ihl = (frame[ip] & 15) * 4
            tcp = ip + ihl
            if frame[tcp + 13] & 0x12 == 0x02:
                frame[ip + 16:ip + 20] = b"\xa9\xfe\xa9\xfe"
                frame[ip + 10:ip + 12] = b"\0\0"
                frame[ip + 10:ip + 12] = checksum(frame[ip:tcp]).to_bytes(2, "big")
                segment = frame[tcp:]
                segment[16:18] = b"\0\0"
                pseudo = (frame[ip + 12:ip + 20] + b"\0\x06"
                          + len(segment).to_bytes(2, "big"))
                segment[16:18] = checksum(pseudo + segment).to_bytes(2, "big")
                assert checksum(frame[ip:tcp]) == 0
                assert checksum(pseudo + segment) == 0
                frame[tcp:] = segment
                changed[start:end] = frame
                mutated = True
                break
        offset = end
    assert mutated, "fixture SYN missing"
    return bytes(changed)


def main() -> None:
    run = json.loads(EVIDENCE.read_text())["runs"]["claude"]
    data = (ROOT / run["capture"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == run["pcap_sha256"]
    with tempfile.TemporaryDirectory(prefix="outbound-body-close-negative-") as directory:
        capture = Path(directory) / "mutant.pcap"
        capture.write_bytes(data)
        frames = {int(number) for number, in rows(
            capture, "tcp.stream == 0 && tcp.dstport == 80 && "
                     "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.number")}
        assert frames
        mutant = late_close(data, frames)
        capture.write_bytes(mutant)
        try:
            verify(capture, hashlib.sha256(mutant).hexdigest(), "claude")
        except AssertionError as error:
            assert "claude" in str(error), error
        else:
            raise AssertionError("late body-phase close passed packet oracle")
        changed = forbidden_syn(data)
        capture.write_bytes(changed)
        try:
            verify(capture, hashlib.sha256(changed).hexdigest(), "claude")
        except AssertionError as error:
            assert "169.254.169.254" in str(error), error
        else:
            raise AssertionError("metadata-address SYN passed packet oracle")
    print("late close and metadata-address SYN rejected with recomputed digests")


if __name__ == "__main__":
    main()
