#!/usr/bin/env python3
"""Prove the TLS close oracle rejects a late close with a recomputed digest."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_native_slow_close_negative_controls import late_close
from verify_native_tls_slow_pcap import rows, verify


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-tls-slow-close-oracle-2026-11-10.json"


def main() -> None:
    record = json.loads(EVIDENCE.read_text())["clients"]["codex"]
    data = (ROOT / record["capture"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record["sha256"]
    with tempfile.TemporaryDirectory(prefix="outbound-tls-slow-negative-") as directory:
        capture = Path(directory) / "mutant.pcap"
        capture.write_bytes(data)
        close_frames = {int(number) for number, in rows(
            capture, "tcp.stream == 1 && tcp.dstport == 443 && "
                     "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.number")}
        assert close_frames, close_frames
        changed = late_close(data, close_frames)
        capture.write_bytes(changed)
        try:
            verify(capture, hashlib.sha256(changed).hexdigest())
        except AssertionError as error:
            assert "'/drip'" in str(error), error
        else:
            raise AssertionError("late TLS client close passed the packet oracle")
    print("late TLS client close rejected with recomputed capture digest")


if __name__ == "__main__":
    main()
