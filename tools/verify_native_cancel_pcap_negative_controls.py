#!/usr/bin/env python3
"""Require cancellation packet oracle to reject a valid-digest late close."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_native_cancel_pcap import rows, verify
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-three-cancellation-pcap-2026-11-10.json"


def main() -> None:
    record = json.loads(EVIDENCE.read_text())["runs"]["claude"]
    data = (ROOT / record["capture"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record["pcap_sha256"]
    with tempfile.TemporaryDirectory(prefix="outbound-cancel-close-negative-") as directory:
        capture = Path(directory) / "mutant.pcap"
        capture.write_bytes(data)
        close_frames = {int(number) for number, in rows(
            capture, "tcp.stream == 0 && tcp.dstport == 80 && "
                     "(tcp.flags.fin == 1 || tcp.flags.reset == 1)", "frame.number")}
        assert close_frames
        changed = late_close(data, close_frames)
        capture.write_bytes(changed)
        try:
            verify(capture, hashlib.sha256(changed).hexdigest(), "claude")
        except AssertionError as error:
            assert "claude" in str(error), error
        else:
            raise AssertionError("late close passed native cancellation packet oracle")
    print("late native cancellation close rejected with recomputed digest")


if __name__ == "__main__":
    main()
