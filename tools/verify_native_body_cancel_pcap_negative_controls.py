#!/usr/bin/env python3
"""A recomputed capture digest cannot conceal a late body-phase socket close."""

import hashlib
import json
from pathlib import Path
import tempfile

from verify_native_body_cancel_pcap import verify
from verify_native_cancel_pcap import rows
from verify_native_slow_close_negative_controls import late_close


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs/evidence/native-body-cancellation-pcap-2026-11-10.json"


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
    print("late native body-phase close rejected with recomputed digest")


if __name__ == "__main__":
    main()
