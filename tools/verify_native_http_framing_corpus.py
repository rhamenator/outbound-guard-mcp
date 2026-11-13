#!/usr/bin/env python3
"""Recheck retained native hostile-HTTP captures against evidence and wire oracles."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
CASES = (
    ("claude", "malformed", "tools/verify_native_malformed_http_pcap.py", "2026-11-07", ()),
    ("codex", "malformed", "tools/verify_native_malformed_http_pcap.py", "2026-11-07", ()),
    ("claude", "framing", "tools/verify_native_framing_http_pcap.py", "2026-11-07", ()),
    ("codex", "framing", "tools/verify_native_framing_http_pcap.py", "2026-11-07", ()),
    ("claude", "comma", "tools/verify_native_framing_http_pcap.py", "2026-11-09", ("--mode", "comma")),
    ("codex", "comma", "tools/verify_native_framing_http_pcap.py", "2026-11-09", ("--mode", "comma")),
    ("claude", "coding", "tools/verify_native_framing_http_pcap.py", "2026-11-09", ("--mode", "coding")),
    ("codex", "coding", "tools/verify_native_framing_http_pcap.py", "2026-11-09", ("--mode", "coding")),
    ("claude", "obs-fold", "tools/verify_native_framing_http_pcap.py", "2026-11-10", ("--mode", "obs-fold")),
    ("codex", "obs-fold", "tools/verify_native_framing_http_pcap.py", "2026-11-10", ("--mode", "obs-fold")),
    ("claude", "version", "tools/verify_native_framing_http_pcap.py", "2026-11-11", ("--mode", "version")),
    ("codex", "version", "tools/verify_native_framing_http_pcap.py", "2026-11-11", ("--mode", "version")),
    ("claude", "bombs", "tools/verify_native_compressed_bomb_pcap.py", "2026-11-10", ()),
    ("codex", "bombs", "tools/verify_native_compressed_bomb_pcap.py", "2026-11-10", ()),
)


def main() -> None:
    results = []
    seen = set()
    for client, kind, verifier, date, options in CASES:
        filename = (f"native-{client}-{kind}-http-pcap-{date}.json" if kind in ("comma", "coding", "obs-fold", "version", "bombs") else
                    f"native-{client}-{kind}-http-upgrade-pcap-{date}.json")
        document = json.loads((ROOT / "docs/evidence" / filename).read_text())
        assert document["result"] == "passed", filename
        assert client in document["client"].lower(), filename
        relative = Path(document["pcap_path"])
        capture = (ROOT / relative).resolve(strict=True)
        assert capture.is_relative_to(CAPTURE_ROOT), relative
        assert capture not in seen, capture
        seen.add(capture)
        digest = document["pcap_sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
        checked = json.loads(subprocess.check_output(
            ["python3", str(ROOT / verifier), str(capture), digest, *options],
            text=True, timeout=25))
        recorded = document["packet_verifier"]
        assert checked == recorded, (filename, "packet oracle differs from evidence")
        if kind == "obs-fold":
            # A corrected digest must not make a forbidden connection acceptable.
            with tempfile.TemporaryDirectory(prefix="outbound-obs-fold-negative-") as directory:
                mutant = forbidden_syn(capture.read_bytes())
                changed = Path(directory) / "forbidden-syn.pcap"
                changed.write_bytes(mutant)
                rejected = subprocess.run(
                    ["python3", str(ROOT / verifier), str(changed),
                     hashlib.sha256(mutant).hexdigest(), *options],
                    text=True, capture_output=True, timeout=25)
                assert rejected.returncode != 0 and "169.254.169.254" in rejected.stderr, (
                    filename, rejected.returncode, rejected.stderr[-500:])
        results.append({"evidence": filename, "client": client, "kind": kind,
                        "capture": str(relative), "sha256": digest})
    assert len(results) == len(CASES)
    print(json.dumps({"verified_captures": results, "count": len(results)}, sort_keys=True))


if __name__ == "__main__":
    main()
