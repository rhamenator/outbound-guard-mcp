#!/usr/bin/env python3
"""Recheck retained native DNS captures against their evidence digests and wire oracle."""

import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = (
    ("native-client-dns-truncated-pcap-2026-11-08.json", "refused"),
    ("native-client-dns-tcp-private-pcap-2026-11-08.json", "private-answer"),
    ("native-client-dns-tcp-mixed-v6-pcap-2026-11-08.json", "mixed-v6"),
    ("native-client-dns-tcp-mixed-v6-upgrade-2026-11-08.json", "mixed-v6"),
    ("native-client-dns-tcp-mixed-v6-binary-upgrade-2026-11-08.json", "mixed-v6"),
)


def main() -> None:
    results = []
    seen = set()
    for filename, scenario in EVIDENCE:
        document = json.loads((ROOT / "docs/evidence" / filename).read_text())
        assert set(document["runs"]) == {"claude", "codex"}, filename
        for client in ("claude", "codex"):
            run = document["runs"][client]
            relative = Path(run["capture_path"])
            capture = (ROOT / relative).resolve(strict=True)
            assert capture.is_relative_to(CAPTURE_ROOT), relative
            assert capture not in seen, capture
            seen.add(capture)
            digest = run["capture_sha256"]
            assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
            checked = json.loads(subprocess.check_output(
                ["python3", str(ROOT / "tools/verify_native_dns_truncated_pcap.py"),
                 str(capture), digest, "--scenario", scenario], text=True, timeout=25))
            assert checked["sha256"] == digest and checked["scenario"] == scenario
            results.append({"evidence": filename, "client": client,
                            "capture": str(relative), "sha256": digest, "scenario": scenario})
    assert len(results) == 2 * len(EVIDENCE)
    print(json.dumps({"verified_captures": results, "count": len(results)}, sort_keys=True))


if __name__ == "__main__":
    main()
