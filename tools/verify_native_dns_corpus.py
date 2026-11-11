#!/usr/bin/env python3
"""Recheck retained native DNS captures against their evidence digests and wire oracle."""

import json
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

from verify_native_body_cancel_pcap_negative_controls import forbidden_syn


ROOT = Path(__file__).resolve().parent.parent
CAPTURE_ROOT = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = (
    ("native-client-dns-truncated-pcap-2026-11-08.json", "refused"),
    ("native-client-dns-tcp-private-pcap-2026-11-08.json", "private-answer"),
    ("native-client-dns-tcp-mixed-v6-pcap-2026-11-08.json", "mixed-v6"),
    ("native-client-dns-tcp-mixed-v6-upgrade-2026-11-08.json", "mixed-v6"),
    ("native-client-dns-tcp-mixed-v6-binary-upgrade-2026-11-08.json", "mixed-v6"),
    ("native-current-mixed-v6-2026-11-11.json", "mixed-v6"),
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
            if filename == "native-current-mixed-v6-2026-11-11.json":
                assert document["source_base"] == "0456105251691f2a11892f5bef65ef5b4592eb38"
                assert document["trusted_main_package_ci_run"] == 42990714476
                assert run["client_version"] == ("2.1.319 (Claude Code)" if client == "claude"
                                                 else "codex-cli 0.151.0")
                assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_FORBIDDEN_ADDRESS", "EGRESS_ALLOWED"]
                assert run["fixture_hits"] == ["/plain", "/plain"]
                assert run["native_skill_loaded"] is True
                assert (run["native_skill_invoked"] is True or
                        run["explicit_skill_input_accepted"] is True)
                assert run["checks"] == ["checksum", "clean_dpkg_install", "no_upgrade",
                    "native_skill_and_guarded_calls", "truncated_udp_mixed_v6_tcp_dns_denial",
                    "approved_recovery_after_forbidden_address", "fixture_namespace_tcp_syn_capture",
                    "approved_recovery", "package_remove", "residue"]
                assert checked == run["independent_packet_verification"]
                assert checked["truncated_dns_query_types"] == ["1", "28"]
                assert checked["tcp_dns_answers"] == [["1", "11.0.0.1", "", "1", "False"],
                                                     ["28", "", "::1", "1", "False"]]
                assert checked["tcp_syn_destinations"] == ["11.0.0.1:80", "127.0.0.1:53",
                                                           "11.0.0.1:80"]
                assert run["package"]["revision"] == document["source_base"]
                assert run["package"]["package_sha256"] == document["package_sha256"]
                assert run["package"]["binary_sha256"] == "5fc99be48e904bc3cb26f9595627ed1183ea6bcd0f1524918fab79f8a2c4b95d"
                assert run["skill_zip_sha256"] == document["skill_zip_sha256"]
                manifest = ROOT / document["ci_sha256sums_path"]
                assert hashlib.sha256(manifest.read_bytes()).hexdigest() == document["ci_sha256sums_sha256"]
                lines = manifest.read_text().splitlines()
                assert f'{document["package_sha256"]}  {document["package_name"]}' in lines
                assert f'{document["skill_zip_sha256"]}  {document["skill_name"]}' in lines
                container = run["container_resource_observation"]
                assert container["memory_limit_mib"] == 128
                assert container["memory_peak_bytes"] < 128 * 1024 * 1024
                assert 0 < container["pids_peak"] <= 64
                assert container["memory_events"]["oom"] == container["memory_events"]["oom_kill"] == 0
                server = run["server_resource_observation"]
                assert server["sample_interval_ms"] == 50 and server["samples"] > 0
                assert 0 < server["max_sampled_fd"] <= 64
                for source, source_digest in document["harness_sha256"].items():
                    historical = subprocess.check_output(
                        ["git", "show", f'{document["source_base"]}:{source}'], cwd=ROOT, timeout=10)
                    assert hashlib.sha256(historical).hexdigest() == source_digest
                mutant = forbidden_syn(capture.read_bytes())
                with tempfile.TemporaryDirectory(prefix="outbound-mixed-v6-mutant-") as directory:
                    path = Path(directory) / "metadata-syn.pcap"
                    path.write_bytes(mutant)
                    rejected = subprocess.run(["python3", str(ROOT / "tools/verify_native_dns_truncated_pcap.py"),
                        str(path), hashlib.sha256(mutant).hexdigest(), "--scenario", "mixed-v6"],
                        capture_output=True, text=True, timeout=25)
                    assert rejected.returncode != 0 and "169.254.169.254" in rejected.stderr
            results.append({"evidence": filename, "client": client,
                            "capture": str(relative), "sha256": digest, "scenario": scenario})
    assert len(results) == 2 * len(EVIDENCE)
    print(json.dumps({"verified_captures": results, "count": len(results)}, sort_keys=True))


if __name__ == "__main__":
    main()
