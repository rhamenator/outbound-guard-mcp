#!/usr/bin/env python3
"""Recheck retained native-client forged DNS transaction-ID captures."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "tests/fixtures/packet-capture"
EVIDENCE = (
    ROOT / "docs/evidence/native-dns-spoof-id-2026-11-09.json",
    ROOT / "docs/evidence/native-dns-spoof-id-upgrade-2026-11-09.json",
)


def rows(path, display_filter, *fields):
    command = ["tshark", "-n", "-r", str(path), "-Y", display_filter,
               "-T", "fields", "-E", "separator=;"]
    for field in fields:
        command.extend(("-e", field))
    return [line.split(";") for line in subprocess.check_output(
        command, text=True, timeout=15).splitlines()]


def verify(path, digest):
    data = path.read_bytes()
    assert 24 < len(data) <= 1024 * 1024
    assert hashlib.sha256(data).hexdigest() == digest
    dns = rows(path, 'dns.qry.name == "spoof-id.test" && udp.port == 53',
               "dns.id", "dns.flags.response", "dns.qry.type", "dns.a", "dns.aaaa")
    queries = {(int(id_, 0), qtype) for id_, response, qtype, _, _ in dns
               if response == "False"}
    forged = {(int(id_, 0), qtype) for id_, response, qtype, _, _ in dns
              if response == "True"}
    assert {qtype for _, qtype in queries} == {"1", "28"}, dns
    assert forged == {((id_ + 1) & 0xffff, qtype) for id_, qtype in queries}, dns
    assert not queries & forged, dns
    assert all((address, v6) == ("127.0.0.1", "") if qtype == "1"
               else (address, v6) == ("", "::1")
               for _, response, qtype, address, v6 in dns if response == "True"), dns
    syns = rows(path, "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.dst", "tcp.dstport")
    assert syns == [["11.0.0.1", "80"]] * 2, syns
    requests = rows(path, "http.request", "http.host", "http.request.uri")
    assert requests == [["allowed.test", "/plain"]] * 2, requests
    dns_destinations = rows(path, "dns.flags.response == 0 && udp.dstport == 53",
                            "ip.dst", "udp.dstport")
    assert dns_destinations and set(map(tuple, dns_destinations)) == {("127.0.0.1", "53")}
    destinations = rows(path, "ip || ipv6", "ip.dst", "ipv6.dst")
    addresses = {address for ipv4, ipv6 in destinations
                 for address in (ipv4 or ipv6).split(",") if address}
    assert addresses and addresses <= {"11.0.0.1", "127.0.0.1"}
    return {"sha256": digest, "question_types": sorted({qtype for _, qtype in queries}),
            "forged_response_count": len(forged), "approved_http_requests": len(requests),
            "scope": "fixture network namespace only"}


def main():
    results = {}
    for evidence in EVIDENCE:
        document = json.loads(evidence.read_text())
        assert set(document["runs"]) == {"codex", "claude"}
        upgrade = "upgrade" in evidence.stem
        if upgrade:
            previous = document["previous_package"]
            current = document["current_package"]
            assert previous["binary_sha256"] != current["binary_sha256"]
            assert previous["revision"] != current["revision"]
            assert document["source_revision"] == current["revision"]
        for client, run in document["runs"].items():
            assert run["rules"] == ["EGRESS_ALLOWED", "EGRESS_DNS_TIMEOUT", "EGRESS_ALLOWED"]
            assert run["fixture_hits"] == ["/plain", "/plain"]
            assert run["dns_pairs"] == {"query_count": 2, "forged_response_count": 2,
                                        "all_ids_mismatched": True}
            assert run["tcp_syn_destinations"] == ["11.0.0.1:80"]
            assert run["skill_loaded"] and run["native_turn_or_skill_completed"]
            required = {"clean_dpkg_install", "package_remove", "residue"}
            if upgrade:
                required |= {"package_upgrade", "old_package_launch_and_loopback_denial"}
            assert required <= set(run["install_remove_residue_checks"])
            path = (ROOT / run["capture_path"]).resolve(strict=True)
            assert path.is_relative_to(CAPTURES)
            # The local tshark profile reads fixture captures from /tmp.
            with tempfile.TemporaryDirectory(prefix="outbound-dns-spoof-verify-") as directory:
                copy = Path(directory) / "fixture.pcap"
                shutil.copyfile(path, copy)
                results[f"{evidence.stem}:{client}"] = verify(copy, run["capture_sha256"])
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
