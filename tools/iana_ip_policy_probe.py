#!/usr/bin/env python3
"""Finite differential safety check against pinned IANA special-address data."""
import csv
import hashlib
import ipaddress
from pathlib import Path
import random
import subprocess
import sys

SEED = 0x49414E4132303236
SNAPSHOTS = {
    'ipv4.csv': 'cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac',
    'ipv6.csv': 'bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66',
}


def main(binary):
    root = Path(__file__).resolve().parents[1] / 'tests/fixtures/iana'
    ranges = []
    samples = set()
    rng = random.Random(SEED)
    for name, digest in SNAPSHOTS.items():
        data = (root / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, name
        for row in csv.DictReader(data.decode().splitlines()):
            # Strip registry footnote references, retaining each separate CIDR.
            for block in row['Address Block'].split(','):
                network = ipaddress.ip_network(block.strip().split()[0])
                flag = (row['Globally Reachable'].split() or ['N/A'])[0]
                assert flag in ('True', 'False', 'N/A'), (block, flag)
                ranges.append((network, flag))
                first, last = int(network.network_address), int(network.broadcast_address)
                for value in (first - 1, first, first + 1, last - 1, last, last + 1):
                    if 0 <= value < 1 << network.max_prefixlen:
                        samples.add((network.version, value))
                for _ in range(256):
                    samples.add((network.version, rng.randrange(first, last + 1)))
    # Most-specific registry entry controls overlaps and special exceptions.
    denied = []
    skipped = 0
    for version, value in sorted(samples):
        ip = (ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address)(value)
        matches = [(n, flag) for n, flag in ranges if n.version == version and ip in n]
        if matches and max(matches, key=lambda entry: entry[0].prefixlen)[1] == 'False':
            denied.append(str(ip))
        else:
            skipped += 1  # No requirement to allow globally reachable exceptions.
    assert len(denied) > 3000, len(denied)
    controls = ['8.8.8.8', '2606:4700:4700::1111']
    payload = ('\n'.join(denied + controls) + '\n').encode()
    result = subprocess.run([binary], input=payload, capture_output=True, timeout=15, check=True)
    answers = result.stdout.splitlines()
    assert not result.stderr and len(answers) == len(denied) + len(controls)
    failures = [ip for ip, answer in zip(denied, answers[:len(denied)]) if answer != b'false']
    assert not failures, failures[:20]
    assert answers[len(denied):] == [b'true'] * len(controls), 'positive controls failed'
    print(f'IANA non-global differential: {len(denied)} denied samples and {len(controls)} positive controls; '
          f'{len(ranges)} registry CIDRs; {skipped} non-denial samples excluded; '
          f'seed={SEED}; corpus_sha256={hashlib.sha256(payload).hexdigest()}; '
          'finite network-free classification check, not socket/coverage-guided evidence')


if __name__ == '__main__':
    main(sys.argv[1])
