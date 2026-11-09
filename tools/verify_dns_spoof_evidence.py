#!/usr/bin/env python3
"""Check the retained forged-DNS-ID fixture record without network access."""
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify(record_path: Path) -> dict:
    record = json.loads(record_path.read_text())
    assert record['subject'] == 'Controlled forged DNS transaction-ID response during guarded MCP fetch'
    assert record['observed']['full_probe_mcp_decisions'] == 2252
    relative = Path(record['retained_log']['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    compressed = (ROOT / relative).read_bytes()
    assert hashlib.sha256(compressed).hexdigest() == record['retained_log']['sha256']
    log = gzip.decompress(compressed).decode('utf-8')
    required = (
        'forged DNS transaction ID: 2 mismatched private answers ignored; EGRESS_DNS_FAILURE before HTTP; same-process approved recovery',
        'post-DNS syscall legacy: 9 real-DNS forbidden-answer/spoof denials (2 mismatched IDs), zero extra Internet stream sockets',
        'post-DNS syscall modern: 9 real-DNS forbidden-answer/spoof denials (2 mismatched IDs), zero extra Internet stream sockets',
        'netns adversarial probe: 2252 MCP decisions',
    )
    assert all(line in log for line in required)
    return {'log_sha256': record['retained_log']['sha256'], 'required_observations': len(required)}


if __name__ == '__main__':
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'docs/evidence/dns-transaction-id-spoof-2026-11-09.json'
    print(json.dumps(verify(path), sort_keys=True))
