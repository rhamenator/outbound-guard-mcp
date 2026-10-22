#!/usr/bin/env python3
"""Require observed instrumentation/coverage growth; preserve corpus identities."""
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
log = (root / 'campaign.log').read_text()
assert 'inline 8-bit counters' in log and 'PC tables' in log, 'instrumentation missing'
match = re.search(r'#(\d+)\s+DONE\s+cov: (\d+) ft: (\d+)', log)
assert match and int(match[1]) >= 1000 and int(match[2]) > 0, 'campaign incomplete'
added = re.search(r'stat::new_units_added:\s+(\d+)', log)
assert added and int(added[1]) > 0, 'no feedback-guided corpus growth'
assert not list((root / 'artifacts').iterdir()), 'crash/timeout artifact present'
corpus = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted((root / 'corpus').iterdir())}
report = {'seed': 306373022, 'executions': int(match[1]), 'coverage_counters': int(match[2]),
          'features': int(match[3]), 'new_units_added': int(added[1]), 'corpus': corpus,
          'limits': '60s target; 2s/input; hard 1GiB address space/64 FDs/90s CPU; no ASan',
          'scope': 'validate only, stub DNS; no sockets, HTTP parser or MCP transport'}
(root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'corpus'}))
