#!/usr/bin/env python3
"""Bounded two-process oversized-frame test inside one user cgroup."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid


def inside(binary):
    group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
    limits = {name: (group / name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    assert limits['memory.max'] == '67108864' and limits['memory.swap.max'] == '0', limits
    assert limits['pids.max'] == '16', limits
    quota, period = map(int, limits['cpu.max'].split())
    assert quota * 2 == period, limits
    own_group = Path('/proc/self/cgroup').read_text()
    before = {key: int(value) for key, value in
              (line.split() for line in (group / 'memory.events').read_text().splitlines())}
    env = {key: value for key, value in os.environ.items() if not key.startswith('OUTBOUND_GUARD_')}
    children = [subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env) for _ in range(2)]
    errors = []
    gate = threading.Barrier(3)

    def send(index, child):
        try:
            gate.wait(timeout=3)
            chunk = b'x' * 65536
            for _ in range(128):
                child.stdin.write(chunk)
            child.stdin.write(b'\n' + json.dumps({'jsonrpc': '2.0', 'id': index,
                                                    'method': 'ping'}).encode() + b'\n')
            child.stdin.close()
        except Exception as exc:
            errors.append(repr(exc))

    workers = [threading.Thread(target=send, args=(index, child), daemon=True)
               for index, child in enumerate(children)]
    start = time.monotonic()
    try:
        for child in children:
            assert Path(f'/proc/{child.pid}/cgroup').read_text() == own_group
        for worker in workers:
            worker.start()
        gate.wait(timeout=3)
        for worker in workers:
            worker.join(timeout=14)
            assert not worker.is_alive(), 'oversized-frame writer stalled'
        assert not errors, errors
        for index, child in enumerate(children):
            assert child.wait(timeout=3) == 0, child.returncode
            replies = [json.loads(line) for line in child.stdout.read().splitlines()]
            assert len(replies) == 2, replies
            assert replies[0]['error']['code'] == -32600
            assert replies[0]['error']['message'] == 'Request too large'
            assert replies[1] == {'jsonrpc': '2.0', 'id': index, 'result': {}}, replies[1]
            assert not child.stderr.read(), 'unexpected server stderr'
        after = {key: int(value) for key, value in
                 (line.split() for line in (group / 'memory.events').read_text().splitlines())}
        assert after['oom'] == before['oom'] and after['oom_kill'] == before['oom_kill'], (before, after)
        peak = int((group / 'memory.peak').read_text())
        assert peak < 67108864, peak
        print(json.dumps({'result': 'passed', 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          'limits': limits, 'concurrent_servers': 2, 'oversized_frame_bytes_each': 8388608,
                          'recovered_ping_each': True, 'memory_peak_bytes': peak,
                          'oom_delta': after['oom'] - before['oom'],
                          'oom_kill_delta': after['oom_kill'] - before['oom_kill'],
                          'elapsed_seconds': round(time.monotonic() - start, 3),
                          'limitations': 'two finite stdio inputs; no active HTTP/DNS, multiple MCP clients, or sustained load'}), flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            for handle in (child.stdin, child.stdout, child.stderr):
                if handle and not handle.closed:
                    handle.close()


def main():
    if len(sys.argv) < 2 or sys.platform != 'linux':
        raise SystemExit('usage (Linux only): systemd_aggregate_frame_probe.py PATH_TO_SERVER')
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    unit = 'outbound-guard-frame-probe-' + uuid.uuid4().hex + '.service'
    try:
        subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe',
                        '--unit=' + unit, '--property=MemoryMax=64M', '--property=MemorySwapMax=0',
                        '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
                        sys.executable, str(Path(__file__).resolve()), binary, '--inside'], check=True, timeout=25)
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)


if __name__ == '__main__':
    main()
