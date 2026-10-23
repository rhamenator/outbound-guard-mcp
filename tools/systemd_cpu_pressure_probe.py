#!/usr/bin/env python3
"""Optional bounded cgroup-v2 CPU-throttling/MCP responsiveness control."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
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
    env = {k: v for k, v in os.environ.items() if not k.startswith('OUTBOUND_GUARD_')}
    child = burner = None

    def stats():
        return {key: int(value) for key, value in
                (line.split() for line in (group / 'cpu.stat').read_text().splitlines())}

    def rpc(method, id_, params=None):
        params = dict(params or {})
        params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                           'io.modelcontextprotocol/clientCapabilities': {}}
        started = time.monotonic()
        child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': id_, 'method': method,
                                     'params': params}) + '\n')
        child.stdin.flush()
        assert select.select([child.stdout], [], [], 3)[0], 'MCP reply deadline'
        reply = json.loads(child.stdout.readline())
        assert reply['id'] == id_ and reply['result']['resultType'] == 'complete', reply
        return reply['result'], time.monotonic() - started

    try:
        child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, text=True)
        rpc('ping', 'before')
        own_group = Path('/proc/self/cgroup').read_text()
        assert Path(f'/proc/{child.pid}/cgroup').read_text() == own_group
        before = stats()
        burner = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--burn'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert Path(f'/proc/{burner.pid}/cgroup').read_text() == own_group
        # Observe actual throttling before counting responsiveness controls.
        deadline = time.monotonic() + 2
        while stats()['nr_throttled'] <= before['nr_throttled']:
            assert burner.poll() is None, 'CPU helper ended before throttling'
            assert time.monotonic() < deadline, 'no kernel CPU-throttling event observed'
            time.sleep(.02)
        latencies = []
        for index in range(10):
            assert burner.poll() is None, 'CPU helper ended before MCP controls'
            _, latency = rpc('ping', f'pressure-ping-{index}')
            latencies.append(latency)
            result, latency = rpc('tools/call', f'pressure-deny-{index}',
                                 {'name': 'guarded_fetch', 'arguments': {'url': 'http://127.0.0.1/'}})
            decision = result['structuredContent']
            assert decision['rule'] == 'EGRESS_INVALID_HOST' and decision['status'] == 'BLOCKED', decision
            latencies.append(latency)
            time.sleep(.1)  # Spread controls across multiple quota periods.
        after = stats()
        assert after['nr_throttled'] - before['nr_throttled'] >= 5
        assert after['throttled_usec'] > before['throttled_usec']
        assert burner.wait(timeout=6) == 0
        rpc('ping', 'after')
        print(json.dumps({'result': 'passed', 'limits': limits,
            'pressure_pings': 10, 'pressure_pre_network_denials': 10,
            'max_reply_seconds': round(max(latencies), 6),
            'throttled_periods_delta': after['nr_throttled'] - before['nr_throttled'],
            'throttled_usec_delta': after['throttled_usec'] - before['throttled_usec'],
            'usage_usec_delta': after['usage_usec'] - before['usage_usec'],
            'post_pressure_ping': True,
            'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            'limitations': 'one finite helper-induced CPU saturation case; no active network/DNS timeout or automatic recovery guarantee'}), flush=True)
    finally:
        for process in (burner, child):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for handle in (process.stdin, process.stdout, process.stderr):
                    if handle is not None:
                        handle.close()


def main():
    if sys.argv[1:] == ['--burn']:
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            pass
        return
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    unit = 'outbound-guard-cpu-probe-' + uuid.uuid4().hex + '.service'
    try:
        subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe',
            '--unit=' + unit, '--property=MemoryMax=64M', '--property=MemorySwapMax=0',
            '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
            sys.executable, str(Path(__file__).resolve()), binary, '--inside'], check=True, timeout=20)
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)


if __name__ == '__main__':
    main()
