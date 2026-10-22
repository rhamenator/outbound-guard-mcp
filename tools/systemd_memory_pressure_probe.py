#!/usr/bin/env python3
"""Optional Linux cgroup OOM test, bounded to one owned 64MiB no-swap unit."""
import json
from pathlib import Path
import subprocess
import sys
import uuid


def inside(binary):
    import os
    import select
    group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
    assert (group / 'memory.max').read_text().strip() == '67108864'
    assert (group / 'memory.swap.max').read_text().strip() == '0'
    assert (group / 'memory.oom.group').read_text().strip() == '1'
    env = {k: v for k, v in os.environ.items() if not k.startswith('OUTBOUND_GUARD_')}
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, text=True)
    # The server is live before pressure; no network request is issued.
    child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': 'live', 'method': 'ping',
                     'params': {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                               'io.modelcontextprotocol/clientCapabilities': {}}}}) + '\n')
    child.stdin.flush()
    assert select.select([child.stdout], [], [], 3)[0]
    reply = json.loads(child.stdout.readline())
    assert reply['id'] == 'live' and reply['result']['resultType'] == 'complete', reply
    assert Path(f'/proc/{child.pid}/cgroup').read_text() == Path('/proc/self/cgroup').read_text()
    print('LIVE_MCP_BEFORE_BOUNDED_PRESSURE', flush=True)
    # Touch at most128MiB; the64MiB aggregate group must kill us first.
    held = []
    for _ in range(128):
        held.append(bytearray(b'x' * (1024 * 1024)))
    raise AssertionError('allocation exceeded the configured cgroup ceiling')


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    unit = 'outbound-guard-oom-probe-' + uuid.uuid4().hex + '.service'
    try:
        result = subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe',
            '--unit=' + unit, '--property=MemoryMax=64M', '--property=MemorySwapMax=0',
            '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
            '--property=OOMPolicy=kill', sys.executable, str(Path(__file__).resolve()), binary,
            '--inside'], capture_output=True, text=True, timeout=20)
        assert result.returncode != 0, result.returncode
        assert result.stdout.strip() == 'LIVE_MCP_BEFORE_BOUNDED_PRESSURE', result.stdout
        state = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=Result', '--property=ActiveState', '--property=ControlGroup'],
            capture_output=True, text=True, check=True).stdout
        values = dict(line.split('=', 1) for line in state.splitlines())
        assert values['Result'] == 'oom-kill' and values['ActiveState'] == 'failed', values
        group = values['ControlGroup']
        if group:
            procs = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs'
            assert not procs.exists() or not procs.read_text().strip(), 'owned group retained processes'
        print(json.dumps({'result': 'passed', 'memory_max': 67108864, 'swap_max': 0,
                          'unit_result': values['Result'], 'live_mcp_before_pressure': True,
                          'structured_oom_reply': False, 'surviving_group_processes': 0}), flush=True)
    finally:
        # Exact randomly named owned unit only, including timeout/failure cleanup.
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)
    # Verify a fresh normally limited group can start and serve MCP after the failure.
    subprocess.run([sys.executable, str(Path(__file__).with_name('systemd_deployment_probe.py')),
                    binary], check=True, timeout=20)


if __name__ == '__main__':
    main()
