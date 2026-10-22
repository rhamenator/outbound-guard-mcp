#!/usr/bin/env python3
"""Optional Linux user-systemd/cgroup-v2 deployment probe; no network fixtures."""
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys


def child_probe(binary):
    relative = Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1]
    group = Path('/sys/fs/cgroup') / relative.lstrip('/')
    limits = {name: (group / name).read_text().strip()
              for name in ('memory.max', 'pids.max', 'cpu.max')}
    assert limits['memory.max'] == '67108864', limits
    assert limits['pids.max'] == '16', limits
    quota, period = map(int, limits['cpu.max'].split())
    assert quota * 2 == period, limits
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
    env = {k: v for k, v in os.environ.items() if not k.startswith('OUTBOUND_GUARD_')}
    children = []

    def start():
        child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, text=True)
        children.append(child)
        return child

    def rpc(child, method, id_, params=None):
        params = dict(params or {})
        params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                           'io.modelcontextprotocol/clientCapabilities': {}}
        child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': id_, 'method': method,
                                     'params': params}) + '\n')
        child.stdin.flush()
        assert select.select([child.stdout], [], [], 3)[0], 'MCP reply deadline'
        reply = json.loads(child.stdout.readline())
        assert reply['id'] == id_, reply
        result = reply['result']
        result.pop('_meta', None)
        assert result.pop('resultType') == 'complete', result
        return result

    def audit(child):
        return json.loads(rpc(child, 'resources/read', 'audit',
                             {'uri': 'outbound-guard://logs/audit.json'})['contents'][0]['text'])['events']

    try:
        first, second = start(), start()
        for child in (first, second):
            assert rpc(child, 'ping', 'ping') == {}
            assert Path(f'/proc/{child.pid}/cgroup').read_text() == Path('/proc/self/cgroup').read_text()
            limits_text = Path(f'/proc/{child.pid}/limits').read_text()
            assert any(line.split()[3:5] == ['64', '64'] for line in limits_text.splitlines()
                       if line.startswith('Max open files')), limits_text
            assert audit(child) == []
        # Unsupported loopback URL is denied before DNS; no approved host configured.
        result = rpc(first, 'tools/call', 'deny', {'name': 'guarded_fetch',
                     'arguments': {'url': 'http://127.0.0.1/'}})['structuredContent']
        assert result['status'] == 'BLOCKED', result
        assert len(audit(first)) == 1 and audit(second) == []
        first.kill()  # Explicit simulated process failure, not a claim of OOM testing.
        assert first.wait(timeout=3) == -signal.SIGKILL
        assert rpc(second, 'ping', 'survivor') == {}
        replacement = start()
        assert rpc(replacement, 'ping', 'replacement') == {}
        assert audit(replacement) == []  # Process-local state does not survive restart.
        for child in (second, replacement):
            child.stdin.close()
            assert child.wait(timeout=3) == 0
            assert child.stdout.read() == '' and child.stderr.read() == ''
        print(json.dumps({'result': 'passed', 'limits': limits,
                          'nofile': [64, 64], 'instances': 2,
                          'recovery': 'one killed process replaced; sibling remained responsive',
                          'limitations': 'no OOM/CPU saturation test; audit and budgets are process-local'}))
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait()
            for handle in (child.stdin, child.stdout, child.stderr):
                handle.close()


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        child_probe(binary)
        return
    # Only this uniquely created transient service and its descendants receive limits.
    subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                    '--property=MemoryMax=64M', '--property=TasksMax=16',
                    '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
                    sys.executable, str(Path(__file__).resolve()), binary, '--inside'], check=True)


if __name__ == '__main__':
    main()
