#!/usr/bin/env python3
"""Optional bounded cgroup-v2 task-exhaustion and manual recovery control."""
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import threading
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
    children, threads = [], []
    release = threading.Event()

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
        assert reply['id'] == id_ and reply['result']['resultType'] == 'complete', reply
        return reply['result']

    def event_count():
        return int(dict(line.split() for line in (group / 'pids.events').read_text().splitlines())['max'])

    try:
        child = start()
        rpc(child, 'ping', 'before')
        assert Path(f'/proc/{child.pid}/cgroup').read_text() == Path('/proc/self/cgroup').read_text()
        before = event_count()
        # At most16 sleeping threads; the exact group's TasksMax must stop us first.
        for _ in range(16):
            thread = threading.Thread(target=release.wait)
            try:
                thread.start()
            except RuntimeError:
                break
            threads.append(thread)
        else:
            raise AssertionError('task ceiling did not reject thread creation')
        saturated = int((group / 'pids.current').read_text())
        assert saturated == 16 and event_count() > before, (saturated, before, event_count())
        # No shell, fork bomb or external target: one additional owned process attempt.
        try:
            unexpected = start()
        except OSError as error:
            assert error.errno == errno.EAGAIN, error.errno
        else:
            unexpected.kill()
            unexpected.wait(timeout=3)
            raise AssertionError('process creation succeeded at task ceiling')
        rpc(child, 'ping', 'saturated')
        denied = rpc(child, 'tools/call', 'deny', {'name': 'guarded_fetch',
                     'arguments': {'url': 'http://127.0.0.1/'}})['structuredContent']
        assert denied['status'] == 'BLOCKED' and denied['rule'] == 'EGRESS_INVALID_HOST', denied
        after = event_count()
        assert after > before
        release.set()
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()
        recovered = int((group / 'pids.current').read_text())
        assert recovered < 16, recovered
        replacement = start()
        rpc(replacement, 'ping', 'replacement')
        rpc(child, 'ping', 'survivor')
        print(json.dumps({'result': 'passed', 'limits': limits,
            'pids_at_ceiling': saturated, 'pids_after_release': recovered,
            'sleeping_helper_threads': len(threads), 'pids_events_max_delta': after-before,
            'process_creation_errno': 'EAGAIN', 'mcp_ping_at_ceiling': True,
            'pre_network_denial_at_ceiling': denied['rule'],
            'manual_replacement_after_release': True,
            'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            'limitations': 'helper-induced task exhaustion; no active fetch, CPU saturation, automatic recovery or new-worker success claimed'}), flush=True)
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=3)
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            for handle in (child.stdin, child.stdout, child.stderr):
                handle.close()


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    unit = 'outbound-guard-task-probe-' + uuid.uuid4().hex + '.service'
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
