#!/usr/bin/env python3
"""Linux strace evidence: selected pre-DNS denials issue no network syscalls.

Development/candidate gate only; requires strace with permission to trace children.
No sudo, public target, credentials or runtime dependency is required.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile

NETWORK = re.compile(r'\b(?:socket|socketpair|connect|bind|listen|accept|accept4|sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|shutdown|getsockname|getpeername|setsockopt|getsockopt)\(')
MARKER = 'synthetic-syscall-marker'
CASES = (
    ({'url':'http://127.0.0.1/'}, 'EGRESS_INVALID_HOST'),
    ({'url':'http://[::1]/'}, 'EGRESS_INVALID_HOST'),
    ({'url':'http://unapproved.test/'}, 'EGRESS_HOST_NOT_ALLOWED'),
    ({'url':'file:///etc/passwd'}, 'EGRESS_INVALID_URL'),
    ({'url':'http://allowed.test:8080/'}, 'EGRESS_INVALID_PORT'),
    ({'url':f'http://user:{MARKER}@allowed.test/'}, 'EGRESS_INVALID_URL'),
    ({'url':f'http://allowed.test/?token={MARKER}'}, 'EGRESS_INVALID_URL'),
    ({'url':'http://allowed.test/%41'}, 'EGRESS_INVALID_URL'),
    ({'url':'http://allowed.test/ghp_' + 'A'*20}, 'EGRESS_SECRET_DETECTED'),
    ({'url':'http://allowed.test/', 'method':'POST'}, 'EGRESS_METHOD_DENIED'),
    ({'url':'http://allowed.test/', 'headers':{'X-Key':MARKER}}, 'EGRESS_INVALID_INPUT'),
    ({'url':'http://allowed.test/', 'headers':{'Authorization':'Bearer '+MARKER}}, 'EGRESS_INVALID_INPUT'),
    ({'url':'http://allowed.test/', 'body':MARKER}, 'EGRESS_INVALID_INPUT'),
    ({'url':'http://allowed.test/', 'max_return_bytes':0}, 'EGRESS_RESPONSE_LIMIT'),
)


def calls(path):
    assert path.stat().st_size < 2*1024*1024, 'unexpected trace growth'
    return [line for line in path.read_text().splitlines() if NETWORK.search(line)]


def probe(binary, modern, folder):
    trace = folder / ('modern.trace' if modern else 'legacy.trace')
    env = {k:v for k,v in os.environ.items() if not k.startswith('OUTBOUND_GUARD_')}
    env['OUTBOUND_GUARD_ALLOWED_HOSTS'] = 'allowed.test'
    child = subprocess.Popen(['strace','-f','-qq','-e','trace=network','-o',str(trace),str(binary)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=env, start_new_session=True)
    def send(method, id_, params=None):
        params = dict(params or {})
        if modern:
            params['_meta'] = {'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                               'io.modelcontextprotocol/clientCapabilities':{}}
        message = {'jsonrpc':'2.0','method':method,'params':params}
        if id_ is not None:
            message['id'] = id_
        child.stdin.write(json.dumps(message)+'\n')
        child.stdin.flush()
    def receive(id_):
        assert select.select([child.stdout], [], [], 3)[0], 'traced server response deadline'
        reply = json.loads(child.stdout.readline())
        assert reply.get('id') == id_, reply
        assert MARKER not in json.dumps(reply), 'synthetic marker reflected'
        return reply['result']
    try:
        if not modern:
            send('initialize', 'init', {'protocolVersion':'2025-06-18','capabilities':{},
                 'clientInfo':{'name':'syscall-probe','version':'1'}})
            receive('init')
            send('notifications/initialized', None)
        for index, (args, rule) in enumerate(CASES):
            send('tools/call', index, {'name':'guarded_fetch','arguments':args})
            result = receive(index)
            assert result['isError'] is True and result['structuredContent']['rule'] == rule, result
        send('ping', 'recovery')
        receive('recovery')
        send('resources/read', 'audit', {'uri':'outbound-guard://logs/audit.json'})
        audit = json.loads(receive('audit')['contents'][0]['text'])
        assert [event['rule'] for event in audit['events']] == [rule for _,rule in CASES]
        child.stdin.close()
        assert child.wait(timeout=3) == 0
        assert not child.stdout.read() and not child.stderr.read()
        assert not calls(trace), 'pre-DNS denial performed a network syscall'
        print(f'syscall denial {"modern" if modern else "legacy"}: {len(CASES)} denials, '
              'zero network syscalls across traced threads; ping/audit recovery passed')
    finally:
        # This process group belongs only to this strace invocation and its child.
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BrokenPipeError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    version = subprocess.run(['strace','--version'], text=True, capture_output=True,
                             check=True, timeout=3).stdout.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix='outbound-syscall-') as tmp:
        folder = Path(tmp)
        control = folder/'control.trace'
        # Positive tracer control creates/closes a socket but never transmits.
        subprocess.run(['strace','-f','-qq','-e','trace=network','-o',str(control),
                        sys.executable,'-c','import socket; s=socket.socket(); s.close()'],
                       check=True, capture_output=True, timeout=3)
        assert any('socket(AF_INET,' in line for line in calls(control)), 'tracer control failed'
        print(f'{version}; positive AF_INET socket control observed (no transmission)')
        for modern in (False, True):
            probe(binary, modern, folder)


if __name__ == '__main__':
    main()
