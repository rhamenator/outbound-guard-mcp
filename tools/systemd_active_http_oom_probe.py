#!/usr/bin/env python3
"""Optional route-free active HTTP request under one bounded cgroup OOM."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import resource
import select
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import uuid


ADDRESS = '11.0.0.1'  # Assigned only to loopback in the disposable netns.
HOST = 'allowed.test'


def inside(binary):
    # ip netns exec hides /sys/fs/cgroup; host PID 1 exposes the same group.
    group = Path('/proc/1/root/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().split('::', 1)[1].strip().lstrip('/')
    assert (group / 'memory.max').read_text().strip() == str(64 * 1024 * 1024)
    assert (group / 'memory.swap.max').read_text().strip() == '0'
    assert (group / 'memory.oom.group').read_text().strip() == '1'
    assert (group / 'pids.max').read_text().strip() == '16'
    assert (group / 'cpu.max').read_text().strip() == '50000 100000'
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
    own_group = Path('/proc/self/cgroup').read_text()
    first_byte = threading.Event()
    stop = threading.Event()
    dns_names = []
    http_paths = []
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('127.0.0.1', 53))
    dns_socket.settimeout(.1)

    def serve_dns():
        while not stop.is_set():
            try:
                query, peer = dns_socket.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            labels, offset = [], 12
            while offset < len(query) and query[offset]:
                size = query[offset]
                offset += 1
                labels.append(query[offset:offset + size].decode('ascii'))
                offset += size
            if offset + 5 > len(query):
                continue
            name = '.'.join(labels).lower()
            qtype = struct.unpack('!H', query[offset + 1:offset + 3])[0]
            dns_names.append((name, qtype))
            answer = (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) +
                      socket.inet_aton(ADDRESS)) if name == HOST and qtype == 1 else b''
            flags = 0x8180 if name == HOST else 0x8183
            response = query[:2] + struct.pack('!HHHHH', flags, 1, bool(answer), 0, 0)
            dns_socket.sendto(response + query[12:offset + 5] + answer, peer)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def address_string(self):
            return ADDRESS

        def do_GET(self):
            http_paths.append(self.path)
            assert self.path == '/held' and self.headers.get('Host') == HOST
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'A')
            self.wfile.flush()
            first_byte.set()
            # The group is killed before the response can complete.
            stop.wait(8)

    class FixtureHTTPServer(HTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = HOST
            self.server_port = 80

    http = FixtureHTTPServer((ADDRESS, 80), Handler)
    dns_thread = threading.Thread(target=serve_dns, daemon=True)
    http_thread = threading.Thread(target=http.serve_forever, daemon=True)
    dns_thread.start()
    http_thread.start()
    env = {key: value for key, value in os.environ.items() if not key.startswith('OUTBOUND_GUARD_')}
    env['OUTBOUND_GUARD_ALLOWED_HOSTS'] = HOST
    env['HTTP_PROXY'] = 'http://127.0.0.1:9'
    env['HTTPS_PROXY'] = 'http://127.0.0.1:9'
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, text=True)
    assert Path(f'/proc/{child.pid}/cgroup').read_text() == own_group
    request = {'jsonrpc': '2.0', 'id': 'held', 'method': 'tools/call', 'params': {
        'name': 'guarded_fetch', 'arguments': {'url': 'http://allowed.test/held'},
        '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                  'io.modelcontextprotocol/clientCapabilities': {}}}}
    child.stdin.write(json.dumps(request) + '\n')
    child.stdin.flush()
    assert first_byte.wait(3), 'approved HTTP request did not reach fixture'
    assert child.poll() is None and not select.select([child.stdout], [], [], .1)[0], 'request completed before pressure'
    assert http_paths == ['/held'] and dns_names.count((HOST, 1)) == 1 and dns_names.count((HOST, 28)) == 1
    print('ACTIVE_HTTP_BEFORE_BOUNDED_OOM ' + json.dumps({
        'http_paths': http_paths, 'dns_queries': dns_names,
        'server_cgroup_member': True, 'reply_pending': True}), flush=True)
    # Touch at most 128 MiB; the 64 MiB no-swap owned group must die first.
    held = []
    for _ in range(128):
        held.append(bytearray(b'x' * (1024 * 1024)))
    raise AssertionError('allocation exceeded the configured group ceiling')


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    namespace = 'outbound-guard-http-oom-' + uuid.uuid4().hex
    unit = namespace + '.service'
    try:
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'add', namespace], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', '-n', namespace, 'link', 'set', 'lo', 'up'], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', '-n', namespace, 'address', 'add', ADDRESS + '/32', 'dev', 'lo'],
                       check=True, timeout=5)
        directory = '/etc/netns/' + namespace
        subprocess.run(['sudo', '-n', 'install', '-d', '-m', '755', directory], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'tee', directory + '/resolv.conf'], input='nameserver 127.0.0.1\n',
                       text=True, stdout=subprocess.DEVNULL, check=True, timeout=5)
        result = subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe',
            '--unit=' + unit, '--property=MemoryMax=64M', '--property=MemorySwapMax=0',
            '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
            '--property=OOMPolicy=kill', 'sudo', '-n', 'ip', 'netns', 'exec', namespace,
            sys.executable, str(Path(__file__).resolve()), binary, '--inside'],
            capture_output=True, text=True, timeout=20)
        assert result.returncode != 0, result.returncode
        marker = [line for line in result.stdout.splitlines() if line.startswith('ACTIVE_HTTP_BEFORE_BOUNDED_OOM ')]
        assert len(marker) == 1, result.stdout
        observed = json.loads(marker[0].split(' ', 1)[1])
        state = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=Result', '--property=ActiveState', '--property=ControlGroup'],
            capture_output=True, text=True, check=True).stdout
        values = dict(line.split('=', 1) for line in state.splitlines())
        assert values['Result'] == 'oom-kill' and values['ActiveState'] == 'failed', values
        group = values['ControlGroup']
        if group:
            procs = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs'
            assert not procs.exists() or not procs.read_text().strip(), 'owned group retained processes'
        evidence = {'result': 'passed', 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                    'limits': {'memory.max': 64 * 1024 * 1024, 'memory.swap.max': 0,
                               'pids.max': 16, 'cpu.max': '50000 100000', 'memory.oom.group': 1},
                    'active_request_before_oom': observed, 'unit_result': values['Result'],
                    'surviving_group_processes': 0,
                    'limitations': 'finite helper-induced group OOM; fixture dies with group, so peer-observed socket closure, post-OOM MCP reply and native-client behavior are not measured'}
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'delete', namespace], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'rm', '-rf', '--', '/etc/netns/' + namespace], capture_output=True, timeout=5)
    # A new limited group can serve MCP after the failed group is gone.
    subprocess.run([sys.executable, str(Path(__file__).with_name('systemd_deployment_probe.py')),
                    binary], check=True, timeout=20, stdout=subprocess.DEVNULL)
    evidence['fresh_limited_group_recovered'] = True
    print(json.dumps(evidence), flush=True)


if __name__ == '__main__':
    main()
