#!/usr/bin/env python3
"""Observe an external HTTP peer closing after a bounded active-fetch group OOM."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import queue
import resource
import select
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid


ADDRESS = '11.0.0.1'  # Assigned only to loopback in the disposable netns.
HOST = 'allowed.test'


def fixture():
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('127.0.0.1', 53))
    dns_socket.settimeout(.1)
    stop = threading.Event()
    dns_names = []

    def emit(event, **fields):
        print(json.dumps({'event': event, **fields}), flush=True)

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
            assert self.path == '/held' and self.headers.get('Host') == HOST
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'A')
            self.wfile.flush()
            started = time.monotonic()
            emit('FIRST_BYTE', dns_queries=dns_names, http_path=self.path)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as marker:
                marker.sendto(b'FIRST_BYTE', ('127.0.0.1', 5353))
            self.connection.settimeout(5)
            try:
                received = self.connection.recv(1)
            except (ConnectionResetError, BrokenPipeError):
                received = b''
            except socket.timeout:
                emit('PEER_TIMEOUT')
                return
            emit('PEER_CLOSED' if received == b'' else 'UNEXPECTED_PEER_DATA',
                 elapsed_seconds=round(time.monotonic() - started, 6))

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
    emit('READY', cgroup=Path('/proc/self/cgroup').read_text().strip())
    try:
        stop.wait()
    finally:
        stop.set()
        dns_socket.close()
        http.shutdown()
        http.server_close()


def inside(binary):
    group = Path('/proc/1/root/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().split('::', 1)[1].strip().lstrip('/')
    assert (group / 'memory.max').read_text().strip() == str(64 * 1024 * 1024)
    assert (group / 'memory.swap.max').read_text().strip() == '0'
    assert (group / 'memory.oom.group').read_text().strip() == '1'
    assert (group / 'pids.max').read_text().strip() == '16'
    assert (group / 'cpu.max').read_text().strip() == '50000 100000'
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
    marker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    marker.bind(('127.0.0.1', 5353))
    marker.settimeout(3)
    own_group = Path('/proc/self/cgroup').read_text()
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
    assert marker.recvfrom(32)[0] == b'FIRST_BYTE'
    assert child.poll() is None and not select.select([child.stdout], [], [], .1)[0], 'request completed before pressure'
    print('ACTIVE_HTTP_BEFORE_BOUNDED_OOM ' + json.dumps({'cgroup': own_group.strip()}), flush=True)
    held = []
    for _ in range(128):
        held.append(bytearray(b'x' * (1024 * 1024)))
    raise AssertionError('allocation exceeded the configured group ceiling')


def main():
    if sys.argv[1:] == ['--fixture']:
        fixture()
        return
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    namespace = 'outbound-guard-http-oom-peer-' + uuid.uuid4().hex
    unit = namespace + '.service'
    fixture_process = None
    events = queue.Queue()
    try:
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'add', namespace], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', '-n', namespace, 'link', 'set', 'lo', 'up'], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', '-n', namespace, 'address', 'add', ADDRESS + '/32', 'dev', 'lo'],
                       check=True, timeout=5)
        directory = '/etc/netns/' + namespace
        subprocess.run(['sudo', '-n', 'install', '-d', '-m', '755', directory], check=True, timeout=5)
        subprocess.run(['sudo', '-n', 'tee', directory + '/resolv.conf'], input='nameserver 127.0.0.1\n',
                       text=True, stdout=subprocess.DEVNULL, check=True, timeout=5)
        fixture_process = subprocess.Popen(['sudo', '-n', 'ip', 'netns', 'exec', namespace,
            sys.executable, str(Path(__file__).resolve()), '--fixture'], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, start_new_session=True)

        def read_events():
            for line in fixture_process.stdout:
                events.put(json.loads(line))

        reader = threading.Thread(target=read_events, daemon=True)
        reader.start()
        ready = events.get(timeout=3)
        assert ready['event'] == 'READY', ready
        result = subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe',
            '--unit=' + unit, '--property=MemoryMax=64M', '--property=MemorySwapMax=0',
            '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
            '--property=OOMPolicy=kill', 'sudo', '-n', 'ip', 'netns', 'exec', namespace,
            sys.executable, str(Path(__file__).resolve()), binary, '--inside'],
            capture_output=True, text=True, timeout=20)
        assert result.returncode != 0, result.returncode
        marker = [line for line in result.stdout.splitlines() if line.startswith('ACTIVE_HTTP_BEFORE_BOUNDED_OOM ')]
        assert len(marker) == 1, result.stdout
        worker_group = json.loads(marker[0].split(' ', 1)[1])['cgroup']
        assert ready['cgroup'] != worker_group, (ready['cgroup'], worker_group)
        first = events.get(timeout=3)
        closed = events.get(timeout=3)
        assert first['event'] == 'FIRST_BYTE' and closed['event'] == 'PEER_CLOSED', (first, closed)
        assert first['http_path'] == '/held' and first['dns_queries'] == [[HOST, 1], [HOST, 28]], first
        assert closed['elapsed_seconds'] < 3, closed
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
                    'fixture_outside_oom_group': True,
                    'fixture_cgroup': ready['cgroup'], 'worker_cgroup': worker_group,
                    'fixture_first_byte': first,
                    'fixture_peer_closure': closed, 'active_request_before_oom': True,
                    'unit_result': values['Result'], 'surviving_group_processes': 0,
                    'limitations': 'finite synthetic stdio and helper-induced group OOM; no native-client delivery, automatic replay or sustained load'}
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)
        if fixture_process is not None:
            if fixture_process.poll() is None:
                os.killpg(fixture_process.pid, signal.SIGTERM)
            try:
                fixture_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(fixture_process.pid, signal.SIGKILL)
                fixture_process.wait(timeout=3)
            fixture_process.stdout.close()
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'delete', namespace], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'rm', '-rf', '--', '/etc/netns/' + namespace], capture_output=True, timeout=5)
    subprocess.run([sys.executable, str(Path(__file__).with_name('systemd_deployment_probe.py')),
                    binary], check=True, timeout=20, stdout=subprocess.DEVNULL)
    evidence['fresh_limited_group_recovered'] = True
    print(json.dumps(evidence), flush=True)


if __name__ == '__main__':
    main()
