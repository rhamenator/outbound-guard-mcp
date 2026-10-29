#!/usr/bin/env python3
"""Optional route-free MCP HTTP fetch under an aggregate CPU quota."""
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
import time
import uuid


ADDRESS = '11.0.0.1'  # Assigned only to loopback in the disposable netns.
HOST = 'allowed.test'


def inside(binary):
    # ip netns exec creates a mount namespace with /sys/fs/cgroup hidden. The
    # host PID 1 mount view exposes the same delegated cgroup for measurements.
    group = Path('/proc/1/root/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().split('::', 1)[1].strip().lstrip('/')
    limits = {name: (group / name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    assert limits['memory.max'] == str(96 * 1024 * 1024) and limits['memory.swap.max'] == '0', limits
    assert limits['pids.max'] == '16' and limits['cpu.max'] == '50000 100000', limits
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
    own_group = Path('/proc/self/cgroup').read_text()
    stop = threading.Event()
    first_byte = threading.Event()
    release_body = threading.Event()
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
            assert self.headers.get('Host') == HOST, self.headers
            assert self.path in ('/drip', '/plain'), self.path
            body = b'AB' if self.path == '/drip' else b'OK'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body[:1])
            self.wfile.flush()
            if self.path == '/drip':
                first_byte.set()
                assert release_body.wait(4), 'held HTTP body was not released'
            self.wfile.write(body[1:])
            self.wfile.flush()

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
    child = burner = None

    def cpu_stats():
        return {key: int(value) for key, value in
                (line.split() for line in (group / 'cpu.stat').read_text().splitlines())}

    def memory_events():
        return {key: int(value) for key, value in
                (line.split() for line in (group / 'memory.events').read_text().splitlines())}

    def rpc(method, id_, params=None):
        payload = dict(params or {})
        payload['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                            'io.modelcontextprotocol/clientCapabilities': {}}
        child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': id_, 'method': method,
                                      'params': payload}) + '\n')
        child.stdin.flush()

    def receive(id_):
        assert select.select([child.stdout], [], [], 4)[0], f'MCP reply deadline for {id_}'
        reply = json.loads(child.stdout.readline())
        assert 'result' in reply, reply
        assert reply['id'] == id_ and reply['result']['resultType'] == 'complete', reply
        return reply['result']

    try:
        child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, text=True)
        assert Path(f'/proc/{child.pid}/cgroup').read_text() == own_group
        rpc('ping', 'before')
        receive('before')
        before = cpu_stats()
        memory_before = memory_events()
        burner = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--burn'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert Path(f'/proc/{burner.pid}/cgroup').read_text() == own_group
        rpc('tools/call', 'active', {'name': 'guarded_fetch',
                                   'arguments': {'url': 'http://allowed.test/drip'}})
        assert first_byte.wait(3), 'approved HTTP request did not reach controlled fixture'
        active = cpu_stats()
        deadline = time.monotonic() + 1.5
        while active['nr_throttled'] - before['nr_throttled'] < 3:
            assert burner.poll() is None and time.monotonic() < deadline, 'no CPU throttling during active HTTP'
            time.sleep(.02)
            active = cpu_stats()
        release_body.set()
        decision = receive('active')['structuredContent']
        assert decision['rule'] == 'EGRESS_ALLOWED' and decision['body_text'] == 'AB', decision
        rpc('tools/call', 'recovery', {'name': 'guarded_fetch',
                                     'arguments': {'url': 'http://allowed.test/plain'}})
        recovery = receive('recovery')['structuredContent']
        assert recovery['rule'] == 'EGRESS_ALLOWED' and recovery['body_text'] == 'OK', recovery
        assert burner.wait(timeout=5) == 0
        rpc('ping', 'after')
        receive('after')
        assert http_paths == ['/drip', '/plain'], http_paths
        assert dns_names.count((HOST, 1)) == 2 and dns_names.count((HOST, 28)) == 2, dns_names
        assert all(name == HOST for name, _ in dns_names), dns_names
        memory_peak = int((group / 'memory.peak').read_text())
        assert memory_peak < 96 * 1024 * 1024, memory_peak
        memory_after = memory_events()
        assert memory_after['oom'] == memory_before['oom']
        assert memory_after['oom_kill'] == memory_before['oom_kill']
        pids_peak = int((group / 'pids.peak').read_text())
        assert pids_peak <= 16, pids_peak
        print(json.dumps({'result': 'passed', 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          'limits': limits, 'http_paths': http_paths, 'dns_queries': dns_names,
                          'throttled_periods_during_active_http': active['nr_throttled'] - before['nr_throttled'],
                          'throttled_usec_during_active_http': active['throttled_usec'] - before['throttled_usec'],
                          'memory_peak_bytes': memory_peak, 'pids_peak': pids_peak,
                          'oom_delta': memory_after['oom'] - memory_before['oom'],
                          'oom_kill_delta': memory_after['oom_kill'] - memory_before['oom_kill'],
                          'post_pressure_ping': True,
                          'limitations': 'one finite active HTTP case in a route-free netns; no native client, cancellation, OOM or PID exhaustion'}),
              flush=True)
    finally:
        release_body.set()
        stop.set()
        dns_socket.close()
        http.shutdown()
        http.server_close()
        dns_thread.join(timeout=2)
        http_thread.join(timeout=2)
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
        end = time.monotonic() + 3
        while time.monotonic() < end:
            pass
        return
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if sys.argv[2:] == ['--inside']:
        inside(binary)
        return
    namespace = 'outbound-guard-http-cpu-' + uuid.uuid4().hex
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
        subprocess.run(['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect',
                        '--unit=' + unit, '--property=MemoryMax=96M', '--property=MemorySwapMax=0',
                        '--property=TasksMax=16', '--property=CPUQuota=50%', '--property=LimitNOFILE=64',
                        'sudo', '-n', 'ip', 'netns', 'exec', namespace, sys.executable,
                        str(Path(__file__).resolve()), binary, '--inside'], check=True, timeout=20)
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=5)
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'ip', 'netns', 'delete', namespace], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'rm', '-rf', '--', '/etc/netns/' + namespace], capture_output=True, timeout=5)


if __name__ == '__main__':
    main()
