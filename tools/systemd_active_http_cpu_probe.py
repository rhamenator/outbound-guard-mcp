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
    cancel_started = threading.Event()
    cancel_closed = threading.Event()
    release_tasks = threading.Event()
    task_threads = []
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
            assert self.path in ('/drip', '/plain', '/cancel'), self.path
            body = b'AB' if self.path == '/drip' else b'OK'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body[:1])
            self.wfile.flush()
            if self.path == '/cancel':
                cancel_started.set()
                self.connection.settimeout(4)
                try:
                    if self.connection.recv(1) == b'':
                        cancel_closed.set()
                except (BrokenPipeError, ConnectionResetError):
                    cancel_closed.set()
                except socket.timeout:
                    pass
                return
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

    def task_limit_events():
        return int(dict(line.split() for line in (group / 'pids.events').read_text().splitlines())['max'])

    def rpc(method, id_, params=None):
        payload = dict(params or {})
        payload['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                            'io.modelcontextprotocol/clientCapabilities': {}}
        child.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': id_, 'method': method,
                                      'params': payload}) + '\n')
        child.stdin.flush()

    def notify(method, params):
        child.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': method,
                                      'params': params}) + '\n')
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
        memory_before = memory_events()
        rpc('tools/call', 'active', {'name': 'guarded_fetch',
                                   'arguments': {'url': 'http://allowed.test/drip'}})
        assert first_byte.wait(3), 'approved HTTP request did not reach controlled fixture'
        before = cpu_stats()
        burner = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--burn'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert Path(f'/proc/{burner.pid}/cgroup').read_text() == own_group
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
        burner.stderr.close()
        burner = None
        rpc('tools/call', 'cancel', {'name': 'guarded_fetch',
                                   'arguments': {'url': 'http://allowed.test/cancel'}})
        assert cancel_started.wait(3), 'cancellable HTTP request did not reach controlled fixture'
        cancel_before = cpu_stats()
        burner = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--burn'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        assert Path(f'/proc/{burner.pid}/cgroup').read_text() == own_group
        cancel_active = cpu_stats()
        deadline = time.monotonic() + 1.5
        while cancel_active['nr_throttled'] - cancel_before['nr_throttled'] < 3:
            assert burner.poll() is None and time.monotonic() < deadline, 'no CPU throttling during pending cancellation'
            time.sleep(.02)
            cancel_active = cpu_stats()
        assert not cancel_closed.is_set(), 'HTTP socket closed before MCP cancellation'
        started = time.monotonic()
        notify('notifications/cancelled', {'requestId': 'cancel'})
        rpc('ping', 'cancel-barrier')
        receive('cancel-barrier')  # A cancelled tool call has no reply.
        assert cancel_closed.wait(1), 'cancelled HTTP socket remained open'
        cancellation_seconds = time.monotonic() - started
        assert cancellation_seconds < 1, cancellation_seconds
        rpc('resources/read', 'audit', {'uri': 'outbound-guard://logs/audit.json'})
        events = json.loads(receive('audit')['contents'][0]['text'])['events']
        assert [event['rule'] for event in events] == [
            'EGRESS_ALLOWED', 'EGRESS_ALLOWED', 'EGRESS_CANCELLED'], events
        rpc('tools/call', 'cancel', {'name': 'guarded_fetch',
                                   'arguments': {'url': 'http://allowed.test/plain'}})
        reused = receive('cancel')['structuredContent']
        assert reused['rule'] == 'EGRESS_ALLOWED' and reused['body_text'] == 'OK', reused
        assert burner.wait(timeout=5) == 0
        burner.stderr.close()
        burner = None
        cancel_started.clear()
        cancel_closed.clear()
        rpc('tools/call', 'task-cancel', {'name': 'guarded_fetch',
                                        'arguments': {'url': 'http://allowed.test/cancel'}})
        assert cancel_started.wait(3), 'task-pressure HTTP request did not reach fixture'
        task_events_before = task_limit_events()
        for _ in range(16):
            thread = threading.Thread(target=release_tasks.wait)
            try:
                thread.start()
            except RuntimeError:
                break
            task_threads.append(thread)
        else:
            raise AssertionError('task ceiling did not reject helper-thread creation')
        tasks_at_ceiling = int((group / 'pids.current').read_text())
        task_events_delta = task_limit_events() - task_events_before
        assert tasks_at_ceiling == 16 and task_events_delta > 0, (tasks_at_ceiling, task_events_delta)
        assert not cancel_closed.is_set(), 'HTTP socket closed before task-ceiling cancellation'
        started = time.monotonic()
        notify('notifications/cancelled', {'requestId': 'task-cancel'})
        rpc('ping', 'task-barrier')
        receive('task-barrier')
        assert cancel_closed.wait(1), 'task-ceiling cancellation retained HTTP socket'
        task_cancel_seconds = time.monotonic() - started
        assert task_cancel_seconds < 1, task_cancel_seconds
        release_tasks.set()
        for thread in task_threads:
            thread.join(timeout=2)
            assert not thread.is_alive()
        tasks_after_release = int((group / 'pids.current').read_text())
        assert tasks_after_release < 16, tasks_after_release
        rpc('resources/read', 'task-audit', {'uri': 'outbound-guard://logs/audit.json'})
        events = json.loads(receive('task-audit')['contents'][0]['text'])['events']
        assert [event['rule'] for event in events] == [
            'EGRESS_ALLOWED', 'EGRESS_ALLOWED', 'EGRESS_CANCELLED',
            'EGRESS_ALLOWED', 'EGRESS_CANCELLED'], events
        rpc('tools/call', 'task-cancel', {'name': 'guarded_fetch',
                                        'arguments': {'url': 'http://allowed.test/plain'}})
        task_reuse = receive('task-cancel')['structuredContent']
        assert task_reuse['rule'] == 'EGRESS_ALLOWED' and task_reuse['body_text'] == 'OK', task_reuse
        rpc('ping', 'after')
        receive('after')
        assert http_paths == ['/drip', '/plain', '/cancel', '/plain', '/cancel', '/plain'], http_paths
        assert dns_names.count((HOST, 1)) == 6 and dns_names.count((HOST, 28)) == 6, dns_names
        assert all(name == HOST for name, _ in dns_names), dns_names
        memory_peak = int((group / 'memory.peak').read_text())
        assert memory_peak < 96 * 1024 * 1024, memory_peak
        memory_after = memory_events()
        assert memory_after['oom'] == memory_before['oom']
        assert memory_after['oom_kill'] == memory_before['oom_kill']
        pids_peak = int((group / 'pids.peak').read_text())
        assert pids_peak <= 16, pids_peak
        child.stdin.close()
        assert child.wait(timeout=3) == 0, child.returncode
        assert not child.stdout.read() and not child.stderr.read(), 'late MCP reply or stderr after cancellation'
        print(json.dumps({'result': 'passed', 'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          'limits': limits, 'http_paths': http_paths, 'dns_queries': dns_names,
                          'throttled_periods_during_active_http': active['nr_throttled'] - before['nr_throttled'],
                          'throttled_usec_during_active_http': active['throttled_usec'] - before['throttled_usec'],
                          'throttled_periods_before_cancellation': cancel_active['nr_throttled'] - cancel_before['nr_throttled'],
                          'cancellation_socket_closed_seconds': round(cancellation_seconds, 6),
                          'cancelled_reply_suppressed': True, 'cancelled_id_reused': True,
                          'task_helper_threads': len(task_threads), 'tasks_at_ceiling': tasks_at_ceiling,
                          'task_limit_events_delta': task_events_delta,
                          'task_cancel_socket_closed_seconds': round(task_cancel_seconds, 6),
                          'tasks_after_release': tasks_after_release, 'task_cancelled_id_reused': True,
                          'memory_peak_bytes': memory_peak, 'pids_peak': pids_peak,
                          'oom_delta': memory_after['oom'] - memory_before['oom'],
                          'oom_kill_delta': memory_after['oom_kill'] - memory_before['oom_kill'],
                          'post_pressure_ping': True,
                          'limitations': 'finite active HTTP cancellation under CPU and PID pressure in a route-free netns; no native client, OOM or sustained load'}),
              flush=True)
    finally:
        release_body.set()
        release_tasks.set()
        for thread in task_threads:
            thread.join(timeout=2)
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
