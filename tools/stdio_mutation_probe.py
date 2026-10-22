#!/usr/bin/env python3
"""Seeded black-box frame mutation and recovery; finite corpus, not coverage-guided fuzzing."""
import hashlib
import json
import os
from pathlib import Path
import queue
import random
import subprocess
import sys
import threading
import time


SEED = 0x4D43504652414D45
META = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {}}
MARKER = b'SYNTHETIC_PRIVATE_FRAME_MARKER'


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def corpus():
    rng = random.Random(SEED)
    seeds = [encode({'jsonrpc': '2.0', 'id': 'mutation', 'method': 'ping', 'params': params})
             for params in ({}, {'_meta': META})]
    result = [b'', b' ', b'\r', b'null', b'true', b'[]', b'{}', b'1e9999', b'"unterminated',
              b'\x00' + MARKER, b'\xff' + MARKER, b'{"private":"' + MARKER + b'",}']
    # Every non-LF ASCII control at three framing positions; LF has its own delimiter tests.
    for control in (*range(32), 127):
        if control == 10:
            continue
        result.extend([bytes([control]) + seeds[0], seeds[0] + bytes([control]),
                       seeds[0][:10] + bytes([control]) + seeds[0][10:]])
    for depth in (16, 127, 128, 129, 256, 1024):
        result.append(b'[' * depth + b'0' + b']' * depth)
    for _ in range(512):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            at = rng.randrange(len(data) + 1)
            op = rng.randrange(4)
            if op == 0 and at < len(data):
                del data[at:min(len(data), at + rng.randint(1, 8))]
            elif op == 1 and at < len(data):
                data[at] = rng.choice([b for b in range(256) if b != 10])
            elif op == 2:
                data[at:at] = bytes(rng.choice([b for b in range(256) if b != 10]) for _ in range(rng.randint(1, 8)))
            else:
                data[at:at] = rng.choice([b'null', b'{}', b'[]', b'\\u0000', b'"', b'\\', b'1e9999'])
        result.append(bytes(data))
    assert all(b'\n' not in frame and len(frame) <= 4096 for frame in result)
    return result


def run(binary, era, frames):
    env = {key: value for key, value in os.environ.items() if not key.startswith('OUTBOUND_GUARD_')}
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    replies = queue.Queue(maxsize=16)
    def read():
        try:
            while line := child.stdout.readline(65537):
                if len(line) > 65536:
                    raise ValueError('unbounded response frame')
                replies.put(line, timeout=2)
        except Exception as error:
            replies.put(error, timeout=2)
    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    timer = threading.Timer(30, child.kill)
    timer.start()
    started = time.monotonic()
    peak_rss = peak_fds = 0
    def request(method, id_, params=None):
        args = dict(params or {})
        if era == 'modern':
            args['_meta'] = META
        return {'jsonrpc': '2.0', 'id': id_, 'method': method, 'params': args}
    def receive():
        item = replies.get(timeout=3)
        if isinstance(item, Exception):
            raise item
        assert MARKER not in item, 'private malformed frame reflected'
        message = json.loads(item)
        assert isinstance(message, dict) and message.get('jsonrpc') == '2.0'
        assert ('result' in message) != ('error' in message)
        if 'error' in message:
            assert type(message['error']['code']) is int and isinstance(message['error']['message'], str)
        return message
    def send(message):
        child.stdin.write(encode(message) + b'\n')
        child.stdin.flush()
    try:
        if era == 'legacy':
            send({'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize', 'params': {
                'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'mutation-probe', 'version': '1'}}})
            assert receive()['id'] == 'init'
            send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        send(request('ping', 'control'))
        control = receive()['result']
        controls = [control]
        # The same process accepts per-request modern metadata alongside legacy framing.
        for params in ({}, {'_meta': META}):
            send({'jsonrpc': '2.0', 'id': 'other-control', 'method': 'ping', 'params': params})
            response = receive()
            if 'result' in response:
                controls.append(response['result'])
        for index, frame in enumerate(frames):
            anchor = f'recovery-{index}'
            ending = b'\r\n' if index % 2 else b'\n'
            child.stdin.write(frame + ending + encode(request('ping', anchor)) + ending)
            child.stdin.flush()
            reply = receive()
            if reply.get('id') != anchor:
                if 'result' in reply:
                    assert reply['result'] in controls, (era, index, 'unexpected dispatch')
                reply = receive()
            assert reply.get('id') == anchor and reply.get('result') == control, (era, index, reply)
            if index % 32 == 0:
                status = Path(f'/proc/{child.pid}/status').read_text()
                rss = int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))
                peak_rss = max(peak_rss, rss)
                peak_fds = max(peak_fds, len(list(Path(f'/proc/{child.pid}/fd').iterdir())))
        send(request('resources/read', 'audit', {'uri': 'outbound-guard://logs/audit.json'}))
        audit = receive()
        assert audit['id'] == 'audit'
        assert json.loads(audit['result']['contents'][0]['text'])['events'] == []
        child.stdin.close()
        assert child.wait(timeout=3) == 0
        worker.join(timeout=2)
        assert not worker.is_alive() and replies.empty()
        assert not child.stderr.read(), 'unexpected diagnostic or panic'
        assert peak_rss < 65536 and peak_fds < 32, (peak_rss, peak_fds)
        print(f'{era} frame mutation: {len(frames)} cases, recovery after every frame, empty audit; '
              f'{time.monotonic()-started:.2f}s, sampled peak {peak_rss} KiB/{peak_fds} FDs')
    finally:
        timer.cancel()
        if child.poll() is None:
            child.kill()
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            try:
                stream.close()
            except BrokenPipeError:
                pass
        worker.join(timeout=2)


def main(binary):
    frames = corpus()
    digest = hashlib.sha256(b''.join(len(frame).to_bytes(4, 'big') + frame for frame in frames)).hexdigest()
    print(f'frame mutation corpus: seed={SEED}; cases={len(frames)}; sha256={digest}')
    for era in ('legacy', 'modern'):
        run(binary, era, frames)


if __name__ == '__main__':
    main(str(Path(sys.argv[1]).resolve()))
