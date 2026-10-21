#!/usr/bin/env python3
"""Linux stdio stress probe: oversized frames stay bounded and do not desync RPC."""

import fcntl
import json
import os
import resource
import signal
import subprocess
import sys
import threading
import time


def frame(method, id_):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method}).encode() + b"\n"


def run(binary, megabytes, suffix=b""):
    env = os.environ.copy()
    env.pop("OUTBOUND_GUARD_ALLOWED_HOSTS", None)
    process = subprocess.Popen([binary], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        chunk = b"x" * (1024 * 1024)
        for _ in range(megabytes):
            process.stdin.write(chunk)
        process.stdin.write(suffix)
        process.stdin.close()
        process.wait(timeout=20)
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        assert process.returncode == 0, process.returncode
        assert not stderr, stderr[:200]
        return [json.loads(line) for line in stdout.splitlines()]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def deadline_cases(binary):
    env = {key: value for key, value in os.environ.items() if not key.startswith("OUTBOUND_GUARD_")}
    children = []
    stop = threading.Event()
    worker = None
    streamed = [0]
    writes = []
    try:
        for payload in (b'{"marker":"PRIVATE_PARTIAL_MARKER"', b"x" * (128 * 1024), b""):
            child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            children.append(child)
            child.stdin.write(payload)
            child.stdin.flush()
        # Keep a fourth peer sending new bytes until the server closes stdin.
        # Nonblocking writes plus a stop event keep cleanup bounded on failure.
        flowing = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env)
        children.append(flowing)
        os.set_blocking(flowing.stdin.fileno(), False)

        def stream():
            chunk = b"CONTINUOUS_PRIVATE_MARKER" * 170
            while not stop.is_set():
                try:
                    count = os.write(flowing.stdin.fileno(), chunk)
                    streamed[0] += count
                    now = time.monotonic()
                    if not writes:
                        writes.extend([now, now])
                    else:
                        writes[1] = now
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    return
                stop.wait(0.02)

        worker = threading.Thread(target=stream)
        worker.start()
        start = time.monotonic()
        for child in (children[0], children[1], flowing):
            child.wait(timeout=13)
            assert child.returncode != 0
            assert child.stdout.read() == b""
            error = child.stderr.read()
            assert b"Input frame deadline exceeded" in error and b"PRIVATE_PARTIAL_MARKER" not in error, error
            assert b"CONTINUOUS_PRIVATE_MARKER" not in error, error
        assert 9 <= time.monotonic() - start <= 13
        assert streamed[0] > 64 * 1024, "continuous writer never crossed the frame cap"
        assert writes[1] - writes[0] >= 9, "stream did not stay active until the deadline"
        idle = children[2]
        assert idle.poll() is None, "idle client was terminated"
        stdout, stderr = idle.communicate(frame("ping", 18), timeout=3)
        assert idle.returncode == 0 and not stderr
        assert json.loads(stdout)["id"] == 18
    finally:
        stop.set()
        if worker is not None:
            worker.join(timeout=1)
            assert not worker.is_alive(), "continuous writer did not stop"
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()


def output_client_controls(binary):
    env = {key: value for key, value in os.environ.items() if not key.startswith("OUTBOUND_GUARD_")}
    marker = "PRIVATE_OUTPUT_MARKER" * 1000
    # Drain a response larger than the backpressure fixture's pipe. A valid
    # large ID must survive byte-for-byte, including a following normal reply.
    result = subprocess.run([binary], input=frame("ping", marker) + frame("ping", 19),
                            capture_output=True, env=env, timeout=6, check=True)
    assert not result.stderr
    assert [json.loads(line) for line in result.stdout.splitlines()] == [
        {"jsonrpc": "2.0", "id": marker, "result": {}},
        {"jsonrpc": "2.0", "id": 19, "result": {}},
    ]
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    try:
        # Keep stdin open: exit must follow the write failure, not input EOF.
        child.stdout.close()
        start = time.monotonic()
        child.stdin.write(frame("ping", marker))
        child.stdin.flush()
        child.wait(timeout=3)
        assert child.returncode != 0
        error = child.stderr.read()
        assert b"Broken pipe" in error and b"PRIVATE_OUTPUT_MARKER" not in error, error
        print(f"stdout client controls: large-ID reply and subsequent ping intact; closed reader exited in {time.monotonic() - start:.2f}s without ID echo on stderr")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def output_backpressure(binary):
    env = {key: value for key, value in os.environ.items() if not key.startswith("OUTBOUND_GUARD_")}
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    try:
        # A valid ping ID yields a response larger than this deliberately unread
        # pipe. No network, tool execution or unbounded parent buffering needed.
        fcntl.fcntl(child.stdout, fcntl.F_SETPIPE_SZ, 4096)
        marker = "PRIVATE_OUTPUT_MARKER" * 1000
        start = time.monotonic()
        child.stdin.write(frame("ping", marker))
        child.stdin.flush()
        child.wait(timeout=6)
        elapsed = time.monotonic() - start
        assert child.returncode != 0 and 2 <= elapsed <= 6
        stderr = child.stderr.read()
        assert b"Output write deadline exceeded" in stderr and b"PRIVATE_OUTPUT_MARKER" not in stderr, stderr
        # Bytes already written cannot be retracted. No complete JSON reply may
        # escape; clients must discard the partial frame and reconnect.
        partial = child.stdout.read()
        assert partial and b"\n" not in partial and len(partial) <= 4096
        print(f"stdout backpressure probe: unread 4 KiB pipe terminated in {elapsed:.2f}s; fixed diagnostic, partial transport frame only")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def main(binary):
    signal.alarm(45)
    replies = run(binary, 160, b"\n" + frame("ping", 17))
    assert len(replies) == 2, replies
    assert replies[0]["error"]["code"] == -32600
    assert replies[0]["error"]["message"] == "Request too large"
    assert replies[1]["id"] == 17 and replies[1]["result"] == {}

    # EOF without a newline must still reject the oversized frame and exit.
    eof_replies = run(binary, 8)
    assert len(eof_replies) == 1, eof_replies
    assert eof_replies[0]["error"]["code"] == -32600

    deadline_cases(binary)
    output_backpressure(binary)
    output_client_controls(binary)

    # Linux reports ru_maxrss in KiB. Keep headroom for runtime and CI variance.
    peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    assert peak_kib < 128 * 1024, f"stdio child peak RSS {peak_kib} KiB"
    signal.alarm(0)
    print(f"stdio resource probe: 160 MiB newline and 8 MiB EOF frames rejected, ping recovered, stalled/continuous partial-frame deadlines and idle recovery verified, child peak RSS {peak_kib} KiB")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.platform != "linux":
        raise SystemExit("usage (Linux only): stdio_resource_probe.py PATH_TO_SERVER")
    main(sys.argv[1])
