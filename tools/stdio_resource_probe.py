#!/usr/bin/env python3
"""Linux stdio stress probe: oversized frames stay bounded and do not desync RPC."""

import json
import os
import resource
import signal
import subprocess
import sys
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
    try:
        for payload in (b'{"marker":"PRIVATE_PARTIAL_MARKER"', b"x" * (128 * 1024), b""):
            child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            children.append(child)
            child.stdin.write(payload)
            child.stdin.flush()
        start = time.monotonic()
        for child in children[:2]:
            child.wait(timeout=13)
            assert child.returncode != 0
            assert child.stdout.read() == b""
            error = child.stderr.read()
            assert b"Input frame deadline exceeded" in error and b"PRIVATE_PARTIAL_MARKER" not in error, error
        assert 9 <= time.monotonic() - start <= 13
        idle = children[2]
        assert idle.poll() is None, "idle client was terminated"
        stdout, stderr = idle.communicate(frame("ping", 18), timeout=3)
        assert idle.returncode == 0 and not stderr
        assert json.loads(stdout)["id"] == 18
    finally:
        for child in children:
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

    # Linux reports ru_maxrss in KiB. Keep headroom for runtime and CI variance.
    peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    assert peak_kib < 128 * 1024, f"stdio child peak RSS {peak_kib} KiB"
    signal.alarm(0)
    print(f"stdio resource probe: 160 MiB newline and 8 MiB EOF frames rejected, ping recovered, partial-frame deadlines and idle recovery verified, child peak RSS {peak_kib} KiB")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.platform != "linux":
        raise SystemExit("usage (Linux only): stdio_resource_probe.py PATH_TO_SERVER")
    main(sys.argv[1])
