#!/usr/bin/env python3
"""Linux stdio stress probe: oversized frames stay bounded and do not desync RPC."""

import json
import os
import resource
import subprocess
import sys


def frame(method, id_):
    return json.dumps({"jsonrpc": "2.0", "id": id_, "method": method}).encode() + b"\n"


def run(binary, payload):
    env = os.environ.copy()
    env.pop("OUTBOUND_GUARD_ALLOWED_HOSTS", None)
    result = subprocess.run([binary], input=payload, capture_output=True,
                            env=env, timeout=20, check=True)
    assert not result.stderr, result.stderr[:200]
    return [json.loads(line) for line in result.stdout.splitlines()]


def main(binary):
    oversized = b"x" * (8 * 1024 * 1024)
    replies = run(binary, oversized + b"\n" + frame("ping", 17))
    assert len(replies) == 2, replies
    assert replies[0]["error"]["code"] == -32600
    assert replies[0]["error"]["message"] == "Request too large"
    assert replies[1]["id"] == 17 and replies[1]["result"] == {}

    # EOF without a newline must still reject the oversized frame and exit.
    eof_replies = run(binary, oversized)
    assert len(eof_replies) == 1, eof_replies
    assert eof_replies[0]["error"]["code"] == -32600

    # Linux reports ru_maxrss in KiB. Keep headroom for runtime and CI variance.
    peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    assert peak_kib < 128 * 1024, f"stdio child peak RSS {peak_kib} KiB"
    print(f"stdio resource probe: 8 MiB newline/EOF frames rejected, ping recovered, child peak RSS {peak_kib} KiB")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.platform != "linux":
        raise SystemExit("usage (Linux only): stdio_resource_probe.py PATH_TO_SERVER")
    main(sys.argv[1])
