"""Paced transport for non-overload probes; no retries or suppressed server errors.

Each ordinary request is followed by its actual response before the next frame.
Dedicated overload/cancellation/backpressure probes use their own concurrent I/O.
"""
import json
import queue
import subprocess
import threading
import time


def exchange(process, payload, timeout):
    textual = isinstance(payload, str)
    lf = '\n' if textual else b'\n'
    frames = payload.split(lf)
    received = queue.Queue()
    def read():
        for line in process.stdout:
            received.put(line)
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    timer = threading.Timer(timeout, process.kill)
    timer.start()
    output = []
    try:
        for i, frame in enumerate(frames):
            last = i == len(frames) - 1
            if last and not frame:
                break
            data = frame if last else frame + lf
            process.stdin.write(data)
            process.stdin.flush()
            if last:
                process.stdin.close()
            expects = True
            try:
                message = json.loads(frame)
                if (isinstance(message, dict) and message.get('jsonrpc') == '2.0'
                        and isinstance(message.get('method'), str) and 'id' not in message):
                    expects = False
            except (ValueError, UnicodeError):
                pass
            if expects:
                output.append(received.get(timeout=max(.01, deadline - time.monotonic())))
        if not process.stdin.closed:
            process.stdin.close()
        process.wait(timeout=max(.01, deadline - time.monotonic()))
        reader.join(timeout=1)
        while not received.empty():
            output.append(received.get_nowait())
        return (('' if textual else b'').join(output), process.stderr.read())
    except (queue.Empty, BrokenPipeError):
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        raise
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait()
        if not process.stdin.closed:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        reader.join(timeout=1)
        process.stdout.close()
        process.stderr.close()


def run(args, *, input, env=None, timeout=20, text=False, capture_output=True, check=True):
    assert capture_output
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=text, env=env)
    stdout, stderr = exchange(process, input, timeout)
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args, stdout, stderr)
    return result
