"""Probe transport pacing must preserve replies and enforce a wall-clock bound."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('exchange', Path(__file__).resolve().parents[1] / 'tools/stdio_exchange.py')
exchange = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exchange)


class ExchangeTests(unittest.TestCase):
    def test_notifications_and_eof_frame_preserve_actual_replies(self):
        program = ('import sys,json\nfor line in sys.stdin:\n m=json.loads(line)\n'
                   ' if "id" in m: print(json.dumps({"id":m["id"]}),flush=True)\n')
        frames = [{'jsonrpc':'2.0','id':1,'method':'ping'},
                  {'jsonrpc':'2.0','method':'notification'},
                  {'jsonrpc':'2.0','id':2,'method':'ping'}]
        payload = '\n'.join(json.dumps(v) for v in frames)  # final frame ends at EOF
        result = exchange.run([sys.executable, '-u', '-c', program], input=payload,
                              text=True, timeout=5, env=os.environ.copy())
        self.assertEqual([json.loads(line)['id'] for line in result.stdout.splitlines()], [1, 2])
        self.assertFalse(result.stderr)

    def test_unresponsive_child_is_killed_at_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            exchange.run([sys.executable, '-c', 'import time;time.sleep(60)'],
                         input=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', timeout=.2)


if __name__ == '__main__':
    unittest.main()
