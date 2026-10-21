#!/usr/bin/env python3
"""Deterministic numeric-ID wire corpus with an independent Decimal oracle.

No network, packages, authentication, or persistent client configuration required.
"""
from decimal import Decimal
import json
from stdio_exchange import run as paced_run, exchange
import os
from pathlib import Path
import random
import subprocess
import sys

META = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {}}


def main(binary):
    rng = random.Random(20260728)
    numbers = ['0', '-0', '1.0', '1e400', '1e-400', '9007199254740993',
               '9007199254740992', '0.000e-999', '-123.00', '1.0001', '100e-2']
    for _ in range(240):
        whole = str(rng.randrange(1, 10**30))
        fraction = str(rng.randrange(100000)).zfill(5)
        exponent = rng.randrange(-40, 41)
        numbers.append(f'{rng.choice(["", "-"])}{whole}.{fraction}e{exponent}')
    messages = []
    # Opening with valid metadata selects modern error semantics even for bad IDs.
    for number in numbers:
        messages.append('{"jsonrpc":"2.0","id":' + number +
                        ',"method":"tools/list","params":' +
                        json.dumps({'_meta': META}) + '}\n')
    messages.append(json.dumps({'jsonrpc': '2.0', 'id': 'audit',
                    'method': 'resources/read', 'params': {'_meta': META,
                    'uri': 'outbound-guard://logs/audit.json'}}) + '\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('OUTBOUND_GUARD_')}
    result = paced_run([str(Path(binary).resolve())], input=''.join(messages),
                            capture_output=True, text=True, timeout=20, env=env, check=True)
    assert not result.stderr, 'unexpected server diagnostics'
    replies = [json.loads(line, parse_int=Decimal, parse_float=Decimal)
               for line in result.stdout.splitlines()]
    assert len(replies) == len(numbers) + 1
    for number, reply in zip(numbers, replies):
        value = Decimal(number)
        if value == value.to_integral_value():
            assert reply['id'] == value, f'ID changed: {number}'
            assert reply['result']['resultType'] == 'complete'
            assert [tool['name'] for tool in reply['result']['tools']] == ['guarded_fetch']
        else:
            assert 'id' not in reply and reply['error']['code'] == -32600, number
    audit = json.loads(replies[-1]['result']['contents'][0]['text'])
    assert audit['events'] == [], 'listing/invalid IDs dispatched guarded fetch'
    print(f'PASS: {len(numbers)} numeric-ID cases against Decimal oracle; no fetch dispatched')


if __name__ == '__main__':
    main(sys.argv[1])
