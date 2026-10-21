#!/usr/bin/env python3
"""Verify standalone CLI diagnostics without external endpoints or credentials."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main(binary, version):
    env = {key: value for key, value in os.environ.items() if not key.startswith('OUTBOUND_GUARD_')}
    marker = 'synthetic-private-config-marker'
    def run(args, changes=None, success=True):
        result = subprocess.run([binary, *args], input='', capture_output=True, text=True,
                                env={**env, **(changes or {})}, timeout=10)
        assert (result.returncode == 0) == success, (args, result.returncode)
        assert marker not in result.stdout + result.stderr
        if success:
            assert not result.stderr
        else:
            assert not result.stdout and result.stderr
        return result.stdout
    invalid = {'OUTBOUND_GUARD_ALLOWED_HOSTS': marker + ',127.0.0.1',
               'OUTBOUND_GUARD_EXTRA_CA_CERT': '/nonexistent/' + marker}
    # Help/version must remain available even when startup configuration is invalid.
    assert run(['--version'], invalid).strip() == 'outbound-guard-mcp ' + version
    help_text = run(['--help'], invalid)
    assert all(value in help_text for value in ('--check-config', 'OUTBOUND_GUARD_ALLOWED_HOSTS',
                                                'OUTBOUND_GUARD_EXTRA_CA_CERT', 'Experimental'))
    assert json.loads(run(['--check-config'])) == {
        'valid': True, 'scope': 'startup', 'allowed_host_count': 0, 'network_checked': False}
    configured = json.loads(run(['--check-config'], {
        'OUTBOUND_GUARD_ALLOWED_HOSTS': 'Example.com, example.com,other.example'}))
    assert configured['allowed_host_count'] == 2 and configured['network_checked'] is False
    run(['--check-config'], {'OUTBOUND_GUARD_ALLOWED_HOSTS': marker + ',127.0.0.1'}, success=False)
    run(['--check-config'], {'OUTBOUND_GUARD_EXTRA_CA_CERT': '/nonexistent/' + marker}, success=False)
    with tempfile.TemporaryDirectory(prefix='guard-cli-') as directory:
        path = Path(directory) / marker
        path.write_text('not a certificate ' + marker)
        run(['--check-config'], {'OUTBOUND_GUARD_EXTRA_CA_CERT': str(path)}, success=False)
    for args in ([marker], ['--version', marker], ['--help', '--version']):
        run(args, success=False)
    print('CLI smoke: help/version, valid/invalid configuration, redaction and unknown-argument rejection passed')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: cli_smoke.py PATH_TO_SERVER EXPECTED_VERSION')
    main(os.path.abspath(sys.argv[1]), sys.argv[2])
