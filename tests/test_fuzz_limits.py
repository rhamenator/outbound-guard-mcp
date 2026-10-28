"""Invalid operator inputs must fail before builds or output-directory mutation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class FuzzLimits(unittest.TestCase):
    def test_unsupported_inputs_do_not_start_campaign_setup(self):
        script = Path(__file__).resolve().parents[1] / 'tools/policy_fuzz.sh'
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'not-created'
            for target, seconds in [('rpc', '0'), ('rpc', '59'), ('rpc', '61'),
                                    ('rpc', '601'), ('rpc', '999999999999999999999'),
                                    ('rpc', '60;echo unexpected'), ('unknown', '60')]:
                with self.subTest(target=target, seconds=seconds):
                    env = dict(os.environ, LIBFUZZER_RUNTIME='/must-not-be-read',
                               POLICY_FUZZ_OUTPUT=str(output), POLICY_FUZZ_TARGET=target,
                               POLICY_FUZZ_SECONDS=seconds)
                    result = subprocess.run(['bash', str(script)], env=env,
                                            capture_output=True, timeout=3)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse(output.exists())
