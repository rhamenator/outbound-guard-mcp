"""Candidate evidence integrity and redacted fail-before-execution policy."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).resolve().parents[1] / 'tools/package_candidate.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class BuildEvidenceTests(unittest.TestCase):
    def test_internal_path_flags_preserve_argument_boundaries_and_reject_overrides(self):
        env = {'CARGO_HOME': '/cache with spaces', 'KEEP': 'unchanged'}
        result = candidate.candidate_build_env(Path('/source with spaces'), Path('/target with spaces'), env)
        self.assertEqual(result['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'), [
            '--remap-path-prefix=/source with spaces=/build/source',
            '--remap-path-prefix=/cache with spaces=/build/cargo',
            '--remap-path-prefix=/target with spaces=/build/target'])
        self.assertEqual(result['KEEP'], 'unchanged')
        self.assertNotIn('CARGO_ENCODED_RUSTFLAGS', env)
        with self.assertRaises(RuntimeError):
            candidate.candidate_build_env(Path('/source'), Path('/target'), {'RUSTFLAGS':'private override'})

    def test_candidate_requires_exact_pinned_compiler_and_cargo(self):
        evidence = dict(toolchain_channel='1.99.1', rustc_verbose_version='rustc fixture\nrelease: 1.99.1',
                        cargo_version='cargo 1.99.1 (fixture)')
        candidate.verify_build_compiler(evidence)
        for changes in [dict(toolchain_channel='stable'), dict(toolchain_channel='1.99'),
                        dict(rustc_verbose_version='release: 1.96.0'),
                        dict(cargo_version='cargo 1.96.0 (fixture)')]:
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                candidate.verify_build_compiler(evidence | changes)

    def test_override_values_are_never_echoed(self):
        for key in ['RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS',
                    'CARGO_PROFILE_RELEASE_LTO', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER']:
            with self.subTest(key=key), patch.object(candidate.subprocess, 'check_output') as run:
                with self.assertRaises(RuntimeError) as error:
                    candidate.reject_build_overrides({key:'SYNTHETIC_PRIVATE_OVERRIDE'})
                self.assertIn(key, str(error.exception))
                self.assertNotIn('SYNTHETIC_PRIVATE_OVERRIDE', str(error.exception))
                run.assert_not_called()
        candidate.reject_build_overrides({'RUSTFLAGS':'', 'RUSTUP_TOOLCHAIN':'stable', 'HOME':'private'})

    def test_evidence_binds_inputs_and_records_actual_versions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Cargo.lock').write_bytes(b'synthetic-lock')
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "fixture-channel"\n')
            with patch.object(candidate.subprocess, 'check_output', side_effect=[b'rustc synthetic\nhost: fixture\n', b'cargo synthetic\n']) as run:
                evidence = candidate.build_evidence(root, b'synthetic-archive')
            self.assertEqual(evidence['cargo_lock_sha256'], candidate.digest(b'synthetic-lock'))
            self.assertEqual(evidence['source_archive_sha256'], candidate.digest(b'synthetic-archive'))
            self.assertEqual(evidence['rustc_verbose_version'], 'rustc synthetic\nhost: fixture')
            self.assertEqual(evidence['cargo_version'], 'cargo synthetic')
            self.assertEqual(evidence['toolchain_channel'], 'fixture-channel')
            self.assertTrue(all(call.kwargs['cwd'] == root for call in run.call_args_list))
            self.assertNotIn(folder, json.dumps(evidence))


if __name__ == '__main__':
    unittest.main()
