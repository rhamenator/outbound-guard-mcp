"""Independent artifact comparison rejects corrupt provenance and unequal inputs."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('comparison', Path(__file__).resolve().parents[1] / 'tools/compare_candidates.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


def archive(files, root='candidate'):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tar:
        for name, data in files:
            entry = tarfile.TarInfo(root + '/' + name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def candidate(binary=b'executable', source_byte=b'input', compiler='rustc fixture', root='candidate', corrupt=False):
    source = archive([('Cargo.lock', b'locked'), ('src/main.rs', source_byte)], root='source')
    build = dict(target='fixture', profile='release', locked=True, jobs=2,
                 toolchain_channel='fixture', rustc_verbose_version=compiler, cargo_version='cargo fixture',
                 cargo_lock_sha256=comparison.digest(b'locked'), source_archive_sha256=comparison.digest(source))
    provenance = dict(revision=root, binary_sha256=comparison.digest(binary), build=build,
                      version='0.1.0', platform='fixture', license='GPL-3.0-or-later', candidate=True, stable_release=False)
    return archive([('bin/outbound-guard-mcp', b'tampered' if corrupt else binary),
                    ('source.tar.gz', source), ('provenance.json', json.dumps(provenance).encode())], root=root)


class CandidateComparisonTests(unittest.TestCase):
    def inspect(self, data):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'candidate.tar.gz'
            path.write_bytes(data)
            return comparison.inspect(path)

    def test_revision_and_tar_root_do_not_change_source_comparison(self):
        left = self.inspect(candidate(root='commit-a'))
        right = self.inspect(candidate(root='commit-b'))
        self.assertNotEqual(left['archive_sha256'], right['archive_sha256'])
        self.assertTrue(comparison.compare(left, right)['matching'])

    def test_compiler_source_and_executable_mismatches_fail(self):
        left = self.inspect(candidate())
        for changed, field in [(dict(compiler='another rustc'), 'settings'),
                               (dict(source_byte=b'changed source'), 'source_files_sha256'),
                               (dict(binary=b'changed executable'), 'binary_sha256')]:
            with self.subTest(field=field):
                report = comparison.compare(left, self.inspect(candidate(**changed)))
                self.assertFalse(report['matching'])
                self.assertIn(field, report['differences'])

    def test_tampering_and_duplicate_members_fail(self):
        with self.assertRaises(ValueError):
            self.inspect(candidate(corrupt=True))
        with self.assertRaises(ValueError):
            comparison.members(archive([('one', b'a'), ('one', b'b')]))
        with self.assertRaises(ValueError):
            comparison.members(archive([('../escape', b'a')]))


if __name__ == '__main__':
    unittest.main()
