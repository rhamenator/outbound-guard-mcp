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

    def test_dependency_sources_are_locked_and_compared_without_extraction(self):
        files = comparison.members(candidate())
        dependency = b'opaque original crate archive'
        checksum = comparison.digest(dependency)
        registry = 'registry+https://github.com/rust-lang/crates.io-index'
        lock = (f'[[package]]\nname="fixture"\nversion="1.0.0"\nsource="{registry}"\nchecksum="{checksum}"\n').encode()
        source = archive([('Cargo.lock', lock), ('src/main.rs', b'input')], root='source')
        provenance = json.loads(files['provenance.json'])
        provenance['build']['cargo_lock_sha256'] = comparison.digest(lock)
        provenance['build']['source_archive_sha256'] = comparison.digest(source)
        path = 'dependency-sources/fixture-1.0.0.crate'
        files.update({'source.tar.gz': source, 'provenance.json': json.dumps(provenance).encode(),
                      path: dependency, 'dependency-inventory.json': json.dumps({'schema_version':2,
                      'packages':[{'name':'fixture','version':'1.0.0','source':registry,
                      'checksum_sha256':checksum,'source_archive':path}]}).encode()})
        valid = self.inspect(archive(files.items()))
        self.assertTrue(comparison.compare(valid, self.inspect(archive(files.items())))['matching'])
        historical = self.inspect(candidate())
        self.assertNotEqual(valid['dependency_sources_sha256'], historical['dependency_sources_sha256'])
        for mutation in ('tamper', 'missing', 'unlisted', 'missing-reference'):
            damaged = dict(files)
            if mutation == 'tamper':
                damaged[path] = b'modified source'
            elif mutation == 'missing':
                del damaged[path]
            elif mutation == 'unlisted':
                damaged['dependency-sources/extra.crate'] = b'unlisted'
            else:
                inv = json.loads(damaged['dependency-inventory.json'])
                del inv['packages'][0]['source_archive']
                damaged['dependency-inventory.json'] = json.dumps(inv).encode()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.inspect(archive(damaged.items()))

    def test_tampering_and_duplicate_members_fail(self):
        with self.assertRaises(ValueError):
            self.inspect(candidate(corrupt=True))
        with self.assertRaises(ValueError):
            comparison.members(archive([('one', b'a'), ('one', b'b')]))
        with self.assertRaises(ValueError):
            comparison.members(archive([('../escape', b'a')]))


if __name__ == '__main__':
    unittest.main()
