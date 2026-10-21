"""Check inventory integrity gates with an isolated fake registry cache."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("candidate", Path(__file__).resolve().parents[1] / "tools/package_candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        crate = self.root / "registry/src/test-index/fixture-1.0.0"
        crate.mkdir(parents=True)
        self.notice = crate / "LICENSE"
        self.notice.write_bytes(b"Synthetic fixture notice\n")
        self.archive = self.root / "registry/cache/test-index/fixture-1.0.0.crate"
        self.archive.parent.mkdir(parents=True)
        with tarfile.open(self.archive, "w:gz") as tar:
            entry = tarfile.TarInfo("fixture-1.0.0/LICENSE")
            entry.size = self.notice.stat().st_size
            tar.addfile(entry, io.BytesIO(self.notice.read_bytes()))
        source = "registry+https://github.com/rust-lang/crates.io-index"
        checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.root / "Cargo.lock").write_text(f'[[package]]\nname="fixture"\nversion="1.0.0"\nsource="{source}"\nchecksum="{checksum}"\n')
        metadata = {"packages":[{"id":"root"},{"id":"fixture","name":"fixture","version":"1.0.0",
            "source":source,"manifest_path":str(crate / "Cargo.toml"),"license":"MIT","license_file":None}],
            "resolve":{"root":"root","nodes":[{"id":"root","deps":[{"pkg":"fixture","dep_kinds":[{"kind":None}]}]},
                {"id":"fixture","deps":[],"features":[]}]}}
        mock = patch.object(candidate.subprocess, "check_output", return_value=json.dumps(metadata).encode())
        mock.start()
        self.addCleanup(mock.stop)

    def test_inventory_preserves_notice_without_host_paths(self):
        files = candidate.dependency_files(self.root)
        data = files["dependency-inventory.json"]
        self.assertNotIn(str(self.root).encode(), data)
        package = json.loads(data)["packages"][0]
        self.assertEqual(package["license_expression"], "MIT")
        self.assertEqual(files[package["notice_files"][0]], self.notice.read_bytes())

    def test_changed_notice_is_rejected(self):
        self.notice.write_bytes(b"X" * self.notice.stat().st_size)
        with self.assertRaises(AssertionError):
            candidate.dependency_files(self.root)

    def test_changed_archive_is_rejected(self):
        with self.archive.open("ab") as archive:
            archive.write(b"changed")
        with self.assertRaises(AssertionError):
            candidate.dependency_files(self.root)


if __name__ == "__main__":
    unittest.main()
