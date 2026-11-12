"""The package archive must not inherit the builder's process umask."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "candidate", Path(__file__).resolve().parents[1] / "tools/package_candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class DebianPackageReproducibilityTests(unittest.TestCase):
    def test_umask_does_not_change_package_bytes_or_directory_modes(self):
        revision = candidate.git("rev-parse", "HEAD").decode().strip()
        previous_umask = os.umask(0o022)
        try:
            with tempfile.TemporaryDirectory() as folder:
                outputs = []
                for index, mask in enumerate((0o002, 0o022, 0o077)):
                    output = Path(folder) / str(index)
                    output.mkdir()
                    os.umask(mask)
                    package = candidate.debian_candidate(
                        b"fixture-binary", "0.1.0", revision, 1, 1700000000,
                        output, b"fixture-source", {}, b"fixture-provenance")
                    outputs.append(package.read_bytes())
                    payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
                    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                        directories = [entry for entry in archive if entry.isdir()]
                    self.assertTrue(directories)
                    self.assertTrue(all(entry.mode == 0o755 for entry in directories))
                for package_bytes in outputs[1:]:
                    self.assertEqual(outputs[0], package_bytes)
        finally:
            os.umask(previous_umask)


if __name__ == "__main__":
    unittest.main()
