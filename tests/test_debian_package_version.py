"""Guard Debian upgrade ordering across candidate commits."""
import importlib.util
from pathlib import Path
import subprocess
import unittest


spec = importlib.util.spec_from_file_location(
    "candidate", Path(__file__).resolve().parents[1] / "tools/package_candidate.py")
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class DebianPackageVersionTests(unittest.TestCase):
    def test_candidate_versions_upgrade_in_main_commit_order(self):
        historical = "0.1.0~candidate+g70b03efa49f3"
        first = candidate.debian_package_version("0.1.0", "ffffffffffff0000", 119)
        second = candidate.debian_package_version("0.1.0", "000000000000abcd", 120)
        for older, newer in ((historical, first), (first, second), (second, "0.1.0")):
            with self.subTest(older=older, newer=newer):
                subprocess.run(["dpkg", "--compare-versions", older, "lt", newer], check=True)


if __name__ == "__main__":
    unittest.main()
