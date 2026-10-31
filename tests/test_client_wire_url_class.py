"""The native bridge must not retain arbitrary client-supplied URL text."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from client_wire_url_class import fixture_url_class  # noqa: E402


class FixtureUrlClassTests(unittest.TestCase):
    def test_known_fixture_urls_have_fixed_labels(self):
        self.assertEqual(fixture_url_class("https://tls-handshake.test/plain"), "tls_fixture")
        self.assertEqual(fixture_url_class("http://allowed.test/plain"), "allowed_plain")

    def test_unknown_inputs_cannot_leak_secret_url_text(self):
        marker = "ghp_" + "A" * 20
        self.assertEqual(fixture_url_class("http://allowed.test/" + marker), "other")
        self.assertEqual(fixture_url_class("https://tls-handshake.test/plain?token=" + marker), "other")
        self.assertEqual(fixture_url_class(None), "missing")
        self.assertEqual(fixture_url_class([marker]), "non_string")


if __name__ == "__main__":
    unittest.main()
