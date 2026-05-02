"""
Unit tests for the single-source version resolver in
``yggdrasim_common.__about__``.

The resolver must:

* return a non-empty string
* match the ``pyproject.toml`` version when the suite is run from a
  source checkout
* fall back to the literal ``"0.0.0+unknown"`` only when both lookups
  fail
"""

import re
import unittest
from pathlib import Path

from yggdrasim_common import __about__
from yggdrasim_common.__about__ import get_version


def _pyproject_version() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match is not None, "pyproject.toml is missing a [project] version"
    return match.group(1).strip()


class VersionResolutionTests(unittest.TestCase):
    def test_get_version_is_non_empty(self) -> None:
        value = get_version()
        self.assertIsInstance(value, str)
        self.assertTrue(len(value) > 0)

    def test_about_module_exports_version_constant(self) -> None:
        self.assertEqual(__about__.__version__, get_version())

    def test_source_checkout_version_matches_pyproject(self) -> None:
        pyproject = _pyproject_version()
        self.assertEqual(get_version(), pyproject)


if __name__ == "__main__":
    unittest.main()
