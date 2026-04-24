"""
Unit tests for ``yggdrasim_common.flavor``.

The flavor module is the single source of truth for distinguishing the
published SKUs (``clean`` / ``full`` / ``source``). These tests exercise
the env-override path, the normalize aliases, the HIL gating predicates,
and the friendly descriptor used by ``--version`` and the launcher
banner. They intentionally avoid asserting on a specific host's flavor
so the test run stays deterministic inside CI matrix jobs that run on
Linux, macOS, and Windows.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from yggdrasim_common import flavor


class FlavorNormalizationTests(unittest.TestCase):
    def test_known_values_pass_through(self) -> None:
        self.assertEqual(flavor.normalize_flavor("clean"), flavor.FLAVOR_CLEAN)
        self.assertEqual(flavor.normalize_flavor("full"), flavor.FLAVOR_FULL)
        self.assertEqual(flavor.normalize_flavor("source"), flavor.FLAVOR_SOURCE)

    def test_aliases_resolve_to_canonical(self) -> None:
        for alias in ("lite", "slim", "minimal", "no-hil"):
            self.assertEqual(flavor.normalize_flavor(alias), flavor.FLAVOR_CLEAN)
        for alias in ("hil", "all", "complete"):
            self.assertEqual(flavor.normalize_flavor(alias), flavor.FLAVOR_FULL)
        for alias in ("src", "dev", "editable"):
            self.assertEqual(flavor.normalize_flavor(alias), flavor.FLAVOR_SOURCE)

    def test_whitespace_and_case_are_ignored(self) -> None:
        self.assertEqual(flavor.normalize_flavor("  CLEAN  "), flavor.FLAVOR_CLEAN)
        self.assertEqual(flavor.normalize_flavor("Full"), flavor.FLAVOR_FULL)

    def test_unknown_value_returns_empty(self) -> None:
        self.assertEqual(flavor.normalize_flavor("rainbow"), "")
        self.assertEqual(flavor.normalize_flavor(""), "")


class FlavorResolutionTests(unittest.TestCase):
    def test_env_override_wins(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            self.assertEqual(flavor.get_flavor(), flavor.FLAVOR_CLEAN)
            self.assertEqual(flavor.get_flavor_source(), "env")
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "FULL"}, clear=False):
            self.assertEqual(flavor.get_flavor(), flavor.FLAVOR_FULL)

    def test_unknown_env_falls_back_to_default(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "banana"}, clear=False):
            resolved = flavor.get_flavor()
            self.assertIn(resolved, flavor.KNOWN_FLAVORS)


class FlavorPredicateTests(unittest.TestCase):
    def test_clean_omits_hil_bridge(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            self.assertFalse(flavor.is_hil_bridge_included())
            reason = flavor.hil_bridge_unavailable_reason()
            self.assertIn("clean", reason.lower())

    def test_full_includes_hil_bridge_on_linux(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            self.assertTrue(flavor.is_hil_bridge_included())
            with mock.patch.object(flavor.sys, "platform", "linux"):
                self.assertTrue(flavor.is_hil_bridge_supported_platform())
                self.assertEqual(flavor.hil_bridge_unavailable_reason(), "")

    def test_full_on_non_linux_reports_reason(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            with mock.patch.object(flavor.sys, "platform", "win32"):
                self.assertFalse(flavor.is_hil_bridge_supported_platform())
                reason = flavor.hil_bridge_unavailable_reason()
                self.assertIn("Linux", reason)

    def test_source_includes_hil_bridge(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "source"}, clear=False):
            self.assertTrue(flavor.is_hil_bridge_included())


class FlavorDescriptionTests(unittest.TestCase):
    def test_describe_flavor_is_human_readable(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            self.assertIn("clean", flavor.describe_flavor().lower())
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            self.assertIn("full", flavor.describe_flavor().lower())
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "source"}, clear=False):
            self.assertIn("source", flavor.describe_flavor().lower())


if __name__ == "__main__":
    unittest.main()
