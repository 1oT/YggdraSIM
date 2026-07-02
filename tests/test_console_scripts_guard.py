# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Tests for the HIL-bridge guard in ``yggdrasim_common.console_scripts``.

The guard is the single defensive line that prevents the clean build
or a non-Linux host from trying to import the HIL bridge runtime when
the user accidentally invokes the console entry points
(``yggdrasim-hil-bridge`` / ``yggdrasim-hil-supervisor``).

The bottom block adds a lightweight "every console script resolves"
assertion — it mirrors the release-checklist item about "console
scripts launch via ``--cmd``" without actually spawning 15 subprocesses
(the per-script ``--help`` smoke is covered by the packaging-side
``test_install_scripts`` suite).
"""

from __future__ import annotations

import importlib
import io
import os
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common import console_scripts, flavor


_REPO_ROOT = Path(__file__).resolve().parent.parent


class GuardReturnCodeTests(unittest.TestCase):
    def test_clean_flavor_exits_with_nonzero_code(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            buffer = io.StringIO()
            with mock.patch.object(console_scripts.sys, "stderr", buffer):
                rc = console_scripts._guard_hil_bridge()
            self.assertNotEqual(rc, 0)
            self.assertIn("yggdrasim-hil", buffer.getvalue())

    def test_non_linux_full_exits_with_nonzero_code(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            with mock.patch.object(flavor.sys, "platform", "darwin"):
                buffer = io.StringIO()
                with mock.patch.object(console_scripts.sys, "stderr", buffer):
                    rc = console_scripts._guard_hil_bridge()
                self.assertNotEqual(rc, 0)
                self.assertIn("Linux", buffer.getvalue())
                self.assertIn("yggdrasim-card-bridge", buffer.getvalue())

    def test_full_linux_returns_zero(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "full"}, clear=False):
            with mock.patch.object(flavor.sys, "platform", "linux"):
                rc = console_scripts._guard_hil_bridge()
                self.assertEqual(rc, 0)


class GuardIntegrationWithEntryPointsTests(unittest.TestCase):
    def test_launcher_entry_delegates_to_unified_cli(self) -> None:
        with mock.patch("main.main.run_cli", return_value=0) as mocked_run_cli:
            with mock.patch.object(console_scripts.sys, "argv", ["yggdrasim", "--version"]):
                rc = console_scripts.launcher()

        self.assertEqual(rc, 0)
        mocked_run_cli.assert_called_once_with(["--version"])

    def test_gui_entry_defaults_to_desktop_mode(self) -> None:
        with mock.patch("main.main.run_cli", return_value=0) as mocked_run_cli:
            with mock.patch.object(console_scripts.sys, "argv", ["yggdrasim-gui", "--port", "27860"]):
                rc = console_scripts.gui()

        self.assertEqual(rc, 0)
        mocked_run_cli.assert_called_once_with(["--gui", "--port", "27860"])

    def test_gui_entry_respects_explicit_web_server_mode(self) -> None:
        with mock.patch("main.main.run_cli", return_value=0) as mocked_run_cli:
            with mock.patch.object(
                console_scripts.sys,
                "argv",
                ["yggdrasim-gui", "--web-server", "--token-file", "./tok"],
            ):
                rc = console_scripts.gui()

        self.assertEqual(rc, 0)
        mocked_run_cli.assert_called_once_with(["--web-server", "--token-file", "./tok"])

    def test_web_server_entry_defaults_to_web_server_mode(self) -> None:
        with mock.patch("main.main.run_cli", return_value=0) as mocked_run_cli:
            with mock.patch.object(
                console_scripts.sys,
                "argv",
                ["yggdrasim-web-server", "--token-file", "./tok"],
            ):
                rc = console_scripts.web_server()

        self.assertEqual(rc, 0)
        mocked_run_cli.assert_called_once_with(["--web-server", "--token-file", "./tok"])

    def test_hil_bridge_entry_refuses_on_clean_without_import(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            buffer = io.StringIO()
            with mock.patch.object(console_scripts.sys, "stderr", buffer):
                rc = console_scripts.hil_bridge()
            self.assertNotEqual(rc, 0)

    def test_hil_supervisor_entry_refuses_on_clean_without_import(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            buffer = io.StringIO()
            with mock.patch.object(console_scripts.sys, "stderr", buffer):
                rc = console_scripts.hil_bridge_supervisor()
            self.assertNotEqual(rc, 0)

    def test_card_bridge_entry_is_available_on_clean_flavor(self) -> None:
        with mock.patch.dict(os.environ, {flavor.FLAVOR_ENV: "clean"}, clear=False):
            with mock.patch.object(console_scripts, "_guard_hil_bridge") as mocked_guard:
                with mock.patch.object(console_scripts, "_invoke", return_value=0) as mocked_invoke:
                    rc = console_scripts.card_bridge()

        self.assertEqual(rc, 0)
        mocked_guard.assert_not_called()
        mocked_invoke.assert_called_once_with("Tools.CardBridge.server", "main")


class ConsoleScriptsResolveTests(unittest.TestCase):
    """Every ``[project.scripts]`` entry in ``pyproject.toml`` must resolve.

    Closes the release-checklist item "console scripts launch via
    ``--cmd``" at the import-time level: each entry point must point at
    an importable module attribute. We do not invoke the callables here
    because several of them drop straight into an interactive shell;
    the PyInstaller bundle smoke in ``.github/workflows/build.yml``
    exercises the actual process-launch path.
    """

    def _load_project_scripts(self) -> dict[str, str]:
        with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
            payload = tomllib.load(handle)
        scripts = payload.get("project", {}).get("scripts", {})
        self.assertIsInstance(scripts, dict)
        return dict(scripts)

    def test_every_registered_console_script_resolves_to_callable(self) -> None:
        scripts = self._load_project_scripts()
        self.assertTrue(len(scripts) >= 12)
        for entry_name, target in scripts.items():
            with self.subTest(entry=entry_name, target=target):
                self.assertIn(":", target, msg=f"{entry_name} entry missing attribute separator")
                module_name, attribute_name = target.split(":", 1)
                module = importlib.import_module(module_name)
                attr = getattr(module, attribute_name, None)
                self.assertTrue(
                    callable(attr),
                    msg=f"{entry_name} -> {target} did not resolve to a callable",
                )


if __name__ == "__main__":
    unittest.main()
