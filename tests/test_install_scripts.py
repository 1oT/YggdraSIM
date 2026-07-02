# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Static and smoke tests for the install scripts under ``scripts/install``.

The tests intentionally stay offline:

* presence / permission checks are filesystem-only
* shell syntax validation uses ``bash -n``
* ``--help`` smoke runs never reach the network because each script
  short-circuits inside ``yg_parse_posix_args``
* negative cases (e.g. ``install-macos.sh --flavor full``) exit before
  any package manager or downloader is touched

The Windows PowerShell script is exercised via a text-only shape check
so the test suite stays runnable on Linux / macOS CI hosts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_DIR = REPO_ROOT / "scripts" / "install"

POSIX_SCRIPTS = (
    "install-linux.sh",
    "install-macos.sh",
    "install-raspberrypi.sh",
)
WINDOWS_SCRIPT = "install-windows.ps1"
SHARED_HELPERS = "_common.sh"


class InstallScriptLayoutTests(unittest.TestCase):
    def test_install_directory_exists(self) -> None:
        self.assertTrue(INSTALL_DIR.is_dir(), f"missing: {INSTALL_DIR}")

    def test_readme_exists_and_references_all_scripts(self) -> None:
        readme = INSTALL_DIR / "README.md"
        self.assertTrue(readme.is_file())
        text = readme.read_text(encoding="utf-8")
        for script in POSIX_SCRIPTS + (WINDOWS_SCRIPT,):
            self.assertIn(script, text, f"README.md missing mention of {script}")

    def test_all_posix_scripts_present_and_executable(self) -> None:
        for script in POSIX_SCRIPTS:
            path = INSTALL_DIR / script
            self.assertTrue(path.is_file(), f"missing: {path}")
            self.assertTrue(os.access(path, os.X_OK), f"not executable: {path}")

    def test_common_helpers_present(self) -> None:
        path = INSTALL_DIR / SHARED_HELPERS
        self.assertTrue(path.is_file(), f"missing: {path}")

    def test_windows_script_present(self) -> None:
        path = INSTALL_DIR / WINDOWS_SCRIPT
        self.assertTrue(path.is_file(), f"missing: {path}")


@unittest.skipIf(shutil.which("bash") is None, "bash not available")
class PosixShellSyntaxTests(unittest.TestCase):
    def _bash_check(self, relative_path: str) -> None:
        path = INSTALL_DIR / relative_path
        result = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"bash -n failed for {relative_path}: {result.stderr}",
        )

    def test_common_helpers_syntax(self) -> None:
        self._bash_check(SHARED_HELPERS)

    def test_linux_script_syntax(self) -> None:
        self._bash_check("install-linux.sh")

    def test_macos_script_syntax(self) -> None:
        self._bash_check("install-macos.sh")

    def test_raspberrypi_script_syntax(self) -> None:
        self._bash_check("install-raspberrypi.sh")


@unittest.skipIf(shutil.which("bash") is None, "bash not available")
class PosixHelpOutputTests(unittest.TestCase):
    def _run_help(self, script_name: str) -> subprocess.CompletedProcess[str]:
        path = INSTALL_DIR / script_name
        return subprocess.run(
            ["bash", str(path), "--help"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=10,
        )

    def test_linux_help_lists_flavor_and_mode(self) -> None:
        result = self._run_help("install-linux.sh")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--flavor", result.stdout)
        self.assertIn("--mode", result.stdout)
        self.assertIn("--with-gui", result.stdout)
        self.assertIn("clean|full", result.stdout)

    def test_macos_help_lists_flavor_and_mode(self) -> None:
        result = self._run_help("install-macos.sh")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--flavor", result.stdout)
        self.assertIn("--mode", result.stdout)
        self.assertIn("--with-gui", result.stdout)

    def test_raspberrypi_help_lists_flavor_and_mode(self) -> None:
        result = self._run_help("install-raspberrypi.sh")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--flavor", result.stdout)
        self.assertIn("--mode", result.stdout)
        self.assertIn("--with-gui", result.stdout)


@unittest.skipIf(shutil.which("bash") is None, "bash not available")
class PosixNegativePathTests(unittest.TestCase):
    """The scripts must refuse invalid flavor/host combinations cleanly."""

    def _run(self, script_name: str, *args: str) -> subprocess.CompletedProcess[str]:
        path = INSTALL_DIR / script_name
        return subprocess.run(
            ["bash", str(path), *args],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=10,
        )

    def test_macos_script_rejects_full_flavor(self) -> None:
        result = self._run("install-macos.sh", "--flavor", "full")
        self.assertNotEqual(result.returncode, 0)
        combined = (result.stdout + result.stderr).lower()
        self.assertIn("linux-only", combined)

    def test_linux_script_rejects_unknown_mode(self) -> None:
        result = self._run("install-linux.sh", "--mode", "magic")
        self.assertNotEqual(result.returncode, 0)
        combined = (result.stdout + result.stderr).lower()
        self.assertIn("mode", combined)

    def test_linux_script_rejects_unknown_flavor(self) -> None:
        result = self._run("install-linux.sh", "--flavor", "sparkle")
        self.assertNotEqual(result.returncode, 0)


class WindowsScriptShapeTests(unittest.TestCase):
    """Light-touch validation of the PowerShell script without running it."""

    def test_expected_parameters_declared(self) -> None:
        text = (INSTALL_DIR / WINDOWS_SCRIPT).read_text(encoding="utf-8")
        for token in (
            "$Flavor",
            "$Mode",
            "$Version",
            "$InstallDir",
            "$RepoRoot",
            "$WithGui",
            "'clean'",
            "'full'",
            "'release'",
            "'source'",
        ):
            self.assertIn(token, text, f"install-windows.ps1 missing {token}")

    def test_rejects_full_flavor_early(self) -> None:
        text = (INSTALL_DIR / WINDOWS_SCRIPT).read_text(encoding="utf-8")
        self.assertIn("Linux-only", text)

    def test_resolves_release_url_helper(self) -> None:
        text = (INSTALL_DIR / WINDOWS_SCRIPT).read_text(encoding="utf-8")
        self.assertIn("Resolve-YgReleaseUrl", text)
        self.assertIn("latest/download", text)


class CiWorkflowCoverageTests(unittest.TestCase):
    """CI matrix must publish every artefact the install scripts target."""

    def test_build_workflow_contains_expected_jobs(self) -> None:
        workflow = REPO_ROOT / ".github" / "workflows" / "build.yml"
        self.assertTrue(workflow.is_file())
        text = workflow.read_text(encoding="utf-8")
        for job in (
            "build-linux-x86_64",
            "build-linux-arm64-clean",
            "build-linux-arm64-full",
            "build-windows-clean",
            "build-macos-clean",
            "build-linux-deb-clean",
        ):
            self.assertIn(job, text, f".github/workflows/build.yml missing job {job}")

    def test_workflow_publishes_arm64_full_artifact(self) -> None:
        workflow = REPO_ROOT / ".github" / "workflows" / "build.yml"
        text = workflow.read_text(encoding="utf-8")
        self.assertIn("yggdrasim-linux-arm64-full-", text)

    def test_workflow_publishes_gui_companion_artifacts(self) -> None:
        workflow = REPO_ROOT / ".github" / "workflows" / "build.yml"
        text = workflow.read_text(encoding="utf-8")
        for asset in (
            "yggdrasim-gui-linux-x86_64-clean",
            "yggdrasim-gui-linux-x86_64-full",
            "yggdrasim-gui-linux-arm64-clean",
            "yggdrasim-gui-linux-arm64-full",
            "yggdrasim-gui-macos-arm64-clean",
            "yggdrasim-gui-windows-x86_64-clean.exe",
        ):
            self.assertIn(asset, text)


if __name__ == "__main__":
    unittest.main()
