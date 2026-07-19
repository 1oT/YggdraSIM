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
LINUX_GUI_RUNTIME_PACKAGES = (
    "libegl1",
    "libgl1",
    "libxkbcommon-x11-0",
    "libxcb-cursor0",
    "libxcb-keysyms1",
    "libxcb-shape0",
    "libxcb-icccm4",
)


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

    def test_full_linux_installers_verify_exact_remsim_client_binary(self) -> None:
        helpers = (INSTALL_DIR / SHARED_HELPERS).read_text(encoding="utf-8")
        exact_package = helpers.index("yg_apt_install osmo-remsim-client-st2")
        compatibility_package = helpers.index("yg_apt_install osmo-remsim-client || true")
        self.assertLess(exact_package, compatibility_package)
        self.assertIn("command -v osmo-remsim-client-st2", helpers)
        self.assertIn(
            "yg_die \"required HIL executable 'osmo-remsim-client-st2'",
            helpers,
        )
        for script in ("install-linux.sh", "install-raspberrypi.sh"):
            text = (INSTALL_DIR / script).read_text(encoding="utf-8")
            self.assertIn("yg_install_remsim_client", text)

    def test_linux_gui_installers_include_qt_xcb_runtime_dependencies(self) -> None:
        for script in ("install-linux.sh", "install-raspberrypi.sh"):
            text = (INSTALL_DIR / script).read_text(encoding="utf-8")
            for package in LINUX_GUI_RUNTIME_PACKAGES:
                self.assertIn(package, text, f"{script} missing {package}")

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

    def test_workflow_builds_and_packages_linux_gui_runtime_dependencies(
        self,
    ) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "build.yml"
        ).read_text(encoding="utf-8")
        x86_job = workflow.split("build-linux-x86_64:", 1)[1].split(
            "build-linux-arm64-clean:",
            1,
        )[0]
        deb_job = workflow.split("build-linux-deb-clean:", 1)[1].split(
            "publish-release:",
            1,
        )[0]

        for package in LINUX_GUI_RUNTIME_PACKAGES:
            self.assertIn(package, x86_job)
            self.assertIn(package, deb_job)

    def test_workflow_artifacts_use_short_retention(self) -> None:
        build_workflow = (
            REPO_ROOT / ".github" / "workflows" / "build.yml"
        ).read_text(encoding="utf-8")
        docker_workflow = (
            REPO_ROOT / ".github" / "workflows" / "docker.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            build_workflow.count("uses: actions/upload-artifact@v6"),
            6,
        )
        build_lines = build_workflow.splitlines()
        upload_indexes = [
            index
            for index, line in enumerate(build_lines)
            if "uses: actions/upload-artifact@v6" in line
        ]
        for upload_index in upload_indexes:
            next_step = next(
                (
                    index
                    for index in range(upload_index + 1, len(build_lines))
                    if build_lines[index].startswith("      - name:")
                ),
                len(build_lines),
            )
            upload_step = "\n".join(build_lines[upload_index:next_step])
            self.assertIn("retention-days: 7", upload_step)

        docker_lines = docker_workflow.splitlines()
        build_index = next(
            index
            for index, line in enumerate(docker_lines)
            if "uses: docker/build-push-action@v7" in line
        )
        next_step = next(
            (
                index
                for index in range(build_index + 1, len(docker_lines))
                if docker_lines[index].startswith("      - name:")
            ),
            len(docker_lines),
        )
        docker_step = "\n".join(docker_lines[build_index:next_step])
        self.assertIn('DOCKER_BUILD_RECORD_RETENTION_DAYS: "7"', docker_step)


if __name__ == "__main__":
    unittest.main()
