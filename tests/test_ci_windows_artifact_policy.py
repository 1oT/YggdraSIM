# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contracts for the manual Windows-only artifact workflow."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "windows-test-artifact.yml"
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


class WindowsArtifactWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_is_manual_only_and_main_guarded(self) -> None:
        on_block = self.text.split("on:\n", 1)[1].split("\nconcurrency:", 1)[0]
        self.assertEqual(on_block.strip(), "workflow_dispatch:")
        for forbidden in ("push:", "pull_request:", "schedule:"):
            self.assertNotIn(forbidden, on_block)
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"', self.text)
        self.assertIn("github.ref == 'refs/heads/main'", self.text)
        self.assertRegex(
            self.text,
            r"(?m)^permissions:\s*\n  contents: read\s*$",
        )

    def test_builds_only_windows_with_pinned_actions(self) -> None:
        self.assertIn("runs-on: windows-latest", self.text)
        for forbidden in ("macos-", "setup-qemu", "matrix:", "linux-arm64"):
            self.assertNotIn(forbidden, self.text.lower())

        action_refs = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.text)
        self.assertEqual(len(action_refs), 4)
        for action_ref in action_refs:
            self.assertRegex(action_ref, PINNED_ACTION)
        checkout = self.text.split("Checkout the requested revision", 1)[1].split(
            "- name: Set up Python",
            1,
        )[0]
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn("ref: ${{ github.sha }}", checkout)

    def test_windows_bundle_and_remote_lab_contracts_are_exercised(self) -> None:
        for marker in (
            "tests/test_remote_cross_platform_boundary.py",
            "tests/test_remote_lab.py",
            "tests/test_gui_card_bridge_actions.py",
            "tests/test_gui_card_bridge_actions_http.py",
            "tests/test_apdu_relay_service.py",
            "tests/test_card_backend_relay_token.py",
            "tests/test_hil_bridge_card_relay.py",
            "tests/test_secure_files_windows.py",
            "PyInstaller --noconfirm --clean yggdrasim_main.spec",
            "yggdrasim-clean.exe --version",
            "yggdrasim-gui-clean.exe --version",
            "scripts/release/validate_release.py artifact",
        ):
            self.assertIn(marker, self.text)

    def test_actions_artifact_is_attempted_without_losing_fallback(self) -> None:
        upload = self.text.split("Try the GitHub Actions artifact service", 1)[
            1
        ].split("- name: Create the isolated Windows draft", 1)[0]
        self.assertIn("continue-on-error: true", upload)
        self.assertIn(
            "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
            upload,
        )
        self.assertIn("retention-days: 1", upload)
        self.assertIn("compression-level: 0", upload)
        self.assertIn("steps.actions-artifact.outcome", self.text)

    def test_release_fallback_is_unique_draft_and_never_overwrites(self) -> None:
        self.assertIn(
            "ci-windows-main-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT",
            self.text,
        )
        self.assertIn(
            "$env:SHORT_SHA-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT",
            self.text,
        )
        for marker in (
            "gh release create",
            "--draft",
            "--prerelease",
            "--latest=false",
            "--target $env:GITHUB_SHA",
            "gh release upload",
            "UNSIGNED TEST BUILD",
        ):
            self.assertIn(marker, self.text)
        for forbidden in (
            "--clobber",
            "gh release delete",
            "git push --force",
            "--draft=false",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_downloaded_release_asset_is_verified_before_complete(self) -> None:
        for marker in (
            "gh release download",
            "Get-FileHash -Algorithm SHA256",
            "Unexpected draft asset set",
            "Malformed SHA-256 sidecar",
            "Expand-Archive",
            "Unexpected archive contents",
            "Downloaded CLI smoke test failed",
            "Downloaded GUI smoke test failed",
            "COMPLETE — WINDOWS UNSIGNED TEST BUILD",
            "INCOMPLETE — WINDOWS UNSIGNED TEST BUILD",
            "if: ${{ failure() }}",
        ):
            self.assertIn(marker, self.text)


if __name__ == "__main__":
    unittest.main()
