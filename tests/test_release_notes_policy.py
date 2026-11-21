# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Release-note policy: what a production tag may publish as its notes.

The v2.1.0 release page carried the tagged commit's message, because the
checkout action re-points ``refs/tags/<tag>`` at the commit and the local-tag
read published what it found. ``scripts/release/release_notes.py`` now judges
the tag message and the changelog before a platform builds and compares the
page with the notes afterwards; these tests pin what it refuses.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "release" / "release_notes.py"


def _load():
    spec = importlib.util.spec_from_file_location("test_release_notes_module", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_notes = _load()

TAG = "v2.4.0"
GOOD_NOTES = """YggdraSIM v2.4.0

Feature release on the 2.x line. Notable changes:

- The first change, described on
  two lines.
- The second change.

Security:

- A hardening.
"""
COMMIT_MESSAGE = """Restore the annotated tag object before the release policy judges it

The tag run failed in "Fail closed for production tags" on its first
check of the tag itself.
"""
CLEAN_CHANGELOG = """# Changelog

## [Unreleased]

## [2.4.0] -- 2026-09-20

### Added

- The first change.

## [2.3.0] -- 2026-08-31

### Fixed

- An older fix.
"""


class TagMessageTests(unittest.TestCase):
    def test_release_note_passes_and_is_normalised(self) -> None:
        crlf = GOOD_NOTES.replace("\n", "  \r\n") + "\r\n\r\n"
        self.assertEqual(release_notes.check_notes(TAG, crlf, COMMIT_MESSAGE), GOOD_NOTES)

    def test_commit_message_is_refused(self) -> None:
        with self.assertRaisesRegex(
            release_notes.ReleaseNotesError, "tagged commit's message"
        ):
            release_notes.check_notes(TAG, COMMIT_MESSAGE, COMMIT_MESSAGE)

    def test_commit_subject_heading_is_named(self) -> None:
        notes = COMMIT_MESSAGE.split("\n", 1)[0] + "\n\n- A change.\n"
        with self.assertRaisesRegex(
            release_notes.ReleaseNotesError, "tagged commit's subject"
        ):
            release_notes.check_notes(TAG, notes, COMMIT_MESSAGE)

    def test_commit_subject_equal_to_the_heading_is_not_a_false_positive(self) -> None:
        commit = "YggdraSIM v2.4.0\n\nBump the version.\n"
        self.assertEqual(release_notes.check_notes(TAG, GOOD_NOTES, commit), GOOD_NOTES)

    def test_empty_message_is_refused(self) -> None:
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "is empty"):
            release_notes.check_notes(TAG, "\n\n", COMMIT_MESSAGE)

    def test_bare_version_is_refused(self) -> None:
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "must open with"):
            release_notes.check_notes(TAG, "v2.4.0\n", COMMIT_MESSAGE)

    def test_heading_for_another_version_is_refused(self) -> None:
        notes = GOOD_NOTES.replace("YggdraSIM v2.4.0", "YggdraSIM v2.3.0", 1)
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "must open with"):
            release_notes.check_notes(TAG, notes, COMMIT_MESSAGE)

    def test_note_without_a_list_is_refused(self) -> None:
        notes = "YggdraSIM v2.4.0\n\nBug fixes and improvements.\n"
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "lists no change"):
            release_notes.check_notes(TAG, notes, COMMIT_MESSAGE)

    def test_trailer_is_refused(self) -> None:
        notes = GOOD_NOTES + "\nSigned-off-by: A Maintainer <maintainer@example.com>\n"
        with self.assertRaisesRegex(
            release_notes.ReleaseNotesError, r"trailer on line 13 \(Signed-off-by:\)"
        ):
            release_notes.check_notes(TAG, notes, COMMIT_MESSAGE)

    def test_signature_block_is_dropped(self) -> None:
        signed = (
            GOOD_NOTES
            + "-----BEGIN PGP SIGNATURE-----\n\nabcdef\n-----END PGP SIGNATURE-----\n"
        )
        self.assertEqual(release_notes.check_notes(TAG, signed, COMMIT_MESSAGE), GOOD_NOTES)

    def test_tag_without_v_prefix_is_refused(self) -> None:
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "v<version>"):
            release_notes.version_of("2.4.0")


class ChangelogTests(unittest.TestCase):
    def test_clean_changelog_passes(self) -> None:
        release_notes.check_changelog("2.4.0", CLEAN_CHANGELOG)

    def test_entries_under_unreleased_are_refused(self) -> None:
        changelog = CLEAN_CHANGELOG.replace(
            "## [Unreleased]\n",
            "## [Unreleased]\n\n### Added\n\n- Shipped but filed as unreleased.\n",
            1,
        )
        with self.assertRaisesRegex(
            release_notes.ReleaseNotesError, r"2 line\(s\) under \[Unreleased\]"
        ):
            release_notes.check_changelog("2.4.0", changelog)

    def test_html_comment_under_unreleased_is_not_an_entry(self) -> None:
        changelog = CLEAN_CHANGELOG.replace(
            "## [Unreleased]\n", "## [Unreleased]\n\n<!-- nothing yet -->\n", 1
        )
        release_notes.check_changelog("2.4.0", changelog)

    def test_missing_version_section_is_refused(self) -> None:
        with self.assertRaisesRegex(
            release_notes.ReleaseNotesError, r"no '## \[2\.5\.0\] -- YYYY-MM-DD' section"
        ):
            release_notes.check_changelog("2.5.0", CLEAN_CHANGELOG)

    def test_version_heading_without_a_date_is_refused(self) -> None:
        changelog = CLEAN_CHANGELOG.replace("## [2.4.0] -- 2026-09-20", "## [2.4.0]", 1)
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "no '## \\[2\\.4\\.0\\]"):
            release_notes.check_changelog("2.4.0", changelog)

    def test_empty_version_section_is_refused(self) -> None:
        changelog = CLEAN_CHANGELOG.replace("### Added\n\n- The first change.\n", "", 1)
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "section is empty"):
            release_notes.check_changelog("2.4.0", changelog)

    def test_changelog_without_an_unreleased_heading_passes(self) -> None:
        release_notes.check_changelog("2.4.0", CLEAN_CHANGELOG.replace("## [Unreleased]\n", ""))


class PublishedBodyTests(unittest.TestCase):
    def test_body_matches_across_line_endings(self) -> None:
        release_notes.check_published(GOOD_NOTES, GOOD_NOTES.replace("\n", "\r\n"))

    def test_different_body_is_refused(self) -> None:
        with self.assertRaisesRegex(release_notes.ReleaseNotesError, "differs"):
            release_notes.check_published(GOOD_NOTES, COMMIT_MESSAGE)


class CommandLineTests(unittest.TestCase):
    def _run(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(
            GIT_AUTHOR_NAME="Release Test",
            GIT_AUTHOR_EMAIL="release@example.test",
            GIT_COMMITTER_NAME="Release Test",
            GIT_COMMITTER_EMAIL="release@example.test",
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd or REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def test_check_with_files_writes_the_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.txt").write_text(GOOD_NOTES + "\n", encoding="utf-8")
            (root / "commit.txt").write_text(COMMIT_MESSAGE, encoding="utf-8")
            (root / "CHANGELOG.md").write_text(CLEAN_CHANGELOG, encoding="utf-8")
            result = self._run(
                "check",
                "--tag",
                TAG,
                "--notes",
                str(root / "notes.txt"),
                "--commit-message",
                str(root / "commit.txt"),
                "--changelog",
                str(root / "CHANGELOG.md"),
                "--output",
                str(root / "body.md"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("release notes for v2.4.0", result.stdout)
            self.assertEqual((root / "body.md").read_text(encoding="utf-8"), GOOD_NOTES)

            (root / "notes.txt").write_text(COMMIT_MESSAGE, encoding="utf-8")
            result = self._run(
                "check",
                "--tag",
                TAG,
                "--notes",
                str(root / "notes.txt"),
                "--commit-message",
                str(root / "commit.txt"),
                "--changelog",
                str(root / "CHANGELOG.md"),
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("release-notes policy: the v2.4.0 tag message is the tagged", result.stderr)

    def test_published_compares_the_page_with_the_notes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.md").write_text(GOOD_NOTES, encoding="utf-8")
            (root / "body.md").write_text(GOOD_NOTES.replace("\n", "\r\n"), encoding="utf-8")
            result = self._run(
                "published", "--notes", str(root / "notes.md"), "--body", str(root / "body.md")
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / "body.md").write_text(COMMIT_MESSAGE, encoding="utf-8")
            result = self._run(
                "published", "--notes", str(root / "notes.md"), "--body", str(root / "body.md")
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("differs from the checked release notes", result.stderr)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_check_reads_the_annotated_tag_from_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = ["git", "-c", "init.defaultBranch=main"]
            env = dict(os.environ)
            env.update(
                GIT_AUTHOR_NAME="Release Test",
                GIT_AUTHOR_EMAIL="release@example.test",
                GIT_COMMITTER_NAME="Release Test",
                GIT_COMMITTER_EMAIL="release@example.test",
            )

            def run(*args: str) -> None:
                subprocess.run(
                    [*git, *args], cwd=root, env=env, check=True, capture_output=True, timeout=60
                )

            run("init", "--quiet")
            (root / "CHANGELOG.md").write_text(CLEAN_CHANGELOG, encoding="utf-8")
            run("add", "CHANGELOG.md")
            run("commit", "--quiet", "-m", COMMIT_MESSAGE)
            run("tag", "-a", TAG, "-m", GOOD_NOTES)
            run("tag", "v2.4.1")

            result = self._run("check", "--tag", TAG, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("[Unreleased] empty", result.stdout)

            result = self._run("check", "--tag", "v2.4.1", cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("is a commit in this checkout, not an annotated tag", result.stderr)


if __name__ == "__main__":
    unittest.main()
