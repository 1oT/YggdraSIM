# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Security and release-policy contracts for CI fallback distribution.

The main-branch fallback deliberately bypasses the Actions artifact service by
placing visibly unsigned test bundles on a private draft GitHub Release.  These
tests keep that narrowly scoped escape hatch from becoming an automatic or
production publishing path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DRAFT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "main-test-release.yml"
PRODUCTION_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build.yml"
CLEANUP_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci-draft-cleanup.yml"

PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
TAG_ONLY_CONDITION = "if: startsWith(github.ref, 'refs/tags/v')"
PINNED_UPLOAD_ACTION = (
    "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f"
)
PINNED_ATTEST_ACTION = (
    "actions/attest-build-provenance@"
    "977bb373ede98d70efdf65b84cb5f73e068dcc2a"
)

EXPECTED_WRITE_JOBS = {
    "bootstrap",
    "build-linux-x86_64",
    "build-linux-arm64",
    "build-windows-clean",
    "build-macos-clean",
    "finalize",
}

EXPECTED_PRIMARY_ASSET_MARKERS = (
    "yggdrasim-linux-x86_64-clean-UNSIGNED-TEST-",
    "yggdrasim-linux-x86_64-full-UNSIGNED-TEST-",
    "yggdrasim-clean_",
    "yggdrasim-linux-arm64-clean-UNSIGNED-TEST-",
    "yggdrasim-linux-arm64-full-UNSIGNED-TEST-",
    "yggdrasim-windows-x86_64-clean-UNSIGNED-TEST-",
    "yggdrasim-macos-arm64-clean-UNSIGNED-UNNOTARIZED-TEST-",
)


def _read(path: Path) -> str:
    if not path.is_file():
        raise AssertionError(f"required workflow is missing: {path}")
    return path.read_text(encoding="utf-8")


def _top_level_block(text: str, key: str) -> str:
    """Return a top-level YAML block without requiring a YAML dependency."""

    match = re.search(rf"(?m)^{re.escape(key)}:\s*$", text)
    if match is None:
        raise AssertionError(f"workflow is missing top-level {key!r} block")
    following = re.search(r"(?m)^[A-Za-z0-9_-]+:\s*$", text[match.end() :])
    end = len(text) if following is None else match.end() + following.start()
    return text[match.start() : end]


def _job_blocks(text: str) -> dict[str, str]:
    """Split the ``jobs`` mapping into blocks keyed by job id."""

    jobs = _top_level_block(text, "jobs")
    matches = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", jobs))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(jobs)
        blocks[match.group(1)] = jobs[match.start() : end]
    return blocks


def _step_containing(text: str, needle: str) -> str:
    """Return the six-space-indented step containing ``needle``."""

    lines = text.splitlines()
    needle_index = next(
        (index for index, line in enumerate(lines) if needle in line),
        None,
    )
    if needle_index is None:
        raise AssertionError(f"workflow step containing {needle!r} is missing")

    start = needle_index
    while start >= 0 and not lines[start].startswith("      - "):
        start -= 1
    if start < 0:
        raise AssertionError(f"could not find start of workflow step for {needle!r}")

    end = start + 1
    while end < len(lines) and not lines[end].startswith("      - "):
        end += 1
    return "\n".join(lines[start:end])


def _steps(text: str) -> list[str]:
    """Return all six-space-indented workflow steps."""

    lines = text.splitlines()
    starts = [
        index for index, line in enumerate(lines) if line.startswith("      - ")
    ]
    return [
        "\n".join(
            lines[
                start : starts[index + 1] if index + 1 < len(starts) else len(lines)
            ]
        )
        for index, start in enumerate(starts)
    ]


def _bash_array_entries(text: str, name: str) -> list[str]:
    """Extract the non-comment entries from an explicit multiline Bash array."""

    match = re.search(
        rf"(?ms)^\s*{re.escape(name)}=\(\s*$\n"
        rf"(?P<body>.*?)^\s*\)\s*$",
        text,
    )
    if match is None:
        raise AssertionError(f"workflow is missing explicit {name} Bash array")
    return [
        line.strip()
        for line in match.group("body").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class DraftReleaseFallbackPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _read(DRAFT_WORKFLOW)
        cls.jobs = _job_blocks(cls.text)

    def test_is_manual_only_with_read_only_default_permissions(self) -> None:
        triggers = _top_level_block(self.text, "on")
        trigger_names = re.findall(
            r"(?m)^  ([A-Za-z0-9_-]+):(?:\s*.*)?$",
            triggers,
        )
        self.assertEqual(trigger_names, ["workflow_dispatch"])
        for forbidden_trigger in (
            "push:",
            "pull_request:",
            "pull_request_target:",
            "schedule:",
        ):
            self.assertNotIn(forbidden_trigger, triggers)

        self.assertRegex(
            self.text,
            r"(?m)^permissions:\s*\n  contents: read\s*$",
        )

    def test_actions_are_sha_pinned_and_checkout_credentials_do_not_persist(
        self,
    ) -> None:
        action_refs = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.text)
        self.assertTrue(action_refs, "fallback workflow must use pinned actions")
        for action_ref in action_refs:
            self.assertRegex(
                action_ref,
                PINNED_ACTION,
                f"action is not pinned to a full commit SHA: {action_ref}",
            )

        checkout_steps = [
            step
            for step in _steps(self.text)
            if re.search(r"(?m)^\s*uses:\s*actions/checkout@", step)
        ]
        self.assertTrue(checkout_steps, "fallback workflow must check out exact source")
        for checkout_step in checkout_steps:
            self.assertRegex(
                checkout_step,
                r"(?m)^\s+persist-credentials:\s*false\s*$",
            )

    def test_release_is_bound_to_exact_main_sha_and_unique_draft_tag(self) -> None:
        main_guard_steps = [
            step
            for step in re.split(r"(?m)(?=^      - )", self.text)
            if "refs/heads/main" in step
        ]
        self.assertTrue(main_guard_steps, "exact main-ref guard is missing")
        self.assertTrue(
            any(
                re.search(r"(?m)^\s*set\s+-[^\n]*e", step)
                and re.search(
                    r'test\s+"\$\{GITHUB_REF\}"\s*=\s*"refs/heads/main"',
                    step,
                )
                for step in main_guard_steps
            ),
            "main-ref check must use an errexit-protected exact test",
        )
        self.assertTrue(
            any(
                re.search(
                    r"(?s)(?:GITHUB_REF|\$\{\{\s*github\.ref\s*\}\})"
                    r".{0,160}refs/heads/main"
                    r"|refs/heads/main.{0,160}"
                    r"(?:GITHUB_REF|\$\{\{\s*github\.ref\s*\}\})",
                    step,
                )
                for step in main_guard_steps
            ),
            "guard must compare the exact GitHub ref with refs/heads/main",
        )

        self.assertIn(
            "ci-main-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
            self.text,
        )
        create_step = _step_containing(self.text, "gh release create")
        for option in ("--draft", "--prerelease", "--latest=false"):
            self.assertIn(option, create_step)
        self.assertRegex(
            create_step,
            r'--target\s+["\']?\$\{?GITHUB_SHA\}?["\']?',
        )
        self.assertIn("UNSIGNED TEST BUILD", create_step)
        finalize = self.jobs.get("finalize", "")
        self.assertIn(
            "--json targetCommitish",
            finalize,
            "finalizer must verify the draft's exact target commit",
        )
        self.assertNotIn(
            'git rev-list -n 1 "${TEST_TAG}"',
            finalize,
            "a tag created after checkout is not guaranteed to exist locally",
        )
        self.assertNotIn(
            "git/ref/tags/${TEST_TAG}",
            finalize,
            "a draft tag identifier is not a Git ref until publication",
        )

    def test_fallback_has_no_overwrite_force_delete_or_publish_escape_hatch(
        self,
    ) -> None:
        lowered = self.text.lower()
        for forbidden in (
            "--clobber",
            "gh release delete",
            "gh api --method delete",
            "git push --force",
            "git push -f",
            "git tag -f",
            "git tag --force",
            "--draft=false",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertNotRegex(
            lowered,
            r"gh\s+api[^\n]*(?:--method|-x)\s+delete",
        )

    def test_release_write_permissions_are_job_scoped_and_allowlisted(self) -> None:
        write_jobs = {
            job_id
            for job_id, block in self.jobs.items()
            if re.search(
                r"(?m)^    permissions:\s*\n(?:      .+\n)*?"
                r"      contents:\s*write\s*$",
                block,
            )
        }
        self.assertEqual(write_jobs, EXPECTED_WRITE_JOBS)

        for job_id, block in self.jobs.items():
            if job_id not in EXPECTED_WRITE_JOBS:
                self.assertNotRegex(block, r"(?m)^\s+contents:\s*write\s*$")

    def test_exact_seven_primary_assets_have_individual_sidecars(self) -> None:
        self.assertEqual(len(EXPECTED_PRIMARY_ASSET_MARKERS), 7)
        for marker in EXPECTED_PRIMARY_ASSET_MARKERS:
            self.assertIn(marker, self.text)

        primary_entries = _bash_array_entries(
            self.jobs.get("finalize", ""),
            "EXPECTED_PRIMARY_ASSETS",
        )
        self.assertEqual(len(primary_entries), 7)
        self.assertTrue(
            all(".sha256" not in entry for entry in primary_entries),
            "the primary-asset array must not include checksum sidecars",
        )
        self.assertRegex(
            self.text,
            r'\$\{#EXPECTED_PRIMARY_ASSETS\[@\]\}.{0,20}'
            r"(?:-eq|-ne|==|!=)\s+7",
        )
        self.assertRegex(
            self.text,
            r'(?s)for\s+\w+\s+in\s+"\$\{EXPECTED_PRIMARY_ASSETS\[@\]\}"'
            r".{0,300}EXPECTED_SIDECARS\+="
            r'\(["\']?\$\{?\w+\}?\.sha256',
            "sidecar list must be derived for every primary asset",
        )

        self.assertIn("dpkg-deb --build", self.text)
        self.assertIn("dpkg-deb --info", self.text)
        self.assertIn("dpkg-deb --contents", self.text)

    def test_finalize_fails_closed_and_verifies_complete_download(self) -> None:
        finalize = self.jobs.get("finalize", "")
        self.assertTrue(finalize, "fallback workflow is missing finalize job")
        self.assertIn("always()", finalize)
        self.assertIn("INCOMPLETE", finalize)
        self.assertIn("COMPLETE", finalize)
        self.assertGreaterEqual(finalize.count("gh release download"), 2)
        self.assertGreaterEqual(finalize.count("sha256sum -c"), 2)
        self.assertIn("scripts/release/generate_sbom.py", finalize)
        self.assertIn("SHA256SUMS", finalize)
        self.assertRegex(
            finalize,
            r"(?:diff\s+-u|comm\s+-3)",
            "finalize must compare the exact expected and downloaded asset sets",
        )
        self.assertIn("gh release edit", finalize)
        self.assertNotIn("--draft=false", finalize)


class ProductionReleaseIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _read(PRODUCTION_WORKFLOW)
        cls.jobs = _job_blocks(cls.text)

    def test_production_actions_are_pinned_and_checkout_is_non_persistent(
        self,
    ) -> None:
        action_refs = re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", self.text)
        self.assertTrue(action_refs)
        for action_ref in action_refs:
            self.assertRegex(
                action_ref,
                PINNED_ACTION,
                f"production action is not immutable: {action_ref}",
            )

        checkout_steps = [
            step
            for step in _steps(self.text)
            if re.search(r"(?m)^\s*uses:\s*actions/checkout@", step)
        ]
        self.assertTrue(checkout_steps)
        for checkout_step in checkout_steps:
            self.assertRegex(
                checkout_step,
                r"(?m)^\s+persist-credentials:\s*false\s*$",
            )

    def test_actions_artifacts_are_tag_only_and_debian_is_tag_only(self) -> None:
        self.assertEqual(self.text.count(f"uses: {PINNED_UPLOAD_ACTION}"), 6)
        upload_offsets = [
            match.start()
            for match in re.finditer(
                rf"uses: {re.escape(PINNED_UPLOAD_ACTION)}",
                self.text,
            )
        ]
        lines = self.text.splitlines()
        for offset in upload_offsets:
            line_index = self.text[:offset].count("\n")
            start = line_index
            while start >= 0 and not lines[start].startswith("      - "):
                start -= 1
            end = line_index + 1
            while end < len(lines) and not lines[end].startswith("      - "):
                end += 1
            upload_step = "\n".join(lines[start:end])
            self.assertIn(TAG_ONLY_CONDITION, upload_step)

        debian = self.jobs.get("build-linux-deb-clean", "")
        self.assertTrue(debian)
        self.assertRegex(
            debian,
            rf"(?m)^    {re.escape(TAG_ONLY_CONDITION)}\s*$",
        )

    def test_production_v_tag_release_path_remains_fail_closed(self) -> None:
        triggers = _top_level_block(self.text, "on")
        self.assertRegex(triggers, r'(?m)^\s+tags:\s*\n\s+- "v\*"\s*$')
        self.assertRegex(
            self.text,
            r"(?m)^permissions:\s*\n  contents: read\s*$",
        )

        publish = self.jobs.get("publish-release", "")
        self.assertTrue(publish)
        self.assertRegex(
            publish,
            rf"(?m)^    {re.escape(TAG_ONLY_CONDITION)}\s*$",
        )
        self.assertIn("gh release create", publish)
        self.assertIn("--verify-tag", publish)
        self.assertIn("--notes-from-tag", publish)
        self.assertIn(PINNED_ATTEST_ACTION, publish)
        self.assertRegex(
            publish,
            r"(?m)^      id-token:\s*write\s*$",
        )
        self.assertRegex(
            publish,
            r"(?m)^      attestations:\s*write\s*$",
        )

    def test_production_signing_requires_annotated_main_history_tag(self) -> None:
        policy = self.jobs.get("release-ref-policy", "")
        self.assertTrue(policy, "production workflow needs an early tag policy")
        for marker in (
            'test "${TAG}" = "v${VERSION}"',
            'git cat-file -t "refs/tags/${TAG}"',
            'git rev-parse "refs/tags/${TAG}^{tag}"',
            'git rev-list -n 1 "refs/tags/${TAG}"',
            "refs/remotes/origin/main",
            'git merge-base --is-ancestor "${GITHUB_SHA}"',
            "tag_object_sha=",
        ):
            self.assertIn(marker, policy)

        for job_id in (
            "build-linux-x86_64",
            "build-linux-arm64-clean",
            "build-linux-arm64-full",
            "build-windows-clean",
            "build-macos-clean",
        ):
            self.assertRegex(
                self.jobs.get(job_id, ""),
                r"(?m)^    needs:\s+release-ref-policy\s*$",
                f"{job_id} can bypass the production tag policy",
            )

        publish = self.jobs.get("publish-release", "")
        for marker in (
            "needs.release-ref-policy.outputs.tag_object_sha",
            "git/ref/tags/${TAG}",
            "git/tags/${REMOTE_TAG_OBJECT}",
            "EXPECTED_TAG_OBJECT",
            "verify_remote_tag",
        ):
            self.assertIn(marker, publish)
        self.assertGreaterEqual(
            publish.count("verify_remote_tag"),
            3,
            "tag identity must be checked before and after release creation",
        )


GH_STUB = """#!/bin/sh
case "$1 $2" in
  "release list") cat "$GH_FIXTURE" ;;
  "release view") echo true ;;
  "release delete") echo "$3" >> "$GH_DELETED" ;;
  *) exit 1 ;;
esac
"""


def _cleanup_script() -> str:
    """Return the reaper's shell body, dedented out of the workflow YAML."""

    text = _read(CLEANUP_WORKFLOW)
    _, _, body = text.partition("        run: |\n")
    if not body:
        raise AssertionError("cleanup workflow has no run block")
    return textwrap.dedent(body)


def _retention_days() -> int:
    """Read the configured window so the fixture ages cannot drift from it."""

    match = re.search(
        r'(?m)^\s*RETENTION_DAYS:\s*"(\d+)"\s*$',
        _read(CLEANUP_WORKFLOW),
    )
    if match is None:
        raise AssertionError("cleanup workflow does not set RETENTION_DAYS")
    return int(match.group(1))


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class CleanupReaperTargetingTests(unittest.TestCase):
    """The reaper holds the only delete path, so its filter is exercised."""

    def _run(self, releases: list[tuple[str, int]]) -> list[str]:
        now = datetime.now(timezone.utc)
        fixture = "".join(
            "{}\t{}\n".format(
                tag,
                (now - timedelta(days=age)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            for tag, age in releases
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            stub = bin_dir / "gh"
            stub.write_text(GH_STUB, encoding="utf-8")
            stub.chmod(0o755)
            (root / "fixture.tsv").write_text(fixture, encoding="utf-8")
            deleted = root / "deleted.txt"
            deleted.touch()

            env = dict(os.environ)
            env.update(
                PATH=f"{bin_dir}{os.pathsep}{env['PATH']}",
                GH_FIXTURE=str(root / "fixture.tsv"),
                GH_DELETED=str(deleted),
                RUNNER_TEMP=str(root),
                GITHUB_STEP_SUMMARY=str(root / "summary.md"),
                RETENTION_DAYS=str(_retention_days()),
            )
            result = subprocess.run(
                ["bash", "-c", _cleanup_script()],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return deleted.read_text(encoding="utf-8").split()

    def test_only_aged_run_scoped_ci_drafts_are_deleted(self) -> None:
        aged = _retention_days() * 2
        deleted = self._run(
            [
                ("ci-main-123-1", aged),
                ("ci-windows-main-456-2", aged),
                ("ci-main-789-1", 0),
                ("v1.2.3", aged),
                ("ci-main-nightly", aged),
                ("ci-main-123-1-extra", aged),
                ("release-ci-main-1-1", aged),
            ]
        )
        self.assertEqual(deleted, ["ci-main-123-1", "ci-windows-main-456-2"])

    def test_nothing_is_deleted_when_no_draft_is_aged(self) -> None:
        self.assertEqual(self._run([("ci-main-123-1", 0)]), [])


if __name__ == "__main__":
    unittest.main()
