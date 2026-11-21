#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Release-note policy for a production tag.

The GitHub Release body is the annotated tag's message, so the message is
judged before it is published. ``check`` refuses a message that would read
as something else on the release page: the tagged commit's message, a bare
version line, notes headed by another version, a note that lists no change,
or one carrying a trailer. It also refuses a CHANGELOG.md that still files
work under ``[Unreleased]`` or has no section for the version, because the
tagged tree ships whatever that section holds. ``published`` compares the
body GitHub stored with the notes that passed.

Without ``--notes``, ``--commit-message`` or ``--changelog`` the inputs come
from the annotated tag in the current checkout, which is the pre-push check
the release checklist asks for. CI passes the files it fetched itself.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


HEADING = "YggdraSIM {tag}"
SIGNATURE_BLOCK = re.compile(
    r"\n?-----BEGIN (?:PGP|SSH) SIGNATURE-----\n.*?-----END (?:PGP|SSH) SIGNATURE-----\n?",
    re.DOTALL,
)
LIST_ITEM = re.compile(r"^\s*[-*] \S")
TRAILER = re.compile(r"^[A-Za-z][A-Za-z-]*-(?:[Bb]y|[Ss]ession):\s")
UNRELEASED_HEADING = re.compile(r"^## \[Unreleased\]\s*$")
SECTION_HEADING = re.compile(r"^## ")
HTML_COMMENT_LINE = re.compile(r"^\s*<!--.*-->\s*$")


class ReleaseNotesError(RuntimeError):
    """Raised when the tag message or the changelog fails the release-note policy."""


def normalise(text: str) -> str:
    """Return ``text`` as the body GitHub renders: LF line endings, no
    detached-signature block, no trailing whitespace, one final newline."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = SIGNATURE_BLOCK.sub("\n", text)
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def version_of(tag: str) -> str:
    """Return the project version a ``v<version>`` tag names."""
    if not tag.startswith("v") or len(tag) < 2:
        raise ReleaseNotesError(f"a production tag is v<version>; got {tag!r}")
    return tag[1:]


def check_notes(tag: str, notes: str, commit_message: str) -> str:
    """Return the release body ``notes`` becomes for ``tag``, or refuse it."""
    body = normalise(notes)
    if not body:
        raise ReleaseNotesError(f"the {tag} tag message is empty")
    lines = body.split("\n")
    commit = normalise(commit_message)
    if commit and body == commit:
        raise ReleaseNotesError(
            f"the {tag} tag message is the tagged commit's message; the release"
            " page needs a release note, not a commit message"
        )
    expected = HEADING.format(tag=tag)
    if lines[0] != expected:
        if commit and lines[0] == commit.split("\n", 1)[0]:
            raise ReleaseNotesError(
                f"the {tag} tag message opens with the tagged commit's subject"
                f" {lines[0]!r}; the release page needs a release note headed"
                f" {expected!r}, not a commit message"
            )
        raise ReleaseNotesError(
            f"the {tag} tag message must open with {expected!r}; it opens with"
            f" {lines[0]!r}"
        )
    if not any(LIST_ITEM.match(line) for line in lines[1:]):
        raise ReleaseNotesError(
            f"the {tag} tag message lists no change (no '- ' line); a release note"
            " names the notable changes"
        )
    for number, line in enumerate(lines, start=1):
        if TRAILER.match(line):
            key = line.split(":", 1)[0]
            raise ReleaseNotesError(
                f"the {tag} tag message carries a trailer on line {number} ({key}:);"
                " release notes carry no trailer"
            )
    return body


def check_changelog(version: str, changelog: str) -> None:
    """Refuse a changelog with work still under Unreleased or no ``version`` section."""
    lines = changelog.replace("\r\n", "\n").split("\n")
    section = re.compile(rf"^## \[{re.escape(version)}\] -- \d{{4}}-\d{{2}}-\d{{2}}\s*$")
    headings = [
        (index, line) for index, line in enumerate(lines) if SECTION_HEADING.match(line)
    ]
    found = False
    for position, (index, heading) in enumerate(headings):
        end = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        entries = [
            line
            for line in lines[index + 1 : end]
            if line.strip() and not HTML_COMMENT_LINE.match(line)
        ]
        if UNRELEASED_HEADING.match(heading):
            if entries:
                raise ReleaseNotesError(
                    f"CHANGELOG.md files {len(entries)} line(s) under [Unreleased] at"
                    f" {version}; the tagged tree ships them, so they belong in the"
                    f" [{version}] section"
                )
        elif section.match(heading):
            found = True
            if not entries:
                raise ReleaseNotesError(f"the CHANGELOG.md [{version}] section is empty")
    if not found:
        raise ReleaseNotesError(
            f"CHANGELOG.md has no '## [{version}] -- YYYY-MM-DD' section"
        )


def check_published(notes: str, body: str) -> None:
    """Refuse a published body that is not the checked notes."""
    if normalise(body) != normalise(notes):
        raise ReleaseNotesError(
            "the published release body differs from the checked release notes"
        )


def _git(args: list[str], cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def tag_message_from_git(tag: str, cwd: Path) -> str:
    """Read the annotated tag's message from the checkout; refuse a lightweight ref."""
    kind = _git(["cat-file", "-t", f"refs/tags/{tag}"], cwd).strip()
    if kind != "tag":
        raise ReleaseNotesError(
            f"refs/tags/{tag} is a {kind} in this checkout, not an annotated tag"
            " object; fetch the tag object back"
            f" (git fetch --force origin +refs/tags/{tag}:refs/tags/{tag}) or pass"
            " --notes"
        )
    return _git(["for-each-ref", "--format=%(contents)", f"refs/tags/{tag}"], cwd)


def commit_message_from_git(tag: str, cwd: Path) -> str:
    return _git(["log", "-1", "--format=%B", f"refs/tags/{tag}^{{commit}}", "--"], cwd)


def changelog_from_git(tag: str, cwd: Path) -> str:
    return _git(["show", f"refs/tags/{tag}:CHANGELOG.md"], cwd)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run_check(args: argparse.Namespace) -> str:
    tag = str(args.tag).strip()
    version = version_of(tag)
    cwd = Path.cwd()
    notes = _read(args.notes) if args.notes else tag_message_from_git(tag, cwd)
    commit_message = (
        _read(args.commit_message)
        if args.commit_message
        else commit_message_from_git(tag, cwd)
    )
    body = check_notes(tag, notes, commit_message)
    changelog = _read(args.changelog) if args.changelog else changelog_from_git(tag, cwd)
    check_changelog(version, changelog)
    if args.output:
        args.output.write_text(body, encoding="utf-8")
    return (
        f"release notes for {tag}: {body.count(chr(10))} lines under"
        f" {HEADING.format(tag=tag)!r}; CHANGELOG.md [{version}] present and"
        " [Unreleased] empty"
    )


def run_published(args: argparse.Namespace) -> str:
    check_published(_read(args.notes), _read(args.body))
    return "the published release body is the checked release notes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Judge a production tag's release notes before and after publication."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check",
        help="refuse a tag message or changelog that would publish badly",
    )
    check.add_argument("--tag", required=True, help="the production tag, v<version>")
    check.add_argument(
        "--notes",
        type=Path,
        help="file holding the tag message (default: the annotated tag in this checkout)",
    )
    check.add_argument(
        "--commit-message",
        type=Path,
        help="file holding the tagged commit's message (default: git log of the tag)",
    )
    check.add_argument(
        "--changelog",
        type=Path,
        help="CHANGELOG.md to judge (default: the tagged tree's copy)",
    )
    check.add_argument(
        "--output",
        type=Path,
        help="write the release body the notes become to this file",
    )
    check.set_defaults(handler=run_check)
    published = commands.add_parser(
        "published",
        help="compare the body GitHub stored with the checked notes",
    )
    published.add_argument("--notes", type=Path, required=True, help="the checked notes")
    published.add_argument("--body", type=Path, required=True, help="the body read back")
    published.set_defaults(handler=run_published)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(args.handler(args))
    except ReleaseNotesError as exc:
        print(f"release-notes policy: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(
            f"release-notes policy: git {' '.join(exc.cmd[1:])} failed:"
            f" {exc.stderr.strip()}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"release-notes policy: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
