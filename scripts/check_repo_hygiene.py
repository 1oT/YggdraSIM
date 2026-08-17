#!/usr/bin/env python3
"""Check tracked content against the release-hygiene rules in CLAUDE.md.

Covers the mechanically checkable parts of sections 1 to 4: reserved-range
identifiers, banned typography, AI-style prose, assistant attribution,
internal-report filenames, and personal markers.

The tree carries pre-existing typography violations, so a strict gate
would fail on adoption. Runs therefore compare against a recorded
baseline and fail only on new violations, matching the "zero new
regressions, not all green" bar the agent standards already set for
tests.

    python scripts/check_repo_hygiene.py                  # report + gate
    python scripts/check_repo_hygiene.py --write-baseline # re-record
    python scripts/check_repo_hygiene.py --strict         # ignore baseline
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple
from collections.abc import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = Path(__file__).with_name("repo_hygiene_baseline.json")

TEXT_SUFFIXES = frozenset(
    {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".lua"}
)

# Section 6 mirrors these from their source, so a hit is reported once
# against the source rather than twice.
MIRROR_PREFIX = "site-docs/sources/"

# These files necessarily contain the patterns they define or search for.
SELF_PATH = "scripts/check_repo_hygiene.py"
RULE_DOC_PATH = "guides/REMOTES_AND_PUBLICATION.md"
EXEMPT_PATHS = frozenset({SELF_PATH, RULE_DOC_PATH})


class Violation(NamedTuple):
    check: str
    path: str
    line: int
    detail: str

    def key(self) -> str:
        return f"{self.check}:{self.path}:{self.detail}"


# --- Section 1: reserved-range identifiers -------------------------------

# Real ITU-T E.118 issuer prefixes that must not appear as ICCID bodies.
REAL_ICCID_IIN = re.compile(r"\b(?:8946|8949|8937|8983|89126)[0-9]{10,}")
# EF.ICCID packed BCD, low nibble first: 8946... becomes 9864...
REAL_ICCID_BCD = re.compile(r"\b9864[0-9A-Fa-f]{14,16}\b")

IDENTIFIER_CHECKS = (
    ("iccid-ascii", REAL_ICCID_IIN, "real ITU-T E.118 issuer prefix; use the 8988 test range"),
    ("iccid-bcd", REAL_ICCID_BCD, "packed-BCD form of a real issuer prefix (TS 102 221 13.2)"),
)


# --- Section 2: typography ----------------------------------------------

BANNED_CODEPOINTS = (
    ("—", "em-dash U+2014; use --"),
    ("–", "en-dash U+2013; use -"),
    ("‘", "smart quote U+2018"),
    ("’", "smart quote U+2019"),
    ("“", "smart quote U+201C"),
    ("”", "smart quote U+201D"),
    ("…", "ellipsis U+2026; use ..."),
    (" ", "non-breaking space U+00A0"),
    ("​", "zero-width space U+200B"),
    ("‌", "zero-width non-joiner U+200C"),
    ("‍", "zero-width joiner U+200D"),
    ("﻿", "byte-order mark U+FEFF"),
)


# --- Section 2: AI-style prose -------------------------------------------

BANNED_PHRASES = (
    "let me",
    "let's",
    "we'll",
    "i'll ",
    "feel free to",
    "as we mentioned",
    "as we noted",
    "as we discussed",
    "it is worth noting",
    "in a nutshell",
    "to sum up",
    "in essence",
    "out of the box",
    "under the hood",
    "behind the scenes",
    "deep dive",
    "first-class",
    "in the wild",
    "seamless",
    "comprehensive",
    "cutting-edge",
    "battle-tested",
    "industry-leading",
    "best-in-class",
    "enterprise-grade",
    "carefully crafted",
    "secret sauce",
    "delve",
    "leverages",
    "leveraging",
    "this module provides",
    "this class represents",
    "this file implements",
)


# --- Section 2: assistant attribution ------------------------------------

# Authorship shapes, not product names. Naming an assistant product as a
# supported integration -- an MCP client in a how-to, say -- is
# documentation; claiming it as an author is the thing being banned. The
# patterns therefore match trailers and identities only.
ATTRIBUTION_CHECKS = (
    (
        re.compile(r"@(?:anthropic|cursor|openai)\.com"),
        "assistant identity in an authorship field",
    ),
    (re.compile(r"claude\.ai/code"), "assistant session link"),
    (re.compile(r"Claude-Session:"), "assistant session trailer"),
    (
        re.compile(
            r"Co-authored-by:\s*\S.*(?:Claude|Copilot|Codex|Cursor|ChatGPT|Gemini|anthropic|openai)",
            re.IGNORECASE,
        ),
        "assistant named in a Co-authored-by trailer",
    ),
    (
        re.compile(r"Generated with \[?(?:Claude|Copilot|Codex|Cursor)"),
        "assistant named in a generation credit",
    ),
    (
        re.compile(r"@author\s+(?:Claude|Copilot|Codex|Cursor|ChatGPT|Gemini)", re.IGNORECASE),
        "assistant named in an @author tag",
    ),
)


# --- Section 3 and 4: filenames and markers ------------------------------

# Internal-report document shapes that belong in .git/info/exclude.
REPORT_FILENAME = re.compile(
    r"(?:^|/)(?:V[12]_.*|.*_(?:PLAN|ROADMAP|SCOPING|SCOPE|DRAFT|BACKLOG|IDEAS|NOTES"
    r"|REVIEW|AUDIT|REMEDIATION|HANDOFF|HAND_OFF|RELEASE_NOTES|PATCHES))\.md$",
    re.IGNORECASE,
)

# Tokens that must not appear in tracked filenames.
FILENAME_TOKENS = (
    (re.compile(r"(?:^|/)(?:1oT|oneot)_", re.IGNORECASE), "vendor token in filename"),
    (re.compile(r"(?:^|/)(?:prod|staging|internal)_", re.IGNORECASE), "environment token in filename"),
    (re.compile(r"(?:^|/)hampus_", re.IGNORECASE), "personal name in filename"),
    (re.compile(r"(?:^|/)(?:phase[0-9]|mvp)_", re.IGNORECASE), "internal phase token in filename"),
    (re.compile(r"phase[0-9]", re.IGNORECASE), "internal phase token in filename"),
    (re.compile(r"\d{4}-\d{2}-\d{2}\.pcapng$"), "dated capture filename"),
)

TODO_MARKER = re.compile(r"\b(?:TODO|FIXME|XXX|HACK)\b")


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def read_text(path: str) -> str | None:
    full_path = REPO_ROOT / path
    if full_path.suffix.lower() not in TEXT_SUFFIXES:
        return None
    try:
        return full_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan_filenames(paths: Iterable[str]) -> list[Violation]:
    found: list[Violation] = []
    for path in paths:
        if path.startswith(MIRROR_PREFIX):
            continue
        if REPORT_FILENAME.search(path):
            found.append(
                Violation("report-filename", path, 0, "internal-report document at a tracked path")
            )
        found.extend(
            Violation("filename-token", path, 0, detail)
            for pattern, detail in FILENAME_TOKENS
            if pattern.search(path)
        )
    return found


def quoted_lines(path: str, text: str) -> frozenset[int]:
    """Line numbers holding cited source rather than prose written here.

    The typography, prose and marker rules police what this repository
    writes. Editing a quotation to satisfy them would misreport what the
    upstream actually says, so citations are skipped. Two shapes carry
    them: a fenced block in Markdown, and an reStructuredText literal
    block introduced by a trailing ``::`` in a Python docstring.
    """
    lines = text.splitlines()
    quoted: set[int] = set()

    if path.endswith(".md"):
        in_fence = False
        for number, line in enumerate(lines, start=1):
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
                quoted.add(number)
                continue
            if in_fence:
                quoted.add(number)
        return frozenset(quoted)

    if path.endswith(".py"):
        indent_of = lambda text_line: len(text_line) - len(text_line.lstrip())  # noqa: E731
        block_indent: int | None = None
        for number, line in enumerate(lines, start=1):
            if block_indent is not None:
                if not line.strip():
                    quoted.add(number)
                    continue
                if indent_of(line) > block_indent:
                    quoted.add(number)
                    continue
                block_indent = None
            if line.rstrip().endswith("::"):
                block_indent = indent_of(line)
        return frozenset(quoted)

    return frozenset()


def scan_contents(paths: Iterable[str]) -> list[Violation]:
    found: list[Violation] = []
    for path in paths:
        if path.startswith(MIRROR_PREFIX) or path in EXEMPT_PATHS:
            continue
        text = read_text(path)
        if text is None:
            continue
        is_source = path.endswith((".py", ".md"))
        cited = quoted_lines(path, text)
        for line_number, line in enumerate(text.splitlines(), start=1):
            for check, pattern, detail in IDENTIFIER_CHECKS:
                if pattern.search(line):
                    found.append(Violation(check, path, line_number, detail))
            found.extend(
                Violation("ai-attribution", path, line_number, detail)
                for pattern, detail in ATTRIBUTION_CHECKS
                if pattern.search(line)
            )
            # Attribution and reserved identifiers are checked even inside a
            # citation: quoting is no reason to carry a real ICCID or credit
            # an assistant as author.
            if not is_source or line_number in cited:
                continue
            for character, detail in BANNED_CODEPOINTS:
                if character in line:
                    found.append(Violation("typography", path, line_number, detail))
            if TODO_MARKER.search(line):
                found.append(Violation("todo-marker", path, line_number, "TODO/FIXME/XXX/HACK marker"))
            lowered = line.lower()
            found.extend(
                Violation("ai-prose", path, line_number, f"banned phrase {phrase!r}")
                for phrase in BANNED_PHRASES
                if phrase in lowered
            )
    return found


def collect() -> list[Violation]:
    paths = tracked_files()
    return scan_filenames(paths) + scan_contents(paths)


def _counted(violations: list[Violation]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for violation in violations:
        counts[violation.key()] = counts.get(violation.key(), 0) + 1
    return counts


def load_baseline() -> dict[str, int]:
    """Return accepted violation keys mapped to their accepted count.

    Counts matter: keys omit the line number so an edit elsewhere in the
    file does not invalidate the baseline, which means a bare key set
    would hide a second em-dash added to a file that already had one.
    """
    if not BASELINE_PATH.exists():
        return {}
    try:
        payload = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    accepted = payload.get("accepted", {})
    if isinstance(accepted, list):
        # Older count-free format: treat each key as allowing one hit.
        return {str(key): 1 for key in accepted}
    return {str(key): int(value) for key, value in accepted.items()}


def new_violations(
    violations: list[Violation],
    accepted: dict[str, int],
) -> list[Violation]:
    """Return the violations that exceed the accepted count for their key."""
    budget = dict(accepted)
    fresh: list[Violation] = []
    for violation in violations:
        remaining = budget.get(violation.key(), 0)
        if remaining > 0:
            budget[violation.key()] = remaining - 1
            continue
        fresh.append(violation)
    return fresh


def write_baseline(violations: list[Violation]) -> None:
    payload = {
        "comment": (
            "Recorded hygiene violations accepted at adoption time, keyed by "
            "check:path:detail with the accepted occurrence count. New or "
            "additional entries fail scripts/check_repo_hygiene.py. Shrink "
            "these counts, never grow them."
        ),
        "accepted": dict(sorted(_counted(violations).items())),
    }
    BASELINE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def summarise(violations: list[Violation]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for violation in violations:
        counts[violation.check] = counts.get(violation.check, 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="record the current violations as accepted and exit 0",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="ignore the baseline and fail on any violation",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the summary",
    )
    args = parser.parse_args(argv)

    violations = collect()

    if args.write_baseline:
        write_baseline(violations)
        counts = summarise(violations)
        print(f"Recorded {len(violations)} violations as the accepted baseline.")
        for check in sorted(counts):
            print(f"  {check:<18} {counts[check]}")
        return 0

    accepted = {} if args.strict else load_baseline()
    new = new_violations(violations, accepted)

    counts = summarise(violations)
    print(f"Tracked hygiene violations: {len(violations)} total, {len(new)} new")
    for check in sorted(counts):
        print(f"  {check:<18} {counts[check]}")

    if not new:
        return 0

    if not args.quiet:
        print("\nNew violations:")
        for violation in sorted(new, key=lambda item: (item.path, item.line)):
            location = f"{violation.path}:{violation.line}" if violation.line else violation.path
            print(f"  [{violation.check}] {location}  {violation.detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
