#!/usr/bin/env python3
"""Replace the stub page-lead with the page's real opening paragraph.

Every content page shipped with an identical filler lead
("X — YggdraSIM operator documentation."), while the real one-sentence
summary — including the "this, not that" disambiguation the authors wrote
into the opening — sits in the first body <p>. This promotes that first
<p> into the lead slot and removes it from the body to avoid duplication.

Guarded on the stub text, so it is safe to re-run after a docs rebuild:
once a real lead is in place the page is skipped.

Usage:  python3 tools/fix-lead.py [--apply]
Default is a dry run that prints what would change.
"""
from __future__ import annotations

import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPLY = "--apply" in sys.argv

STUB_RE = re.compile(
    r'(<p class="page-lead[^"]*">)\s*[^<]*? — YggdraSIM operator documentation\.\s*(</p>)'
)
PROSE_RE = re.compile(r'<div class="doc-prose[^"]*"[^>]*>(.*)', re.S)
# First <p> and everything (whitespace) trailing it, so removal leaves no gap.
FIRST_P_RE = re.compile(r'<p>(.*?)</p>\s*', re.S)


def plain(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


changed, skipped, flagged = [], [], []

for path in sorted(ROOT.rglob("*.html")):
    rel = path.relative_to(ROOT).as_posix()
    if rel.startswith(("partials/", "tools/")):
        continue
    text = path.read_text(encoding="utf-8")

    if not STUB_RE.search(text):
        skipped.append(rel)
        continue

    pm = PROSE_RE.search(text)
    if not pm:
        flagged.append(f"{rel}: no .doc-prose container")
        continue
    prose_start = pm.start(1)
    prose = pm.group(1)

    fp = FIRST_P_RE.search(prose)
    if not fp:
        flagged.append(f"{rel}: no leading <p> in prose")
        continue
    # The first <p> must really be the opening line — not preceded by an
    # admonition/heading/table that would make promotion wrong.
    if re.search(r"<(h2|h3|table)\b|<div class=\"admonition", prose[: fp.start()]):
        flagged.append(f"{rel}: first block is not a <p> (manual)")
        continue

    inner = fp.group(1).strip()

    # Promote into the lead slot, drop the now-duplicate body <p>.
    new = STUB_RE.sub(lambda m: m.group(1) + inner + m.group(2), text, count=1)
    abs_p_start = prose_start + fp.start()
    abs_p_end = prose_start + fp.end()
    new = new[:abs_p_start] + new[abs_p_end:]

    changed.append((rel, plain(inner)[:140]))
    if APPLY:
        path.write_text(new, encoding="utf-8")

mode = "APPLIED" if APPLY else "DRY RUN"
print(f"[{mode}] {len(changed)} pages, {len(flagged)} flagged, {len(skipped)} skipped\n")
for rel, lead in changed:
    print(f"  {rel:44s} {lead}")
if flagged:
    print("\nFLAGGED (manual review):")
    for f in flagged:
        print("  " + f)
