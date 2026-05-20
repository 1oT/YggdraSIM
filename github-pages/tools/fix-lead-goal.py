#!/usr/bin/env python3
"""How-to runbooks: promote the "Goal" paragraph into the lead.

These pages opened with the stub lead, then `<h2 id="goal">Goal</h2>` and a
one-sentence goal. In a task-oriented runbook the goal *is* the lead, so we
move that sentence into the lead slot and drop the now-redundant Goal section
plus its two #goal TOC links (mobile + rail). Guarded on the stub, re-runnable.

Usage: python3 tools/fix-lead-goal.py [--apply]
"""
from __future__ import annotations

import glob
import re
import sys

APPLY = "--apply" in sys.argv

STUB_RE = re.compile(
    r'(<p class="page-lead[^"]*">)\s*[^<]*? — YggdraSIM operator documentation\.\s*(</p>)'
)
GOAL_RE = re.compile(r'<h2 id="goal">Goal</h2>\s*<p>(.*?)</p>\s*', re.S)
TOC_GOAL_RE = re.compile(r'\s*<a href="#goal"[^>]*>Goal</a>')

changed = []
for f in sorted(glob.glob("how-to/*.html")):
    t = open(f, encoding="utf-8").read()
    if not STUB_RE.search(t):
        continue
    gm = GOAL_RE.search(t)
    if not gm:
        continue
    goal = gm.group(1).strip()
    new = STUB_RE.sub(lambda m: m.group(1) + goal + m.group(2), t, count=1)
    new = GOAL_RE.sub("", new, count=1)
    new = TOC_GOAL_RE.sub("", new)  # both mobile + rail copies
    if new != t:
        changed.append(f)
        if APPLY:
            open(f, "w", encoding="utf-8").write(new)

print(f"[{'APPLIED' if APPLY else 'DRY RUN'}] {len(changed)} how-to pages")
print("\n".join("  " + c for c in changed))
