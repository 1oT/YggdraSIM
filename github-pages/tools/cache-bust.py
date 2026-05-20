#!/usr/bin/env python3
"""Stamp a ?v=VERSION query on local CSS/JS links so browsers refetch them.

ygg.css / tailwind.css etc. are cached hard by browsers; during dev a CSS
edit silently doesn't show up. This appends (or updates) ?v=VERSION on every
local stylesheet/script reference across all pages. After editing CSS/JS,
bump VERSION and re-run; the new query forces a refetch everywhere.

Only local assets are touched — external font CDNs are left alone.

Usage: python3 tools/cache-bust.py [--apply]
"""
from __future__ import annotations

import glob
import os
import re
import sys

VERSION = "2"  # bump this after editing ygg.css / ygg.js / tailwind.css / etc.

APPLY = "--apply" in sys.argv
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ASSET = re.compile(
    r'((?:href|src)=")'
    r'((?:\.\./)*(?:ygg-layout|ygg-mermaid|ygg|tailwind)\.(?:css|js))'
    r'(?:\?v=[^"]*)?'
    r'(")'
)

changed = 0
for f in glob.glob("**/*.html", recursive=True):
    if f.startswith(("partials/", "tools/")):
        continue
    t = open(f, encoding="utf-8").read()
    new = ASSET.sub(rf"\g<1>\g<2>?v={VERSION}\g<3>", t)
    if new != t:
        changed += 1
        if APPLY:
            open(f, "w", encoding="utf-8").write(new)

print(f"[{'APPLIED' if APPLY else 'DRY RUN'}] v={VERSION} on local css/js "
      f"in {changed} files")
