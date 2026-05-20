#!/usr/bin/env python3
"""CI link checker — fails the build if any internal link or anchor is broken.

Validates, across every built HTML page:
  * internal href/src targets resolve to a real file (or dir/index.html);
  * every "#fragment" resolves to an id=/name= in the target page
    (same-page or cross-page).

External (http/https/mailto), data: and javascript: URLs are ignored.
Exit status is non-zero with a report when anything is broken, so a CI job
can gate on it and the MkDocs->flat regression cannot come back.
"""
from __future__ import annotations

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

ID_RE = re.compile(r'\s(?:id|name)="([^"]+)"')
LINK_RE = re.compile(r'(?:href|src)="([^"]+)"')

pages = [f for f in glob.glob("**/*.html", recursive=True)
         if not f.startswith(("partials/", "tools/"))]

ids: dict[str, set[str]] = {}
for f in pages:
    ids[f] = set(ID_RE.findall(open(f, encoding="utf-8").read()))

broken: list[str] = []
for f in pages:
    fdir = os.path.dirname(f)
    for url in LINK_RE.findall(open(f, encoding="utf-8").read()):
        if url.startswith(("http://", "https://", "mailto:", "data:", "javascript:")):
            continue
        path, _, frag = url.partition("#")
        path = path.split("?", 1)[0]                    # drop cache-bust query
        if not path:                                   # same-page anchor
            if frag and frag not in ids[f]:
                broken.append(f"{f}: #{frag} (no such id on page)")
            continue
        tgt = os.path.normpath(os.path.join(fdir, path))
        if os.path.isdir(tgt):
            tgt = os.path.join(tgt, "index.html")
        if not os.path.isfile(tgt):
            broken.append(f"{f}: {url} -> missing {tgt}")
            continue
        rel = os.path.relpath(tgt, ROOT)
        if frag and rel in ids and frag not in ids[rel]:
            broken.append(f"{f}: {url} -> #{frag} not in {rel}")

if broken:
    print(f"FAIL: {len(broken)} broken link(s)\n")
    for b in broken:
        print("  " + b)
    sys.exit(1)
print(f"OK: {len(pages)} pages, all internal links and anchors resolve")
