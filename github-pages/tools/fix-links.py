#!/usr/bin/env python3
"""Repair links left broken by the MkDocs -> flat-HTML migration.

The old MkDocs site used directory URLs (`../scp03/#anchor`, `../../reference/
cli-matrix/`); the flat build serves `subsystems/scp03.html`. Many links kept
the old shape, and several carry a wrong `../` depth on top of that.

The robust fix is not to patch the relative path in place (the depth is itself
wrong) but to resolve each broken link by its *slug* to the real file in the
tree, then recompute the correct relative path from the linking page. Renamed
pages and dangling references are handled explicitly.

Also normalises the favicon: extracts the inline brand SVG to a real asset and
points every `rel="icon"` at the correct relative path.

Usage: python3 tools/fix-links.py [--apply]
"""
from __future__ import annotations

import glob
import os
import re
import sys

APPLY = "--apply" in sys.argv
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

# Pages that were renamed in the migration (old slug -> new slug).
RENAME = {"cli-matrix": "command-suite", "cli-and-piping-cheatsheet": "cli-cheatsheet"}
# Dangling refs to pages that never made it into the flat site -> nearest real page.
RETARGET = {"write-a-plugin": "internals/plugin-contract.html"}
# Refs with no equivalent anywhere -> unwrap the <a> to plain text.
DROP = {"source-library", "outline"}

FAVICON_ASSET = "assets/images/yggdrasil-mark.svg"

# --- 0. Extract the brand SVG to a real asset (idempotent) -----------------
if not os.path.isfile(FAVICON_ASSET):
    layout = open("ygg-layout.js", encoding="utf-8").read()
    m = re.search(r'(<svg xmlns="http://www\.w3\.org/2000/svg" viewBox="0 0 128 128".*?</svg>)', layout, re.S)
    if m:
        os.makedirs(os.path.dirname(FAVICON_ASSET), exist_ok=True)
        svg = m.group(1).replace(' class="size-7 shrink-0"', "")
        if APPLY:
            open(FAVICON_ASSET, "w", encoding="utf-8").write(svg + "\n")
        print(f"[{'APPLIED' if APPLY else 'DRY RUN'}] created {FAVICON_ASSET}")

# --- 1. Index every real page by basename slug -----------------------------
by_slug: dict[str, list[str]] = {}
for f in glob.glob("**/*.html", recursive=True):
    if f.startswith(("partials/", "tools/")):
        continue
    by_slug.setdefault(os.path.basename(f)[:-5], []).append(f)


def resolve(slug: str):
    """Real repo-relative file for a slug, or None if unresolved/ambiguous."""
    slug = RENAME.get(slug, slug)
    if slug in RETARGET:
        return RETARGET[slug]
    if slug == "index":
        return "index.html"  # broken subdir index.html -> site root
    hits = by_slug.get(slug)
    return hits[0] if hits and len(hits) == 1 else None


HREF_RE = re.compile(r'(\s(?:href|src)=")([^"]+)(")')
ANCHOR_A_RE_TMPL = r'<a\b[^>]*\shref="{}"[^>]*>(.*?)</a>'

stats = {"mkdocs": 0, "favicon": 0, "index": 0, "unwrapped": 0, "unresolved": 0}
unresolved: list[str] = []

for f in sorted(by_slug_files := glob.glob("**/*.html", recursive=True)):
    if f.startswith(("partials/", "tools/")):
        continue
    fdir = os.path.dirname(f)
    depth = f.count("/")
    t = open(f, encoding="utf-8").read()
    orig = t

    # 1a. Favicon: always point at the asset with the correct relative prefix.
    correct_fav = ("../" * depth) + FAVICON_ASSET
    t, n = re.subn(
        r'(<link rel="icon" href=")[^"]+(")',
        lambda m: m.group(1) + correct_fav + m.group(2), t)
    stats["favicon"] += n

    # 1b. Unwrap dangling <a> refs that have no target anywhere.
    for slug in DROP:
        t, n = re.subn(
            r'<a\b[^>]*\shref="[^"]*' + re.escape(slug) + r'[^"]*"[^>]*>(.*?)</a>',
            lambda m: m.group(1), t, flags=re.S)
        stats["unwrapped"] += n

    # 1c. Rewrite every remaining broken internal link by slug resolution.
    def fix(m):
        attr, url, end = m.group(1), m.group(2), m.group(3)
        if url.startswith(("http://", "https://", "mailto:", "#", "data:", "javascript:")):
            return m.group(0)
        path, _, anchor = url.partition("#")
        if not path or path.endswith(FAVICON_ASSET):
            return m.group(0)
        if os.path.isfile(os.path.normpath(os.path.join(fdir, path))):
            return m.group(0)  # already valid
        if path in ("../", "./", ".", ".."):
            slug = "index"
        else:
            slug = os.path.basename(path.rstrip("/")) or "index"
            if slug.endswith(".html"):
                slug = slug[:-5]
        tgt = resolve(slug)
        if not tgt:
            unresolved.append(f"{f}  ->  {url}")
            stats["unresolved"] += 1
            return m.group(0)
        rel = os.path.relpath(tgt, fdir) or os.path.basename(tgt)
        if tgt == "index.html" and slug == "index":
            stats["index"] += 1
        else:
            stats["mkdocs"] += 1
        return attr + rel + ("#" + anchor if anchor else "") + end

    t = HREF_RE.sub(fix, t)

    if t != orig and APPLY:
        open(f, "w", encoding="utf-8").write(t)

print(f"[{'APPLIED' if APPLY else 'DRY RUN'}] "
      f"mkdocs-dir={stats['mkdocs']} index-base={stats['index']} "
      f"favicon={stats['favicon']} unwrapped={stats['unwrapped']} "
      f"unresolved={stats['unresolved']}")
for u in unresolved:
    print("  UNRESOLVED " + u)
