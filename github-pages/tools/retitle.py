#!/usr/bin/env python3
"""Re-title pages from the sidebar nav — the single source of correctly-cased names.

The page <title>, the <h1 class="doc-h1">, and the breadcrumb current-crumb were
all generated with a naive slug.title(), which mangles domain acronyms
("Scp03", "3Gpp Naa", "Etsi Uicc"). The sidebar in ygg-layout.js already
carries the correct strings ("SCP03 Admin Shell", "3GPP NAA", "ETSI UICC").

This script parses that nav, builds slug -> label, and rewrites the three
spots to match. Idempotent: re-running after a docs rebuild re-applies the fix.
"""
from __future__ import annotations

import html
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAYOUT = ROOT / "ygg-layout.js"

# --- 1. Parse the sidebar nav (the authoritative name source) ---------------
src = LAYOUT.read_text(encoding="utf-8")

# Section toggle buttons:  data-nav-section="concepts" ... <span ...>Concepts</span>
section_label = {}
for m in re.finditer(
    r'data-nav-section="([^"]+)".*?<span[^>]*>([^<]+)</span>', src, re.S
):
    section_label[m.group(1)] = html.unescape(m.group(2).strip())

# Nav links / sub-links:  data-nav-path="x.html" ... >Label</a>
slug_label = {}
for m in re.finditer(r'data-nav-path="([^"]+)"[^>]*>([^<]+)</a>', src):
    slug_label[m.group(1)] = html.unescape(m.group(2).strip())


def canonical_name(rel: str) -> str | None:
    """Authoritative display name for a page, or None to skip it."""
    if rel == "index.html":
        return None  # root hero — title/h1 are bespoke and correct
    # Section index pages are labelled "Overview" in nav; use the section name.
    parts = rel.split("/")
    if len(parts) == 2 and parts[1] == "index.html":
        if parts[0] in section_label:
            return section_label[parts[0]]
    label = slug_label.get(rel)
    if label and label.lower() != "overview":
        return label
    return None


# --- 2. Rewrite the three spots --------------------------------------------
TITLE_RE = re.compile(r"(<title>).*?( — YggdraSIM</title>)")
H1_RE = re.compile(r'(<h1 class="doc-h1 [^"]*">)[^<]*(</h1>)')
# Attribute order varies (aria-current first on deep pages, class first on
# top-level pages), so match any <span> carrying aria-current="page".
CRUMB_RE = re.compile(r'(<span(?=[^>]*\baria-current="page")[^>]*>)[^<]*(</span>)')

changed, skipped, missing = [], [], []

for path in sorted(ROOT.rglob("*.html")):
    rel = path.relative_to(ROOT).as_posix()
    if rel.startswith("partials/") or rel.startswith("tools/"):
        continue
    name = canonical_name(rel)
    if name is None:
        skipped.append(rel)
        continue

    text = path.read_text(encoding="utf-8")
    esc = html.escape(name, quote=False)  # & -> &amp; for HTML text nodes
    new = text
    new, n_t = TITLE_RE.subn(rf"\g<1>{esc}\g<2>", new, count=1)
    new, n_h = H1_RE.subn(rf"\g<1>{esc}\g<2>", new, count=1)
    new, n_c = CRUMB_RE.subn(rf"\g<1>{esc}\g<2>", new, count=1)

    if not n_h:
        missing.append(rel)
    if new != text:
        path.write_text(new, encoding="utf-8")
        changed.append(f"{rel:42s} -> {name}  [title={n_t} h1={n_h} crumb={n_c}]")

print(f"changed {len(changed)} files\n")
print("\n".join(changed))
if skipped:
    print(f"\nskipped (no nav mapping / bespoke): {', '.join(skipped)}")
if missing:
    print(f"\nWARNING no doc-h1 matched in: {', '.join(missing)}", file=sys.stderr)
