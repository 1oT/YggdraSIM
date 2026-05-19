#!/usr/bin/env python3
"""Repair pages corrupted by the buggy first-pass fix-lead.py.

That script computed the body-<p> removal offsets against the original text
but applied them AFTER the lead substitution had shifted every later offset,
so it deleted the wrong byte span — chewing the end of the mobile TOC, the
doc-prose opening tag, and the start of the first paragraph.

Recovery is deterministic. For each page nothing the *desired* output needs
was actually lost:
  * prefix  (head -> breadcrumb -> h1 -> promoted lead)  : intact in F
  * body after the first paragraph (admonition/h2/.../rail/footer) : intact in F
  * mobile TOC links : identical to the intact desktop .ygg-toc-rail
  * mobile-TOC wrapper + doc-prose open : constant boilerplate

So we rebuild = intact prefix + regenerated mobile TOC (links from the rail)
+ constant doc-prose open + intact body tail. Idempotent and self-checking:
skips any candidate that is already structurally clean.

Usage: python3 tools/repair-lead-corruption.py [--apply]
"""
from __future__ import annotations

import glob
import re
import sys

APPLY = "--apply" in sys.argv

# Constant boilerplate (verified against an uncorrupted page, reference/faq.html)
TOC_OPEN = (
    '\n        <details class="toc-mobile xl:hidden mb-8">\n'
    "          <summary>On this page "
    '<svg class="toc-mobile-chevron size-4" viewBox="0 0 16 16" fill="none" '
    'stroke="currentColor" stroke-width="2" aria-hidden="true">'
    '<path d="M4 6l4 4 4-4"/></svg></summary>\n          <nav>\n'
)
TOC_CLOSE = "\n          </nav>\n        </details>"
PROSE_OPEN = (
    '\n        <div class="doc-prose text-[0.9375rem] leading-relaxed '
    'text-zinc-600 dark:text-zinc-400 space-y-4">\n'
)

MANUAL = {
    "concepts/index.html", "subsystems/index.html", "how-to/index.html",
    "internals/index.html", "shell-guides/index.html", "reference/faq.html",
    "build-and-packaging.html", "index.html", "reference.html",
}

LEAD_OPEN = '<p class="page-lead mb-8">'
RAIL_RE = re.compile(r'<aside class="ygg-toc-rail".*?<nav>(.*?)</nav>', re.S)
LINK_RE = re.compile(r'<a href="#[^"]*"[^>]*>.*?</a>', re.S)


# A healthy page has a well-formed doc-prose open tag immediately followed
# (after whitespace) by a block-level element — not orphan text, not a
# mangled class attribute.
PROSE_OK = re.compile(
    r'<div class="doc-prose[^"]*">\s*'
    r'<(p|h2|h3|h4|ul|ol|table|pre|blockquote|figure|hr|!--|div|a)\b'
)


def is_broken(t: str) -> bool:
    # Count real anchors only: "<a " (not <abbr>, not <aside>).
    if len(re.findall(r"<a ", t)) != t.count("</a>"):
        return True
    for h in re.findall(r'href="([^"]*)"', t):
        if "\n" in h or "<" in h:
            return True
        if " " in h and not h.startswith(("http", "mailto:", "#")):
            return True
    return PROSE_OK.search(t) is None


repaired, skipped_clean, flagged = [], [], []

for f in sorted(glob.glob("**/*.html", recursive=True)):
    # how-to/* is NOT blanket-excluded: most were fixed by the goal script and
    # are structurally clean (is_broken skips them), but any how-to page that
    # fix-lead.py corrupted and the goal script didn't touch still needs repair.
    if f.startswith(("partials/", "tools/")) or f in MANUAL:
        continue
    t = open(f, encoding="utf-8").read()
    if LEAD_OPEN not in t:
        continue
    if not is_broken(t):
        skipped_clean.append(f)
        continue

    s = t.index(LEAD_OPEN)
    lead_close = t.index("</p>", s + len(LEAD_OPEN))
    rend = lead_close + len("</p>")          # end of intact prefix (incl. lead)
    prefix = t[:rend]
    lead_inner = t[s + len(LEAD_OPEN):lead_close]

    # First </p> after the lead = the corrupted original first body paragraph.
    body_para_close = t.index("</p>", rend)
    body_rest = t[body_para_close + len("</p>"):]   # intact A[P1:]

    # The first paragraph's </p> is only lost if the promoted lead was barely
    # longer than the stub it replaced (delta < ~5). Reconstruct the original
    # stub text from the slug to measure delta; flag tiny-delta pages.
    stem = f.rsplit("/", 1)[-1][:-len(".html")]
    name = " ".join(w.capitalize() for w in stem.split("-"))
    stub_inner = f"{name} — YggdraSIM operator documentation."
    if len(lead_inner) - len(stub_inner) < 8:
        flagged.append(f + "  (small delta — verify </p> not lost)")
        continue

    rail = RAIL_RE.search(body_rest)            # rail lives in the intact tail
    if rail:
        links = LINK_RE.findall(rail.group(1))
        toc = TOC_OPEN + "\n".join("            " + a for a in links) + TOC_CLOSE
    else:
        toc = ""   # page has no sections / no TOC

    new = prefix + toc + PROSE_OPEN + body_rest.lstrip("\n")

    if is_broken(new):
        flagged.append(f)
        continue
    repaired.append(f)
    if APPLY:
        open(f, "w", encoding="utf-8").write(new)

mode = "APPLIED" if APPLY else "DRY RUN"
print(f"[{mode}] repaired {len(repaired)}, already-clean {len(skipped_clean)}, "
      f"FLAGGED {len(flagged)}\n")
for f in repaired:
    print("  fixed   " + f)
for f in flagged:
    print("  FLAGGED " + f + "  (still broken after rebuild — manual)")
