# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for the global GUI design-system contract."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CSS_ROOT = ROOT / "gui_frontend" / "src" / "css"
TOKEN_ROOT = CSS_ROOT / "tokens"

THEMES = {
    "catppuccin-latte",
    "catppuccin-mocha",
    "dracula",
    "github-dark",
    "github-light",
    "gruv-dark",
    "ink-light",
    "matrix",
    "nord-dark",
    "nord-light",
    "ocean-dark",
    "oneot-dark",
    "oneot-light",
    "solarized-dark",
    "solarized-light",
    "tokyo-night",
}


def _hex_tokens(path: Path) -> dict[str, str]:
    return dict(
        re.findall(
            r"--([\w-]+):\s*(#[0-9a-fA-F]{6})",
            path.read_text(encoding="utf-8"),
        )
    )


def _relative_luminance(value: str) -> float:
    components = [int(value[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        component / 12.92
        if component <= 0.04045
        else ((component + 0.055) / 1.055) ** 2.4
        for component in components
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    high, low = sorted(
        (_relative_luminance(first), _relative_luminance(second)),
        reverse=True,
    )
    return (high + 0.05) / (low + 0.05)


def test_all_themes_keep_secondary_and_semantic_text_readable() -> None:
    theme_paths = {
        path.stem: path
        for path in TOKEN_ROOT.glob("*.css")
        if path.stem not in {"base", "matrix-font-override"}
    }
    assert set(theme_paths) == THEMES

    failures: list[str] = []
    for theme, path in sorted(theme_paths.items()):
        tokens = _hex_tokens(path)
        for foreground in ("fg-dim", "accent", "ok", "warn", "fail"):
            surfaces = (
                ("bg", "bg-elev", "bg-elev-2")
                if foreground == "fg-dim"
                else ("bg", "bg-elev")
            )
            for surface in surfaces:
                ratio = _contrast(tokens[foreground], tokens[surface])
                if ratio < 4.5:
                    failures.append(
                        f"{theme}: --{foreground} on --{surface} is {ratio:.2f}:1"
                    )
        focus_ratio = _contrast(tokens["accent"], tokens["bg-elev-2"])
        if focus_ratio < 3:
            failures.append(
                f"{theme}: --accent focus ring on --bg-elev-2 is "
                f"{focus_ratio:.2f}:1"
            )
    assert not failures, "\n".join(failures)


def test_theme_gradients_keep_their_text_contrast() -> None:
    failures: list[str] = []
    for path in sorted(TOKEN_ROOT.glob("*.css")):
        if path.stem not in THEMES:
            continue
        css = path.read_text(encoding="utf-8")
        tokens = _hex_tokens(path)
        accent_gradient = re.search(r"--gradient-accent:\s*([^;]+)", css)
        brand_gradient = re.search(r"--gradient-brand:\s*([^;]+)", css)
        assert accent_gradient is not None
        assert brand_gradient is not None

        for stop in re.findall(r"#[0-9a-fA-F]{6}", accent_gradient.group(1)):
            ratio = _contrast(stop, tokens["accent-fg"])
            if ratio < 4.5:
                failures.append(
                    f"{path.stem}: accent gradient {stop} is {ratio:.2f}:1"
                )
        for stop in re.findall(r"#[0-9a-fA-F]{6}", brand_gradient.group(1)):
            ratio = _contrast(stop, tokens["bg"])
            if ratio < 4.5:
                failures.append(
                    f"{path.stem}: brand gradient {stop} is {ratio:.2f}:1"
                )
    assert not failures, "\n".join(failures)


def test_base_tokens_bridge_legacy_names_to_canonical_palette() -> None:
    css = (TOKEN_ROOT / "base.css").read_text(encoding="utf-8")
    expected_aliases = {
        "--bg-elev-1: var(--bg-elev)",
        "--bg-elev2: var(--bg-elev-2)",
        "--panel: var(--bg-elev)",
        "--fg-muted: var(--fg-dim)",
        "--text-primary: var(--fg)",
        "--text-secondary: var(--fg-dim)",
        "--err: var(--fail)",
        "--success: var(--ok)",
        "--warning: var(--warn)",
        "--mono: var(--font-mono)",
        "--focus-ring: var(--accent)",
        # 17 rules asked for --danger, which nothing defined, so each fell
        # back to its own literal -- seven different reds across the GUI.
        "--danger: var(--fail)",
    }
    assert expected_aliases <= set(line.strip(" ;") for line in css.splitlines())


def test_shell_has_responsive_canvas_and_consistent_focus_contract() -> None:
    shell = (CSS_ROOT / "layout" / "shell.css").read_text(encoding="utf-8")
    resets = (CSS_ROOT / "layout" / "base-resets.css").read_text(encoding="utf-8")
    sidebar = (CSS_ROOT / "layout" / "sidebar.css").read_text(encoding="utf-8")

    assert "height: 100dvh" in shell
    assert "grid-template-columns: minmax(220px, 260px) minmax(0, 1fr)" in shell
    assert "@media (max-width: 760px)" in shell
    assert "overflow-x: auto" in shell
    assert "--focus-ring" in resets
    assert ":focus-visible" in resets
    assert ".subsystem-entry:focus-visible" in sidebar


def test_shell_markup_exposes_skip_link_and_log_tab_relationships() -> None:
    html = (ROOT / "gui_frontend" / "src" / "index.html").read_text(
        encoding="utf-8"
    )
    assert 'class="skip-link" href="#main"' in html
    assert '<main class="main" id="main" tabindex="-1">' in html
    assert re.search(
        r'<button\s+type="button"\s+data-view="overview"\s+'
        r'class="subsystem-entry active"',
        html,
    )
    assert re.search(
        r'<button\s+type="button"\s+data-view="about"\s+class="subsystem-entry"',
        html,
    )
    for bucket in ("messages", "warnings", "errors", "apdu", "validation"):
        assert f'aria-controls="log-tabpanel-{bucket}"' in html
        assert f'id="log-tabpanel-{bucket}"' in html
        assert f'aria-labelledby="log-tab-{bucket}"' in html


def test_static_shell_ids_are_unique_and_label_targets_exist() -> None:
    html = (ROOT / "gui_frontend" / "src" / "index.html").read_text(
        encoding="utf-8"
    )
    ids = re.findall(r'\bid="([^"]+)"', html)
    duplicates = sorted(
        value for value, count in Counter(ids).items() if count > 1
    )
    assert duplicates == []

    id_set = set(ids)
    missing_targets = sorted(
        target
        for target in re.findall(r'<label\b[^>]*\bfor="([^"]+)"', html)
        if target not in id_set
    )
    assert missing_targets == []


def test_reader_session_close_is_a_sibling_button_with_a_full_target() -> None:
    js = (
        ROOT / "gui_frontend" / "src" / "js" / "command-center.js"
    ).read_text(encoding="utf-8")
    css = (
        CSS_ROOT / "views" / "reader-pill.css"
    ).read_text(encoding="utf-8")
    start = js.index("  function readerBarBuildPill(")
    end = js.index("\n  function readerBarShortName(", start)
    pill = js[start:end]

    assert 'var pillGroup = document.createElement("span")' in pill
    assert 'var pill = document.createElement("button")' in pill
    assert 'var close = document.createElement("button")' in pill
    assert pill.index("pillGroup.appendChild(pill)") < pill.index(
        "pillGroup.appendChild(close)"
    )
    assert "pill.appendChild(close)" not in pill
    assert 'close.setAttribute("aria-label", "Close session on " + name)' in pill
    assert re.search(
        r"\.topbar-reader-pill-close\s*\{[^}]*"
        r"width:\s*28px;[^}]*height:\s*28px;",
        css,
        re.DOTALL,
    )
    assert ".topbar-reader-pill-close:focus-visible" in css


# Surfaces allowed to position themselves against the viewport. Everything
# else renders in normal document flow: action output stacks as
# ``.cc-panel`` sections in the surface that produced it, so a session
# cannot accumulate floating windows the operator has to close by hand.
#
# The entries here are either app chrome (skip link, sidebar) or a
# transient overlay dismissed by the interaction that opened it. Adding a
# row means adding a surface that floats -- justify it in review.
#
# ``.cc-max-backdrop`` is listed to keep this test passing, not as an
# endorsement: its only entry point, ``toggleMaximize`` in trailing.js,
# has no callers. Pending removal.
FIXED_POSITION_SURFACES = {
    ".skip-link",
    ".sidebar",
    ".cc-doc-modal",
    ".cc-fs-explorer-overlay",
    ".saip-find-overlay",
    ".saip-modal-host",
    ".cc-max-backdrop",
    ".ctx-menu",
}


def test_only_chrome_and_transient_overlays_position_against_the_viewport() -> None:
    found: set[str] = set()
    for path in sorted(CSS_ROOT.rglob("*.css")):
        css = re.sub(
            r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.DOTALL
        )
        for match in re.finditer(r"position:\s*fixed", css):
            selector = (
                css[: match.start()]
                .rsplit("}", 1)[-1]
                .split("{")[0]
                .strip()
                .replace("\n", " ")
            )
            found.add(selector)
    assert found == FIXED_POSITION_SURFACES


def test_action_output_renders_as_inline_panels() -> None:
    """The floating action-window system must not come back."""
    bundle = (
        ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
    ).read_text(encoding="utf-8")
    assert "function ccInlinePanel(" in bundle
    assert "cc-popout" not in bundle
    for floating in ("resize: both", "cc-popout-host"):
        assert floating not in bundle


# Colour literals that legitimately stay out of the token layer, per file.
#
# Three kinds survive the token sweep:
#   * a categorical hue -- a PE-kind icon, a diff A/B side, a var kind, a
#     file glyph. These identify a thing, they do not report a status, so
#     folding them onto --ok / --warn / --fail would make a neutral
#     comparison read as a verdict.
#   * a black scrim or drop shadow, which is black in every theme.
#   * a fixed contrast pair (#fff on a filled button, and friends).
#
# Anything that reports a status resolves through a token, so it follows
# all 16 themes. These numbers are a ceiling: they may fall, and a file
# not listed here may not introduce any.
BARE_COLOUR_BUDGET = {
    "layout/readers.css": 1,
    "layout/shell.css": 1,
    "views/cc-status-strip.css": 1,
    "views/eim-local.css": 1,
    "views/env-flags.css": 6,
    "views/guides-modal.css": 2,
    "views/key-value-swatches.css": 1,
    "views/misc-trailing.css": 2,
    "views/pretty-value-ef.css": 1,
    "views/saip/applications-tab-cards.css": 13,
    "views/saip/editor-compare.css": 2,
    "views/saip/file-system-tree.css": 3,
    "views/saip/find-overlay.css": 2,
    "views/saip/pe-card-list.css": 25,
    "views/saip/semantic-diff.css": 6,
    "views/saip/typed-pe-editor.css": 5,
    "views/saip/variable-editor-modal.css": 2,
    "views/saip/variable-editor-polish.css": 11,
    "views/saip/workbench-shell.css": 6,
    "views/scp03-bulk.css": 1,
    "views/workbench-context-menu.css": 1,
    "views/workbench-ribbon.css": 1,
}

_VAR_FALLBACK = re.compile(
    r"var\(\s*--[\w-]+\s*,\s*([^()]*?(?:\([^()]*\))?[^()]*?)\s*\)"
)
_COLOUR_LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)")


def _bare_colour_count(css: str) -> int:
    """Colour literals that are not a var() fallback and not in a comment.

    A ``var(--token, #888)`` fallback never fires -- a theme is always
    loaded -- so it is noise, not a theming bug. ``color-mix()`` resolves
    a token, so its arguments are not literals either.
    """
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    masked = list(body)
    for match in _VAR_FALLBACK.finditer(body):
        start, end = match.span(1)
        for index in range(start, end):
            masked[index] = " "
    resolved = re.sub(r"color-mix\([^)]*\)", " ", "".join(masked))
    return len(_COLOUR_LITERAL.findall(resolved))


def test_status_colours_resolve_through_theme_tokens() -> None:
    over_budget: list[str] = []
    for path in sorted(CSS_ROOT.rglob("*.css")):
        relative = path.relative_to(CSS_ROOT).as_posix()
        if relative.startswith("tokens/"):
            continue
        count = _bare_colour_count(path.read_text(encoding="utf-8"))
        budget = BARE_COLOUR_BUDGET.get(relative, 0)
        if count > budget:
            over_budget.append(f"{relative}: {count} bare literals, budget {budget}")
    assert not over_budget, "\n".join(over_budget)


# Tokens whose var() fallback is load-bearing, and why.
#
# Everything else resolves through base.css or all 16 theme files, so a
# fallback beside it is dead code holding a stale value -- and a stale
# value is what a theme is supposed to replace.
FALLBACK_ALLOWED = {
    # Set from JS (trailing.js sizes the dock), unset until then.
    "--log-dock-height",
    # Nord-only weave. base.css documents these as opt-in: other themes
    # are meant to take the fallback.
    "--ygg-frost", "--ygg-amber",
    "--tree-mf-fg", "--tree-mf-bg", "--tree-mf-edge",
    "--tree-adf-fg", "--tree-adf-bg", "--tree-adf-edge",
    "--tree-df-fg", "--tree-df-bg", "--tree-df-edge",
    "--tree-ef-fg", "--tree-ef-bg", "--tree-ef-edge",
    # Phantom: no theme defines a --nord-* token and none is planned, so
    # these four var() calls always take the fallback. Left as-is because
    # picking their replacement is a design call about what the badges
    # mean, not fallback cleanup.
    "--nord-frost-1", "--nord-frost-2", "--nord-aurora-2", "--nord-aurora-3",
}

_VAR_WITH_FALLBACK = re.compile(r"var\(\s*(--[\w-]+)\s*,")


def _tokens_defined_everywhere() -> set[str]:
    base = set(
        re.findall(r"--([\w-]+)\s*:", (TOKEN_ROOT / "base.css").read_text(encoding="utf-8"))
    )
    per_theme = [
        set(re.findall(r"--([\w-]+)\s*:", path.read_text(encoding="utf-8")))
        for path in TOKEN_ROOT.glob("*.css")
        if path.stem in THEMES
    ]
    return base | set.intersection(*per_theme)


def test_no_var_fallback_shadows_a_token_every_theme_defines() -> None:
    everywhere = _tokens_defined_everywhere()
    offenders: list[str] = []
    for path in sorted(CSS_ROOT.rglob("*.css")):
        relative = path.relative_to(CSS_ROOT).as_posix()
        if relative.startswith("tokens/"):
            continue
        for match in _VAR_WITH_FALLBACK.finditer(path.read_text(encoding="utf-8")):
            token = match.group(1)
            if token in FALLBACK_ALLOWED:
                continue
            if token[2:] in everywhere:
                offenders.append(f"{relative}: {token} has a dead fallback")
    assert not offenders, "\n".join(sorted(set(offenders)))
