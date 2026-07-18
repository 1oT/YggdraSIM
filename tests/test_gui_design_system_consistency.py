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
