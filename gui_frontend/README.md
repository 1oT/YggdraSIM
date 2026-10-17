<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# YggdraSIM Universal GUI -- Frontend Source

This directory holds the canonical source for the YggdraSIM universal GUI
frontend. The served bundle at `yggdrasim_common/gui_server/static/` is
**build output** -- never edit it directly.

## Quickstart

```bash
# Build the production bundle (runs after every source change):
./scripts/build_gui_frontend.sh

# Dev mode -- symlinks static/ → src/ so edits are live:
./scripts/build_gui_frontend.sh --dev

# Desktop launch:
python main/main.py --gui

# Web-server launch:
python main/main.py --web-server --port 27853
```

## Source Structure

```
gui_frontend/src/
  index.html          SPA shell (static DOM)
  theme-init.js       Pre-paint theme bootstrap (single VALID_THEMES source)
  css/
    tokens/           20 theme palettes + base tokens + keyframes
    layout/           Shell, sidebar, topbar, readers, log-dock
    components/       Reusable: buttons, cards, tables, modals, trees, terminal
    views/            View-specific styles grouped by feature
      saip/           SAIP workbench sub-views
  js/
    __head.js         IIFE wrapper + header comment
    core.js           Token, theme, DOM helpers, API client, routing,
                      data loaders, event wiring, terminal, live readers,
                      card bridge panel
    command-center.js Command Center + SCP03 workbench + reader bar +
                      output renderers + auth + mutations
    saip-workbench.js SAIP profile editor -- PE cards, file system tree,
                      typed editors, compare, variable editor
    trailing.js       Tab persistence, FCP cache, log bus, reader pane,
                      log dock, live APDU bus, about, docs, host shell, init
    __foot.js         DOMContentLoaded trigger + IIFE closing
  vendor/
    xterm/            xterm.js + addon-fit.js + styles (vendored, not edited)
```

## Build Pipeline

`scripts/build_gui_frontend.sh` concatenates the modular source files
into the production bundle at `yggdrasim_common/gui_server/static/`.

- CSS concatenation order is governed by `css/.css_order`.
- JS concatenation order is governed by `js/.js_order`.
- Every chunk keeps its own SPDX header; the build retains the first header
  only, producing one clean served document.
- The splitter scripts locate reviewed semantic/content anchors and fail when
  a boundary is missing, ambiguous, or reordered. They no longer depend on
  absolute line numbers.
- Tests reconstruct `app.js`, `app.css`, `index.html`, and `theme-init.js`
  from source and require byte-for-byte equality with the served bundle.

## Adding a Theme

Seven registration points; the first two fail silently when missed.

1. Create `css/tokens/<name>.css` with the `html[data-theme="<name>"]`
   block defining every token the other themes define (diff against
   `github-light.css`; `base.css` is an alias layer, not a fallback).
2. Add `tokens/<name>.css` to `css/.css_order`, or the file never
   reaches the bundle.
3. Add `<name>` to the `VALID` object in `theme-init.js` (the single
   source of truth, exposed as `window.YGG_VALID_THEMES`).
4. Add it to the inline `VALID_THEMES` fallback in `js/core.js`, used
   when `window.YGG_VALID_THEMES` is unset.
5. Add it to `THEMES` in `tests/test_gui_design_system_consistency.py`
   and add the `<option>` in `index.html`'s theme-select dropdown.
6. Add it to the matching `color-scheme` block in
   `css/layout/base-resets.css`. A theme in neither block leaves native
   controls, popup menus and scrollbars on the browser default; the
   `-light` suffix is matched by selector, any other name is listed.
7. Run `python scripts/generate_cli_palettes.py`. The CLI and the
   secure-channel shells read their terminal palettes from
   `yggdrasim_common/cli_palettes.py`, transcribed from these token
   files and selected with `YGGDRASIM_CLI_THEME`;
   `tests/test_cli_theme.py` fails when the table is stale.

Solve the contrast numbers before writing the file: `--fg-dim`,
`--accent`, `--ok`, `--warn` and `--fail` need 4.5:1 on `--bg` and
`--bg-elev` (`--fg-dim` also on `--bg-elev-2`), `--accent` needs 3:1 on
`--bg-elev-2`, every `--gradient-accent` stop 4.5:1 on `--accent-fg` and
every `--gradient-brand` stop 4.5:1 on `--bg`. Then run
`./scripts/build_gui_frontend.sh` and the two tests below.

## Design Contract

One design system, 20 themes: a change is correct when it looks native
in every theme without a palette of its own.
`tests/test_gui_design_system_consistency.py` enforces the rules below;
`tests/test_gui_source_manifests.py` enforces the bundle.

- Colour reaches a rule through a token or not at all. Theme files define
  the palette (`--bg`, `--bg-elev`, `--bg-elev-2`, `--surface`, `--fg`,
  `--fg-dim`, `--accent*`, `--ok*`, `--warn*`, `--fail*`, `--border*`,
  `--code-bg`, `--shadow-*`, `--gradient-*`, `--topbar-bg`);
  `tokens/base.css` adds the aliases and the non-colour tokens
  (`--radius-*`, `--font-*`, `--transition-*`, the `--tree-*` file-kind
  chips).
- The per-file bare-literal budget in the test is a ceiling: it may fall,
  never rise, and a file not listed may not introduce a literal. A
  literal `color:` outside `tokens/` fails outright. Categorical hues (a
  PE kind, a diff side, a file glyph) are the only literals that survive
  review; anything reporting a status resolves through `--ok`, `--warn`
  or `--fail`.
- No `var(--token, fallback)` for a token every theme defines: the
  fallback is dead code holding a stale value.
- `position: fixed` is reserved for app chrome and transient overlays.
  Action output renders inline as `.cc-panel` sections in the surface
  that produced it; no floating windows, no `resize: both`.
- A chrome element that carries `overflow: hidden` (for a rounded corner
  or a clipped background) and sits in a flex column needs
  `flex: 0 0 auto`. The overflow makes it a scroll container, which
  zeroes the automatic minimum size it would otherwise get as a flex
  item, so it is the one child the column can shrink below its content
  and it absorbs the whole deficit while its siblings hold their floors.
  The SCP03 ribbon rendered 37px against a 118px content height that
  way, cutting its tab labels in half. The panes are what a squeeze is
  meant to reach: they scroll, the chrome does not.
- Layers: `tokens/` (palettes, keyframes, responsive and reduced-motion
  rules), `layout/` (grid areas and chrome), `components/` (theme-agnostic
  reusable pieces), `views/` and `views/saip/` (feature-specific; they
  read tokens and never redefine them).
- Motion uses `var(--transition-*)`; reduced-motion handling lives in
  `tokens/base.css`.
- Every operator-visible label is anchored in a specification or marked
  YggdraSIM-coined in `guides/NAMING_CONVENTIONS.md`; a new label adds a
  row there.
- The page CSP is `script-src 'self'` with no `unsafe-eval`: no inline
  scripts, styles or event handlers in `index.html`, no `eval` or
  `new Function`. Build DOM with `createElement` / `textContent`; where
  `innerHTML` is used, every interpolated value goes through
  `escapeHtml()`.

## JS Conventions

- The IIFE wrapper (`__head.js` / `__foot.js`) provides the shared
  closure. All `var` declarations and `function` definitions inside
  share the same scope -- treat them as if they were in one file.
- `core.js` contains infrastructure that everything else depends on
  (API client, routing, DOM helpers, health poll).
- Larger feature chunks (`command-center.js`, `saip-workbench.js`)
  are self-contained within their domain but may reference functions
  and state from `core.js`.
- `trailing.js` contains init-time setup and late-binding features.

## Testing

- `--gui`: `python main/main.py --gui`. Opens a native window against
  `127.0.0.1:27853` by default.
- `--web-server`: `python main/main.py --web-server --token-file tok`
  (token file must contain >= 32 characters and be `chmod 600`).
- Headless API smoke: `curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:27853/api/health`.
- After any `src/` change: `./scripts/build_gui_frontend.sh`, then
  `tests/test_gui_source_manifests.py` and
  `tests/test_gui_design_system_consistency.py`.
