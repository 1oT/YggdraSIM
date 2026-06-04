# YggdraSIM GUI — Comprehensive Refactor Plan

**Status**: draft / review
**Date**: 2026-05-20
**Scope**: GUI presentation layer only (HTML, CSS, JS). Backend Python logic preserved as-is.

---

## 1. Root Cause Analysis

The GUI suffers from a **dual-source-tree divergence** that has been
growing unchecked since Phase A landed. Every attempt to add features,
modify styling, or fix bugs runs into one or more of the override
layers described below, resulting in failed or multi-attempt changes.

### 1.1 The Two Trees

| Location | Intended role | Actual role | JS lines | CSS lines | HTML lines |
|---|---|---|---|---|---|
| `gui_frontend/src/` | Editable source | Stale orphan (Phase A snapshot) | 3,759 | 3,319 | 435 |
| `yggdrasim_common/gui_server/static/` | Built output (served by FastAPI) | De-facto source (all features landed here) | 43,361 | 14,899 | 698 |

The README at `gui_frontend/README.md` says: *"When editing Phase A
assets, change both copies in lockstep — or use
`scripts/build_gui_frontend.sh` once it lands."* Neither directive was
followed:

- `scripts/build_gui_frontend.sh` was **never created**.
- All feature development bypassed `gui_frontend/src/` entirely and
  landed directly in `yggdrasim_common/gui_server/static/`.
- The "source" tree now has **5 themes** vs the static tree's **16
  themes**, a fundamentally different HTML layout, and is missing the
  sidebar-collapse toggle, topbar reader strip, card bridge panel,
  guides viewer, terminal tabs, log dock copy button, and the entire
  SAIP workbench.

### 1.2 Override Layers (Why Changes Fail)

Changes typically need to touch 3-5 independent layers, and missing
any one causes broken behavior:

**Layer 1 — CSS cascade:**
```
:root (base tokens)
  → html[data-theme="nord-dark"] (theme override, ~70 properties)
  → Yggdrasil weave tokens (--ygg-frost etc., Nord-only)  
  → Component-specific selectors (e.g. .cc-tree-icon-*)
  → JS-applied inline styles (terminal, SAIP workbench)
```

**Layer 2 — JS theme state:**
```
theme-init.js (pre-paint, validates 5 themes in gui_frontend, 16 in static)
  → app.js VALID_THEMES object (duplicate of theme-init.js validation)
  → app.js applyTheme() (writes to localStorage + DOM attribute)
  → Individual component theme-aware rendering (hardcoded color refs)
```

**Layer 3 — HTML DOM structure:**
```
index.html (static DOM shell: topbar, sidebar, views, log-dock)
  → app.js (dynamically generates: action cards, SAIP workbench,
     file system trees, form inputs, modals, guides viewer, etc.)
```
Changes to dynamically generated DOM must match the CSS selectors
and the static HTML structure.

**Layer 4 — File duplication:**
Any edit to a static file (JS/CSS/HTML/vendor) must be mirrored to
`gui_frontend/src/` — but since the files have diverged so massively,
this mirroring is impossible to do mechanically.

### 1.3 Monolith Metrics

`app.js` (43,361 lines):
- Zero section markers or module boundaries
- No class definitions — entirely procedural
- No `"use strict"` function wrappers
- Top-level variables interleaved with function definitions
- Mixed concerns: API client, routing, view rendering, theme
  management, terminal PTY, SAIP workbench, file system trees, form
  handling, CSV export, clipboard operations, keyboard shortcuts

`app.css` (14,899 lines):
- 16 full theme blocks (~40 properties each, many repeated tokens)
- Component styles interleaved with layout and theme overrides
- SAIP workbench alone spans ~8,000 lines with its own sub-sections
- No import mechanism, no cascade layers

---

## 2. What Stays Unchanged (Preserved)

The entire Python backend is out of scope for this refactor:

| Module | Lines | Role |
|---|---|---|
| `yggdrasim_common/gui_server/app.py` | 626 | FastAPI factory + run_desktop / run_web_server |
| `yggdrasim_common/gui_server/config.py` | — | GuiServerConfig, arg parsing, env resolution |
| `yggdrasim_common/gui_server/auth.py` | — | Bearer-token middleware, CSP, rate limiting |
| `yggdrasim_common/gui_server/sessions.py` | — | Card session lifecycle |
| `yggdrasim_common/gui_server/terminal.py` | — | PTY bridge for xterm.js |
| `yggdrasim_common/gui_server/host_shell.py` | — | Host shell PTY |
| `yggdrasim_common/gui_server/at_decoder.py` | — | AT command decoder |
| `yggdrasim_common/gui_server/routes/*.py` | 3,206 | All HTTP/WS endpoints |
| `yggdrasim_common/gui_server/actions/*.py` | ~34,000 | All action dispatchers |
| `yggdrasim_common/gui_server/actions/registry.py` | 317 | ActionSpec, ActionRegistry, coerce_input |

These modules wrap CLI engine logic for the GUI. They are
well-structured, independently testable, and share no code with the
presentation layer. The refactor only touches:

- `yggdrasim_common/gui_server/static/` (all files)
- `gui_frontend/src/` (all files)
- `gui_frontend/README.md` (update)
- New `scripts/build_gui_frontend.sh`

---

## 3. The Plan

### Phase 0 — Safety: Stake Current State

Before any changes, create irrevocable backups:

```bash
# Backup the served bundle
cp -a yggdrasim_common/gui_server/static yggdrasim_common/gui_server/static._pre_refactor

# Backup the orphan source
cp -a gui_frontend/src gui_frontend/src._pre_refactor

# Backup the entire GUI server Python tree (actions, routes, app.py, etc.)
cp -a yggdrasim_common/gui_server yggdrasim_common/gui_server._pre_refactor_backend

# Tag the current commit
git tag pre-gui-refactor-$(date +%Y%m%d)
```

These backups are **never modified** during the refactor. They serve as
the reference for re-adding any backend logic that might be affected.

### Phase 1 — Establish Single Source of Truth

**Goal**: `gui_frontend/src/` becomes the single canonical source.
`yggdrasim_common/gui_server/static/` becomes build output only.

**Steps:**

1. Delete the stale content in `gui_frontend/src/` (it is >10x smaller
   and outdated — all features already exist in the static tree).

2. Port the current static tree contents into `gui_frontend/src/` as
   the starting point:
   - `static/app.js` → `gui_frontend/src/app.js`
   - `static/app.css` → `gui_frontend/src/app.css`
   - `static/index.html` → `gui_frontend/src/index.html`
   - `static/theme-init.js` → `gui_frontend/src/theme-init.js`
   - `static/vendor/` → `gui_frontend/src/vendor/` (xterm.js, addon-fit.js, xterm.css)

3. Update `gui_frontend/README.md` to reflect the new reality.

### Phase 2 — Modularize JavaScript

**Goal**: Split the 43,361-line monolith into modules with clear
responsibilities. Each module is loaded via a `<script>` tag (Phase A
stays build-free). A simple concatenation build step produces the final
`app.js`.

**Proposed module split:**

```
gui_frontend/src/js/
  core/
    bootstrap.js      — token extraction, CSP compliance, init sequence
    api.js             — fetch() wrapper, auth header injection, error normalization
    router.js          — view switching, breadcrumbs, URL hash routing
    theme.js           — VALID_THEMES (single source), applyTheme(), theme picker
    state.js           — shared reactive state (active reader, session, backend, etc.)
    log-dock.js        — event log dock (messages/warnings/errors/APDU tabs)
    readers.js         — PC/SC reader enumeration, topbar pill strip
    statusbar.js       — footer status bar (action, readers, sessions, activity)
    keyboard.js        — global keyboard shortcuts
  views/
    overview.js        — overview dashboard (health, backend, command center cards)
    command-center.js  — action card grid, form rendering, run/stream dispatch
    registry.js        — registry browser (symbol search, table)
    backend.js         — card backend settings panel
    env-flags.js       — environment flags viewer/editor
    terminal.js        — xterm.js PTY terminal (tabbed)
    host-shell.js      — host shell terminal + AT decode pane
    live-readers.js    — PC/SC reader table view
    card-bridge.js     — card bridge status + probe + latency chart
    about.js           — about page + guides viewer modal
    saip-workbench.js  — SAIP workbench (largest module, ~17K lines)
    saip-tree.js       — SAIP file system tree + icon rendering
    saip-editor.js     — SAIP PE editor + variable editor
    saip-compare.js    — SAIP compare/diff views
    saip-validate.js   — SAIP validation dock
  components/
    modal.js           — generic modal dialog
    tree.js            — recursive tree view (used by SAIP + SCP03 FS)
    table.js           — sortable/filterable data table
    form.js            — dynamic form builder from ActionSpec schema
    badge.js           — status badge component
    toast.js           — transient notification
```

**Loading strategy (Phase A, no build step required for dev):**

```html
<!-- index.html loads individual modules -->
<script src="/static/js/core/bootstrap.js"></script>
<script src="/static/js/core/api.js"></script>
...
```

The build step (Phase 4) concatenates them in dependency order for
production.

### Phase 3 — Modularize CSS

**Goal**: Split the 14,899-line monolith into a layered architecture
where themes, layout, components, and views are separate files.

**Proposed CSS split:**

```
gui_frontend/src/css/
  tokens/
    base.css           — :root { --radius-*, --font-*, --transition-*,
                          @keyframes, @media (prefers-reduced-motion) }
    nord-dark.css      — html[data-theme="nord-dark"] { --bg, --fg, ... }
    nord-light.css     — html[data-theme="nord-light"] { ... }
    oneot-dark.css
    oneot-light.css
    ocean-dark.css
    gruv-dark.css
    ink-light.css
    solarized-dark.css
    solarized-light.css
    tokyo-night.css
    catppuccin-mocha.css
    catppuccin-latte.css
    dracula.css
    github-dark.css
    github-light.css
    matrix.css
  layout/
    shell.css          — .app-shell, .topbar, .sidebar, .main, .log-dock,
                          .statusbar, CSS Grid areas
    responsive.css     — media queries, collapse states
  components/
    buttons.css        — .btn, .btn-primary, .btn-danger, .btn-small
    cards.css          — .card, .card-grid, .cc-actions
    forms.css          — .form-row, input, select, textarea, checkbox
    tables.css         — .data-table
    modals.css         — .cc-doc-modal, .cc-modal-backdrop
    tree.css           — .cc-tree-*, file system tree styles
    badges.css         — .badge, .badge-mode, .badge-api, .cc-chip
    terminal.css       — .terminal-host, .cc-wb-*
    log-dock.css       — .log-dock-*
    readers.css        — .topbar-readers, .reader-pill
  views/
    overview.css
    command-center.css
    registry.css
    backend.css
    env-flags.css
    terminal.css
    host-shell.css
    live-readers.css
    card-bridge.css
    about.css
    saip/
      workbench.css    — SAIP shell: ribbons, tab strip, panels
      tree.css         — SAIP file system tree specifics
      editor.css       — PE editor, typed PE cards, token editor
      compare.css      — diff views
      validate.css     — collapsible validation dock
```

**Theme file template (every theme is exactly one file):**

```css
/* css/tokens/nord-dark.css — Nord Dark palette */
html[data-theme="nord-dark"] {
  --bg:             #2e3440;
  --bg-elev:        #3b4252;
  --bg-elev-2:      #434c5e;
  --surface:        #3b4252;
  --surface-alt:    rgba(255, 255, 255, 0.04);
  --bg-hover:       rgba(216, 222, 233, 0.06);
  --border:         rgba(216, 222, 233, 0.12);
  --border-strong:  rgba(216, 222, 233, 0.22);
  --fg:             #eceff4;
  --fg-dim:         #9aa5b8;
  --accent:         #88c0d0;
  --accent-strong:  #5e81ac;
  --accent-soft:    rgba(136, 192, 208, 0.16);
  --accent-fg:      #2e3440;
  --accent-glow:    rgba(136, 192, 208, 0.45);
  --gradient-accent: linear-gradient(135deg, #88c0d0 0%, #81a1c1 50%, #5e81ac 100%);
  --gradient-brand:  linear-gradient(135deg, #88c0d0 0%, #b48ead 100%);
  --ok:             #a3be8c;
  --ok-soft:        rgba(163, 190, 140, 0.15);
  --warn:           #ebcb8b;
  --warn-soft:      rgba(235, 203, 139, 0.15);
  --fail:           #bf616a;
  --fail-soft:      rgba(191, 97, 106, 0.15);
  --code-bg:        #242933;
  --kbd-bg:         rgba(36, 41, 51, 0.96);
  --shadow-card:    0 10px 26px rgba(0, 0, 0, 0.28);
  --shadow-card-hover: 0 18px 42px rgba(0, 0, 0, 0.42);
  --shadow-glow-accent: 0 0 0 1px var(--accent-soft), 0 12px 40px -12px var(--accent-glow);
  --topbar-bg:      rgba(59, 66, 82, 0.72);

  /* Yggdrasil weave (Nord-only) */
  --ygg-frost:  #88c0d0;  --ygg-amber: #d8a76a;  --ygg-runic: #9c8eb6;
  --ygg-leaf:   #a3be8c;  --ygg-bark:  #8b7a63;  --ygg-ember: #c98a6e;
  --ygg-mist:   #aebed1;

  --tree-mf-fg:  var(--ygg-frost);  --tree-mf-bg:  rgba(136,192,208,0.16);
  --tree-adf-fg: var(--ygg-amber);  --tree-adf-bg: rgba(216,167,106,0.16);
  --tree-df-fg:  var(--ygg-runic);  --tree-df-bg:  rgba(156,142,182,0.16);
  --tree-ef-fg:  var(--ygg-leaf);   --tree-ef-bg:  rgba(163,190,140,0.14);

  --theme-tint: radial-gradient(circle at top left,
    rgba(136,192,208,0.12), transparent 42%),
    radial-gradient(circle at bottom right,
    rgba(156,142,182,0.09), transparent 40%), ...;
}
```

**Adding a new theme** becomes a 3-step process:
1. Create `css/tokens/<name>.css` with the token block.
2. Add `<link rel="stylesheet" href="/static/css/tokens/<name>.css">` to index.html.
3. Add the theme name to `VALID_THEMES` in `js/core/theme.js`.

### Phase 4 — Build Pipeline

**Goal**: A trivial shell script that concatenates the modular source
files into the production bundle served by FastAPI.

```bash
# scripts/build_gui_frontend.sh
# Concatenates modular JS and CSS sources from gui_frontend/src/
# into yggdrasim_common/gui_server/static/ for FastAPI serving.
#
# Usage:
#   ./scripts/build_gui_frontend.sh          # production (concatenated)
#   ./scripts/build_gui_frontend.sh --dev    # symlink for live editing

set -euo pipefail

SRC="gui_frontend/src"
OUT="yggdrasim_common/gui_server/static"

if [ "${1:-}" = "--dev" ]; then
  # Dev mode: symlink static/ → src/ so edits are live.
  rm -rf "$OUT"
  ln -s "../../gui_frontend/src" "$OUT"
  echo "[+] Dev mode: $OUT → $SRC (symlink)"
  exit 0
fi

# Production mode: concatenate and copy.
mkdir -p "$OUT/css" "$OUT/js" "$OUT/vendor"

# --- CSS concatenation ---
cat "$SRC/css/tokens/base.css" \
    "$SRC/css/tokens/"*.css \
    "$SRC/css/layout/"*.css \
    "$SRC/css/components/"*.css \
    "$SRC/css/views/"*.css \
    "$SRC/css/views/saip/"*.css \
    > "$OUT/app.css"

# --- JS concatenation ---
cat "$SRC/js/core/bootstrap.js" \
    "$SRC/js/core/api.js" \
    "$SRC/js/core/state.js" \
    "$SRC/js/core/theme.js" \
    "$SRC/js/core/router.js" \
    "$SRC/js/core/readers.js" \
    "$SRC/js/core/log-dock.js" \
    "$SRC/js/core/statusbar.js" \
    "$SRC/js/core/keyboard.js" \
    "$SRC/js/components/modal.js" \
    "$SRC/js/components/tree.js" \
    "$SRC/js/components/table.js" \
    "$SRC/js/components/form.js" \
    "$SRC/js/components/badge.js" \
    "$SRC/js/views/overview.js" \
    "$SRC/js/views/command-center.js" \
    "$SRC/js/views/registry.js" \
    "$SRC/js/views/backend.js" \
    "$SRC/js/views/env-flags.js" \
    "$SRC/js/views/terminal.js" \
    "$SRC/js/views/host-shell.js" \
    "$SRC/js/views/live-readers.js" \
    "$SRC/js/views/card-bridge.js" \
    "$SRC/js/views/about.js" \
    "$SRC/js/views/saip-workbench.js" \
    "$SRC/js/views/saip-tree.js" \
    "$SRC/js/views/saip-editor.js" \
    "$SRC/js/views/saip-compare.js" \
    "$SRC/js/views/saip-validate.js" \
    > "$OUT/app.js"

# --- Static assets (copy verbatim) ---
cp "$SRC/index.html" "$OUT/index.html"
cp "$SRC/theme-init.js" "$OUT/theme-init.js"
cp -r "$SRC/vendor/" "$OUT/vendor/"

echo "[+] Built $OUT/ from $SRC/"
echo "    app.js  : $(wc -l < "$OUT/app.js") lines"
echo "    app.css : $(wc -l < "$OUT/app.css") lines"
```

### Phase 5 — Single Theme Validation Source

**Goal**: One authoritative list of valid themes. Adding a theme
touches exactly 3 places (CSS file, HTML `<link>`, VALID_THEMES entry).

**`js/core/theme.js`** (single source):
```javascript
var VALID_THEMES = {
  "nord-dark":          1, "nord-light":          1,
  "oneot-dark":         1, "oneot-light":         1,
  "ocean-dark":         1, "gruv-dark":           1,
  "ink-light":          1, "solarized-dark":      1,
  "solarized-light":    1, "tokyo-night":         1,
  "catppuccin-mocha":   1, "catppuccin-latte":    1,
  "dracula":            1, "github-dark":         1,
  "github-light":       1, "matrix":              1
};
```

**`theme-init.js`** imports this from a shared inline constant (or the
build step inlines it). No more dual validation.

### Phase 6 — Deprecate the Duplicate Copy

After the build pipeline is in place:

1. `yggdrasim_common/gui_server/static/` becomes **build output
   only** — never edited directly.
2. Add a check to `build_gui_frontend.sh` that refuses to run if
   `static/` contains uncommitted changes (i.e., someone edited the
   output directly).
3. Update `.gitignore` to mark `static/` as generated:
   ```
   yggdrasim_common/gui_server/static/app.js
   yggdrasim_common/gui_server/static/app.css
   ```
   (Keep `index.html`, `theme-init.js`, and `vendor/` tracked since
   they're needed for the SPA to function in the installed wheel.)

4. Update `CLAUDE.md` and `.cursor/rules/*.mdc` with the new rule:
   > GUI frontend edits go into `gui_frontend/src/`. Run
   > `scripts/build_gui_frontend.sh` after every change. Never edit
   > `yggdrasim_common/gui_server/static/` directly.

### Phase 7 — Verification

After each phase, verify:

1. **Parse check**: `node -e "require('./gui_frontend/src/app.js')"` —
   or for ES5: `eslint gui_frontend/src/js/` for syntax errors.

2. **Build**: `scripts/build_gui_frontend.sh` produces the expected
   output.

3. **Launch desktop**: `python main/main.py --gui` opens the pywebview
   window, all views render, theme switcher works.

4. **Launch web-server**: `python main/main.py --web-server --port 0`
   starts, SPA loads in browser.

5. **Smoke test actions**: Run one action from each subsystem
   (SCP03, SCP11, Tools, SAIP).

6. **Targeted pytest**: Run the GUI test suite one file at a time,
   comparing pass/fail counts against the pre-refactor baseline.

---

## 4. Expected Outcomes

| Problem | Resolution |
|---|---|
| Dual source trees diverged | Single source at `gui_frontend/src/`, build step produces `static/` |
| 43K-line monolithic app.js | ~30 modules, each <2K lines, with clear ownership |
| 15K-line monolithic app.css | ~50 files in 4 layers (tokens/layout/components/views) |
| Theme validation duplicated | Single VALID_THEMES in `js/core/theme.js` |
| Adding a theme = editing 1 file | Adding a theme = 3 files (CSS + HTML link + theme.js entry) |
| No build pipeline | `scripts/build_gui_frontend.sh` (concat + copy) |
| Files edited in wrong location | Static/ marked as generated; CLAUDE.md updated |
| Backend logic at risk | Backend stashed before refactor; zero changes to Python code |

---

## 5. Implementation Order

The phases should be executed **sequentially** with verification at
each step:

```
Phase 0  →  Safety backups
Phase 1  →  Consolidate source tree (port static → gui_frontend/src/)
Phase 4  →  Build pipeline (so we can verify after each subsequent phase)
Phase 5  →  Single theme validation (small, high-signal change)
Phase 3  →  Modularize CSS (can be done in parallel with Phase 2)
Phase 2  →  Modularize JS (largest effort, benefits from CSS being done)
Phase 6  →  Deprecate duplicate copy + update docs
Phase 7  →  Full verification
```

Phases 2 and 3 can be done in parallel if multiple developers/agents
are working, since CSS and JS modules are independent (they share no
code — only DOM class names which are already established).

---

## 6. Risk Assessment

| Risk | Mitigation |
|---|---|
| JS module ordering dependency | Build script enforces order; test with concatenated output |
| CSS specificity changes | All selectors preserved; only file boundaries change |
| Theme token mismatch | Diff before/after CSS to verify no property drift |
| SAIP workbench breakage | Largest module (~17K JS, ~8K CSS) — extract last, verify first |
| Backend accidentally modified | Phase 0 backup + git diff against pre-refactor tag |
| Dev workflow disruption | `--dev` flag in build script gives symlink mode for live editing |
