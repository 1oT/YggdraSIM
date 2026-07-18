#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# build_gui_frontend.sh — Build the GUI frontend bundle from source.
#
# Reads source files from gui_frontend/src/ and produces the served
# bundle at yggdrasim_common/gui_server/static/.
#
# Modes:
#   ./scripts/build_gui_frontend.sh           production (concatenated)
#   ./scripts/build_gui_frontend.sh --dev     symlink for live editing
#
# The --dev mode replaces static/ with a symlink to gui_frontend/src/
# so edits are reflected immediately without a rebuild. Do not commit
# the symlink.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/gui_frontend/src"
OUT="$REPO_ROOT/yggdrasim_common/gui_server/static"

# ---------------------------------------------------------------------------
# --dev mode: symlink static/ -> ../../gui_frontend/src/
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--dev" ]; then
    if [ -L "$OUT" ]; then
        echo "[*] Dev symlink already in place: $OUT -> $(readlink "$OUT")"
        exit 0
    fi
    if [ -d "$OUT" ] || [ -f "$OUT" ]; then
        echo "[*] Removing existing static/ before creating dev symlink..."
        rm -rf "$OUT"
    fi
    ln -s "../../gui_frontend/src" "$OUT"
    echo "[+] Dev mode active: static/ -> ../../gui_frontend/src/"
    echo "    Edits to gui_frontend/src/ are served immediately."
    exit 0
fi

# ---------------------------------------------------------------------------
# Production mode: concatenate modular sources, or copy monoliths.
# ---------------------------------------------------------------------------
if [ ! -d "$SRC" ]; then
    echo "[!] Source directory missing: $SRC"
    exit 1
fi

mkdir -p "$OUT/css" "$OUT/js" "$OUT/vendor"

# --- CSS ----------------------------------------------------------------
if [ -d "$SRC/css" ]; then
    # Modular CSS: concatenate in order from .css_order manifest so the
    # output is byte-identical to the canonical source. Each source chunk
    # carries its own SPDX header for standalone review; only the first
    # header belongs in the served monolith.
    ORDER_FILE="$SRC/css/.css_order"
    if [ -f "$ORDER_FILE" ]; then
        {
            first_css=1
            while IFS= read -r rel; do
                [ -z "$rel" ] && continue
                f="$SRC/css/$rel"
                if [ ! -f "$f" ]; then
                    echo "[!] CSS manifest entry is missing: $f" >&2
                    exit 1
                fi
                if [ "$first_css" -eq 1 ]; then
                    cat "$f"
                    first_css=0
                elif head -n 2 "$f" | grep -q "SPDX-License-Identifier:"; then
                    tail -n +6 "$f"
                else
                    cat "$f"
                fi
            done < "$ORDER_FILE"
        } > "$OUT/app.css"
        echo "    app.css  : $(wc -l < "$OUT/app.css") lines (modular, ordered)"
    else
        echo "[!] CSS order manifest is missing: $ORDER_FILE" >&2
        exit 1
    fi
else
    cp "$SRC/app.css" "$OUT/app.css"
    echo "    app.css  : $(wc -l < "$OUT/app.css") lines (monolith)"
fi

# --- JS -----------------------------------------------------------------
if [ -d "$SRC/js" ]; then
    # Modular JS: concatenate in order from .js_order manifest. The
    # IIFE wrapper (__head.js / __foot.js) is part of the concatenation.
    # Strip per-chunk SPDX headers after the first source file so the served
    # output remains one clean JavaScript document.
    ORDER_FILE="$SRC/js/.js_order"
    if [ -f "$ORDER_FILE" ]; then
        {
            first_js=1
            while IFS= read -r rel; do
                [ -z "$rel" ] && continue
                f="$SRC/js/$rel"
                if [ ! -f "$f" ]; then
                    echo "[!] JavaScript manifest entry is missing: $f" >&2
                    exit 1
                fi
                if [ "$first_js" -eq 1 ]; then
                    cat "$f"
                    first_js=0
                elif head -n 1 "$f" | grep -q "^// SPDX-License-Identifier:"; then
                    tail -n +4 "$f"
                else
                    cat "$f"
                fi
            done < "$ORDER_FILE"
        } > "$OUT/app.js"
        echo "    app.js   : $(wc -l < "$OUT/app.js") lines (modular, ordered)"
    else
        echo "[!] JavaScript order manifest is missing: $ORDER_FILE" >&2
        exit 1
    fi
else
    cp "$SRC/app.js" "$OUT/app.js"
    echo "    app.js   : $(wc -l < "$OUT/app.js") lines (monolith)"
fi

# --- Static assets (copied verbatim) ------------------------------------
cp "$SRC/index.html" "$OUT/index.html"
cp "$SRC/theme-init.js" "$OUT/theme-init.js"
if [ -d "$SRC/vendor" ]; then
    rm -rf "$OUT/vendor"
    cp -r "$SRC/vendor" "$OUT/vendor"
fi

echo "[+] Built $OUT/ from $SRC/"
echo "    index.html : $(wc -l < "$OUT/index.html") lines"
echo "    theme-init : $(wc -l < "$OUT/theme-init.js") lines"
echo "    vendor     : $(find "$OUT/vendor" -type f | wc -l) files"
