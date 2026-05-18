# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Standalone Textual app for visual side-by-side SAIP profile diffing.

Usage from the SAIP shell::

    DIFF-TUI <profile_a> <profile_b>

Or directly::

    python -m Tools.ProfilePackage.saip_diff_tui <profile_a> <profile_b>

The app loads both profiles via :mod:`saip_diff_loader` (transcode
JSON, simulator manifest, or SAIP DER), runs
:func:`saip_diff_engine.diff_saip_documents`, and renders:

* A left tree pane that mirrors document A with diff markers.
* A right tree pane that mirrors document B with diff markers.
* A bottom status bar showing counters and current selection.
* An optional decoded-view pane (``d``) that shows what the leaf
  under the tree cursor decodes to on each side, using the same
  read-only decoder cascade as the transcode TUI's Decoded pane.

Keybindings:

* ``n`` / ``N`` — next / previous diff entry.
* ``v`` — toggle value display.
* ``d`` — toggle the decoded view pane.
* ``q`` / ``Ctrl+C`` — quit.

Textual is only imported inside the app launcher so this module stays
importable on hosts that do not ship the TUI extra. The standalone CLI
guards with a clear ImportError message.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from Tools.ProfilePackage.saip_diff_canonical import (
    canonicalize_document_for_diff,
)
from Tools.ProfilePackage.saip_diff_engine import (
    DIFF_OP_ADDED,
    DIFF_OP_CHANGED,
    DIFF_OP_MOVED,
    DIFF_OP_REMOVED,
    DiffEntry,
    DiffSummary,
    diff_saip_documents,
    format_diff_text,
)
from Tools.ProfilePackage.saip_diff_loader import (
    LoadedDocument,
    SaipDiffLoadError,
    load_two_profile_documents,
)
from Tools.ProfilePackage.saip_diff_tui_prefs import (
    DECODED_HEIGHT_DEFAULT,
    DECODED_HEIGHT_MAX,
    DECODED_HEIGHT_MIN,
    clamp_decoded_height,
    load_diff_tui_layout,
    load_theme_pref,
    next_theme_in_cycle,
    persist_diff_tui_layout,
    persist_theme,
)


_OP_MARKER: dict[str, str] = {
    DIFF_OP_ADDED: "[+]",
    DIFF_OP_REMOVED: "[-]",
    DIFF_OP_CHANGED: "[~]",
    DIFF_OP_MOVED: "[>]",
}


# Style applied to a tree label / decoded-pane heading to surface its
# diff op without relying on Rich BBCode markup (which is disabled on
# the informational Static widgets to keep raw payload text safe).
_OP_STYLE: dict[str, str] = {
    DIFF_OP_ADDED: "bold green",
    DIFF_OP_REMOVED: "bold red",
    DIFF_OP_CHANGED: "bold yellow",
    DIFF_OP_MOVED: "bold cyan",
}


# Per-side directional colouring of diverging bytes. Side A (the
# "before" / left pane) gets a red background so a byte that is no
# longer there in B reads as a deletion; side B (the "after" / right
# pane) gets a green background so a byte that wasn't there in A
# reads as an addition. ``black on …`` keeps the digits legible on
# light *and* dark themes — ``reverse`` was unreliable on a couple
# of terminal palettes seen in the lab.
_HEX_DIFF_BYTE_STYLE_A: str = "black on red"
_HEX_DIFF_BYTE_STYLE_B: str = "black on green"

# How many bytes (= 2 hex chars) per rendered line. 16 mirrors xxd /
# hexdump conventions so the visual scan is familiar.
_HEX_RENDER_BYTES_PER_LINE: int = 16

# Style for the offset prefix ``0010:`` at the start of each line.
_HEX_OFFSET_STYLE: str = "dim"

# Style for the "n of m bytes differ" header. Bold so it sticks out
# at the top of the pane without leaning on a warning colour.
_HEX_DIFF_SUMMARY_STYLE: str = "bold"


_DIFF_PATH_INDEX_RE: re.Pattern[str] = re.compile(r"\[(\d+)\]")


def _is_hex_string(value: Any) -> bool:
    """Return ``True`` for non-empty strings made of even-count hex digits."""
    if isinstance(value, str) is False:
        return False
    text = value.strip()
    if len(text) == 0 or (len(text) % 2) != 0:
        return False
    try:
        int(text, 16)
    except ValueError:
        return False
    return True


def _hex_to_byte_pairs(hex_text: str) -> list[str]:
    """Split a hex string into 2-char byte tokens (uppercased).

    Trailing nibbles are emitted as a single token so the renderer
    surfaces malformed input rather than silently swallowing it.
    """
    if hex_text is None or len(hex_text) == 0:
        return []
    text = hex_text.upper()
    bytes_out: list[str] = []
    for offset in range(0, len(text), 2):
        bytes_out.append(text[offset:offset + 2])
    return bytes_out


def _count_diverging_bytes(self_bytes: list[str], other_bytes: list[str]) -> int:
    """How many byte positions differ between the two byte lists.

    Length mismatch counts as additional diverging bytes on the
    longer side, mirroring how ``_render_hex_with_byte_diff`` paints
    the trailing tail.
    """
    diverging = 0
    max_len = max(len(self_bytes), len(other_bytes))
    for offset in range(max_len):
        if offset >= len(self_bytes):
            break
        a_byte = self_bytes[offset]
        b_byte = other_bytes[offset] if offset < len(other_bytes) else ""
        if a_byte != b_byte:
            diverging += 1
    return diverging


def _render_hex_with_byte_diff(
    self_hex: str,
    other_hex: str | None,
    *,
    side: str = "a",
    bytes_per_line: int = _HEX_RENDER_BYTES_PER_LINE,
) -> Any:
    """Build a Rich ``Text`` of ``self_hex`` with diverging bytes highlighted.

    The output mimics ``xxd``'s byte panel:

        0000: A0 00 00 01 67 41 00 00 47 53 4D 41 31 35 31 32
        0010: …

    Bytes are space-separated so the boundaries are obvious at any
    zoom level. Diverging bytes carry a directional background:

    * ``side="a"`` paints diverging bytes on a red background — the
      byte was here in A but is different / missing in B (deletion).
    * ``side="b"`` paints diverging bytes on a green background — the
      byte is here in B but is different / missing in A (addition).

    A summary line ``(n of m bytes differ)`` is prepended when there
    is at least one divergence. Bytes that match across the two sides
    are rendered in the default foreground.

    Returns a Rich ``Text``. Falls back to a plain newline-joined
    string when ``rich`` is unavailable so the renderer never blows
    up.
    """
    try:
        from rich.text import Text
    except ImportError:
        return self_hex
    self_bytes = _hex_to_byte_pairs(self_hex)
    other_bytes = _hex_to_byte_pairs(other_hex or "")
    diff_style = (
        _HEX_DIFF_BYTE_STYLE_B if side == "b" else _HEX_DIFF_BYTE_STYLE_A
    )
    diverging = _count_diverging_bytes(self_bytes, other_bytes)
    text = Text()
    if diverging > 0 and len(self_bytes) > 0:
        text.append(
            f"({diverging} of {len(self_bytes)} bytes differ)\n",
            style=_HEX_DIFF_SUMMARY_STYLE,
        )
    if len(self_bytes) == 0:
        return text
    line_width = max(int(bytes_per_line), 1)
    for line_start in range(0, len(self_bytes), line_width):
        text.append(f"{line_start:04X}: ", style=_HEX_OFFSET_STYLE)
        line_end = min(line_start + line_width, len(self_bytes))
        for offset in range(line_start, line_end):
            a_byte = self_bytes[offset]
            b_byte = (
                other_bytes[offset] if offset < len(other_bytes) else ""
            )
            if a_byte == b_byte:
                text.append(a_byte)
            else:
                text.append(a_byte, style=diff_style)
            if offset < line_end - 1:
                text.append(" ")
        if line_end < len(self_bytes):
            text.append("\n")
    return text


def _styled_op_line(prefix: str, op: str) -> Any:
    """Build a heading line styled with the op palette.

    Plain strings come back when ``rich`` is missing; the call sites
    fall back gracefully because ``Static.update`` accepts both.
    """
    try:
        from rich.text import Text
    except ImportError:
        return prefix
    style = _OP_STYLE.get(op, "")
    return Text(prefix, style=style) if len(style) > 0 else Text(prefix)


def _build_relevant_path_set(diff_paths: Any) -> set[str]:
    """Return the set of paths that should be shown in diffs-only mode.

    Includes every diff path itself plus every ancestor of every diff
    path (the breadcrumb the operator needs to see *where* in the
    profile the diff lives). The empty string represents the document
    root and is always included so the tree builder has a sentinel.

    Descendants of a diff path are NOT enumerated here — the tree
    walker switches to "show everything" once it dips below a diff
    boundary so `changed`-block subtrees stay fully expanded.
    """
    out: set[str] = {""}
    for path in diff_paths:
        if isinstance(path, str) is False:
            continue
        out.add(path)
        cur = path
        while len(cur) > 0:
            idx_dot = cur.rfind(".")
            idx_brk = cur.rfind("[")
            last = max(idx_dot, idx_brk)
            if last <= 0:
                break
            cur = cur[:last]
            out.add(cur)
    return out


def diff_path_to_components(path: str) -> list[str | int]:
    """Convert a jq-style diff path into walker components.

    ``sections.foo[3].bar.@[1].key.hex`` becomes
    ``['sections', 'foo', 3, 'bar', '@', 1, 'key', 'hex']``. Bracket
    indices fused onto a key (``foo[3]``) split into the key plus
    successive integer indices. Used by the decoded-view pane to look
    up the same leaf in either loaded document.
    """
    components: list[str | int] = []
    if len(path) == 0:
        return components
    for raw_segment in path.split("."):
        if len(raw_segment) == 0:
            continue
        first_bracket = raw_segment.find("[")
        if first_bracket < 0:
            components.append(raw_segment)
            continue
        if first_bracket > 0:
            components.append(raw_segment[:first_bracket])
        for index_match in _DIFF_PATH_INDEX_RE.finditer(raw_segment):
            components.append(int(index_match.group(1)))
    return components


def _walk_components(value: Any, components: list[str | int]) -> Any:
    cursor = value
    for part in components:
        if isinstance(part, int) is True:
            if isinstance(cursor, list) is False:
                raise KeyError(part)
            if part < 0 or part >= len(cursor):
                raise KeyError(part)
            cursor = cursor[part]
            continue
        if isinstance(cursor, dict) is False:
            raise KeyError(part)
        if part not in cursor:
            raise KeyError(part)
        cursor = cursor[part]
    return cursor


def _resolve_field_context(
    document: Any,
    components: list[str | int],
) -> tuple[Any, str | None, str | None, str | None] | None:
    """Mirror the field-name / ef-key resolution from the transcode TUI.

    Returns ``(raw_value, field_name, last_ef_key, pe_section_key)``.
    The path is normalised so the decoder cascade sees the same input
    it would see when the JSON-editor cursor lands on the equivalent
    leaf in transcode mode.
    """
    from .saip_json_codec import (
        _LEGACY_TAG_BYTES,
        _LEGACY_TAG_TUPLE,
        _TAG_BYTES,
        _TAG_TUPLE,
    )

    path: list[str | int] = list(components)
    try:
        raw_value = _walk_components(document, path)
    except (KeyError, IndexError, TypeError):
        return None

    field_name: str | None = None

    if (
        len(path) > 0
        and isinstance(path[-1], str)
        and path[-1] in {_TAG_BYTES, _LEGACY_TAG_BYTES}
    ):
        path = path[:-1]
        try:
            raw_value = _walk_components(document, path)
        except (KeyError, IndexError, TypeError):
            return None
        if (
            len(path) >= 2
            and path[-2] in {_TAG_TUPLE, _LEGACY_TAG_TUPLE}
            and path[-1] == 1
        ):
            try:
                tuple_tag = _walk_components(document, path[:-1] + [0])
            except (KeyError, IndexError, TypeError):
                tuple_tag = None
            if isinstance(tuple_tag, str) is True:
                field_name = tuple_tag
        elif len(path) > 0 and isinstance(path[-1], str) is True:
            field_name = path[-1]
    elif (
        len(path) >= 2
        and path[-2] in {_TAG_TUPLE, _LEGACY_TAG_TUPLE}
        and path[-1] == 1
    ):
        try:
            tuple_tag = _walk_components(document, path[:-1] + [0])
        except (KeyError, IndexError, TypeError):
            tuple_tag = None
        if isinstance(tuple_tag, str) is True:
            field_name = tuple_tag
    elif len(path) > 0 and isinstance(path[-1], str) is True:
        field_name = path[-1]

    pe_key: str | None = None
    if (
        len(path) >= 2
        and path[0] == "sections"
        and isinstance(path[1], str) is True
    ):
        pe_key = path[1]

    last_ef_key: str | None = None
    for component in path:
        if isinstance(component, str) is True and component.startswith("ef-") is True:
            last_ef_key = component

    return raw_value, field_name, last_ef_key, pe_key


def build_decoded_view_for_diff_path(
    document: Any,
    diff_path: str,
) -> dict[str, Any] | None:
    """Run the read-only decoder cascade against a diff path.

    Returns a small dict with ``title`` / ``payload`` / ``kind`` that
    the diff-tui's decoded pane can render. Returns ``None`` when the
    path has no decodable leaf or no decoder claims the field.
    """
    from .saip_decoded_edit import (
        build_decoded_value_editor_model,
        build_decoded_value_raw_hex_model,
        build_decoded_value_readonly_view,
    )

    components = diff_path_to_components(diff_path)
    if len(components) == 0:
        return None
    context = _resolve_field_context(document, components)
    if context is None:
        return None
    raw_value, field_name, last_ef_key, pe_key = context
    if field_name is None or len(field_name) == 0:
        return None

    editor = build_decoded_value_editor_model(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
        pe_section_key=pe_key,
    )
    if isinstance(editor, dict) is True:
        payload = editor.get("payload", {})
        return {
            "title": str(editor.get("title", "Decoded view") or "Decoded view"),
            "field_name": field_name,
            "last_ef_key": last_ef_key,
            "payload": payload if isinstance(payload, (dict, list)) else {"value": payload},
            "kind": "editor",
        }

    readonly = build_decoded_value_readonly_view(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
        pe_section_key=pe_key,
    )
    if isinstance(readonly, dict) is True:
        payload = readonly.get("payload", {})
        return {
            "title": str(readonly.get("title", "Read-only decode") or "Read-only decode"),
            "field_name": field_name,
            "last_ef_key": last_ef_key,
            "payload": payload if isinstance(payload, (dict, list)) else {"value": payload},
            "kind": "readonly",
        }

    raw_hex = build_decoded_value_raw_hex_model(
        field_name=field_name,
        raw_value=raw_value,
        last_ef_key=last_ef_key,
    )
    if isinstance(raw_hex, dict) is True:
        payload = raw_hex.get("payload", {})
        return {
            "title": str(raw_hex.get("title", "Raw hex view") or "Raw hex view"),
            "field_name": field_name,
            "last_ef_key": last_ef_key,
            "payload": payload if isinstance(payload, (dict, list)) else {"hex": str(payload or "")},
            "kind": "raw_hex",
        }

    return None


def _decoded_pane_text(
    document: Any,
    diff_path: str,
    *,
    side_label: str,
    missing_label: str,
) -> str:
    """Render the decoded payload for one side as a Static-friendly string."""
    if len(diff_path) == 0:
        return f"{side_label}: select a leaf in either tree to decode."
    components = diff_path_to_components(diff_path)
    try:
        _walk_components(document, components)
    except Exception:
        return f"{side_label}: {missing_label}"
    decoded = build_decoded_view_for_diff_path(document, diff_path)
    if decoded is None:
        try:
            raw = _walk_components(document, components)
        except Exception:
            return f"{side_label}: {missing_label}"
        rendered = _render_value(raw, limit=240)
        return (
            f"{side_label}: no decoder for `{components[-1]}`\n"
            f"  raw value = {rendered}"
        )
    title = decoded.get("title", "Decoded view")
    payload = decoded.get("payload", {})
    try:
        body = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        body = str(payload)
    return f"{side_label}: {title}\n{body}"


def _resolve_decoded_payload(
    document: Any,
    diff_path: str,
) -> dict[str, Any] | None:
    """Resolve a diff path into a side-payload usable by the colour renderer.

    Returns either the decoded view dict (with ``kind``, ``title`` and
    ``payload`` keys) or, when no decoder claims the field, a synthetic
    record with ``kind='raw'`` so the renderer still has a hex string
    or formatted value to compare against the other side. Returns
    ``None`` when the path does not resolve in this side at all (e.g.
    one of the documents is missing a section).
    """
    if len(diff_path) == 0:
        return None
    components = diff_path_to_components(diff_path)
    if len(components) == 0:
        return None
    try:
        raw = _walk_components(document, components)
    except Exception:
        return None
    decoded = build_decoded_view_for_diff_path(document, diff_path)
    if isinstance(decoded, dict) is True:
        return decoded
    rendered = _render_value(raw, limit=240)
    return {
        "title": "no decoder",
        "kind": "raw",
        "field_name": str(components[-1]),
        "payload": {"value": rendered, "raw": raw},
    }


def _extract_hex_from_payload(payload: dict[str, Any] | None) -> str | None:
    """Pull a single ``hex`` string out of a decoded-view payload, if any.

    Looks first at the top-level ``hex`` key (raw-hex view), then at
    ``payload.hex`` for the editor / readonly views. Returns ``None``
    when the payload does not carry a flat hex string the byte-level
    differ can compare.
    """
    if isinstance(payload, dict) is False:
        return None
    inner = payload.get("payload", payload)
    if isinstance(inner, dict) is False:
        return None
    candidate = inner.get("hex")
    if isinstance(candidate, str) is True and _is_hex_string(candidate):
        return candidate.upper()
    return None


def _render_decoded_pane(
    self_payload: dict[str, Any] | None,
    other_payload: dict[str, Any] | None,
    *,
    side_label: str,
    missing_label: str,
    op: str,
    show_hex_diff: bool,
) -> Any:
    """Render one decoded-pane side.

    Two display modes, switched by ``show_hex_diff``:

    * ``show_hex_diff=False`` (default) — original plain decoded
      view. The body is the decoder's canonical rendering: a
      pretty-printed JSON object for structural payloads, the raw
      hex string for raw-hex payloads. No diff colouring is applied
      anywhere in the pane; the side-by-side tree above carries the
      diff signal via its op markers and op colours.
    * ``show_hex_diff=True`` — byte-level hex diff overlay. When
      the payload exposes a flat hex string the bytes are paired
      with the other side and diverging bytes are painted on the
      directional background (red on A, green on B), shown in xxd
      style with a "n of m bytes differ" summary. Payloads without a
      hex string fall back to the plain decoded view above.

    Returns a Rich ``Text`` when ``rich`` is importable, otherwise a
    plain string with the same content minus the colours.
    """
    if self_payload is None:
        body = f"{side_label}: {missing_label}"
        if show_hex_diff is False:
            return body
        try:
            from rich.text import Text
        except ImportError:
            return body
        style = _OP_STYLE.get(op, "dim")
        out = Text()
        out.append(body, style=style)
        return out
    title = str(self_payload.get("title") or "Decoded view")
    side_role = "b" if side_label.upper() == "B" else "a"
    self_hex = _extract_hex_from_payload(self_payload)
    if show_hex_diff is True and self_hex is not None:
        try:
            from rich.text import Text
        except ImportError:
            return f"{side_label}: {title}\n{self_hex}"
        text = Text()
        heading_style = _OP_STYLE.get(op, "")
        text.append(
            f"{side_label}: {title}\n",
            style=heading_style if len(heading_style) > 0 else "bold",
        )
        other_hex = _extract_hex_from_payload(other_payload)
        text.append(
            _render_hex_with_byte_diff(self_hex, other_hex, side=side_role),
        )
        return text
    payload = self_payload.get("payload", {})
    try:
        body = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        body = str(payload)
    return f"{side_label}: {title}\n{body}"


def _path_segments(path: str) -> list[str]:
    """Split a jq-style path into labelled tree segments.

    ``sections.mf.fid`` becomes ``["sections", "mf", "fid"]``.
    ``sections.gfm[3].fid`` becomes ``["sections", "gfm[3]", "fid"]``.
    Used by the tree renderer to find the right insertion point.
    """
    if len(path) == 0:
        return []
    raw = path.split(".")
    return [segment for segment in raw if len(segment) > 0]


def _render_value(value: Any, *, limit: int = 64) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool) is True:
        return "true" if value else "false"
    if isinstance(value, (int, float)) is True:
        return str(value)
    if isinstance(value, (list, tuple)) is True:
        return f"[{len(value)} items]"
    if isinstance(value, dict) is True:
        return f"{{{len(value)} keys}}"
    text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _launch(
    loaded_a: LoadedDocument,
    loaded_b: LoadedDocument,
    summary: DiffSummary,
    *,
    canonical_mode: bool = True,
    workspace_root: Path | None = None,
) -> int:
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.widgets import Footer, Header, Static, Tree
    except ImportError as error:
        sys.stderr.write(
            "[-] DIFF-TUI requires the textual TUI extra. "
            "Install with `pip install 'yggdrasim[tui]'` or "
            "`pip install textual`. "
            f"Underlying error: {error}\n"
        )
        return 2

    prefs_root: Path = (
        workspace_root.resolve()
        if workspace_root is not None
        else Path.cwd().resolve()
    )
    persisted_layout = load_diff_tui_layout(prefs_root)
    persisted_theme = load_theme_pref(prefs_root)
    initial_show_values = bool(persisted_layout.get("show_values", True))
    initial_show_decoded = bool(persisted_layout.get("decoded_visible", False))
    initial_diffs_only = bool(persisted_layout.get("diffs_only", False))
    initial_show_hex_diff = bool(
        persisted_layout.get("decoded_show_hex_diff", False),
    )
    initial_decoded_height = clamp_decoded_height(
        int(persisted_layout.get("decoded_height", DECODED_HEIGHT_DEFAULT)),
    )

    class DiffApp(App):  # type: ignore[misc]
        CSS = """
        Screen {
            layout: vertical;
        }
        #panes {
            height: 1fr;
        }
        #pane-a, #pane-b {
            width: 1fr;
            border: solid $accent;
        }
        #decoded {
            height: 14;
            display: none;
        }
        #decoded.visible {
            display: block;
        }
        #decoded-a-scroll, #decoded-b-scroll {
            width: 1fr;
            border: solid $primary;
            padding: 0 1;
        }
        #decoded-a, #decoded-b {
            width: 100%;
            height: auto;
        }
        #status {
            height: 3;
            background: $boost;
            color: $text;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("n", "next_diff", "Next diff"),
            Binding("N", "prev_diff", "Prev diff"),
            Binding("v", "toggle_values", "Toggle values"),
            Binding("d", "toggle_decoded_view", "Toggle decoded view"),
            Binding("o", "toggle_diffs_only", "Toggle diffs-only"),
            Binding("h", "toggle_decoded_hex_diff", "Toggle hex-diff overlay"),
            Binding("]", "grow_decoded_pane", "Grow decoded"),
            Binding("[", "shrink_decoded_pane", "Shrink decoded"),
            Binding("f7", "cycle_theme", "Cycle theme", priority=True),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._loaded_a = loaded_a
            self._loaded_b = loaded_b
            self._summary = summary
            self._canonical_mode = canonical_mode
            self._workspace_root = prefs_root
            self._show_values = initial_show_values
            self._show_decoded = initial_show_decoded
            self._diffs_only = initial_diffs_only
            self._decoded_show_hex_diff = initial_show_hex_diff
            self._decoded_height = initial_decoded_height
            self._diff_cursor = 0
            self._current_diff_path: str = ""
            if persisted_theme is not None:
                # ``App.theme`` may not exist on older Textual versions.
                # ``setattr`` keeps the codebase importable on hosts that
                # ship a pre-theme-cycle release; the cycle action below
                # gates writes the same way.
                try:
                    self.theme = persisted_theme
                except Exception:
                    pass

        def compose(self) -> ComposeResult:
            """Compose the main two-pane diff layout with side-by-side JSON outline trees."""
            yield Header()
            with Horizontal(id="panes"):
                with Vertical(id="pane-a"):
                    # ``markup=False`` so brackets in source paths,
                    # status keybinding hints (``[/]`` for resize) and
                    # raw hex leaf payloads are rendered verbatim
                    # instead of triggering Rich's auto-close parser.
                    yield Static(
                        f"A: {self._loaded_a.source_path}  "
                        f"[{self._loaded_a.shape}]",
                        id="label-a",
                        markup=False,
                    )
                    yield Tree("document", id="tree-a")
                with Vertical(id="pane-b"):
                    yield Static(
                        f"B: {self._loaded_b.source_path}  "
                        f"[{self._loaded_b.shape}]",
                        id="label-b",
                        markup=False,
                    )
                    yield Tree("document", id="tree-b")
            with Horizontal(id="decoded"):
                with VerticalScroll(id="decoded-a-scroll"):
                    yield Static(
                        "A decoded: select a leaf in either tree.",
                        id="decoded-a",
                        markup=False,
                    )
                with VerticalScroll(id="decoded-b-scroll"):
                    yield Static(
                        "B decoded: select a leaf in either tree.",
                        id="decoded-b",
                        markup=False,
                    )
            yield Static("", id="status", markup=False)
            yield Footer()

        def on_mount(self) -> None:
            """Populate both outline trees and apply the initial decoded-pane height on mount."""
            self._rebuild_tree("tree-a", self._loaded_a.document, side="a")
            self._rebuild_tree("tree-b", self._loaded_b.document, side="b")
            self._apply_decoded_pane_height()
            if self._show_decoded is True:
                # Restore the persisted "open decoded pane" state. We
                # reuse the toggle action so the .visible class, the
                # initial paint and the status bar all converge through
                # one code path.
                decoded_pane = self.query_one("#decoded")
                decoded_pane.add_class("visible")
                if (
                    len(self._current_diff_path) == 0
                    and len(self._summary.entries) > 0
                ):
                    self._current_diff_path = (
                        self._summary.entries[self._diff_cursor].path
                    )
                self._refresh_decoded_panes()
            self._update_status()

        def _rebuild_tree(
            self,
            tree_id: str,
            document: dict[str, Any],
            *,
            side: str,
        ) -> None:
            tree_widget = self.query_one(f"#{tree_id}", Tree)
            tree_widget.clear()
            tree_widget.root.data = {"path": "", "side": side}
            tree_widget.root.expand()
            diff_paths: dict[str, str] = {}
            for entry in self._summary.entries:
                diff_paths[entry.path] = entry.op
            relevant_paths: set[str] | None = None
            if self._diffs_only is True:
                relevant_paths = _build_relevant_path_set(diff_paths.keys())
            self._attach_subtree(
                tree_widget.root,
                parent_path="",
                value=document,
                diff_paths=diff_paths,
                relevant_paths=relevant_paths,
                inside_diff=False,
            )

        def _attach_subtree(
            self,
            parent_node: Any,
            *,
            parent_path: str,
            value: Any,
            diff_paths: dict[str, str],
            relevant_paths: set[str] | None,
            inside_diff: bool,
        ) -> None:
            if isinstance(value, dict) is True:
                for key in sorted(value.keys(), key=str):
                    child_path = (
                        str(key)
                        if len(parent_path) == 0
                        else f"{parent_path}.{key}"
                    )
                    op = diff_paths.get(child_path, "")
                    if (
                        relevant_paths is not None
                        and inside_diff is False
                        and child_path not in relevant_paths
                    ):
                        continue
                    marker = _OP_MARKER.get(op, "   ")
                    label = self._format_node_label(
                        marker=marker,
                        key_text=str(key),
                        value=value[key],
                        op=op,
                    )
                    node = parent_node.add(label)
                    node.data = {"path": child_path, "op": op}
                    next_inside_diff = inside_diff is True or len(op) > 0
                    self._attach_subtree(
                        node,
                        parent_path=child_path,
                        value=value[key],
                        diff_paths=diff_paths,
                        relevant_paths=relevant_paths,
                        inside_diff=next_inside_diff,
                    )
                return
            if isinstance(value, (list, tuple)) is True:
                for index, child in enumerate(value):
                    child_path = f"{parent_path}[{index}]"
                    op = diff_paths.get(child_path, "")
                    if (
                        relevant_paths is not None
                        and inside_diff is False
                        and child_path not in relevant_paths
                    ):
                        continue
                    marker = _OP_MARKER.get(op, "   ")
                    label = self._format_node_label(
                        marker=marker,
                        key_text=f"[{index}]",
                        value=child,
                        op=op,
                    )
                    node = parent_node.add(label)
                    node.data = {"path": child_path, "op": op}
                    next_inside_diff = inside_diff is True or len(op) > 0
                    self._attach_subtree(
                        node,
                        parent_path=child_path,
                        value=child,
                        diff_paths=diff_paths,
                        relevant_paths=relevant_paths,
                        inside_diff=next_inside_diff,
                    )
                return

        def _format_node_label(
            self,
            *,
            marker: str,
            key_text: str,
            value: Any,
            op: str,
        ) -> Any:
            if (
                isinstance(value, (dict, list, tuple)) is True
                or self._show_values is False
            ):
                body = f"{marker} {key_text}"
            else:
                body = f"{marker} {key_text} = {_render_value(value)}"
            try:
                from rich.text import Text
            except ImportError:
                return body
            style = _OP_STYLE.get(op, "")
            return Text(body, style=style) if len(style) > 0 else Text(body)

        def action_toggle_values(self) -> None:
            self._show_values = self._show_values is False
            self._rebuild_tree("tree-a", self._loaded_a.document, side="a")
            self._rebuild_tree("tree-b", self._loaded_b.document, side="b")
            self._persist_layout()
            self._update_status()

        def action_toggle_diffs_only(self) -> None:
            self._diffs_only = self._diffs_only is False
            self._rebuild_tree("tree-a", self._loaded_a.document, side="a")
            self._rebuild_tree("tree-b", self._loaded_b.document, side="b")
            self._persist_layout()
            self._update_status()

        def action_toggle_decoded_hex_diff(self) -> None:
            self._decoded_show_hex_diff = self._decoded_show_hex_diff is False
            if self._show_decoded is True:
                self._refresh_decoded_panes()
            self._persist_layout()
            self._update_status()

        def action_toggle_decoded_view(self) -> None:
            """Toggle the decoded-fields bottom pane between visible and hidden."""
            self._show_decoded = self._show_decoded is False
            decoded_pane = self.query_one("#decoded")
            if self._show_decoded is True:
                decoded_pane.add_class("visible")
            else:
                decoded_pane.remove_class("visible")
            if self._show_decoded is True:
                if (
                    len(self._current_diff_path) == 0
                    and len(self._summary.entries) > 0
                ):
                    self._current_diff_path = (
                        self._summary.entries[self._diff_cursor].path
                    )
                self._refresh_decoded_panes()
            self._persist_layout()
            self._update_status()

        def action_grow_decoded_pane(self) -> None:
            """Grow the decoded-fields pane height by two rows."""
            new_height = clamp_decoded_height(self._decoded_height + 2)
            if new_height == self._decoded_height:
                return
            self._decoded_height = new_height
            self._apply_decoded_pane_height()
            self._persist_layout()
            self._update_status()

        def action_shrink_decoded_pane(self) -> None:
            """Shrink the decoded-fields pane height by two rows."""
            new_height = clamp_decoded_height(self._decoded_height - 2)
            if new_height == self._decoded_height:
                return
            self._decoded_height = new_height
            self._apply_decoded_pane_height()
            self._persist_layout()
            self._update_status()

        def action_cycle_theme(self) -> None:
            """Rotate the TUI colour theme to the next entry in the theme cycle."""
            current = str(getattr(self, "theme", "") or "textual-dark")
            nxt = next_theme_in_cycle(current)
            try:
                self.theme = nxt
            except Exception as exc:
                # Older Textual versions raised on unknown themes; fall
                # back to a status note rather than crashing the app.
                self._set_transient_status(f"Theme {nxt!r} failed: {exc}")
                return
            persist_theme(self._workspace_root, nxt)
            self._set_transient_status(f"Theme: {nxt} (saved)")

        def _apply_decoded_pane_height(self) -> None:
            try:
                decoded_pane = self.query_one("#decoded")
            except Exception:
                return
            decoded_pane.styles.height = self._decoded_height

        def _persist_layout(self) -> None:
            try:
                persist_diff_tui_layout(
                    self._workspace_root,
                    decoded_visible=self._show_decoded,
                    decoded_height=self._decoded_height,
                    show_values=self._show_values,
                    diffs_only=self._diffs_only,
                    decoded_show_hex_diff=self._decoded_show_hex_diff,
                )
            except Exception:
                # Persistence is best-effort — never let a write failure
                # take down the running session.
                pass

        def _set_transient_status(self, message: str) -> None:
            try:
                status_widget = self.query_one("#status", Static)
            except Exception:
                return
            status_widget.update(message)

        def action_next_diff(self) -> None:
            """Move the diff cursor to the next changed entry in the diff summary."""
            if len(self._summary.entries) == 0:
                return
            self._diff_cursor = (
                self._diff_cursor + 1
            ) % len(self._summary.entries)
            self._current_diff_path = (
                self._summary.entries[self._diff_cursor].path
            )
            self._focus_diff()
            if self._show_decoded is True:
                self._refresh_decoded_panes()
            self._update_status()

        def action_prev_diff(self) -> None:
            """Move the diff cursor to the previous changed entry in the diff summary."""
            if len(self._summary.entries) == 0:
                return
            self._diff_cursor = (
                self._diff_cursor - 1 + len(self._summary.entries)
            ) % len(self._summary.entries)
            self._current_diff_path = (
                self._summary.entries[self._diff_cursor].path
            )
            self._focus_diff()
            if self._show_decoded is True:
                self._refresh_decoded_panes()
            self._update_status()

        def _focus_diff(self) -> None:
            # Lightweight focus hint — Textual tree widgets do not
            # expose a stable "jump to data-key" primitive across 0.x
            # versions, so we just update the status line with the
            # current path and let the operator scroll to it.
            pass

        def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
            """Update the decoded-fields pane when an outline tree node is highlighted."""
            data = getattr(event.node, "data", None)
            if isinstance(data, dict) is False:
                return
            path_value = data.get("path", "")
            if isinstance(path_value, str) is False:
                return
            self._current_diff_path = path_value
            if self._show_decoded is True:
                self._refresh_decoded_panes()
            self._update_status()

        def _refresh_decoded_panes(self) -> None:
            try:
                pane_a = self.query_one("#decoded-a", Static)
                pane_b = self.query_one("#decoded-b", Static)
            except Exception:
                return
            path = self._current_diff_path
            op = ""
            if len(self._summary.entries) > 0:
                # Resolve the op for the *current* path so the pane
                # heading is colour-coded the same way as the tree.
                for entry in self._summary.entries:
                    if entry.path == path:
                        op = entry.op
                        break
            payload_a = _resolve_decoded_payload(
                self._loaded_a.document,
                path,
            )
            payload_b = _resolve_decoded_payload(
                self._loaded_b.document,
                path,
            )
            pane_a.update(
                _render_decoded_pane(
                    payload_a,
                    payload_b,
                    side_label="A",
                    missing_label="<missing on this side>",
                    op=op,
                    show_hex_diff=self._decoded_show_hex_diff,
                ),
            )
            pane_b.update(
                _render_decoded_pane(
                    payload_b,
                    payload_a,
                    side_label="B",
                    missing_label="<missing on this side>",
                    op=op,
                    show_hex_diff=self._decoded_show_hex_diff,
                ),
            )

        def _update_status(self) -> None:
            status_widget = self.query_one("#status", Static)
            decoded_state = "on" if self._show_decoded is True else "off"
            values_state = "on" if self._show_values is True else "off"
            view_state = "diffs-only" if self._diffs_only is True else "full"
            decoded_mode = (
                "hex-diff" if self._decoded_show_hex_diff is True else "json"
            )
            mode_label = (
                "canonical" if self._canonical_mode is True else "by-cmd-index"
            )
            decoded_size = (
                f"{self._decoded_height}r"
                if self._show_decoded is True
                else "hidden"
            )
            if len(self._summary.entries) == 0:
                status_widget.update(
                    f"No differences detected.  mode={mode_label}  "
                    f"view={view_state}  values={values_state}  "
                    f"decoded={decoded_state} ({decoded_size}, {decoded_mode})  "
                    "(q quit  v values  o diffs-only  d decoded  h hex-diff  "
                    "[/] resize  F7 theme)"
                )
                return
            current: DiffEntry = self._summary.entries[self._diff_cursor]
            status_widget.update(
                f"diff {self._diff_cursor + 1}/{len(self._summary.entries)}: "
                f"{current.op:7s} {current.path}  "
                f"A={_render_value(current.value_a)}  "
                f"B={_render_value(current.value_b)}  |  "
                f"added={self._summary.added}  "
                f"removed={self._summary.removed}  "
                f"changed={self._summary.changed}  "
                f"moved={self._summary.moved}  "
                f"mode={mode_label}  view={view_state}  "
                f"values={values_state}  "
                f"decoded={decoded_state} ({decoded_size}, {decoded_mode})  "
                f"(n/N cycle  v values  o diffs-only  d decoded  h hex-diff  "
                f"[/] resize  F7 theme  q quit)"
            )

    app = DiffApp()
    app.run()
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and launch the SAIP diff TUI; return an exit code."""
    parser = argparse.ArgumentParser(
        prog="saip-diff-tui",
        description=(
            "Open two SAIP profiles in a side-by-side visual diff "
            "(transcode JSON, simulator manifest, or SAIP DER)."
        ),
    )
    parser.add_argument("profile_a", help="left-hand profile path")
    parser.add_argument("profile_b", help="right-hand profile path")
    parser.add_argument(
        "--workspace-root",
        default="",
        help="override the workspace root used for DER decode (pySim lookup)",
    )
    parser.add_argument(
        "--text",
        action="store_true",
        help="skip the Textual app and print the plain-text diff report instead",
    )
    parser.add_argument(
        "--by-cmd-index",
        action="store_true",
        help=(
            "compare genericFileManagement by raw list-index rather than "
            "by resolved file path. Restores the pre-canonical noisy diff "
            "where mechanical SELECT shifts surface as added/removed entries."
        ),
    )
    args = parser.parse_args(argv)

    path_a = Path(args.profile_a).expanduser().resolve()
    path_b = Path(args.profile_b).expanduser().resolve()
    workspace_root = (
        Path(args.workspace_root).expanduser().resolve()
        if len(str(args.workspace_root or "").strip()) > 0
        else Path.cwd().resolve()
    )

    try:
        loaded_a, loaded_b = load_two_profile_documents(
            path_a,
            path_b,
            workspace_root=workspace_root,
        )
    except SaipDiffLoadError as error:
        sys.stderr.write(f"[-] DIFF-TUI load failed: {error}\n")
        return 3

    canonical_mode = args.by_cmd_index is False
    if canonical_mode is True:
        from dataclasses import replace as _dc_replace
        loaded_a = _dc_replace(
            loaded_a,
            document=canonicalize_document_for_diff(loaded_a.document),
        )
        loaded_b = _dc_replace(
            loaded_b,
            document=canonicalize_document_for_diff(loaded_b.document),
        )

    summary = diff_saip_documents(loaded_a.document, loaded_b.document)

    if args.text is True:
        mode_label = "canonical" if canonical_mode is True else "by-cmd-index"
        sys.stdout.write(
            f"=== SAIP diff ===\n"
            f"  A: {loaded_a.source_path}  [{loaded_a.shape}]\n"
            f"  B: {loaded_b.source_path}  [{loaded_b.shape}]\n"
            f"  mode: {mode_label}\n"
        )
        sys.stdout.write(format_diff_text(summary))
        return 0

    return _launch(
        loaded_a,
        loaded_b,
        summary,
        canonical_mode=canonical_mode,
        workspace_root=workspace_root,
    )


if __name__ == "__main__":
    raise SystemExit(run_cli())
