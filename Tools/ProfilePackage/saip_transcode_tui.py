"""
Split-pane Textual UI for SAIP decoded JSON editing with DER hex preview.

Imported only from the TRANSCODE-TUI shell command so Textual stays off the
default CLI import path.

JSON uses pySim ProfileElement.decoded field names (asn1tools structures) plus
``__ygg_saip_bytes__`` / ``__ygg_saip_tuple__`` tags for JSON round-trip.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .saip_tool import SaipToolBridge


def _clipboard_write_commands() -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    if len(str(os.environ.get("WAYLAND_DISPLAY", "") or "").strip()) > 0:
        wl_copy = shutil.which("wl-copy")
        if wl_copy is not None:
            commands.append(("wl-copy", [wl_copy]))
    if len(str(os.environ.get("DISPLAY", "") or "").strip()) > 0:
        xclip = shutil.which("xclip")
        if xclip is not None:
            commands.append(("xclip", [xclip, "-selection", "clipboard", "-in"]))
        xsel = shutil.which("xsel")
        if xsel is not None:
            commands.append(("xsel", [xsel, "--clipboard", "--input"]))
    pbcopy = shutil.which("pbcopy")
    if pbcopy is not None:
        commands.append(("pbcopy", [pbcopy]))
    return commands


def _clipboard_read_commands() -> list[tuple[str, list[str]]]:
    commands: list[tuple[str, list[str]]] = []
    if len(str(os.environ.get("WAYLAND_DISPLAY", "") or "").strip()) > 0:
        wl_paste = shutil.which("wl-paste")
        if wl_paste is not None:
            commands.append(("wl-paste", [wl_paste, "--no-newline"]))
    if len(str(os.environ.get("DISPLAY", "") or "").strip()) > 0:
        xclip = shutil.which("xclip")
        if xclip is not None:
            commands.append(("xclip", [xclip, "-selection", "clipboard", "-out"]))
        xsel = shutil.which("xsel")
        if xsel is not None:
            commands.append(("xsel", [xsel, "--clipboard", "--output"]))
    pbpaste = shutil.which("pbpaste")
    if pbpaste is not None:
        commands.append(("pbpaste", [pbpaste]))
    return commands


def _copy_text_to_system_clipboard(text: str) -> str | None:
    normalized_text = str(text or "")
    for backend_name, command in _clipboard_write_commands():
        try:
            subprocess.run(
                command,
                input=normalized_text,
                text=True,
                capture_output=True,
                check=True,
                timeout=2,
            )
        except Exception:
            continue
        return backend_name
    return None


def _read_text_from_system_clipboard() -> tuple[str | None, str | None]:
    for backend_name, command in _clipboard_read_commands():
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=2,
            )
        except Exception:
            continue
        return (str(completed.stdout), backend_name)
    return (None, None)


def run_saip_transcode_tui(bridge: SaipToolBridge) -> None:
    from dataclasses import dataclass
    import json
    import sys

    resolved_input = bridge.resolve_input_path(str(bridge.get_input_file()), must_exist=True)
    prepared_input = bridge._prepare_input_for_tool(resolved_input)
    raw_der = prepared_input.read_bytes()

    pysim_root = bridge.workspace_root / "pysim"
    if pysim_root.is_dir() is False:
        raise RuntimeError(f"Local pySim source tree not found: {pysim_root}")
    pysim_root_text = str(pysim_root.resolve())
    if pysim_root_text not in sys.path:
        sys.path.insert(0, pysim_root_text)

    from pySim.esim.saip import ProfileElementSequence

    def describe_exception_chain(error: Exception) -> str:
        parts: list[str] = []
        current: Exception | None = error
        while current is not None:
            text = str(current).strip() or current.__class__.__name__
            if len(parts) == 0 or parts[-1] != text:
                parts.append(text)
            next_error = current.__cause__
            if isinstance(next_error, Exception):
                next_text = str(next_error).strip() or next_error.__class__.__name__
                if len(next_text) > 0 and next_text in text:
                    break
                current = next_error
                continue
            break
        return " | ".join(parts)

    def format_der_preview(raw_profile_der: bytes, *, limit: int = 16) -> str:
        if len(raw_profile_der) == 0:
            return "(empty)"
        preview = " ".join(f"{byte:02X}" for byte in raw_profile_der[:limit])
        if len(raw_profile_der) > limit:
            preview += " ..."
        return preview

    def build_invalid_profile_hints(raw_profile_der: bytes, error: Exception) -> list[str]:
        hints: list[str] = []
        detail = describe_exception_chain(error)
        lowered_detail = detail.lower()
        if len(raw_profile_der) == 0:
            hints.append("Input DER is empty.")
            return hints
        if "profileelement" in lowered_detail and "has no attribute 'type'" in lowered_detail:
            hints.append(
                "Decoder reached a ProfileElement instance without a `type` attribute. "
                "This usually means the input is not a complete SAIP profile package, "
                "is truncated or corrupted, or the active pySim SAIP schema does not "
                "match the file."
            )
        if len(hints) == 0:
            hints.append(
                "Input is not a decodable SAIP profile element sequence under the current "
                "pySim schema."
            )
        return hints

    @dataclass
    class ValidationIssue:
        summary: str

    def decode_profile_sequence_or_raise(
        raw_profile_der: bytes,
        *,
        prefix: str = "Profile ASN1 is not valid.",
        source_label: str = "",
    ):
        try:
            return ProfileElementSequence.from_der(raw_profile_der)
        except Exception as error:
            detail = describe_exception_chain(error)
            message_parts: list[str] = [prefix]
            normalized_source = str(source_label or "").strip()
            if len(normalized_source) > 0:
                message_parts.append(f"Source: {normalized_source}.")
            message_parts.append(f"Size: {len(raw_profile_der)} bytes.")
            message_parts.append(f"First bytes: {format_der_preview(raw_profile_der)}.")
            if len(detail) > 0:
                message_parts.append(f"Decoder error: {detail}.")
            for hint in build_invalid_profile_hints(raw_profile_der, error):
                message_parts.append(f"Hint: {hint}")
            raise ValueError(" ".join(message_parts)) from error

    def validate_editor_buffer(editor_text: str) -> ValidationIssue | None:
        stripped = str(editor_text or "").strip()
        if len(stripped) == 0:
            return ValidationIssue("JSON buffer is empty.")
        try:
            document = parse_editor_json(editor_text)
        except json.JSONDecodeError as error:
            return ValidationIssue(
                f"JSON syntax error at line {error.lineno}, column {error.colno}: {error.msg}"
            )
        except Exception as error:
            return ValidationIssue(describe_exception_chain(error))
        try:
            der = encode_der_from_document(document, workspace_root)
        except Exception as error:
            return ValidationIssue(describe_exception_chain(error))
        try:
            decode_profile_sequence_or_raise(
                der,
                prefix="Re-encoded profile ASN1 is not valid.",
                source_label="re-encoded JSON buffer",
            )
        except Exception as error:
            return ValidationIssue(describe_exception_chain(error))
        return None

    pes_loaded = decode_profile_sequence_or_raise(
        raw_der,
        source_label=str(resolved_input),
    )
    from .saip_pe_quick_add import (
        copy_pe_snapshot,
        insert_blank_pe_for_menu_id,
        iter_option_list_specs,
        menu_ids_blocked_if_present,
        move_pe_in_document,
        paste_pe_snapshot,
    )
    from .saip_tui_lint import format_finding_rich_markup, lint_profile_json_buffer

    from .saip_json_codec import (
        _TAG_BYTES,
        _TAG_LABEL,
        _TAG_TUPLE,
        _canonical_tag_key,
        _LEGACY_TAG_BYTES,
        _LEGACY_TAG_LABEL,
        _LEGACY_TAG_TUPLE,
        _structural_data_keys,
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
        base_pe_type,
        dejsonify_document,
        document_to_pretty_json,
        encode_der_from_document,
        format_der_hex,
        jsonify_document,
        parse_editor_json,
        reapply_transcode_editor_placeholders,
    )
    from .saip_transcode_inspect import build_transcode_inspector_text
    from .saip_transcode_sync import (
        _scan_json_value_end,
        build_json_entry_spans,
        byte_range_to_hex_selection,
        der_byte_range_to_json_editor_range,
        enclosing_json_value_span,
        hex_selection_to_byte_range,
        infer_section_key_from_json_cursor,
        json_editor_range_to_der_byte_range,
        location_to_offset,
        offset_to_location,
        ordered_section_keys_from_pes,
        pe_byte_ranges_from_raw_der,
        scan_json_list_items,
        scan_json_object_members,
    )
    from .saip_transcode_tui_prefs import (
        load_pane_layout_prefs,
        load_split_size_prefs,
        load_transcode_tui_prefs,
        next_theme_in_cycle,
        persist_pane_layout_prefs,
        persist_split_sizes,
        persist_theme,
    )
    document = build_decoded_document_from_sequence(
        pes_loaded,
        intro_lines=[
            (
                f"Read {len(pes_loaded.pe_list)} profile elements from "
                f"{resolved_input.name}"
            ),
        ],
    )
    initial_json = document_to_pretty_json(document)
    initial_hex = format_der_hex(raw_der)
    workspace_root = bridge.workspace_root
    profile_label = resolved_input.name
    transcode_json_path, transcode_der_path, transcode_txt_path = bridge.resolve_transcode_sidecar_paths(
        resolved_input
    )
    transcode_json_display = bridge.display_path(transcode_json_path)
    transcode_der_display = bridge.display_path(transcode_der_path)
    transcode_txt_display = bridge.display_path(transcode_txt_path)
    transcode_dir_display = bridge.display_path(transcode_json_path.parent)

    from textual import events
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.document._document import Selection
    from textual.screen import ModalScreen
    from rich.markup import escape
    from rich.text import Text
    from textual.widgets import ContentSwitcher, OptionList, RichLog, Static, TextArea, Tree
    from textual.widgets.option_list import Option

    def build_save_status(prefix: str) -> str:
        return (
            f"{prefix} - wrote {transcode_json_display} + {transcode_der_display} + "
            f"{transcode_txt_display}, "
            "reloaded JSON from disk (green border ~2.5s)"
        )

    class PeBlockPicker(ModalScreen[str | None]):
        """Choose a pySim blank PE template to insert at the selected PE anchor."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(self, blocked_ids: set[str], target_hint: str) -> None:
            super().__init__()
            self._blocked_ids = blocked_ids
            self._target_hint = str(target_hint).strip()

        def compose(self) -> ComposeResult:
            options: list[Option] = []
            for oid, title, hint, disabled in iter_option_list_specs(self._blocked_ids):
                if hint is None:
                    prompt = title
                else:
                    prompt = f"{title}  [dim]{hint}[/dim]"
                options.append(Option(prompt, id=oid, disabled=disabled))
            with Vertical(id="pe_picker_shell"):
                yield Static("Add blank profile element (pySim constructor defaults)")
                if len(self._target_hint) > 0:
                    yield Static(f"[dim]Insertion target: {self._target_hint}[/dim]")
                yield OptionList(*options, id="pe_opts")
                yield Static("[dim]Enter confirm · Esc close[/dim]")

        def on_mount(self) -> None:
            widget = self.query_one("#pe_opts", OptionList)
            widget.focus()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            oid = event.option_id
            if oid is None:
                self.dismiss(None)
                return
            if oid == "_cancel":
                self.dismiss(None)
                return
            self.dismiss(oid)

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class PaneLayoutPicker(ModalScreen[str | None]):
        """Direct pane layout assignment menu."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(self, outline_visible: bool, pane_modes: dict[str, str]) -> None:
            super().__init__()
            self._outline_visible = bool(outline_visible)
            self._pane_modes = dict(pane_modes)

        def compose(self) -> ComposeResult:
            options: list[Option] = []
            outline_target = "Hide" if self._outline_visible else "Show"
            options.append(
                Option(
                    f"Outline -> {outline_target}  [dim](current: {'Shown' if self._outline_visible else 'Hidden'})[/dim]",
                    id="outline:toggle",
                )
            )
            mode_titles = {
                "der": "DER",
                "inspect": "Inspect",
                "lint": "Lint",
                "none": "Hidden",
            }
            slot_titles = {
                "right": "Right pane",
                "bottom_left": "Bottom-left pane",
                "bottom_right": "Bottom-right pane",
            }
            mode_order_by_slot = {
                "right": ("der", "inspect", "lint", "none"),
                "bottom_left": ("inspect", "lint", "der", "none"),
                "bottom_right": ("lint", "der", "inspect", "none"),
            }
            for slot_name in ("right", "bottom_left", "bottom_right"):
                current_mode = str(self._pane_modes.get(slot_name, "")).lower()
                for mode_name in mode_order_by_slot[slot_name]:
                    suffix = ""
                    if mode_name == current_mode:
                        suffix = "  [dim][current][/dim]"
                    options.append(
                        Option(
                            f"{slot_titles[slot_name]} -> {mode_titles[mode_name]}{suffix}",
                            id=f"slot:{slot_name}:{mode_name}",
                        )
                    )
            options.append(Option("Reset default layout", id="reset"))
            with Vertical(id="pane_picker_shell"):
                yield Static("Pane layout")
                yield Static(
                    "[dim]Choose exactly what each pane shows. Enter confirm · Esc close[/dim]"
                )
                yield OptionList(*options, id="pane_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#pane_opts", OptionList)
            widget.focus()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            oid = event.option_id
            if oid is None:
                self.dismiss(None)
                return
            self.dismiss(oid)

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class DragHandle(Static):
        """Dedicated split handle with direct mouse capture."""

        def on_mouse_down(self, event: events.MouseDown) -> None:
            wid = self.id or ""
            app = self.app
            if hasattr(app, "_begin_split_drag") is False:
                return
            self.capture_mouse()
            app._begin_split_drag(
                wid,
                int(event.screen_x or 0),
                int(event.screen_y or 0),
            )
            event.stop()

        def on_mouse_move(self, event: events.MouseMove) -> None:
            app = self.app
            if hasattr(app, "_continue_split_drag") is False:
                return
            if getattr(app, "_drag_state", None) is None:
                return
            app._continue_split_drag(
                int(event.screen_x or 0),
                int(event.screen_y or 0),
            )
            event.stop()

        def on_mouse_up(self, event: events.MouseUp) -> None:
            app = self.app
            if hasattr(app, "_end_split_drag"):
                app._end_split_drag()
            self.release_mouse()
            event.stop()

    class SaipTranscodeApp(App):
        TITLE = "SAIP JSON ↔ DER"
        SUB_TITLE = (
            f"{resolved_input.name} · Ctrl+S save · F3 add PE · Ctrl+Shift+↑/↓ move PE · "
            "Ctrl+C/V text · Ctrl+Shift+C/V/B PE copy/paste · F4 inspect left · "
            "F5/F6/F8/F9 panes · F7 theme · F10 pane menu · Ctrl+Q quit"
        )
        _PANE_MODE_SEQUENCE = ("der", "inspect", "lint", "none")
        _SLOT_DEFAULTS = {
            "right": "der",
            "bottom_left": "inspect",
            "bottom_right": "lint",
        }
        _SLOT_SWITCHERS = {
            "right": "right_switcher",
            "bottom_left": "inspect_switcher",
            "bottom_right": "lint_switcher",
        }
        _SLOT_CAPTIONS = {
            "right": "right_col_caption",
            "bottom_left": "inspect_col_caption",
            "bottom_right": "lint_col_caption",
        }
        _SLOT_MODE_WIDGETS = {
            "right": {
                "der": "der_view",
                "inspect": "right_inspect_log",
                "lint": "right_lint_log",
                "none": "right_none",
            },
            "bottom_left": {
                "der": "inspect_der_view",
                "inspect": "inspect_log",
                "lint": "inspect_lint_log",
                "none": "inspect_none",
            },
            "bottom_right": {
                "der": "lint_der_view",
                "inspect": "lint_inspect_log",
                "lint": "lint_log",
                "none": "lint_none",
            },
        }

        CSS = """
        Screen {
            layout: vertical;
            height: 100%;
            width: 100%;
            background: transparent;
        }
        #chrome {
            width: 100%;
            height: 100%;
            background: transparent;
            padding: 0;
        }
        #chrome_title {
            height: 1;
            padding: 0 1;
            background: transparent;
            color: #DDF7FF;
            border-bottom: solid #6FD3FF;
        }
        #split_row {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #json_col {
            width: 5fr;
            height: 100%;
            min-width: 48;
            min-height: 0;
        }
        #der_col {
            width: 4fr;
            height: 100%;
            min-width: 28;
            min-height: 0;
        }
        .pane-caption {
            height: 1;
            padding: 0 1;
            background: transparent;
            color: #BFEAFF;
        }
        #json_editor {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid #6FD3FF;
            background: transparent;
        }
        #json_inner {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #json_outline {
            width: 34;
            min-width: 24;
            max-width: 48;
            height: 100%;
            border: solid #6FD3FF;
            background: transparent;
        }
        .drag-handle {
            background: #59C7FF;
        }
        #json_handle, #der_handle, #inspect_handle {
            width: 2;
            min-width: 2;
            height: 100%;
        }
        #bottom_handle {
            height: 1;
            min-height: 1;
            width: 100%;
        }
        #json_editor_box {
            width: 1fr;
            height: 100%;
            min-width: 0;
        }
        .slot-switcher {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #der_view {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid #6FD3FF;
            background: transparent;
        }
        .der-pane {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid #6FD3FF;
            background: transparent;
        }
        #json_editor.flash-ok {
            border: tall #44cc44;
        }
        #der_view.flash-ok {
            border: tall #44cc44;
        }
        .der-pane.flash-ok {
            border: tall #44cc44;
        }
        #json_editor.invalid-buffer {
            border: tall #FF6B6B;
            color: #FFB4B4;
        }
        #der_view.invalid-buffer {
            border: tall #FF6B6B;
            color: #FFB4B4;
        }
        .der-pane.invalid-buffer {
            border: tall #FF6B6B;
            color: #FFB4B4;
        }
        #json_editor.peer-sync {
            border: tall $accent;
        }
        #der_view.peer-sync {
            border: tall $accent;
        }
        .der-pane.peer-sync {
            border: tall $accent;
        }
        #upper {
            height: 1fr;
            min-height: 0;
        }
        #bottom_row {
            height: 14;
            min-height: 6;
            max-height: 24;
            width: 100%;
            layout: horizontal;
        }
        #inspect_col, #lint_col {
            width: 1fr;
            height: 100%;
            min-width: 0;
        }
        #inspect_log, #lint_log {
            height: 1fr;
            min-height: 4;
            border-top: solid #6FD3FF;
            background: transparent;
        }
        .log-pane {
            height: 1fr;
            min-height: 4;
            border-top: solid #6FD3FF;
            background: transparent;
        }
        .pane-placeholder {
            height: 1fr;
            min-height: 4;
            border-top: solid #6FD3FF;
            background: transparent;
            color: #8EC6D8;
            padding: 0 1;
        }
        #status_line {
            height: 1;
            border-top: solid #6FD3FF;
            background: transparent;
            color: #DDF7FF;
            padding: 0 1;
        }
        #status_line.error-state {
            border-top: solid #FF6B6B;
            color: #FFB4B4;
        }
        PeBlockPicker {
            align: center middle;
        }
        #pe_picker_shell {
            width: 88;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick #6FD3FF;
        }
        #pe_opts {
            height: 22;
            min-height: 8;
            margin-top: 1;
            margin-bottom: 1;
        }
        #pane_picker_shell {
            width: 96;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick #6FD3FF;
        }
        #pane_opts {
            height: 24;
            min-height: 8;
            margin-top: 1;
        }
        """

        BINDINGS = [
            Binding("ctrl+c", "copy_text_selection", "Copy text", show=False, priority=True),
            Binding("ctrl+v", "paste_text_clipboard", "Paste text", show=False, priority=True),
            Binding("ctrl+insert", "copy_text_selection", "Copy text", show=False, priority=True),
            Binding("shift+insert", "paste_text_clipboard", "Paste text", show=False, priority=True),
            Binding("ctrl+s", "save_refresh", "Save / re-encode", priority=True),
            Binding("f2", "save_refresh", "Save / re-encode", priority=True),
            Binding("f3", "add_pe_block", "Add PE", priority=True),
            Binding("ctrl+shift+up", "move_selected_pe_up", "Move PE up", priority=True),
            Binding("ctrl+shift+down", "move_selected_pe_down", "Move PE down", priority=True),
            Binding("ctrl+shift+c", "copy_contextual", "Copy PE", priority=True),
            Binding("ctrl+shift+v", "paste_selected_pe_after", "Paste PE after", priority=True),
            Binding("ctrl+shift+b", "paste_selected_pe_before", "Paste PE before", priority=True),
            Binding("f4", "toggle_inspect_left_mode", "Inspect left mode", priority=True),
            Binding("f5", "cycle_right_pane", "Right pane", priority=True),
            Binding("f6", "toggle_outline_pane", "Outline", priority=True),
            Binding("f7", "cycle_theme", "Cycle theme", priority=True),
            Binding("f8", "cycle_bottom_left_pane", "Bottom-left pane", priority=True),
            Binding("f9", "cycle_bottom_right_pane", "Bottom-right pane", priority=True),
            Binding("f10", "open_pane_layout_menu", "Pane menu", priority=True),
            Binding("ctrl+q", "quit", "Quit (exit TUI)", priority=True),
        ]

        def __init__(self) -> None:
            self._peer_lock = False
            self._lint_debounce_gen = 0
            self._left_inspect_mode = "selection"
            self._drag_state: dict[str, int] | None = None
            self._json_outline_width = 34
            self._json_col_width = 0
            self._inspect_width = 0
            self._bottom_height = 14
            self._pe_clipboard: dict[str, object] | None = None
            self._pending_insert_anchor_key: str | None = None
            self._pending_insert_after = True
            self._status_base_text = ""
            self._validation_issue: ValidationIssue | None = None
            self._outline_visible = True
            self._pane_modes = dict(self._SLOT_DEFAULTS)
            super().__init__()

        def compose(self) -> ComposeResult:
            with Vertical(id="chrome"):
                yield Static(
                    "SAIP JSON↔DER · Text Ctrl+C/V · Save Ctrl+S/F2 · Add F3 · Inspect F4 · "
                    "Panes F5/F6/F8/F9 · Pane menu F10 · Theme F7 · Quit Ctrl+Q",
                    id="chrome_title",
                )
                with Vertical(id="upper"):
                    with Horizontal(id="split_row"):
                        with Vertical(id="json_col"):
                            yield Static(
                                (
                                    f"JSON editor · save dir {transcode_dir_display} · "
                                    f"writes {transcode_json_path.name} + {transcode_der_path.name} + "
                                    f"{transcode_txt_path.name} · "
                                    "placeholders supported"
                                ),
                                classes="pane-caption",
                            )
                            with Horizontal(id="json_inner"):
                                yield Tree("ProfileElements", id="json_outline")
                                yield DragHandle("", id="json_handle", classes="drag-handle")
                                with Vertical(id="json_editor_box"):
                                    yield TextArea(
                                        initial_json,
                                        id="json_editor",
                                        language="json",
                                        show_line_numbers=True,
                                    )
                        yield DragHandle("", id="der_handle", classes="drag-handle")
                        with Vertical(id="der_col"):
                            yield Static(
                                self._slot_caption_text("right"),
                                classes="pane-caption",
                                id="right_col_caption",
                            )
                            with ContentSwitcher(
                                initial=self._SLOT_MODE_WIDGETS["right"][self._pane_modes["right"]],
                                id="right_switcher",
                                classes="slot-switcher",
                            ):
                                yield TextArea(
                                    initial_hex,
                                    id="der_view",
                                    classes="der-pane",
                                    language=None,
                                    soft_wrap=False,
                                    read_only=True,
                                    show_line_numbers=True,
                                )
                                yield RichLog(
                                    id="right_inspect_log",
                                    classes="inspect-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=None,
                                    highlight=False,
                                )
                                yield RichLog(
                                    id="right_lint_log",
                                    classes="lint-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=320,
                                    highlight=False,
                                )
                                yield Static(
                                    "Pane hidden. Press F5 to cycle the right pane.",
                                    id="right_none",
                                    classes="pane-placeholder",
                                )
                    yield DragHandle("", id="bottom_handle", classes="drag-handle")
                    with Horizontal(id="bottom_row"):
                        with Vertical(id="inspect_col"):
                            yield Static(
                                self._slot_caption_text("bottom_left"),
                                id="inspect_col_caption",
                                classes="pane-caption",
                            )
                            with ContentSwitcher(
                                initial=self._SLOT_MODE_WIDGETS["bottom_left"][self._pane_modes["bottom_left"]],
                                id="inspect_switcher",
                                classes="slot-switcher",
                            ):
                                yield RichLog(
                                    id="inspect_log",
                                    classes="inspect-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=None,
                                    highlight=False,
                                )
                                yield TextArea(
                                    initial_hex,
                                    id="inspect_der_view",
                                    classes="der-pane",
                                    language=None,
                                    soft_wrap=False,
                                    read_only=True,
                                    show_line_numbers=True,
                                )
                                yield RichLog(
                                    id="inspect_lint_log",
                                    classes="lint-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=320,
                                    highlight=False,
                                )
                                yield Static(
                                    "Pane hidden. Press F8 to cycle the bottom-left pane.",
                                    id="inspect_none",
                                    classes="pane-placeholder",
                                )
                        yield DragHandle("", id="inspect_handle", classes="drag-handle")
                        with Vertical(id="lint_col"):
                            yield Static(
                                self._slot_caption_text("bottom_right"),
                                id="lint_col_caption",
                                classes="pane-caption",
                            )
                            with ContentSwitcher(
                                initial=self._SLOT_MODE_WIDGETS["bottom_right"][self._pane_modes["bottom_right"]],
                                id="lint_switcher",
                                classes="slot-switcher",
                            ):
                                yield RichLog(
                                    id="lint_log",
                                    classes="lint-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=320,
                                    highlight=False,
                                )
                                yield TextArea(
                                    initial_hex,
                                    id="lint_der_view",
                                    classes="der-pane",
                                    language=None,
                                    soft_wrap=False,
                                    read_only=True,
                                    show_line_numbers=True,
                                )
                                yield RichLog(
                                    id="lint_inspect_log",
                                    classes="inspect-pane log-pane",
                                    auto_scroll=True,
                                    wrap=True,
                                    max_lines=None,
                                    highlight=False,
                                )
                                yield Static(
                                    "Pane hidden. Press F9 to cycle the bottom-right pane.",
                                    id="lint_none",
                                    classes="pane-placeholder",
                                )
                yield Static("", id="status_line")

        def _slot_display_name(self, slot_name: str) -> str:
            return {
                "right": "Right pane",
                "bottom_left": "Bottom-left pane",
                "bottom_right": "Bottom-right pane",
            }.get(slot_name, slot_name)

        def _is_der_view(self, widget: object) -> bool:
            return isinstance(widget, TextArea) and widget.has_class("der-pane")

        def _all_der_views(self) -> list[TextArea]:
            return [widget for widget in self.query(".der-pane") if isinstance(widget, TextArea)]

        def _all_inspect_logs(self) -> list[RichLog]:
            return [widget for widget in self.query(".inspect-pane") if isinstance(widget, RichLog)]

        def _all_lint_logs(self) -> list[RichLog]:
            return [widget for widget in self.query(".lint-pane") if isinstance(widget, RichLog)]

        def _mode_display_name(self, mode_name: str) -> str:
            return {
                "der": "DER",
                "inspect": "Inspect",
                "lint": "Lint",
                "none": "Hidden",
            }.get(str(mode_name or "").lower(), str(mode_name or "").lower() or "Unknown")

        def _slot_caption_text(self, slot_name: str) -> str:
            mode = self._pane_modes.get(slot_name, self._SLOT_DEFAULTS[slot_name])
            title = self._slot_display_name(slot_name)
            if mode == "der":
                return (
                    f"{title}: DER hex · follows selected JSON value · "
                    "double-click DER to jump back"
                )
            if mode == "inspect":
                if self._left_inspect_mode == "selection":
                    return f"{title}: selection decode (ASN.1 + EF parser)"
                return f"{title}: whole profile ASN.1 decode (all PEs)"
            if mode == "lint":
                return f"{title}: profile lint (live)"
            return f"{title}: hidden"

        def _persist_pane_layout(self) -> None:
            persist_pane_layout_prefs(
                workspace_root,
                outline_visible=self._outline_visible,
                right_mode=self._pane_modes["right"],
                bottom_left_mode=self._pane_modes["bottom_left"],
                bottom_right_mode=self._pane_modes["bottom_right"],
            )

        def _apply_pane_layout(self) -> None:
            outline = self.query_one("#json_outline", Tree)
            json_handle = self.query_one("#json_handle")
            outline.display = self._outline_visible
            json_handle.display = self._outline_visible

            for slot_name, switcher_id in self._SLOT_SWITCHERS.items():
                switcher = self.query_one(f"#{switcher_id}", ContentSwitcher)
                switcher.current = self._SLOT_MODE_WIDGETS[slot_name][self._pane_modes[slot_name]]
                caption = self.query_one(f"#{self._SLOT_CAPTIONS[slot_name]}", Static)
                caption.update(self._slot_caption_text(slot_name))

            der_handle = self.query_one("#der_handle")
            der_col = self.query_one("#der_col", Vertical)
            right_visible = self._pane_modes["right"] != "none"
            der_handle.display = right_visible
            der_col.display = right_visible

            bottom_handle = self.query_one("#bottom_handle")
            bottom_row = self.query_one("#bottom_row", Horizontal)
            inspect_handle = self.query_one("#inspect_handle")
            inspect_col = self.query_one("#inspect_col", Vertical)
            lint_col = self.query_one("#lint_col", Vertical)
            bottom_left_visible = self._pane_modes["bottom_left"] != "none"
            bottom_right_visible = self._pane_modes["bottom_right"] != "none"
            any_bottom_visible = bottom_left_visible or bottom_right_visible
            bottom_handle.display = any_bottom_visible
            bottom_row.display = any_bottom_visible
            inspect_col.display = bottom_left_visible
            lint_col.display = bottom_right_visible
            inspect_handle.display = bottom_left_visible and bottom_right_visible
            self._apply_split_sizes()

        def _set_slot_mode(self, slot_name: str, mode_name: str) -> str:
            normalized_slot = str(slot_name or "").strip()
            normalized_mode = str(mode_name or "").strip().lower()
            if normalized_slot not in self._SLOT_DEFAULTS:
                raise ValueError(f"unknown pane slot: {normalized_slot}")
            if normalized_mode not in self._PANE_MODE_SEQUENCE:
                raise ValueError(f"unknown pane mode: {normalized_mode}")
            self._pane_modes[normalized_slot] = normalized_mode
            self._persist_pane_layout()
            self._apply_pane_layout()
            self._refresh_bottom_panel()
            return normalized_mode

        def _reset_pane_layout_defaults(self) -> None:
            self._outline_visible = True
            self._pane_modes = dict(self._SLOT_DEFAULTS)
            self._persist_pane_layout()
            self._apply_pane_layout()
            self._refresh_bottom_panel()

        def _cycle_slot_mode(self, slot_name: str) -> str:
            current = self._pane_modes.get(slot_name, self._SLOT_DEFAULTS[slot_name])
            try:
                index = self._PANE_MODE_SEQUENCE.index(current)
            except ValueError:
                index = 0
            next_mode = self._PANE_MODE_SEQUENCE[(index + 1) % len(self._PANE_MODE_SEQUENCE)]
            self._set_slot_mode(slot_name, next_mode)
            self._set_status(
                f"{self._slot_display_name(slot_name)} -> {self._slot_caption_text(slot_name)} (saved)",
                remember=False,
            )
            return next_mode

        def action_cycle_right_pane(self) -> None:
            self._cycle_slot_mode("right")

        def action_cycle_bottom_left_pane(self) -> None:
            self._cycle_slot_mode("bottom_left")

        def action_cycle_bottom_right_pane(self) -> None:
            self._cycle_slot_mode("bottom_right")

        def action_toggle_outline_pane(self) -> None:
            self._outline_visible = not self._outline_visible
            self._persist_pane_layout()
            self._apply_pane_layout()
            state = "shown" if self._outline_visible else "hidden"
            self._set_status(f"Outline pane {state} (saved).", remember=False)

        def action_open_pane_layout_menu(self) -> None:
            self.push_screen(
                PaneLayoutPicker(self._outline_visible, self._pane_modes),
                callback=self._on_pane_layout_choice,
            )

        def _on_pane_layout_choice(self, choice: str | None) -> None:
            if choice is None:
                return
            raw_choice = str(choice).strip()
            if raw_choice == "outline:toggle":
                self.action_toggle_outline_pane()
                return
            if raw_choice == "reset":
                self._reset_pane_layout_defaults()
                self._set_status("Pane layout reset to defaults (saved).", remember=False)
                return
            if raw_choice.startswith("slot:") is False:
                self._set_status(f"Unknown pane layout choice: {raw_choice}", remember=False)
                return
            parts = raw_choice.split(":")
            if len(parts) != 3:
                self._set_status(f"Invalid pane layout choice: {raw_choice}", remember=False)
                return
            _, slot_name, mode_name = parts
            try:
                applied_mode = self._set_slot_mode(slot_name, mode_name)
            except Exception as exc:
                self._set_status(f"Pane layout failed: {exc}", remember=False)
                return
            self._set_status(
                f"{self._slot_display_name(slot_name)} set to {self._mode_display_name(applied_mode)} (saved).",
                remember=False,
            )

        def on_mount(self) -> None:
            prefs = load_transcode_tui_prefs(workspace_root)
            want_theme = str(prefs.get("theme") or "textual-ansi")
            if want_theme == "textual-dark":
                want_theme = "textual-ansi"
            try:
                self.theme = want_theme
            except Exception:
                self.theme = "textual-ansi"
            split_prefs = load_split_size_prefs(workspace_root)
            saved_json_outline_width = split_prefs.get("json_outline_width")
            if saved_json_outline_width is not None:
                self._json_outline_width = saved_json_outline_width
            saved_json_col_width = split_prefs.get("json_col_width")
            if saved_json_col_width is not None:
                self._json_col_width = saved_json_col_width
            saved_inspect_width = split_prefs.get("inspect_width")
            if saved_inspect_width is not None:
                self._inspect_width = saved_inspect_width
            saved_bottom_height = split_prefs.get("bottom_height")
            if saved_bottom_height is not None:
                self._bottom_height = saved_bottom_height
            pane_prefs = load_pane_layout_prefs(workspace_root)
            saved_outline_visible = pane_prefs.get("outline_visible")
            if isinstance(saved_outline_visible, bool):
                self._outline_visible = saved_outline_visible
            for slot_name, pref_key in (
                ("right", "right_mode"),
                ("bottom_left", "bottom_left_mode"),
                ("bottom_right", "bottom_right_mode"),
            ):
                saved_mode = pane_prefs.get(pref_key)
                if isinstance(saved_mode, str):
                    self._pane_modes[slot_name] = saved_mode
            self._pes = pes_loaded
            self._raw_der = raw_der
            self._json_snapshot = initial_json
            self._hex_snapshot = initial_hex
            self._keys: list[str] = ordered_section_keys_from_pes(self._pes)
            self._byte_ranges: list[tuple[str, int, int]] = []
            self._ranges_by_key: dict[str, tuple[int, int]] = {}
            self._json_spans: dict[str, tuple[int, int]] = {}
            self._rebuild_peer_map()
            outline = self.query_one("#json_outline", Tree)
            outline.show_root = False
            outline.root.expand()
            self._apply_pane_layout()
            self._set_status(
                f"Transcode save dir: {transcode_dir_display} "
                f"({transcode_json_path.name} + {transcode_der_path.name} + "
                f"{transcode_txt_path.name})"
            )
            self.call_after_refresh(self._apply_split_sizes)
            self._refresh_validation_feedback()
            self._refresh_json_outline()
            self._refresh_bottom_panel()

        def _set_status(self, message: str, *, remember: bool = True) -> None:
            if remember:
                self._status_base_text = str(message or "")
            stat = self.query_one("#status_line", Static)
            if self._validation_issue is not None:
                return
            stat.remove_class("error-state")
            stat.update(str(message or ""))

        def _set_validation_issue(self, issue: ValidationIssue | None) -> None:
            self._validation_issue = issue
            editor = self.query_one("#json_editor", TextArea)
            der_widgets = self._all_der_views()
            stat = self.query_one("#status_line", Static)
            if issue is None:
                editor.remove_class("invalid-buffer")
                for der_widget in der_widgets:
                    der_widget.remove_class("invalid-buffer")
                stat.remove_class("error-state")
                stat.update(self._status_base_text)
                return
            editor.add_class("invalid-buffer")
            for der_widget in der_widgets:
                der_widget.remove_class("invalid-buffer")
            stat.add_class("error-state")
            stat.update(issue.summary)

        def _refresh_validation_feedback(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            self._set_validation_issue(validate_editor_buffer(editor.text))

        def _focused_text_area(self) -> TextArea | None:
            focused = self.focused
            if isinstance(focused, TextArea):
                return focused
            return None

        def _copy_selected_text_from_focused_area(self) -> bool:
            widget = self._focused_text_area()
            if widget is None:
                return False
            selection = widget.selection
            if selection.is_empty:
                return False
            selected_text = widget.selected_text
            if len(selected_text) == 0:
                return False
            self.copy_to_clipboard(selected_text)
            system_backend = _copy_text_to_system_clipboard(selected_text)
            area_label = "text area"
            if widget.id == "json_editor":
                area_label = "JSON editor"
            elif self._is_der_view(widget):
                area_label = "DER view"
            clipboard_target = "terminal clipboard"
            if system_backend is not None:
                clipboard_target = f"OS clipboard via {system_backend}"
            self._set_status(
                f"Copied {len(selected_text)} character(s) from {area_label} to {clipboard_target}.",
                remember=False,
            )
            return True

        def _paste_clipboard_into_focused_area(self) -> bool:
            widget = self._focused_text_area()
            if widget is None:
                return False
            if getattr(widget, "read_only", False):
                self._set_status(
                    "Focused text area is read-only. Paste is only available in the JSON editor.",
                    remember=False,
                )
                return True
            clipboard_text, system_backend = _read_text_from_system_clipboard()
            clipboard_source = None
            if clipboard_text is None:
                clipboard_text = str(self.clipboard or "")
                if len(clipboard_text) > 0:
                    clipboard_source = "terminal clipboard"
            else:
                clipboard_source = f"OS clipboard via {system_backend}"
            if len(clipboard_text) == 0:
                self._set_status("Clipboard is empty.", remember=False)
                return True
            selection = widget.selection
            edit_result = widget.replace(
                clipboard_text,
                selection.start,
                selection.end,
                maintain_selection_offset=False,
            )
            widget.move_cursor(edit_result.end_location)
            if clipboard_source is None:
                clipboard_source = "clipboard"
            self._set_status(
                f"Pasted {len(clipboard_text)} character(s) from {clipboard_source} into the JSON editor.",
                remember=False,
            )
            return True

        def action_copy_text_selection(self) -> None:
            if self._copy_selected_text_from_focused_area():
                return
            self._set_status(
                "Select text in the JSON editor or DER view first.",
                remember=False,
            )

        def action_paste_text_clipboard(self) -> None:
            if self._paste_clipboard_into_focused_area():
                return
            self._set_status(
                "Focus the JSON editor to paste clipboard text.",
                remember=False,
            )

        def action_copy_contextual(self) -> None:
            if self._copy_selected_text_from_focused_area():
                return
            self.action_copy_selected_pe()

        def on_text_area_changed(self, event: TextArea.Changed) -> None:
            if event.text_area.id != "json_editor":
                return
            self._lint_debounce_gen += 1
            generation = self._lint_debounce_gen

            def maybe_refresh() -> None:
                if generation != self._lint_debounce_gen:
                    return
                self._refresh_validation_feedback()
                self._refresh_json_outline()
                self._refresh_bottom_panel()

            self.set_timer(0.48, maybe_refresh)

        def action_toggle_inspect_left_mode(self) -> None:
            if self._left_inspect_mode == "selection":
                self._left_inspect_mode = "profile_asn1"
            else:
                self._left_inspect_mode = "selection"
            self._apply_pane_layout()
            self._refresh_inspect_panel()

        def action_cycle_theme(self) -> None:
            cur = str(self.theme or "textual-dark")
            nxt = next_theme_in_cycle(cur)
            try:
                self.theme = nxt
            except Exception as exc:
                self._set_status(f"Theme {nxt!r} failed: {exc}", remember=False)
                return
            persist_theme(workspace_root, nxt)
            self._set_status(f"Theme: {nxt} (saved)")

        def _apply_split_sizes(self) -> None:
            try:
                split_row = self.query_one("#split_row", Horizontal)
                json_col = self.query_one("#json_col", Vertical)
                json_outline = self.query_one("#json_outline", Tree)
                bottom_row = self.query_one("#bottom_row", Horizontal)
                inspect_col = self.query_one("#inspect_col", Vertical)
                lint_col = self.query_one("#lint_col", Vertical)
                der_col = self.query_one("#der_col", Vertical)
            except Exception:
                return
            split_width = int(split_row.size.width)
            if self._pane_modes["right"] == "none":
                json_col.styles.width = "1fr"
            elif self._json_col_width > 0 and split_width > 0:
                max_json_col_width = max(24, split_width - 30)
                min_json_col_width = min(48, max_json_col_width)
                self._json_col_width = max(
                    min_json_col_width,
                    min(max_json_col_width, self._json_col_width),
                )
                json_col.styles.width = self._json_col_width
                der_col.styles.width = "4fr"
            json_outline.styles.width = self._json_outline_width
            bottom_row.styles.height = self._bottom_height
            bottom_width = bottom_row.size.width
            if self._inspect_width <= 0 and bottom_width > 0:
                self._inspect_width = max(24, bottom_width // 2)
            if (
                self._inspect_width > 0
                and self._pane_modes["bottom_left"] != "none"
                and self._pane_modes["bottom_right"] != "none"
            ):
                inspect_col.styles.width = self._inspect_width
                lint_col.styles.width = "1fr"
            else:
                inspect_col.styles.width = "1fr"
                lint_col.styles.width = "1fr"

        def on_resize(self) -> None:
            self._apply_split_sizes()

        def _begin_split_drag(self, wid: str, sx: int, sy: int) -> None:
            if wid not in {"json_handle", "der_handle", "inspect_handle", "bottom_handle"}:
                return
            json_outline_width = self._json_outline_width
            json_col_width = self._json_col_width
            inspect_width = self._inspect_width
            bottom_height = self._bottom_height
            try:
                json_outline_width = max(
                    20,
                    int(self.query_one("#json_outline", Tree).region.width),
                )
            except Exception:
                pass
            try:
                json_col_width = max(
                    48,
                    int(self.query_one("#json_col", Vertical).region.width),
                )
            except Exception:
                pass
            try:
                inspect_width = max(
                    24,
                    int(self.query_one("#inspect_col", Vertical).region.width),
                )
            except Exception:
                pass
            try:
                bottom_height = max(
                    6,
                    int(self.query_one("#bottom_row", Horizontal).region.height),
                )
            except Exception:
                pass
            self._drag_state = {
                "wid": wid,
                "sx": sx,
                "sy": sy,
                "json_outline_width": json_outline_width,
                "json_col_width": json_col_width,
                "inspect_width": inspect_width,
                "bottom_height": bottom_height,
            }

        def _end_split_drag(self) -> None:
            if self._drag_state is None:
                return
            self._drag_state = None
            persist_split_sizes(
                workspace_root,
                json_outline_width=self._json_outline_width,
                json_col_width=self._json_col_width,
                inspect_width=self._inspect_width,
                bottom_height=self._bottom_height,
            )

        def _continue_split_drag(self, sx: int, sy: int) -> None:
            if self._drag_state is None:
                return
            dx = sx - self._drag_state["sx"]
            dy = sy - self._drag_state["sy"]
            wid = self._drag_state["wid"]
            if wid == "json_handle":
                total = max(self.query_one("#json_inner", Horizontal).size.width, 30)
                self._json_outline_width = max(
                    20,
                    min(total - 20, self._drag_state["json_outline_width"] + dx),
                )
            elif wid == "der_handle":
                total = max(self.query_one("#split_row", Horizontal).size.width, 78)
                max_json_col_width = max(24, total - 30)
                min_json_col_width = min(48, max_json_col_width)
                self._json_col_width = max(
                    min_json_col_width,
                    min(
                        max_json_col_width,
                        self._drag_state["json_col_width"] + dx,
                    ),
                )
            elif wid == "inspect_handle":
                total = max(self.query_one("#bottom_row", Horizontal).size.width, 40)
                self._inspect_width = max(
                    24,
                    min(total - 24, self._drag_state["inspect_width"] + dx),
                )
            elif wid == "bottom_handle":
                total = max(self.query_one("#upper", Vertical).size.height, 12)
                self._bottom_height = max(
                    6,
                    min(total - 6, self._drag_state["bottom_height"] - dy),
                )
            self._apply_split_sizes()

        def _skip_json_ws(self, text: str, pos: int, end: int) -> int:
            while pos < end and text[pos] in " \t\r\n":
                pos += 1
            return pos

        def _scan_object_members(
            self,
            text: str,
            start: int,
            end: int,
        ) -> list[tuple[str, int, int]]:
            return scan_json_object_members(text, start, end)

        def _scan_list_items(
            self,
            text: str,
            start: int,
            end: int,
        ) -> list[tuple[int, int]]:
            return scan_json_list_items(text, start, end)

        def _section_key_for_offset(
            self,
            text: str,
            offset: int,
        ) -> str | None:
            spans = self._json_spans_for_text(text)
            for key in self._keys:
                triple = spans.get(key)
                if triple is None:
                    continue
                entry_begin, _value_start, value_end = triple
                if entry_begin <= offset < value_end:
                    return key
            line = text.count("\n", 0, max(0, min(offset, len(text))))
            return infer_section_key_from_json_cursor(text, line)

        def _focus_span_for_offsets(
            self,
            text: str,
            start_off: int,
            end_off: int,
        ) -> tuple[int, int]:
            if end_off < start_off:
                start_off, end_off = end_off, start_off
            spans = self._json_spans_for_text(text)
            anchor = start_off
            pe_key = self._section_key_for_offset(text, anchor)
            if pe_key is None:
                return enclosing_json_value_span(text, start_off, end_off)
            triple = spans.get(pe_key)
            if triple is None:
                return enclosing_json_value_span(text, start_off, end_off)
            _entry_begin, value_start, value_end = triple
            if value_start >= value_end or value_start >= len(text):
                return enclosing_json_value_span(text, start_off, end_off)
            head = text[value_start]
            if head == "{":
                for _key_text, member_start, member_end in self._scan_object_members(
                    text,
                    value_start,
                    value_end,
                ):
                    if start_off == end_off:
                        if member_start <= anchor <= member_end:
                            return (member_start, member_end)
                    else:
                        if end_off <= member_start or start_off >= member_end:
                            continue
                        return (member_start, member_end)
                return (value_start, value_end)
            if head == "[":
                for item_start, item_end in self._scan_list_items(text, value_start, value_end):
                    if start_off == end_off:
                        if item_start <= anchor <= item_end:
                            return (item_start, item_end)
                    else:
                        if end_off <= item_start or start_off >= item_end:
                            continue
                        return (item_start, item_end)
                return (value_start, value_end)
            return enclosing_json_value_span(text, start_off, end_off)

        def _focus_object_key_for_span(
            self,
            text: str,
            focus_span: tuple[int, int],
        ) -> str | None:
            pe_key = self._section_key_for_offset(text, focus_span[0])
            if pe_key is None:
                return None
            spans = self._json_spans_for_text(text)
            triple = spans.get(pe_key)
            if triple is None:
                return None
            _entry_begin, value_start, value_end = triple
            if value_start >= value_end or value_start >= len(text):
                return None
            if text[value_start] != "{":
                return None
            for key_text, member_start, member_end in self._scan_object_members(
                text,
                value_start,
                value_end,
            ):
                if member_start == focus_span[0] and member_end == focus_span[1]:
                    return key_text
                if focus_span[0] >= member_start and focus_span[1] <= member_end:
                    return key_text
            return None

        def _jump_editor_to_span(self, start_off: int, end_off: int) -> None:
            editor = self.query_one("#json_editor", TextArea)
            start_off, end_off = self._focus_span_for_offsets(editor.text, start_off, end_off)
            sel_json = Selection(
                offset_to_location(editor.text, start_off),
                offset_to_location(editor.text, end_off),
            )
            self._peer_lock = True
            try:
                editor.selection = sel_json
                editor.focus()
                editor.scroll_cursor_visible(center=True)
            finally:
                self._peer_lock = False
            self._refresh_inspect_panel()

        def _sync_json_selection_from_der_selection(
            self,
            *,
            focus_editor: bool,
            source_der: TextArea | None = None,
        ) -> bool:
            editor = self.query_one("#json_editor", TextArea)
            der = source_der
            if der is None:
                focused = self._focused_text_area()
                if self._is_der_view(focused):
                    der = focused
            if der is None:
                der = self.query_one("#der_view", TextArea)
            rng = hex_selection_to_byte_range(der.text, der.selection)
            if rng is None:
                editor.remove_class("peer-sync")
                for der_widget in self._all_der_views():
                    der_widget.remove_class("peer-sync")
                return False
            spans = self._json_spans_for_text(editor.text)
            jpair = der_byte_range_to_json_editor_range(
                self._keys,
                spans,
                self._ranges_by_key,
                rng[0],
                rng[1],
            )
            if jpair is None:
                editor.remove_class("peer-sync")
                for der_widget in self._all_der_views():
                    der_widget.remove_class("peer-sync")
                return False
            j0, j1 = jpair
            sel_json = Selection(
                offset_to_location(editor.text, j0),
                offset_to_location(editor.text, j1),
            )
            self._peer_lock = True
            try:
                if editor.selection != sel_json:
                    editor.selection = sel_json
                if focus_editor:
                    editor.focus()
                    editor.scroll_cursor_visible(center=True)
                editor.remove_class("peer-sync")
                for der_widget in self._all_der_views():
                    if der_widget is not der and der_widget.selection != der.selection:
                        der_widget.selection = der.selection
                    der_widget.remove_class("peer-sync")
                editor.add_class("peer-sync")
                der.add_class("peer-sync")
            finally:
                self._peer_lock = False
            if self._left_inspect_mode == "selection":
                self._refresh_inspect_panel()
            return True

        def _selected_tree_span(self) -> tuple[int, int] | None:
            tree = self.query_one("#json_outline", Tree)
            node = tree.cursor_node
            if node is None:
                return None
            span = node.data
            if (
                isinstance(span, tuple)
                and len(span) == 2
                and all(isinstance(x, int) for x in span)
            ):
                return (int(span[0]), int(span[1]))
            return None

        def _preferred_selected_pe_key(self) -> str | None:
            editor = self.query_one("#json_editor", TextArea)
            tree_span = self._selected_tree_span()
            if tree_span is not None:
                tree_key = self._section_key_for_offset(editor.text, tree_span[0])
                if tree_key is not None:
                    return tree_key
            sel = editor.selection
            start_off = location_to_offset(editor.text, sel.start)
            return self._section_key_for_offset(editor.text, start_off)

        def _describe_insert_target(self, anchor_key: str | None, insert_after: bool) -> str:
            if anchor_key is None:
                return "before end PE"
            anchor_type = base_pe_type(anchor_key)
            if anchor_type == "end":
                return "before end PE"
            if insert_after:
                return f"after {anchor_key}"
            return f"before {anchor_key}"

        def _apply_document_edit(
            self,
            new_doc: dict[str, object],
            *,
            status_ok: str,
            failure_prefix: str,
        ) -> None:
            editor = self.query_one("#json_editor", TextArea)
            editor.text = document_to_pretty_json(new_doc)
            try:
                self._sync_json_der_from_editor(status_ok=status_ok)
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"{failure_prefix}: {exc}", remember=False)

        def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.control is not tree:
                return
            pe_key = self._preferred_selected_pe_key()
            if pe_key is None:
                self._set_status("Tree selection active.")
                return
            self._set_status(
                f"Tree PE {pe_key} selected — F3 add after · Ctrl+Shift+↑/↓ move · "
                "Ctrl+Shift+C copy · Ctrl+Shift+V paste after · Ctrl+Shift+B paste before"
            )

        def on_click(self, event: events.Click) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.widget is tree:
                if event.chain < 2:
                    return
                node = tree.cursor_node
                if node is None:
                    return
                span = node.data
                if (
                    isinstance(span, tuple)
                    and len(span) == 2
                    and all(isinstance(x, int) for x in span)
                ):
                    self._jump_editor_to_span(span[0], span[1])
                return
            editor = self.query_one("#json_editor", TextArea)
            if event.widget is editor:
                editor.focus()
                return
            if self._is_der_view(event.widget) is False:
                return
            der = event.widget
            der.focus()
            if event.chain < 2:
                return
            self._sync_json_selection_from_der_selection(
                focus_editor=True,
                source_der=der,
            )

        def _refresh_bottom_panel(self) -> None:
            self._refresh_inspect_panel()
            self._refresh_lint_panel()

        def _outline_label_for_value(self, key_text: str, value: object) -> str:
            if isinstance(value, dict):
                structural = set(_structural_data_keys(value))
                if structural == {_TAG_BYTES}:
                    raw = str(value.get(_TAG_BYTES, value.get("__ygg_saip_bytes__", "")))
                    compact = raw.replace(" ", "").replace("\n", "").replace("\t", "")
                    byte_len = len(compact) // 2 if len(compact) % 2 == 0 else len(compact)
                    hint = str(value.get(_TAG_LABEL, value.get(_LEGACY_TAG_LABEL, ""))).strip()
                    if hint != "":
                        return f"{key_text} [{byte_len}B] — {hint}"
                    return f"{key_text} [{byte_len}B]"
                if structural == {_TAG_TUPLE}:
                    inner = value.get(_TAG_TUPLE, value.get(_LEGACY_TAG_TUPLE))
                    if isinstance(inner, list) and len(inner) > 0:
                        return f"{key_text} ({inner[0]})"
                return f"{key_text} {{{len(value)}}}"
            if isinstance(value, list):
                return f"{key_text} [{len(value)}]"
            text = repr(value)
            if len(text) > 42:
                text = text[:39] + "..."
            return f"{key_text}: {text}"

        def _populate_json_outline(
            self,
            parent: object,
            value: object,
            text: str,
            start: int,
            end: int,
        ) -> None:
            if isinstance(value, dict):
                structural = set(_structural_data_keys(value))
                if structural == {_TAG_BYTES}:
                    return
                members = self._scan_object_members(text, start, end)
                if structural == {_TAG_TUPLE}:
                    inner = value.get(_TAG_TUPLE, value.get(_LEGACY_TAG_TUPLE))
                    if isinstance(inner, list):
                        tuple_span: tuple[int, int] | None = None
                        for key_name, value_start, value_end in members:
                            if _canonical_tag_key(key_name) == _TAG_TUPLE:
                                tuple_span = (value_start, value_end)
                                break
                        if tuple_span is None:
                            return
                        item_spans = self._scan_list_items(text, tuple_span[0], tuple_span[1])
                        for idx, item in enumerate(inner):
                            if idx >= len(item_spans):
                                break
                            label = f"[{idx}]"
                            if idx >= 1 and len(inner) > 0 and isinstance(inner[0], str):
                                label = f"{inner[0]} [{idx}]"
                            child = parent.add(
                                self._outline_label_for_value(label, item),
                                data=item_spans[idx],
                            )
                            self._populate_json_outline(
                                child,
                                item,
                                text,
                                item_spans[idx][0],
                                item_spans[idx][1],
                            )
                    return
                members_map = {key_name: (value_start, value_end) for key_name, value_start, value_end in members}
                for key, item in value.items():
                    key_text = str(key)
                    if key_text in (_TAG_LABEL, _LEGACY_TAG_LABEL):
                        continue
                    pair = members_map.get(key_text)
                    if pair is None:
                        continue
                    child = parent.add(
                        self._outline_label_for_value(key_text, item),
                        data=pair,
                    )
                    self._populate_json_outline(child, item, text, pair[0], pair[1])
                return
            if isinstance(value, list):
                item_spans = self._scan_list_items(text, start, end)
                for idx, item in enumerate(value):
                    if idx >= len(item_spans):
                        break
                    child = parent.add(
                        self._outline_label_for_value(f"[{idx}]", item),
                        data=item_spans[idx],
                    )
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        item_spans[idx][0],
                        item_spans[idx][1],
                    )

        def _refresh_json_outline(self) -> None:
            tree = self.query_one("#json_outline", Tree)
            editor = self.query_one("#json_editor", TextArea)
            tree.root.remove_children()
            text = str(editor.text or "")
            stripped = text.strip()
            if len(stripped) == 0:
                tree.root.add("JSON empty")
                tree.root.expand()
                return
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError as exc:
                tree.root.add(f"JSON parse error: {exc.msg}")
                tree.root.expand()
                return
            if isinstance(loaded, dict) is False:
                tree.root.add("Root must be a JSON object")
                tree.root.expand()
                return
            root_start = self._skip_json_ws(text, 0, len(text))
            root_end = _scan_json_value_end(text, root_start)
            sections_value = loaded.get("sections")
            if isinstance(sections_value, dict) is False:
                tree.root.add("No sections object")
                tree.root.expand()
                return
            sections_span: tuple[int, int] | None = None
            for key_name, value_start, value_end in self._scan_object_members(
                text,
                root_start,
                root_end,
            ):
                if key_name == "sections":
                    sections_span = (value_start, value_end)
                    break
            if sections_span is None:
                tree.root.add("Could not locate sections in JSON buffer")
                tree.root.expand()
                return
            pe_root = tree.root.add("ProfileElements", data=sections_span)
            self._populate_json_outline(
                pe_root,
                sections_value,
                text,
                sections_span[0],
                sections_span[1],
            )
            tree.root.expand()
            pe_root.expand()

        def _refresh_inspect_panel(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            sel = editor.selection
            start_off = location_to_offset(editor.text, sel.start)
            end_off = location_to_offset(editor.text, sel.end)
            focus_span = self._focus_span_for_offsets(editor.text, start_off, end_off)
            pe_key = self._section_key_for_offset(editor.text, focus_span[0])
            focus_key = self._focus_object_key_for_span(editor.text, focus_span)
            body = build_transcode_inspector_text(
                editor.text,
                start_off,
                end_off,
                left_mode=self._left_inspect_mode,
                fixed_span=focus_span if self._left_inspect_mode == "selection" else None,
                pe_key_hint=pe_key,
                focus_key_hint=focus_key,
            )
            for log in self._all_inspect_logs():
                log.clear()
                for line in body.splitlines():
                    log.write(Text(line))

        def _refresh_lint_panel(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            logs = self._all_lint_logs()
            for log in logs:
                log.clear()
            if self._validation_issue is not None:
                for log in logs:
                    log.write(
                        Text.from_markup(
                            "[bold red]Validation error[/bold red] — "
                            f"[dim]{escape(self._validation_issue.summary)}[/dim]"
                        )
                    )
                return
            outcome = lint_profile_json_buffer(editor.text, profile_label, strict=False)
            if outcome.parse_error is not None:
                for log in logs:
                    log.write(
                        Text.from_markup(
                            "[bold red]JSON parse error[/bold red] — fix syntax to run lint rules.\n"
                            f"[dim]{escape(str(outcome.parse_error))}[/dim]"
                        )
                    )
                return
            report = outcome.report
            if report is None:
                return
            payload = report.to_dict()
            summary = payload.get("summary", {})
            fail_n = int(summary.get("fail", 0))
            warn_n = int(summary.get("warn", 0))
            info_n = int(summary.get("info", 0))
            score = int(payload.get("score", 0))
            for log in logs:
                log.write(
                    Text.from_markup(
                        "[bold]Live lint[/bold] (same rules as [cyan]LINT[/cyan]; "
                        "[dim]saip-tool check omitted[/dim]) — "
                        f"score [bold]{score}[/]/100 · "
                        f"[red]FAIL {fail_n}[/] · [yellow]WARN {warn_n}[/] · "
                        f"[bright_blue]INFO {info_n}[/]"
                    )
                )
                shown = 0
                for finding in report.findings:
                    if finding.severity == "PASS":
                        continue
                    line = format_finding_rich_markup(
                        finding.code,
                        finding.severity,
                        finding.path,
                        finding.message,
                    )
                    log.write(Text.from_markup(line))
                    shown += 1
                    if shown >= 120:
                        log.write(Text.from_markup("[dim]… truncated at 120 non-PASS rows[/dim]"))
                        break
                if shown == 0:
                    log.write(Text.from_markup("[green]No FAIL/WARN/INFO findings.[/green]"))

        def _sync_json_der_from_editor(self, *, status_ok: str) -> None:
            editor = self.query_one("#json_editor", TextArea)
            der_widgets = self._all_der_views()
            stripped = str(editor.text or "").strip()
            if len(stripped) == 0:
                raise ValueError("JSON buffer is empty.")

            transcode_json_path.parent.mkdir(parents=True, exist_ok=True)
            transcode_der_path.parent.mkdir(parents=True, exist_ok=True)

            transcode_json_path.write_text(stripped + "\n", encoding="utf-8")
            disk_json_text = transcode_json_path.read_text(encoding="utf-8").strip()
            pre_loaded = json.loads(disk_json_text)
            if isinstance(pre_loaded, dict) is False:
                raise ValueError("Root JSON value must be an object.")

            doc = dejsonify_document(pre_loaded)
            der = encode_der_from_document(doc, workspace_root)
            pes_round = decode_profile_sequence_or_raise(der)
            doc_round = build_decoded_document_from_sequence(
                pes_round,
                intro_lines=[
                    (
                        f"Re-encoded {len(der)} bytes DER, "
                        f"{len(pes_round.pe_list)} profile elements"
                    ),
                ],
            )
            post_tagged = jsonify_document(doc_round)
            reapply_transcode_editor_placeholders(pre_loaded, post_tagged)
            pretty = json.dumps(post_tagged, indent=2, ensure_ascii=False) + "\n"

            transcode_json_path.write_text(pretty, encoding="utf-8")
            transcode_der_path.write_bytes(der)
            transcode_txt_path.write_text(der.hex().upper() + "\n", encoding="utf-8")

            editor.text = transcode_json_path.read_text(encoding="utf-8")
            hex_text = format_der_hex(der)
            for der_widget in der_widgets:
                der_widget.text = hex_text
            self._pes = pes_round
            self._raw_der = der
            self._json_snapshot = pretty
            self._hex_snapshot = hex_text
            self._rebuild_peer_map()
            self._refresh_json_outline()
            editor.remove_class("flash-ok")
            editor.remove_class("peer-sync")
            editor.add_class("flash-ok")
            for der_widget in der_widgets:
                der_widget.remove_class("flash-ok")
                der_widget.remove_class("peer-sync")
                der_widget.add_class("flash-ok")

            def clear_flash() -> None:
                try:
                    editor.remove_class("flash-ok")
                    for der_widget in self._all_der_views():
                        der_widget.remove_class("flash-ok")
                except Exception:
                    pass

            self.set_timer(2.5, clear_flash)
            self._set_validation_issue(None)
            self._set_status(status_ok)
            self._refresh_bottom_panel()

        def _rebuild_peer_map(self) -> None:
            self._keys = ordered_section_keys_from_pes(self._pes)
            self._byte_ranges = pe_byte_ranges_from_raw_der(self._raw_der, self._pes)
            self._ranges_by_key = {key: (a, b) for key, a, b in self._byte_ranges}
            self._json_spans = build_json_entry_spans(self._json_snapshot, self._keys)

        def _json_spans_for_text(self, editor_text: str) -> dict[str, tuple[int, int, int]]:
            if editor_text == self._json_snapshot:
                return self._json_spans
            try:
                parse_editor_json(editor_text)
            except Exception:
                return self._json_spans
            return build_json_entry_spans(editor_text, self._keys)

        def on_text_area_selection_changed(self, event: TextArea.SelectionChanged) -> None:
            if self._peer_lock:
                return
            editor = self.query_one("#json_editor", TextArea)
            self._peer_lock = True
            try:
                if event.text_area is editor:
                    spans = self._json_spans_for_text(editor.text)
                    sel = editor.selection
                    start_off = location_to_offset(editor.text, sel.start)
                    end_off = location_to_offset(editor.text, sel.end)
                    effective_empty = sel.is_empty
                    rng = json_editor_range_to_der_byte_range(
                        self._keys,
                        spans,
                        self._ranges_by_key,
                        start_off,
                        end_off,
                        empty_selection=effective_empty,
                    )
                    if rng is None:
                        editor.remove_class("peer-sync")
                        for der_widget in self._all_der_views():
                            der_widget.remove_class("peer-sync")
                        return
                    a, b = rng
                    for der_widget in self._all_der_views():
                        sel_hex = byte_range_to_hex_selection(der_widget.text, a, b)
                        if der_widget.selection != sel_hex:
                            der_widget.selection = sel_hex
                    editor.remove_class("peer-sync")
                    for der_widget in self._all_der_views():
                        der_widget.remove_class("peer-sync")
                    editor.add_class("peer-sync")
                    for der_widget in self._all_der_views():
                        der_widget.add_class("peer-sync")
                elif self._is_der_view(event.text_area):
                    editor.remove_class("peer-sync")
                    for der_widget in self._all_der_views():
                        if der_widget is event.text_area:
                            continue
                        der_widget.remove_class("peer-sync")
            finally:
                self._peer_lock = False
                if self._left_inspect_mode == "selection":
                    self._refresh_inspect_panel()

        def action_save_refresh(self) -> None:
            try:
                self._sync_json_der_from_editor(
                    status_ok=build_save_status("Save OK"),
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Save failed: {exc}", remember=False)

        def action_add_pe_block(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            try:
                doc = parse_editor_json(editor.text)
                pes_probe = build_profile_sequence_from_document(doc, workspace_root)
                blocked = menu_ids_blocked_if_present(pes_probe)
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Add PE: fix JSON first: {exc}", remember=False)
                return
            anchor_key = self._preferred_selected_pe_key()
            insert_after = True
            if anchor_key is not None and base_pe_type(anchor_key) == "end":
                insert_after = False
            self._pending_insert_anchor_key = anchor_key
            self._pending_insert_after = insert_after
            target_hint = self._describe_insert_target(anchor_key, insert_after)
            self.push_screen(
                PeBlockPicker(blocked, target_hint),
                callback=self._on_pe_block_chosen,
            )

        def _on_pe_block_chosen(self, choice: str | None) -> None:
            if choice is None:
                self._pending_insert_anchor_key = None
                self._pending_insert_after = True
                return
            editor = self.query_one("#json_editor", TextArea)
            try:
                doc = parse_editor_json(editor.text)
                new_doc = insert_blank_pe_for_menu_id(
                    doc,
                    workspace_root,
                    menu_id=choice,
                    anchor_key=self._pending_insert_anchor_key,
                    insert_after=self._pending_insert_after,
                )
            except Exception as exc:
                self._pending_insert_anchor_key = None
                self._pending_insert_after = True
                self._refresh_validation_feedback()
                self._set_status(f"Add PE failed: {exc}", remember=False)
                return
            target_hint = self._describe_insert_target(
                self._pending_insert_anchor_key,
                self._pending_insert_after,
            )
            self._pending_insert_anchor_key = None
            self._pending_insert_after = True
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Inserted {choice!r} {target_hint}"),
                failure_prefix="Re-encode after add failed",
            )

        def action_move_selected_pe_up(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            try:
                doc = parse_editor_json(editor.text)
                pe_key = self._preferred_selected_pe_key()
                if pe_key is None:
                    raise ValueError("select a profile element in the tree or editor first")
                new_doc = move_pe_in_document(
                    doc,
                    workspace_root,
                    section_key=pe_key,
                    direction="up",
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Move PE up failed: {exc}", remember=False)
                return
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Moved {pe_key} up"),
                failure_prefix="Re-encode after move failed",
            )

        def action_move_selected_pe_down(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            try:
                doc = parse_editor_json(editor.text)
                pe_key = self._preferred_selected_pe_key()
                if pe_key is None:
                    raise ValueError("select a profile element in the tree or editor first")
                new_doc = move_pe_in_document(
                    doc,
                    workspace_root,
                    section_key=pe_key,
                    direction="down",
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Move PE down failed: {exc}", remember=False)
                return
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Moved {pe_key} down"),
                failure_prefix="Re-encode after move failed",
            )

        def action_copy_selected_pe(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            try:
                doc = parse_editor_json(editor.text)
                pe_key = self._preferred_selected_pe_key()
                if pe_key is None:
                    raise ValueError("select a profile element in the tree or editor first")
                self._pe_clipboard = copy_pe_snapshot(doc, section_key=pe_key)
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Copy PE failed: {exc}", remember=False)
                return
            self._set_status(f"Copied PE {pe_key} into the TUI clipboard.")

        def action_paste_selected_pe_after(self) -> None:
            self._paste_selected_pe(insert_after=True)

        def action_paste_selected_pe_before(self) -> None:
            self._paste_selected_pe(insert_after=False)

        def _paste_selected_pe(self, *, insert_after: bool) -> None:
            editor = self.query_one("#json_editor", TextArea)
            try:
                if self._pe_clipboard is None:
                    raise ValueError("clipboard is empty")
                doc = parse_editor_json(editor.text)
                anchor_key = self._preferred_selected_pe_key()
                new_doc = paste_pe_snapshot(
                    doc,
                    workspace_root,
                    snapshot=self._pe_clipboard,
                    anchor_key=anchor_key,
                    insert_after=insert_after,
                )
            except Exception as exc:
                where_text = "after" if insert_after else "before"
                self._refresh_validation_feedback()
                self._set_status(f"Paste PE {where_text} failed: {exc}", remember=False)
                return
            target_hint = self._describe_insert_target(anchor_key, insert_after)
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Pasted copied PE {target_hint}"),
                failure_prefix="Re-encode after paste failed",
            )

        def action_quit(self) -> None:
            self.exit()

    SaipTranscodeApp().run(inline=False)
