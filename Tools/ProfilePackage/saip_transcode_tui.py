"""
Split-pane Textual UI for SAIP decoded JSON editing with DER hex preview.

Imported only from the TRANSCODE-TUI shell command so Textual stays off the
default CLI import path.

JSON uses pySim ProfileElement.decoded field names (asn1tools structures) plus
``__ygg_saip_bytes__`` / ``__ygg_saip_tuple__`` tags for JSON round-trip.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .saip_tool import SaipToolBridge


def run_saip_transcode_tui(bridge: SaipToolBridge) -> None:
    from dataclasses import dataclass
    import json

    from textual import events
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.document._document import Selection
    from textual.screen import ModalScreen
    from rich.markup import escape
    from rich.text import Text
    from textual.widgets import OptionList, RichLog, Static, TextArea, Tree
    from textual.widgets.option_list import Option

    from .saip_json_codec import ensure_workspace_pysim_on_path

    ensure_workspace_pysim_on_path(bridge.workspace_root)

    from pySim.esim.saip import ProfileElementSequence

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
        load_split_size_prefs,
        load_transcode_tui_prefs,
        next_theme_in_cycle,
        persist_split_sizes,
        persist_theme,
    )

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

    @dataclass
    class ValidationIssue:
        summary: str

    def decode_profile_sequence_or_raise(
        raw_profile_der: bytes,
        *,
        prefix: str = "Profile ASN1 is not valid.",
    ):
        try:
            return ProfileElementSequence.from_der(raw_profile_der)
        except Exception as error:
            detail = describe_exception_chain(error)
            if len(detail) > 0:
                raise ValueError(f"{prefix} Cause: {detail}") from error
            raise ValueError(prefix) from error

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
            )
        except Exception as error:
            return ValidationIssue(describe_exception_chain(error))
        return None

    resolved_input = bridge.resolve_input_path(str(bridge.get_input_file()), must_exist=True)
    prepared_input = bridge._prepare_input_for_tool(resolved_input)
    raw_der = prepared_input.read_bytes()
    pes_loaded = decode_profile_sequence_or_raise(raw_der)
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
    transcode_json_path, transcode_der_path = bridge.resolve_transcode_sidecar_paths(
        resolved_input
    )
    transcode_json_display = bridge.display_path(transcode_json_path)
    transcode_der_display = bridge.display_path(transcode_der_path)
    transcode_dir_display = bridge.display_path(transcode_json_path.parent)

    def build_save_status(prefix: str) -> str:
        return (
            f"{prefix} - wrote {transcode_json_display} + {transcode_der_display}, "
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
            "Ctrl+Shift+C/V copy/paste PE · F4 inspect left · F7 theme · Ctrl+Q quit"
        )

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
        #der_view {
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
        #json_editor.invalid-buffer {
            border: tall #FF6B6B;
            color: #FFB4B4;
        }
        #der_view.invalid-buffer {
            border: tall #FF6B6B;
            color: #FFB4B4;
        }
        #json_editor.peer-sync {
            border: tall $accent;
        }
        #der_view.peer-sync {
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
        """

        BINDINGS = [
            Binding("ctrl+s", "save_refresh", "Save / re-encode", priority=True),
            Binding("f2", "save_refresh", "Save / re-encode", priority=True),
            Binding("f3", "add_pe_block", "Add PE", priority=True),
            Binding("ctrl+shift+up", "move_selected_pe_up", "Move PE up", priority=True),
            Binding("ctrl+shift+down", "move_selected_pe_down", "Move PE down", priority=True),
            Binding("ctrl+shift+c", "copy_selected_pe", "Copy PE", priority=True),
            Binding("ctrl+shift+v", "paste_selected_pe_after", "Paste PE after", priority=True),
            Binding("ctrl+shift+b", "paste_selected_pe_before", "Paste PE before", priority=True),
            Binding("f4", "toggle_inspect_left_mode", "Inspect left mode", priority=True),
            Binding("f7", "cycle_theme", "Cycle theme", priority=True),
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
            super().__init__()

        def compose(self) -> ComposeResult:
            with Vertical(id="chrome"):
                yield Static(
                    "SAIP JSON↔DER · Save Ctrl+S/F2 · Add F3 · Inspect F4 · Theme F7 · Quit Ctrl+Q",
                    id="chrome_title",
                )
                with Vertical(id="upper"):
                    with Horizontal(id="split_row"):
                        with Vertical(id="json_col"):
                            yield Static(
                                (
                                    f"JSON editor · save dir {transcode_dir_display} · "
                                    f"writes {transcode_json_path.name} + {transcode_der_path.name} · "
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
                                (
                                    "DER hex · follows selected JSON value · "
                                    "double-click DER to jump back"
                                ),
                                classes="pane-caption",
                            )
                            yield TextArea(
                                initial_hex,
                                id="der_view",
                                language=None,
                                soft_wrap=False,
                                read_only=True,
                                show_line_numbers=True,
                            )
                    yield DragHandle("", id="bottom_handle", classes="drag-handle")
                    with Horizontal(id="bottom_row"):
                        with Vertical(id="inspect_col"):
                            yield Static(
                                "Left: selection decode (SCP03 + pySim)",
                                id="inspect_col_caption",
                                classes="pane-caption",
                            )
                            yield RichLog(
                                id="inspect_log",
                                auto_scroll=True,
                                wrap=True,
                                max_lines=320,
                                highlight=False,
                            )
                        yield DragHandle("", id="inspect_handle", classes="drag-handle")
                        with Vertical(id="lint_col"):
                            yield Static(
                                "Right: profile lint (live)",
                                id="lint_col_caption",
                                classes="pane-caption",
                            )
                            yield RichLog(
                                id="lint_log",
                                auto_scroll=True,
                                wrap=True,
                                max_lines=320,
                                highlight=False,
                            )
                yield Static("", id="status_line")

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
            self._set_status(
                f"Transcode save dir: {transcode_dir_display} "
                f"({transcode_json_path.name} + {transcode_der_path.name})"
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
            der_widget = self.query_one("#der_view", TextArea)
            stat = self.query_one("#status_line", Static)
            if issue is None:
                editor.remove_class("invalid-buffer")
                der_widget.remove_class("invalid-buffer")
                stat.remove_class("error-state")
                stat.update(self._status_base_text)
                return
            editor.add_class("invalid-buffer")
            der_widget.remove_class("invalid-buffer")
            stat.add_class("error-state")
            stat.update(issue.summary)

        def _refresh_validation_feedback(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            self._set_validation_issue(validate_editor_buffer(editor.text))

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
                self._left_inspect_mode = "profile_scp03"
            else:
                self._left_inspect_mode = "selection"
            cap = self.query_one("#inspect_col_caption", Static)
            if self._left_inspect_mode == "selection":
                cap.update("Left: selection decode (SCP03 + pySim)")
            else:
                cap.update("Left: whole profile SCP03 decode (all PEs)")
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
            except Exception:
                return
            split_width = int(split_row.size.width)
            if self._json_col_width > 0 and split_width > 0:
                max_json_col_width = max(24, split_width - 30)
                min_json_col_width = min(48, max_json_col_width)
                self._json_col_width = max(
                    min_json_col_width,
                    min(max_json_col_width, self._json_col_width),
                )
                json_col.styles.width = self._json_col_width
            json_outline.styles.width = self._json_outline_width
            bottom_row.styles.height = self._bottom_height
            bottom_width = bottom_row.size.width
            if self._inspect_width <= 0 and bottom_width > 0:
                self._inspect_width = max(24, bottom_width // 2)
            if self._inspect_width > 0:
                inspect_col.styles.width = self._inspect_width

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

        def _sync_json_selection_from_der_selection(self, *, focus_editor: bool) -> bool:
            editor = self.query_one("#json_editor", TextArea)
            der = self.query_one("#der_view", TextArea)
            rng = hex_selection_to_byte_range(der.text, der.selection)
            if rng is None:
                editor.remove_class("peer-sync")
                der.remove_class("peer-sync")
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
                der.remove_class("peer-sync")
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
                der.remove_class("peer-sync")
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
            der = self.query_one("#der_view", TextArea)
            if event.widget is not der:
                return
            if event.chain < 2:
                return
            self._sync_json_selection_from_der_selection(focus_editor=True)

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
            log = self.query_one("#inspect_log", RichLog)
            log.clear()
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
            for line in body.splitlines():
                log.write(Text(line))

        def _refresh_lint_panel(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            log = self.query_one("#lint_log", RichLog)
            log.clear()
            if self._validation_issue is not None:
                log.write(
                    Text.from_markup(
                        "[bold red]Validation error[/bold red] — "
                        f"[dim]{escape(self._validation_issue.summary)}[/dim]"
                    )
                )
                return
            outcome = lint_profile_json_buffer(editor.text, profile_label, strict=False)
            if outcome.parse_error is not None:
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
            der_widget = self.query_one("#der_view", TextArea)
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

            editor.text = transcode_json_path.read_text(encoding="utf-8")
            hex_text = format_der_hex(der)
            der_widget.text = hex_text
            self._pes = pes_round
            self._raw_der = der
            self._json_snapshot = pretty
            self._hex_snapshot = hex_text
            self._rebuild_peer_map()
            self._refresh_json_outline()
            editor.remove_class("flash-ok")
            der_widget.remove_class("flash-ok")
            editor.remove_class("peer-sync")
            der_widget.remove_class("peer-sync")
            editor.add_class("flash-ok")
            der_widget.add_class("flash-ok")

            def clear_flash() -> None:
                try:
                    editor.remove_class("flash-ok")
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
            der = self.query_one("#der_view", TextArea)
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
                        der.remove_class("peer-sync")
                        return
                    a, b = rng
                    sel_hex = byte_range_to_hex_selection(der.text, a, b)
                    if der.selection != sel_hex:
                        der.selection = sel_hex
                    editor.remove_class("peer-sync")
                    der.remove_class("peer-sync")
                    editor.add_class("peer-sync")
                    der.add_class("peer-sync")
                elif event.text_area is der:
                    editor.remove_class("peer-sync")
                    der.remove_class("peer-sync")
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
