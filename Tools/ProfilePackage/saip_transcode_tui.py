"""
Split-pane Textual UI for SAIP decoded JSON editing with DER hex preview.

Imported only from the TRANSCODE-TUI shell command so Textual stays off the
default CLI import path.

JSON uses pySim ProfileElement.decoded field names (asn1tools structures) plus
``__ygg_saip_bytes__`` / ``__ygg_saip_tuple__`` tags for JSON round-trip.
"""

from __future__ import annotations

import os
import pathlib
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
    import copy
    from dataclasses import dataclass
    import json

    resolved_input = bridge.resolve_input_path(str(bridge.get_input_file()), must_exist=True)
    prepared_input = bridge._prepare_input_for_tool(resolved_input)
    raw_der = prepared_input.read_bytes()

    from .saip_json_codec import ensure_workspace_pysim_on_path

    ensure_workspace_pysim_on_path(
        bridge.workspace_root,
        getattr(bridge, "bundle_root", None),
    )

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

    @dataclass
    class OutlineSelectionData:
        span: tuple[int, int]
        inspect_subtree: object | None = None
        inspect_text: str | None = None

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
        file_add_override_defaults,
        gfm_root_bootstrap_defaults,
        insert_blank_pe_for_menu_id,
        insert_blank_file_for_pename,
        iter_option_list_specs,
        list_addable_file_rows,
        menu_ids_blocked_if_present,
        move_pe_in_document,
        paste_pe_snapshot,
        remove_pe_from_document,
    )
    from .saip_tui_lint import (
        TuiLintOutcome,
        format_finding_rich_markup,
        lint_profile_json_buffer,
    )

    from .saip_json_codec import (
        _TAG_BYTES,
        _TAG_LABEL,
        _TAG_TUPLE,
        _canonical_tag_key,
        _LEGACY_TAG_BYTES,
        _LEGACY_TAG_LABEL,
        _LEGACY_TAG_TUPLE,
        _structural_data_keys,
        _token_ctx_from_loaded_document,
        TokenExpansionContext,
        build_decoded_document_from_sequence,
        build_profile_sequence_from_document,
        base_pe_type,
        dejsonify_document,
        dejsonify_saip_value,
        document_to_pretty_json,
        encode_der_from_document,
        format_der_hex,
        humanize_saip_display_name,
        jsonify_document,
        parse_editor_json,
        reapply_transcode_editor_placeholders,
    )
    from .saip_asn1_decode import (
        _decode_file_descriptor,
        _decode_file_path,
        _fid_name_from_hex,
        _hex_from_tagged_bytes,
        parent_token_from_file_path_hex,
    )
    from .saip_decoded_edit import (
        build_decoded_value_editor_model,
        build_decoded_value_raw_hex_model,
        build_decoded_value_readonly_view,
        build_decoded_value_roundtrip_model,
        encode_decoded_value_editor_payload,
    )
    from .saip_token_sidecar import (
        TokenSidecarError,
        count_token_references,
        find_unmigrated_length_candidates,
        parse_token_value_argument,
        read_token_defs_from_file,
        remove_token_definition,
        rename_token_in_template,
        retokenise_template_lengths,
        set_token_definition,
    )
    from .saip_transcode_tui_tokens import (
        build_token_rows,
        format_token_row,
        placeholder_style_from_document,
        summarize_token_counts,
    )
    from .saip_transcode_tui_preview import (
        find_placeholder_locations,
        format_placeholder_hud,
        format_preview_banner,
        format_template_mode_sub_title,
        render_resolved_preview_json,
    )
    from .saip_transcode_inspect import (
        build_template_defaults_report,
        build_transcode_inspector_text,
    )
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
        scan_json_object_member_entries,
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
    from textual.message import Message
    from textual.screen import ModalScreen
    from rich.markup import escape
    from rich.text import Text
    from textual.widgets import (
        Button,
        Checkbox,
        ContentSwitcher,
        Input,
        OptionList,
        RichLog,
        SelectionList,
        Static,
        TextArea,
        Tree,
    )
    from textual.widgets.option_list import Option
    from textual.widgets.tree import TreeNode

    STRUCTURED_DECODED_EDITOR_KINDS = {
        "arr_reference",
        "byte_count",
        "file_id",
        "fill_file_offset",
        "lcsi_state",
        "short_efid",
    }
    _FILESYSTEM_PE_TYPES = frozenset({
        "mf",
        "telecom",
        "cd",
        "phonebook",
        "gsm-access",
        "df-5gs",
        "eap",
        "df-saip",
        "df-snpn",
        "df-5gprose",
        "usim",
        "opt-usim",
        "isim",
        "opt-isim",
        "genericFileManagement",
    })
    SEARCH_MATCH_STYLE = "bold #2E3440 on #EBCB8B"
    SEARCH_ACTIVE_MATCH_STYLE = "bold underline #2E3440 on #D08770"

    def _search_query_tokens(query_text: str) -> list[str]:
        tokens: list[str] = []
        for raw_token in str(query_text or "").strip().split():
            token = str(raw_token or "").strip().lower()
            if len(token) == 0:
                continue
            if token in tokens:
                continue
            tokens.append(token)
        return tokens

    def _search_highlight_ranges(text: str, query_text: str) -> list[tuple[int, int]]:
        plain_text = str(text or "")
        lowered_text = plain_text.lower()
        ranges: list[tuple[int, int]] = []
        for token in _search_query_tokens(query_text):
            start_index = 0
            while True:
                match_index = lowered_text.find(token, start_index)
                if match_index < 0:
                    break
                ranges.append((match_index, match_index + len(token)))
                start_index = match_index + len(token)
        if len(ranges) <= 1:
            return ranges
        ranges.sort()
        merged: list[tuple[int, int]] = [ranges[0]]
        for start_index, end_index in ranges[1:]:
            last_start, last_end = merged[-1]
            if start_index <= last_end:
                merged[-1] = (last_start, max(last_end, end_index))
                continue
            merged.append((start_index, end_index))
        return merged

    def _highlight_query_text(text: str, query_text: str, *, active: bool = False) -> Text:
        highlighted = Text(str(text or ""))
        match_style = SEARCH_ACTIVE_MATCH_STYLE if active else SEARCH_MATCH_STYLE
        for start_index, end_index in _search_highlight_ranges(highlighted.plain, query_text):
            highlighted.stylize(match_style, start_index, end_index)
        return highlighted

    def build_save_status(prefix: str) -> str:
        return (
            f"{prefix} - wrote {transcode_json_display} + {transcode_der_display} + "
            f"{transcode_txt_display}, "
            "reloaded JSON from disk (green border ~2.5s)"
        )

    def build_keybind_help_text() -> str:
        sections: list[tuple[str, list[tuple[str, str]]]] = [
            (
                "General",
                [
                    ("F1", "Show this shortcut list."),
                    ("Ctrl+S / F2", "Save, re-encode, and reload JSON/DER sidecars."),
                    ("Ctrl+Q", "Quit the TUI."),
                ],
            ),
            (
                "Tree And PE Editing",
                [
                    ("Ctrl+F", "Focus the outline tree search."),
                    ("Ctrl+T", "Open the tree action menu for the selected node."),
                    ("Ctrl+A", "Add a file under the selected filesystem PE/DF."),
                    ("F3", "Open the profile-element insert picker."),
                    ("F11 / F12", "Insert a PE after or before the selected PE."),
                    ("Ctrl+Up/Down", "Move the selected PE up or down."),
                    ("Ctrl+D", "Remove the selected PE."),
                    ("Ctrl+Y", "Copy the selected PE into the TUI clipboard."),
                    ("Ctrl+P / Ctrl+B", "Paste the copied PE after or before the selection."),
                    ("Ctrl+L", "Run lint on the current buffer."),
                    ("Ctrl+K", "Open the token manager (add/rename/set/remove placeholder defs)."),
                    ("Ctrl+R", "Toggle the resolved preview (read-only view with placeholders expanded)."),
                    ("Ctrl+Alt+N / P", "Jump cursor to the next / previous placeholder."),
                ],
            ),
            (
                "Token Manager",
                [
                    ("A", "Add a new token."),
                    ("V / E / Enter", "Edit the value of the selected token."),
                    ("R", "Rename the selected token (optionally rewrites refs)."),
                    ("D", "Delete the selected token."),
                    ("Ctrl+S", "Apply token changes and re-encode the buffer."),
                    ("Esc", "Close the token manager (confirms if there are unsaved edits)."),
                ],
            ),
            (
                "Views And Panes",
                [
                    ("F4", "Toggle the left inspect mode."),
                    ("F5", "Cycle the right pane."),
                    ("F6", "Show or hide the outline pane."),
                    ("F7", "Cycle the color theme."),
                    ("F8 / F9", "Cycle the bottom-left or bottom-right pane."),
                    ("F10", "Open the pane layout menu."),
                ],
            ),
            (
                "Mouse",
                [
                    ("Tree double-click", "Jump the JSON editor to the selected outline node."),
                    ("Tree right-click", "Open the tree action menu when the terminal passes mouse secondary-clicks."),
                    ("DER double-click", "Jump back from DER to the matching JSON selection."),
                    ("Split handles drag", "Resize the outline, pane widths, and bottom panel height."),
                ],
            ),
        ]
        lines: list[str] = [
            "Shortcut Reference",
            "",
        ]
        for heading, rows in sections:
            lines.append(heading)
            for key_text, description in rows:
                lines.append(f"  {key_text:<26} {description}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

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

    class PeInsertTargetPicker(ModalScreen[str | None]):
        """Choose where a new profile element will be inserted."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(self, anchor_key: str | None) -> None:
            super().__init__()
            self._anchor_key = anchor_key

        def _build_options(self) -> list[Option]:
            options: list[Option] = []
            anchor_key = str(self._anchor_key or "").strip()
            if len(anchor_key) == 0:
                options.append(Option("Insert before end PE", id="before_end"))
                return options

            anchor_type = base_pe_type(anchor_key)
            if anchor_type == "end":
                options.append(Option("Insert before end PE", id="before_end"))
                return options

            options.append(Option(f"Insert after {anchor_key}", id="after_anchor"))
            if anchor_type != "header":
                options.append(Option(f"Insert before {anchor_key}", id="before_anchor"))
            options.append(Option("Insert before end PE", id="before_end"))
            return options

        def compose(self) -> ComposeResult:
            with Vertical(id="pe_insert_target_shell"):
                yield Static("Choose insertion target for new PE")
                anchor_key = str(self._anchor_key or "").strip()
                if len(anchor_key) > 0:
                    yield Static(f"[dim]Current selection: {anchor_key}[/dim]")
                else:
                    yield Static("[dim]No PE selected. Default target is before end.[/dim]")
                yield Static("[dim]Enter confirm · Esc close[/dim]")
                yield OptionList(*self._build_options(), id="pe_insert_target_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#pe_insert_target_opts", OptionList)
            widget.focus()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            oid = event.option_id
            if oid is None:
                self.dismiss(None)
                return
            self.dismiss(oid)

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class PeRemoveConfirmPicker(ModalScreen[str | None]):
        """Confirm removal of the currently selected profile element."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(self, pe_key: str) -> None:
            super().__init__()
            self._pe_key = str(pe_key or "").strip()

        def compose(self) -> ComposeResult:
            options = [
                Option("Keep selected PE", id="_cancel"),
                Option(f"Remove {self._pe_key}", id="confirm_remove"),
            ]
            with Vertical(id="pe_remove_confirm_shell"):
                yield Static("Remove selected profile element?")
                if len(self._pe_key) > 0:
                    yield Static(f"[dim]Selected PE: {self._pe_key}[/dim]")
                yield Static("[dim]This updates the JSON and re-encodes the profile. Enter confirm · Esc close[/dim]")
                yield OptionList(*options, id="pe_remove_confirm_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#pe_remove_confirm_opts", OptionList)
            widget.focus()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            oid = event.option_id
            if oid is None:
                self.dismiss(None)
                return
            self.dismiss(oid)

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class PeFilePicker(ModalScreen[str | None]):
        """Choose a context-aware file to add to the selected filesystem PE."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(
            self,
            rows: list[tuple[str, str, str | None]],
            *,
            pe_key: str,
            target_label: str,
        ) -> None:
            super().__init__()
            self._rows = list(rows)
            self._pe_key = str(pe_key or "").strip()
            self._target_label = str(target_label or "").strip()

        def compose(self) -> ComposeResult:
            options: list[Option] = [Option("— Cancel —", id="_cancel")]
            for option_id, title, hint in self._rows:
                prompt = str(title or "").strip()
                hint_text = str(hint or "").strip()
                if len(hint_text) > 0:
                    prompt = f"{prompt}  [dim]{hint_text}[/dim]"
                options.append(Option(prompt, id=option_id))
            with Vertical(id="pe_file_picker_shell"):
                yield Static("Add file inside selected profile element")
                if len(self._pe_key) > 0:
                    yield Static(f"[dim]Selected PE: {self._pe_key}[/dim]")
                if len(self._target_label) > 0:
                    yield Static(f"[dim]Target directory: {self._target_label}[/dim]")
                yield Static("[dim]Only missing files valid for this context are shown. Enter confirm · Esc close[/dim]")
                yield OptionList(*options, id="pe_file_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#pe_file_opts", OptionList)
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

    class TreeContextActionPicker(ModalScreen[str | None]):
        """Choose an action for the currently selected outline node."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(
            self,
            rows: list[tuple[str, str, str | None, bool]],
            *,
            pe_key: str,
            node_label: str,
        ) -> None:
            super().__init__()
            self._rows = list(rows)
            self._pe_key = str(pe_key or "").strip()
            self._node_label = str(node_label or "").strip()

        def compose(self) -> ComposeResult:
            options: list[Option] = [Option("— Cancel —", id="_cancel")]
            for option_id, title, hint, disabled in self._rows:
                prompt = str(title or "").strip()
                hint_text = str(hint or "").strip()
                if len(hint_text) > 0:
                    prompt = f"{prompt}  [dim]{hint_text}[/dim]"
                options.append(Option(prompt, id=option_id, disabled=disabled))
            with Vertical(id="tree_context_picker_shell"):
                yield Static("Tree actions")
                if len(self._pe_key) > 0:
                    yield Static(f"[dim]Selected PE: {self._pe_key}[/dim]")
                if len(self._node_label) > 0:
                    yield Static(f"[dim]Selected node: {self._node_label}[/dim]")
                yield Static("[dim]Right-click opens this menu for the current tree node. Enter confirm · Esc close[/dim]")
                yield OptionList(*options, id="tree_context_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#tree_context_opts", OptionList)
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

    class AdfBootstrapPicker(ModalScreen[dict[str, str] | None]):
        """Override ADF root bootstrap values before MF-root one-shot creation."""

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
            Binding("ctrl+enter", "submit_form", "Apply", show=False, priority=True),
        ]

        def __init__(self, bootstrap_defaults: dict[str, str], *, target_label: str) -> None:
            super().__init__()
            self._defaults = dict(bootstrap_defaults)
            self._target_label = str(target_label or "").strip()

        def compose(self) -> ComposeResult:
            root_name = str(self._defaults.get("root_name", "ADF") or "ADF")
            aid_prefix = str(self._defaults.get("aid_prefix", "") or "").strip()
            with Vertical(id="adf_bootstrap_shell"):
                yield Static(f"ADF bootstrap values for {root_name}")
                if len(self._target_label) > 0:
                    yield Static(f"[dim]Requested target: {self._target_label}[/dim]")
                if len(aid_prefix) > 0:
                    yield Static(
                        f"[dim]AID must start with {aid_prefix} so guided add-file can keep recognizing this ADF.[/dim]"
                    )
                yield Static("Temporary FID (4 hex)")
                yield Input(
                    value=str(self._defaults.get("temporary_fid", "") or ""),
                    id="adf_bootstrap_fid",
                )
                yield Static("ADF AID / dfName (hex)")
                yield Input(
                    value=str(self._defaults.get("df_name", "") or ""),
                    id="adf_bootstrap_aid",
                )
                yield Static(
                    "[dim]Fixed template defaults remain implicit: local EF.ARR link, PIN status template DO, and LCSI.[/dim]"
                )
                yield Static("", id="adf_bootstrap_error")
                with Horizontal(id="adf_bootstrap_buttons"):
                    yield Button("Cancel", id="adf_bootstrap_cancel")
                    yield Button("Apply values", id="adf_bootstrap_apply", variant="primary")

        def on_mount(self) -> None:
            widget = self.query_one("#adf_bootstrap_fid", Input)
            widget.focus()

        def _set_error(self, text: str) -> None:
            widget = self.query_one("#adf_bootstrap_error", Static)
            widget.update(f"[bold red]{escape(str(text or '').strip())}[/bold red]")

        def _collect_result(self) -> dict[str, str]:
            fid_input = self.query_one("#adf_bootstrap_fid", Input)
            aid_input = self.query_one("#adf_bootstrap_aid", Input)
            fid_text = str(fid_input.value or "").strip().upper()
            aid_text = str(aid_input.value or "").strip().replace(" ", "").upper()
            aid_prefix = str(self._defaults.get("aid_prefix", "") or "").strip().upper()
            if len(fid_text) != 4:
                raise ValueError("Temporary FID must be exactly 4 hex characters.")
            try:
                int(fid_text, 16)
            except ValueError as exc:
                raise ValueError("Temporary FID must be hexadecimal.") from exc
            if len(aid_text) == 0 or len(aid_text) % 2 != 0:
                raise ValueError("ADF AID must be non-empty even-length hex.")
            try:
                bytes.fromhex(aid_text)
            except ValueError as exc:
                raise ValueError("ADF AID must be hexadecimal.") from exc
            if len(aid_prefix) > 0 and aid_text.startswith(aid_prefix) is False:
                raise ValueError(f"ADF AID must start with {aid_prefix}.")
            fid_input.value = fid_text
            aid_input.value = aid_text
            return {
                "temporary_fid": fid_text,
                "df_name": aid_text,
            }

        def _submit_form(self) -> None:
            try:
                result = self._collect_result()
            except ValueError as exc:
                self._set_error(str(exc))
                return
            self.dismiss(result)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = str(event.button.id or "").strip()
            if button_id == "adf_bootstrap_cancel":
                self.dismiss(None)
                return
            if button_id == "adf_bootstrap_apply":
                self._submit_form()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            del event
            self._submit_form()

        def action_submit_form(self) -> None:
            self._submit_form()

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class PeFileOverridePicker(ModalScreen[dict[str, str] | None]):
        """Override selected file descriptor defaults before insertion."""

        _FIELD_LABELS = {
            "short_efid": "Short EFID (decimal 1..30)",
            "arr_record": "ARR record (decimal 1..255)",
            "file_size": "EF file size (bytes)",
            "record_length": "Record length (bytes)",
            "record_count": "Record count",
        }
        _FIELD_ORDER = (
            "short_efid",
            "arr_record",
            "file_size",
            "record_length",
            "record_count",
        )

        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
            Binding("ctrl+enter", "submit_form", "Apply", show=False, priority=True),
        ]

        def __init__(self, override_defaults: dict[str, str], *, target_label: str) -> None:
            super().__init__()
            self._defaults = dict(override_defaults)
            self._target_label = str(target_label or "").strip()

        def _active_field_names(self) -> list[str]:
            return [
                field_name
                for field_name in self._FIELD_ORDER
                if len(str(self._defaults.get(field_name, "") or "").strip()) > 0
            ]

        def compose(self) -> ComposeResult:
            file_name = str(self._defaults.get("file_name", "file") or "file")
            file_type = str(self._defaults.get("file_type", "") or "").strip().upper()
            with Vertical(id="pe_file_override_shell"):
                if len(file_type) > 0:
                    yield Static(f"Per-file overrides for {file_name} [{file_type}]")
                else:
                    yield Static(f"Per-file overrides for {file_name}")
                if len(self._target_label) > 0:
                    yield Static(f"[dim]Requested target: {self._target_label}[/dim]")
                arr_summary = str(self._defaults.get("arr_summary", "") or "").strip()
                if len(arr_summary) > 0:
                    yield Static(f"[dim]Current ARR meaning: {arr_summary}[/dim]")
                derived_size = str(self._defaults.get("derived_file_size", "") or "").strip()
                if len(derived_size) > 0:
                    yield Static(f"[dim]Template record layout derives {derived_size} byte(s).[/dim]")
                for field_name in self._active_field_names():
                    yield Static(self._FIELD_LABELS[field_name])
                    yield Input(
                        value=str(self._defaults.get(field_name, "") or ""),
                        id=f"pe_file_override_{field_name}",
                    )
                yield Static(
                    "[dim]Apply with the shown values to keep template defaults unchanged.[/dim]"
                )
                yield Static("", id="pe_file_override_error")
                with Horizontal(id="pe_file_override_buttons"):
                    yield Button("Cancel", id="pe_file_override_cancel")
                    yield Button("Apply values", id="pe_file_override_apply", variant="primary")

        def on_mount(self) -> None:
            active_fields = self._active_field_names()
            if len(active_fields) == 0:
                return
            widget = self.query_one(
                f"#pe_file_override_{active_fields[0]}",
                Input,
            )
            widget.focus()

        def _set_error(self, text: str) -> None:
            widget = self.query_one("#pe_file_override_error", Static)
            widget.update(f"[bold red]{escape(str(text or '').strip())}[/bold red]")

        def _collect_result(self) -> dict[str, str]:
            out: dict[str, str] = {}
            for field_name in self._active_field_names():
                widget = self.query_one(f"#pe_file_override_{field_name}", Input)
                field_value = str(widget.value or "").strip()
                if len(field_value) == 0:
                    continue
                if field_value.isdigit() is False:
                    raise ValueError(f"{self._FIELD_LABELS[field_name]} must be a decimal integer.")
                out[field_name] = field_value
                widget.value = field_value
            return out

        def _submit_form(self) -> None:
            try:
                result = self._collect_result()
            except ValueError as exc:
                self._set_error(str(exc))
                return
            self.dismiss(result)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = str(event.button.id or "").strip()
            if button_id == "pe_file_override_cancel":
                self.dismiss(None)
                return
            if button_id == "pe_file_override_apply":
                self._submit_form()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            del event
            self._submit_form()

        def action_submit_form(self) -> None:
            self._submit_form()

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class ServiceTableToggleEditor(Vertical):
        """Purpose-built toggle editor for EF service tables."""

        BINDINGS = [
            Binding("space", "toggle_highlighted", "Toggle", show=False, priority=True),
            Binding("enter", "toggle_highlighted", "Toggle", show=False, priority=True),
            Binding("y", "enable_highlighted", "Enable", show=False, priority=True),
            Binding("n", "disable_highlighted", "Disable", show=False, priority=True),
            Binding("ctrl+f", "focus_filter", "Filter", show=False, priority=True),
            Binding("/", "focus_filter", "Filter", show=False, priority=True),
            Binding("f3", "next_filter_match", "Next match", show=False, priority=True),
            Binding("ctrl+r", "previous_filter_match", "Previous match", show=False, priority=True),
            Binding("shift+f3", "previous_filter_match", "Previous match", show=False, priority=True),
            Binding("ctrl+g", "next_filter_match", "Next match", show=False, priority=True),
            Binding("ctrl+shift+g", "previous_filter_match", "Previous match", show=False, priority=True),
        ]

        class Changed(Message):
            def __init__(
                self,
                editor: "ServiceTableToggleEditor",
                payload: dict[str, object],
            ) -> None:
                super().__init__()
                self.editor = editor
                self.payload = payload

        def __init__(
            self,
            *,
            payload: dict[str, object] | None = None,
            note: str | None = None,
            read_only: bool = False,
            id: str | None = None,
            classes: str | None = None,
        ) -> None:
            super().__init__(id=id, classes=classes)
            self._payload = dict(payload or {})
            self._note = str(note or "").strip()
            self._read_only = bool(read_only)
            self._syncing = False
            self._filter_query = ""

        @staticmethod
        def _flag_enabled(value: object) -> bool:
            normalized = str(value or "").strip().lower()
            return normalized in {"y", "yes", "true", "1", "on", "enabled"}

        def _service_items(self) -> list[tuple[str, bool]]:
            services_payload = self._payload.get("services")
            if isinstance(services_payload, dict) is False:
                return []
            items: list[tuple[str, bool]] = []
            for raw_key, raw_value in services_payload.items():
                service_key = str(raw_key or "").strip()
                if len(service_key) == 0:
                    continue
                items.append((service_key, self._flag_enabled(raw_value)))
            return items

        def _filter_query_text(self) -> str:
            return str(self._filter_query or "").strip()

        def _service_matches_filter(self, service_key: str) -> bool:
            query_text = self._filter_query_text().lower()
            if len(query_text) == 0:
                return True
            normalized_key = str(service_key or "").strip().lower()
            if len(normalized_key) == 0:
                return False
            for token in query_text.split():
                if token not in normalized_key:
                    return False
            return True

        def _filtered_service_items(self) -> list[tuple[str, bool]]:
            return [
                (service_key, enabled)
                for service_key, enabled in self._service_items()
                if self._service_matches_filter(service_key)
            ]

        def _selection_specs(self) -> list[tuple[str, str, bool]]:
            return [
                (_highlight_query_text(service_key, self._filter_query_text()), service_key, enabled)
                for service_key, enabled in self._filtered_service_items()
            ]

        def _refresh_visible_service_prompt_highlighting(self) -> None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            active_service_key = self._highlighted_service_key()
            filter_text = self._filter_query_text()
            for option_index, (service_key, _enabled) in enumerate(self._filtered_service_items()):
                selection_list.replace_option_prompt_at_index(
                    option_index,
                    _highlight_query_text(
                        service_key,
                        filter_text,
                        active=service_key == active_service_key and len(filter_text) > 0,
                    ),
                )

        def compose(self) -> ComposeResult:
            yield Static("", classes="service_table_note")
            with Horizontal(classes="service_table_toolbar"):
                yield Static("Preserve bytes", classes="service_table_byte_label")
                yield Input(
                    value="",
                    placeholder="0",
                    classes="service_table_byte_input",
                )
                yield Static("", classes="service_table_summary")
            with Horizontal(classes="service_table_filter_row"):
                yield Static("Filter", classes="service_table_filter_label")
                yield Input(
                    value="",
                    placeholder="Search services",
                    classes="service_table_filter_input",
                )
            yield SelectionList(
                *self._selection_specs(),
                classes="service_table_selection",
            )

        def on_mount(self) -> None:
            self._apply_state_to_widgets()

        def focus_editor(self) -> None:
            widget = self.query_one(SelectionList)
            widget.focus()

        def action_focus_filter(self) -> None:
            widget = self.query_one(".service_table_filter_input", Input)
            widget.focus()

        def set_filter_query(self, query_text: str) -> None:
            self._filter_query = str(query_text or "")
            if self.is_mounted:
                self._apply_state_to_widgets()

        def set_payload(
            self,
            payload: dict[str, object],
            *,
            note: str | None = None,
            read_only: bool | None = None,
        ) -> None:
            self._payload = dict(payload)
            if note is not None:
                self._note = str(note or "").strip()
            if read_only is not None:
                self._read_only = bool(read_only)
            if self.is_mounted:
                self._apply_state_to_widgets()

        def current_payload(self) -> dict[str, object]:
            byte_input = self.query_one(".service_table_byte_input", Input)
            selection_list = self.query_one(".service_table_selection", SelectionList)
            selected_keys = {str(value) for value in selection_list.selected}
            services_payload = self._payload.get("services")
            normalized_services: dict[str, str] = {}
            if isinstance(services_payload, dict):
                for raw_key, raw_value in services_payload.items():
                    service_key = str(raw_key or "").strip()
                    if len(service_key) == 0:
                        continue
                    normalized_services[service_key] = "y" if self._flag_enabled(raw_value) else "n"
                for service_key, _enabled in self._filtered_service_items():
                    normalized_services[service_key] = "y" if service_key in selected_keys else "n"
            preserve_text = str(byte_input.value or "").strip()
            preserve_value: object = preserve_text
            if preserve_text.isdigit():
                preserve_value = int(preserve_text)
            return {
                "preserveByteLength": preserve_value,
                "services": normalized_services,
            }

        def _status_note_text(self) -> str:
            base_text = self._note
            hint = (
                "Space toggles highlighted service. Use y/n to force state. "
                "Ctrl+F or / filters services. F3/Ctrl+G moves next match; "
                "Ctrl+R moves previous."
            )
            if len(base_text) == 0:
                return hint
            return f"{base_text} {hint}"

        @staticmethod
        def _note_markup(text: str) -> str:
            normalized = str(text or "").strip()
            if len(normalized) == 0:
                return ""
            return (
                "[bold #EBCB8B]Guide[/bold #EBCB8B] "
                f"[#E5E9F0]{escape(normalized)}[/]"
            )

        @staticmethod
        def _summary_markup(text: str) -> str:
            normalized = str(text or "").strip()
            if len(normalized) == 0:
                return ""
            return (
                "[bold #8FBCBB]Summary[/bold #8FBCBB] "
                f"[#E5E9F0]{escape(normalized)}[/]"
            )

        def _refresh_summary(self) -> None:
            summary = self.query_one(".service_table_summary", Static)
            services_total = len(self._service_items())
            visible_total = len(self._filtered_service_items())
            selection_list = self.query_one(".service_table_selection", SelectionList)
            enabled_total = sum(1 for _service_key, enabled in self._service_items() if enabled)
            highlighted = selection_list.highlighted
            highlight_text = ""
            if isinstance(highlighted, int) and highlighted >= 0 and highlighted < selection_list.option_count:
                highlighted_option = selection_list.get_option_at_index(highlighted)
                highlighted_key = str(highlighted_option.prompt)
                highlight_text = f" · match: {highlighted + 1}/{max(visible_total, 1)} · selected: {highlighted_key}"
            filter_text = self._filter_query_text()
            visible_text = f" · visible: {visible_total}/{services_total}"
            if len(filter_text) > 0:
                visible_text += f" · filter: {filter_text}"
            if visible_total == 0 and len(filter_text) > 0:
                visible_text += " · no matches"
            summary.update(
                self._summary_markup(
                    f"{enabled_total}/{services_total} enabled{visible_text}{highlight_text}"
                )
            )

        def _highlight_visible_service_key(self, service_key: str | None) -> bool:
            normalized_key = str(service_key or "").strip()
            if len(normalized_key) == 0:
                return False
            selection_list = self.query_one(".service_table_selection", SelectionList)
            for option_index in range(selection_list.option_count):
                option = selection_list.get_option_at_index(option_index)
                if str(option.value or "").strip() == normalized_key:
                    selection_list.highlighted = option_index
                    return True
            return False

        def _move_filter_match(self, step: int) -> None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            if selection_list.option_count <= 0:
                self._refresh_summary()
                return
            highlighted = selection_list.highlighted
            if isinstance(highlighted, int) is False or highlighted < 0 or highlighted >= selection_list.option_count:
                if step < 0:
                    selection_list.highlighted = selection_list.option_count - 1
                else:
                    selection_list.highlighted = 0
            else:
                selection_list.highlighted = (highlighted + step) % selection_list.option_count
            self._refresh_visible_service_prompt_highlighting()
            self._refresh_summary()

        def _sync_visible_selection_to_payload(self) -> None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            selected_keys = {str(value) for value in selection_list.selected}
            payload = self.current_payload()
            services_payload = payload.get("services")
            if isinstance(services_payload, dict) is False:
                return
            for service_key, _enabled in self._filtered_service_items():
                services_payload[service_key] = "y" if service_key in selected_keys else "n"
            self._payload = payload

        def _apply_state_to_widgets(self) -> None:
            note_widget = self.query_one(".service_table_note", Static)
            byte_input = self.query_one(".service_table_byte_input", Input)
            filter_input = self.query_one(".service_table_filter_input", Input)
            selection_list = self.query_one(".service_table_selection", SelectionList)
            current_highlight_key = self._highlighted_service_key()
            self._syncing = True
            try:
                note_widget.update(self._note_markup(self._status_note_text()))
                preserve_value = self._payload.get("preserveByteLength", 0)
                byte_input.value = str(preserve_value)
                byte_input.disabled = self._read_only
                filter_input.value = self._filter_query
                filter_input.disabled = False
                selection_list.disabled = self._read_only
                selection_list.clear_options()
                selection_specs = self._selection_specs()
                if len(selection_specs) > 0:
                    selection_list.add_options(selection_specs)
            finally:
                self._syncing = False
            if selection_list.option_count > 0:
                restored = self._highlight_visible_service_key(current_highlight_key)
                if restored is False and len(self._filter_query_text()) > 0:
                    selection_list.highlighted = 0
                self._refresh_visible_service_prompt_highlighting()
            self._refresh_summary()

        def _emit_changed(self) -> None:
            if self._syncing or self._read_only:
                return
            self._payload = dict(self.current_payload())
            self.post_message(self.Changed(self, self._payload))

        def _highlighted_service_key(self) -> str | None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            highlighted = selection_list.highlighted
            if isinstance(highlighted, int) is False:
                return None
            if highlighted < 0 or highlighted >= selection_list.option_count:
                return None
            highlighted_option = selection_list.get_option_at_index(highlighted)
            return str(highlighted_option.value or "").strip() or None

        def set_service_enabled(self, service_key: str, enabled: bool) -> None:
            normalized_key = str(service_key or "").strip()
            if len(normalized_key) == 0:
                return
            payload = self.current_payload()
            services_payload = payload.get("services")
            if isinstance(services_payload, dict) is False:
                return
            if normalized_key not in services_payload:
                return
            services_payload[normalized_key] = "y" if enabled else "n"
            self._payload = payload
            self._apply_state_to_widgets()
            self._highlight_visible_service_key(normalized_key)
            self._emit_changed()

        def action_toggle_highlighted(self) -> None:
            if self._read_only:
                return
            service_key = self._highlighted_service_key()
            if service_key is None:
                return
            services_payload = self.current_payload().get("services")
            if isinstance(services_payload, dict) is False:
                return
            current_enabled = self._flag_enabled(services_payload.get(service_key, "n"))
            self.set_service_enabled(service_key, not current_enabled)

        def action_enable_highlighted(self) -> None:
            if self._read_only:
                return
            service_key = self._highlighted_service_key()
            if service_key is None:
                return
            self.set_service_enabled(service_key, True)

        def action_disable_highlighted(self) -> None:
            if self._read_only:
                return
            service_key = self._highlighted_service_key()
            if service_key is None:
                return
            self.set_service_enabled(service_key, False)

        def action_next_filter_match(self) -> None:
            self._move_filter_match(1)

        def action_previous_filter_match(self) -> None:
            self._move_filter_match(-1)

        def on_selection_list_selected_changed(
            self,
            event: SelectionList.SelectedChanged,
        ) -> None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            if event.selection_list is not selection_list:
                return
            self._sync_visible_selection_to_payload()
            self._refresh_summary()
            self._emit_changed()

        def on_selection_list_selection_highlighted(
            self,
            event: SelectionList.SelectionHighlighted,
        ) -> None:
            selection_list = self.query_one(".service_table_selection", SelectionList)
            if event.selection_list is not selection_list:
                return
            self._refresh_visible_service_prompt_highlighting()
            self._refresh_summary()

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.has_class("service_table_filter_input"):
                if self._syncing:
                    return
                current_highlight_key = self._highlighted_service_key()
                self._filter_query = str(event.value or "")
                self._apply_state_to_widgets()
                self._highlight_visible_service_key(current_highlight_key)
                return
            if event.input.has_class("service_table_byte_input") is False:
                return
            self._payload = self.current_payload()
            self._emit_changed()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if event.input.has_class("service_table_filter_input") is False:
                return
            if len(self._filter_query_text()) == 0:
                selection_list = self.query_one(".service_table_selection", SelectionList)
                selection_list.focus()
                return
            self.action_next_filter_match()

    class StructuredDecodedFieldEditor(Vertical):
        """Structured form editor for decoded descriptor leaf fields."""

        _LCSI_STATES = (
            "no_information",
            "creation",
            "initialization",
            "operational_activated",
            "operational_deactivated",
            "termination",
        )

        class Changed(Message):
            def __init__(
                self,
                editor: "StructuredDecodedFieldEditor",
                editor_kind: str,
                payload: dict[str, object],
            ) -> None:
                super().__init__()
                self.editor = editor
                self.editor_kind = str(editor_kind or "").strip().lower()
                self.payload = payload

        def __init__(
            self,
            *,
            editor_kind: str = "json",
            payload: dict[str, object] | None = None,
            note: str | None = None,
            read_only: bool = False,
            id: str | None = None,
            classes: str | None = None,
        ) -> None:
            super().__init__(id=id, classes=classes)
            self._editor_kind = str(editor_kind or "json").strip().lower() or "json"
            self._payload = dict(payload or {})
            self._note = str(note or "").strip()
            self._read_only = bool(read_only)
            self._syncing = False

        def compose(self) -> ComposeResult:
            yield Static("", classes="structured_field_note")
            yield Checkbox("", classes="structured_field_checkbox")
            with Horizontal(classes="structured_field_row structured_field_primary_row"):
                yield Static("", classes="structured_field_label structured_field_primary_label")
                yield Input(value="", classes="structured_field_input structured_field_primary_input")
            with Horizontal(classes="structured_field_row structured_field_secondary_row"):
                yield Static("", classes="structured_field_label structured_field_secondary_label")
                yield Input(value="", classes="structured_field_input structured_field_secondary_input")
            yield Static("", classes="structured_field_summary")
            yield OptionList(classes="structured_field_options")

        def on_mount(self) -> None:
            self._apply_state_to_widgets()

        @property
        def editor_kind(self) -> str:
            return self._editor_kind

        def focus_editor(self) -> None:
            if self._editor_kind == "lcsi_state":
                widget = self.query_one(".structured_field_options", OptionList)
                widget.focus()
                return
            checkbox = self.query_one(".structured_field_checkbox", Checkbox)
            if checkbox.display and checkbox.disabled is False:
                checkbox.focus()
            primary_input = self.query_one(".structured_field_primary_input", Input)
            if primary_input.display and primary_input.disabled is False:
                primary_input.focus()
                return
            if checkbox.display and checkbox.disabled is False:
                checkbox.focus()

        def set_editor_state(
            self,
            *,
            editor_kind: str,
            payload: dict[str, object],
            note: str | None = None,
            read_only: bool | None = None,
        ) -> None:
            self._editor_kind = str(editor_kind or "json").strip().lower() or "json"
            self._payload = dict(payload)
            if note is not None:
                self._note = str(note or "").strip()
            if read_only is not None:
                self._read_only = bool(read_only)
            if self.is_mounted:
                self._apply_state_to_widgets()

        def update_payload(
            self,
            payload: dict[str, object],
            *,
            refresh_widgets: bool = True,
        ) -> None:
            self._payload = dict(payload)
            if refresh_widgets and self.is_mounted:
                self._apply_state_to_widgets()
            elif self.is_mounted:
                summary = self.query_one(".structured_field_summary", Static)
                summary.update(self._summary_markup(self._summary_text()))
            self._emit_changed()

        def current_payload(self) -> dict[str, object]:
            return copy.deepcopy(self._payload)

        def _emit_changed(self) -> None:
            if self._syncing or self._read_only:
                return
            self.post_message(
                self.Changed(
                    self,
                    self._editor_kind,
                    self.current_payload(),
                )
            )

        def _summary_text(self) -> str:
            if self._editor_kind == "arr_reference":
                arr_file_id = str(self._payload.get("arrFileId", "") or "").strip()
                record_number = str(self._payload.get("recordNumber", "") or "").strip()
                if len(arr_file_id) == 0:
                    return f"Encodes local EF.ARR record {record_number or '?'}."
                return f"Encodes EF.ARR {arr_file_id.upper()} record {record_number or '?'}."
            if self._editor_kind == "short_efid":
                if bool(self._payload.get("supported", False)) is False:
                    return "Encodes empty bytes when SFI support is disabled."
                return f"SFI {self._payload.get('sfi', '?')} encodes as bit-shifted short EFID."
            if self._editor_kind == "byte_count":
                return "Byte count is encoded as minimal big-endian hex."
            if self._editor_kind == "file_id":
                return "FID must remain exactly four hexadecimal characters."
            if self._editor_kind == "fill_file_offset":
                return "Offset stays as a plain decimal integer."
            if self._editor_kind == "lcsi_state":
                state = str(self._payload.get("state", "") or "").strip() or "unknown"
                return f"Selected LCSI state: {state}."
            return ""

        @staticmethod
        def _note_markup(text: str) -> str:
            normalized = str(text or "").strip()
            if len(normalized) == 0:
                return ""
            return (
                "[bold #EBCB8B]Field hint[/bold #EBCB8B] "
                f"[#E5E9F0]{escape(normalized)}[/]"
            )

        @staticmethod
        def _summary_markup(text: str) -> str:
            normalized = str(text or "").strip()
            if len(normalized) == 0:
                return ""
            return (
                "[bold #8FBCBB]Encoding[/bold #8FBCBB] "
                f"[#E5E9F0]{escape(normalized)}[/]"
            )

        def _apply_state_to_widgets(self) -> None:
            note_widget = self.query_one(".structured_field_note", Static)
            checkbox = self.query_one(".structured_field_checkbox", Checkbox)
            primary_row = self.query_one(".structured_field_primary_row", Horizontal)
            primary_label = self.query_one(".structured_field_primary_label", Static)
            primary_input = self.query_one(".structured_field_primary_input", Input)
            secondary_row = self.query_one(".structured_field_secondary_row", Horizontal)
            secondary_label = self.query_one(".structured_field_secondary_label", Static)
            secondary_input = self.query_one(".structured_field_secondary_input", Input)
            summary = self.query_one(".structured_field_summary", Static)
            options = self.query_one(".structured_field_options", OptionList)
            self._syncing = True
            try:
                note_widget.update(self._note_markup(self._note))
                checkbox.display = False
                primary_row.display = False
                secondary_row.display = False
                options.display = False
                checkbox.disabled = self._read_only
                primary_input.disabled = self._read_only
                secondary_input.disabled = self._read_only
                options.disabled = self._read_only

                if self._editor_kind == "short_efid":
                    checkbox.label = "Supported SFI encoding"
                    checkbox.value = bool(self._payload.get("supported", False))
                    checkbox.display = True
                    primary_row.display = checkbox.value
                    primary_label.update("SFI (1-30)")
                    primary_input.value = str(self._payload.get("sfi", "") or "")
                    primary_input.disabled = self._read_only or checkbox.value is False
                elif self._editor_kind == "arr_reference":
                    explicit = len(str(self._payload.get("arrFileId", "") or "").strip()) > 0
                    checkbox.label = "Use explicit ARR file ID"
                    checkbox.value = explicit
                    checkbox.display = True
                    primary_row.display = True
                    primary_label.update("Record number")
                    primary_input.value = str(self._payload.get("recordNumber", "") or "")
                    secondary_row.display = True
                    secondary_label.update("ARR file ID")
                    secondary_input.value = str(self._payload.get("arrFileId", "") or "")
                    secondary_input.disabled = self._read_only or explicit is False
                elif self._editor_kind == "byte_count":
                    primary_row.display = True
                    primary_label.update("Byte count")
                    primary_input.value = str(self._payload.get("byteCount", "") or "")
                elif self._editor_kind == "file_id":
                    primary_row.display = True
                    primary_label.update("File ID (hex)")
                    primary_input.value = str(self._payload.get("fid", "") or "")
                elif self._editor_kind == "fill_file_offset":
                    primary_row.display = True
                    primary_label.update("Offset")
                    primary_input.value = str(self._payload.get("offset", "") or "")
                elif self._editor_kind == "lcsi_state":
                    options.display = True
                    options.clear_options()
                    current_state = str(self._payload.get("state", "") or "").strip().lower()
                    option_items: list[Option] = []
                    for state_name in self._LCSI_STATES:
                        prompt = state_name
                        if state_name == current_state:
                            prompt += "  [dim][current][/dim]"
                        option_items.append(Option(prompt, id=state_name))
                    if len(option_items) > 0:
                        options.add_options(option_items)
                    highlighted_index = 0
                    if current_state in self._LCSI_STATES:
                        highlighted_index = self._LCSI_STATES.index(current_state)
                    options.highlighted = highlighted_index
                summary.update(self._summary_markup(self._summary_text()))
            finally:
                self._syncing = False

        def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
            checkbox = self.query_one(".structured_field_checkbox", Checkbox)
            if event.checkbox is not checkbox:
                return
            if self._editor_kind == "short_efid":
                if event.value:
                    next_payload = {
                        "supported": True,
                        "sfi": self._payload.get("sfi", ""),
                    }
                else:
                    next_payload = {"supported": False}
                self.update_payload(next_payload)
                return
            if self._editor_kind == "arr_reference":
                next_payload = dict(self._payload)
                if event.value:
                    next_payload["arrFileId"] = str(next_payload.get("arrFileId", "") or "").strip() or "6F06"
                else:
                    next_payload.pop("arrFileId", None)
                self.update_payload(next_payload)

        def on_input_changed(self, event: Input.Changed) -> None:
            if self._syncing:
                return
            primary_input = self.query_one(".structured_field_primary_input", Input)
            secondary_input = self.query_one(".structured_field_secondary_input", Input)
            if event.input is primary_input:
                next_payload = dict(self._payload)
                if self._editor_kind == "short_efid":
                    next_payload["supported"] = bool(next_payload.get("supported", False))
                    next_payload["sfi"] = str(primary_input.value or "").strip()
                elif self._editor_kind == "arr_reference":
                    next_payload["recordNumber"] = str(primary_input.value or "").strip()
                elif self._editor_kind == "byte_count":
                    next_payload["byteCount"] = str(primary_input.value or "").strip()
                elif self._editor_kind == "file_id":
                    next_payload["fid"] = str(primary_input.value or "").strip().upper()
                elif self._editor_kind == "fill_file_offset":
                    next_payload["offset"] = str(primary_input.value or "").strip()
                else:
                    return
                self.update_payload(next_payload, refresh_widgets=False)
                return
            if event.input is secondary_input and self._editor_kind == "arr_reference":
                next_payload = dict(self._payload)
                next_payload["arrFileId"] = str(secondary_input.value or "").strip().upper()
                self.update_payload(next_payload, refresh_widgets=False)

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            options = self.query_one(".structured_field_options", OptionList)
            if event.option_list is not options:
                return
            if self._editor_kind != "lcsi_state":
                return
            state_name = str(event.option.id or "").strip().lower()
            if len(state_name) == 0:
                return
            self.update_payload({"state": state_name})

    class KeybindHelpPicker(ModalScreen[None]):
        """Show the main TUI shortcuts in one place."""

        BINDINGS = [
            Binding("escape", "close_help", "Close", priority=True),
            Binding("f1", "close_help", "Close", show=False, priority=True),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="keybind_help_shell"):
                yield Static("Keybind help")
                yield Static("[dim]Press Esc or F1 to close.[/dim]")
                yield TextArea(
                    build_keybind_help_text(),
                    id="keybind_help_text",
                    language=None,
                    read_only=True,
                    show_line_numbers=False,
                    soft_wrap=True,
                )

        def on_mount(self) -> None:
            widget = self.query_one("#keybind_help_text", TextArea)
            widget.focus()

        def action_close_help(self) -> None:
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
                "decoded": "Decoded view",
                "none": "Hidden",
            }
            slot_titles = {
                "right": "Right pane",
                "bottom_left": "Bottom-left pane",
                "bottom_right": "Bottom-right pane",
            }
            mode_order_by_slot = {
                "right": ("der", "inspect", "lint", "decoded", "none"),
                "bottom_left": ("inspect", "lint", "decoded", "der", "none"),
                "bottom_right": ("lint", "decoded", "der", "inspect", "none"),
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

    class TokenInputPrompt(ModalScreen[dict | None]):
        """Generic prompt for token name / value input.

        Modes:

        - ``add``: prompts for a new name and value.
        - ``rename``: prompts for a new name only.
        - ``value``: prompts for a new value only.
        """

        BINDINGS = [
            Binding("escape", "cancel_prompt", "Close", priority=True),
            Binding("ctrl+enter", "apply_prompt", "Apply", show=False, priority=True),
        ]

        def __init__(
            self,
            *,
            mode: str,
            title: str,
            existing_name: str | None = None,
            existing_value: str | None = None,
            helper_text: str | None = None,
        ) -> None:
            super().__init__()
            self._mode = str(mode or "").strip().lower()
            if self._mode not in ("add", "rename", "value"):
                raise ValueError(f"Unknown TokenInputPrompt mode: {mode!r}")
            self._title = str(title or "Token")
            self._existing_name = str(existing_name or "")
            self._existing_value = str(existing_value or "")
            self._helper_text = helper_text

        def compose(self) -> ComposeResult:
            with Vertical(id="token_prompt_shell"):
                yield Static(self._title)
                if self._helper_text is not None:
                    yield Static(f"[dim]{self._helper_text}[/dim]")
                if self._mode in ("add", "rename"):
                    if self._mode == "rename":
                        label = "New name (current: " + self._existing_name + ")"
                        initial = self._existing_name
                    else:
                        label = "Token name (e.g. ICCID)"
                        initial = ""
                    yield Static(label)
                    yield Input(value=initial, id="token_prompt_name")
                if self._mode in ("add", "value"):
                    label = (
                        "Value — hex string or JSON object "
                        "(e.g. 89461111111111111112 or {\"zero_len\":10})"
                    )
                    if self._mode == "value":
                        label = "New value (current: " + self._existing_value + ")"
                    yield Static(label)
                    yield Input(value=self._existing_value, id="token_prompt_value")
                yield Static("", id="token_prompt_error")
                with Horizontal(id="token_prompt_buttons"):
                    yield Button("Cancel", id="token_prompt_cancel")
                    yield Button("Apply", id="token_prompt_apply", variant="primary")

        def on_mount(self) -> None:
            if self._mode in ("add", "rename"):
                self.query_one("#token_prompt_name", Input).focus()
            else:
                self.query_one("#token_prompt_value", Input).focus()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "token_prompt_apply":
                self._submit()
            elif event.button.id == "token_prompt_cancel":
                self.dismiss(None)

        def action_apply_prompt(self) -> None:
            self._submit()

        def action_cancel_prompt(self) -> None:
            self.dismiss(None)

        def _submit(self) -> None:
            result: dict[str, str] = {"mode": self._mode}
            if self._mode in ("add", "rename"):
                name_widget = self.query_one("#token_prompt_name", Input)
                result["name"] = str(name_widget.value or "").strip()
            if self._mode in ("add", "value"):
                value_widget = self.query_one("#token_prompt_value", Input)
                result["value"] = str(value_widget.value or "").strip()
            self.dismiss(result)

    class TokenConfirmPicker(ModalScreen[bool | None]):
        """Two-option confirmation dialog used for destructive token actions."""

        BINDINGS = [
            Binding("escape", "cancel_confirm", "Close", priority=True),
        ]

        def __init__(
            self,
            *,
            title: str,
            body: str,
            confirm_label: str = "Apply",
            cancel_label: str = "Cancel",
        ) -> None:
            super().__init__()
            self._title = str(title)
            self._body = str(body)
            self._confirm_label = str(confirm_label)
            self._cancel_label = str(cancel_label)

        def compose(self) -> ComposeResult:
            options = [
                Option(self._cancel_label, id="cancel"),
                Option(self._confirm_label, id="confirm"),
            ]
            with Vertical(id="token_confirm_shell"):
                yield Static(self._title)
                yield Static(f"[dim]{self._body}[/dim]")
                yield Static("[dim]Enter confirm · Esc close[/dim]")
                yield OptionList(*options, id="token_confirm_opts")

        def on_mount(self) -> None:
            widget = self.query_one("#token_confirm_opts", OptionList)
            widget.focus()

        def on_option_list_option_selected(
            self, event: OptionList.OptionSelected
        ) -> None:
            oid = event.option_id
            if oid == "confirm":
                self.dismiss(True)
                return
            self.dismiss(False)

        def action_cancel_confirm(self) -> None:
            self.dismiss(None)

    class TokenManagerPicker(ModalScreen[dict | None]):
        """Main TUI token manager modal.

        Receives the current editor document as a Python dict and returns a
        new dict when changes were applied (or ``None`` on cancel). The main
        app is responsible for serialising the result back into the
        ``#json_editor`` buffer and re-running the save/lint pipeline.
        """

        BINDINGS = [
            Binding("escape", "close_manager", "Close", priority=True),
            Binding("a", "add_token", "Add", priority=True),
            Binding("r", "rename_token", "Rename", priority=True),
            Binding("v", "set_value", "Set value", priority=True),
            Binding("e", "set_value", "Set value", show=False, priority=True),
            Binding("d", "delete_token", "Delete", priority=True),
            Binding("enter", "set_value", "Set value", show=False, priority=True),
            Binding("ctrl+s", "apply_changes", "Apply", priority=True),
        ]

        def __init__(self, document: dict) -> None:
            super().__init__()
            self._document = copy.deepcopy(document)
            self._dirty = False

        def compose(self) -> ComposeResult:
            with Vertical(id="token_manager_shell"):
                yield Static("Token manager")
                yield Static(
                    "[dim]Manage __ygg_token_defs__ for the current buffer.[/dim]"
                )
                yield Static(
                    "[dim]A=Add  R=Rename  V=Set value  D=Delete  "
                    "Ctrl+S=Apply  Esc=Close[/dim]"
                )
                yield Static("", id="token_manager_summary")
                yield OptionList(id="token_manager_list")
                yield Static("", id="token_manager_status")

        def on_mount(self) -> None:
            self._refresh_list()
            widget = self.query_one("#token_manager_list", OptionList)
            widget.focus()

        def _set_status(self, text: str) -> None:
            status = self.query_one("#token_manager_status", Static)
            status.update(str(text))

        def _update_summary(self) -> None:
            summary_widget = self.query_one("#token_manager_summary", Static)
            counts = summarize_token_counts(self._document)
            style = placeholder_style_from_document(self._document)
            dirty_badge = " [dirty]" if self._dirty else ""
            summary_widget.update(
                f"[dim]style='{style}'  tokens={counts['tokens']}  "
                f"content refs={counts['content_refs']}  "
                f"length refs={counts['length_refs']}{dirty_badge}[/dim]"
            )

        def _refresh_list(self) -> None:
            widget = self.query_one("#token_manager_list", OptionList)
            widget.clear_options()
            rows = build_token_rows(self._document)
            if len(rows) == 0:
                widget.add_option(
                    Option(
                        "(no tokens defined — press A to add)",
                        id="__empty__",
                        disabled=True,
                    )
                )
            else:
                name_width = max(len(r["name"]) for r in rows)
                for row in rows:
                    widget.add_option(
                        Option(
                            format_token_row(row, name_width=name_width),
                            id=row["name"],
                        )
                    )
            self._update_summary()

        def _selected_token_name(self) -> str | None:
            widget = self.query_one("#token_manager_list", OptionList)
            highlighted = widget.highlighted
            if highlighted is None:
                return None
            try:
                option = widget.get_option_at_index(highlighted)
            except Exception:
                return None
            if option is None or option.id in (None, "__empty__"):
                return None
            return str(option.id)

        def action_close_manager(self) -> None:
            if self._dirty is False:
                self.dismiss(None)
                return

            def _on_confirm(result: bool | None) -> None:
                if result is True:
                    self.dismiss(None)

            self.app.push_screen(
                TokenConfirmPicker(
                    title="Discard token changes?",
                    body=(
                        "You have unsaved token edits. Close without applying?"
                    ),
                    confirm_label="Discard",
                    cancel_label="Keep editing",
                ),
                _on_confirm,
            )

        def action_apply_changes(self) -> None:
            self.dismiss(copy.deepcopy(self._document) if self._dirty else None)

        def action_add_token(self) -> None:
            self.app.push_screen(
                TokenInputPrompt(
                    mode="add",
                    title="Add token",
                    helper_text=(
                        "Hex values can include spaces. JSON objects: "
                        '{"zero_len":10} or {"pattern_hex":"FF","byte_len":4}.'
                    ),
                ),
                self._on_add_result,
            )

        def _on_add_result(self, result: dict | None) -> None:
            if result is None:
                return
            name = str(result.get("name", "")).strip()
            value_text = str(result.get("value", "")).strip()
            if len(name) == 0 or len(value_text) == 0:
                self._set_status("Add cancelled: name and value are required.")
                return
            try:
                parsed = parse_token_value_argument(value_text)
                created, _prev = set_token_definition(
                    self._document, name, parsed, overwrite=False,
                )
            except TokenSidecarError as error:
                self._set_status(f"Add failed: {error}")
                return
            if created is False:
                self._set_status(
                    f"Token {name} already exists. Press V to change value."
                )
                return
            self._dirty = True
            self._set_status(f"Added token {name}.")
            self._refresh_list()

        def action_set_value(self) -> None:
            name = self._selected_token_name()
            if name is None:
                self._set_status("Select a token first (use ↑/↓).")
                return
            current_rows = build_token_rows(self._document)
            current = next(
                (row for row in current_rows if row["name"] == name),
                None,
            )
            initial_value = ""
            if current is not None:
                raw = current["raw_value"]
                if isinstance(raw, str):
                    initial_value = raw
                elif isinstance(raw, dict):
                    initial_value = json.dumps(raw, ensure_ascii=False)
            self.app.push_screen(
                TokenInputPrompt(
                    mode="value",
                    title=f"Set value for {name}",
                    existing_name=name,
                    existing_value=initial_value,
                    helper_text=(
                        "Leave unchanged to cancel. Hex or JSON object accepted."
                    ),
                ),
                lambda result: self._on_set_value_result(name, result),
            )

        def _on_set_value_result(self, name: str, result: dict | None) -> None:
            if result is None:
                return
            value_text = str(result.get("value", "")).strip()
            if len(value_text) == 0:
                self._set_status("Set value cancelled: value cannot be empty.")
                return
            try:
                parsed = parse_token_value_argument(value_text)
                created, previous = set_token_definition(
                    self._document, name, parsed, overwrite=True,
                )
            except TokenSidecarError as error:
                self._set_status(f"Set value failed: {error}")
                return
            if created is True:
                self._set_status(f"Token {name} added.")
            else:
                self._set_status(f"Token {name} value updated.")
            self._dirty = True
            self._refresh_list()

        def action_rename_token(self) -> None:
            name = self._selected_token_name()
            if name is None:
                self._set_status("Select a token first (use ↑/↓).")
                return
            self.app.push_screen(
                TokenInputPrompt(
                    mode="rename",
                    title=f"Rename token {name}",
                    existing_name=name,
                    helper_text=(
                        "If the current name is referenced inside the buffer "
                        "you will be asked whether to rewrite those refs."
                    ),
                ),
                lambda result: self._on_rename_name_result(name, result),
            )

        def _on_rename_name_result(
            self, old_name: str, result: dict | None
        ) -> None:
            if result is None:
                return
            new_name = str(result.get("name", "")).strip()
            if len(new_name) == 0:
                self._set_status("Rename cancelled: new name cannot be empty.")
                return
            if new_name == old_name:
                self._set_status("Rename cancelled: new name matches existing.")
                return
            try:
                refs = count_token_references(self._document, old_name)
            except TokenSidecarError as error:
                self._set_status(f"Rename failed: {error}")
                return
            if refs["total"] == 0:
                self._finish_rename(old_name, new_name, rewrite_refs=False)
                return
            body = (
                f"{old_name} is referenced {refs['content']} time(s) as content "
                f"and {refs['length']} time(s) as length. Rewrite all refs to "
                f"{new_name} now?"
            )
            self.app.push_screen(
                TokenConfirmPicker(
                    title=f"Rename {old_name} → {new_name}",
                    body=body,
                    confirm_label=f"Rewrite refs to {new_name}",
                    cancel_label="Rename def only",
                ),
                lambda choice: self._on_rename_confirm(
                    old_name, new_name, choice,
                ),
            )

        def _on_rename_confirm(
            self,
            old_name: str,
            new_name: str,
            choice: bool | None,
        ) -> None:
            if choice is None:
                return
            self._finish_rename(old_name, new_name, rewrite_refs=bool(choice))

        def _finish_rename(
            self,
            old_name: str,
            new_name: str,
            *,
            rewrite_refs: bool,
        ) -> None:
            try:
                summary = rename_token_in_template(
                    self._document,
                    old_name,
                    new_name,
                    rewrite_references=rewrite_refs,
                )
            except TokenSidecarError as error:
                self._set_status(f"Rename failed: {error}")
                return
            if summary["renamed_def"] is False:
                self._set_status(
                    f"Rename skipped: {old_name} not found in token defs."
                )
                return
            self._dirty = True
            if rewrite_refs:
                self._set_status(
                    f"Renamed {old_name} → {new_name} and rewrote "
                    f"{summary['content_refs']} content + "
                    f"{summary['length_refs']} length reference(s)."
                )
            else:
                self._set_status(
                    f"Renamed {old_name} → {new_name} (references left "
                    f"pointing at undefined token)."
                )
            self._refresh_list()

        def action_delete_token(self) -> None:
            name = self._selected_token_name()
            if name is None:
                self._set_status("Select a token first (use ↑/↓).")
                return
            try:
                refs = count_token_references(self._document, name)
            except TokenSidecarError as error:
                self._set_status(f"Delete failed: {error}")
                return
            if refs["total"] == 0:
                self._finish_delete(name)
                return
            body = (
                f"{name} is referenced {refs['content']} time(s) as content "
                f"and {refs['length']} time(s) as length. Deleting the def "
                "leaves those refs unresolved."
            )
            self.app.push_screen(
                TokenConfirmPicker(
                    title=f"Delete {name}?",
                    body=body,
                    confirm_label=f"Delete {name}",
                    cancel_label="Keep token",
                ),
                lambda choice: self._on_delete_confirm(name, choice),
            )

        def _on_delete_confirm(self, name: str, choice: bool | None) -> None:
            if choice is None or choice is False:
                return
            self._finish_delete(name)

        def _finish_delete(self, name: str) -> None:
            try:
                removed = remove_token_definition(self._document, name)
            except TokenSidecarError as error:
                self._set_status(f"Delete failed: {error}")
                return
            if removed is None:
                self._set_status(f"Token {name} not found.")
                return
            self._dirty = True
            self._set_status(f"Removed token {name}.")
            self._refresh_list()

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
            f"{resolved_input.name} · Ctrl+S save · Ctrl+T tree actions · Ctrl+A add file · "
            "F3 insert picker · F11/F12 insert after/before · Ctrl+↑/↓ move PE · Ctrl+D remove PE · "
            "Ctrl+C/V text · Ctrl+Y/P/B PE copy/paste · Ctrl+L lint · "
            "Ctrl+K tokens · Ctrl+R resolved preview · Ctrl+Alt+N/P next/prev placeholder · "
            "F4 inspect left · F5/F6/F8/F9 panes · "
            "F7 theme · F10 pane menu · Ctrl+Q quit"
        )
        _PANE_MODE_SEQUENCE = ("der", "inspect", "lint", "none", "decoded")
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
                "decoded": "right_decoded_editor",
                "none": "right_none",
            },
            "bottom_left": {
                "der": "inspect_der_view",
                "inspect": "inspect_log",
                "lint": "inspect_lint_log",
                "decoded": "inspect_decoded_editor",
                "none": "inspect_none",
            },
            "bottom_right": {
                "der": "lint_der_view",
                "inspect": "lint_inspect_log",
                "lint": "lint_log",
                "decoded": "lint_decoded_editor",
                "none": "lint_none",
            },
        }
        _DECODED_SLOT_WIDGETS = {
            "right": {
                "host": "right_decoded_editor",
                "switcher": "right_decoded_switcher",
                "json": "right_decoded_json_editor",
                "structured": "right_decoded_structured_editor",
                "service": "right_decoded_service_editor",
                "raw_hex": "right_decoded_raw_hex",
            },
            "bottom_left": {
                "host": "inspect_decoded_editor",
                "switcher": "inspect_decoded_switcher",
                "json": "inspect_decoded_json_editor",
                "structured": "inspect_decoded_structured_editor",
                "service": "inspect_decoded_service_editor",
                "raw_hex": "inspect_decoded_raw_hex",
            },
            "bottom_right": {
                "host": "lint_decoded_editor",
                "switcher": "lint_decoded_switcher",
                "json": "lint_decoded_json_editor",
                "structured": "lint_decoded_structured_editor",
                "service": "lint_decoded_service_editor",
                "raw_hex": "lint_decoded_raw_hex",
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
            color: $text;
            border-bottom: solid $accent;
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
            background: $boost;
            color: $text;
            text-style: bold;
        }
        #json_editor {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
            background: transparent;
        }
        #json_inner {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #json_outline_shell {
            width: 34;
            min-width: 24;
            max-width: 48;
            height: 100%;
            min-height: 0;
        }
        #json_outline_search {
            width: 100%;
            margin-bottom: 1;
        }
        #json_outline_search_summary {
            width: 100%;
            min-height: 1;
            margin-bottom: 1;
            color: $text-muted;
        }
        #json_outline {
            width: 100%;
            min-width: 24;
            max-width: 48;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
            background: transparent;
        }
        .drag-handle {
            background: $boost;
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
        .placeholder-hud {
            width: 100%;
            height: 1;
            padding: 0 1;
            color: $secondary;
            background: $surface;
            text-style: italic;
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
            border: solid $accent;
            background: transparent;
        }
        .der-pane {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
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
        .decoded-pane {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
            background: $surface;
        }
        .decoded-pane.read-only-pane {
            color: $text;
            background: $boost;
        }
        .decoded-host {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        .decoded-host-switcher {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        .decoded-raw-hex {
            width: 100%;
            height: auto;
            min-height: 1;
            margin-top: 1;
            padding: 0 1;
            background: $boost;
            color: $text;
            border-top: solid $primary;
        }
        .decoded-json-pane {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        .service-table-editor {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
            background: $surface;
            padding: 0 1;
        }
        .service_table_note {
            width: 100%;
            height: auto;
            min-height: 1;
            padding: 0 1;
            background: $boost;
            color: $text;
            border-top: solid $primary;
        }
        .service_table_toolbar {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        .service_table_filter_row {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        .service_table_byte_label {
            width: 16;
            content-align: left middle;
        }
        .service_table_byte_input {
            width: 12;
            margin-right: 1;
        }
        .service_table_filter_label {
            width: 16;
            content-align: left middle;
        }
        .service_table_filter_input {
            width: 1fr;
        }
        .service_table_summary {
            width: 1fr;
            content-align: right middle;
            color: $text;
            background: $boost;
            padding: 0 1;
        }
        .service_table_selection {
            width: 100%;
            height: 1fr;
            min-height: 4;
            margin-top: 1;
            border-top: solid $primary;
            background: $panel;
        }
        .structured-field-editor {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $accent;
            background: $surface;
            padding: 0 1;
        }
        .structured_field_note {
            width: 100%;
            min-height: 1;
            padding: 0 1;
            background: $boost;
            color: $text;
            border-top: solid $primary;
        }
        .structured_field_checkbox {
            width: 100%;
            margin-top: 1;
        }
        .structured_field_row {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        .structured_field_label {
            width: 18;
            content-align: left middle;
            padding-right: 1;
        }
        .structured_field_input {
            width: 1fr;
        }
        .structured_field_summary {
            width: 100%;
            min-height: 1;
            margin-top: 1;
            color: $text;
            background: $boost;
            padding: 0 1;
        }
        .structured_field_options {
            width: 100%;
            height: 1fr;
            min-height: 6;
            margin-top: 1;
            border-top: solid $primary;
            background: $panel;
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
            border-top: solid $accent;
            background: transparent;
        }
        .log-pane {
            height: 1fr;
            min-height: 4;
            border-top: solid $accent;
            background: $surface;
            color: $text;
        }
        .pane-placeholder {
            height: 1fr;
            min-height: 4;
            border-top: solid $accent;
            background: transparent;
            color: $text-muted;
            padding: 0 1;
        }
        #status_line {
            height: 1;
            border-top: solid $accent;
            background: transparent;
            color: $text;
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
            border: thick $accent;
        }
        #pe_opts {
            height: 22;
            min-height: 8;
            margin-top: 1;
            margin-bottom: 1;
        }
        PeInsertTargetPicker {
            align: center middle;
        }
        #pe_insert_target_shell {
            width: 72;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #pe_insert_target_opts {
            height: auto;
            min-height: 4;
            margin-top: 1;
            margin-bottom: 1;
        }
        PeRemoveConfirmPicker {
            align: center middle;
        }
        #pe_remove_confirm_shell {
            width: 84;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #pe_remove_confirm_opts {
            height: auto;
            min-height: 4;
            margin-top: 1;
        }
        PeFilePicker {
            align: center middle;
        }
        #pe_file_picker_shell {
            width: 92;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #pe_file_opts {
            height: 20;
            min-height: 6;
            margin-top: 1;
            margin-bottom: 1;
        }
        TreeContextActionPicker {
            align: center middle;
        }
        #tree_context_picker_shell {
            width: 88;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #tree_context_opts {
            height: auto;
            min-height: 6;
            margin-top: 1;
            margin-bottom: 1;
        }
        KeybindHelpPicker {
            align: center middle;
        }
        #keybind_help_shell {
            width: 110;
            height: 34;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #keybind_help_text {
            height: 1fr;
            min-height: 12;
            margin-top: 1;
            border: solid $accent;
            background: $surface;
        }
        AdfBootstrapPicker {
            align: center middle;
        }
        #adf_bootstrap_shell {
            width: 92;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #adf_bootstrap_fid, #adf_bootstrap_aid {
            width: 1fr;
            margin-top: 1;
            margin-bottom: 1;
        }
        #adf_bootstrap_error {
            min-height: 1;
            margin-top: 1;
        }
        #adf_bootstrap_buttons {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        #adf_bootstrap_cancel, #adf_bootstrap_apply {
            width: 1fr;
        }
        PeFileOverridePicker {
            align: center middle;
        }
        #pe_file_override_shell {
            width: 92;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #pe_file_override_short_efid,
        #pe_file_override_arr_record,
        #pe_file_override_file_size,
        #pe_file_override_record_length,
        #pe_file_override_record_count {
            width: 1fr;
            margin-top: 1;
            margin-bottom: 1;
        }
        #pe_file_override_error {
            min-height: 1;
            margin-top: 1;
        }
        #pe_file_override_buttons {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        #pe_file_override_cancel, #pe_file_override_apply {
            width: 1fr;
        }
        #pane_picker_shell {
            width: 96;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #pane_opts {
            height: 24;
            min-height: 8;
            margin-top: 1;
        }
        TokenManagerPicker {
            align: center middle;
        }
        #token_manager_shell {
            width: 110;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #token_manager_list {
            height: 20;
            min-height: 6;
            margin-top: 1;
            border: solid $accent;
            background: $surface;
        }
        #token_manager_summary, #token_manager_status {
            min-height: 1;
            margin-top: 1;
        }
        TokenInputPrompt {
            align: center middle;
        }
        #token_prompt_shell {
            width: 90;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #token_prompt_name, #token_prompt_value {
            width: 1fr;
            margin-top: 1;
        }
        #token_prompt_error {
            min-height: 1;
            margin-top: 1;
        }
        #token_prompt_buttons {
            width: 100%;
            height: auto;
            margin-top: 1;
        }
        #token_prompt_cancel, #token_prompt_apply {
            width: 1fr;
        }
        TokenConfirmPicker {
            align: center middle;
        }
        #token_confirm_shell {
            width: 80;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            background: $surface;
            border: thick $accent;
        }
        #token_confirm_opts {
            height: auto;
            min-height: 4;
            margin-top: 1;
        }
        """

        BINDINGS = [
            Binding("ctrl+c", "copy_text_selection", "Copy text", show=False, priority=True),
            Binding("ctrl+v", "paste_text_clipboard", "Paste text", show=False, priority=True),
            Binding("ctrl+insert", "copy_text_selection", "Copy text", show=False, priority=True),
            Binding("shift+insert", "paste_text_clipboard", "Paste text", show=False, priority=True),
            Binding("f1", "open_keybind_help", "Key help", priority=True),
            Binding("ctrl+f", "focus_outline_search", "Tree search", priority=True),
            Binding("ctrl+s", "save_refresh", "Save / re-encode", priority=True),
            Binding("ctrl+t", "open_tree_context_menu", "Tree actions", priority=True),
            Binding("ctrl+a", "add_selected_pe_file", "Add file", priority=True),
            Binding("ctrl+up", "move_selected_pe_up", "Move PE up", priority=True),
            Binding("ctrl+down", "move_selected_pe_down", "Move PE down", priority=True),
            Binding("ctrl+d", "remove_selected_pe", "Remove PE", priority=True),
            Binding("ctrl+y", "copy_contextual", "Copy PE", priority=True),
            Binding("ctrl+p", "paste_selected_pe_after", "Paste PE after", priority=True),
            Binding("ctrl+b", "paste_selected_pe_before", "Paste PE before", priority=True),
            Binding("ctrl+l", "run_lint_now", "Run lint", priority=True),
            Binding("ctrl+k", "open_token_manager", "Token manager", priority=True),
            Binding("ctrl+r", "toggle_resolved_preview", "Resolved preview", priority=True),
            Binding(
                "ctrl+alt+n",
                "jump_next_placeholder",
                "Next placeholder",
                priority=True,
            ),
            Binding(
                "ctrl+alt+p",
                "jump_prev_placeholder",
                "Previous placeholder",
                priority=True,
            ),
            Binding("f2", "save_refresh", "Save / re-encode", priority=True),
            Binding("f3", "add_pe_block", "Insert picker", priority=True),
            Binding("ctrl+shift+f", "add_selected_pe_file", "Add file", priority=True),
            Binding("f11", "insert_selected_pe_after_direct", "Insert PE after", priority=True),
            Binding("f12", "insert_selected_pe_before_direct", "Insert PE before", priority=True),
            Binding("ctrl+shift+up", "move_selected_pe_up", "Move PE up", priority=True),
            Binding("ctrl+shift+down", "move_selected_pe_down", "Move PE down", priority=True),
            Binding("ctrl+shift+d", "remove_selected_pe", "Remove PE", priority=True),
            Binding("ctrl+shift+c", "copy_contextual", "Copy PE", priority=True),
            Binding("ctrl+shift+v", "paste_selected_pe_after", "Paste PE after", priority=True),
            Binding("ctrl+shift+b", "paste_selected_pe_before", "Paste PE before", priority=True),
            Binding("ctrl+shift+l", "run_lint_now", "Run lint", priority=True),
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
            self._pending_insert_blocked_ids: set[str] = set()
            self._pending_insert_anchor_key: str | None = None
            self._pending_insert_after = True
            self._pending_remove_section_key: str | None = None
            self._pending_file_section_key: str | None = None
            self._pending_file_context_key: object | None = None
            self._pending_file_group_index: int | None = None
            self._pending_file_target_label = ""
            self._pending_file_insert: dict[str, object] | None = None
            self._adf_bootstrap_memory: dict[str, dict[str, str]] = {}
            self._status_base_text = ""
            self._validation_issue: ValidationIssue | None = None
            self._skip_live_refresh_for_text: str | None = None
            self._editor_document_cache_text: str | None = None
            self._editor_document_cache_value: dict[str, object] | None = None
            self._editor_document_cache_error: Exception | None = None
            self._editor_json_cache_text: str | None = None
            self._editor_json_cache_value: object | None = None
            self._editor_json_cache_error: Exception | None = None
            self._editor_spans_cache_text: str | None = None
            self._editor_spans_cache_value: dict[str, tuple[int, int, int]] | None = None
            self._lint_dirty = True
            self._lint_cached_text: str | None = None
            self._lint_cached_outcome: TuiLintOutcome | None = None
            self._lint_last_trigger = "not-run"
            self._inspect_debounce_gen = 0
            self._inspect_cache_text: str | None = None
            self._inspect_cache_key: tuple[object, ...] | None = None
            self._inspect_cache_body: str | None = None
            self._template_defaults_cache_text: str | None = None
            self._template_defaults_cache: dict[tuple[str, str], str | None] = {}
            self._decoded_debounce_gen = 0
            self._decoded_pane_syncing = False
            self._skip_decoded_change_text: str | None = None
            self._skip_decoded_change_remaining = 0
            self._decoded_pane_context: dict[str, object] | None = None
            self._decoded_pane_context_key: tuple[object, ...] | None = None
            self._decoded_pane_editor_kind = "json"
            self._decoded_pane_payload: dict[str, object] | None = None
            self._decoded_pane_note = ""
            self._decoded_pane_text = "{\n  \"message\": \"Decoded pane not initialized yet.\"\n}\n"
            self._decoded_pane_raw_hex = ""
            self._decoded_pane_dirty = False
            self._outline_visible = True
            self._outline_search_query = ""
            self._outline_search_index = -1
            self._outline_search_match_count = 0
            self._outline_search_selecting = False
            self._pane_modes = dict(self._SLOT_DEFAULTS)
            self._resolved_preview_active = False
            self._resolved_preview_original_text: str | None = None
            self._resolved_preview_banner: str = ""
            self._base_sub_title: str = str(getattr(self.__class__, "SUB_TITLE", "") or "")
            self._placeholder_locations: list[dict[str, object]] = []
            self._placeholder_nav_index: int = -1
            self._token_manager_pre_defs: dict[str, object] = {}
            self._pending_auto_retoken_updated: dict | None = None
            self._pending_auto_retoken_tokens: list[str] = []
            self._token_watcher_path: pathlib.Path | None = None
            self._token_watcher_mtime: float | None = None
            self._token_watcher_last_defs: dict[str, object] = {}
            self._token_watcher_last_style: str = "brace"
            self._token_watcher_prompt_open: bool = False
            self._token_watcher_pending_defs: dict[str, object] | None = None
            self._token_watcher_pending_style: str | None = None
            super().__init__()

        def compose(self) -> ComposeResult:
            with Vertical(id="chrome"):
                yield Static(
                    "SAIP JSON↔DER · Help F1 · Text Ctrl+C/V · Save Ctrl+S/F2 · Tree actions Ctrl+T · "
                    "Add file Ctrl+A · Insert picker F3 · Insert after F11 · Insert before F12 · "
                    "Remove Ctrl+D · Lint Ctrl+L · Inspect F4 · "
                    "Panes F5/F6/F8/F9 · Pane menu F10 · Theme F7 · Quit Ctrl+Q",
                    id="chrome_title",
                )
                with Vertical(id="upper"):
                    with Horizontal(id="split_row"):
                        with Vertical(id="json_col"):
                            yield Static(
                                (
                                    f"JSON editor · tree search Ctrl+F · save dir {transcode_dir_display} · "
                                    f"writes {transcode_json_path.name} + {transcode_der_path.name} + "
                                    f"{transcode_txt_path.name} · "
                                    "placeholders supported"
                                ),
                                classes="pane-caption",
                            )
                            with Horizontal(id="json_inner"):
                                with Vertical(id="json_outline_shell"):
                                    yield Input(
                                        value="",
                                        placeholder="Search outline tree",
                                        id="json_outline_search",
                                    )
                                    yield Static(
                                        (
                                            "Tree search: type to jump · Enter/F3/Ctrl+G next · "
                                            "Ctrl+R previous"
                                        ),
                                        id="json_outline_search_summary",
                                    )
                                    yield Tree("ProfileElements", id="json_outline")
                                yield DragHandle("", id="json_handle", classes="drag-handle")
                                with Vertical(id="json_editor_box"):
                                    yield Static(
                                        "",
                                        id="placeholder_hud",
                                        classes="placeholder-hud",
                                    )
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
                                with Vertical(id="right_decoded_editor", classes="decoded-host"):
                                    with ContentSwitcher(
                                        initial="right_decoded_json_editor",
                                        id="right_decoded_switcher",
                                        classes="decoded-host-switcher",
                                    ):
                                        yield TextArea(
                                            "{}\n",
                                            id="right_decoded_json_editor",
                                            classes="decoded-pane decoded-json-pane",
                                            language="json",
                                            read_only=True,
                                            show_line_numbers=False,
                                        )
                                        yield StructuredDecodedFieldEditor(
                                            id="right_decoded_structured_editor",
                                            classes="structured-field-editor decoded-structured-field",
                                            read_only=True,
                                        )
                                        yield ServiceTableToggleEditor(
                                            id="right_decoded_service_editor",
                                            classes="service-table-editor decoded-service-table",
                                            read_only=True,
                                        )
                                    yield Static("", id="right_decoded_raw_hex", classes="decoded-raw-hex")
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
                                with Vertical(id="inspect_decoded_editor", classes="decoded-host"):
                                    with ContentSwitcher(
                                        initial="inspect_decoded_json_editor",
                                        id="inspect_decoded_switcher",
                                        classes="decoded-host-switcher",
                                    ):
                                        yield TextArea(
                                            "{}\n",
                                            id="inspect_decoded_json_editor",
                                            classes="decoded-pane decoded-json-pane",
                                            language="json",
                                            read_only=True,
                                            show_line_numbers=False,
                                        )
                                        yield StructuredDecodedFieldEditor(
                                            id="inspect_decoded_structured_editor",
                                            classes="structured-field-editor decoded-structured-field",
                                            read_only=True,
                                        )
                                        yield ServiceTableToggleEditor(
                                            id="inspect_decoded_service_editor",
                                            classes="service-table-editor decoded-service-table",
                                            read_only=True,
                                        )
                                    yield Static("", id="inspect_decoded_raw_hex", classes="decoded-raw-hex")
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
                                with Vertical(id="lint_decoded_editor", classes="decoded-host"):
                                    with ContentSwitcher(
                                        initial="lint_decoded_json_editor",
                                        id="lint_decoded_switcher",
                                        classes="decoded-host-switcher",
                                    ):
                                        yield TextArea(
                                            "{}\n",
                                            id="lint_decoded_json_editor",
                                            classes="decoded-pane decoded-json-pane",
                                            language="json",
                                            read_only=True,
                                            show_line_numbers=False,
                                        )
                                        yield StructuredDecodedFieldEditor(
                                            id="lint_decoded_structured_editor",
                                            classes="structured-field-editor decoded-structured-field",
                                            read_only=True,
                                        )
                                        yield ServiceTableToggleEditor(
                                            id="lint_decoded_service_editor",
                                            classes="service-table-editor decoded-service-table",
                                            read_only=True,
                                        )
                                    yield Static("", id="lint_decoded_raw_hex", classes="decoded-raw-hex")
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

        def _is_decoded_text_view(self, widget: object) -> bool:
            return isinstance(widget, TextArea) and widget.has_class("decoded-json-pane")

        def _all_decoded_text_views(self) -> list[TextArea]:
            return [widget for widget in self.query(".decoded-json-pane") if isinstance(widget, TextArea)]

        def _all_decoded_service_views(self) -> list[ServiceTableToggleEditor]:
            return [
                widget
                for widget in self.query(".decoded-service-table")
                if isinstance(widget, ServiceTableToggleEditor)
            ]

        def _all_decoded_structured_views(self) -> list[StructuredDecodedFieldEditor]:
            return [
                widget
                for widget in self.query(".decoded-structured-field")
                if isinstance(widget, StructuredDecodedFieldEditor)
            ]

        def _visible_decoded_text_views(self) -> list[TextArea]:
            views: list[TextArea] = []
            for slot_name, active_mode in self._pane_modes.items():
                if str(active_mode or "").strip().lower() != "decoded":
                    continue
                widget_ids = self._DECODED_SLOT_WIDGETS.get(slot_name)
                if isinstance(widget_ids, dict) is False:
                    continue
                views.append(self.query_one(f"#{widget_ids['json']}", TextArea))
            return views

        def _visible_decoded_service_views(self) -> list[ServiceTableToggleEditor]:
            views: list[ServiceTableToggleEditor] = []
            for slot_name, active_mode in self._pane_modes.items():
                if str(active_mode or "").strip().lower() != "decoded":
                    continue
                widget_ids = self._DECODED_SLOT_WIDGETS.get(slot_name)
                if isinstance(widget_ids, dict) is False:
                    continue
                views.append(
                    self.query_one(
                        f"#{widget_ids['service']}",
                        ServiceTableToggleEditor,
                    )
                )
            return views

        def _visible_decoded_structured_views(self) -> list[StructuredDecodedFieldEditor]:
            views: list[StructuredDecodedFieldEditor] = []
            for slot_name, active_mode in self._pane_modes.items():
                if str(active_mode or "").strip().lower() != "decoded":
                    continue
                widget_ids = self._DECODED_SLOT_WIDGETS.get(slot_name)
                if isinstance(widget_ids, dict) is False:
                    continue
                views.append(
                    self.query_one(
                        f"#{widget_ids['structured']}",
                        StructuredDecodedFieldEditor,
                    )
                )
            return views

        def _all_decoded_raw_hex_views(self) -> list[Static]:
            views: list[Static] = []
            for widget_ids in self._DECODED_SLOT_WIDGETS.values():
                raw_hex_id = widget_ids.get("raw_hex")
                if isinstance(raw_hex_id, str) is False:
                    continue
                try:
                    views.append(self.query_one(f"#{raw_hex_id}", Static))
                except Exception:
                    continue
            return views

        def _decoded_content_mode_for_editor_kind(self, editor_kind: str) -> str:
            normalized_kind = str(editor_kind or "").strip().lower()
            if normalized_kind == "service_table":
                return "service"
            if normalized_kind in STRUCTURED_DECODED_EDITOR_KINDS:
                return "structured"
            return "json"

        def _set_decoded_content_mode(self, mode_name: str) -> None:
            target_key = self._decoded_content_mode_for_editor_kind(mode_name)
            for widget_ids in self._DECODED_SLOT_WIDGETS.values():
                try:
                    switcher = self.query_one(f"#{widget_ids['switcher']}", ContentSwitcher)
                except Exception:
                    continue
                switcher.current = widget_ids[target_key]

        @staticmethod
        def _decoded_placeholder_text(message: str, *, hint: str | None = None) -> str:
            payload: dict[str, str] = {"message": str(message or "").strip()}
            hint_text = str(hint or "").strip()
            if len(hint_text) > 0:
                payload["hint"] = hint_text
            return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

        @staticmethod
        def _decoded_context_key(context: dict[str, object]) -> tuple[object, ...]:
            replacement_path = context.get("replacement_path")
            frozen_path: tuple[object, ...] = ()
            if isinstance(replacement_path, list):
                frozen_path = tuple(replacement_path)
            return (
                frozen_path,
                str(context.get("field_name", "") or "").strip(),
                str(context.get("last_ef_key", "") or "").strip(),
                str(context.get("editor_kind", "") or "").strip().lower(),
                str(context.get("raw_hex", "") or "").strip().upper(),
            )

        @staticmethod
        def _normalize_raw_hex(raw_hex: object) -> str | None:
            compact = "".join(str(raw_hex or "").split()).upper()
            if len(compact) == 0:
                return None
            if len(compact) % 2 != 0:
                return None
            if any(ch not in "0123456789ABCDEF" for ch in compact):
                return None
            return compact

        @classmethod
        def _decoded_raw_hex_rows(cls, raw_hex: object) -> list[str]:
            normalized = cls._normalize_raw_hex(raw_hex)
            if normalized is None:
                return []
            octets = [normalized[idx : idx + 2] for idx in range(0, len(normalized), 2)]
            return [" ".join(octets[idx : idx + 16]) for idx in range(0, len(octets), 16)]

        @classmethod
        def _decoded_raw_hex_renderable(cls, raw_hex: object) -> Text:
            normalized = cls._normalize_raw_hex(raw_hex)
            if normalized is None:
                return Text("")
            renderable = Text(
                f"Raw hex [{len(normalized) // 2}B]",
                style="bold #8FBCBB",
            )
            rows = cls._decoded_raw_hex_rows(normalized)
            if len(rows) > 0:
                renderable.append("\n")
                renderable.append("\n".join(rows), style="#E5E9F0")
            return renderable

        def _raw_hex_from_encoded_value(self, value: object) -> str | None:
            if isinstance(value, dict):
                return self._normalize_raw_hex(_hex_from_tagged_bytes(value))
            return None

        def _current_decoded_raw_hex(self) -> str | None:
            context = self._decoded_pane_context
            if isinstance(context, dict) is False:
                return None
            fallback_raw_hex = self._normalize_raw_hex(context.get("raw_hex"))
            field_name = str(context.get("field_name", "") or "").strip()
            if len(field_name) == 0:
                return fallback_raw_hex
            payload = self._decoded_pane_payload
            if self._decoded_pane_editor_kind in ("json", "roundtrip_decoded", "raw_hex_decoded"):
                if self._decoded_pane_dirty:
                    try:
                        parsed_payload = json.loads(str(self._decoded_pane_text or "").strip())
                    except Exception:
                        return fallback_raw_hex
                    if isinstance(parsed_payload, dict):
                        payload = parsed_payload
                elif isinstance(payload, dict) is False:
                    candidate_payload = context.get("payload")
                    if isinstance(candidate_payload, dict):
                        payload = candidate_payload
            elif isinstance(payload, dict) is False:
                candidate_payload = context.get("payload")
                if isinstance(candidate_payload, dict):
                    payload = candidate_payload
            if isinstance(payload, dict) is False:
                return fallback_raw_hex
            target_length_value = context.get("target_length")
            if isinstance(target_length_value, int) is False or isinstance(target_length_value, bool):
                target_length_value = None
            try:
                encoded_value = encode_decoded_value_editor_payload(
                    field_name=field_name,
                    editor_payload=payload,
                    last_ef_key=str(context.get("last_ef_key", "") or "").strip() or None,
                    target_length=target_length_value,
                    editor_kind=self._decoded_pane_editor_kind,
                )
            except Exception:
                return fallback_raw_hex
            raw_hex = self._raw_hex_from_encoded_value(encoded_value)
            if raw_hex is not None:
                return raw_hex
            return fallback_raw_hex

        def _refresh_decoded_raw_hex_views(self) -> None:
            raw_hex = self._current_decoded_raw_hex()
            self._decoded_pane_raw_hex = raw_hex or ""
            show = self._normalize_raw_hex(raw_hex) is not None
            for view in self._all_decoded_raw_hex_views():
                view.display = show
                view.update(self._decoded_raw_hex_renderable(raw_hex) if show else "")

        def _set_decoded_text_views_state(self, text: str, *, read_only: bool) -> None:
            normalized_text = str(text or "")
            if normalized_text.endswith("\n") is False:
                normalized_text += "\n"
            self._skip_decoded_change_text = normalized_text
            self._skip_decoded_change_remaining = len(self._all_decoded_text_views())
            self._decoded_pane_syncing = True
            try:
                self._set_decoded_content_mode("json")
                for view in self._all_decoded_text_views():
                    if view.text != normalized_text:
                        view.text = normalized_text
                    view.read_only = read_only
                    view.set_class(read_only, "read-only-pane")
            finally:
                self._decoded_pane_syncing = False
            self._decoded_pane_text = normalized_text
            self._refresh_slot_captions()
            self._refresh_decoded_raw_hex_views()

        def _set_service_table_views_state(
            self,
            payload: dict[str, object],
            *,
            note: str,
            read_only: bool,
        ) -> None:
            normalized_payload = copy.deepcopy(payload)
            self._decoded_pane_payload = copy.deepcopy(normalized_payload)
            self._decoded_pane_note = str(note or "").strip()
            self._set_decoded_content_mode("service_table")
            for view in self._all_decoded_service_views():
                view.set_payload(
                    normalized_payload,
                    note=self._decoded_pane_note,
                    read_only=read_only,
                )
            self._refresh_slot_captions()
            self._refresh_decoded_raw_hex_views()

        def _set_structured_field_views_state(
            self,
            editor_kind: str,
            payload: dict[str, object],
            *,
            note: str,
            read_only: bool,
        ) -> None:
            normalized_payload = copy.deepcopy(payload)
            self._decoded_pane_payload = copy.deepcopy(normalized_payload)
            self._decoded_pane_note = str(note or "").strip()
            self._set_decoded_content_mode(editor_kind)
            for view in self._all_decoded_structured_views():
                view.set_editor_state(
                    editor_kind=editor_kind,
                    payload=normalized_payload,
                    note=self._decoded_pane_note,
                    read_only=read_only,
                )
            self._refresh_slot_captions()
            self._refresh_decoded_raw_hex_views()

        def _refresh_decoded_panel(self, *, force: bool = False) -> None:
            # Decoded pane is a pure viewer in v1; the Decoded Editor
            # feature has been carved out to the V2 GUI (see
            # ``V2_UNIVERSAL_GUI_PLAN.md`` section 7.5). Every state
            # transition below forces ``read_only=True`` so the inline
            # structured / service-table widgets render the decoded
            # payload without accepting edits.
            if self._has_visible_mode("decoded") is False:
                return
            try:
                context = self._decoded_edit_context_for_selection()
            except Exception as exc:
                self._decoded_pane_context = None
                self._decoded_pane_context_key = None
                self._decoded_pane_editor_kind = "json"
                self._decoded_pane_payload = None
                self._decoded_pane_note = ""
                self._decoded_pane_dirty = False
                self._set_decoded_text_views_state(
                    self._decoded_placeholder_text(
                        "Decoded pane failed to build for the current selection.",
                        hint=str(exc),
                    ),
                    read_only=True,
                )
                return
            if isinstance(context, dict) is False:
                self._decoded_pane_context = None
                self._decoded_pane_context_key = None
                self._decoded_pane_editor_kind = "json"
                self._decoded_pane_payload = None
                self._decoded_pane_note = ""
                self._decoded_pane_dirty = False
                self._set_decoded_text_views_state(
                    self._decoded_placeholder_text(
                        "Decoded view is not available for the current selection.",
                        hint="Move the JSON cursor onto a supported decoded field.",
                    ),
                    read_only=True,
                )
                return
            context_key = self._decoded_context_key(context)
            payload_text = str(context.get("payload_text", "") or "{}")
            editor_kind = str(context.get("editor_kind", "json") or "json").strip().lower()
            payload = context.get("payload")
            if isinstance(payload, dict) is False:
                payload = {}
            self._decoded_pane_context = context
            self._decoded_pane_context_key = context_key
            self._decoded_pane_editor_kind = editor_kind
            self._decoded_pane_note = str(context.get("note", "") or "").strip()
            self._decoded_pane_dirty = False
            if editor_kind == "service_table":
                self._set_service_table_views_state(
                    payload,
                    note=self._decoded_pane_note,
                    read_only=True,
                )
                return
            if editor_kind in STRUCTURED_DECODED_EDITOR_KINDS:
                self._set_structured_field_views_state(
                    editor_kind,
                    payload,
                    note=self._decoded_pane_note,
                    read_only=True,
                )
                return
            self._decoded_pane_payload = copy.deepcopy(payload)
            self._set_decoded_text_views_state(payload_text, read_only=True)

        def _has_visible_mode(self, mode_name: str) -> bool:
            normalized_mode = str(mode_name or "").strip().lower()
            return any(
                str(mode or "").strip().lower() == normalized_mode
                for mode in self._pane_modes.values()
            )

        def _visible_logs_for_mode(self, mode_name: str) -> list[RichLog]:
            normalized_mode = str(mode_name or "").strip().lower()
            logs: list[RichLog] = []
            for slot_name, active_mode in self._pane_modes.items():
                if str(active_mode or "").strip().lower() != normalized_mode:
                    continue
                widget_id = self._SLOT_MODE_WIDGETS[slot_name].get(normalized_mode)
                if widget_id is None:
                    continue
                widget = self.query_one(f"#{widget_id}", RichLog)
                logs.append(widget)
            return logs

        def _parse_editor_document_cached(self, editor_text: str) -> dict[str, object]:
            text = str(editor_text or "")
            if text == self._editor_document_cache_text:
                if self._editor_document_cache_error is not None:
                    raise self._editor_document_cache_error
                if self._editor_document_cache_value is None:
                    raise ValueError("Parsed editor document cache is empty.")
                return self._editor_document_cache_value
            try:
                document = parse_editor_json(text)
            except Exception as exc:
                self._editor_document_cache_text = text
                self._editor_document_cache_value = None
                self._editor_document_cache_error = exc
                raise
            self._editor_document_cache_text = text
            self._editor_document_cache_value = document
            self._editor_document_cache_error = None
            return document

        def _load_editor_json_cached(self, editor_text: str) -> object:
            text = str(editor_text or "")
            if text == self._editor_json_cache_text:
                if self._editor_json_cache_error is not None:
                    raise self._editor_json_cache_error
                return self._editor_json_cache_value
            stripped = text.strip()
            try:
                loaded = json.loads(stripped)
            except Exception as exc:
                self._editor_json_cache_text = text
                self._editor_json_cache_value = None
                self._editor_json_cache_error = exc
                raise
            self._editor_json_cache_text = text
            self._editor_json_cache_value = loaded
            self._editor_json_cache_error = None
            return loaded

        def _current_editor_document(self) -> dict[str, object]:
            editor = self.query_one("#json_editor", TextArea)
            return self._parse_editor_document_cached(editor.text)

        def _set_editor_text_programmatically(self, editor: TextArea, text: str) -> None:
            self._skip_live_refresh_for_text = str(text)
            editor.text = str(text)

        def _mark_lint_dirty(self) -> None:
            self._lint_dirty = True

        def _mode_display_name(self, mode_name: str) -> str:
            return {
                "der": "DER",
                "inspect": "Inspect",
                "lint": "Lint",
                "decoded": "Decoded view",
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
                return f"{title}: profile lint (manual or save)"
            if mode == "decoded":
                view_label = "decoded view"
                if self._decoded_pane_editor_kind == "service_table":
                    view_label = "service table view"
                elif self._decoded_pane_editor_kind in STRUCTURED_DECODED_EDITOR_KINDS:
                    view_label = "field view"
                return (
                    f"{title}: {view_label} · read-only · "
                    "follows selected field"
                )
            return f"{title}: hidden"

        @staticmethod
        def _render_inspect_log_line(line: str) -> Text:
            raw = str(line or "")
            stripped = raw.strip()
            if len(stripped) == 0:
                return Text("")
            if stripped.startswith("[") and stripped.endswith("]"):
                return Text(stripped, style="bold #ECEFF4 on #434C5E")
            if stripped in {
                "Field semantics",
                "EF payload",
                "X.509 certificate",
                "ASN.1 / BER",
                "Binary summary",
                "Template defaults",
                "Standard template values:",
                "Implicit here because the JSON omits them:",
                "Template parameters without a universal default:",
            }:
                return Text(stripped, style="bold #EBCB8B")
            if stripped.startswith("JSON parse error"):
                return Text(raw, style="bold #BF616A")
            if stripped.startswith("No decodable") or stripped.startswith("Empty selection span"):
                return Text(raw, style="#81A1C1")
            leading_ws = raw[: len(raw) - len(raw.lstrip(" "))]
            visible = raw[len(leading_ws) :]
            if visible.startswith("- "):
                text = Text(leading_ws)
                text.append("- ", style="bold #88C0D0")
                text.append(visible[2:], style="#ECEFF4")
                return text
            if ":" in visible and len(visible) > 0 and visible[0].isalnum():
                key_text, remainder = visible.split(":", 1)
                key_style = "bold #88C0D0"
                if key_text in {
                    "PE",
                    "Template OID",
                    "Template mode",
                    "Base root",
                    "Selected file",
                    "Source",
                    "Size",
                    "Decoder error",
                }:
                    key_style = "bold #EBCB8B"
                text = Text(leading_ws)
                text.append(f"{key_text}:", style=key_style)
                text.append(remainder, style="#ECEFF4")
                return text
            return Text(raw, style="#ECEFF4")

        def _refresh_slot_captions(self) -> None:
            for slot_name, caption_id in self._SLOT_CAPTIONS.items():
                try:
                    caption = self.query_one(f"#{caption_id}", Static)
                except Exception:
                    continue
                caption.update(self._slot_caption_text(slot_name))

        @staticmethod
        def _tree_node_label_text(node: TreeNode[object]) -> str:
            label = getattr(node, "label", "")
            plain_text = getattr(label, "plain", None)
            if isinstance(plain_text, str):
                return plain_text.strip()
            return str(label or "").strip()

        def _iter_outline_nodes(self, node: TreeNode[object]) -> list[TreeNode[object]]:
            nodes: list[TreeNode[object]] = [node]
            for child in node.children:
                nodes.extend(self._iter_outline_nodes(child))
            return nodes

        def _refresh_outline_search_highlighting(
            self,
            query_text: str,
            *,
            active_node: TreeNode[object] | None = None,
        ) -> None:
            tree = self.query_one("#json_outline", Tree)
            for child in tree.root.children:
                for node in self._iter_outline_nodes(child):
                    plain_label = self._tree_node_label_text(node)
                    node.set_label(
                        _highlight_query_text(
                            plain_label,
                            query_text,
                            active=node is active_node and len(str(query_text or "").strip()) > 0,
                        )
                    )

        def _outline_search_matches(self, query_text: str) -> list[TreeNode[object]]:
            normalized_query = str(query_text or "").strip().lower()
            if len(normalized_query) == 0:
                return []
            tree = self.query_one("#json_outline", Tree)
            matches: list[TreeNode[object]] = []
            for child in tree.root.children:
                for node in self._iter_outline_nodes(child):
                    label_text = self._tree_node_label_text(node).lower()
                    if len(label_text) == 0:
                        continue
                    if normalized_query in label_text:
                        matches.append(node)
            return matches

        def _set_outline_search_summary(self, text: str) -> None:
            try:
                summary = self.query_one("#json_outline_search_summary", Static)
            except Exception:
                return
            summary.update(str(text or ""))

        def _expand_outline_ancestors(self, node: TreeNode[object]) -> None:
            chain: list[TreeNode[object]] = []
            current: TreeNode[object] | None = node.parent
            while isinstance(current, TreeNode):
                chain.append(current)
                current = current.parent
            for item in reversed(chain):
                item.expand()

        def _outline_search_input_focused(self) -> bool:
            focused = self.focused
            if isinstance(focused, Input) is False:
                return False
            return str(focused.id or "").strip() == "json_outline_search"

        def _focus_outline_search_match(
            self,
            matches: list[TreeNode[object]],
            match_index: int,
            *,
            query_text: str,
            jump_to_editor: bool,
            report_status: bool,
        ) -> bool:
            if len(matches) == 0:
                self._outline_search_index = -1
                self._outline_search_match_count = 0
                self._refresh_outline_search_highlighting(query_text, active_node=None)
                self._set_outline_search_summary(f'No tree matches for "{query_text}".')
                if report_status:
                    self._set_status(f'Tree search found no matches for "{query_text}".', remember=False)
                return False
            normalized_index = match_index % len(matches)
            node = matches[normalized_index]
            self._outline_search_index = normalized_index
            self._outline_search_match_count = len(matches)
            self._refresh_outline_search_highlighting(query_text, active_node=node)
            self._expand_outline_ancestors(node)
            tree = self.query_one("#json_outline", Tree)
            self._outline_search_selecting = True
            try:
                tree.select_node(node)
                tree.move_cursor(node, animate=False)
                tree.scroll_to_node(node, animate=False)
            finally:
                self._outline_search_selecting = False
            label_text = self._tree_node_label_text(node)
            self._set_outline_search_summary(
                f'{normalized_index + 1}/{len(matches)} matches for "{query_text}" · {label_text}'
            )
            if self._has_visible_mode("inspect"):
                self._refresh_inspect_panel()
            if jump_to_editor:
                span = self._outline_data_span(node.data)
                if span is not None:
                    keep_search_focus = self._outline_search_input_focused()
                    self._jump_editor_to_span(
                        span[0],
                        span[1],
                        focus_editor=keep_search_focus is False,
                        preserve_exact_span=self._outline_preserves_exact_span(node.data),
                    )
                    if keep_search_focus:
                        try:
                            self.query_one("#json_outline_search", Input).focus()
                        except Exception:
                            pass
            if report_status:
                self._set_status(
                    f'Tree search "{query_text}" -> {normalized_index + 1}/{len(matches)}: {label_text}',
                    remember=False,
                )
            return True

        def _apply_outline_search(
            self,
            *,
            reset_index: bool,
            step: int = 0,
            jump_to_editor: bool,
            report_status: bool,
        ) -> bool:
            try:
                search_input = self.query_one("#json_outline_search", Input)
            except Exception:
                return False
            query_text = str(search_input.value or "").strip()
            self._outline_search_query = query_text
            if len(query_text) == 0:
                self._outline_search_index = -1
                self._outline_search_match_count = 0
                self._refresh_outline_search_highlighting("", active_node=None)
                self._set_outline_search_summary(
                    "Tree search: type to jump · Enter/F3/Ctrl+G next · Ctrl+R previous"
                )
                return False
            matches = self._outline_search_matches(query_text)
            if len(matches) == 0:
                return self._focus_outline_search_match(
                    matches,
                    0,
                    query_text=query_text,
                    jump_to_editor=jump_to_editor,
                    report_status=report_status,
                )
            if reset_index or self._outline_search_index < 0 or self._outline_search_index >= len(matches):
                match_index = 0
            else:
                match_index = self._outline_search_index
            if step != 0:
                match_index = (match_index + step) % len(matches)
            return self._focus_outline_search_match(
                matches,
                match_index,
                query_text=query_text,
                jump_to_editor=jump_to_editor,
                report_status=report_status,
            )

        def _persist_pane_layout(self) -> None:
            persist_pane_layout_prefs(
                workspace_root,
                outline_visible=self._outline_visible,
                right_mode=self._pane_modes["right"],
                bottom_left_mode=self._pane_modes["bottom_left"],
                bottom_right_mode=self._pane_modes["bottom_right"],
            )

        def _apply_pane_layout(self) -> None:
            outline_shell = self.query_one("#json_outline_shell", Vertical)
            json_handle = self.query_one("#json_handle")
            outline_shell.display = self._outline_visible
            json_handle.display = self._outline_visible

            for slot_name, switcher_id in self._SLOT_SWITCHERS.items():
                switcher = self.query_one(f"#{switcher_id}", ContentSwitcher)
                switcher.current = self._SLOT_MODE_WIDGETS[slot_name][self._pane_modes[slot_name]]
            self._refresh_slot_captions()

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

        def action_focus_outline_search(self) -> None:
            if self._outline_visible is False:
                self._outline_visible = True
                self._persist_pane_layout()
                self._apply_pane_layout()
            search_input = self.query_one("#json_outline_search", Input)
            search_input.focus()
            self._set_status(
                (
                    "Tree search focused. Type to jump through outline labels; "
                    "Enter/F3/Ctrl+G moves next and Ctrl+R moves previous."
                ),
                remember=False,
            )

        def _advance_outline_search(self, step: int) -> None:
            if self._outline_visible is False:
                self.action_focus_outline_search()
            try:
                search_input = self.query_one("#json_outline_search", Input)
            except Exception:
                return
            query_text = str(search_input.value or "").strip()
            if len(query_text) == 0:
                search_input.focus()
                self._set_status("Enter a tree search query first.", remember=False)
                return
            reset_index = False
            if query_text != self._outline_search_query:
                reset_index = True
            if self._outline_search_match_count <= 0:
                reset_index = True
            if self._outline_search_index < 0:
                reset_index = True
            effective_step = step
            if reset_index and step > 0:
                effective_step = 0
            self._apply_outline_search(
                reset_index=reset_index,
                step=effective_step,
                jump_to_editor=True,
                report_status=True,
            )
            if self._outline_search_input_focused() is False:
                try:
                    search_input.focus()
                except Exception:
                    pass

        def action_next_outline_search_result(self) -> None:
            self._advance_outline_search(1)

        def action_previous_outline_search_result(self) -> None:
            self._advance_outline_search(-1)

        def action_open_keybind_help(self) -> None:
            self.push_screen(KeybindHelpPicker())

        def action_open_tree_context_menu(self) -> None:
            tree = self.query_one("#json_outline", Tree)
            node = tree.cursor_node
            if node is None:
                self._set_status("Tree actions: select an outline node first.", remember=False)
                return
            self._open_tree_context_menu(node_label=str(node.label))

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
            self._editor_document_cache_text = self._json_snapshot
            self._editor_document_cache_value = document
            self._editor_document_cache_error = None
            self._editor_json_cache_text = self._json_snapshot
            self._editor_json_cache_value = json.loads(self._json_snapshot)
            self._editor_json_cache_error = None
            self._keys: list[str] = ordered_section_keys_from_pes(self._pes)
            self._byte_ranges: list[tuple[str, int, int]] = []
            self._ranges_by_key: dict[str, tuple[int, int]] = {}
            self._json_spans: dict[str, tuple[int, int]] = {}
            self._rebuild_peer_map()
            self._editor_spans_cache_text = self._json_snapshot
            self._editor_spans_cache_value = self._json_spans
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
            self._refresh_placeholder_hud(self._json_snapshot)
            self._init_token_defs_watcher(resolved_input)

        def _set_status(self, message: str, *, remember: bool = True) -> None:
            if remember:
                self._status_base_text = str(message or "")
            stat = self.query_one("#status_line", Static)
            if self._validation_issue is not None:
                return
            stat.remove_class("error-state")
            stat.update(str(message or ""))

        def _notify_user_action(
            self,
            message: str,
            *,
            title: str = "",
            severity: str = "information",
            status_message: str | None = None,
            remember_status: bool = False,
        ) -> None:
            """
            Show user-driven action feedback as both a status-bar line and a
            toast notification. The status bar is easy to overlook when the
            focused widget is a multi-line text area or when the user is
            tracking the tree cursor, so we surface the same message as a
            transient toast for redundancy. Failure paths (``severity`` in
            ``{"warning", "error"}``) therefore never silently no-op.
            """
            text = str(message or "").strip()
            if len(text) == 0:
                return
            status_text = status_message if status_message is not None else text
            self._set_status(str(status_text or ""), remember=remember_status)
            try:
                self.notify(text, title=str(title or ""), severity=severity)
            except Exception:
                pass

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
            if self._is_decoded_text_view(event.text_area):
                # Decoded pane is read-only in v1 (decoded-edit moved
                # to V2 GUI); only the programmatic-update skip
                # counter needs to run here.
                if self._decoded_pane_syncing:
                    return
                current_text = str(event.text_area.text or "")
                if (
                    self._skip_decoded_change_remaining > 0
                    and current_text == self._skip_decoded_change_text
                ):
                    self._skip_decoded_change_remaining -= 1
                    if self._skip_decoded_change_remaining == 0:
                        self._skip_decoded_change_text = None
                return
            if event.text_area.id != "json_editor":
                return
            if str(event.text_area.text or "") == self._skip_live_refresh_for_text:
                self._skip_live_refresh_for_text = None
                return
            self._lint_debounce_gen += 1
            generation = self._lint_debounce_gen
            self._mark_lint_dirty()
            self._refresh_placeholder_hud(str(event.text_area.text or ""))

            def maybe_refresh() -> None:
                if generation != self._lint_debounce_gen:
                    return
                try:
                    self._refresh_validation_feedback()
                    self._refresh_json_outline()
                    self._refresh_bottom_panel()
                except Exception:
                    return

            self.set_timer(0.48, maybe_refresh)

        def _schedule_inspect_refresh(self, *, delay: float = 0.08) -> None:
            if self._left_inspect_mode != "selection":
                return
            if self._has_visible_mode("inspect") is False:
                return
            self._inspect_debounce_gen += 1
            generation = self._inspect_debounce_gen

            def maybe_refresh() -> None:
                if generation != self._inspect_debounce_gen:
                    return
                try:
                    self._refresh_inspect_panel()
                except Exception:
                    return

            self.set_timer(delay, maybe_refresh)

        def _schedule_decoded_refresh(self, *, delay: float = 0.08) -> None:
            if self._has_visible_mode("decoded") is False:
                return
            self._decoded_debounce_gen += 1
            generation = self._decoded_debounce_gen

            def maybe_refresh() -> None:
                if generation != self._decoded_debounce_gen:
                    return
                try:
                    self._refresh_decoded_panel()
                except Exception:
                    return

            self.set_timer(delay, maybe_refresh)

        def action_toggle_inspect_left_mode(self) -> None:
            if self._left_inspect_mode == "selection":
                self._left_inspect_mode = "profile_asn1"
            else:
                self._left_inspect_mode = "selection"
            self._apply_pane_layout()
            self._refresh_inspect_panel()
            self._refresh_decoded_panel()

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
                json_outline_shell = self.query_one("#json_outline_shell", Vertical)
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
            json_outline_shell.styles.width = self._json_outline_width
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
                    int(self.query_one("#json_outline_shell", Vertical).region.width),
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

        def _scan_object_member_entries(
            self,
            text: str,
            start: int,
            end: int,
        ) -> list[tuple[str, int, int, int, int]]:
            return scan_json_object_member_entries(text, start, end)

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

        def _member_key_for_offset(
            self,
            text: str,
            offset: int,
        ) -> str | None:
            pe_key = self._section_key_for_offset(text, offset)
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
            for key_text, key_start, key_end, member_start, member_end in self._scan_object_member_entries(
                text,
                value_start,
                value_end,
            ):
                if key_start <= offset < key_end:
                    return key_text
                if member_start <= offset < member_end:
                    return key_text
            return None

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
            for (
                key_text,
                key_start,
                key_end,
                member_start,
                member_end,
            ) in self._scan_object_member_entries(
                text,
                value_start,
                value_end,
            ):
                if key_start <= focus_span[0] < key_end:
                    return key_text
                if member_start == focus_span[0] and member_end == focus_span[1]:
                    return key_text
                if focus_span[0] >= member_start and focus_span[1] <= member_end:
                    return key_text
            return None

        def _json_get_by_path(self, value: object, path: list[object]) -> object:
            current = value
            for part in path:
                if isinstance(part, int):
                    if isinstance(current, list) is False:
                        raise KeyError(part)
                    current = current[part]
                    continue
                if isinstance(current, dict) is False:
                    raise KeyError(part)
                current = current[part]
            return current

        def _json_set_by_path(self, value: object, path: list[object], replacement: object) -> None:
            if len(path) == 0:
                raise ValueError("Decoded editor target path must not be empty.")
            parent = self._json_get_by_path(value, path[:-1]) if len(path) > 1 else value
            last = path[-1]
            if isinstance(last, int):
                if isinstance(parent, list) is False:
                    raise KeyError(last)
                parent[last] = replacement
                return
            if isinstance(parent, dict) is False:
                raise KeyError(last)
            parent[last] = replacement

        def _json_path_for_offset(
            self,
            text: str,
            start: int,
            end: int,
            offset: int,
            path: list[object] | None = None,
        ) -> tuple[list[object], tuple[int, int]]:
            current_path = list(path or [])
            cursor = max(start, min(offset, max(start, end - 1)))
            value_start = start
            while value_start < end and text[value_start] in " \t\r\n":
                value_start += 1
            if value_start >= end:
                return (current_path, (start, end))
            lead = text[value_start]
            if lead == "{":
                for key_text, _key_start, _key_end, member_start, member_end in self._scan_object_member_entries(
                    text,
                    value_start,
                    end,
                ):
                    if member_start <= cursor < member_end:
                        return self._json_path_for_offset(
                            text,
                            member_start,
                            member_end,
                            cursor,
                            current_path + [key_text],
                        )
                return (current_path, (value_start, end))
            if lead == "[":
                for index, (item_start, item_end) in enumerate(
                    self._scan_list_items(text, value_start, end)
                ):
                    if item_start <= cursor < item_end:
                        return self._json_path_for_offset(
                            text,
                            item_start,
                            item_end,
                            cursor,
                            current_path + [index],
                        )
                return (current_path, (value_start, end))
            return (current_path, (value_start, end))

        def _decoded_edit_context_for_selection(self) -> dict[str, object] | None:
            editor = self.query_one("#json_editor", TextArea)
            text = str(editor.text or "")
            stripped = text.lstrip()
            if len(stripped) == 0:
                return None
            root_start = len(text) - len(stripped)
            root_end = _scan_json_value_end(text, root_start)
            sel = editor.selection
            cursor_offset = location_to_offset(text, sel.start)
            loaded = json.loads(text)
            path, _value_span = self._json_path_for_offset(
                text,
                root_start,
                root_end,
                cursor_offset,
            )
            if len(path) == 0:
                return None
            replacement_path = list(path)
            field_name: str | None = None
            raw_value = self._json_get_by_path(loaded, replacement_path)
            if (
                len(replacement_path) > 0
                and isinstance(replacement_path[-1], str)
                and replacement_path[-1] in {_TAG_BYTES, _LEGACY_TAG_BYTES}
            ):
                replacement_path = replacement_path[:-1]
                raw_value = self._json_get_by_path(loaded, replacement_path)
                if (
                    len(replacement_path) >= 2
                    and replacement_path[-2] in {_TAG_TUPLE, _LEGACY_TAG_TUPLE}
                    and replacement_path[-1] == 1
                ):
                    tuple_tag = self._json_get_by_path(
                        loaded,
                        replacement_path[:-1] + [0],
                    )
                    if isinstance(tuple_tag, str):
                        field_name = tuple_tag
                elif len(replacement_path) > 0 and isinstance(replacement_path[-1], str):
                    field_name = replacement_path[-1]
            elif (
                len(replacement_path) >= 2
                and replacement_path[-2] in {_TAG_TUPLE, _LEGACY_TAG_TUPLE}
                and replacement_path[-1] == 1
            ):
                tuple_tag = self._json_get_by_path(
                    loaded,
                    replacement_path[:-1] + [0],
                )
                if isinstance(tuple_tag, str):
                    field_name = tuple_tag
            elif isinstance(replacement_path[-1], str):
                field_name = replacement_path[-1]
            if field_name is None:
                return None
            pe_key = None
            if len(replacement_path) >= 2 and replacement_path[0] == "sections":
                if isinstance(replacement_path[1], str):
                    pe_key = replacement_path[1]
            last_ef_key = None
            if len(replacement_path) >= 3 and replacement_path[0] == "sections":
                candidate = replacement_path[2]
                if isinstance(candidate, str) and candidate.startswith("ef-"):
                    last_ef_key = candidate
            model = build_decoded_value_editor_model(
                field_name=field_name,
                raw_value=raw_value,
                last_ef_key=last_ef_key,
                pe_section_key=pe_key,
            )
            if isinstance(model, dict) is False and isinstance(raw_value, list):
                for item_index, item in enumerate(raw_value):
                    if isinstance(item, dict) is False:
                        continue
                    tagged = item.get(_TAG_TUPLE, item.get(_LEGACY_TAG_TUPLE))
                    if isinstance(tagged, list) is False:
                        continue
                    if len(tagged) < 2:
                        continue
                    candidate_field_name = tagged[0]
                    if isinstance(candidate_field_name, str) is False:
                        continue
                    candidate_raw_value = tagged[1]
                    candidate_model = build_decoded_value_editor_model(
                        field_name=candidate_field_name,
                        raw_value=candidate_raw_value,
                        last_ef_key=last_ef_key,
                        pe_section_key=pe_key,
                    )
                    if isinstance(candidate_model, dict) is False:
                        continue
                    replacement_path = replacement_path + [item_index, _TAG_TUPLE, 1]
                    field_name = candidate_field_name
                    raw_value = candidate_raw_value
                    model = candidate_model
                    break
            if isinstance(model, dict) is False:
                roundtrip_model = build_decoded_value_roundtrip_model(
                    field_name=field_name,
                    raw_value=raw_value,
                    last_ef_key=last_ef_key,
                    pe_section_key=pe_key,
                )
                if isinstance(roundtrip_model, dict):
                    roundtrip_payload = roundtrip_model.get("payload", {})
                    if isinstance(roundtrip_payload, dict) is False:
                        roundtrip_payload = {"value": roundtrip_payload}
                    return {
                        "replacement_path": replacement_path,
                        "field_name": field_name,
                        "last_ef_key": last_ef_key,
                        "pe_key": pe_key,
                        "raw_hex": self._normalize_raw_hex(_hex_from_tagged_bytes(raw_value)),
                        "title": str(roundtrip_model.get("title", "") or "Decoded editor"),
                        "note": roundtrip_model.get("note"),
                        "editor_kind": "roundtrip_decoded",
                        "payload": copy.deepcopy(roundtrip_payload),
                        "payload_text": json.dumps(
                            roundtrip_payload,
                            indent=2,
                            ensure_ascii=False,
                        ),
                        "target_length": roundtrip_model.get("target_length"),
                    }
                readonly_view = build_decoded_value_readonly_view(
                    field_name=field_name,
                    raw_value=raw_value,
                    last_ef_key=last_ef_key,
                    pe_section_key=pe_key,
                )
                if isinstance(readonly_view, dict):
                    readonly_payload = readonly_view.get("payload", {})
                    if isinstance(readonly_payload, dict) is False:
                        readonly_payload = {"value": readonly_payload}
                    return {
                        "replacement_path": replacement_path,
                        "field_name": field_name,
                        "last_ef_key": last_ef_key,
                        "pe_key": pe_key,
                        "raw_hex": self._normalize_raw_hex(_hex_from_tagged_bytes(raw_value)),
                        "title": str(readonly_view.get("title", "") or "Read-only decode"),
                        "note": readonly_view.get("note"),
                        "editor_kind": "readonly_json",
                        "payload": copy.deepcopy(readonly_payload),
                        "payload_text": json.dumps(
                            readonly_payload,
                            indent=2,
                            ensure_ascii=False,
                        ),
                        "read_only": True,
                    }
                raw_hex_model = build_decoded_value_raw_hex_model(
                    field_name=field_name,
                    raw_value=raw_value,
                    last_ef_key=last_ef_key,
                )
                if isinstance(raw_hex_model, dict):
                    raw_hex_payload = raw_hex_model.get("payload", {})
                    if isinstance(raw_hex_payload, dict) is False:
                        raw_hex_payload = {"hex": str(raw_hex_payload or "").upper()}
                    return {
                        "replacement_path": replacement_path,
                        "field_name": field_name,
                        "last_ef_key": last_ef_key,
                        "pe_key": pe_key,
                        "raw_hex": self._normalize_raw_hex(_hex_from_tagged_bytes(raw_value)),
                        "title": str(raw_hex_model.get("title", "") or "Raw hex editor"),
                        "note": raw_hex_model.get("note"),
                        "editor_kind": "raw_hex_decoded",
                        "payload": copy.deepcopy(raw_hex_payload),
                        "payload_text": json.dumps(
                            raw_hex_payload,
                            indent=2,
                            ensure_ascii=False,
                        ),
                        "target_length": raw_hex_model.get("target_length"),
                    }
                return None
            return {
                "replacement_path": replacement_path,
                "field_name": field_name,
                "last_ef_key": last_ef_key,
                "pe_key": pe_key,
                "raw_hex": self._normalize_raw_hex(_hex_from_tagged_bytes(raw_value)),
                "title": model["title"],
                "note": model.get("note"),
                "editor_kind": str(model.get("editor_kind", "json") or "json").strip() or "json",
                "payload": copy.deepcopy(model.get("payload", {})),
                "payload_text": json.dumps(
                    model["payload"],
                    indent=2,
                    ensure_ascii=False,
                ),
            }

        def _jump_editor_to_span(
            self,
            start_off: int,
            end_off: int,
            *,
            focus_editor: bool = True,
            preserve_exact_span: bool = False,
        ) -> None:
            editor = self.query_one("#json_editor", TextArea)
            if end_off < start_off:
                start_off, end_off = end_off, start_off
            if preserve_exact_span is False:
                start_off, end_off = self._focus_span_for_offsets(editor.text, start_off, end_off)
            sel_json = Selection(
                offset_to_location(editor.text, start_off),
                offset_to_location(editor.text, end_off),
            )
            self._peer_lock = True
            try:
                editor.selection = sel_json
                if focus_editor:
                    editor.focus()
                    editor.scroll_cursor_visible(center=True)
            finally:
                self._peer_lock = False
            self._refresh_inspect_panel()
            self._refresh_decoded_panel()

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
            return self._outline_data_span(node.data)

        def _tree_context_action_rows(
            self,
        ) -> list[tuple[str, str, str | None, bool]]:
            pe_key = self._preferred_selected_pe_key()
            normalized_pe_key = str(pe_key or "").strip()
            base_type = base_pe_type(normalized_pe_key) if len(normalized_pe_key) > 0 else ""
            add_file_disabled = base_type not in _FILESYSTEM_PE_TYPES
            insert_before_disabled = base_type == "header"
            remove_disabled = base_type in {"", "header", "end"}
            copy_disabled = len(normalized_pe_key) == 0
            paste_disabled = self._pe_clipboard is None
            return [
                (
                    "add_file",
                    "Add file",
                    "Open the context-aware file picker for the selected filesystem PE.",
                    add_file_disabled,
                ),
                (
                    "add_pe",
                    "Add PE",
                    "Open the profile-element insert picker near the selected PE.",
                    False,
                ),
                (
                    "insert_after",
                    "Insert PE after",
                    "Insert a new PE after the selected profile element.",
                    False,
                ),
                (
                    "insert_before",
                    "Insert PE before",
                    "Insert a new PE before the selected profile element.",
                    insert_before_disabled,
                ),
                (
                    "copy_pe",
                    "Copy PE",
                    "Copy the selected profile element into the TUI clipboard.",
                    copy_disabled,
                ),
                (
                    "paste_after",
                    "Paste copied PE after",
                    "Paste the clipboard PE after the selected profile element.",
                    paste_disabled,
                ),
                (
                    "paste_before",
                    "Paste copied PE before",
                    "Paste the clipboard PE before the selected profile element.",
                    paste_disabled,
                ),
                (
                    "remove_pe",
                    "Remove PE",
                    "Remove the selected profile element after confirmation.",
                    remove_disabled,
                ),
            ]

        @staticmethod
        def _tree_node_for_context_click(
            tree: Tree,
            event: events.MouseDown,
        ) -> tuple[TreeNode | None, int | None]:
            candidate_lines: list[int] = []
            hover_line = getattr(tree, "hover_line", None)
            if isinstance(hover_line, int):
                candidate_lines.append(hover_line)
            try:
                content_offset = event.get_content_offset(tree)
            except Exception:
                content_offset = None
            if content_offset is not None:
                scroll_offset = getattr(tree, "scroll_offset", None)
                scroll_y = int(getattr(scroll_offset, "y", 0)) if scroll_offset is not None else 0
                candidate_lines.append(scroll_y + int(getattr(content_offset, "y", 0)))
            cursor_line = getattr(tree, "cursor_line", None)
            if isinstance(cursor_line, int):
                candidate_lines.append(cursor_line)
            last_line = int(getattr(tree, "last_line", 0))
            seen_lines: set[int] = set()
            for raw_line in candidate_lines:
                line = max(0, min(last_line, int(raw_line)))
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                try:
                    return (tree.get_node_at_line(line), line)
                except Exception:
                    continue
            return (None, None)

        def _open_tree_context_menu(self, *, node_label: str) -> None:
            pe_key = self._preferred_selected_pe_key()
            rows = self._tree_context_action_rows()
            self.push_screen(
                TreeContextActionPicker(
                    rows,
                    pe_key=str(pe_key or "").strip(),
                    node_label=node_label,
                ),
                callback=self._on_tree_context_action_chosen,
            )

        def _on_tree_context_action_chosen(self, choice: str | None) -> None:
            if choice is None:
                return
            if choice == "add_file":
                self.action_add_selected_pe_file()
                return
            if choice == "add_pe":
                self.action_add_pe_block()
                return
            if choice == "insert_after":
                self.action_insert_selected_pe_after_direct()
                return
            if choice == "insert_before":
                self.action_insert_selected_pe_before_direct()
                return
            if choice == "copy_pe":
                self.action_copy_selected_pe()
                return
            if choice == "paste_after":
                self.action_paste_selected_pe_after()
                return
            if choice == "paste_before":
                self.action_paste_selected_pe_before()
                return
            if choice == "remove_pe":
                self.action_remove_selected_pe()

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

        def _preferred_selected_pe_member_key(self) -> str | None:
            editor = self.query_one("#json_editor", TextArea)
            tree_span = self._selected_tree_span()
            if tree_span is not None:
                tree_member_key = self._member_key_for_offset(editor.text, tree_span[0])
                if tree_member_key is not None:
                    return tree_member_key
                tree_member_key = self._focus_object_key_for_span(editor.text, tree_span)
                if tree_member_key is not None:
                    return tree_member_key
            sel = editor.selection
            start_off = location_to_offset(editor.text, sel.start)
            member_key = self._member_key_for_offset(editor.text, start_off)
            if member_key is not None:
                return member_key
            end_off = location_to_offset(editor.text, sel.end)
            focus_span = self._focus_span_for_offsets(editor.text, start_off, end_off)
            return self._focus_object_key_for_span(editor.text, focus_span)

        def _selected_gfm_group_index(self, pe_key: str) -> int | None:
            editor = self.query_one("#json_editor", TextArea)
            spans = self._json_spans_for_text(editor.text)
            triple = spans.get(pe_key)
            if triple is None:
                return None
            _entry_begin, value_start, value_end = triple
            if value_start >= value_end or value_start >= len(editor.text):
                return None
            if editor.text[value_start] != "{":
                return None
            commands_span: tuple[int, int] | None = None
            for key_text, member_start, member_end in self._scan_object_members(
                editor.text,
                value_start,
                value_end,
            ):
                if key_text == "fileManagementCMD":
                    commands_span = (member_start, member_end)
                    break
            if commands_span is None:
                return None
            item_spans = self._scan_list_items(
                editor.text,
                commands_span[0],
                commands_span[1],
            )
            if len(item_spans) == 0:
                return None
            focus_span = self._selected_tree_span()
            if focus_span is None:
                sel = editor.selection
                focus_span = self._focus_span_for_offsets(
                    editor.text,
                    location_to_offset(editor.text, sel.start),
                    location_to_offset(editor.text, sel.end),
                )
            for index, (item_start, item_end) in enumerate(item_spans):
                if focus_span[0] >= item_start and focus_span[1] <= item_end:
                    return index
                if focus_span[1] <= item_start or focus_span[0] >= item_end:
                    continue
                return index
            return len(item_spans) - 1

        def _normalize_insert_target(
            self,
            anchor_key: str | None,
            insert_after: bool,
        ) -> tuple[str | None, bool]:
            if anchor_key is None:
                return (None, True)
            anchor_type = base_pe_type(anchor_key)
            if anchor_type == "end":
                return (anchor_key, False)
            return (anchor_key, insert_after)

        def _describe_insert_target(self, anchor_key: str | None, insert_after: bool) -> str:
            if anchor_key is None:
                return "before end PE"
            anchor_type = base_pe_type(anchor_key)
            if anchor_type == "end":
                return "before end PE"
            if anchor_type == "header":
                return "after header"
            if insert_after:
                return f"after {anchor_key}"
            return f"before {anchor_key}"

        def _reset_pending_insert_state(self) -> None:
            self._pending_insert_blocked_ids = set()
            self._pending_insert_anchor_key = None
            self._pending_insert_after = True

        def _reset_pending_remove_state(self) -> None:
            self._pending_remove_section_key = None

        def _reset_pending_file_state(self) -> None:
            self._pending_file_section_key = None
            self._pending_file_context_key = None
            self._pending_file_group_index = None
            self._pending_file_target_label = ""

        def _reset_pending_file_insert_state(self) -> None:
            self._pending_file_insert = None

        def _adf_bootstrap_defaults_for_picker(
            self,
            bootstrap_defaults: dict[str, str],
        ) -> dict[str, str]:
            merged = dict(bootstrap_defaults)
            root_kind = str(bootstrap_defaults.get("root_kind", "") or "").strip()
            if len(root_kind) == 0:
                return merged
            remembered = self._adf_bootstrap_memory.get(root_kind)
            if isinstance(remembered, dict) is False:
                return merged
            for field_name in ("temporary_fid", "df_name"):
                remembered_value = str(remembered.get(field_name, "") or "").strip()
                if len(remembered_value) == 0:
                    continue
                merged[field_name] = remembered_value
            return merged

        def _remember_adf_bootstrap_values(
            self,
            root_kind: str | None,
            values: dict[str, str],
        ) -> None:
            normalized_root_kind = str(root_kind or "").strip()
            if len(normalized_root_kind) == 0:
                return
            remembered: dict[str, str] = {}
            for field_name in ("temporary_fid", "df_name"):
                field_value = str(values.get(field_name, "") or "").strip()
                if len(field_value) == 0:
                    continue
                remembered[field_name] = field_value
            if len(remembered) == 0:
                return
            self._adf_bootstrap_memory[normalized_root_kind] = remembered

        def _show_pe_block_picker(self) -> None:
            target_hint = self._describe_insert_target(
                self._pending_insert_anchor_key,
                self._pending_insert_after,
            )
            self.push_screen(
                PeBlockPicker(self._pending_insert_blocked_ids, target_hint),
                callback=self._on_pe_block_chosen,
            )

        def _begin_insert_pe_flow(
            self,
            *,
            direct_insert_after: bool | None,
        ) -> None:
            try:
                doc = self._current_editor_document()
                pes_probe = build_profile_sequence_from_document(doc, workspace_root)
                blocked = menu_ids_blocked_if_present(pes_probe)
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Insert PE: fix JSON first: {exc}", remember=False)
                return
            anchor_key = self._preferred_selected_pe_key()
            self._pending_insert_blocked_ids = blocked
            self._pending_insert_anchor_key = anchor_key
            self._pending_insert_after = True
            if direct_insert_after is None:
                self.push_screen(
                    PeInsertTargetPicker(anchor_key),
                    callback=self._on_insert_target_chosen,
                )
                return
            (
                self._pending_insert_anchor_key,
                self._pending_insert_after,
            ) = self._normalize_insert_target(anchor_key, direct_insert_after)
            self._show_pe_block_picker()

        def _begin_add_file_flow(self) -> None:
            try:
                doc = self._current_editor_document()
                pe_key = self._preferred_selected_pe_key()
                if pe_key is None:
                    raise ValueError("select a filesystem profile element in the tree or editor first")
                if base_pe_type(pe_key) not in _FILESYSTEM_PE_TYPES:
                    raise ValueError(
                        f"selected profile element {pe_key!r} is not a filesystem "
                        "container — pick MF / TELECOM / USIM / ISIM / genericFileManagement / "
                        "an ADF branch before adding files"
                    )
                context_key: object | None = self._preferred_selected_pe_member_key()
                group_index: int | None = None
                if base_pe_type(pe_key) == "genericFileManagement":
                    context_key = None
                    group_index = self._selected_gfm_group_index(pe_key)
                (
                    normalized_context_key,
                    target_label,
                    rows,
                ) = list_addable_file_rows(
                    doc,
                    workspace_root,
                    section_key=pe_key,
                    context_key=context_key,
                    group_index=group_index,
                )
                if len(rows) == 0:
                    raise ValueError(f"no addable files remain under {target_label!r}")
            except Exception as exc:
                self._reset_pending_file_state()
                self._refresh_validation_feedback()
                self._notify_user_action(
                    f"Add file failed: {exc}",
                    title="Add file",
                    severity="warning",
                )
                return
            self._pending_file_section_key = pe_key
            self._pending_file_context_key = normalized_context_key
            self._pending_file_group_index = group_index
            self._pending_file_target_label = target_label
            self.push_screen(
                PeFilePicker(
                    rows,
                    pe_key=pe_key,
                    target_label=target_label,
                ),
                callback=self._on_file_choice,
            )

        def _apply_file_choice(
            self,
            *,
            choice: str,
            section_key: str,
            context_key: object | None,
            group_index: int | None,
            target_label: str,
            bootstrap_overrides: dict[str, str] | None = None,
            file_overrides: dict[str, str] | None = None,
        ) -> None:
            try:
                doc = self._current_editor_document()
                new_doc = insert_blank_file_for_pename(
                    doc,
                    workspace_root,
                    section_key=section_key,
                    file_pe_name=choice,
                    context_key=context_key,
                    group_index=group_index,
                    bootstrap_overrides=bootstrap_overrides,
                    file_overrides=file_overrides,
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Add file failed: {exc}", remember=False)
                return
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(
                    f"Added file {choice!r} under {target_label} in {section_key}"
                ),
                failure_prefix="Re-encode after file add failed",
            )

        def _show_pending_file_override_picker(self) -> None:
            pending = self._pending_file_insert
            if isinstance(pending, dict) is False:
                self._set_status("Add file failed: no file insertion pending", remember=False)
                return
            override_defaults = pending.get("file_override_defaults")
            if isinstance(override_defaults, dict) is False or len(override_defaults) == 0:
                self._apply_pending_file_insert()
                return
            self.push_screen(
                PeFileOverridePicker(
                    override_defaults,
                    target_label=str(pending.get("target_label", "") or ""),
                ),
                callback=self._on_file_override_choice,
            )

        def _apply_pending_file_insert(self) -> None:
            pending = self._pending_file_insert
            self._reset_pending_file_insert_state()
            if isinstance(pending, dict) is False:
                self._set_status("Add file failed: no file insertion pending", remember=False)
                return
            choice = str(pending.get("choice", "") or "").strip()
            section_key = str(pending.get("section_key", "") or "").strip()
            if len(choice) == 0 or len(section_key) == 0:
                self._set_status("Add file failed: pending file insertion is incomplete", remember=False)
                return
            self._apply_file_choice(
                choice=choice,
                section_key=section_key,
                context_key=pending.get("context_key"),
                group_index=pending.get("group_index")
                if isinstance(pending.get("group_index"), int) or pending.get("group_index") is None
                else None,
                target_label=str(pending.get("target_label", "") or ""),
                bootstrap_overrides=pending.get("bootstrap_overrides")
                if isinstance(pending.get("bootstrap_overrides"), dict)
                else None,
                file_overrides=pending.get("file_overrides")
                if isinstance(pending.get("file_overrides"), dict)
                else None,
            )

        def _on_file_choice(self, choice: str | None) -> None:
            if choice is None:
                self._reset_pending_file_state()
                return
            section_key = self._pending_file_section_key
            context_key = self._pending_file_context_key
            group_index = self._pending_file_group_index
            target_label = self._pending_file_target_label
            self._reset_pending_file_state()
            try:
                if section_key is None:
                    raise ValueError("no filesystem PE pending file insertion")
                doc = self._current_editor_document()
                bootstrap_defaults = gfm_root_bootstrap_defaults(
                    doc,
                    workspace_root,
                    section_key=section_key,
                    file_pe_name=choice,
                    context_key=context_key,
                    group_index=group_index,
                )
                override_defaults = file_add_override_defaults(
                    doc,
                    workspace_root,
                    section_key=section_key,
                    file_pe_name=choice,
                    context_key=context_key,
                    group_index=group_index,
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Add file failed: {exc}", remember=False)
                return
            if bootstrap_defaults is None and override_defaults is None:
                self._apply_file_choice(
                    choice=choice,
                    section_key=section_key,
                    context_key=context_key,
                    group_index=group_index,
                    target_label=target_label,
                )
                return
            self._pending_file_insert = {
                "choice": choice,
                "section_key": section_key,
                "context_key": context_key,
                "group_index": group_index,
                "target_label": target_label,
                "bootstrap_overrides": None,
                "file_overrides": None,
                "file_override_defaults": override_defaults,
                "bootstrap_root_kind": None,
            }
            if bootstrap_defaults is not None:
                bootstrap_defaults = self._adf_bootstrap_defaults_for_picker(
                    bootstrap_defaults
                )
                self._pending_file_insert["bootstrap_root_kind"] = (
                    str(bootstrap_defaults.get("root_kind", "") or "").strip() or None
                )
                self.push_screen(
                    AdfBootstrapPicker(
                        bootstrap_defaults,
                        target_label=target_label,
                    ),
                    callback=self._on_adf_bootstrap_choice,
                )
                return
            self._show_pending_file_override_picker()

        def _on_adf_bootstrap_choice(self, result: dict[str, str] | None) -> None:
            if result is None:
                self._reset_pending_file_insert_state()
                return
            pending = self._pending_file_insert
            if isinstance(pending, dict) is False:
                self._set_status("Add file failed: no ADF bootstrap insertion pending", remember=False)
                return
            root_kind = str(pending.get("bootstrap_root_kind", "") or "").strip() or None
            self._remember_adf_bootstrap_values(root_kind, result)
            pending["bootstrap_overrides"] = result
            self._show_pending_file_override_picker()

        def _on_file_override_choice(self, result: dict[str, str] | None) -> None:
            if result is None:
                self._reset_pending_file_insert_state()
                return
            pending = self._pending_file_insert
            if isinstance(pending, dict) is False:
                self._set_status("Add file failed: no file override insertion pending", remember=False)
                return
            pending["file_overrides"] = result
            self._apply_pending_file_insert()

        def _apply_document_edit(
            self,
            new_doc: dict[str, object],
            *,
            status_ok: str,
            failure_prefix: str,
        ) -> None:
            if self._preview_guard_active("Profile edit"):
                return
            editor = self.query_one("#json_editor", TextArea)
            self._set_editor_text_programmatically(
                editor,
                document_to_pretty_json(new_doc),
            )
            try:
                self._sync_json_der_from_editor(status_ok=status_ok)
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"{failure_prefix}: {exc}", remember=False)

        def on_input_changed(self, event: Input.Changed) -> None:
            if str(event.input.id or "").strip() != "json_outline_search":
                return
            self._apply_outline_search(
                reset_index=True,
                step=0,
                jump_to_editor=True,
                report_status=False,
            )

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if str(event.input.id or "").strip() != "json_outline_search":
                return
            previous_query = self._outline_search_query
            previous_match_count = self._outline_search_match_count
            query_text = str(event.value or "").strip()
            reset_index = query_text != previous_query or previous_match_count <= 0
            step = 0 if reset_index else 1
            if len(query_text) == 0:
                self._set_status("Enter a tree search query first.", remember=False)
                return
            self._apply_outline_search(
                reset_index=reset_index,
                step=step,
                jump_to_editor=True,
                report_status=True,
            )

        def on_key(self, event: events.Key) -> None:
            if self._outline_search_input_focused() is False:
                return
            normalized_key = str(event.key or "").strip().lower()
            if normalized_key in {"ctrl+g", "ctrl+r", "ctrl+shift+g", "shift+f3"}:
                if normalized_key == "ctrl+g":
                    self.action_next_outline_search_result()
                else:
                    self.action_previous_outline_search_result()
                event.stop()
                event.prevent_default()

        def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.control is not tree:
                return
            if self._outline_search_selecting:
                return
            self._follow_tree_cursor_in_editor(event.node)
            pe_key = self._preferred_selected_pe_key()
            if pe_key is None:
                self._set_status("Tree selection active.")
                return
            self._set_status(
                f"Tree PE {pe_key} selected — Ctrl+T tree actions · Ctrl+A add file · F3 picker · "
                "F11 after · F12 before · Ctrl+↑/↓ move · Ctrl+D remove · Ctrl+Y copy · "
                "Ctrl+P paste after · Ctrl+B paste before · "
                "F1 help · Ctrl+L lint"
            )
            if self._has_visible_mode("inspect"):
                self._refresh_inspect_panel()

        def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.control is not tree:
                return
            if self._outline_search_selecting:
                return
            self._follow_tree_cursor_in_editor(event.node)

        def _follow_tree_cursor_in_editor(self, node: TreeNode | None) -> None:
            """Sync the JSON editor cursor to a tree node's span.

            The decoded pane (field editor / service table / JSON), the
            DER view, and the inspect pane all derive their content from
            the JSON editor selection via ``_decoded_edit_context_for_selection``
            and ``on_text_area_selection_changed``. Without this sync the
            decoded field editor stays locked on whichever leaf the editor
            cursor last landed on (typically an early ``fileId`` like
            ``6F3D``), which is exactly the "does not follow any
            selection" symptom. We intentionally keep focus on the tree
            so arrow-key navigation continues to belong to the tree, and
            we schedule the downstream panels through the existing
            debouncers to avoid stalling rapid key-repeat navigation.
            """
            if node is None:
                return
            span = self._outline_data_span(node.data)
            if span is None:
                return
            preserve_exact_span = self._outline_preserves_exact_span(node.data)
            editor = self.query_one("#json_editor", TextArea)
            start_off, end_off = int(span[0]), int(span[1])
            if end_off < start_off:
                start_off, end_off = end_off, start_off
            if preserve_exact_span is False:
                start_off, end_off = self._focus_span_for_offsets(
                    editor.text,
                    start_off,
                    end_off,
                )
            sel_json = Selection(
                offset_to_location(editor.text, start_off),
                offset_to_location(editor.text, end_off),
            )
            if editor.selection == sel_json:
                return
            self._peer_lock = True
            try:
                editor.selection = sel_json
            finally:
                self._peer_lock = False
            self._schedule_inspect_refresh()
            self._schedule_decoded_refresh()

        def on_mouse_down(self, event: events.MouseDown) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.widget is not tree or int(getattr(event, "button", 0)) != 3:
                return
            node, line = self._tree_node_for_context_click(tree, event)
            if node is None:
                self._set_status("Tree right-click: no outline node under pointer.", remember=False)
                event.stop()
                event.prevent_default()
                return
            tree.focus()
            if isinstance(line, int) and line >= 0:
                try:
                    tree.move_cursor_to_line(line)
                except Exception:
                    pass
            tree.select_node(node)
            self._open_tree_context_menu(node_label=str(node.label))
            event.stop()
            event.prevent_default()

        def on_click(self, event: events.Click) -> None:
            tree = self.query_one("#json_outline", Tree)
            if event.widget is tree:
                if event.chain < 2:
                    return
                node = tree.cursor_node
                if node is None:
                    return
                span = self._outline_data_span(node.data)
                if span is not None:
                    self._jump_editor_to_span(
                        span[0],
                        span[1],
                        preserve_exact_span=self._outline_preserves_exact_span(node.data),
                    )
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
            if self._has_visible_mode("inspect"):
                self._refresh_inspect_panel()
            if self._has_visible_mode("lint"):
                self._refresh_lint_panel()
            if self._has_visible_mode("decoded"):
                self._refresh_decoded_panel()

        def _format_lint_status_message(self, outcome: TuiLintOutcome) -> str:
            if outcome.parse_error is not None:
                return f"Lint parse error: {outcome.parse_error}"
            report = outcome.report
            if report is None:
                return "Lint completed with no report output."
            payload = report.to_dict()
            summary = payload.get("summary", {})
            fail_n = int(summary.get("fail", 0))
            warn_n = int(summary.get("warn", 0))
            info_n = int(summary.get("info", 0))
            score = int(payload.get("score", 0))
            base = (
                f"Lint refreshed — score {score}/100 · "
                f"FAIL {fail_n} · WARN {warn_n} · INFO {info_n}"
            )
            if outcome.template_mode is True or len(outcome.undefined_tokens) > 0:
                token_count = len(outcome.undefined_tokens)
                hint = "Resolve with APPLY-TEMPLATE / APPLY-TOKENS."
                if token_count == 0:
                    return base + f" · template mode · {hint}"
                tokens = ", ".join(sorted(outcome.undefined_tokens))
                return base + (
                    f" · template mode (unresolved: {tokens}) · {hint}"
                )
            if len(outcome.placeholder_paths) > 0:
                return (
                    base
                    + f" · template placeholders: {len(outcome.placeholder_paths)}"
                    + " · Ctrl+R to preview resolved form."
                )
            return base

        def _run_lint_for_current_buffer(
            self,
            *,
            trigger: str,
            report_status: bool,
            refresh_panel: bool = True,
        ) -> None:
            editor = self.query_one("#json_editor", TextArea)
            current_text = str(editor.text or "")
            self._lint_cached_text = current_text
            self._lint_last_trigger = str(trigger or "").strip() or "manual"
            self._lint_dirty = False
            if self._validation_issue is not None:
                self._lint_cached_outcome = None
                self._refresh_template_mode_badge()
                if refresh_panel:
                    self._refresh_lint_panel()
                if report_status:
                    self._set_status(
                        "Lint not run: fix the current validation error first.",
                        remember=False,
                    )
                return
            outcome = lint_profile_json_buffer(current_text, profile_label, strict=False)
            self._lint_cached_outcome = outcome
            self._refresh_template_mode_badge()
            self._refresh_placeholder_hud(current_text)
            if refresh_panel:
                self._refresh_lint_panel()
            if report_status:
                self._set_status(
                    self._format_lint_status_message(outcome),
                    remember=False,
                )

        def _refresh_placeholder_hud(self, current_text: str | None = None) -> None:
            """Recompute placeholder locations and update the HUD strip."""

            if current_text is None:
                try:
                    editor = self.query_one("#json_editor", TextArea)
                    current_text = str(editor.text or "")
                except Exception:
                    current_text = ""
            locations = find_placeholder_locations(current_text or "")
            self._placeholder_locations = locations
            if self._placeholder_nav_index >= len(locations):
                self._placeholder_nav_index = -1
            undefined: set[str] = set()
            outcome = self._lint_cached_outcome
            if outcome is not None:
                undefined = set(getattr(outcome, "undefined_tokens", ()) or ())
            summary = format_placeholder_hud(locations, undefined_tokens=undefined)
            try:
                hud = self.query_one("#placeholder_hud", Static)
            except Exception:
                return
            if len(summary) == 0:
                hud.update("")
                hud.display = False
            else:
                hud.update(summary)
                hud.display = True

        def _select_placeholder_by_index(self, index: int) -> bool:
            if len(self._placeholder_locations) == 0:
                self._set_status(
                    "No placeholders in the current buffer.",
                    remember=False,
                )
                return False
            index = index % len(self._placeholder_locations)
            self._placeholder_nav_index = index
            loc = self._placeholder_locations[index]
            try:
                editor = self.query_one("#json_editor", TextArea)
            except Exception:
                return False
            start_line = int(loc.get("line", 1)) - 1
            start_col = int(loc.get("column", 1)) - 1
            length = int(loc.get("end", 0)) - int(loc.get("start", 0))
            end_col = start_col + length
            try:
                editor.move_cursor((start_line, start_col), select=False)
                editor.selection = editor.selection.replace(  # type: ignore[attr-defined]
                    start=(start_line, start_col),
                    end=(start_line, end_col),
                )
            except Exception:
                try:
                    editor.move_cursor((start_line, end_col), select=True)
                except Exception:
                    pass
            name = str(loc.get("name", ""))
            style = str(loc.get("style", "brace"))
            opener, closer = ("{", "}") if style == "brace" else ("[", "]")
            marker = "#" if loc.get("is_length") else ""
            token_repr = f"{opener}{marker}{name}{closer}"
            self._set_status(
                f"Placeholder {index + 1}/{len(self._placeholder_locations)} — "
                f"{token_repr} at L{loc.get('line')}:C{loc.get('column')}",
                remember=False,
            )
            return True

        def action_jump_next_placeholder(self) -> None:
            if len(self._placeholder_locations) == 0:
                self._refresh_placeholder_hud()
            next_index = self._placeholder_nav_index + 1
            self._select_placeholder_by_index(next_index)

        def action_jump_prev_placeholder(self) -> None:
            if len(self._placeholder_locations) == 0:
                self._refresh_placeholder_hud()
            if self._placeholder_nav_index < 0:
                prev_index = len(self._placeholder_locations) - 1
            else:
                prev_index = self._placeholder_nav_index - 1
            self._select_placeholder_by_index(prev_index)

        def _refresh_template_mode_badge(self) -> None:
            """Update ``self.sub_title`` to reflect template-mode / preview state.

            The base session hint is preserved; a badge segment is appended
            whenever the current lint outcome reports unresolved placeholders,
            active placeholder paths, or when the resolved-preview toggle is
            on.
            """

            outcome = self._lint_cached_outcome
            template_mode = False
            undefined: set[str] = set()
            placeholder_paths: tuple[str, ...] = tuple()
            if outcome is not None:
                template_mode = bool(getattr(outcome, "template_mode", False))
                undefined = set(getattr(outcome, "undefined_tokens", ()) or ())
                placeholder_paths = tuple(
                    getattr(outcome, "placeholder_paths", ()) or ()
                )
            self.sub_title = format_template_mode_sub_title(
                self._base_sub_title,
                preview_active=bool(self._resolved_preview_active),
                template_mode=template_mode,
                undefined_tokens=undefined,
                placeholder_paths=placeholder_paths,
            )

        def _outline_bytes_hex(self, value: object) -> str | None:
            if isinstance(value, dict) is False:
                return None
            structural = set(_structural_data_keys(value))
            if structural != {_TAG_BYTES}:
                return None
            raw = str(value.get(_TAG_BYTES, value.get(_LEGACY_TAG_BYTES, "")))
            compact = raw.replace(" ", "").replace("\n", "").replace("\t", "").upper()
            if len(compact) == 0:
                return None
            return compact

        def _outline_compact_summary(self, items: list[str], *, limit: int = 3) -> str | None:
            unique_items: list[str] = []
            for item in items:
                text = str(item or "").strip()
                if len(text) == 0:
                    continue
                if text in unique_items:
                    continue
                unique_items.append(text)
            if len(unique_items) == 0:
                return None
            if len(unique_items) <= limit:
                return ", ".join(unique_items)
            shown = ", ".join(unique_items[:limit])
            return f"{shown} +{len(unique_items) - limit}"

        def _outline_file_label_from_fid(
            self,
            fid_hex: str | None,
            *,
            parent_hint: str | None = None,
        ) -> str | None:
            normalized = str(fid_hex or "").strip().upper()
            if len(normalized) == 0:
                return None
            fid_name = _fid_name_from_hex(normalized, parent_hint=parent_hint)
            if fid_name is None:
                return normalized
            return f"{fid_name} ({normalized})"

        def _outline_file_path_label(
            self,
            path_hex: str | None,
            *,
            parent_hint: str | None = None,
        ) -> str | None:
            normalized = str(path_hex or "").strip().upper()
            if len(normalized) == 0:
                return None
            try:
                path_bytes = bytes.fromhex(normalized)
            except ValueError:
                return normalized
            decoded = _decode_file_path(path_bytes, parent_hint=parent_hint)
            if isinstance(decoded, dict):
                summary = str(decoded.get("summary", "")).strip()
                if len(summary) > 0:
                    return summary
            return normalized

        def _outline_tuple_parts(self, value: object) -> tuple[str, object] | None:
            if isinstance(value, dict) is False:
                return None
            structural = set(_structural_data_keys(value))
            if structural != {_TAG_TUPLE}:
                return None
            inner = value.get(_TAG_TUPLE, value.get(_LEGACY_TAG_TUPLE))
            if isinstance(inner, list) is False:
                return None
            if len(inner) < 2:
                return None
            if isinstance(inner[0], str) is False:
                return None
            return (inner[0], inner[1])

        def _outline_create_fcp_file_label(
            self,
            payload: object,
            *,
            parent_hint: str | None = None,
        ) -> str | None:
            if isinstance(payload, dict) is False:
                return None
            return self._outline_file_label_from_fid(
                self._outline_bytes_hex(payload.get("fileID")),
                parent_hint=parent_hint,
            )

        def _outline_tuple_payload_span(
            self,
            text: str,
            start: int,
            end: int,
        ) -> tuple[int, int] | None:
            tuple_span: tuple[int, int] | None = None
            for key_name, value_start, value_end in self._scan_object_members(text, start, end):
                if _canonical_tag_key(key_name) == _TAG_TUPLE:
                    tuple_span = (value_start, value_end)
                    break
            if tuple_span is None:
                return None
            item_spans = self._scan_list_items(text, tuple_span[0], tuple_span[1])
            if len(item_spans) < 2:
                return None
            return item_spans[1]

        def _outline_file_structure_from_descriptor_payload(
            self,
            descriptor_payload: object,
        ) -> str | None:
            if isinstance(descriptor_payload, dict) is False:
                return None
            descriptor_hex = self._outline_bytes_hex(descriptor_payload.get("fileDescriptor"))
            if descriptor_hex is None:
                return None
            try:
                descriptor_bytes = bytes.fromhex(descriptor_hex)
            except ValueError:
                return None
            decoded = _decode_file_descriptor(descriptor_bytes)
            if isinstance(decoded, dict) is False:
                return None
            structure = str(decoded.get("structure", "") or "").strip().lower()
            if structure in {"linear_fixed", "cyclic", "transparent"}:
                return structure
            return None

        @staticmethod
        def _outline_is_record_based_file(structure: str | None) -> bool:
            normalized = str(structure or "").strip().lower()
            return normalized in {"linear_fixed", "cyclic"}

        @staticmethod
        def _outline_selection_data_for_items(
            items: list[object],
            spans: list[tuple[int, int]],
        ) -> OutlineSelectionData | None:
            if len(items) == 0:
                return None
            if len(spans) == 0:
                return None
            return OutlineSelectionData(
                span=(spans[0][0], spans[-1][1]),
                inspect_subtree=list(items),
            )

        def _template_defaults_body_for_focus(
            self,
            editor_text: str,
            *,
            pe_key: str | None,
            focus_key: str | None,
        ) -> str | None:
            normalized_pe_key = str(pe_key or "").strip()
            normalized_focus_key = str(focus_key or "").strip()
            if len(normalized_pe_key) == 0 or len(normalized_focus_key) == 0:
                return None
            text = str(editor_text or "")
            if text != self._template_defaults_cache_text:
                self._template_defaults_cache_text = text
                self._template_defaults_cache = {}
            cache_key = (normalized_pe_key, normalized_focus_key)
            if cache_key in self._template_defaults_cache:
                return self._template_defaults_cache[cache_key]
            try:
                loaded = self._load_editor_json_cached(text)
            except Exception:
                body = None
            else:
                body = build_template_defaults_report(
                    loaded,
                    pe_key=normalized_pe_key,
                    focus_key_hint=normalized_focus_key,
                )
            self._template_defaults_cache[cache_key] = body
            return body

        def _template_defaults_inspect_text_for_span(
            self,
            text: str,
            span: tuple[int, int],
        ) -> str | None:
            pe_key = self._section_key_for_offset(text, span[0])
            if pe_key is None:
                return None
            focus_key = self._focus_object_key_for_span(text, span)
            body = self._template_defaults_body_for_focus(
                text,
                pe_key=pe_key,
                focus_key=focus_key,
            )
            if body is None:
                return None
            if "Selected file:" not in body:
                return None
            return f"PE: {humanize_saip_display_name(pe_key)}\n{body}"

        def _outline_add_template_defaults_node(
            self,
            parent: object,
            *,
            item_span: tuple[int, int],
            text: str,
        ) -> None:
            inspect_text = self._template_defaults_inspect_text_for_span(text, item_span)
            if inspect_text is None:
                return
            parent.add(
                "Template defaults",
                data=OutlineSelectionData(
                    span=item_span,
                    inspect_text=inspect_text,
                ),
            )

        def _outline_add_tuple_payload_node(
            self,
            parent: object,
            *,
            node_label: str,
            item: object,
            item_span: tuple[int, int],
            payload: object,
            payload_span: tuple[int, int] | None,
            text: str,
        ) -> object:
            node = parent.add(
                node_label,
                data=OutlineSelectionData(
                    span=item_span,
                    inspect_subtree=[item],
                ),
            )
            if payload_span is None:
                return node
            self._populate_json_outline(
                node,
                payload,
                text,
                payload_span[0],
                payload_span[1],
                container_key=None,
                file_management_sequence=False,
            )
            return node

        def _outline_add_file_content_leaf(
            self,
            parent: object,
            *,
            payload: object,
            item: object,
            item_span: tuple[int, int],
            data: object | None = None,
        ) -> object:
            node_data: object = data
            if node_data is None:
                node_data = OutlineSelectionData(
                    span=item_span,
                    inspect_subtree=[item],
                )
            return parent.add(
                self._outline_label_for_value("fileContent", payload),
                data=node_data,
            )

        def _outline_label_with_suffix(self, base_label: str, suffix: str | None) -> str:
            text = str(suffix or "").strip()
            if len(text) == 0:
                return base_label
            return f"{base_label} — {text}"

        def _outline_file_management_group_suffix(self, value: object) -> str | None:
            if isinstance(value, list) is False:
                return None
            path_label: str | None = None
            parent_hint: str | None = None
            file_labels: list[str] = []
            for item in value:
                tuple_parts = self._outline_tuple_parts(item)
                if tuple_parts is None:
                    continue
                tag_name, payload = tuple_parts
                if tag_name == "filePath" and path_label is None:
                    path_hex = self._outline_bytes_hex(payload)
                    path_label = self._outline_file_path_label(path_hex)
                    parent_hint = parent_token_from_file_path_hex(path_hex)
                    continue
                if tag_name != "createFCP":
                    continue
                file_label = self._outline_create_fcp_file_label(
                    payload,
                    parent_hint=parent_hint,
                )
                if file_label is not None:
                    file_labels.append(file_label)
            files_summary = self._outline_compact_summary(file_labels)
            if path_label is not None and files_summary is not None:
                return f"{path_label} :: {files_summary}"
            if files_summary is not None:
                return files_summary
            return path_label

        def _outline_file_management_sequence_suffix(
            self,
            value: object,
            *,
            active_file_label: str | None,
            active_parent_hint: str | None = None,
        ) -> tuple[str | None, str | None, str | None]:
            """
            Return ``(display_suffix, active_file_label, active_parent_hint)``.

            The third element tracks the DF/ADF parent token derived from the
            most recent ``filePath`` so that subsequent ``createFCP`` entries
            resolve FID collisions (e.g. 6F40 MSISDN vs CSIM-MDN) against
            the correct parent.
            """

            tuple_parts = self._outline_tuple_parts(value)
            if tuple_parts is None:
                return (None, active_file_label, active_parent_hint)
            tag_name, payload = tuple_parts
            if tag_name == "filePath":
                path_hex = self._outline_bytes_hex(payload)
                path_label = self._outline_file_path_label(path_hex)
                next_parent = parent_token_from_file_path_hex(path_hex)
                return (path_label, None, next_parent)
            if tag_name == "createFCP":
                file_label = self._outline_create_fcp_file_label(
                    payload,
                    parent_hint=active_parent_hint,
                )
                return (file_label, file_label, active_parent_hint)
            if tag_name in {"fillFileOffset", "fillFileContent"}:
                return (active_file_label, active_file_label, active_parent_hint)
            return (None, active_file_label, active_parent_hint)

        def _outline_label_for_value(self, key_text: str, value: object) -> str:
            display_key = humanize_saip_display_name(key_text)
            if isinstance(value, dict):
                structural = set(_structural_data_keys(value))
                if structural == {_TAG_BYTES}:
                    raw = str(value.get(_TAG_BYTES, value.get("__ygg_saip_bytes__", "")))
                    compact = raw.replace(" ", "").replace("\n", "").replace("\t", "")
                    byte_len = len(compact) // 2 if len(compact) % 2 == 0 else len(compact)
                    hint = str(value.get(_TAG_LABEL, value.get(_LEGACY_TAG_LABEL, ""))).strip()
                    if hint != "":
                        return f"{display_key} [{byte_len}B] — {hint}"
                    return f"{display_key} [{byte_len}B]"
                if structural == {_TAG_TUPLE}:
                    inner = value.get(_TAG_TUPLE, value.get(_LEGACY_TAG_TUPLE))
                    if isinstance(inner, list) and len(inner) > 0:
                        return f"{display_key} ({humanize_saip_display_name(str(inner[0]))})"
                return f"{display_key} {{{len(value)}}}"
            if isinstance(value, list):
                return f"{display_key} [{len(value)}]"
            text = repr(value)
            if len(text) > 42:
                text = text[:39] + "..."
            return f"{display_key}: {text}"

        @staticmethod
        def _outline_list_index_key(idx: int, *, container_key: str | None = None) -> str:
            del container_key
            return f"[{idx}]"

        def _populate_ef_tuple_sequence_outline(
            self,
            parent: object,
            value: list[object],
            text: str,
            start: int,
            end: int,
        ) -> bool:
            item_spans = self._scan_list_items(text, start, end)
            file_structure: str | None = None
            pending_fill_items: list[object] = []
            pending_fill_spans: list[tuple[int, int]] = []
            record_number = 0
            handled = False
            for idx, item in enumerate(value):
                if idx >= len(item_spans):
                    break
                item_span = item_spans[idx]
                tuple_parts = self._outline_tuple_parts(item)
                if tuple_parts is None:
                    child = parent.add(
                        self._outline_label_for_value(f"[{idx}]", item),
                        data=item_span,
                    )
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        item_span[0],
                        item_span[1],
                        container_key=None,
                        file_management_sequence=False,
                    )
                    pending_fill_items = []
                    pending_fill_spans = []
                    handled = True
                    continue
                tag_name, payload = tuple_parts
                payload_span = self._outline_tuple_payload_span(
                    text,
                    item_span[0],
                    item_span[1],
                )
                if tag_name == "fileDescriptor":
                    file_structure = self._outline_file_structure_from_descriptor_payload(
                        payload,
                    )
                    descriptor_node = self._outline_add_tuple_payload_node(
                        parent,
                        node_label=humanize_saip_display_name(tag_name),
                        item=item,
                        item_span=item_span,
                        payload=payload,
                        payload_span=payload_span,
                        text=text,
                    )
                    self._outline_add_template_defaults_node(
                        descriptor_node,
                        item_span=item_span,
                        text=text,
                    )
                    pending_fill_items = []
                    pending_fill_spans = []
                    handled = True
                    continue
                if tag_name == "fillFileOffset":
                    pending_fill_items.append(item)
                    pending_fill_spans.append(item_span)
                    handled = True
                    continue
                if tag_name == "fillFileContent":
                    fill_items = list(pending_fill_items)
                    fill_items.append(item)
                    fill_spans = list(pending_fill_spans)
                    fill_spans.append(item_span)
                    pending_fill_items = []
                    pending_fill_spans = []
                    if self._outline_is_record_based_file(file_structure):
                        record_number += 1
                        record_data = self._outline_selection_data_for_items(
                            fill_items,
                            fill_spans,
                        )
                        if record_data is None:
                            record_data = item_span
                        record_node = parent.add(
                            f"Record {record_number}",
                            data=record_data,
                        )
                        self._outline_add_file_content_leaf(
                            record_node,
                            payload=payload,
                            item=item,
                            item_span=item_span,
                        )
                    else:
                        file_content_data = self._outline_selection_data_for_items(
                            fill_items,
                            fill_spans,
                        )
                        self._outline_add_file_content_leaf(
                            parent,
                            payload=payload,
                            item=item,
                            item_span=item_span,
                            data=file_content_data,
                        )
                    handled = True
                    continue
                self._outline_add_tuple_payload_node(
                    parent,
                    node_label=humanize_saip_display_name(tag_name),
                    item=item,
                    item_span=item_span,
                    payload=payload,
                    payload_span=payload_span,
                    text=text,
                )
                pending_fill_items = []
                pending_fill_spans = []
                handled = True
            return handled

        def _outline_data_span(self, data: object) -> tuple[int, int] | None:
            candidate = data
            if isinstance(data, OutlineSelectionData):
                candidate = data.span
            if isinstance(candidate, tuple) is False:
                return None
            if len(candidate) != 2:
                return None
            if all(isinstance(item, int) for item in candidate) is False:
                return None
            return (int(candidate[0]), int(candidate[1]))

        def _selected_outline_selection_data(self) -> OutlineSelectionData | None:
            tree = self.query_one("#json_outline", Tree)
            outline_search = self.query_one("#json_outline_search", Input)
            focused_widget = self.focused
            if focused_widget is not tree and focused_widget is not outline_search:
                return None
            node = tree.cursor_node
            if node is None:
                return None
            data = node.data
            if isinstance(data, OutlineSelectionData):
                return data
            span = self._outline_data_span(data)
            if span is None:
                return None
            return OutlineSelectionData(span=span)

        def _outline_preserves_exact_span(self, data: object) -> bool:
            if isinstance(data, OutlineSelectionData) is False:
                return False
            return data.inspect_subtree is not None or data.inspect_text is not None

        def _populate_file_management_group_outline(
            self,
            parent: object,
            value: list[object],
            text: str,
            start: int,
            end: int,
        ) -> None:
            item_spans = self._scan_list_items(text, start, end)
            current_file_node = None
            current_file_start: int | None = None
            current_file_items: list[object] = []
            current_file_structure: str | None = None
            current_record_number = 0
            pending_fill_items: list[object] = []
            pending_fill_spans: list[tuple[int, int]] = []
            for idx, item in enumerate(value):
                if idx >= len(item_spans):
                    break
                item_span = item_spans[idx]
                tuple_parts = self._outline_tuple_parts(item)
                if tuple_parts is None:
                    current_file_node = None
                    current_file_start = None
                    current_file_items = []
                    current_file_structure = None
                    current_record_number = 0
                    pending_fill_items = []
                    pending_fill_spans = []
                    child = parent.add(
                        self._outline_label_for_value(f"[{idx}]", item),
                        data=item_span,
                    )
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        item_span[0],
                        item_span[1],
                        container_key=None,
                        file_management_sequence=False,
                    )
                    continue
                tag_name, payload = tuple_parts
                payload_span = self._outline_tuple_payload_span(
                    text,
                    item_span[0],
                    item_span[1],
                )
                if tag_name == "filePath":
                    current_file_node = None
                    current_file_start = None
                    current_file_items = []
                    current_file_structure = None
                    current_record_number = 0
                    pending_fill_items = []
                    pending_fill_spans = []
                    label = self._outline_label_with_suffix(
                        self._outline_label_for_value(f"[{idx}]", item),
                        self._outline_file_path_label(self._outline_bytes_hex(payload)),
                    )
                    child = parent.add(label, data=item_span)
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        item_span[0],
                        item_span[1],
                        container_key=None,
                        file_management_sequence=False,
                    )
                    continue
                if tag_name == "createFCP":
                    current_file_node = None
                    current_file_start = None
                    current_file_items = []
                    current_file_structure = None
                    current_record_number = 0
                    pending_fill_items = []
                    pending_fill_spans = []
                    file_label = self._outline_create_fcp_file_label(payload)
                    if file_label is None:
                        child = parent.add(
                            self._outline_label_for_value(f"[{idx}]", item),
                            data=item_span,
                        )
                        self._populate_json_outline(
                            child,
                            item,
                            text,
                            item_span[0],
                            item_span[1],
                            container_key=None,
                            file_management_sequence=False,
                        )
                        continue
                    current_file_items = [item]
                    current_file_start = item_span[0]
                    current_file_structure = self._outline_file_structure_from_descriptor_payload(
                        payload,
                    )
                    current_file_node = parent.add(
                        file_label,
                        data=OutlineSelectionData(
                            span=item_span,
                            inspect_subtree=list(current_file_items),
                        ),
                    )
                    self._outline_add_tuple_payload_node(
                        current_file_node,
                        node_label=humanize_saip_display_name(tag_name),
                        item=item,
                        item_span=item_span,
                        payload=payload,
                        payload_span=payload_span,
                        text=text,
                    )
                    continue
                if current_file_node is not None and current_file_start is not None:
                    current_file_items.append(item)
                    current_file_node.data = OutlineSelectionData(
                        span=(current_file_start, item_span[1]),
                        inspect_subtree=list(current_file_items),
                    )
                    if tag_name == "fillFileOffset":
                        pending_fill_items.append(item)
                        pending_fill_spans.append(item_span)
                        continue
                    if tag_name == "fillFileContent":
                        fill_items = list(pending_fill_items)
                        fill_items.append(item)
                        fill_spans = list(pending_fill_spans)
                        fill_spans.append(item_span)
                        pending_fill_items = []
                        pending_fill_spans = []
                        if self._outline_is_record_based_file(current_file_structure):
                            current_record_number += 1
                            record_data = self._outline_selection_data_for_items(
                                fill_items,
                                fill_spans,
                            )
                            if record_data is None:
                                record_data = item_span
                            record_node = current_file_node.add(
                                f"Record {current_record_number}",
                                data=record_data,
                            )
                            self._outline_add_file_content_leaf(
                                record_node,
                                payload=payload,
                                item=item,
                                item_span=item_span,
                            )
                        else:
                            file_content_data = self._outline_selection_data_for_items(
                                fill_items,
                                fill_spans,
                            )
                            self._outline_add_file_content_leaf(
                                current_file_node,
                                payload=payload,
                                item=item,
                                item_span=item_span,
                                data=file_content_data,
                            )
                        continue
                    pending_fill_items = []
                    pending_fill_spans = []
                    self._outline_add_tuple_payload_node(
                        current_file_node,
                        node_label=humanize_saip_display_name(tag_name),
                        item=item,
                        item_span=item_span,
                        payload=payload,
                        payload_span=payload_span,
                        text=text,
                    )
                    continue
                (
                    suffix,
                    _ignored_file_label,
                    _ignored_parent_hint,
                ) = self._outline_file_management_sequence_suffix(
                    item,
                    active_file_label=None,
                )
                label = self._outline_label_with_suffix(
                    self._outline_label_for_value(f"[{idx}]", item),
                    suffix,
                )
                child = parent.add(label, data=item_span)
                self._populate_json_outline(
                    child,
                    item,
                    text,
                    item_span[0],
                    item_span[1],
                    container_key=None,
                    file_management_sequence=False,
                )

        def _populate_json_outline(
            self,
            parent: object,
            value: object,
            text: str,
            start: int,
            end: int,
            *,
            container_key: str | None = None,
            file_management_sequence: bool = False,
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
                        has_string_tag = len(inner) > 0 and isinstance(inner[0], str)
                        if (
                            has_string_tag
                            and len(inner) == 2
                            and len(item_spans) >= 2
                            and isinstance(inner[1], (dict, list))
                        ):
                            payload_item = inner[1]
                            payload_span = item_spans[1]
                            self._populate_json_outline(
                                parent,
                                payload_item,
                                text,
                                payload_span[0],
                                payload_span[1],
                                container_key=None,
                                file_management_sequence=False,
                            )
                            return
                        for idx, item in enumerate(inner):
                            if idx >= len(item_spans):
                                break
                            if has_string_tag and idx == 0:
                                continue
                            label = f"[{idx}]"
                            if idx >= 1 and has_string_tag:
                                if idx == 1:
                                    label = str(inner[0])
                                else:
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
                                container_key=None,
                                file_management_sequence=False,
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
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        pair[0],
                        pair[1],
                        container_key=key_text,
                        file_management_sequence=False,
                    )
                return
            if isinstance(value, list):
                if file_management_sequence:
                    self._populate_file_management_group_outline(parent, value, text, start, end)
                    return
                if isinstance(container_key, str) and container_key.startswith("ef-"):
                    if self._populate_ef_tuple_sequence_outline(parent, value, text, start, end):
                        return
                item_spans = self._scan_list_items(text, start, end)
                for idx, item in enumerate(value):
                    if idx >= len(item_spans):
                        break
                    label = self._outline_label_for_value(
                        self._outline_list_index_key(idx, container_key=container_key),
                        item,
                    )
                    if container_key == "fileManagementCMD":
                        label = self._outline_label_with_suffix(
                            label,
                            self._outline_file_management_group_suffix(item),
                        )
                    child = parent.add(
                        label,
                        data=item_spans[idx],
                    )
                    next_file_management_sequence = False
                    if container_key == "fileManagementCMD":
                        next_file_management_sequence = True
                    self._populate_json_outline(
                        child,
                        item,
                        text,
                        item_spans[idx][0],
                        item_spans[idx][1],
                        container_key=None,
                        file_management_sequence=next_file_management_sequence,
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
                loaded = self._load_editor_json_cached(text)
            except json.JSONDecodeError as exc:
                tree.root.add(f"JSON parse error: {exc.msg}")
                tree.root.expand()
                return
            except ValueError as exc:
                tree.root.add(f"JSON parse error: {exc}")
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
                container_key="sections",
                file_management_sequence=False,
            )
            tree.root.expand()
            pe_root.expand()
            self._apply_outline_search(
                reset_index=False,
                step=0,
                jump_to_editor=False,
                report_status=False,
            )

        def _refresh_inspect_panel(self) -> None:
            logs = self._visible_logs_for_mode("inspect")
            if len(logs) == 0:
                return
            editor = self.query_one("#json_editor", TextArea)
            outline_selection = self._selected_outline_selection_data()
            subtree_override = None
            inspect_override_text = None
            selection_kind = "editor"
            if outline_selection is None:
                sel = editor.selection
                start_off = location_to_offset(editor.text, sel.start)
                end_off = location_to_offset(editor.text, sel.end)
                focus_span = self._focus_span_for_offsets(editor.text, start_off, end_off)
            else:
                start_off = outline_selection.span[0]
                end_off = outline_selection.span[1]
                focus_span = outline_selection.span
                subtree_override = outline_selection.inspect_subtree
                inspect_override_text = outline_selection.inspect_text
                if inspect_override_text is not None:
                    selection_kind = "tree_report"
                elif subtree_override is None:
                    selection_kind = "tree_span"
                else:
                    selection_kind = "tree_subtree"
            pe_key = self._section_key_for_offset(editor.text, focus_span[0])
            focus_key = self._focus_object_key_for_span(editor.text, focus_span)
            cache_key: tuple[object, ...] = (
                self._left_inspect_mode,
                selection_kind,
                focus_span,
                pe_key,
                focus_key,
                start_off,
                end_off,
                inspect_override_text,
            )
            body = self._inspect_cache_body
            if editor.text != self._inspect_cache_text or cache_key != self._inspect_cache_key:
                if self._left_inspect_mode == "selection" and inspect_override_text is not None:
                    body = inspect_override_text
                else:
                    body = build_transcode_inspector_text(
                        editor.text,
                        start_off,
                        end_off,
                        left_mode=self._left_inspect_mode,
                        fixed_span=focus_span if self._left_inspect_mode == "selection" else None,
                        pe_key_hint=pe_key,
                        focus_key_hint=focus_key,
                        subtree_override=(
                            subtree_override if self._left_inspect_mode == "selection" else None
                        ),
                    )
                self._inspect_cache_text = editor.text
                self._inspect_cache_key = cache_key
                self._inspect_cache_body = body
            if body is None:
                body = ""
            for log in logs:
                log.clear()
                for line in body.splitlines():
                    log.write(self._render_inspect_log_line(line))

        def _refresh_lint_panel(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            logs = self._visible_logs_for_mode("lint")
            if len(logs) == 0:
                return
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
            current_text = str(editor.text or "")
            if (
                self._lint_dirty
                or self._lint_cached_text != current_text
                or self._lint_cached_outcome is None
            ):
                trigger_text = "Save or Ctrl+L"
                if self._lint_last_trigger == "save":
                    trigger_text = "Save again or Ctrl+L"
                for log in logs:
                    log.write(
                        Text.from_markup(
                            "[bold]Lint pending[/bold] — live lint is disabled for performance.\n"
                            f"[dim]{trigger_text} to refresh lint findings for the current buffer.[/dim]"
                        )
                    )
                return
            outcome = self._lint_cached_outcome
            if outcome is None:
                return
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
                        "[bold]Lint[/bold] (same rules as [cyan]LINT[/cyan]; "
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
            if self._resolved_preview_active:
                raise ValueError(
                    "Resolved preview is active; press Ctrl+R to return to the template "
                    "before saving or re-encoding."
                )
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

            template_probe_paths: set[str] = set()
            probe_ctx = _token_ctx_from_loaded_document(pre_loaded)
            probe_tolerant = TokenExpansionContext(
                pre_loaded.get("__ygg_token_defs__", {}) if probe_ctx is not None else {},
                str(pre_loaded.get("__ygg_placeholder_style__", "brace")),
                tolerate_undefined=True,
            )
            try:
                dejsonify_saip_value(
                    pre_loaded.get("sections", {}),
                    probe_tolerant,
                    ("sections",),
                    placeholder_paths=template_probe_paths,
                )
            except Exception:
                pass
            if len(probe_tolerant.undefined_tokens) > 0:
                unresolved = ", ".join(sorted(probe_tolerant.undefined_tokens))
                self._set_status(
                    "Template mode — DER re-encode skipped. Unresolved placeholders: "
                    + unresolved
                    + ". Use APPLY-TEMPLATE / GENERATE-PROFILE to materialise.",
                    remember=False,
                )
                self._set_validation_issue(None)
                self._run_lint_for_current_buffer(
                    trigger="save",
                    report_status=False,
                    refresh_panel=False,
                )
                self._refresh_bottom_panel()
                return

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

            self._set_editor_text_programmatically(
                editor,
                transcode_json_path.read_text(encoding="utf-8"),
            )
            hex_text = format_der_hex(der)
            for der_widget in der_widgets:
                der_widget.text = hex_text
            self._pes = pes_round
            self._raw_der = der
            self._json_snapshot = pretty
            self._hex_snapshot = hex_text
            self._editor_document_cache_text = self._json_snapshot
            self._editor_document_cache_value = doc_round
            self._editor_document_cache_error = None
            self._editor_json_cache_text = self._json_snapshot
            self._editor_json_cache_value = post_tagged
            self._editor_json_cache_error = None
            self._rebuild_peer_map()
            self._editor_spans_cache_text = self._json_snapshot
            self._editor_spans_cache_value = self._json_spans
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
            self._run_lint_for_current_buffer(
                trigger="save",
                report_status=False,
                refresh_panel=False,
            )
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
            if (
                editor_text == self._editor_spans_cache_text
                and self._editor_spans_cache_value is not None
            ):
                return self._editor_spans_cache_value
            try:
                self._parse_editor_document_cached(editor_text)
            except Exception:
                return self._json_spans
            spans = build_json_entry_spans(editor_text, self._keys)
            self._editor_spans_cache_text = str(editor_text or "")
            self._editor_spans_cache_value = spans
            return spans

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
                self._schedule_inspect_refresh()
                self._schedule_decoded_refresh()

        def action_save_refresh(self) -> None:
            if self._resolved_preview_active:
                self._set_status(
                    "Resolved preview is read-only. Press Ctrl+R to return to the template before saving.",
                    remember=False,
                )
                return
            try:
                self._sync_json_der_from_editor(
                    status_ok=build_save_status("Save OK"),
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Save failed: {exc}", remember=False)

        def action_run_lint_now(self) -> None:
            try:
                self._refresh_validation_feedback()
                self._run_lint_for_current_buffer(
                    trigger="manual",
                    report_status=True,
                    refresh_panel=True,
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Lint failed: {exc}", remember=False)

        def action_open_token_manager(self) -> None:
            if self._resolved_preview_active:
                self._set_status(
                    "Token manager unavailable in resolved preview. Press Ctrl+R to return to the template.",
                    remember=False,
                )
                return
            editor = self.query_one("#json_editor", TextArea)
            text = str(editor.text or "").strip()
            if len(text) == 0:
                self._set_status(
                    "Token manager unavailable: editor buffer is empty.",
                    remember=False,
                )
                return
            try:
                loaded = json.loads(text)
            except json.JSONDecodeError as error:
                self._set_status(
                    f"Token manager unavailable: JSON parse error — {error}",
                    remember=False,
                )
                return
            if isinstance(loaded, dict) is False:
                self._set_status(
                    "Token manager unavailable: root JSON value must be an object.",
                    remember=False,
                )
                return
            pre_defs_container = loaded.get("__ygg_token_defs__")
            if isinstance(pre_defs_container, dict):
                self._token_manager_pre_defs = copy.deepcopy(pre_defs_container)
            else:
                self._token_manager_pre_defs = {}
            self.push_screen(
                TokenManagerPicker(loaded),
                self._on_token_manager_result,
            )

        def _on_token_manager_result(self, updated: dict | None) -> None:
            pre_defs = dict(self._token_manager_pre_defs or {})
            self._token_manager_pre_defs = {}
            if updated is None:
                self._set_status("Token manager closed — no changes.", remember=False)
                return
            editor = self.query_one("#json_editor", TextArea)
            pretty = json.dumps(updated, indent=2, ensure_ascii=False) + "\n"
            self._set_editor_text_programmatically(editor, pretty)
            self._refresh_validation_feedback()
            try:
                self._sync_json_der_from_editor(
                    status_ok=build_save_status("Token changes applied"),
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(
                    f"Token changes saved to editor, but re-encode failed: {exc}",
                    remember=False,
                )
                return
            self._set_status(
                "Token changes applied and buffer re-encoded.",
                remember=False,
            )
            self._maybe_offer_length_companion_migration(updated, pre_defs)

        def _maybe_offer_length_companion_migration(
            self,
            updated: dict,
            pre_defs: dict,
        ) -> None:
            post_defs_container = updated.get("__ygg_token_defs__")
            post_defs: dict[str, object] = {}
            if isinstance(post_defs_container, dict):
                post_defs = post_defs_container
            changed_tokens: list[str] = []
            for name, value in post_defs.items():
                if pre_defs.get(name) != value:
                    changed_tokens.append(str(name))
            if len(changed_tokens) == 0:
                return
            candidate_map: dict[str, list[dict[str, object]]] = {}
            for name in changed_tokens:
                try:
                    hits = find_unmigrated_length_candidates(updated, name)
                except Exception:
                    hits = []
                if len(hits) > 0:
                    candidate_map[name] = list(hits)
            if len(candidate_map) == 0:
                return
            self._pending_auto_retoken_updated = copy.deepcopy(updated)
            self._pending_auto_retoken_tokens = list(candidate_map.keys())
            total_hits = sum(len(v) for v in candidate_map.values())
            preview_lines: list[str] = []
            for name, hits in candidate_map.items():
                sites = ", ".join(
                    f"{hit.get('path', '?')} (prefix {hit.get('prefix', '')})"
                    for hit in hits[:4]
                )
                suffix = "" if len(hits) <= 4 else f", +{len(hits) - 4} more"
                preview_lines.append(f"• {name}: {sites}{suffix}")
            body = (
                f"Detected {total_hits} literal length byte(s) that match the "
                "currently-defined length of the token(s) you just edited. "
                "Migrate them to companion form {#NAME}{NAME} so the "
                "length byte recomputes automatically?\n\n"
                + "\n".join(preview_lines)
            )
            self.push_screen(
                TokenConfirmPicker(
                    title="Migrate length companions?",
                    body=body,
                    confirm_label="Migrate",
                    cancel_label="Keep as-is",
                ),
                self._on_auto_retoken_confirm,
            )

        def _on_auto_retoken_confirm(self, decision: bool | None) -> None:
            pending_doc = self._pending_auto_retoken_updated
            pending_tokens = list(self._pending_auto_retoken_tokens or [])
            self._pending_auto_retoken_updated = None
            self._pending_auto_retoken_tokens = []
            if decision is not True or pending_doc is None or len(pending_tokens) == 0:
                return
            try:
                report = retokenise_template_lengths(
                    pending_doc, only_tokens=set(pending_tokens)
                )
            except Exception as exc:
                self._set_status(
                    f"Auto-migrate failed: {exc}", remember=False
                )
                return
            if report.get("rewrites", 0) == 0:
                self._set_status(
                    "Auto-migrate: nothing changed.", remember=False
                )
                return
            editor = self.query_one("#json_editor", TextArea)
            pretty = json.dumps(pending_doc, indent=2, ensure_ascii=False) + "\n"
            self._set_editor_text_programmatically(editor, pretty)
            self._refresh_validation_feedback()
            try:
                self._sync_json_der_from_editor(
                    status_ok=build_save_status(
                        f"Migrated {report['rewrites']} length companion(s)"
                    ),
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(
                    f"Migrated companions but re-encode failed: {exc}",
                    remember=False,
                )
                return
            self._set_status(
                f"Migrated {report['rewrites']} length companion(s) across "
                f"{len(report.get('paths', []))} path(s).",
                remember=False,
            )

        def _init_token_defs_watcher(self, source_path) -> None:
            """Arm the periodic on-disk token-defs watcher.

            Only JSON source files are watched. DER sources are tokenless at
            rest, so comparing to the in-buffer state is not meaningful.
            The watcher polls every few seconds and raises a modal prompt
            when the file's ``__ygg_token_defs__`` block changes on disk.
            """

            try:
                path = pathlib.Path(str(source_path))
            except Exception:
                return
            if path.suffix.lower() != ".json":
                return
            try:
                stat_result = path.stat()
            except OSError:
                return
            snapshot = read_token_defs_from_file(path)
            if snapshot is None:
                return
            defs_now, style_now = snapshot
            self._token_watcher_path = path
            self._token_watcher_mtime = float(stat_result.st_mtime)
            self._token_watcher_last_defs = defs_now
            self._token_watcher_last_style = style_now
            try:
                self.set_interval(3.0, self._check_token_defs_disk_change)
            except Exception:
                return

        def _check_token_defs_disk_change(self) -> None:
            path = self._token_watcher_path
            if path is None or self._token_watcher_prompt_open:
                return
            try:
                stat_result = path.stat()
            except OSError:
                return
            mtime_now = float(stat_result.st_mtime)
            if (
                self._token_watcher_mtime is not None
                and mtime_now <= self._token_watcher_mtime
            ):
                return
            self._token_watcher_mtime = mtime_now
            snapshot = read_token_defs_from_file(path)
            if snapshot is None:
                return
            disk_defs, disk_style = snapshot
            if (
                disk_defs == self._token_watcher_last_defs
                and disk_style == self._token_watcher_last_style
            ):
                return
            self._token_watcher_pending_defs = disk_defs
            self._token_watcher_pending_style = disk_style
            diff_summary = self._format_token_defs_diff(
                self._token_watcher_last_defs, disk_defs
            )
            body = (
                f"{path.name} on disk has updated __ygg_token_defs__ — "
                "likely from a shell SET-TOKEN / RENAME-TOKEN / REMOVE-TOKEN "
                "run in another pane. Import the on-disk defs into the "
                "editor buffer?\n\n"
                f"{diff_summary}\n\n"
                "Unsaved edits elsewhere in the buffer are preserved; only "
                "__ygg_token_defs__ and __ygg_placeholder_style__ are replaced."
            )
            self._token_watcher_prompt_open = True
            self.push_screen(
                TokenConfirmPicker(
                    title="Reload token defs from disk?",
                    body=body,
                    confirm_label="Reload defs",
                    cancel_label="Keep current",
                ),
                self._on_token_watcher_confirm,
            )

        @staticmethod
        def _format_token_defs_diff(
            before: dict[str, object],
            after: dict[str, object],
        ) -> str:
            before_names = set(before.keys())
            after_names = set(after.keys())
            added = sorted(after_names - before_names)
            removed = sorted(before_names - after_names)
            changed = sorted(
                name
                for name in (before_names & after_names)
                if before.get(name) != after.get(name)
            )
            parts: list[str] = []
            if len(added) > 0:
                parts.append(f"added: {', '.join(added)}")
            if len(removed) > 0:
                parts.append(f"removed: {', '.join(removed)}")
            if len(changed) > 0:
                parts.append(f"changed: {', '.join(changed)}")
            if len(parts) == 0:
                return "(placeholder style changed)"
            return "; ".join(parts)

        def _on_token_watcher_confirm(self, decision: bool | None) -> None:
            pending_defs = self._token_watcher_pending_defs
            pending_style = self._token_watcher_pending_style
            self._token_watcher_prompt_open = False
            self._token_watcher_pending_defs = None
            self._token_watcher_pending_style = None
            if decision is not True or pending_defs is None:
                return
            editor = self.query_one("#json_editor", TextArea)
            try:
                loaded = json.loads(str(editor.text or ""))
            except json.JSONDecodeError:
                self._set_status(
                    "Reload skipped: editor JSON is currently invalid.",
                    remember=False,
                )
                return
            if isinstance(loaded, dict) is False:
                return
            loaded["__ygg_token_defs__"] = copy.deepcopy(pending_defs)
            if pending_style is not None:
                loaded["__ygg_placeholder_style__"] = pending_style
            self._token_watcher_last_defs = copy.deepcopy(pending_defs)
            if pending_style is not None:
                self._token_watcher_last_style = pending_style
            pretty = json.dumps(loaded, indent=2, ensure_ascii=False) + "\n"
            self._set_editor_text_programmatically(editor, pretty)
            self._refresh_validation_feedback()
            try:
                self._sync_json_der_from_editor(
                    status_ok=build_save_status("Token defs reloaded"),
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(
                    f"Token defs reloaded in editor, but re-encode failed: {exc}",
                    remember=False,
                )
                return
            self._set_status(
                f"Token defs reloaded from disk ({len(pending_defs)} token(s)).",
                remember=False,
            )

        def action_toggle_resolved_preview(self) -> None:
            if self._resolved_preview_active:
                self._exit_resolved_preview()
                return
            self._enter_resolved_preview()

        def _preview_guard_active(self, label: str) -> bool:
            if self._resolved_preview_active is False:
                return False
            self._set_status(
                f"{label} is unavailable in resolved preview. Press Ctrl+R to return to the template.",
                remember=False,
            )
            return True

        def _enter_resolved_preview(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            original_text = str(editor.text or "")
            stripped = original_text.strip()
            if len(stripped) == 0:
                self._set_status(
                    "Resolved preview unavailable: editor buffer is empty.",
                    remember=False,
                )
                return
            try:
                loaded = json.loads(stripped)
            except json.JSONDecodeError as error:
                self._set_status(
                    f"Resolved preview unavailable: JSON parse error — {error}",
                    remember=False,
                )
                return
            if isinstance(loaded, dict) is False:
                self._set_status(
                    "Resolved preview unavailable: root JSON value must be an object.",
                    remember=False,
                )
                return
            try:
                pretty, undefined_paths = render_resolved_preview_json(loaded)
            except Exception as error:
                self._set_status(
                    f"Resolved preview failed: {error}",
                    remember=False,
                )
                return
            self._resolved_preview_original_text = original_text
            self._resolved_preview_active = True
            self._resolved_preview_banner = format_preview_banner(undefined_paths)
            self._set_editor_text_programmatically(editor, pretty)
            editor.read_only = True
            self._refresh_template_mode_badge()
            self._set_status(self._resolved_preview_banner, remember=False)

        def _exit_resolved_preview(self) -> None:
            editor = self.query_one("#json_editor", TextArea)
            editor.read_only = False
            restored = self._resolved_preview_original_text
            if restored is not None:
                self._set_editor_text_programmatically(editor, restored)
            self._resolved_preview_active = False
            self._resolved_preview_original_text = None
            self._resolved_preview_banner = ""
            self._refresh_validation_feedback()
            self._refresh_template_mode_badge()
            self._set_status(
                "Resolved preview closed — editor is editable again.",
                remember=False,
            )

        def action_add_selected_pe_file(self) -> None:
            self._begin_add_file_flow()

        def action_add_pe_block(self) -> None:
            if self._outline_search_input_focused():
                self.action_next_outline_search_result()
                return
            self._begin_insert_pe_flow(direct_insert_after=None)

        def action_insert_selected_pe_after_direct(self) -> None:
            self._begin_insert_pe_flow(direct_insert_after=True)

        def action_insert_selected_pe_before_direct(self) -> None:
            self._begin_insert_pe_flow(direct_insert_after=False)

        def _on_insert_target_chosen(self, choice: str | None) -> None:
            if choice is None:
                self._reset_pending_insert_state()
                return
            if choice == "before_end":
                self._pending_insert_anchor_key = None
                self._pending_insert_after = True
            elif choice == "before_anchor":
                (
                    self._pending_insert_anchor_key,
                    self._pending_insert_after,
                ) = self._normalize_insert_target(
                    self._pending_insert_anchor_key,
                    False,
                )
            else:
                (
                    self._pending_insert_anchor_key,
                    self._pending_insert_after,
                ) = self._normalize_insert_target(
                    self._pending_insert_anchor_key,
                    True,
                )
            self._show_pe_block_picker()

        def _on_pe_block_chosen(self, choice: str | None) -> None:
            if choice is None:
                self._reset_pending_insert_state()
                return
            try:
                doc = self._current_editor_document()
                new_doc = insert_blank_pe_for_menu_id(
                    doc,
                    workspace_root,
                    menu_id=choice,
                    anchor_key=self._pending_insert_anchor_key,
                    insert_after=self._pending_insert_after,
                )
            except Exception as exc:
                self._reset_pending_insert_state()
                self._refresh_validation_feedback()
                self._set_status(f"Insert PE failed: {exc}", remember=False)
                return
            target_hint = self._describe_insert_target(
                self._pending_insert_anchor_key,
                self._pending_insert_after,
            )
            self._reset_pending_insert_state()
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Inserted {choice!r} {target_hint}"),
                failure_prefix="Re-encode after add failed",
            )

        def action_move_selected_pe_up(self) -> None:
            try:
                doc = self._current_editor_document()
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
            try:
                doc = self._current_editor_document()
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

        def action_remove_selected_pe(self) -> None:
            try:
                self._current_editor_document()
                pe_key = self._preferred_selected_pe_key()
                if pe_key is None:
                    raise ValueError("select a profile element in the tree or editor first")
                if base_pe_type(pe_key) in {"header", "end"}:
                    raise ValueError(f"Cannot remove anchored PE type {base_pe_type(pe_key)!r}.")
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Remove PE failed: {exc}", remember=False)
                return
            self._pending_remove_section_key = pe_key
            self.push_screen(
                PeRemoveConfirmPicker(pe_key),
                callback=self._on_remove_selected_pe_confirmed,
            )

        def _on_remove_selected_pe_confirmed(self, choice: str | None) -> None:
            if choice != "confirm_remove":
                self._reset_pending_remove_state()
                return
            pe_key = self._pending_remove_section_key
            self._reset_pending_remove_state()
            try:
                if pe_key is None:
                    raise ValueError("no PE pending removal")
                doc = self._current_editor_document()
                new_doc = remove_pe_from_document(
                    doc,
                    workspace_root,
                    section_key=pe_key,
                )
            except Exception as exc:
                self._refresh_validation_feedback()
                self._set_status(f"Remove PE failed: {exc}", remember=False)
                return
            self._apply_document_edit(
                new_doc,
                status_ok=build_save_status(f"Removed {pe_key}"),
                failure_prefix="Re-encode after remove failed",
            )

        def action_copy_selected_pe(self) -> None:
            try:
                doc = self._current_editor_document()
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
            try:
                if self._pe_clipboard is None:
                    raise ValueError("clipboard is empty")
                doc = self._current_editor_document()
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

    import warnings

    with warnings.catch_warnings():
        # Textual's linux driver schedules ``self._app.panic`` via
        # ``call_later`` from its input-thread except-handler on exit.
        # When the teardown happens after the app's message pump has
        # already stopped, the coroutine produced by ``_post_message``
        # is never awaited and Python emits a RuntimeWarning from the
        # coroutine's finalizer. Nothing is lost and no state is
        # corrupted — the warning is cosmetic noise bound to Textual's
        # shutdown race (observed on Textual 8.x). Silence just this
        # exact message so unrelated RuntimeWarnings still surface.
        warnings.filterwarnings(
            "ignore",
            message=r"coroutine 'MessagePump\._post_message' was never awaited",
            category=RuntimeWarning,
        )
        SaipTranscodeApp().run(inline=False)
