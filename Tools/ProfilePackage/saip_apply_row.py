# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Reusable label + input + Apply row for SAIP Textual surfaces.

Values typed in the input are drafts until Apply. Hex mode strips
whitespace, ASCII dashes, and ``0x`` / ``0X`` prefixes before commit.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Input, Static

_HEX_BODY = re.compile(r"^[0-9A-Fa-f]*$")
_UNSET = object()


def normalize_hex_bytes_text(raw: str) -> str:
    """Return contiguous uppercase hex digits from operator text."""
    text = str(raw or "").strip()
    lowered = text.lower()
    if lowered.startswith("0x"):
        text = text[2:]
    text = re.sub(r"[\s:-]+", "", text)
    return text.upper()


class SaipApplyRow(Vertical):
    """One editable field: label, draft input, optional hint, Apply."""

    DEFAULT_CSS = """
    SaipApplyRow {
        width: 100%;
        height: auto;
        margin-top: 1;
        padding: 0 1;
        background: $boost;
        border: solid $primary;
    }
    SaipApplyRow .saip_apply_row_line {
        width: 100%;
        height: auto;
    }
    SaipApplyRow .saip_apply_row_label {
        width: 22;
        content-align: left middle;
        color: $text;
    }
    SaipApplyRow .saip_apply_row_input_col {
        width: 1fr;
        height: auto;
    }
    SaipApplyRow .saip_apply_row_input {
        width: 100%;
        border: tall $panel;
        background: $panel;
    }
    SaipApplyRow .saip_apply_row_hint {
        width: 100%;
        min-height: 1;
        color: $text-muted;
        text-style: italic;
        padding-top: 0;
    }
    SaipApplyRow .saip_apply_row_apply {
        width: 10;
        margin-left: 1;
        content-align: center middle;
    }
    """

    class Committed(Message):
        """Posted after Apply with the normalized committed string."""

        def __init__(
            self,
            row: "SaipApplyRow",
            *,
            row_id: str,
            value: str,
        ) -> None:
            super().__init__()
            self.row = row
            self.row_id = str(row_id or "").strip()
            self.value = str(value or "")

    def __init__(
        self,
        row_id: str,
        label: str,
        *,
        mode: Literal["hex", "decimal", "text"] = "hex",
        placeholder: str = "",
        hint: str = "",
        read_only: bool = False,
        apply_callback: Callable[["SaipApplyRow", str], None] | None = None,
        hint_formatter: Callable[[str], str] | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._row_id = str(row_id or "").strip()
        self._label_text = str(label or "").strip()
        self._mode: Literal["hex", "decimal", "text"] = mode
        self._placeholder = str(placeholder or "")
        self._static_hint = str(hint or "").strip()
        self._read_only = bool(read_only)
        self._apply_callback = apply_callback
        self._hint_formatter = hint_formatter
        self._suppress_input_sync = False

    @property
    def row_id(self) -> str:
        return self._row_id

    def compose(self) -> ComposeResult:
        with Horizontal(classes="saip_apply_row_line"):
            yield Static(
                self._label_text,
                classes="saip_apply_row_label",
                id=f"saip_apply_label_{self._row_id}",
            )
            with Vertical(classes="saip_apply_row_input_col"):
                yield Input(
                    value="",
                    placeholder=self._placeholder,
                    classes="saip_apply_row_input",
                    id=f"saip_apply_input_{self._row_id}",
                    disabled=self._read_only,
                )
                yield Static("", classes="saip_apply_row_hint", id=f"saip_apply_hint_{self._row_id}")
            yield Button(
                "Apply",
                classes="saip_apply_row_apply",
                id=f"saip_apply_btn_{self._row_id}",
                variant="primary",
                disabled=self._read_only,
            )

    def configure(
        self,
        *,
        label: str | None = None,
        mode: Literal["hex", "decimal", "text"] | None = None,
        placeholder: str | None = None,
        hint_formatter: Callable[[str], str] | None | object = _UNSET,
        static_hint: str | object = _UNSET,
    ) -> None:
        """Update operator-facing metadata without changing the draft text."""
        if label is not None:
            self._label_text = str(label or "").strip()
            if self.is_mounted:
                label_widget = self.query_one(f"#saip_apply_label_{self._row_id}", Static)
                label_widget.update(self._label_text)
        if mode is not None:
            self._mode = mode
        if placeholder is not None:
            self._placeholder = str(placeholder or "")
            if self.is_mounted:
                inp = self.query_one(f"#saip_apply_input_{self._row_id}", Input)
                inp.placeholder = self._placeholder
        if hint_formatter is not _UNSET:
            cast = hint_formatter
            if cast is None:
                self._hint_formatter = None
            else:
                self._hint_formatter = cast
        if static_hint is not _UNSET:
            self._static_hint = str(static_hint or "").strip()
        if self.is_mounted:
            self._refresh_hint_from_draft()

    def set_draft(self, text: str, *, refresh_hint: bool = True) -> None:
        """Programmatically set the draft input (does not fire commit)."""
        self._suppress_input_sync = True
        try:
            widget = self.query_one(f"#saip_apply_input_{self._row_id}", Input)
            widget.value = str(text or "")
        finally:
            self._suppress_input_sync = False
        if refresh_hint and self.is_mounted:
            self._refresh_hint_from_draft()

    def draft_text(self) -> str:
        try:
            widget = self.query_one(f"#saip_apply_input_{self._row_id}", Input)
        except Exception:
            return ""
        return str(widget.value or "")

    def committed_preview_hint(self) -> str:
        """Return the hint line for the current draft (no mutation)."""
        return self._hint_for_draft(self.draft_text())

    def on_mount(self) -> None:
        self._refresh_hint_from_draft()

    def _normalize_for_commit(self, raw: str) -> str:
        if self._mode == "hex":
            return normalize_hex_bytes_text(raw)
        if self._mode == "decimal":
            return re.sub(r"\D+", "", str(raw or ""))
        return str(raw or "").strip()

    def _hint_for_draft(self, raw: str) -> str:
        if self._hint_formatter is not None:
            try:
                formatted = str(self._hint_formatter(raw) or "").strip()
                if len(formatted) > 0:
                    return formatted
            except Exception:
                pass
        return self._static_hint

    def _refresh_hint_from_draft(self) -> None:
        hint_widget = self.query_one(f"#saip_apply_hint_{self._row_id}", Static)
        text = self._hint_for_draft(self.draft_text())
        hint_widget.update(text)

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_input_sync:
            return
        if event.input.id != f"saip_apply_input_{self._row_id}":
            return
        self._refresh_hint_from_draft()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if str(event.button.id or "") != f"saip_apply_btn_{self._row_id}":
            return
        if self._read_only:
            return
        raw = self.draft_text()
        normalized = self._normalize_for_commit(raw)
        if self._mode == "hex" and len(normalized) > 0:
            if _HEX_BODY.fullmatch(normalized) is None:
                self._refresh_hint_from_draft()
                return
        if self._apply_callback is not None:
            self._apply_callback(self, normalized)
            return
        self.post_message(
            self.Committed(
                self,
                row_id=self._row_id,
                value=normalized,
            ),
        )

    def set_read_only(self, read_only: bool) -> None:
        self._read_only = bool(read_only)
        if self.is_mounted is False:
            return
        try:
            inp = self.query_one(f"#saip_apply_input_{self._row_id}", Input)
            btn = self.query_one(f"#saip_apply_btn_{self._row_id}", Button)
        except Exception:
            return
        inp.disabled = self._read_only
        btn.disabled = self._read_only


__all__ = [
    "SaipApplyRow",
    "normalize_hex_bytes_text",
]
