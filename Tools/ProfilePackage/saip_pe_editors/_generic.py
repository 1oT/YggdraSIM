"""
Generic fallback PE editor.

Used for any PE that does not have a custom editor registered yet. Shows
the SAIP header form on top and a member overview underneath so the
operator at least sees the structured shape (as opposed to the raw JSON
dump that the legacy decoded pane produced). Edits to the header
round-trip through the host TUI; the member list itself is read-only
in this widget -- operators still drop into the JSON column to edit
fields the generic editor does not know about.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from ._base import (
    BasePeEditor,
    base_pe_type_for_section_key,
    header_member_key_from_pe,
    header_value_from_pe,
    rebuild_pe_with_header,
)
from ._header import PeHeaderForm


class GenericPeEditor(BasePeEditor):
    """Header form plus a structured member overview."""

    DEFAULT_CSS = """
    GenericPeEditor {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    GenericPeEditor .pe_member_list {
        width: 100%;
        height: auto;
        min-height: 1;
        padding: 0 1;
    }
    GenericPeEditor .pe_member_row {
        width: 100%;
        height: 1;
        color: $text;
    }
    GenericPeEditor .pe_member_row.section_header {
        text-style: bold;
        color: $accent;
        margin-top: 1;
    }
    GenericPeEditor .pe_member_row.muted {
        color: $text-muted;
    }
    """

    PE_TYPE_LABEL = "Profile element"

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="generic_pe_header",
        )
        with Vertical(classes="pe_member_list", id="generic_pe_member_list"):
            yield Static("Members", classes="pe_member_row section_header")
            yield Static("(no PE selected)", classes="pe_member_row muted", id="generic_pe_empty")

    def rebuild_form(self) -> None:
        header = header_value_from_pe(self._pe_value) or {}
        header_form = self.query_one("#generic_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header,
            read_only=self._read_only,
        )
        self._refresh_member_list()

    def _refresh_member_list(self) -> None:
        member_list = self.query_one("#generic_pe_member_list", Vertical)
        for child in list(member_list.children):
            if child.id == "generic_pe_member_list_title":
                continue
            child.remove()
        member_list.mount(
            Static("Members", classes="pe_member_row section_header"),
        )
        if isinstance(self._pe_value, dict) is False or len(self._pe_value) == 0:
            member_list.mount(
                Static("(no PE selected)", classes="pe_member_row muted"),
            )
            return
        rows: list[str] = []
        for key, value in self._pe_value.items():
            if isinstance(key, str) and key.lower().endswith("header"):
                continue
            rows.append(_describe_member(key, value))
        if len(rows) == 0:
            member_list.mount(
                Static(
                    "(only the SAIP header member; no further data fields)",
                    classes="pe_member_row muted",
                ),
            )
            return
        for row_text in rows:
            member_list.mount(Static(row_text, classes="pe_member_row"))

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value)
            or _default_header_member_key(self._pe_section_key)
        )
        new_pe = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self._pe_value = new_pe
        self.emit_change(
            summary=(
                f"Header updated · identification={event.identification_text or '?'} "
                f"· mandated={'yes' if event.mandated else 'no'}"
            ),
        )


def _default_header_member_key(pe_section_key: str) -> str:
    base = base_pe_type_for_section_key(pe_section_key)
    if len(base) == 0:
        return "header"
    return f"{base}-header"


def _describe_member(key: str, value: Any) -> str:
    if isinstance(value, dict):
        if "__ygg_saip_bytes__" in value or "hex" in value:
            return f"{key}: <bytes>"
        if "__ygg_saip_tuple__" in value or "@" in value:
            tagged = value.get("__ygg_saip_tuple__") or value.get("@")
            if isinstance(tagged, list) and len(tagged) >= 1:
                return f"{key}: <tagged {tagged[0]!r}>"
            return f"{key}: <tagged>"
        size = len(value)
        return f"{key}: <object · {size} member{'s' if size != 1 else ''}>"
    if isinstance(value, list):
        return f"{key}: <list · {len(value)} item{'s' if len(value) != 1 else ''}>"
    if isinstance(value, bool):
        return f"{key}: {'true' if value else 'false'}"
    if value is None:
        return f"{key}: NULL"
    if isinstance(value, str):
        snippet = value if len(value) <= 40 else value[:37] + "..."
        return f"{key}: {snippet!r}"
    return f"{key}: {value}"


__all__ = ["GenericPeEditor"]
