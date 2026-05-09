# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Reusable SAIP profile-element header form.

Every SAIP PE carries the two-field ``ProfileHeader`` (``mandated``,
``identification``) under a ``*-header`` / ``*-Header`` member. This
module exposes the form widget that the per-PE editors mount at the top
of their layout. Mirrors the screenshot's "Header" group with three
inputs (Name, Identification, Mandated) — the Name is read-only because
SAIP does not expose a renamable instance label, the JSON section key
is what the operator edits.
"""

from __future__ import annotations

import copy
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Checkbox, Static

from ..saip_apply_row import SaipApplyRow


class PeHeaderForm(Vertical):
    """Two-field SAIP profile-element header form."""

    DEFAULT_CSS = """
    PeHeaderForm {
        width: 100%;
        height: auto;
        padding: 0 1;
        background: $surface;
        border: solid $accent;
        margin-bottom: 1;
    }
    PeHeaderForm > .pe_header_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
    }
    PeHeaderForm > .pe_header_row {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    PeHeaderForm .pe_header_label {
        width: 18;
        content-align: left middle;
        padding-right: 1;
    }
    PeHeaderForm .pe_header_input {
        width: 1fr;
    }
    PeHeaderForm .pe_header_name_value {
        width: 1fr;
        content-align: left middle;
        color: $text;
    }
    PeHeaderForm .pe_header_mandated {
        width: 1fr;
    }
    """

    class Changed(Message):
        def __init__(
            self,
            form: "PeHeaderForm",
            *,
            mandated: bool,
            identification: int | None,
            identification_text: str,
        ) -> None:
            super().__init__()
            self.form = form
            self.mandated = bool(mandated)
            self.identification = identification
            self.identification_text = str(identification_text or "")

    def __init__(
        self,
        *,
        section_label: str = "",
        header_payload: dict[str, Any] | None = None,
        read_only: bool = False,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._section_label = str(section_label or "").strip()
        self._payload = (
            copy.deepcopy(header_payload) if isinstance(header_payload, dict) else {}
        )
        self._read_only = bool(read_only)
        self._suppress_emit = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static("Header", classes="pe_header_title")
        with Horizontal(classes="pe_header_row"):
            yield Static("Name:", classes="pe_header_label")
            yield Static(
                self._section_label or "(no section selected)",
                classes="pe_header_name_value",
            )
        yield SaipApplyRow(
            "pe_header_identification",
            "Identification:",
            mode="decimal",
            placeholder="0..255",
            hint="Decimal 0..255 · cleared draft clears identification on Apply.",
            id="pe_header_identification_row",
        )
        with Horizontal(classes="pe_header_row"):
            yield Static("Mandated:", classes="pe_header_label")
            yield Checkbox(
                "Marked mandated (NULL present)",
                classes="pe_header_mandated",
                id="pe_header_mandated",
            )

    def on_mount(self) -> None:
        self._refresh_widgets()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def update_header(
        self,
        *,
        section_label: str | None = None,
        header_payload: dict[str, Any] | None = None,
        read_only: bool | None = None,
    ) -> None:
        if section_label is not None:
            self._section_label = str(section_label or "").strip()
        if header_payload is not None:
            self._payload = copy.deepcopy(header_payload)
        if read_only is not None:
            self._read_only = bool(read_only)
        if self.is_mounted:
            self._refresh_widgets()

    def current_payload(self) -> dict[str, Any]:
        return copy.deepcopy(self._payload)

    def _refresh_widgets(self) -> None:
        ident = self._payload.get("identification") if isinstance(self._payload, dict) else None
        mandated = self._payload.get("mandated") if isinstance(self._payload, dict) else None
        self._suppress_emit = True
        try:
            ident_row = self.query_one("#pe_header_identification_row", SaipApplyRow)
            mandated_box = self.query_one("#pe_header_mandated", Checkbox)
            if isinstance(ident, int) and isinstance(ident, bool) is False:
                ident_row.set_draft(str(ident))
            elif isinstance(ident, str):
                ident_row.set_draft(ident.strip())
            else:
                ident_row.set_draft("")
            ident_row.set_read_only(self._read_only)
            mandated_box.value = mandated is not None
            mandated_box.disabled = self._read_only
            for static in self.query(".pe_header_name_value"):
                if isinstance(static, Static):
                    static.update(self._section_label or "(no section selected)")
        finally:
            # Defer clearing the suppression flag until after Textual has
            # drained any ``Input.Changed`` / ``Checkbox.Changed`` events that
            # the value-assignments above queued. Otherwise the next
            # microtask fires the change handlers with stale ``_suppress_emit``.
            self.call_after_refresh(self._clear_suppress_emit)

    def _clear_suppress_emit(self) -> None:
        self._suppress_emit = False

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._suppress_emit or self._read_only:
            return
        if event.row_id != "pe_header_identification":
            return
        text = str(event.value or "").strip()
        ident_value: int | None
        if len(text) == 0:
            ident_value = None
        else:
            try:
                ident_value = int(text, 10)
            except ValueError:
                ident_value = None
        next_payload = dict(self._payload) if isinstance(self._payload, dict) else {}
        if ident_value is None:
            next_payload.pop("identification", None)
        else:
            next_payload["identification"] = ident_value
        self._payload = next_payload
        self._post_changed(text)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if self._suppress_emit or self._read_only:
            return
        if event.checkbox.id != "pe_header_mandated":
            return
        next_payload = dict(self._payload) if isinstance(self._payload, dict) else {}
        if event.value:
            next_payload["mandated"] = None
        else:
            next_payload.pop("mandated", None)
        self._payload = next_payload
        ident_row = self.query_one("#pe_header_identification_row", SaipApplyRow)
        self._post_changed(ident_row.draft_text())

    def _post_changed(self, ident_text: str) -> None:
        ident_value = self._payload.get("identification") if isinstance(self._payload, dict) else None
        mandated = self._payload.get("mandated") if isinstance(self._payload, dict) else None
        self.post_message(
            self.Changed(
                self,
                mandated=mandated is not None,
                identification=(ident_value if isinstance(ident_value, int) else None),
                identification_text=ident_text,
            )
        )


__all__ = ["PeHeaderForm"]
