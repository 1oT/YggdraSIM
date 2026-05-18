# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
PE-PINCodes and PE-PUKCodes structured editors.

The SAIP JSON shape for these PEs is:

* ``PE-PINCodes``::

      {
          "pin-Header": {"identification": 3, "mandated": None},
          "pinCodes": {
              "__ygg_saip_tuple__": ["pinconfig", [
                  {"keyReference": 1,
                   "maxNumOfAttemps-retryNumLeft": 0x33,
                   "pinAttributes": 6,
                   "pinValue": {"__ygg_saip_bytes__": "31323334ffffffff"},
                   "unblockingPINReference": 1},
                  ...
              ]]
          }
      }

* ``PE-PUKCodes`` (flat list, no tagged-tuple)::

      {
          "puk-Header": {"identification": 2, "mandated": None},
          "pukCodes": [
              {"keyReference": 1,
               "maxNumOfAttemps-retryNumLeft": 0xAA,
               "pukValue": {"__ygg_saip_bytes__": "3132333435363738"}},
              ...
          ]
      }

The packed retry counter uses 4-bit nibbles (max attempts / remaining
attempts), matching ``encode_pin_puk_retry_counter`` in
``saip_asn1_encode``.
"""

from __future__ import annotations

import re
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Static

from ..saip_apply_row import SaipApplyRow, normalize_hex_bytes_text
from ._base import (
    BasePeEditor,
    base_pe_type_for_section_key,
    hex_from_tagged_bytes,
    header_member_key_from_pe,
    header_value_from_pe,
    rebuild_pe_with_header,
    tagged_bytes,
    tagged_tuple,
    unwrap_tagged_tuple,
)
from ._header import PeHeaderForm


_HEX_REGEX = re.compile(r"^[0-9A-Fa-f]+$")


def _retry_counter_to_pair(packed: Any) -> tuple[int, int]:
    """Split the packed nibble counter into (max, remaining)."""
    if isinstance(packed, bool):
        return (0, 0)
    if isinstance(packed, int) is False:
        try:
            packed = int(packed)
        except (TypeError, ValueError):
            return (0, 0)
    packed = int(packed)
    return ((packed >> 4) & 0x0F, packed & 0x0F)


def _pair_to_retry_counter(max_attempts: int, remaining: int) -> int:
    return ((int(max_attempts) & 0x0F) << 4) | (int(remaining) & 0x0F)


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if len(text) == 0:
        return default
    try:
        return int(text, 10)
    except ValueError:
        return default


def _normalize_hex(value: Any) -> str:
    text = re.sub(r"\s+", "", str(value or "")).upper()
    if len(text) == 0:
        return ""
    if _HEX_REGEX.fullmatch(text) is None:
        return text
    if len(text) % 2 == 1:
        return text + "0"
    return text


# ---------------------------------------------------------------------------
# PIN editor
# ---------------------------------------------------------------------------


class _PinRowForm(Vertical):
    """Single PIN entry: stacked apply-rows plus remove."""

    DEFAULT_CSS = """
    _PinRowForm {
        width: 100%;
        height: auto;
        margin-top: 1;
        padding: 0 1;
        background: $boost;
        border: solid $primary;
    }
    _PinRowForm .pin_row_heading {
        width: 100%;
        height: auto;
        margin-bottom: 1;
    }
    _PinRowForm .pin_row_heading_label {
        width: 1fr;
        content-align: left middle;
        color: $text-muted;
        text-style: bold;
    }
    _PinRowForm .pin_row_remove {
        width: 8;
    }
    """

    def __init__(
        self,
        row_index: int,
        *,
        read_only: bool = False,
        initial_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._row_index = int(row_index)
        self._read_only = bool(read_only)
        self._pending_payload: dict[str, Any] = (
            dict(initial_payload) if isinstance(initial_payload, dict) else {}
        )
        self._last_payload: dict[str, Any] = dict(self._pending_payload)
        self._populating: bool = False

    def on_mount(self) -> None:
        if len(self._pending_payload) > 0:
            self.populate(self._pending_payload)
            self._pending_payload = {}

    def compose(self) -> ComposeResult:
        with Horizontal(classes="pin_row_heading"):
            yield Static(f"PIN #{self._row_index + 1}", classes="pin_row_heading_label")
            yield Button(
                "Remove",
                classes="pin_row_remove",
                id=f"pin_row_remove_{self._row_index}",
                disabled=self._read_only,
            )
        yield SaipApplyRow(
            f"pin_{self._row_index}_keyref",
            "Key reference:",
            mode="decimal",
            placeholder="1",
            hint="Decimal · Apply commits this PIN row.",
            id=f"pin_slot_{self._row_index}_keyref",
        )
        yield SaipApplyRow(
            f"pin_{self._row_index}_max",
            "Max attempts:",
            mode="decimal",
            placeholder="0–15",
            hint="Packed retry nibble (high) · Apply commits.",
            id=f"pin_slot_{self._row_index}_max",
        )
        yield SaipApplyRow(
            f"pin_{self._row_index}_remaining",
            "Remaining:",
            mode="decimal",
            placeholder="0–15",
            hint="Packed retry nibble (low) · Apply commits.",
            id=f"pin_slot_{self._row_index}_remaining",
        )
        yield SaipApplyRow(
            f"pin_{self._row_index}_attrs",
            "PIN attributes:",
            mode="decimal",
            placeholder="octet decimal",
            hint="Optional pinAttributes · empty drops on encode · Apply commits.",
            id=f"pin_slot_{self._row_index}_attrs",
        )
        yield SaipApplyRow(
            f"pin_{self._row_index}_value",
            "PIN value:",
            mode="hex",
            placeholder="hex",
            hint="Hex bytes (odd nibbles padded on encode) · Apply commits.",
            id=f"pin_slot_{self._row_index}_value",
        )
        yield SaipApplyRow(
            f"pin_{self._row_index}_unblock",
            "Unblock ref:",
            mode="decimal",
            placeholder="optional",
            hint="Optional unblockingPINReference · Apply commits.",
            id=f"pin_slot_{self._row_index}_unblock",
        )

    def _slot(self, suffix: str) -> SaipApplyRow:
        return self.query_one(f"#pin_slot_{self._row_index}_{suffix}", SaipApplyRow)

    def populate(self, payload: dict[str, Any]) -> None:
        self._populating = True
        try:
            max_a, remaining = _retry_counter_to_pair(payload.get("maxNumOfAttemps-retryNumLeft"))
            attrs = payload.get("pinAttributes")
            attrs_text = "" if attrs is None else str(int(attrs))
            unblock = payload.get("unblockingPINReference")
            unblock_text = "" if unblock is None else str(int(unblock))
            try:
                self._slot("keyref").set_draft(str(_safe_int(payload.get("keyReference"))))
                self._slot("max").set_draft(str(max_a))
                self._slot("remaining").set_draft(str(remaining))
                self._slot("attrs").set_draft(attrs_text)
                self._slot("value").set_draft(hex_from_tagged_bytes(payload.get("pinValue")) or "")
                self._slot("unblock").set_draft(unblock_text)
                for suffix in (
                    "keyref",
                    "max",
                    "remaining",
                    "attrs",
                    "value",
                    "unblock",
                ):
                    self._slot(suffix).set_read_only(self._read_only)
            except NoMatches:
                return
            self._last_payload = dict(payload)
        finally:
            self._populating = False

    def collect(self) -> dict[str, Any]:
        if self._populating:
            return dict(self._last_payload or self._pending_payload)
        try:
            keyref_text = self._slot("keyref").draft_text().strip()
        except NoMatches:
            return dict(self._last_payload or self._pending_payload)
        if len(keyref_text) == 0 and len(self._last_payload) > 0:
            return dict(self._last_payload)
        key_ref = _safe_int(keyref_text)
        max_a = _safe_int(self._slot("max").draft_text())
        remaining = _safe_int(self._slot("remaining").draft_text())
        attrs_text = self._slot("attrs").draft_text().strip()
        value_hex = _normalize_hex(normalize_hex_bytes_text(self._slot("value").draft_text()))
        unblock_text = self._slot("unblock").draft_text().strip()
        record: dict[str, Any] = {
            "keyReference": key_ref,
            "maxNumOfAttemps-retryNumLeft": _pair_to_retry_counter(max_a, remaining),
            "pinValue": tagged_bytes(value_hex),
        }
        if len(attrs_text) > 0:
            record["pinAttributes"] = _safe_int(attrs_text)
        if len(unblock_text) > 0:
            record["unblockingPINReference"] = _safe_int(unblock_text)
        self._last_payload = dict(record)
        return record


class PinCodesEditor(BasePeEditor):
    """PE-PINCodes structured editor."""

    DEFAULT_CSS = """
    PinCodesEditor {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    PinCodesEditor .pin_section_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 1;
        margin-top: 1;
    }
    PinCodesEditor .pin_rows_host {
        width: 100%;
        height: auto;
        padding: 0 1;
    }
    PinCodesEditor .pin_actions_row {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    PinCodesEditor .pin_actions_row Button {
        margin-right: 1;
    }
    PinCodesEditor .pin_section_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
        margin-top: 1;
    }
    """

    PE_TYPE_LABEL = "PE-PINCodes"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._row_count = 0
        # Set while ``rebuild_form`` is re-populating rows. Cleared by
        # ``_exit_rebuilding`` via ``call_after_refresh``. Kept as a
        # belt-and-braces fallback in addition to the per-form
        # ``_populating`` check inside ``on_input_changed``.
        self._rebuilding: bool = False

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="pin_pe_header",
        )
        yield Static("PIN entries", classes="pin_section_title")
        yield Vertical(id="pin_rows_host", classes="pin_rows_host")
        with Horizontal(classes="pin_actions_row"):
            yield Button("+ Add PIN", id="pin_add_row")
            yield Button("⟳ Re-emit", id="pin_reemit")
        yield Static(
            "Each field has Apply. Hex inputs strip whitespace, dashes, 0x. "
            "Attrs is pinAttributes as decimal (e.g. 6). Empty unblock ref drops the member.",
            classes="pin_section_note",
        )

    def rebuild_form(self) -> None:
        header_payload = header_value_from_pe(self._pe_value) or {}
        header_form = self.query_one("#pin_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header_payload,
            read_only=self._read_only,
        )
        records = _extract_pin_records(self._pe_value)
        host = self.query_one("#pin_rows_host", Vertical)
        self._rebuilding = True
        for child in list(host.children):
            child.remove()
        self._row_count = len(records)
        for index, record in enumerate(records):
            host.mount(
                _PinRowForm(
                    index,
                    read_only=self._read_only,
                    initial_payload=record,
                ),
            )
        if self._row_count == 0:
            host.mount(
                Static(
                    "(empty pinconfig — use '+ Add PIN' to create the first entry)",
                    classes="pin_section_note",
                ),
            )
        # Drop the guard after every pending mount + populate has run
        # so subsequent user edits resume firing emit_change.
        self.call_after_refresh(self._exit_rebuilding)

    def _exit_rebuilding(self) -> None:
        self._rebuilding = False

    def _row_at(self, index: int) -> _PinRowForm | None:
        host = self.query_one("#pin_rows_host", Vertical)
        rows = [child for child in host.children if isinstance(child, _PinRowForm)]
        if index < 0 or index >= len(rows):
            return None
        return rows[index]

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value) or "pin-Header"
        )
        new_pe = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self._pe_value = new_pe
        self.emit_change(summary="PIN PE header updated")

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._read_only:
            return
        if str(event.row_id or "").startswith("pin_") is False:
            return
        if self._rebuilding:
            return
        walker: Any = event.row
        while walker is not None:
            if isinstance(walker, _PinRowForm):
                if walker._populating:
                    return
                break
            walker = getattr(walker, "parent", None)
        self._collect_and_emit("PIN field applied")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._read_only:
            return
        button_id = str(event.button.id or "")
        if button_id == "pin_add_row":
            self._add_row()
            return
        if button_id == "pin_reemit":
            self._collect_and_emit("PIN PE re-emitted")
            return
        if button_id.startswith("pin_row_remove_"):
            try:
                index = int(button_id.rsplit("_", 1)[-1])
            except ValueError:
                return
            self._remove_row(index)

    def _add_row(self) -> None:
        host = self.query_one("#pin_rows_host", Vertical)
        index = self._row_count
        host.mount(
            _PinRowForm(
                index,
                read_only=False,
                initial_payload={
                    "keyReference": 1,
                    "maxNumOfAttemps-retryNumLeft": _pair_to_retry_counter(3, 3),
                    "pinValue": tagged_bytes("3131313131313131"),
                },
            ),
        )
        self._row_count += 1
        self.call_after_refresh(self._collect_and_emit, "PIN row added")

    def _remove_row(self, index: int) -> None:
        records = self._collect_records()
        if index < 0 or index >= len(records):
            return
        records.pop(index)
        self._pe_value = _rebuild_pin_pe(self._pe_value, records)
        self.rebuild_form()
        self.emit_change(summary="PIN row removed")

    def _collect_records(self) -> list[dict[str, Any]]:
        host = self.query_one("#pin_rows_host", Vertical)
        return [
            child.collect()
            for child in host.children
            if isinstance(child, _PinRowForm)
        ]

    def _collect_and_emit(self, summary: str) -> None:
        records = self._collect_records()
        self._pe_value = _rebuild_pin_pe(self._pe_value, records)
        self.emit_change(summary=summary)


def _extract_pin_records(pe_value: Any) -> list[dict[str, Any]]:
    if isinstance(pe_value, dict) is False:
        return []
    pin_node = pe_value.get("pinCodes")
    tagged = unwrap_tagged_tuple(pin_node)
    if tagged is None:
        return []
    _tag, payload = tagged
    if isinstance(payload, list) is False:
        return []
    records: list[dict[str, Any]] = []
    for entry in payload:
        if isinstance(entry, dict):
            records.append(entry)
    return records


def _rebuild_pin_pe(
    original: Any,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    new_pe: dict[str, Any] = {}
    if isinstance(original, dict):
        for key, value in original.items():
            if key == "pinCodes":
                continue
            new_pe[key] = value
    if header_member_key_from_pe(new_pe) is None:
        # Always materialise a header so the PE is round-tripable.
        new_pe.setdefault("pin-Header", {"mandated": None, "identification": 0})
    new_pe["pinCodes"] = tagged_tuple("pinconfig", list(records))
    return new_pe


# ---------------------------------------------------------------------------
# PUK editor
# ---------------------------------------------------------------------------


class _PukRowForm(Vertical):

    DEFAULT_CSS = """
    _PukRowForm {
        width: 100%;
        height: auto;
        margin-top: 1;
        padding: 0 1;
        background: $boost;
        border: solid $primary;
    }
    _PukRowForm .puk_row_heading {
        width: 100%;
        height: auto;
        margin-bottom: 1;
    }
    _PukRowForm .puk_row_heading_label {
        width: 1fr;
        content-align: left middle;
        color: $text-muted;
        text-style: bold;
    }
    _PukRowForm .puk_row_remove {
        width: 8;
    }
    """

    def __init__(
        self,
        row_index: int,
        *,
        read_only: bool = False,
        initial_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._row_index = int(row_index)
        self._read_only = bool(read_only)
        self._pending_payload: dict[str, Any] = (
            dict(initial_payload) if isinstance(initial_payload, dict) else {}
        )
        self._last_payload: dict[str, Any] = dict(self._pending_payload)
        self._populating: bool = False

    def on_mount(self) -> None:
        if len(self._pending_payload) > 0:
            self.populate(self._pending_payload)
            self._pending_payload = {}

    def compose(self) -> ComposeResult:
        with Horizontal(classes="puk_row_heading"):
            yield Static(f"PUK #{self._row_index + 1}", classes="puk_row_heading_label")
            yield Button(
                "Remove",
                classes="puk_row_remove",
                id=f"puk_row_remove_{self._row_index}",
                disabled=self._read_only,
            )
        yield SaipApplyRow(
            f"puk_{self._row_index}_keyref",
            "Key reference:",
            mode="decimal",
            placeholder="1",
            hint="Decimal · Apply commits this PUK row.",
            id=f"puk_slot_{self._row_index}_keyref",
        )
        yield SaipApplyRow(
            f"puk_{self._row_index}_max",
            "Max attempts:",
            mode="decimal",
            placeholder="0–15",
            hint="Packed retry nibble (high) · Apply commits.",
            id=f"puk_slot_{self._row_index}_max",
        )
        yield SaipApplyRow(
            f"puk_{self._row_index}_remaining",
            "Remaining:",
            mode="decimal",
            placeholder="0–15",
            hint="Packed retry nibble (low) · Apply commits.",
            id=f"puk_slot_{self._row_index}_remaining",
        )
        yield SaipApplyRow(
            f"puk_{self._row_index}_value",
            "PUK value:",
            mode="hex",
            placeholder="hex",
            hint="Hex OCTET STRING body · Apply commits.",
            id=f"puk_slot_{self._row_index}_value",
        )

    def _slot(self, suffix: str) -> SaipApplyRow:
        return self.query_one(f"#puk_slot_{self._row_index}_{suffix}", SaipApplyRow)

    def populate(self, payload: dict[str, Any]) -> None:
        self._populating = True
        try:
            max_a, remaining = _retry_counter_to_pair(
                payload.get("maxNumOfAttemps-retryNumLeft")
            )
            try:
                self._slot("keyref").set_draft(str(_safe_int(payload.get("keyReference"))))
                self._slot("max").set_draft(str(max_a))
                self._slot("remaining").set_draft(str(remaining))
                self._slot("value").set_draft(hex_from_tagged_bytes(payload.get("pukValue")) or "")
                for suffix in ("keyref", "max", "remaining", "value"):
                    self._slot(suffix).set_read_only(self._read_only)
            except NoMatches:
                return
            self._last_payload = dict(payload)
        finally:
            self._populating = False

    def collect(self) -> dict[str, Any]:
        if self._populating:
            return dict(self._last_payload or self._pending_payload)
        try:
            keyref_text = self._slot("keyref").draft_text().strip()
        except NoMatches:
            return dict(self._last_payload or self._pending_payload)
        if len(keyref_text) == 0 and len(self._last_payload) > 0:
            return dict(self._last_payload)
        key_ref = _safe_int(keyref_text)
        max_a = _safe_int(self._slot("max").draft_text())
        remaining = _safe_int(self._slot("remaining").draft_text())
        value_hex = _normalize_hex(normalize_hex_bytes_text(self._slot("value").draft_text()))
        record = {
            "keyReference": key_ref,
            "maxNumOfAttemps-retryNumLeft": _pair_to_retry_counter(max_a, remaining),
            "pukValue": tagged_bytes(value_hex),
        }
        self._last_payload = dict(record)
        return record


class PukCodesEditor(BasePeEditor):
    """PE-PUKCodes structured editor."""

    DEFAULT_CSS = """
    PukCodesEditor {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    PukCodesEditor .puk_section_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 1;
        margin-top: 1;
    }
    PukCodesEditor .puk_rows_host {
        width: 100%;
        height: auto;
        padding: 0 1;
    }
    PukCodesEditor .puk_actions_row {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    PukCodesEditor .puk_actions_row Button {
        margin-right: 1;
    }
    PukCodesEditor .puk_section_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
        margin-top: 1;
    }
    """

    PE_TYPE_LABEL = "PE-PUKCodes"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._row_count = 0
        self._rebuilding: bool = False

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="puk_pe_header",
        )
        yield Static("PUK entries", classes="puk_section_title")
        yield Vertical(id="puk_rows_host", classes="puk_rows_host")
        with Horizontal(classes="puk_actions_row"):
            yield Button("+ Add PUK", id="puk_add_row")
            yield Button("⟳ Re-emit", id="puk_reemit")
        yield Static(
            "Each field has Apply. PUK body is hex (whitespace and 0x stripped on commit).",
            classes="puk_section_note",
        )

    def rebuild_form(self) -> None:
        header_payload = header_value_from_pe(self._pe_value) or {}
        header_form = self.query_one("#puk_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header_payload,
            read_only=self._read_only,
        )
        records = _extract_puk_records(self._pe_value)
        host = self.query_one("#puk_rows_host", Vertical)
        self._rebuilding = True
        for child in list(host.children):
            child.remove()
        self._row_count = len(records)
        for index, record in enumerate(records):
            host.mount(
                _PukRowForm(
                    index,
                    read_only=self._read_only,
                    initial_payload=record,
                ),
            )
        if self._row_count == 0:
            host.mount(
                Static(
                    "(empty pukCodes list — use '+ Add PUK' to create the first entry)",
                    classes="puk_section_note",
                ),
            )
        self.call_after_refresh(self._exit_rebuilding)

    def _exit_rebuilding(self) -> None:
        self._rebuilding = False

    def _row_at(self, index: int) -> _PukRowForm | None:
        host = self.query_one("#puk_rows_host", Vertical)
        rows = [child for child in host.children if isinstance(child, _PukRowForm)]
        if index < 0 or index >= len(rows):
            return None
        return rows[index]

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value) or "puk-Header"
        )
        new_pe = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self._pe_value = new_pe
        self.emit_change(summary="PUK PE header updated")

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._read_only:
            return
        if str(event.row_id or "").startswith("puk_") is False:
            return
        if self._rebuilding:
            return
        walker: Any = event.row
        while walker is not None:
            if isinstance(walker, _PukRowForm):
                if walker._populating:
                    return
                break
            walker = getattr(walker, "parent", None)
        self._collect_and_emit("PUK field applied")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._read_only:
            return
        button_id = str(event.button.id or "")
        if button_id == "puk_add_row":
            self._add_row()
            return
        if button_id == "puk_reemit":
            self._collect_and_emit("PUK PE re-emitted")
            return
        if button_id.startswith("puk_row_remove_"):
            try:
                index = int(button_id.rsplit("_", 1)[-1])
            except ValueError:
                return
            self._remove_row(index)

    def _add_row(self) -> None:
        host = self.query_one("#puk_rows_host", Vertical)
        index = self._row_count
        host.mount(
            _PukRowForm(
                index,
                read_only=False,
                initial_payload={
                    "keyReference": 1,
                    "maxNumOfAttemps-retryNumLeft": _pair_to_retry_counter(10, 10),
                    "pukValue": tagged_bytes("3131313131313131"),
                },
            ),
        )
        self._row_count += 1
        self.call_after_refresh(self._collect_and_emit, "PUK row added")

    def _remove_row(self, index: int) -> None:
        records = self._collect_records()
        if index < 0 or index >= len(records):
            return
        records.pop(index)
        self._pe_value = _rebuild_puk_pe(self._pe_value, records)
        self.rebuild_form()
        self.emit_change(summary="PUK row removed")

    def _collect_records(self) -> list[dict[str, Any]]:
        host = self.query_one("#puk_rows_host", Vertical)
        return [
            child.collect()
            for child in host.children
            if isinstance(child, _PukRowForm)
        ]

    def _collect_and_emit(self, summary: str) -> None:
        records = self._collect_records()
        self._pe_value = _rebuild_puk_pe(self._pe_value, records)
        self.emit_change(summary=summary)


def _extract_puk_records(pe_value: Any) -> list[dict[str, Any]]:
    if isinstance(pe_value, dict) is False:
        return []
    raw = pe_value.get("pukCodes")
    if isinstance(raw, list) is False:
        return []
    return [item for item in raw if isinstance(item, dict)]


def _rebuild_puk_pe(
    original: Any,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    new_pe: dict[str, Any] = {}
    if isinstance(original, dict):
        for key, value in original.items():
            if key == "pukCodes":
                continue
            new_pe[key] = value
    if header_member_key_from_pe(new_pe) is None:
        new_pe.setdefault("puk-Header", {"mandated": None, "identification": 0})
    new_pe["pukCodes"] = list(records)
    return new_pe


__all__ = ["PinCodesEditor", "PukCodesEditor"]
