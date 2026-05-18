# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
PE-AKAParameter / PE-AKAParameter2 structured editor.

Mirrors the SAIP shape::

    {
        "aka-header": {"identification": ..., "mandated": None},
        "algoConfiguration": {
            "__ygg_saip_tuple__": ["algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": {"__ygg_saip_bytes__": "01"},
                ...
            }],
        },
        "sqnOptions": {"__ygg_saip_bytes__": "0e"},
        ...
        "sqnInit": [{"__ygg_saip_bytes__": "..."}, ...],
    }

Hex parameters use label + draft + Apply per row (normalisation matches
the shared SAIP apply-row helper). Algorithm choice stays on the option
list (immediate).
"""

from __future__ import annotations

import copy
import re
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, OptionList, Static
from textual.widgets.option_list import Option

from ..saip_apply_row import SaipApplyRow, normalize_hex_bytes_text
from ._base import (
    BasePeEditor,
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
_AKA_ALGORITHM_NAMES: dict[int, str] = {
    1: "milenage",
    2: "tuak",
    3: "usim-test-algorithm",
}


def _normalize_hex(value: Any) -> str:
    text = re.sub(r"\s+", "", str(value or "")).upper()
    if len(text) == 0:
        return ""
    if _HEX_REGEX.fullmatch(text) is None:
        return text
    if len(text) % 2 == 1:
        return text + "0"
    return text


class _AkaSqnRowBlock(Vertical):
    """One sqnInit slot with apply-row + remove."""

    DEFAULT_CSS = """
    _AkaSqnRowBlock {
        width: 100%;
        height: auto;
        margin-top: 1;
        padding: 0 1;
        border: solid $primary;
        background: $boost;
    }
    _AkaSqnRowBlock .aka_sqn_rm_row {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        index: int,
        *,
        read_only: bool = False,
        initial_hex: str = "",
    ) -> None:
        super().__init__(id=f"aka_sqn_block_{index}")
        self._index = int(index)
        self._read_only = bool(read_only)
        self._initial_hex = str(initial_hex or "")

    def compose(self) -> ComposeResult:
        yield Static(f"SQN init [{self._index}]", classes="aka_section_note")
        yield SaipApplyRow(
            f"aka_sqn_{self._index}",
            "Counter:",
            mode="hex",
            placeholder="6-byte hex",
            hint="Apply commits sqnInit with other AKA fields.",
            id=f"aka_sqn_slot_{self._index}",
        )
        with Horizontal(classes="aka_sqn_rm_row"):
            yield Button(
                "Remove slot",
                id=f"aka_sqn_remove_{self._index}",
                disabled=self._read_only,
            )

    def on_mount(self) -> None:
        slot = self.query_one(f"#aka_sqn_slot_{self._index}", SaipApplyRow)
        slot.set_draft(self._initial_hex)
        slot.set_read_only(self._read_only)

    def draft_hex(self) -> str:
        slot = self.query_one(f"#aka_sqn_slot_{self._index}", SaipApplyRow)
        return _normalize_hex(normalize_hex_bytes_text(slot.draft_text()))


class AkaParameterEditor(BasePeEditor):
    """Structured editor for PE-AKAParameter / PE-AKAParameter2."""

    DEFAULT_CSS = """
    AkaParameterEditor {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    AkaParameterEditor .aka_section_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 1;
        margin-top: 1;
    }
    AkaParameterEditor .aka_algo_options {
        width: 100%;
        height: 6;
        margin-top: 1;
        padding: 0 1;
    }
    AkaParameterEditor .aka_section_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
        margin-top: 1;
    }
    AkaParameterEditor .aka_sqn_host {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    AkaParameterEditor .aka_actions_row {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    AkaParameterEditor .aka_actions_row Button {
        margin-right: 1;
    }
    """

    PE_TYPE_LABEL = "PE-AKAParameter"

    _CORE_HEX_FIELDS: tuple[tuple[str, str, str], ...] = (
        ("key", "K (subscriber key)", "32 hex chars"),
        ("opc", "OP(c)", "32 hex chars"),
        ("algorithmOptions", "algorithmOptions", "1 byte"),
        ("authCounterMax", "authCounterMax", "3 byte counter"),
        ("rotationConstants", "rotationConstants", "5 bytes (R1..R5)"),
        ("xoringConstants", "xoringConstants", "5 × 16 bytes"),
        ("sqnOptions", "sqnOptions", "1 byte"),
        ("sqnDelta", "sqnDelta", "6 bytes"),
        ("sqnAgeLimit", "sqnAgeLimit", "6 bytes"),
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._sqn_count = 0
        self._algo_options: list[tuple[int, str]] = sorted(
            [(value, name) for value, name in _AKA_ALGORITHM_NAMES.items()],
        )

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="aka_pe_header",
        )
        yield Static("Algorithm", classes="aka_section_title")
        yield OptionList(
            *(
                Option(f"{algo_id}: {name}", id=str(algo_id))
                for algo_id, name in self._algo_options
            ),
            id="aka_algorithm_picker",
            classes="aka_algo_options",
        )
        yield Static("Algorithm parameters", classes="aka_section_title")
        yield Static(
            "Hex rows strip whitespace, dashes, 0x on Apply. Structural checks run at re-encode.",
            classes="aka_section_note",
        )
        for field_id, label, placeholder in self._CORE_HEX_FIELDS:
            yield SaipApplyRow(
                f"aka_{field_id}",
                f"{label}:",
                mode="hex",
                placeholder=placeholder,
                hint="Apply commits algorithm payload and SQN fields.",
                id=f"aka_slot_{field_id}",
            )
        yield SaipApplyRow(
            "aka_numberOfKeccak",
            "numberOfKeccak:",
            mode="decimal",
            placeholder="decimal",
            hint="TUAK rounds · optional · Apply commits.",
            id="aka_slot_numberOfKeccak",
        )
        yield Static("SQN init list", classes="aka_section_title")
        yield Vertical(id="aka_sqn_host", classes="aka_sqn_host")
        with Horizontal(classes="aka_actions_row"):
            yield Button("+ Add SQN init slot", id="aka_sqn_add")
            yield Button("⟳ Re-emit", id="aka_reemit")
        yield Static(
            "3GPP TS 35.206 (MILENAGE), TS 35.231 (TUAK).",
            classes="aka_section_note",
        )

    def rebuild_form(self) -> None:
        header_form = self.query_one("#aka_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header_value_from_pe(self._pe_value) or {},
            read_only=self._read_only,
        )
        algo_id, algo_payload = self._extract_algo_payload(self._pe_value)
        self._set_algorithm_picker(algo_id)
        for field_id, _label, _placeholder in self._CORE_HEX_FIELDS:
            slot = self.query_one(f"#aka_slot_{field_id}", SaipApplyRow)
            value = self._field_value(field_id, algo_payload, self._pe_value)
            slot.set_draft(value)
            slot.set_read_only(self._read_only)
        keccak_slot = self.query_one("#aka_slot_numberOfKeccak", SaipApplyRow)
        keccak_value = algo_payload.get("numberOfKeccak") if isinstance(algo_payload, dict) else None
        if isinstance(keccak_value, int) and isinstance(keccak_value, bool) is False:
            keccak_slot.set_draft(str(keccak_value))
        else:
            keccak_slot.set_draft("" if keccak_value is None else str(keccak_value))
        keccak_slot.set_read_only(self._read_only)

        host = self.query_one("#aka_sqn_host", Vertical)
        for child in list(host.children):
            child.remove()
        sqn_init = self._extract_sqn_init(self._pe_value)
        self._sqn_count = len(sqn_init)
        if self._sqn_count == 0:
            host.mount(
                Static(
                    "(empty sqnInit list — use '+ Add SQN init slot' to add one)",
                    classes="aka_section_note",
                ),
            )
            return
        for index, sqn_hex in enumerate(sqn_init):
            host.mount(
                _AkaSqnRowBlock(index, read_only=self._read_only, initial_hex=sqn_hex),
            )

    def _set_algorithm_picker(self, algo_id: int | None) -> None:
        picker = self.query_one("#aka_algorithm_picker", OptionList)
        picker.disabled = self._read_only
        if algo_id is None:
            return
        option_id = str(int(algo_id))
        try:
            target_index = picker.get_option_index(option_id)
        except Exception:
            target_index = None
        if isinstance(target_index, int):
            picker.highlighted = target_index

    def _field_value(
        self,
        field_id: str,
        algo_payload: dict[str, Any],
        pe_value: Any,
    ) -> str:
        if field_id in {"sqnOptions", "sqnDelta", "sqnAgeLimit"}:
            return hex_from_tagged_bytes(pe_value.get(field_id) if isinstance(pe_value, dict) else None) or ""
        return hex_from_tagged_bytes(algo_payload.get(field_id)) or ""

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value) or "aka-header"
        )
        self._pe_value = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self.emit_change(summary="AKA PE header updated")

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._read_only:
            return
        rid = str(event.row_id or "")
        if rid.startswith("aka_") is False:
            return
        self._collect_and_emit("AKA field applied")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if self._read_only:
            return
        if str(event.option_list.id or "") != "aka_algorithm_picker":
            return
        try:
            algo_id = int(str(event.option.id or "0").strip())
        except ValueError:
            return
        algo_payload = self._collect_algo_payload()
        algo_payload["algorithmID"] = algo_id
        self._pe_value = self._compose_pe_value(algo_payload)
        self.emit_change(
            summary=f"Algorithm set to {_AKA_ALGORITHM_NAMES.get(algo_id, str(algo_id))}",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._read_only:
            return
        button_id = str(event.button.id or "")
        if button_id == "aka_reemit":
            self._collect_and_emit("AKA PE re-emitted")
            return
        if button_id == "aka_sqn_add":
            self._add_sqn_row()
            return
        if button_id.startswith("aka_sqn_remove_"):
            try:
                index = int(button_id.rsplit("_", 1)[-1])
            except ValueError:
                return
            self._remove_sqn_row(index)

    def _collect_sqn_drafts(self) -> list[str]:
        host = self.query_one("#aka_sqn_host", Vertical)
        values: list[str] = []
        for child in host.children:
            if isinstance(child, _AkaSqnRowBlock):
                values.append(child.draft_hex())
        return values

    def _add_sqn_row(self) -> None:
        host = self.query_one("#aka_sqn_host", Vertical)
        if self._sqn_count == 0:
            for child in list(host.children):
                child.remove()
        index = self._sqn_count
        host.mount(_AkaSqnRowBlock(index, read_only=False, initial_hex="000000000000"))
        self._sqn_count += 1
        self._collect_and_emit("SQN init slot added")

    def _remove_sqn_row(self, index: int) -> None:
        sqn_values = self._collect_sqn_drafts()
        if index < 0 or index >= len(sqn_values):
            return
        sqn_values.pop(index)
        algo_payload = self._collect_algo_payload()
        self._pe_value = self._compose_pe_value(algo_payload, sqn_init_override=sqn_values)
        self.rebuild_form()
        self.emit_change(summary="SQN init slot removed")

    def _collect_algo_payload(self) -> dict[str, Any]:
        algo_id, current_payload = self._extract_algo_payload(self._pe_value)
        merged: dict[str, Any] = {}
        if isinstance(current_payload, dict):
            merged.update(copy.deepcopy(current_payload))
        if algo_id is not None:
            merged["algorithmID"] = algo_id
        try:
            picker = self.query_one("#aka_algorithm_picker", OptionList)
            highlighted = picker.highlighted
            if isinstance(highlighted, int) and 0 <= highlighted < len(self._algo_options):
                merged["algorithmID"] = self._algo_options[highlighted][0]
        except Exception:
            pass
        for field_id, _label, _placeholder in self._CORE_HEX_FIELDS:
            if field_id in {"sqnOptions", "sqnDelta", "sqnAgeLimit"}:
                continue
            slot = self.query_one(f"#aka_slot_{field_id}", SaipApplyRow)
            normalized = _normalize_hex(normalize_hex_bytes_text(slot.draft_text()))
            if len(normalized) == 0:
                merged.pop(field_id, None)
                continue
            merged[field_id] = tagged_bytes(normalized)
        keccak_slot = self.query_one("#aka_slot_numberOfKeccak", SaipApplyRow)
        keccak_text = str(keccak_slot.draft_text() or "").strip()
        if len(keccak_text) == 0:
            merged.pop("numberOfKeccak", None)
        else:
            try:
                merged["numberOfKeccak"] = int(keccak_text, 10)
            except ValueError:
                pass
        return merged

    def _compose_pe_value(
        self,
        algo_payload: dict[str, Any],
        *,
        sqn_init_override: list[str] | None = None,
    ) -> dict[str, Any]:
        new_pe: dict[str, Any] = {}
        if isinstance(self._pe_value, dict):
            for key, value in self._pe_value.items():
                new_pe[key] = value
        if header_member_key_from_pe(new_pe) is None:
            new_pe.setdefault("aka-header", {"mandated": None, "identification": 0})
        new_pe["algoConfiguration"] = tagged_tuple("algoParameter", algo_payload)
        for field_id in ("sqnOptions", "sqnDelta", "sqnAgeLimit"):
            slot = self.query_one(f"#aka_slot_{field_id}", SaipApplyRow)
            normalized = _normalize_hex(normalize_hex_bytes_text(slot.draft_text()))
            if len(normalized) == 0:
                new_pe.pop(field_id, None)
                continue
            new_pe[field_id] = tagged_bytes(normalized)
        if sqn_init_override is None:
            sqn_values = self._collect_sqn_drafts()
        else:
            sqn_values = list(sqn_init_override)
        if len(sqn_values) == 0:
            new_pe.pop("sqnInit", None)
        else:
            new_pe["sqnInit"] = [tagged_bytes(value) for value in sqn_values]
        return new_pe

    def _collect_and_emit(self, summary: str) -> None:
        algo_payload = self._collect_algo_payload()
        self._pe_value = self._compose_pe_value(algo_payload)
        self.emit_change(summary=summary)

    def _extract_algo_payload(self, pe_value: Any) -> tuple[int | None, dict[str, Any]]:
        if isinstance(pe_value, dict) is False:
            return (None, {})
        algo_node = pe_value.get("algoConfiguration")
        tagged = unwrap_tagged_tuple(algo_node)
        if tagged is None:
            return (None, {})
        _tag, payload = tagged
        if isinstance(payload, dict) is False:
            return (None, {})
        algo_id = payload.get("algorithmID")
        if isinstance(algo_id, bool) or isinstance(algo_id, int) is False:
            algo_id_int = None
        else:
            algo_id_int = int(algo_id)
        return (algo_id_int, payload)

    def _extract_sqn_init(self, pe_value: Any) -> list[str]:
        if isinstance(pe_value, dict) is False:
            return []
        raw = pe_value.get("sqnInit")
        if isinstance(raw, list) is False:
            return []
        return [hex_from_tagged_bytes(item) or "" for item in raw]


__all__ = ["AkaParameterEditor"]
