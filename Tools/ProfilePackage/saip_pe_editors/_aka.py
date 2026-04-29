"""
PE-AKAParameter / PE-AKAParameter2 structured editor.

Mirrors the SAIP shape::

    {
        "aka-header": {"identification": ..., "mandated": None},
        "algoConfiguration": {
            "__ygg_saip_tuple__": ["algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": {"__ygg_saip_bytes__": "01"},
                "authCounterMax": {"__ygg_saip_bytes__": "ffffff"},
                "key": {"__ygg_saip_bytes__": "..."},
                "opc": {"__ygg_saip_bytes__": "..."},
                "numberOfKeccak": 1,
                "rotationConstants": {"__ygg_saip_bytes__": "..."},
                "xoringConstants": {"__ygg_saip_bytes__": "..."},
            }],
        },
        "sqnOptions": {"__ygg_saip_bytes__": "0e"},
        "sqnDelta": {"__ygg_saip_bytes__": "..."},
        "sqnAgeLimit": {"__ygg_saip_bytes__": "..."},
        "sqnInit": [{"__ygg_saip_bytes__": "..."}, ...],
    }

The form exposes the algorithm dropdown plus K / OP(c) / R / C and SQN
counters as hex inputs. Round-trip uses the existing tagged-bytes
encoders by writing the form values straight back as ``tagged_bytes``
dicts.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, OptionList, Static
from textual.widgets.option_list import Option

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
    AkaParameterEditor .aka_field_row {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    AkaParameterEditor .aka_field_label {
        width: 24;
        content-align: left middle;
        color: $text;
    }
    AkaParameterEditor .aka_field_input {
        width: 1fr;
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
    AkaParameterEditor .aka_sqn_row {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    AkaParameterEditor .aka_sqn_label {
        width: 12;
        content-align: left middle;
        color: $text-muted;
    }
    AkaParameterEditor .aka_sqn_input {
        width: 1fr;
        margin-right: 1;
    }
    AkaParameterEditor .aka_sqn_remove {
        width: 6;
        margin-left: 1;
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

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

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
        for field_id, label, placeholder in self._CORE_HEX_FIELDS:
            with Horizontal(classes="aka_field_row"):
                yield Static(label, classes="aka_field_label")
                yield Input(
                    value="",
                    placeholder=placeholder,
                    classes="aka_field_input",
                    id=f"aka_field_{field_id}",
                )
        with Horizontal(classes="aka_field_row"):
            yield Static("numberOfKeccak", classes="aka_field_label")
            yield Input(
                value="",
                placeholder="decimal",
                classes="aka_field_input",
                id="aka_field_numberOfKeccak",
            )
        yield Static("SQN init list", classes="aka_section_title")
        yield Vertical(id="aka_sqn_host", classes="aka_sqn_host")
        with Horizontal(classes="aka_actions_row"):
            yield Button("+ Add SQN init slot", id="aka_sqn_add")
            yield Button("⟳ Re-emit", id="aka_reemit")
        yield Static(
            "Spec: 3GPP TS 35.206 (MILENAGE), TS 35.231 (TUAK). Hex inputs are auto-uppercased "
            "and padded; structural validation happens at re-encode time.",
            classes="aka_section_note",
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

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
            input_widget = self.query_one(f"#aka_field_{field_id}", Input)
            value = self._field_value(field_id, algo_payload, self._pe_value)
            input_widget.value = value
            input_widget.disabled = self._read_only
        keccak_input = self.query_one("#aka_field_numberOfKeccak", Input)
        keccak_value = algo_payload.get("numberOfKeccak") if isinstance(algo_payload, dict) else None
        if isinstance(keccak_value, int) and isinstance(keccak_value, bool) is False:
            keccak_input.value = str(keccak_value)
        else:
            keccak_input.value = "" if keccak_value is None else str(keccak_value)
        keccak_input.disabled = self._read_only

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
            host.mount(_MountSqnRow.create(self, index, sqn_hex))

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

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

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

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._read_only:
            return
        widget_id = str(event.input.id or "")
        if widget_id.startswith("aka_field_") or widget_id.startswith("aka_sqn_input_"):
            self._collect_and_emit("AKA field edited")

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

    # ------------------------------------------------------------------
    # Form <-> PE value helpers
    # ------------------------------------------------------------------

    def _add_sqn_row(self) -> None:
        host = self.query_one("#aka_sqn_host", Vertical)
        if self._sqn_count == 0:
            for child in list(host.children):
                child.remove()
        index = self._sqn_count
        host.mount(_MountSqnRow.create(self, index, "000000000000"))
        self._sqn_count += 1
        self._collect_and_emit("SQN init slot added")

    def _remove_sqn_row(self, index: int) -> None:
        sqn_values = [
            _normalize_hex(child.value)
            for child in self.query("Input")
            if isinstance(child, Input) and str(child.id or "").startswith("aka_sqn_input_")
        ]
        if index < 0 or index >= len(sqn_values):
            return
        sqn_values.pop(index)
        algo_payload = self._collect_algo_payload()
        self._pe_value = self._compose_pe_value(algo_payload, sqn_init_override=sqn_values)
        self.rebuild_form()
        self.emit_change(summary="SQN init slot removed")

    def _collect_algo_payload(self) -> dict[str, Any]:
        # Carry forward any opaque keys we don't surface, so re-emit
        # is non-destructive.
        algo_id, current_payload = self._extract_algo_payload(self._pe_value)
        merged: dict[str, Any] = {}
        if isinstance(current_payload, dict):
            merged.update(copy.deepcopy(current_payload))
        if algo_id is not None:
            merged["algorithmID"] = algo_id
        # Algorithm picker can override the algorithm ID.
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
            input_widget = self.query_one(f"#aka_field_{field_id}", Input)
            normalized = _normalize_hex(input_widget.value)
            if len(normalized) == 0:
                merged.pop(field_id, None)
                continue
            merged[field_id] = tagged_bytes(normalized)
        keccak_input = self.query_one("#aka_field_numberOfKeccak", Input)
        keccak_text = str(keccak_input.value or "").strip()
        if len(keccak_text) == 0:
            merged.pop("numberOfKeccak", None)
        else:
            try:
                merged["numberOfKeccak"] = int(keccak_text)
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
        # Per-PE counters live outside the algorithm payload.
        for field_id in ("sqnOptions", "sqnDelta", "sqnAgeLimit"):
            input_widget = self.query_one(f"#aka_field_{field_id}", Input)
            normalized = _normalize_hex(input_widget.value)
            if len(normalized) == 0:
                new_pe.pop(field_id, None)
                continue
            new_pe[field_id] = tagged_bytes(normalized)
        if sqn_init_override is None:
            sqn_values: list[str] = []
            for child in self.query("Input"):
                if isinstance(child, Input) is False:
                    continue
                widget_id = str(child.id or "")
                if widget_id.startswith("aka_sqn_input_") is False:
                    continue
                sqn_values.append(_normalize_hex(child.value))
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

    # ------------------------------------------------------------------
    # PE value extraction
    # ------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
#
# Textual widgets composed inline cannot easily include a Button + Input on
# the same row when the parent uses ``mount()`` after ``compose()``. The
# small mounting helper below pre-builds the row's children in __init__ and
# yields them in compose so we can mount the row dynamically and Textual
# still resolves the child IDs through the standard query path.
# ---------------------------------------------------------------------------


class _MountSqnRow(Horizontal):

    DEFAULT_CSS = """
    _MountSqnRow {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    """

    def __init__(
        self,
        label: Static,
        input_widget: Input,
        remove_button: Button,
        *,
        row_id: str = "",
    ) -> None:
        super().__init__()
        self._label_widget = label
        self._input_widget = input_widget
        self._remove_button = remove_button
        if len(str(row_id or "")) > 0:
            self.id = row_id

    def compose(self) -> ComposeResult:
        yield self._label_widget
        yield self._input_widget
        yield self._remove_button

    @classmethod
    def create(
        cls,
        editor: AkaParameterEditor,
        index: int,
        sqn_hex: str,
    ) -> "_MountSqnRow":
        label = Static(f"SQN[{index}]", classes="aka_sqn_label")
        input_widget = Input(
            value=sqn_hex,
            placeholder="6 byte counter",
            classes="aka_sqn_input",
            id=f"aka_sqn_input_{index}",
            disabled=editor.read_only,
        )
        remove_button = Button(
            "−",
            classes="aka_sqn_remove",
            id=f"aka_sqn_remove_{index}",
            disabled=editor.read_only,
        )
        return cls(label, input_widget, remove_button, row_id=f"aka_sqn_row_{index}")


__all__ = ["AkaParameterEditor"]
