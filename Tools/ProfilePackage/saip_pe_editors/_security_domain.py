# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
PE-SecurityDomain structured editor.

The SAIP PE shape is roughly::

    {
        "sd-Header": {"identification": ..., "mandated": None},
        "instance": {
            "applicationLoadPackageAID": {"__ygg_saip_bytes__": "..."},
            "classAID":                  {"__ygg_saip_bytes__": "..."},
            "instanceAID":                {"__ygg_saip_bytes__": "..."},
            "applicationPrivileges":      {"__ygg_saip_bytes__": "..."},
            "lifeCycleState":             {"__ygg_saip_bytes__": "..."},
            "applicationSpecificParametersC9": {"__ygg_saip_bytes__": "..."},
            "applicationParameters": {
                "uiccToolkitApplicationSpecificParametersField": {"__ygg_saip_bytes__": "..."},
            },
        },
        "keyList": [
            {"keyAccess": ..., "keyComponents": [...], "keyIdentifier": ...,
             "keyUsageQualifier": ..., "keyVersionNumber": ...},
            ...
        ],
        "sdPersoData": [{"__ygg_saip_bytes__": "..."}, ...],
    }

Hex fields use label + draft input + Apply per row (whitespace, dashes,
``0x`` stripped on commit). Any Apply flushes the whole PE form into the
document splice path via ``emit_change``.
"""

from __future__ import annotations

import copy
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from ..saip_apply_row import SaipApplyRow, normalize_hex_bytes_text
from ._base import (
    BasePeEditor,
    hex_from_tagged_bytes,
    header_member_key_from_pe,
    header_value_from_pe,
    rebuild_pe_with_header,
    tagged_bytes,
)
from ._header import PeHeaderForm


_INSTANCE_HEX_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("applicationLoadPackageAID", "Load package AID", "AID hex"),
    ("classAID", "Class AID", "AID hex"),
    ("instanceAID", "Instance AID", "AID hex"),
    ("applicationPrivileges", "Privileges (3 bytes)", "GP privileges"),
    ("lifeCycleState", "Life cycle state", "1 byte (0F = personalised)"),
    ("applicationSpecificParametersC9", "App specific params (C9)", "BER-TLV"),
)


_KEY_HEX_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("keyIdentifier", "ID", "1 byte"),
    ("keyVersionNumber", "KVN", "1 byte"),
    ("keyUsageQualifier", "Usage", "1 byte"),
    ("keyAccess", "Access", "1 byte"),
)


def _component_hex(component: dict[str, Any]) -> tuple[str, str, str]:
    return (
        hex_from_tagged_bytes(component.get("keyData")) or "",
        hex_from_tagged_bytes(component.get("keyType")) or "",
        str(component.get("macLength", "")) if component.get("macLength") is not None else "",
    )


class _KeyRow(Vertical):

    DEFAULT_CSS = """
    _KeyRow {
        width: 100%;
        height: auto;
        margin-top: 1;
        padding: 0 1;
        background: $boost;
        border: solid $primary;
    }
    _KeyRow .sd_key_heading {
        width: 100%;
        height: auto;
        margin-bottom: 1;
    }
    _KeyRow .sd_key_heading_label {
        width: 1fr;
        content-align: left middle;
        color: $text-muted;
    }
    _KeyRow .sd_key_remove {
        width: 8;
    }
    """

    def __init__(
        self,
        index: int,
        *,
        read_only: bool = False,
        initial_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._index = int(index)
        self._read_only = bool(read_only)
        self._pending_payload: dict[str, Any] = (
            dict(initial_payload) if isinstance(initial_payload, dict) else {}
        )

    def on_mount(self) -> None:
        if len(self._pending_payload) > 0:
            self.populate(self._pending_payload)
            self._pending_payload = {}

    def compose(self) -> ComposeResult:
        with Horizontal(classes="sd_key_heading"):
            yield Static(f"Key #{self._index + 1}", classes="sd_key_heading_label")
            yield Button(
                "−",
                classes="sd_key_remove",
                id=f"sd_key_remove_{self._index}",
                disabled=self._read_only,
            )
        for field_id, label, placeholder in _KEY_HEX_FIELDS:
            yield SaipApplyRow(
                f"sd_key_{self._index}_{field_id}",
                f"{label}:",
                mode="hex",
                placeholder=placeholder,
                hint="Hex bytes · Apply commits this PE.",
                id=f"sd_key_row_{self._index}_{field_id}",
                classes="sd_key_apply_slot",
            )
        yield SaipApplyRow(
            f"sd_key_{self._index}_keyData",
            "Component keyData:",
            mode="hex",
            placeholder="key octets",
            hint="Hex bytes · Apply commits this PE.",
            id=f"sd_key_row_{self._index}_keyData",
            classes="sd_key_apply_slot",
        )
        yield SaipApplyRow(
            f"sd_key_{self._index}_keyType",
            "Component keyType:",
            mode="hex",
            placeholder="1–2 bytes",
            hint="Hex bytes · Apply commits this PE.",
            id=f"sd_key_row_{self._index}_keyType",
            classes="sd_key_apply_slot",
        )
        yield SaipApplyRow(
            f"sd_key_{self._index}_macLength",
            "macLength:",
            mode="decimal",
            placeholder="decimal",
            hint="Decimal macLength · Apply commits this PE.",
            id=f"sd_key_row_{self._index}_macLength",
            classes="sd_key_apply_slot",
        )

    def populate(self, payload: dict[str, Any]) -> None:
        for field_id, _label, _placeholder in _KEY_HEX_FIELDS:
            row = self.query_one(f"#sd_key_row_{self._index}_{field_id}", SaipApplyRow)
            row.set_draft(hex_from_tagged_bytes(payload.get(field_id)) or "")
            row.set_read_only(self._read_only)
        data_row = self.query_one(f"#sd_key_row_{self._index}_keyData", SaipApplyRow)
        type_row = self.query_one(f"#sd_key_row_{self._index}_keyType", SaipApplyRow)
        mac_row = self.query_one(f"#sd_key_row_{self._index}_macLength", SaipApplyRow)
        components = payload.get("keyComponents")
        if isinstance(components, list) is False or len(components) == 0:
            data_row.set_draft("")
            type_row.set_draft("")
            mac_row.set_draft("")
        else:
            primary = components[0] if isinstance(components[0], dict) else {}
            data_hex, type_hex, mac_text = _component_hex(primary)
            data_row.set_draft(data_hex)
            type_row.set_draft(type_hex)
            mac_row.set_draft(mac_text)
        data_row.set_read_only(self._read_only)
        type_row.set_read_only(self._read_only)
        mac_row.set_read_only(self._read_only)

    def collect(self) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for field_id, _label, _placeholder in _KEY_HEX_FIELDS:
            row = self.query_one(f"#sd_key_row_{self._index}_{field_id}", SaipApplyRow)
            value = normalize_hex_bytes_text(row.draft_text())
            if len(value) > 0:
                record[field_id] = tagged_bytes(value)
        component: dict[str, Any] = {}
        data_hex = normalize_hex_bytes_text(
            self.query_one(f"#sd_key_row_{self._index}_keyData", SaipApplyRow).draft_text()
        )
        type_hex = normalize_hex_bytes_text(
            self.query_one(f"#sd_key_row_{self._index}_keyType", SaipApplyRow).draft_text()
        )
        mac_text = (
            self.query_one(f"#sd_key_row_{self._index}_macLength", SaipApplyRow).draft_text()
        ).strip()
        if len(data_hex) > 0:
            component["keyData"] = tagged_bytes(data_hex)
        if len(type_hex) > 0:
            component["keyType"] = tagged_bytes(type_hex)
        if len(mac_text) > 0:
            try:
                component["macLength"] = int(mac_text, 10)
            except ValueError:
                pass
        if len(component) > 0:
            record["keyComponents"] = [component]
        return record


class _PersoBlobRow(Vertical):
    """One perso blob: hex apply row + remove."""

    DEFAULT_CSS = """
    _PersoBlobRow {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    _PersoBlobRow .sd_perso_remove_row {
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
        super().__init__()
        self._index = int(index)
        self._read_only = bool(read_only)
        self._initial_hex = str(initial_hex or "")

    def compose(self) -> ComposeResult:
        yield Static(f"Perso [{self._index}]", classes="sd_section_note")
        yield SaipApplyRow(
            f"sd_perso_{self._index}",
            "Blob hex:",
            mode="hex",
            placeholder="BER-TLV hex",
            hint="Opaque blob · Apply commits this PE.",
            id=f"sd_perso_apply_{self._index}",
        )
        with Horizontal(classes="sd_perso_remove_row"):
            yield Button(
                "Remove blob",
                id=f"sd_perso_remove_{self._index}",
                disabled=self._read_only,
            )

    def on_mount(self) -> None:
        row = self.query_one(f"#sd_perso_apply_{self._index}", SaipApplyRow)
        row.set_draft(self._initial_hex)
        row.set_read_only(self._read_only)


class SecurityDomainEditor(BasePeEditor):
    """Structured editor for PE-SecurityDomain."""

    DEFAULT_CSS = """
    SecurityDomainEditor {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    SecurityDomainEditor .sd_section_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 1;
        margin-top: 1;
    }
    SecurityDomainEditor .sd_section_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
        margin-top: 1;
    }
    SecurityDomainEditor .sd_keys_host {
        width: 100%;
        height: auto;
        padding: 0 1;
    }
    SecurityDomainEditor .sd_actions_row {
        width: 100%;
        height: auto;
        padding: 0 1;
        margin-top: 1;
    }
    SecurityDomainEditor .sd_actions_row Button {
        margin-right: 1;
    }
    SecurityDomainEditor .sd_perso_host {
        width: 100%;
        height: auto;
        padding: 0 1;
    }
    """

    PE_TYPE_LABEL = "PE-SecurityDomain"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._key_count = 0
        self._perso_count = 0

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="sd_pe_header",
        )
        yield Static("Instance", classes="sd_section_title")
        yield Static(
            "Hex fields: whitespace, dashes, 0x stripped on Apply. Any Apply writes the full PE.",
            classes="sd_section_note",
        )
        for field_id, label, placeholder in _INSTANCE_HEX_FIELDS:
            yield SaipApplyRow(
                f"sd_inst_{field_id}",
                f"{label}:",
                mode="hex",
                placeholder=placeholder,
                hint="Hex · Apply commits this PE.",
                id=f"sd_ir_{field_id}",
            )
        yield SaipApplyRow(
            "sd_inst_uiccToolkit",
            "UICC Toolkit params:",
            mode="hex",
            placeholder="ETSI TS 102 226 hex",
            hint="Hex · Apply commits this PE.",
            id="sd_ir_uiccToolkit",
        )

        yield Static("Key list", classes="sd_section_title")
        yield Vertical(id="sd_keys_host", classes="sd_keys_host")
        with Horizontal(classes="sd_actions_row"):
            yield Button("+ Add key entry", id="sd_keys_add")
            yield Button("⟳ Re-emit", id="sd_keys_reemit")

        yield Static("SD perso data (CASD personalisation blobs)", classes="sd_section_title")
        yield Vertical(id="sd_perso_host", classes="sd_perso_host")
        with Horizontal(classes="sd_actions_row"):
            yield Button("+ Add perso blob", id="sd_perso_add")
        yield Static(
            "Inspect pane (F4) decodes BER-TLV when the cursor selects these blobs.",
            classes="sd_section_note",
        )

    def rebuild_form(self) -> None:
        header_form = self.query_one("#sd_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header_value_from_pe(self._pe_value) or {},
            read_only=self._read_only,
        )
        instance = self._instance_payload(self._pe_value)
        for field_id, _label, _placeholder in _INSTANCE_HEX_FIELDS:
            row = self.query_one(f"#sd_ir_{field_id}", SaipApplyRow)
            row.set_draft(hex_from_tagged_bytes(instance.get(field_id)) or "")
            row.set_read_only(self._read_only)
        toolkit_row = self.query_one("#sd_ir_uiccToolkit", SaipApplyRow)
        toolkit_row.set_draft(self._toolkit_hex(instance))
        toolkit_row.set_read_only(self._read_only)

        self._render_keys()
        self._render_perso()

    def _toolkit_hex(self, instance: dict[str, Any]) -> str:
        app_params = instance.get("applicationParameters")
        if isinstance(app_params, dict) is False:
            return ""
        return hex_from_tagged_bytes(
            app_params.get("uiccToolkitApplicationSpecificParametersField")
        ) or ""

    def _render_keys(self) -> None:
        host = self.query_one("#sd_keys_host", Vertical)
        for child in list(host.children):
            child.remove()
        records = self._key_list_payload(self._pe_value)
        self._key_count = len(records)
        if self._key_count == 0:
            host.mount(
                Static(
                    "(empty keyList — use '+ Add key entry' to start)",
                    classes="sd_section_note",
                ),
            )
            return
        for index, record in enumerate(records):
            host.mount(
                _KeyRow(
                    index,
                    read_only=self._read_only,
                    initial_payload=record,
                ),
            )

    def _render_perso(self) -> None:
        host = self.query_one("#sd_perso_host", Vertical)
        for child in list(host.children):
            child.remove()
        blobs = self._perso_payload(self._pe_value)
        self._perso_count = len(blobs)
        if self._perso_count == 0:
            host.mount(
                Static(
                    "(no SD perso blobs in this PE)",
                    classes="sd_section_note",
                ),
            )
            return
        for index, blob in enumerate(blobs):
            host.mount(
                _PersoBlobRow(
                    index,
                    read_only=self._read_only,
                    initial_hex=blob,
                ),
            )

    def _instance_payload(self, pe_value: Any) -> dict[str, Any]:
        if isinstance(pe_value, dict) is False:
            return {}
        instance = pe_value.get("instance")
        if isinstance(instance, dict) is False:
            return {}
        return instance

    def _key_list_payload(self, pe_value: Any) -> list[dict[str, Any]]:
        if isinstance(pe_value, dict) is False:
            return []
        keys = pe_value.get("keyList")
        if isinstance(keys, list) is False:
            return []
        return [item for item in keys if isinstance(item, dict)]

    def _perso_payload(self, pe_value: Any) -> list[str]:
        if isinstance(pe_value, dict) is False:
            return []
        raw = pe_value.get("sdPersoData")
        if isinstance(raw, list) is False:
            return []
        return [hex_from_tagged_bytes(item) or "" for item in raw]

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value) or "sd-Header"
        )
        self._pe_value = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self.emit_change(summary="SD PE header updated")

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._read_only:
            return
        rid = event.row_id
        if rid.startswith("sd_inst_") or rid.startswith("sd_key_") or rid.startswith("sd_perso_"):
            self._collect_and_emit("SD PE field applied")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._read_only:
            return
        button_id = str(event.button.id or "")
        if button_id == "sd_keys_reemit":
            self._collect_and_emit("SD PE re-emitted")
            return
        if button_id == "sd_keys_add":
            self._add_key_row()
            return
        if button_id == "sd_perso_add":
            self._add_perso_row()
            return
        if button_id.startswith("sd_key_remove_"):
            try:
                index = int(button_id.rsplit("_", 1)[-1])
            except ValueError:
                return
            self._remove_key_row(index)
            return
        if button_id.startswith("sd_perso_remove_"):
            try:
                index = int(button_id.rsplit("_", 1)[-1])
            except ValueError:
                return
            self._remove_perso_row(index)

    def _add_key_row(self) -> None:
        host = self.query_one("#sd_keys_host", Vertical)
        if self._key_count == 0:
            for child in list(host.children):
                child.remove()
        index = self._key_count
        host.mount(
            _KeyRow(
                index,
                read_only=False,
                initial_payload={
                    "keyIdentifier": tagged_bytes("01"),
                    "keyVersionNumber": tagged_bytes("01"),
                    "keyUsageQualifier": tagged_bytes("38"),
                    "keyAccess": tagged_bytes("00"),
                    "keyComponents": [
                        {
                            "keyData": tagged_bytes("00" * 16),
                            "keyType": tagged_bytes("88"),
                            "macLength": 8,
                        },
                    ],
                },
            ),
        )
        self._key_count += 1
        self.call_after_refresh(self._collect_and_emit, "SD key entry added")

    def _remove_key_row(self, index: int) -> None:
        records = self._collect_keys()
        if index < 0 or index >= len(records):
            return
        records.pop(index)
        self._pe_value = self._compose_pe_value(key_list_override=records)
        self.rebuild_form()
        self.emit_change(summary="SD key entry removed")

    def _add_perso_row(self) -> None:
        blobs = self._collect_perso_blobs()
        blobs.append("")
        self._pe_value = self._compose_pe_value(perso_override=blobs)
        self.rebuild_form()
        self.emit_change(summary="SD perso blob added")

    def _remove_perso_row(self, index: int) -> None:
        blobs = self._collect_perso_blobs()
        if index < 0 or index >= len(blobs):
            return
        blobs.pop(index)
        self._pe_value = self._compose_pe_value(perso_override=blobs)
        self.rebuild_form()
        self.emit_change(summary="SD perso blob removed")

    def _collect_keys(self) -> list[dict[str, Any]]:
        host = self.query_one("#sd_keys_host", Vertical)
        records: list[dict[str, Any]] = []
        for child in host.children:
            if isinstance(child, _KeyRow):
                records.append(child.collect())
        return records

    def _collect_perso_blobs(self) -> list[str]:
        host = self.query_one("#sd_perso_host", Vertical)
        blobs: list[str] = []
        for child in host.children:
            if isinstance(child, _PersoBlobRow) is False:
                continue
            for wid in child.query(SaipApplyRow):
                blobs.append(normalize_hex_bytes_text(wid.draft_text()))
                break
        return blobs

    def _collect_instance(self) -> dict[str, Any]:
        existing = self._instance_payload(self._pe_value)
        instance: dict[str, Any] = copy.deepcopy(existing) if isinstance(existing, dict) else {}
        for field_id, _label, _placeholder in _INSTANCE_HEX_FIELDS:
            row = self.query_one(f"#sd_ir_{field_id}", SaipApplyRow)
            value = normalize_hex_bytes_text(row.draft_text())
            if len(value) == 0:
                instance.pop(field_id, None)
                continue
            instance[field_id] = tagged_bytes(value)
        toolkit_row = self.query_one("#sd_ir_uiccToolkit", SaipApplyRow)
        toolkit_value = normalize_hex_bytes_text(toolkit_row.draft_text())
        app_params = instance.get("applicationParameters")
        if isinstance(app_params, dict) is False:
            app_params = {}
        if len(toolkit_value) == 0:
            app_params.pop("uiccToolkitApplicationSpecificParametersField", None)
        else:
            app_params["uiccToolkitApplicationSpecificParametersField"] = tagged_bytes(toolkit_value)
        if len(app_params) == 0:
            instance.pop("applicationParameters", None)
        else:
            instance["applicationParameters"] = app_params
        return instance

    def _compose_pe_value(
        self,
        *,
        key_list_override: list[dict[str, Any]] | None = None,
        perso_override: list[str] | None = None,
    ) -> dict[str, Any]:
        new_pe: dict[str, Any] = {}
        if isinstance(self._pe_value, dict):
            for key, value in self._pe_value.items():
                new_pe[key] = value
        if header_member_key_from_pe(new_pe) is None:
            new_pe.setdefault("sd-Header", {"mandated": None, "identification": 0})
        new_pe["instance"] = self._collect_instance()
        if key_list_override is None:
            key_list_override = self._collect_keys()
        if len(key_list_override) == 0:
            new_pe.pop("keyList", None)
        else:
            new_pe["keyList"] = key_list_override
        if perso_override is None:
            perso_override = self._collect_perso_blobs()
        cleaned_perso = [tagged_bytes(blob) for blob in perso_override if len(blob) > 0]
        if len(cleaned_perso) == 0:
            new_pe.pop("sdPersoData", None)
        else:
            new_pe["sdPersoData"] = cleaned_perso
        return new_pe

    def _collect_and_emit(self, summary: str) -> None:
        self._pe_value = self._compose_pe_value()
        self.emit_change(summary=summary)


__all__ = ["SecurityDomainEditor"]
