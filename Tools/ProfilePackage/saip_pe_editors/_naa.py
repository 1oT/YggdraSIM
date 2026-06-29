# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Filesystem-bearing PE editors (USIM / ISIM / CSIM / Telecom families).

Every PE in this family shares the same outer structure::

    {
        "<base>-header": {"identification": ..., "mandated": None},
        "templateID": "2.23.143.1.2.<n>",
        "<root df>": [...],
        "ef-imsi": [...],
        ...
    }

The editor exposes:

* The reusable ``PeHeaderForm``.
* A ``Template ID`` input with a curated dropdown of the known SAIP
  filesystem templates.
* A check-tree of EF members so the operator can quickly see which EFs
  are currently materialised inside the PE. Toggling a check-box drops
  the corresponding EF from the PE — adding new EFs still routes
  through the existing "Add file" / template defaults flow because
  materialising a fresh EF requires the FCP defaults from
  ``saip_pe_quick_add``.

This editor never mutates the EF *content* itself — that lives in the
File System tab so the operator gets a single place to edit record
bodies instead of hunting through the PE editor.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Checkbox, OptionList, Static
from textual.widgets.option_list import Option

from ._base import (
    BasePeEditor,
    base_pe_type_for_section_key,
    header_member_key_from_pe,
    header_value_from_pe,
    rebuild_pe_with_header,
)
from ..saip_apply_row import SaipApplyRow
from ._header import PeHeaderForm


# Curated list of the SAIP eUICC filesystem template IDs the project
# regularly ships. Used to populate the dropdown — operators can still
# type any OID into the input and the editor will accept it.
_TEMPLATE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("2.23.143.1.2.1", "MF (TS 102 221)"),
    ("2.23.143.1.2.2", "DF.TELECOM (TS 31.102)"),
    ("2.23.143.1.2.3", "ADF.USIM Rel-9"),
    ("2.23.143.1.2.4", "ADF.USIM Rel-12"),
    ("2.23.143.1.2.5", "ADF.USIM Rel-15"),
    ("2.23.143.1.2.6", "ADF.ISIM Rel-9"),
    ("2.23.143.1.2.7", "DF.GSM-ACCESS"),
    ("2.23.143.1.2.8", "ADF.ISIM Rel-13"),
    ("2.23.143.1.2.9", "DF.5GS"),
    ("2.23.143.1.2.10", "DF.SAIP"),
    ("2.23.143.1.2.11", "DF.SNPN"),
    ("2.23.143.1.2.12", "DF.5GPROSE"),
    ("2.23.143.1.2.13", "ADF.CSIM"),
    ("2.23.143.1.2.14", "DF.PHONEBOOK"),
    ("2.23.143.1.2.15", "ADF.USIM Rel-17"),
)


class _NaaPeEditorBase(BasePeEditor):
    """Common shape for filesystem-bearing PE editors."""

    DEFAULT_CSS = """
    _NaaPeEditorBase {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    _NaaPeEditorBase .naa_section_title {
        width: 100%;
        height: 1;
        text-style: bold;
        color: $accent;
        padding: 0 1;
        margin-top: 1;
    }
    _NaaPeEditorBase .naa_section_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
        margin-top: 1;
    }
    _NaaPeEditorBase .naa_template_picker {
        width: 100%;
        height: 8;
        margin-top: 1;
        padding: 0 1;
    }
    _NaaPeEditorBase .naa_files_host {
        width: 100%;
        height: auto;
        padding: 0 1;
    }
    _NaaPeEditorBase .naa_file_row {
        width: 100%;
        height: 1;
        margin: 0;
        color: $text;
    }
    """

    PE_TYPE_LABEL = "Filesystem PE"

    def compose(self) -> ComposeResult:
        yield PeHeaderForm(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            id="naa_pe_header",
        )
        yield Static("File system template", classes="naa_section_title")
        yield SaipApplyRow(
            "naa_template_oid",
            "Template ID:",
            mode="text",
            placeholder="OID e.g. 2.23.143.1.2.4",
            hint="Apply commits templateID on this PE.",
            id="naa_template_apply_row",
        )
        yield OptionList(
            *(
                Option(f"{oid}  {label}", id=oid)
                for oid, label in _TEMPLATE_OPTIONS
            ),
            id="naa_template_picker",
            classes="naa_template_picker",
        )
        yield Static("Files in this PE", classes="naa_section_title")
        yield Vertical(id="naa_files_host", classes="naa_files_host")
        yield Static(
            "Uncheck a row to drop the EF from this PE. To add a new EF, use the "
            "Add file picker (Ctrl+A) so the SAIP template defaults populate the "
            "FCP correctly.",
            classes="naa_section_note",
        )

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def rebuild_form(self) -> None:
        header_form = self.query_one("#naa_pe_header", PeHeaderForm)
        header_form.update_header(
            section_label=self._pe_section_key or self.PE_TYPE_LABEL,
            header_payload=header_value_from_pe(self._pe_value) or {},
            read_only=self._read_only,
        )
        template_row = self.query_one("#naa_template_apply_row", SaipApplyRow)
        template_row.set_read_only(self._read_only)
        template_value = ""
        if isinstance(self._pe_value, dict):
            raw = self._pe_value.get("templateID")
            if isinstance(raw, str):
                template_value = raw
        template_row.set_draft(template_value)

        picker = self.query_one("#naa_template_picker", OptionList)
        picker.disabled = self._read_only
        if len(template_value) > 0:
            try:
                target_index = picker.get_option_index(template_value)
            except Exception:
                target_index = None
            if isinstance(target_index, int):
                picker.highlighted = target_index

        host = self.query_one("#naa_files_host", Vertical)
        for child in list(host.children):
            child.remove()
        ef_keys = self._iter_ef_keys()
        if len(ef_keys) == 0:
            host.mount(
                Static(
                    "(no EF members declared at the PE root — content lives "
                    "under template defaults or has been suppressed)",
                    classes="naa_section_note",
                ),
            )
            return
        for ef_key in ef_keys:
            host.mount(
                Checkbox(
                    self._format_ef_label(ef_key),
                    value=True,
                    id=f"naa_ef_check_{ef_key}",
                    classes="naa_file_row",
                    disabled=self._read_only,
                ),
            )

    def _iter_ef_keys(self) -> list[str]:
        if isinstance(self._pe_value, dict) is False:
            return []
        ef_keys: list[str] = []
        for key in self._pe_value.keys():
            if isinstance(key, str) is False:
                continue
            if key.startswith("ef-"):
                ef_keys.append(key)
                continue
            if key.startswith("df-") or key.startswith("adf-"):
                ef_keys.append(key)
        return ef_keys

    def _format_ef_label(self, ef_key: str) -> str:
        member = self._pe_value.get(ef_key) if isinstance(self._pe_value, dict) else None
        record_count = 0
        if isinstance(member, list):
            record_count = sum(
                1
                for item in member
                if isinstance(item, dict) and "__ygg_saip_tuple__" in item or "@" in item
            )
        return f"{ef_key}  ({record_count} record{'s' if record_count != 1 else ''})"

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_pe_header_form_changed(self, event: PeHeaderForm.Changed) -> None:
        if self._read_only:
            return
        header_member_key = (
            header_member_key_from_pe(self._pe_value)
            or self._fallback_header_member_key()
        )
        self._pe_value = rebuild_pe_with_header(
            self._pe_value if isinstance(self._pe_value, dict) else {},
            header_member_key=header_member_key,
            header_payload=event.form.current_payload(),
        )
        self.emit_change(summary="NAA PE header updated")

    def on_saip_apply_row_committed(self, event: SaipApplyRow.Committed) -> None:
        if self._read_only:
            return
        if event.row_id != "naa_template_oid":
            return
        new_template = str(event.value or "").strip()
        if isinstance(self._pe_value, dict) is False:
            return
        if len(new_template) == 0:
            self._pe_value.pop("templateID", None)
        else:
            self._pe_value["templateID"] = new_template
        self.emit_change(summary=f"Template ID set to {new_template or '(none)'}")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if self._read_only:
            return
        if str(event.option_list.id or "") != "naa_template_picker":
            return
        oid = str(event.option.id or "").strip()
        if len(oid) == 0:
            return
        if isinstance(self._pe_value, dict) is False:
            return
        self._pe_value["templateID"] = oid
        template_row = self.query_one("#naa_template_apply_row", SaipApplyRow)
        if template_row.draft_text().strip() != oid:
            template_row.set_draft(oid)
        self.emit_change(summary=f"Template ID set to {oid}")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if self._read_only:
            return
        widget_id = str(event.checkbox.id or "")
        prefix = "naa_ef_check_"
        if widget_id.startswith(prefix) is False:
            return
        ef_key = widget_id[len(prefix):]
        if event.value:
            # Keep current value (no-op).
            return
        if isinstance(self._pe_value, dict) is False:
            return
        if ef_key in self._pe_value:
            self._pe_value.pop(ef_key)
            self.emit_change(summary=f"Dropped {ef_key} from PE")

    def _fallback_header_member_key(self) -> str:
        base = base_pe_type_for_section_key(self._pe_section_key)
        return f"{base}-header" if len(base) > 0 else "header"


class NaaPeEditor(_NaaPeEditorBase):
    """Editor for PE-USIM / PE-OPT-USIM / PE-ISIM / PE-OPT-ISIM / PE-CSIM / PE-OPT-CSIM."""

    PE_TYPE_LABEL = "PE-USIM"


class TelecomPeEditor(_NaaPeEditorBase):
    """Editor for PE-Telecom (DF.TELECOM)."""

    PE_TYPE_LABEL = "PE-Telecom"


__all__ = ["NaaPeEditor", "TelecomPeEditor"]
