# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Filesystem tree for SAIP sections that carry MF/DF/EF tuples.

Renders an MF/DF tree from ``document["sections"]``. The detail column
uses a **File data** tab (hex + optional record navigation for linear
fixed / cyclic EFs) and an **FCP metadata** tab so FCP rows are not
mixed with payload bytes.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Select, Static, TabbedContent, TabPane, Tree
from textual.widgets.tree import TreeNode

from ._base import (
    base_pe_type_for_section_key,
    hex_from_tagged_bytes,
    unwrap_tagged_tuple,
)


_PE_SECTION_TO_DF_LABEL = {
    "mf": "MF (3F00)",
    "telecom": "DF.TELECOM (7F10)",
    "phonebook": "DF.PHONEBOOK (5F3A)",
    "graphics": "DF.GRAPHICS (5F50)",
    "multimedia": "DF.MMSS (5F3B)",
    "gsm-access": "DF.GSM-ACCESS (5F3B)",
    "df-5gs": "DF.5GS (5FC0)",
    "df-saip": "DF.SAIP",
    "df-snpn": "DF.SNPN (5FE0)",
    "df-5gprose": "DF.5GPROSE (5FB0)",
    "usim": "ADF.USIM",
    "opt-usim": "ADF.USIM (optional)",
    "isim": "ADF.ISIM",
    "opt-isim": "ADF.ISIM (optional)",
    "csim": "ADF.CSIM",
    "opt-csim": "ADF.CSIM (optional)",
    "eap": "DF.EAP",
    "genericFileManagement": "Generic file management",
    "cd": "DF.CD (Card Description)",
    "application": "Application",
    "rfm": "RFM",
}


_FILESYSTEM_PE_TYPES = frozenset(_PE_SECTION_TO_DF_LABEL.keys())


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


_STRUCTURE_LABELS = {
    0: "no_info",
    1: "transparent",
    2: "linear_fixed",
    6: "cyclic",
}


_FILE_TYPE_LABELS = {0: "WEF", 1: "IEF", 7: "DF"}


_LCSI_LABELS = {
    "00": "no information given",
    "01": "creation state",
    "03": "initialisation state",
    "05": "operational state - activated",
    "07": "operational state - deactivated",
    "0D": "termination state",
    "0F": "personalised",
}


def _decode_file_descriptor(descriptor_hex: str) -> dict[str, str]:
    if descriptor_hex is None or len(descriptor_hex) == 0:
        return {}
    try:
        byte0 = int(descriptor_hex[:2], 16)
    except ValueError:
        return {"raw": descriptor_hex}
    info: dict[str, str] = {"raw": descriptor_hex}
    structure_id = byte0 & 0x07
    struct_label = _STRUCTURE_LABELS.get(structure_id, "?")
    if (byte0 & 0x3F) == 0x39:
        struct_label = "ber_tlv"
    type_id = (byte0 >> 3) & 0x07
    type_label = _FILE_TYPE_LABELS.get(type_id, "?")
    info["type"] = type_label
    info["structure"] = struct_label
    info["shareable"] = "Yes" if (byte0 & 0x40) != 0 else "No"
    if len(descriptor_hex) >= 8 and struct_label in {"linear_fixed", "cyclic"}:
        try:
            record_size = int(descriptor_hex[4:8], 16)
            info["record_size"] = f"{record_size} bytes"
        except ValueError:
            pass
    if len(descriptor_hex) >= 10 and struct_label in {"linear_fixed", "cyclic"}:
        try:
            num_records = int(descriptor_hex[8:10], 16)
            info["record_count"] = str(num_records)
        except ValueError:
            pass
    return info


def _file_descriptor_summary(member: Any) -> str:
    info = _file_descriptor_info(member)
    type_label = info.get("type", "")
    struct_label = info.get("structure", "")
    if len(type_label) == 0 and len(struct_label) == 0:
        return ""
    return f"{type_label} · {struct_label}"


def _file_descriptor_info(member: Any) -> dict[str, str]:
    if isinstance(member, list) is False:
        return {}
    for entry in member:
        tag = unwrap_tagged_tuple(entry)
        if tag is None:
            continue
        name, payload = tag
        if name != "fileDescriptor":
            continue
        descriptor_hex = hex_from_tagged_bytes(payload) or ""
        return _decode_file_descriptor(descriptor_hex)
    return {}


def _first_tagged_hex(member: Any, name: str) -> str:
    if isinstance(member, list) is False:
        return ""
    for entry in member:
        tag = unwrap_tagged_tuple(entry)
        if tag is None:
            continue
        tag_name, payload = tag
        if tag_name != name:
            continue
        return hex_from_tagged_bytes(payload) or ""
    return ""


def _collect_fill_records(member: Any) -> list[dict[str, str]]:
    """Pair each ``fillFileContent`` with the preceding ``fillFileOffset`` hex, if any."""
    records: list[dict[str, str]] = []
    if isinstance(member, list) is False:
        return records
    pending_offset = ""
    for entry in member:
        tagged = unwrap_tagged_tuple(entry)
        if tagged is None:
            continue
        tag_name, payload = tagged
        if tag_name == "fillFileOffset":
            pending_offset = hex_from_tagged_bytes(payload) or ""
            continue
        if tag_name == "fillFileContent":
            content_hex = hex_from_tagged_bytes(payload) or ""
            records.append(
                {
                    "offset_hex": pending_offset,
                    "content_hex": content_hex,
                },
            )
            pending_offset = ""
            continue
        pending_offset = ""
    return records


def _record_count(member: Any) -> int:
    return len(_collect_fill_records(member))


def _record_size_bytes(member: Any) -> int:
    largest = 0
    for rec in _collect_fill_records(member):
        hex_value = rec.get("content_hex", "") or ""
        size = len("".join(hex_value.split())) // 2
        if size > largest:
            largest = size
    return largest


def _lcsi_label(hex_value: str) -> str:
    if len(hex_value) == 0:
        return ""
    label = _LCSI_LABELS.get(hex_value.upper())
    if label is None:
        return f"0x{hex_value.upper()}"
    return f"{label} (0x{hex_value.upper()})"


def _format_field_rows(rows: list[tuple[str, str]]) -> list[str]:
    if len(rows) == 0:
        return []
    label_width = max(len(label) for label, _ in rows)
    formatted: list[str] = []
    for label, value in rows:
        formatted.append(f"  {label.ljust(label_width)}  {value}")
    return formatted


def _compact_hex(hex_text: str) -> str:
    return "".join(ch for ch in hex_text.upper() if ch in "0123456789ABCDEF")


def _format_hex_dump(hex_text: str, *, bytes_per_row: int = 16) -> str:
    compact = _compact_hex(hex_text)
    if len(compact) == 0:
        return "(empty)"
    if len(compact) % 2 != 0:
        compact = compact[:-1]
    lines: list[str] = []
    for row_start in range(0, len(compact), bytes_per_row * 2):
        chunk = compact[row_start : row_start + bytes_per_row * 2]
        octets = [chunk[j : j + 2] for j in range(0, len(chunk), 2)]
        addr = row_start // 2
        hex_part = " ".join(octets)
        raw = bytes(int(octets[k], 16) for k in range(len(octets)))
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        lines.append(f"{addr:04X}  {hex_part:<{bytes_per_row * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def _offset_summary(offset_hex: str) -> str | None:
    compact = _compact_hex(offset_hex)
    if len(compact) == 0:
        return None
    try:
        value = int(compact, 16)
    except ValueError:
        return f"offset hex: {compact}"
    return f"fillFileOffset: {value} byte(s)"


class FileSystemView(Vertical):
    """Filesystem tree with tabbed FCP metadata and file-data hex."""

    DEFAULT_CSS = """
    FileSystemView {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    FileSystemView .fs_tree {
        width: 100%;
        height: 1fr;
        min-height: 0;
        border: solid $accent;
        background: transparent;
    }
    FileSystemView .fs_caption {
        width: 100%;
        height: 1;
        padding: 0 1;
        background: $boost;
        color: $text;
        text-style: bold;
    }
    FileSystemView .fs_tabs {
        width: 100%;
        height: 1fr;
        min-height: 0;
    }
    FileSystemView .fs_file_data_column {
        width: 100%;
        height: 1fr;
        min-height: 0;
    }
    FileSystemView .fs_record_toolbar {
        width: 100%;
        height: auto;
        min-height: 1;
        margin-bottom: 1;
    }
    FileSystemView .fs_record_nav {
        width: auto;
        min-width: 5;
    }
    FileSystemView #fs_record_select {
        width: 1fr;
        min-width: 12;
        height: auto;
    }
    FileSystemView .fs_file_data_body {
        width: 100%;
        height: 1fr;
        min-height: 0;
        border-top: solid $primary;
        padding: 0 1;
        background: $boost;
        color: $text;
    }
    FileSystemView .fs_fcp_body {
        width: 100%;
        height: 1fr;
        min-height: 0;
        border-top: solid $primary;
        padding: 0 1;
        background: $boost;
        color: $text;
    }
    """

    class FileSelected(Message):
        def __init__(
            self,
            view: "FileSystemView",
            *,
            pe_section_key: str,
            ef_key: str,
        ) -> None:
            super().__init__()
            self.view = view
            self.pe_section_key = str(pe_section_key or "").strip()
            self.ef_key = str(ef_key or "").strip()

    def __init__(
        self,
        *,
        document: dict[str, Any] | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._document = document or {}
        self._fill_records: list[dict[str, str]] = []
        self._record_index = 0
        self._structure_label = ""
        self._record_nav_visible = False
        self._fs_record_syncing = False

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical():
                yield Static("Filesystem", classes="fs_caption")
                yield Tree("Profile filesystem", id="fs_tree", classes="fs_tree")
            with Vertical():
                yield Static("Selection", classes="fs_caption")
                with TabbedContent(classes="fs_tabs", id="fs_tabs"):
                    with TabPane("File data"):
                        with Vertical(classes="fs_file_data_column"):
                            with Horizontal(classes="fs_record_toolbar", id="fs_record_toolbar"):
                                yield Button("◀", id="fs_record_prev", classes="fs_record_nav")
                                yield Select(
                                    [("—", 0)],
                                    id="fs_record_select",
                                    allow_blank=False,
                                    disabled=True,
                                )
                                yield Button("▶", id="fs_record_next", classes="fs_record_nav")
                            yield Static(
                                "(no file selected)",
                                id="fs_file_data_body",
                                classes="fs_file_data_body",
                            )
                    with TabPane("FCP metadata"):
                        yield Static(
                            "(no file selected)",
                            id="fs_fcp_body",
                            classes="fs_fcp_body",
                        )

    def on_mount(self) -> None:
        self.refresh_view()
        toolbar = self.query_one("#fs_record_toolbar", Horizontal)
        toolbar.display = False

    def update_document(self, document: dict[str, Any]) -> None:
        self._document = document or {}
        if self.is_mounted:
            self.refresh_view()

    def refresh_view(self) -> None:
        tree = self.query_one("#fs_tree", Tree)
        tree.clear()
        sections = self._document.get("sections") if isinstance(self._document, dict) else None
        if isinstance(sections, dict) is False:
            tree.root.add_leaf("(no profile sections decoded)")
            return
        for pe_key, pe_value in sections.items():
            base = base_pe_type_for_section_key(pe_key)
            if base not in _FILESYSTEM_PE_TYPES:
                continue
            label = _PE_SECTION_TO_DF_LABEL.get(base, base) + f"  ({pe_key})"
            section_node = tree.root.add(label, expand=True, data={"pe_key": pe_key})
            self._populate_section(section_node, pe_key, pe_value)
        tree.root.expand()

    def _populate_section(
        self,
        node: TreeNode[Any],
        pe_key: str,
        pe_value: Any,
    ) -> None:
        if isinstance(pe_value, dict) is False:
            return
        for member_key, member_value in pe_value.items():
            if isinstance(member_key, str) is False:
                continue
            if member_key.lower().endswith("header"):
                continue
            if member_key in {"templateID"}:
                continue
            if member_key.startswith(("ef-", "df-", "adf-", "mf")) is False:
                continue
            label = self._format_file_label(member_key, member_value)
            data = {"pe_key": pe_key, "ef_key": member_key}
            node.add_leaf(label, data=data)

    def _format_file_label(self, key: str, value: Any) -> str:
        descriptor = _file_descriptor_summary(value)
        records = _record_count(value)
        suffix_parts: list[str] = []
        if len(descriptor) > 0:
            suffix_parts.append(descriptor)
        if records > 0:
            suffix_parts.append(f"{records} record{'s' if records != 1 else ''}")
        suffix = ""
        if len(suffix_parts) > 0:
            suffix = "  [" + " · ".join(suffix_parts) + "]"
        return f"{key}{suffix}"

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        data = node.data if hasattr(node, "data") else None
        fcp_body = self.query_one("#fs_fcp_body", Static)
        data_body = self.query_one("#fs_file_data_body", Static)
        toolbar = self.query_one("#fs_record_toolbar", Horizontal)
        if isinstance(data, dict) is False:
            fcp_body.update("(no file selected)")
            data_body.update("(no file selected)")
            toolbar.display = False
            return
        pe_key = str(data.get("pe_key") or "")
        ef_key = str(data.get("ef_key") or "")
        if len(ef_key) == 0:
            fcp_body.update(f"PE: {pe_key} — pick a file under this DF/ADF.")
            data_body.update("(choose an EF leaf in the tree)")
            toolbar.display = False
            return
        sections = self._document.get("sections") if isinstance(self._document, dict) else {}
        pe_value = sections.get(pe_key, {}) if isinstance(sections, dict) else {}
        member = pe_value.get(ef_key) if isinstance(pe_value, dict) else None
        info = _file_descriptor_info(member) if isinstance(member, list) else {}
        self._structure_label = str(info.get("structure", "") or "").strip().lower()
        self._fill_records = _collect_fill_records(member) if isinstance(member, list) else []
        self._record_index = 0
        self._record_nav_visible = (
            len(self._fill_records) > 1
            and self._structure_label in {"linear_fixed", "cyclic"}
        )
        toolbar.display = self._record_nav_visible
        fcp_text = self._render_fcp_metadata_text(pe_key, ef_key, member)
        fcp_body.update(fcp_text)
        data_body.update(self._render_file_data_text())
        self._sync_record_select_widget()
        self.post_message(
            self.FileSelected(self, pe_section_key=pe_key, ef_key=ef_key),
        )

    def _render_fcp_metadata_text(
        self,
        pe_key: str,
        ef_key: str,
        member: Any,
    ) -> str:
        if isinstance(member, list) is False or len(member) == 0:
            return f"{pe_key} / {ef_key}\n(no file descriptor decoded)"
        info = _file_descriptor_info(member)
        type_label = info.get("type", "")
        struct_label = info.get("structure", "")
        shareable = info.get("shareable", "")
        descriptor_record_size = info.get("record_size", "")
        descriptor_record_count = info.get("record_count", "")
        file_id = _first_tagged_hex(member, "fileID")
        short_id = _first_tagged_hex(member, "shortEFID")
        lcsi_hex = _first_tagged_hex(member, "lcsi")
        sec_ref = _first_tagged_hex(member, "securityAttributesReferenced")
        sec_compact = _first_tagged_hex(member, "securityAttributesCompact")
        link_path = _first_tagged_hex(member, "linkPath")
        file_path = _first_tagged_hex(member, "filePath")
        record_count = _record_count(member)
        record_payload_size = _record_size_bytes(member)

        type_caption_parts: list[str] = []
        if len(type_label) > 0:
            type_caption_parts.append(type_label)
        if len(struct_label) > 0:
            type_caption_parts.append(f"{struct_label} elementary file")
        type_caption = " · ".join(type_caption_parts) if type_caption_parts else "Elementary file"

        general_rows: list[tuple[str, str]] = []
        general_rows.append(("File type", type_caption))
        if len(file_id) > 0:
            general_rows.append(("File identifier", file_id.upper()))
        if len(short_id) > 0:
            general_rows.append(("Short file identifier", short_id.upper()))
        if len(descriptor_record_size) > 0:
            general_rows.append(("Record size", descriptor_record_size))
        elif record_payload_size > 0:
            general_rows.append(("Record size", f"{record_payload_size} bytes"))
        if len(descriptor_record_count) > 0:
            general_rows.append(("Record count", descriptor_record_count))
        elif record_count > 0:
            general_rows.append(("Record count", str(record_count)))
        if len(lcsi_hex) > 0:
            general_rows.append(("Life cycle status", _lcsi_label(lcsi_hex)))
        if len(shareable) > 0:
            general_rows.append(("Shareable", shareable))
        if len(link_path) > 0:
            general_rows.append(("Linked path", link_path.upper()))
        if len(file_path) > 0:
            general_rows.append(("File path", file_path.upper()))

        security_rows: list[tuple[str, str]] = []
        if len(sec_ref) > 0:
            security_rows.append(("Format", "Referenced"))
            security_rows.append(("Reference bytes", sec_ref.upper()))
        if len(sec_compact) > 0:
            security_rows.append(("Format", "Compact"))
            security_rows.append(("Compact bytes", sec_compact.upper()))

        title = f"{ef_key.upper()}  ({pe_key})"
        lines: list[str] = [title, "─" * max(len(title), 24), ""]
        lines.append("File Control Parameters")
        lines.extend(_format_field_rows(general_rows))
        if len(security_rows) > 0:
            lines.append("")
            lines.append("Security Attributes")
            lines.extend(_format_field_rows(security_rows))
        lines.append("")
        lines.append(
            "Raw content bytes live under the File data tab "
            "(JSON editor still carries fillFileContent for encode).",
        )
        return "\n".join(lines)

    def _render_file_data_text(self) -> str:
        records = self._fill_records
        if len(records) == 0:
            return "(no fillFileContent in this EF — nothing to show as file data)"
        if self._record_nav_visible:
            idx = max(0, min(self._record_index, len(records) - 1))
            return self._format_one_record_block(records[idx], idx + 1, len(records))
        blocks: list[str] = []
        for i, rec in enumerate(records):
            blocks.append(self._format_one_record_block(rec, i + 1, len(records)))
        return "\n\n".join(blocks)

    def _format_one_record_block(
        self,
        rec: dict[str, str],
        index_1based: int,
        total: int,
    ) -> str:
        lines: list[str] = []
        if total > 1:
            lines.append(f"Record {index_1based} of {total}")
        off_line = _offset_summary(rec.get("offset_hex", "") or "")
        if off_line is not None:
            lines.append(off_line)
        lines.append("")
        lines.append(_format_hex_dump(rec.get("content_hex", "") or ""))
        return "\n".join(lines)

    def _sync_record_select_widget(self) -> None:
        select = self.query_one("#fs_record_select", Select)
        prev_btn = self.query_one("#fs_record_prev", Button)
        next_btn = self.query_one("#fs_record_next", Button)
        n = len(self._fill_records)
        self._fs_record_syncing = True
        try:
            if self._record_nav_visible is False or n <= 1:
                select.set_options([("—", 0)])
                select.disabled = True
                prev_btn.disabled = True
                next_btn.disabled = True
                return
            options = [(f"Record #{i}", i - 1) for i in range(1, n + 1)]
            select.set_options(options)
            select.disabled = False
            clamped = max(0, min(self._record_index, n - 1))
            self._record_index = clamped
            select.value = clamped
            prev_btn.disabled = clamped <= 0
            next_btn.disabled = clamped >= n - 1
        finally:
            self._fs_record_syncing = False

    def _apply_record_index(self, new_index: int) -> None:
        n = len(self._fill_records)
        if n <= 0:
            return
        clamped = max(0, min(int(new_index), n - 1))
        self._record_index = clamped
        data_body = self.query_one("#fs_file_data_body", Static)
        data_body.update(self._render_file_data_text())
        self._sync_record_select_widget()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = str(event.button.id or "")
        if self._record_nav_visible is False:
            return
        if button_id == "fs_record_prev":
            self._apply_record_index(self._record_index - 1)
            return
        if button_id == "fs_record_next":
            self._apply_record_index(self._record_index + 1)

    def on_select_changed(self, event: Select.Changed) -> None:
        if str(event.select.id or "") != "fs_record_select":
            return
        if self._fs_record_syncing:
            return
        if self._record_nav_visible is False:
            return
        raw_value = event.value
        try:
            idx = int(raw_value)
        except (TypeError, ValueError):
            return
        self._record_index = idx
        data_body = self.query_one("#fs_file_data_body", Static)
        data_body.update(self._render_file_data_text())
        self._sync_record_select_widget()


__all__ = ["FileSystemView", "_FILESYSTEM_PE_TYPES"]
