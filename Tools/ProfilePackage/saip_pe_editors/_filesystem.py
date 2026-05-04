"""
File-system view.

Walks the full ``document["sections"]`` mapping and renders an MF/DF
tree similar to the screenshot's "File System" tab. Each leaf yields
the file's FID, structure type, record count, and a translation of the
first record's payload (delegating to ``saip_asn1_decode`` for content
decoding when possible).

The view is read-only -- operators continue to drop
into the JSON column for byte-level edits, but the tree replaces the
"raw JSON dump" experience for whole filesystems.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Static, Tree
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
    "gsm-access": "DF.GSM-ACCESS (5F3C)",
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


def _record_count(member: Any) -> int:
    if isinstance(member, list) is False:
        return 0
    count = 0
    for entry in member:
        tagged = unwrap_tagged_tuple(entry)
        if tagged is None:
            continue
        if tagged[0] == "fillFileContent":
            count += 1
    return count


def _record_size_bytes(member: Any) -> int:
    if isinstance(member, list) is False:
        return 0
    largest = 0
    for entry in member:
        tagged = unwrap_tagged_tuple(entry)
        if tagged is None:
            continue
        if tagged[0] != "fillFileContent":
            continue
        hex_value = hex_from_tagged_bytes(tagged[1]) or ""
        size = len(hex_value) // 2
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


class FileSystemView(Vertical):
    """Read-only filesystem tree rendered from a SAIP document."""

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
    FileSystemView .fs_detail {
        width: 100%;
        height: 1fr;
        min-height: 0;
        border: solid $accent;
        background: $boost;
        color: $text;
        padding: 0 1;
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

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical():
                yield Static("File System", classes="fs_caption")
                yield Tree("Profile filesystem", id="fs_tree", classes="fs_tree")
            with Vertical():
                yield Static("Selection", classes="fs_caption")
                yield Static(
                    "(no file selected)",
                    id="fs_detail",
                    classes="fs_detail",
                )

    def on_mount(self) -> None:
        self.refresh_view()

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
        detail = self.query_one("#fs_detail", Static)
        if isinstance(data, dict) is False:
            detail.update("(no file selected)")
            return
        pe_key = str(data.get("pe_key") or "")
        ef_key = str(data.get("ef_key") or "")
        if len(ef_key) == 0:
            detail.update(f"PE: {pe_key} -- pick a file under this DF/ADF.")
            return
        sections = self._document.get("sections") if isinstance(self._document, dict) else {}
        pe_value = sections.get(pe_key, {}) if isinstance(sections, dict) else {}
        member = pe_value.get(ef_key) if isinstance(pe_value, dict) else None
        rendered = self._render_file_detail(pe_key, ef_key, member)
        detail.update(rendered)
        self.post_message(
            self.FileSelected(self, pe_section_key=pe_key, ef_key=ef_key),
        )

    def _render_file_detail(
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
        if record_count > 0:
            lines.append("")
            lines.append(
                f"Data: {record_count} record{'s' if record_count != 1 else ''} "
                "stored -- open the JSON pane to inspect record bytes.",
            )
        return "\n".join(lines)


__all__ = ["FileSystemView", "_FILESYSTEM_PE_TYPES"]
