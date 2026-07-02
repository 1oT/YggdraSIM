# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Applications view.

A flat list of every PE that maps onto a GlobalPlatform application
(PE-SecurityDomain → ISD instances, PE-Application → applets) along
with their AID and life-cycle state. Read-only — double-click jumps
to the PE editor.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Static, Tree
from textual.widgets.tree import TreeNode

from ._base import (
    base_pe_type_for_section_key,
    hex_from_tagged_bytes,
)


_LIFE_CYCLE_LABELS = {
    "01": "LOADED",
    "03": "INSTALLED",
    "07": "SELECTABLE",
    "0F": "PERSONALIZED",
    "83": "LOCKED",
    "FF": "TERMINATED",
}


def _life_cycle_label(payload: Any) -> str:
    hex_value = hex_from_tagged_bytes(payload)
    if hex_value is None or len(hex_value) == 0:
        return "(unknown lifecycle)"
    label = _LIFE_CYCLE_LABELS.get(hex_value.upper())
    if label is None:
        return f"0x{hex_value.upper()}"
    return label


class ApplicationsView(Vertical):
    """Read-only application overview rendered from a SAIP document."""

    DEFAULT_CSS = """
    ApplicationsView {
        width: 100%;
        height: 1fr;
        min-height: 0;
        background: $surface;
    }
    ApplicationsView .apps_caption {
        width: 100%;
        height: 1;
        padding: 0 1;
        background: $boost;
        color: $text;
        text-style: bold;
    }
    ApplicationsView .apps_tree {
        width: 100%;
        height: 1fr;
        min-height: 0;
        border: solid $accent;
    }
    ApplicationsView .apps_note {
        width: 100%;
        height: auto;
        padding: 0 1;
        color: $text-muted;
    }
    """

    class ApplicationSelected(Message):
        def __init__(
            self,
            view: "ApplicationsView",
            *,
            pe_section_key: str,
        ) -> None:
            super().__init__()
            self.view = view
            self.pe_section_key = str(pe_section_key or "").strip()

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
        yield Static("Applications & ISD instances", classes="apps_caption")
        yield Tree("Applications", id="apps_tree", classes="apps_tree")
        yield Static(
            "Double-click an entry to focus the JSON pane on the matching PE. "
            "PE-SecurityDomain shows the ISD/SSD installation parameters; "
            "PE-Application shows third-party applet AIDs.",
            classes="apps_note",
        )

    def on_mount(self) -> None:
        self.refresh_view()

    def update_document(self, document: dict[str, Any]) -> None:
        self._document = document or {}
        if self.is_mounted:
            self.refresh_view()

    def refresh_view(self) -> None:
        tree = self.query_one("#apps_tree", Tree)
        tree.clear()
        sections = self._document.get("sections") if isinstance(self._document, dict) else None
        if isinstance(sections, dict) is False:
            tree.root.add_leaf("(no profile sections decoded)")
            return
        sd_root = tree.root.add("Issuer / Security Domain", expand=True)
        app_root = tree.root.add("Applications", expand=True)
        sd_count = 0
        app_count = 0
        for pe_key, pe_value in sections.items():
            base = base_pe_type_for_section_key(pe_key)
            if base == "securityDomain":
                self._add_security_domain(sd_root, pe_key, pe_value)
                sd_count += 1
                continue
            if base == "application":
                self._add_application(app_root, pe_key, pe_value)
                app_count += 1
        if sd_count == 0:
            sd_root.add_leaf("(no PE-SecurityDomain instances)")
        if app_count == 0:
            app_root.add_leaf("(no PE-Application instances)")
        tree.root.expand()

    def _add_security_domain(
        self,
        parent: TreeNode[Any],
        pe_key: str,
        pe_value: Any,
    ) -> None:
        instance = pe_value.get("instance") if isinstance(pe_value, dict) else None
        if isinstance(instance, dict) is False:
            parent.add_leaf(f"{pe_key} (no instance member)")
            return
        instance_aid = hex_from_tagged_bytes(instance.get("instanceAID")) or "?"
        load_aid = hex_from_tagged_bytes(instance.get("applicationLoadPackageAID")) or ""
        class_aid = hex_from_tagged_bytes(instance.get("classAID")) or ""
        lcs = _life_cycle_label(instance.get("lifeCycleState"))
        label = f"{instance_aid}  [{lcs}]  ({pe_key})"
        sd_node = parent.add(label, expand=False, data={"pe_key": pe_key})
        if len(load_aid) > 0:
            sd_node.add_leaf(f"Load package: {load_aid}")
        if len(class_aid) > 0:
            sd_node.add_leaf(f"Class:        {class_aid}")
        privileges = hex_from_tagged_bytes(instance.get("applicationPrivileges"))
        if privileges:
            sd_node.add_leaf(f"Privileges:   {privileges}")
        c9 = hex_from_tagged_bytes(instance.get("applicationSpecificParametersC9"))
        if c9:
            sd_node.add_leaf(f"C9 install:   {c9}")
        app_params = instance.get("applicationParameters")
        if isinstance(app_params, dict):
            toolkit = hex_from_tagged_bytes(
                app_params.get("uiccToolkitApplicationSpecificParametersField"),
            )
            if toolkit:
                sd_node.add_leaf(f"Toolkit EA:   {toolkit}")

    def _add_application(
        self,
        parent: TreeNode[Any],
        pe_key: str,
        pe_value: Any,
    ) -> None:
        if isinstance(pe_value, dict) is False:
            parent.add_leaf(f"{pe_key} (empty)")
            return
        instance = pe_value.get("instance")
        if isinstance(instance, dict) is False:
            parent.add_leaf(f"{pe_key} (no instance member)")
            return
        instance_aid = hex_from_tagged_bytes(instance.get("instanceAID")) or "?"
        lcs = _life_cycle_label(instance.get("lifeCycleState"))
        label = f"{instance_aid}  [{lcs}]  ({pe_key})"
        app_node = parent.add(label, expand=False, data={"pe_key": pe_key})
        load_aid = hex_from_tagged_bytes(instance.get("applicationLoadPackageAID"))
        if load_aid:
            app_node.add_leaf(f"Load package: {load_aid}")
        class_aid = hex_from_tagged_bytes(instance.get("classAID"))
        if class_aid:
            app_node.add_leaf(f"Class:        {class_aid}")
        privileges = hex_from_tagged_bytes(instance.get("applicationPrivileges"))
        if privileges:
            app_node.add_leaf(f"Privileges:   {privileges}")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, dict) is False:
            return
        pe_key = str(data.get("pe_key") or "")
        if len(pe_key) == 0:
            return
        self.post_message(self.ApplicationSelected(self, pe_section_key=pe_key))


__all__ = ["ApplicationsView"]
