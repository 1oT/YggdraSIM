# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for the ``saip.list_addable_files_for_pe`` and
``saip.add_template_subtree`` dispatchers.

* ``saip.list_addable_files_for_pe`` projects a PE's pySim filesystem
  template (``ProfileTemplateRegistry.get_by_oid`` route) into a JSON
  DF/EF tree with ``disabled`` flags on already-present entries.
* ``saip.add_template_subtree`` calls ``saip.add_template_file`` once
  per ``pe_names`` entry in declared order with snapshot/restore
  rollback on any failure.

These tests drive both dispatchers against the reference profile and
pin the rollback contract.
"""

from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

_REFERENCE_PROFILE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")


def _pysim_available() -> bool:
    try:
        import pySim  # noqa: F401
    except Exception:
        return False
    return True


@unittest.skipUnless(
    _REFERENCE_PROFILE.exists() and _pysim_available(),
    "reference profile or pySim missing — skipping end-to-end test",
)
class AddTemplateSubtreeEndToEndTests(unittest.TestCase):
    """Drive the new dispatchers against the reference profile."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module(
            "yggdrasim_common.gui_server.sessions"
        )

        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        ws = Path(".").resolve()
        bridge = SaipToolBridge(ws)
        src = bridge.resolve_input_path(
            str(_REFERENCE_PROFILE),
            must_exist=True,
        )
        raw = bridge._prepare_input_for_tool(src).read_bytes()
        tmp = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        tmp.write(raw)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        open_resp = self.saip._dispatch_open_package(
            self.ctx,
            path=tmp.name,
        )
        self.session_id = open_resp["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)

    def _pick_usim_section_with_template(self) -> str:
        """Return a section_key for a PE that exposes ``create_file()``."""
        pes = self.handle["pes"]
        sections = list(self.handle["decoded_document"].get("sections") or {})
        for idx, key in enumerate(sections):
            if idx >= len(pes.pe_list):
                continue
            pe = pes.pe_list[idx]
            if not hasattr(pe, "create_file"):
                continue
            template_id = getattr(pe, "templateID", None)
            if isinstance(template_id, str) and len(template_id.strip()) > 0:
                return key
        self.fail("reference profile has no template-bearing PE for add-file tests")

    def test_list_addable_files_returns_tree_with_disabled_flags(self) -> None:
        section = self._pick_usim_section_with_template()
        resp = self.saip._dispatch_list_addable_files_for_pe(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )
        self.assertEqual(resp["section_key"], section)
        self.assertTrue(resp["supports_add_file"])
        self.assertIsInstance(resp["tree"], list)
        self.assertGreater(len(resp["tree"]), 0)
        # Every node in the projected tree carries the wire keys the GUI
        # tree picker reads from.
        def walk(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                for key in ("pe_name", "name", "fid", "kind", "disabled", "children"):
                    self.assertIn(key, node, repr(node))
                self.assertIn(node["kind"], ("df", "ef"))
                self.assertIsInstance(node["disabled"], bool)
                walk(node["children"])

        walk(resp["tree"])

        # At least one disabled entry — the PE almost certainly has
        # ``ef-imsi`` (or another core EF) materialised already.
        flat: list[dict[str, Any]] = []

        def collect(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                flat.append(node)
                collect(node["children"])

        collect(resp["tree"])
        self.assertTrue(any(n["disabled"] for n in flat))
        # And at least one addable entry to drive the subtree dispatcher
        # against. Test profiles ship with a non-trivial gap between
        # template and materialised entries.
        if not any(not n["disabled"] for n in flat):
            self.skipTest("No addable entries available in reference profile.")

    def test_add_template_subtree_happy_path_single_entry(self) -> None:
        section = self._pick_usim_section_with_template()
        listed = self.saip._dispatch_list_addable_files_for_pe(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )

        flat: list[dict[str, Any]] = []

        def collect(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                flat.append(node)
                collect(node["children"])

        collect(listed["tree"])

        target = next(
            (n for n in flat if not n["disabled"] and n["kind"] == "ef"),
            None,
        )
        if target is None:
            self.skipTest("No addable EF available in reference profile.")
        target_name = target["pe_name"]

        resp = self.saip._dispatch_add_template_subtree(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
            pe_names=[target_name],
        )
        self.assertEqual(resp["added"], [target_name])
        self.assertEqual(resp["added_count"], 1)
        # Re-listing now flags the entry disabled.
        relist = self.saip._dispatch_list_addable_files_for_pe(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )

        post_flat: list[dict[str, Any]] = []
        collect_iter = relist["tree"]
        # Same collect() helper, fresh accumulator.

        def collect2(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                post_flat.append(node)
                collect2(node["children"])

        collect2(collect_iter)
        added_post = next(
            (n for n in post_flat if n["pe_name"] == target_name),
            None,
        )
        self.assertIsNotNone(added_post)
        self.assertTrue(added_post["disabled"])

    def test_add_template_subtree_rolls_back_on_midstream_failure(self) -> None:
        section = self._pick_usim_section_with_template()
        listed = self.saip._dispatch_list_addable_files_for_pe(
            self.ctx,
            session_id=self.session_id,
            section_key=section,
        )

        flat: list[dict[str, Any]] = []

        def collect(nodes: list[dict[str, Any]]) -> None:
            for node in nodes:
                flat.append(node)
                collect(node["children"])

        collect(listed["tree"])

        addable_efs = [n for n in flat if not n["disabled"] and n["kind"] == "ef"]
        if len(addable_efs) < 1:
            self.skipTest("Need at least one addable EF for rollback fixture.")

        first_pe_name = addable_efs[0]["pe_name"]

        # Snapshot the PE state BEFORE the call so we can compare after.
        from copy import deepcopy

        pes = self.handle["pes"]
        sections = list(self.handle["decoded_document"].get("sections") or {})
        pe_index = sections.index(section)
        pe = pes.pe_list[pe_index]
        before_keys = set(getattr(pe, "decoded", {}).keys())

        # Drive the subtree with the first valid name then a deliberately
        # bogus name so the second invocation raises. The dispatcher
        # MUST roll back the first add.
        with self.assertRaises(ValueError) as ctx_mgr:
            self.saip._dispatch_add_template_subtree(
                self.ctx,
                session_id=self.session_id,
                section_key=section,
                pe_names=[first_pe_name, "ef-this-name-does-not-exist"],
            )
        self.assertIn("rolled back", str(ctx_mgr.exception))

        # Verify state is unchanged (no half-state leaked through).
        after_keys = set(getattr(pe, "decoded", {}).keys())
        self.assertEqual(
            before_keys,
            after_keys,
            "rollback failed to restore pe.decoded keys",
        )


class AddTemplateSubtreeArgumentValidationTests(unittest.TestCase):
    """Argument-shape validation does not need a session."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )

        class _Ctx:
            pass

        self.ctx = _Ctx()

    def test_session_id_required(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_template_subtree(
                self.ctx,
                section_key="usim",
                pe_names=["ef-imsi"],
            )

    def test_pe_names_must_be_list(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_template_subtree(
                self.ctx,
                session_id="dummy",
                section_key="usim",
                pe_names="ef-imsi",
            )

    def test_pe_names_must_be_non_empty(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_add_template_subtree(
                self.ctx,
                session_id="dummy",
                section_key="usim",
                pe_names=[],
            )


if __name__ == "__main__":
    unittest.main()
