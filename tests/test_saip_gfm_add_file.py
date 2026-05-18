# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression tests for ``saip.gfm_add_file_element``.

The TCA SAIP profile element family for filesystem creation
(genericFileManagement, §6.6.7) defines two affordances inside a
PE-GFM editor: *Add select element* and *Add file element*. Template
PEs (USIM / ISIM / OPT-USIM / MF / …)
are served by ``saip.add_template_file`` /
``saip.add_template_subtree``; PE-GFM is the free-form fallback and
needed its own dispatcher.

These tests drive the dispatcher end-to-end against the reference
profile so a regression that drops the new file from the FS tree,
mangles the parent path, or breaks ``_locate_file_payload`` fails
loudly.
"""

from __future__ import annotations

import importlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path


_REFERENCE_PROFILE = Path(
    "Workspace/SAIP/transcode/_external/example_test_profile-45a94746b86d.transcode.der"
)


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    f"reference profile missing: {_REFERENCE_PROFILE}",
)
class GfmAddFileElementEndToEndTests(unittest.TestCase):
    """End-to-end coverage against a real GFM-heavy profile."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module(
            "yggdrasim_common.gui_server.sessions"
        )
        tmp = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        shutil.copy(_REFERENCE_PROFILE, tmp.name)
        tmp.close()
        self.tmp_path = tmp.name
        self.addCleanup(lambda: os.unlink(self.tmp_path))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        resp = self.saip._dispatch_open_package(self.ctx, path=self.tmp_path)
        self.session_id = resp["session_id"]

    def _list_gfm_files(self) -> list[dict]:
        lf = self.saip._dispatch_list_files(
            self.ctx, session_id=self.session_id
        )
        return [r for r in lf["rows"] if r["source"] == "gfm"]

    def test_adds_file_under_specified_parent_df(self) -> None:
        before = self._list_gfm_files()
        resp = self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="7F10",
            file_id="6F99",
            file_descriptor="4121",
        )
        self.assertTrue(resp["added"])
        self.assertEqual(resp["file_id"], "6F99")
        self.assertEqual(resp["parent_path"], "7F10")

        after = self._list_gfm_files()
        self.assertEqual(len(after), len(before) + 1)

        new_rows = [r for r in after if r["file_id"] == "6F99"]
        self.assertEqual(len(new_rows), 1)
        new = new_rows[0]
        self.assertEqual(new["parent_path"], "3F00/7F10")
        self.assertEqual(new["fid_chain"], "3F00/7F10/6F99")
        self.assertEqual(new["kind"], "ef-trans")

    def test_marks_owning_pe_dirty(self) -> None:
        self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="7F10",
            file_id="6F9A",
        )
        handle = self.sessions.get_manager().claim(self.session_id)
        self.assertIn(5, handle.get("dirty_pes") or set())

    def test_show_file_locates_new_entry(self) -> None:
        resp = self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="7F10",
            file_id="6F9B",
        )
        # show_file walks the augmented row list and dispatches to
        # _locate_file_payload, which must understand the synthetic
        # ``fileManagementCMD[i][j]`` field_path that GFM rows use.
        show = self.saip._dispatch_show_file(
            self.ctx,
            session_id=self.session_id,
            section_key=resp["section_key"],
            field_path=f"fileManagementCMD[{resp['transaction_index']}][1]",
        )
        self.assertEqual(show["fcp"]["file_id"], "6F9B")
        self.assertEqual(show["fcp"]["parent_path"], "3F00/7F10")

    def test_empty_parent_path_lands_under_mf(self) -> None:
        self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="",
            file_id="2FAA",
        )
        rows = self._list_gfm_files()
        target = [r for r in rows if r["file_id"] == "2FAA"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["parent_path"], "3F00")

    def test_strips_leading_3f00_from_parent_path(self) -> None:
        # ``3F00/7F10`` and ``7F10`` must resolve to the same logical
        # location — pySim's ``filePath`` SELECT encoding already
        # implies MF as the base.
        self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="3F007F10",
            file_id="6F88",
        )
        rows = self._list_gfm_files()
        target = [r for r in rows if r["file_id"] == "6F88"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["parent_path"], "3F00/7F10")

    def test_descriptor_drives_file_kind(self) -> None:
        # 0x4221 — record-fixed working EF (mask 0x07 == 0x02).
        self.saip._dispatch_gfm_add_file_element(
            self.ctx,
            session_id=self.session_id,
            section_key="genericFileManagement",
            parent_path="7F10",
            file_id="6F77",
            file_descriptor="4221001E",
            record_size="1E",
            record_count="01",
        )
        rows = self._list_gfm_files()
        target = [r for r in rows if r["file_id"] == "6F77"]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["kind"], "ef-lf")


class GfmAddFileElementValidationTests(unittest.TestCase):
    """Argument validation — should never reach the mutation path."""

    def setUp(self) -> None:
        self.saip = importlib.import_module(
            "yggdrasim_common.gui_server.actions.saip"
        )

        class _Ctx:
            pass

        self.ctx = _Ctx()

    def test_session_id_required(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_gfm_add_file_element(
                self.ctx,
                section_key="genericFileManagement",
                file_id="6F99",
            )

    def test_section_must_be_gfm(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_gfm_add_file_element(
                self.ctx,
                session_id="ignored",
                section_key="usim",
                file_id="6F99",
            )

    def test_file_id_must_be_4_hex_digits(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_gfm_add_file_element(
                self.ctx,
                session_id="ignored",
                section_key="genericFileManagement",
                file_id="6F",
            )

    def test_file_id_rejects_non_hex(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_gfm_add_file_element(
                self.ctx,
                session_id="ignored",
                section_key="genericFileManagement",
                file_id="ZZZZ",
            )

    def test_parent_path_must_have_even_hex_length(self) -> None:
        with self.assertRaises(ValueError):
            self.saip._dispatch_gfm_add_file_element(
                self.ctx,
                session_id="ignored",
                section_key="genericFileManagement",
                parent_path="7F1",
                file_id="6F99",
            )


if __name__ == "__main__":
    unittest.main()
