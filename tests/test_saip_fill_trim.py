# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The padded-content trimmer drops only what a file's initial image holds.

TCA SAIP V3.4.1 section 8.3.3 gives ``fillFileContent`` the effect of an
update on a file created with its fill / repeat pattern or template default,
so a byte equal to that image can go. These tests pin the planner on
synthetic files and run the whole trimmer over the reference profile through
the GUI action, comparing every file image before and after.
"""

from __future__ import annotations

import importlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from Tools.ProfilePackage.saip_fill_trim import (
    MERGE_GAP,
    data_tuple_cost,
    encode_runs,
    explicit_writes,
    initial_image,
    plan_trim,
    replay,
)


_REFERENCE_PROFILE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")


def _content(*chunks: bytes) -> list[tuple[str, object]]:
    return [("fillFileContent", chunk) for chunk in chunks]


class PlannerTests(unittest.TestCase):
    """The planner keeps what differs and skips what the image already holds."""

    def test_trailing_and_interior_padding_is_dropped(self) -> None:
        image: list[int | None] = [0xFF] * 24
        body = bytes.fromhex("0102030405") + bytes([0xFF] * 12) + bytes.fromhex("AABB") + bytes([0xFF] * 5)
        trimmed, reason = plan_trim(_content(body), image=image, file_type="TR", rec_len=0)
        self.assertEqual(reason, "")
        self.assertEqual(
            trimmed,
            [
                ("fillFileContent", bytes.fromhex("0102030405")),
                ("fillFileOffset", 12),
                ("fillFileContent", bytes.fromhex("AABB")),
            ],
        )
        self.assertEqual(replay(trimmed, image), replay(_content(body), image))
        self.assertLess(data_tuple_cost(trimmed), data_tuple_cost(_content(body)))

    def test_short_written_gaps_stay_inline(self) -> None:
        image: list[int | None] = [0xFF] * 12
        body = bytes.fromhex("01") + bytes([0xFF] * MERGE_GAP) + bytes.fromhex("02") + bytes([0xFF] * 4)
        trimmed, _reason = plan_trim(_content(body), image=image, file_type="TR", rec_len=0)
        self.assertEqual(trimmed, [("fillFileContent", body[: MERGE_GAP + 2])])

    def test_an_unwritten_gap_is_never_bridged(self) -> None:
        image: list[int | None] = [0xFF] * 8
        tuples = [("fillFileContent", b"\x01"), ("fillFileOffset", 2), ("fillFileContent", b"\x02")]
        trimmed, _reason = plan_trim(tuples, image=image, file_type="TR", rec_len=0)
        self.assertEqual(trimmed, tuples)

    def test_undefined_image_bytes_are_kept(self) -> None:
        image: list[int | None] = [0x00, 0x00, None, None]
        trimmed, _reason = plan_trim(_content(bytes(4)), image=image, file_type="TR", rec_len=0)
        self.assertEqual(trimmed, [("fillFileOffset", 2), ("fillFileContent", bytes(2))])

    def test_cyclic_file_keeps_its_first_written_record(self) -> None:
        # SAIP V3.4.1 section 8.3.5: the record pointer ends on the first record
        # created, so that record stays written even when it equals the image.
        image: list[int | None] = [0xFF] * 12
        body = bytes([0xFF] * 4) + bytes.fromhex("01020304") + bytes([0xFF] * 4)
        trimmed, _reason = plan_trim(_content(body), image=image, file_type="CY", rec_len=4)
        # The first byte is kept for the record pointer; the three bytes up
        # to the kept run are cheaper inline than behind a fillFileOffset.
        self.assertEqual(trimmed, [("fillFileContent", body[:8])])
        self.assertLess(data_tuple_cost(trimmed), data_tuple_cost(_content(body)))
        linear, _reason = plan_trim(_content(body), image=image, file_type="LF", rec_len=4)
        self.assertEqual(linear, [("fillFileOffset", 4), ("fillFileContent", bytes.fromhex("01020304"))])

    def test_content_equal_to_the_image_leaves_no_tuples(self) -> None:
        image: list[int | None] = [0xFF] * 6
        trimmed, _reason = plan_trim(_content(bytes([0xFF] * 6)), image=image, file_type="LF", rec_len=3)
        self.assertEqual(trimmed, [])

    def test_content_beyond_the_declared_size_raises(self) -> None:
        with self.assertRaises(ValueError):
            plan_trim(_content(bytes(5)), image=[0xFF] * 4, file_type="TR", rec_len=0)

    def test_writes_follow_the_pointer_and_a_later_write_wins(self) -> None:
        tuples = [
            ("fillFileOffset", 2),
            ("fillFileContent", b"\x01\x02"),
            ("fillFileOffset", 1),
            ("fillFileContent", b"\x03"),
        ]
        self.assertEqual(explicit_writes(tuples), {2: 1, 3: 2, 5: 3})
        again = tuples + [("fillFileOffset", 0)]
        self.assertEqual(explicit_writes(again + [("fillFileContent", b"\x09")]), {2: 1, 3: 2, 5: 3, 6: 9})
        self.assertEqual(encode_runs([(2, 3), (5, 5)], {2: 1, 3: 2, 5: 3}), tuples)


class InitialImageTests(unittest.TestCase):
    """The image comes from the Fcp pattern, else the template default, else nowhere."""

    def test_fill_pattern_is_laid_into_every_record(self) -> None:
        # ETSI TS 102 222 v17.1 6.3.2.2.2 tag 'C1': W-1 leading bytes, then the last byte.
        pe_file = SimpleNamespace(fill_pattern=b"\x00\xff", fill_pattern_repeat=False, template=None)
        image, source = initial_image(pe_file, 8, 4)
        self.assertEqual(source, "fillPattern")
        self.assertEqual(image, [0x00, 0xFF, 0xFF, 0xFF] * 2)

    def test_repeat_pattern_truncates_at_the_record_end(self) -> None:
        pe_file = SimpleNamespace(fill_pattern=b"\xaa\xbb\xcc", fill_pattern_repeat=True, template=None)
        image, source = initial_image(pe_file, 8, 4)
        self.assertEqual(source, "repeatPattern")
        self.assertEqual(image, [0xAA, 0xBB, 0xCC, 0xAA] * 2)

    def test_template_default_fills_each_record_and_marks_a_short_literal(self) -> None:
        pattern = SimpleNamespace(default_val="FF...FF01", expand_default_value_pattern=lambda n: b"\xff" * (n - 1) + b"\x01")
        pe_file = SimpleNamespace(fill_pattern=None, fill_pattern_repeat=False, template=pattern)
        image, source = initial_image(pe_file, 6, 3)
        self.assertEqual(source, "template")
        self.assertEqual(image, [0xFF, 0xFF, 0x01] * 2)
        literal = SimpleNamespace(default_val="AABB", expand_default_value_pattern=lambda n: b"\xaa\xbb")
        pe_file = SimpleNamespace(fill_pattern=None, fill_pattern_repeat=False, template=literal)
        image, source = initial_image(pe_file, 8, 4)
        self.assertEqual(image, [0xAA, 0xBB, None, None] * 2)

    def test_a_file_declaring_nothing_has_no_image(self) -> None:
        pe_file = SimpleNamespace(fill_pattern=None, fill_pattern_repeat=False, template=None)
        image, source = initial_image(pe_file, 4, 4)
        self.assertEqual(source, "")
        self.assertEqual(image, [None] * 4)


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), f"reference profile missing: {_REFERENCE_PROFILE}")
class ReferenceProfileTrimTests(unittest.TestCase):
    """The whole trimmer over the shipped reference profile, through the action."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        cls.saip._ensure_pysim_importable()
        cls.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")

    def setUp(self) -> None:
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        shutil.copy(_REFERENCE_PROFILE, tmp.name)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        self.session_id = self.saip._dispatch_open_package(self.ctx, path=tmp.name)["session_id"]
        self.handle = self.sessions.get_manager().claim(self.session_id)

    def _template_bodies(self) -> dict[tuple[str, str], bytes]:
        from pySim.esim.saip import File

        bodies: dict[tuple[str, str], bytes] = {}
        for pe in self.handle["pes"].pe_list:
            files = getattr(pe, "files", None)
            if not isinstance(files, dict) or pe.type == "genericFileManagement":
                continue
            for pe_name, pe_file in files.items():
                entries = pe.decoded.get(pe_name)
                if not isinstance(entries, list):
                    continue
                rebuilt = File(pe_name, list(entries), template=pe_file.template)
                if rebuilt.body is not None:
                    bodies[(pe.type, pe_name)] = bytes(rebuilt.body)
        return bodies

    def _gfm_bodies(self) -> list[bytes]:
        from pySim.esim.saip import File

        bodies: list[bytes] = []
        for pe in self.handle["pes"].pe_list:
            if pe.type != "genericFileManagement":
                continue
            for transaction in pe.decoded.get("fileManagementCMD", []):
                head = None
                data: list[tuple[str, object]] = []
                for item in transaction + [("filePath", b"")]:
                    if item[0] in ("createFCP", "filePath"):
                        if head is not None:
                            bodies.append(bytes(File("x", [("fileDescriptor", head)] + data).body or b""))
                        head = item[1] if item[0] == "createFCP" else None
                        data = []
                    elif item[0] in ("fillFileOffset", "fillFileContent"):
                        data.append(item)
        return bodies

    def test_dry_run_reports_without_changing_the_package(self) -> None:
        der_before = bytes(self.handle["pes"].to_der())
        result = self.saip._dispatch_trim_padded_content(self.ctx, session_id=self.session_id)
        self.assertFalse(result["applied"])
        self.assertGreater(result["totals"]["saved"], 1000)
        self.assertEqual(result["changed_pe_indexes"], [])
        self.assertEqual(bytes(self.handle["pes"].to_der()), der_before)
        statuses = {item["status"] for item in result["files"]}
        self.assertIn("trim", statuses)
        undeclared = [item for item in result["files"] if item["image_source"] == ""]
        self.assertTrue(all(item["status"] == "skipped" for item in undeclared))
        ici = [item for item in result["files"] if item["file"] == "ef-ici"]
        self.assertEqual(len(ici), 1)
        self.assertEqual(ici[0]["image_source"], "template")
        self.assertEqual(ici[0]["status"], "trim")

    def test_apply_shrinks_the_package_and_keeps_every_file_image(self) -> None:
        template_before = self._template_bodies()
        gfm_before = self._gfm_bodies()
        der_before = len(bytes(self.handle["pes"].to_der()))
        result = self.saip._dispatch_trim_padded_content(self.ctx, session_id=self.session_id, apply=True)
        self.assertTrue(result["applied"])
        self.assertGreater(len(result["changed_pe_indexes"]), 0)
        self.assertLess(result["der_bytes_after"], der_before)
        self.assertEqual(self._template_bodies(), template_before)
        self.assertEqual(self._gfm_bodies(), gfm_before)
        self.assertGreater(result["dirty_pe_count"], 0)
        again = self.saip._dispatch_trim_padded_content(self.ctx, session_id=self.session_id)
        self.assertEqual(again["totals"]["saved"], 0)


class TrimPaddedContentRibbonEntryTests(unittest.TestCase):
    """The workbench ribbon renders "Trim padded content" from the registry.

    Its Actions group lists every ``saip.*`` action tagged
    ``saip-ribbon-active-session-form`` by title, so the bundle carries no
    literal for the id; this is the reference the declared-action audit
    looks for, and it pins the tag that puts the button on the ribbon.
    """

    def test_action_is_registered_for_the_ribbon(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

        spec = ensure_builtin_actions_loaded().get("saip.trim_padded_content")
        self.assertEqual(spec.title, "Trim padded content")
        self.assertIn("saip-ribbon-active-session-form", spec.tags)


if __name__ == "__main__":
    unittest.main()
