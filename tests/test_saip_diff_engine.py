# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``Tools.ProfilePackage.saip_diff_engine``.

The engine is a pure function so these tests need no pySim, no
filesystem, and no card transport. They lock in the behaviour the TUI
and the ``DIFF`` shell command rely on:

* Identical documents produce an empty summary.
* Key additions / removals / value changes are flagged with the correct
  op code and path.
* Deeply nested sections stay intact under traversal and the emitted
  paths use dotted ``foo.bar[3].baz`` notation.
* Section reordering is caught by the ``diff_saip_documents`` high-level
  helper even though the lower-level walker treats maps as unordered.
* The text renderer yields a grep-able report with summary counters.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_diff_engine import (
    DIFF_OP_ADDED,
    DIFF_OP_CHANGED,
    DIFF_OP_MOVED,
    DIFF_OP_REMOVED,
    DiffEntry,
    DiffSummary,
    diff_documents,
    diff_saip_documents,
    format_diff_text,
)


class DiffEngineStructureTests(unittest.TestCase):
    def test_identical_documents_yield_empty_summary(self) -> None:
        doc = {
            "intro": ["profile foo"],
            "sections": {
                "mf": {"fileDescriptor": "01"},
            },
        }
        summary = diff_documents(doc, dict(doc))
        self.assertTrue(summary.is_empty)
        self.assertEqual(summary.total, 0)
        self.assertEqual(summary.entries, ())

    def test_key_addition_in_nested_mapping(self) -> None:
        doc_a = {"intro": [], "sections": {"mf": {"fid": "3F00"}}}
        doc_b = {
            "intro": [],
            "sections": {"mf": {"fid": "3F00", "sfi": "1F"}},
        }
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.added, 1)
        self.assertEqual(summary.removed, 0)
        self.assertEqual(summary.changed, 0)
        self.assertEqual(summary.entries[0].path, "sections.mf.sfi")
        self.assertEqual(summary.entries[0].op, DIFF_OP_ADDED)
        self.assertEqual(summary.entries[0].value_b, "1F")

    def test_key_removal_in_nested_mapping(self) -> None:
        doc_a = {"sections": {"mf": {"fid": "3F00", "sfi": "1F"}}}
        doc_b = {"sections": {"mf": {"fid": "3F00"}}}
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.removed, 1)
        self.assertEqual(summary.entries[0].path, "sections.mf.sfi")
        self.assertEqual(summary.entries[0].op, DIFF_OP_REMOVED)
        self.assertEqual(summary.entries[0].value_a, "1F")

    def test_value_change_on_leaf(self) -> None:
        doc_a = {"sections": {"profile": {"iccid": "89001020304050607080"}}}
        doc_b = {"sections": {"profile": {"iccid": "89001020304050607099"}}}
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.changed, 1)
        entry = summary.entries[0]
        self.assertEqual(entry.op, DIFF_OP_CHANGED)
        self.assertEqual(entry.path, "sections.profile.iccid")
        self.assertEqual(entry.value_a, "89001020304050607080")
        self.assertEqual(entry.value_b, "89001020304050607099")

    def test_list_entry_indexing_uses_bracket_notation(self) -> None:
        doc_a = {"sections": {"gfm": [{"fid": "6F00"}, {"fid": "6F01"}]}}
        doc_b = {"sections": {"gfm": [{"fid": "6F00"}, {"fid": "6F02"}]}}
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.changed, 1)
        self.assertEqual(summary.entries[0].path, "sections.gfm[1].fid")

    def test_list_growth_and_shrink_emit_added_and_removed(self) -> None:
        doc_a = {"sections": {"x": [1, 2]}}
        doc_b = {"sections": {"x": [1, 2, 3]}}
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.added, 1)
        self.assertEqual(summary.entries[0].path, "sections.x[2]")
        self.assertEqual(summary.entries[0].op, DIFF_OP_ADDED)
        self.assertEqual(summary.entries[0].value_b, 3)

        summary_reverse = diff_documents(doc_b, doc_a)
        self.assertEqual(summary_reverse.removed, 1)
        self.assertEqual(summary_reverse.entries[0].op, DIFF_OP_REMOVED)

    def test_type_change_is_reported_as_single_change(self) -> None:
        doc_a = {"sections": {"x": {"nested": "string"}}}
        doc_b = {"sections": {"x": {"nested": ["list"]}}}
        summary = diff_documents(doc_a, doc_b)
        self.assertEqual(summary.changed, 1)
        self.assertEqual(summary.entries[0].path, "sections.x.nested")

    def test_entries_are_stable_sorted_by_path_and_op(self) -> None:
        doc_a = {
            "sections": {
                "a": {"child": 1},
                "b": {"child": 2},
                "c": {"child": 3},
            }
        }
        doc_b = {
            "sections": {
                "c": {"child": 30},
                "a": {"child": 10},
                "b": {"child": 20},
            }
        }
        first = diff_documents(doc_a, doc_b)
        second = diff_documents(doc_a, doc_b)
        self.assertEqual(first.entries, second.entries)
        paths = [entry.path for entry in first.entries]
        self.assertEqual(paths, sorted(paths))


class DiffEngineSaipHighLevelTests(unittest.TestCase):
    def test_section_reorder_is_flagged_by_high_level_helper(self) -> None:
        doc_a = {
            "intro": [],
            "sections": {"mf": {"fid": "3F00"}, "adf_usim": {"fid": "7FFF"}},
        }
        doc_b = {
            "intro": [],
            "sections": {"adf_usim": {"fid": "7FFF"}, "mf": {"fid": "3F00"}},
        }
        summary = diff_saip_documents(doc_a, doc_b)
        self.assertEqual(summary.moved, 1)
        move_entries = [e for e in summary.entries if e.op == DIFF_OP_MOVED]
        self.assertEqual(len(move_entries), 1)
        self.assertEqual(move_entries[0].path, "sections")
        self.assertEqual(move_entries[0].value_a, ("mf", "adf_usim"))
        self.assertEqual(move_entries[0].value_b, ("adf_usim", "mf"))

    def test_reorder_not_flagged_when_section_sets_differ(self) -> None:
        doc_a = {"sections": {"mf": {}, "adf": {}}}
        doc_b = {"sections": {"mf": {}, "isd-r": {}}}
        summary = diff_saip_documents(doc_a, doc_b)
        self.assertEqual(summary.moved, 0)
        self.assertEqual(summary.added + summary.removed, 2)


class DiffEngineRenderTests(unittest.TestCase):
    def test_empty_summary_text_is_explicit(self) -> None:
        summary = DiffSummary()
        self.assertEqual(format_diff_text(summary), "(no differences)\n")

    def test_text_report_contains_counters_and_entries(self) -> None:
        doc_a = {"sections": {"mf": {"fid": "3F00"}}}
        doc_b = {"sections": {"mf": {"fid": "3F01", "sfi": "1F"}}}
        summary = diff_documents(doc_a, doc_b)
        report = format_diff_text(summary)
        self.assertIn("added=1", report)
        self.assertIn("changed=1", report)
        self.assertIn("+ sections.mf.sfi", report)
        self.assertIn("~ sections.mf.fid", report)
        self.assertIn("3F00", report)
        self.assertIn("3F01", report)

    def test_show_values_false_suppresses_payload(self) -> None:
        doc_a = {"sections": {"x": "before"}}
        doc_b = {"sections": {"x": "after"}}
        summary = diff_documents(doc_a, doc_b)
        report = format_diff_text(summary, show_values=False)
        self.assertIn("~ sections.x", report)
        self.assertNotIn("before", report)
        self.assertNotIn("after", report)


class DiffEngineGuardsTests(unittest.TestCase):
    def test_non_mapping_inputs_raise_type_error(self) -> None:
        with self.assertRaises(TypeError):
            diff_documents([1, 2], {"sections": {}})
        with self.assertRaises(TypeError):
            diff_documents({"sections": {}}, "not a dict")

    def test_diff_entry_is_hashable_and_frozen(self) -> None:
        entry = DiffEntry(path="foo", op=DIFF_OP_ADDED, value_b=1)
        with self.assertRaises(Exception):
            entry.op = DIFF_OP_REMOVED  # type: ignore[misc]
        self.assertEqual(hash(entry), hash(entry))
