# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""An ARR record means what the file citing it is, and MF/DF/ADF mean CREATE.

The ISO/IEC 7816-4 access mode byte is file dependent (TS 102 221 §9.2.2): the low
three bits of an access-mode byte are READ / UPDATE / APPEND for an EF and
DELETE FILE (child) / CREATE FILE (EF) / CREATE FILE (DF) for MF, a DF or an
ADF. The record carries no clue which it is -- the FCP that references it does.
"""

from __future__ import annotations

import unittest

from SCP03.core.decoders import AdvancedDecoders
from Tools.ProfilePackage.saip_arr_record_picker import ACCESS_MODE_TOKENS
from Tools.ProfilePackage.saip_asn1_decode import (
    ARR_SCOPE_DF,
    ARR_SCOPE_EF,
    _decode_ef_arr,
    arr_scope_for_file_kind,
)
from Tools.ProfilePackage.saip_asn1_encode import encode_ef_arr_rules
from yggdrasim_common.gui_server.actions import saip as gui_saip
from yggdrasim_common.gui_server.actions.saip import (
    _arr_record_citations,
    _arr_record_scopes,
    _decode_for_show_file,
    _flatten_arr_records_legacy,
)


# A container rule: every operation ADM1 may perform on MF / a DF / an ADF.
_CONTAINER_RECORD = "80017FA40383010AFFFFFFFFFFFFFFFFFFFFFFFFFF"


class ArrAccessModeScopeTests(unittest.TestCase):
    def test_container_record_names_create_under_df_scope(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)
        assert decoded is not None
        self.assertEqual(
            decoded["rules"][0]["accessModes"],
            [
                "DELETE_CHILD",
                "CREATE_EF",
                "CREATE_DF",
                "DEACTIVATE",
                "ACTIVATE",
                "TERMINATE",
                "DELETE_FILE",
            ],
        )

    def test_same_record_reads_as_file_operations_under_ef_scope(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_EF)
        assert decoded is not None
        self.assertEqual(decoded["rules"][0]["accessModes"][:3], ["READ", "UPDATE", "APPEND"])

    def test_decode_stamps_the_scope_it_was_read_under(self) -> None:
        self.assertEqual(
            _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)["accessModeScope"],
            ARR_SCOPE_DF,
        )
        self.assertEqual(
            _decode_ef_arr(_CONTAINER_RECORD)["accessModeScope"],
            ARR_SCOPE_EF,
        )

    def test_encoder_follows_the_stamped_scope(self) -> None:
        # Without it, re-encoding a container record raises on CREATE_EF as a
        # mode belonging to the other file kind.
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)
        rebuilt = encode_ef_arr_rules(decoded, target_length=len(_CONTAINER_RECORD) // 2)
        self.assertEqual(rebuilt.hex().upper(), _CONTAINER_RECORD)

    def test_zero_filler_is_padding_not_a_parse_error(self) -> None:
        # ISO 7816-4 §5.2.2.1 -- '00' and 'FF' filler carry no meaning.
        decoded = _decode_ef_arr("8001019000" + "00" * 8)
        assert decoded is not None
        self.assertNotIn("parseErrorOffset", decoded)
        self.assertEqual(decoded["summary"], "READ: Always")

    def test_truncated_rule_still_reports_where_the_decode_stopped(self) -> None:
        # Reading '00' as filler must not swallow a rule cut short: a tail that
        # is not filler end to end still reports parseErrorOffset.
        decoded = _decode_ef_arr("8001019000" + "A40F83" + "00" * 3)
        assert decoded is not None
        self.assertEqual(decoded["parseErrorOffset"], 5)
        self.assertEqual(decoded["rules"], [{"accessModes": ["READ"], "condition": "Always"}])

    def test_scope_follows_the_referring_file_kind(self) -> None:
        for kind in ("mf", "df", "adf", "df-telecom", "DF", "ADF"):
            self.assertEqual(arr_scope_for_file_kind(kind), ARR_SCOPE_DF)
        for kind in ("ef", "ef-lf", "ef-trans", "ef-cyclic", "ef-bertlv", "", None):
            self.assertEqual(arr_scope_for_file_kind(kind), ARR_SCOPE_EF)


class ArrBothReadingsTests(unittest.TestCase):
    """Every record is decoded against both tables, whatever its citers are."""

    def test_record_carries_the_other_table_reading(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)
        assert decoded is not None
        alternate = decoded["alternateReading"]
        self.assertEqual(alternate["accessModeScope"], ARR_SCOPE_EF)
        self.assertEqual(
            alternate["rules"][0]["accessModes"][:3], ["READ", "UPDATE", "APPEND"]
        )
        self.assertTrue(decoded["scopeSensitive"])

    def test_alternate_is_present_under_either_scope(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD)
        assert decoded is not None
        self.assertEqual(decoded["alternateReading"]["accessModeScope"], ARR_SCOPE_DF)
        self.assertEqual(
            decoded["alternateReading"]["rules"][0]["accessModes"][:3],
            ["DELETE_CHILD", "CREATE_EF", "CREATE_DF"],
        )

    def test_readings_coincide_when_no_low_bit_is_used(self) -> None:
        # 0x78 touches only DEACTIVATE / ACTIVATE / TERMINATE / DELETE FILE,
        # which both tables name the same way.
        decoded = _decode_ef_arr("8001789000")
        assert decoded is not None
        self.assertFalse(decoded["scopeSensitive"])
        self.assertEqual(decoded["alternateReading"]["rules"], decoded["rules"])

    def test_alternate_does_not_nest(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD)
        self.assertNotIn("alternateReading", decoded["alternateReading"])

    def test_second_reading_does_not_disturb_the_byte_preserving_encode(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)
        rebuilt = encode_ef_arr_rules(decoded, target_length=len(_CONTAINER_RECORD) // 2)
        self.assertEqual(rebuilt.hex().upper(), _CONTAINER_RECORD)


class ArrRecordScopeResolutionTests(unittest.TestCase):
    """The referrer scan behind ``saip.show_file`` for an EF.ARR."""

    def _rows(self) -> list[dict[str, object]]:
        return [
            # MF cites record 0x0E through the short form.
            {"section_key": "mf", "kind": "mf", "security_attrs": "0E"},
            # EF.PL cites record 1 the same way.
            {"section_key": "mf", "kind": "ef-trans", "security_attrs": "01"},
            # An ADF in another PE cites record 0x16 of MF's EF.ARR explicitly.
            {"section_key": "usim", "kind": "adf", "security_attrs": "2F0616"},
            # A file citing the ADF-local EF.ARR must not colour 2F06.
            {"section_key": "usim", "kind": "df", "security_attrs": "6F060E"},
            # Short-form references outside this PE point at their own EF.ARR.
            {"section_key": "telecom", "kind": "df", "security_attrs": "01"},
        ]

    def _scopes(self) -> dict[int, str]:
        rows = self._rows()
        module = "yggdrasim_common.gui_server.actions.saip"
        import sys

        target = sys.modules[module]
        original = target._filesystem_tree_rows
        target._filesystem_tree_rows = lambda _doc: rows
        try:
            return _arr_record_scopes({}, section_key="mf", file_id="2F06")
        finally:
            target._filesystem_tree_rows = original

    def test_record_cited_by_mf_is_df_scoped(self) -> None:
        self.assertEqual(self._scopes().get(0x0E), ARR_SCOPE_DF)

    def test_record_cited_by_an_ef_stays_ef_scoped(self) -> None:
        self.assertEqual(self._scopes().get(1), ARR_SCOPE_EF)

    def test_explicit_reference_to_this_arr_is_honoured(self) -> None:
        self.assertEqual(self._scopes().get(0x16), ARR_SCOPE_DF)

    def test_reference_to_another_arr_file_is_ignored(self) -> None:
        # 6F060E addresses the ADF-local EF.ARR; 2F06 record 0x0E keeps the
        # scope its own referrers give it.
        scopes = self._scopes()
        self.assertEqual(scopes.get(0x0E), ARR_SCOPE_DF)
        self.assertNotIn(0x06, scopes)


class ArrRecordCitationTests(unittest.TestCase):
    """The citers are reported, and a record both kinds cite is flagged."""

    _ROWS = [
        {
            "section_key": "mf",
            "kind": "mf",
            "friendly_name": "MF",
            "security_attrs": "0E",
        },
        {
            "section_key": "mf",
            "kind": "ef-trans",
            "friendly_name": "EF.PL",
            "security_attrs": "0E",
        },
        {
            "section_key": "mf",
            "kind": "ef-lf",
            "friendly_name": "EF.DIR",
            "security_attrs": "01",
        },
    ]

    def _citations(self) -> dict:
        original = gui_saip._filesystem_tree_rows
        gui_saip._filesystem_tree_rows = lambda _doc: list(self._ROWS)
        try:
            return _arr_record_citations({}, section_key="mf", file_id="2F06")
        finally:
            gui_saip._filesystem_tree_rows = original

    def test_citers_are_named(self) -> None:
        entry = self._citations()[0x0E]
        self.assertEqual(
            [item["file"] for item in entry["citedBy"]], ["MF", "EF.PL"]
        )

    def test_record_cited_by_both_kinds_is_flagged_and_reads_as_container(self) -> None:
        entry = self._citations()[0x0E]
        self.assertTrue(entry["mixed"])
        self.assertEqual(entry["scope"], ARR_SCOPE_DF)

    def test_single_kind_citation_is_not_flagged(self) -> None:
        entry = self._citations()[1]
        self.assertFalse(entry["mixed"])
        self.assertEqual(entry["scope"], ARR_SCOPE_EF)

    def test_legacy_flattener_keeps_both_readings_and_citers(self) -> None:
        decoded = _decode_ef_arr(_CONTAINER_RECORD, scope=ARR_SCOPE_DF)
        flat = _flatten_arr_records_legacy(
            [
                {
                    "record": 14,
                    "empty": False,
                    "decoded": decoded,
                    "citedBy": [{"file": "MF", "kind": "mf"}],
                    "scopeMixed": False,
                }
            ]
        )
        self.assertEqual(flat[0]["accessModeScope"], ARR_SCOPE_DF)
        self.assertEqual(
            flat[0]["alternateReading"]["accessModeScope"], ARR_SCOPE_EF
        )
        self.assertTrue(flat[0]["scopeSensitive"])
        self.assertEqual(flat[0]["citedBy"][0]["file"], "MF")
        self.assertIs(flat[0]["scopeMixed"], False)


class ArrShowFileAnnotationTests(unittest.TestCase):
    """Every record the file view returns names the files citing it."""

    # Linear-fixed, 21-byte records, two of them: record 1 carries the
    # container rule, record 2 is an unwritten FF slot.
    _DESCRIPTOR = bytes.fromhex("4221001502")
    _FILE_VALUE = [
        ("fileDescriptor", {"fileDescriptor": _DESCRIPTOR}),
        (
            "fillFileContent",
            bytes.fromhex("80017FA40383010A") + b"\xFF" * 13 + b"\xFF" * 21,
        ),
    ]
    _ROWS = [
        {
            "section_key": "mf",
            "kind": "mf",
            "friendly_name": "MF",
            "security_attrs": "01",
        },
        {
            "section_key": "mf",
            "kind": "ef-lf",
            "friendly_name": "EF.GHOST",
            "security_attrs": "02",
        },
    ]

    def _records(self) -> list[dict]:
        original = gui_saip._filesystem_tree_rows
        gui_saip._filesystem_tree_rows = lambda _doc: list(self._ROWS)
        try:
            _decoded, records = _decode_for_show_file(
                section_key="mf",
                field_path="ef-arr",
                file_value=self._FILE_VALUE,
                file_id="2F06",
                pes=None,
                decoded_document={},
            )
        finally:
            gui_saip._filesystem_tree_rows = original
        return records or []

    def test_record_cited_by_mf_decodes_as_a_container_rule(self) -> None:
        record = self._records()[0]
        decoded = record["decoded"]
        self.assertEqual(decoded["accessModeScope"], ARR_SCOPE_DF)
        self.assertIn("CREATE_EF", decoded["rules"][0]["accessModes"])
        self.assertEqual([c["file"] for c in record["citedBy"]], ["MF"])

    def test_unwritten_slot_still_reports_the_file_pointing_at_it(self) -> None:
        # A reference into an FF-padded slot resolves to no rule on card.
        record = self._records()[1]
        self.assertTrue(record["empty"])
        self.assertEqual([c["file"] for c in record["citedBy"]], ["EF.GHOST"])

    def test_flattener_keeps_citers_on_an_empty_slot(self) -> None:
        flat = _flatten_arr_records_legacy(self._records())
        self.assertTrue(flat[1]["empty"])
        self.assertEqual(flat[1]["citedBy"][0]["file"], "EF.GHOST")


class LiveArrDecoderTests(unittest.TestCase):
    """``AdvancedDecoders.decode_ef_arr`` reads the same two tables."""

    def test_df_scope_names_create(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr(_CONTAINER_RECORD, scope="df"),
            ["DELETE_CHILD/CREATE_EF/CREATE_DF/DEACTIVATE/ACTIVATE/TERMINATE/DELETE_FILE: ADM1"],
        )

    def test_bit_seven_is_delete_file_and_bit_six_is_terminate(self) -> None:
        self.assertEqual(AdvancedDecoders.decode_ef_arr("8001409000"), ["DELETE_FILE: Always"])
        self.assertEqual(AdvancedDecoders.decode_ef_arr("8001209000"), ["TERMINATE: Always"])

    def test_picker_tokens_cover_both_tables(self) -> None:
        for name in ("READ", "UPDATE", "APPEND", "DELETE_CHILD", "CREATE_EF", "CREATE_DF"):
            self.assertIn(name, ACCESS_MODE_TOKENS)


if __name__ == "__main__":
    unittest.main()
