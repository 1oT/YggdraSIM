# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for `_decode_for_show_file` records-branch parity with the TUI.

The GUI's `saip.show_file` dispatcher used to require both `recordLength`
and `numberOfRecords` from the FCP descriptor before entering the
record-fixed decode branch. SAIP packages that elide `numberOfRecords`
(deriving record count from `efFileSize` or buffer length) silently fell
through to the transparent branch, where the canonical per-record
decoder was fed the whole image and either returned the first record
only or a parse error. The TUI's
`_decode_arr_records_from_descriptor_and_chunks` enters the record
branch on `recordLength > 0` alone and derives the count from the
buffer when missing — these tests lock the GUI dispatcher to the same
contract.
"""

from __future__ import annotations

import unittest

from yggdrasim_common.gui_server.actions.saip import (
    _decode_for_show_file,
    _flatten_arr_records_legacy,
    _is_arr_field_path,
)


# Linear-fixed descriptor encoding: byte 0 = 0x42 (working_ef +
# linear_fixed), byte 1 = data coding byte, bytes 2-3 = recordLength.
# The optional 5th byte carries `numberOfRecords` (omitted in the
# elided-count fixtures below).
_DESCRIPTOR_NO_COUNT: bytes = bytes.fromhex("42210014")  # recordLength=20
_DESCRIPTOR_WITH_COUNT: bytes = bytes.fromhex("4221001416")  # +numberOfRecords=22

# Single ARR record carrying one rule (READ|UPDATE access modes
# under the Always condition), padded to the 20-byte slot with FF.
_ARR_RECORD_TEMPLATE: bytes = bytes.fromhex("80010390" + "00" + "FF" * 15)


def _make_file_value(descriptor_bytes: bytes, fill_bytes: bytes) -> list:
    """Mimic pySim's tagged-tuple file_value shape consumed by `_tuple_payload_items`."""
    return [
        ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
        ("fillFileContent", fill_bytes),
    ]


class TestDecodeForShowFileRecords(unittest.TestCase):
    """Records-branch parity between GUI dispatcher and TUI decoder."""

    def test_elided_numberOfRecords_derives_count_from_buffer(self) -> None:
        # 22 ARR records × 20 bytes = 440 bytes total.
        # Descriptor declares only recordLength=20; numberOfRecords absent.
        fill_blob = _ARR_RECORD_TEMPLATE * 22
        file_value = _make_file_value(_DESCRIPTOR_NO_COUNT, fill_blob)

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-arr",
            file_value=file_value,
            file_id="2F06",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 22)
        for entry in records:
            self.assertFalse(entry.get("empty"), entry)
            self.assertIn("decoded", entry)
            self.assertEqual(entry["decoded"].get("format"), "EF.ARR access rules")

    def test_explicit_numberOfRecords_unchanged(self) -> None:
        # Regression: the explicit-count path must keep working unchanged.
        fill_blob = _ARR_RECORD_TEMPLATE * 22
        file_value = _make_file_value(_DESCRIPTOR_WITH_COUNT, fill_blob)

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-arr",
            file_value=file_value,
            file_id="2F06",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 22)

    def test_short_write_floors_to_record_layout(self) -> None:
        # Only the first record is written; no efFileSize is supplied.
        # The descriptor declares 22 records, so the FF-padded image
        # floor must extend to recordLength*22 = 440 bytes. Records
        # 2..22 then read as FF-only and are marked empty rather than
        # truncated mid-record.
        fill_blob = _ARR_RECORD_TEMPLATE
        file_value = _make_file_value(_DESCRIPTOR_WITH_COUNT, fill_blob)

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-arr",
            file_value=file_value,
            file_id="2F06",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 22)
        populated = [r for r in records if not r.get("empty")]
        empty = [r for r in records if r.get("empty")]
        self.assertEqual(len(populated), 1)
        self.assertEqual(len(empty), 21)

    def test_transparent_ef_routes_whole_image(self) -> None:
        # Transparent EF (descriptor byte 0x41) must keep going through
        # the whole-image branch even when recordLength is absent. EF.IMSI
        # is the canonical smoke target.
        descriptor_bytes = bytes.fromhex("4121")
        imsi_bytes = bytes.fromhex("089910070000000033")
        file_value = [
            (
                "fileDescriptor",
                {
                    "fileDescriptor": descriptor_bytes,
                    "efFileSize": b"\x00\x09",
                },
            ),
            ("fillFileContent", imsi_bytes),
        ]

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-imsi",
            file_value=file_value,
            file_id="6F07",
        )

        self.assertIsNone(records)
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded.get("format"), "USIM IMSI")

    def test_fillFileOffset_is_relative_seek_cur(self) -> None:
        # pySim ``saip/__init__.py`` line 432 calls
        # ``stream.seek(v, os.SEEK_CUR)``; ``fillFileOffset`` advances
        # the write head by ``v`` bytes from its current position, NOT
        # to absolute offset ``v``. The dispatcher used to read the
        # value as absolute and collapse every record after the first
        # into the same byte range. This test pins the corrected
        # semantic by writing two distinct rules into separate records.
        descriptor_bytes = bytes.fromhex("4221001403")  # rec_len=20 nb_rec=3
        rule_a = bytes.fromhex("80010190008001029700")  # 10 bytes — 2 rules
        rule_b = bytes.fromhex("8001049000")  # 5 bytes — 1 rule (UPDATE Always)
        # After writing rule_a (10 bytes) at cursor 0, cursor is at 10.
        # Record 2 starts at byte 20, so we need a delta of 10 to reach
        # it. Treating the value as absolute would mis-place rule_b at
        # offset 10 (still inside record 1).
        file_value = [
            ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
            ("fillFileOffset", 0),
            ("fillFileContent", rule_a),
            ("fillFileOffset", 10),
            ("fillFileContent", rule_b),
        ]

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-arr",
            file_value=file_value,
            file_id="2F06",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 3)
        # Record 1 has 2 rules from rule_a.
        rec1 = records[0]
        self.assertFalse(rec1.get("empty"))
        self.assertEqual(rec1["decoded"].get("ruleCount"), 2)
        # Record 2 has 1 rule from rule_b.
        rec2 = records[1]
        self.assertFalse(rec2.get("empty"))
        self.assertEqual(rec2["decoded"].get("ruleCount"), 1)
        # Record 3 is FF padding.
        self.assertTrue(records[2].get("empty"))

    def test_ff_padded_record_clean_summary_no_parse_error(self) -> None:
        # A populated EF.ARR record with one rule followed by FF padding
        # must surface a clean summary / ruleCount and NOT a
        # ``parseErrorOffset`` warning. SAIP encodes records FF-padded
        # to ``recordLength``; the trailing FFs are not malformed TLVs.
        descriptor_bytes = bytes.fromhex("4221001401")  # rec_len=20 nb_rec=1
        # 5 bytes: AM_DO READ|UPDATE + SC_DO Always; 15 bytes FF.
        record = bytes.fromhex("80010390" + "00") + b"\xFF" * 15
        file_value = [
            ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
            ("fillFileContent", record),
        ]

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-arr",
            file_value=file_value,
            file_id="2F06",
        )

        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertFalse(rec.get("empty"))
        self.assertNotIn("parseErrorOffset", rec.get("decoded", {}))
        self.assertEqual(rec["decoded"].get("ruleCount"), 1)
        self.assertIn("summary", rec["decoded"])


class TestArrRecordsLegacyFlatten(unittest.TestCase):
    """``saip.show_file`` emits ``arr_records`` via ``_flatten_arr_records_legacy``."""

    def test_contextual_arr_field_paths_are_arr(self) -> None:
        for field_path in (
            "ef-arr",
            "ef-arr-usim",
            "usim/ef-arr",
            "usim/ef-arr-usim",
            "foo-ef-arr",
        ):
            self.assertTrue(_is_arr_field_path(field_path), field_path)
        self.assertFalse(_is_arr_field_path("ef-adn"))

    def test_nested_decoded_lifted_to_row_root(self) -> None:
        nested = [
            {
                "record": 3,
                "empty": False,
                "decoded": {
                    "format": "EF.ARR access rules",
                    "ruleCount": 1,
                    "rules": [],
                    "summary": "smoke",
                },
            },
        ]
        flat = _flatten_arr_records_legacy(nested)
        self.assertEqual(len(flat), 1)
        self.assertEqual(flat[0]["record"], 3)
        self.assertEqual(flat[0]["format"], "EF.ARR access rules")
        self.assertEqual(flat[0]["summary"], "smoke")
        self.assertNotIn("decoded", flat[0])


class TestLinearFixedNonArrDispatch(unittest.TestCase):
    """Linear-fixed EFs other than EF.ARR populate per-record ``decoded``.

    Pins the ``_decode_known_ef_payload`` dispatcher's coverage so
    every record-fixed EF returns a populated ``decoded`` dict per
    record. EF.ARR has its own focused suite above; the cases below
    smoke a representative non-ARR sample (EF.ADN, EF.SMS, EF.SMSP)
    so dispatcher regressions in those families are caught early.
    """

    def test_ef_adn_record_decodes_msisdn_digits(self) -> None:
        # TS 31.102 §4.4.2.3 / TS 51.011 §10.5.1 — record layout is
        # ``alpha (X) || numLen (1) || TON/NPI (1) || digits (10 BCD)
        # || CCP (1) || EXT (1)``. We use X=16 so rec_len=30 (0x1E),
        # nb_rec=2.
        descriptor_bytes = bytes.fromhex("4221001E02")  # 0x1E=30, 0x02=2
        # Record 1: alpha is 16 FF (empty), then numLen=6, TON/NPI=0x91,
        # 10-byte BCD digit field, CCP=FF, EXT=FF (footer = 14 B).
        record_one = (
            b"\xFF" * 16
            + bytes.fromhex("0691" + "21436587F9FFFFFFFFFF" + "FFFF")
        )
        self.assertEqual(len(record_one), 30)
        # Record 2: full FF padding (unallocated slot).
        record_two = b"\xFF" * 30
        file_value = [
            ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
            ("fillFileContent", record_one + record_two),
        ]

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-adn",
            file_value=file_value,
            file_id="6F3A",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertFalse(first.get("empty"))
        self.assertIn("decoded", first)
        adn = first["decoded"]
        self.assertEqual(adn.get("numberLength"), 6)
        self.assertEqual(adn.get("tonNpi"), "0x91")
        # BCD digits decoded to "1234567890" (the trailing F nibble is the
        # filler the spec reserves when numLen-1 is odd).
        self.assertTrue(str(adn.get("number", "")).startswith("123456789"))
        self.assertTrue(records[1].get("empty"))

    def test_ef_dir_record_tolerates_trailing_ff_padding(self) -> None:
        # ETSI TS 102 221 §13.1 — EF.DIR record carries an Application
        # Template (tag 61) wrapping AID + label; the slot is FF-padded
        # to record_size. The BER-TLV stream decoder used to bail with
        # ``parseErrorOffset`` on the FF tail because 0xFF is the
        # never-terminating long-form continuation tag. Tail FF must be
        # treated as personalisation padding.
        descriptor_bytes = bytes.fromhex("42210026")  # rec_len=38, no count byte
        rec = bytes.fromhex(
            "61184F10A0000000871002FF34FF0789312E30FF50045553494D"
        ) + b"\xFF" * 12
        self.assertEqual(len(rec), 38)
        file_value = [
            ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
            ("fillFileContent", rec),
        ]

        decoded, records = _decode_for_show_file(
            section_key="mf",
            field_path="ef-dir",
            file_value=file_value,
            file_id="2F00",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)
        entry = records[0]
        self.assertFalse(entry.get("empty"))
        self.assertIn("decoded", entry)
        dir_decoded = entry["decoded"]
        self.assertEqual(dir_decoded.get("recordType"), "EF.DIR application template")
        items = dir_decoded.get("items") or []
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].get("tag"), "61")

    def test_ef_sms_record_decodes_record_status(self) -> None:
        # TS 31.102 §4.2.25 / TS 51.011 §10.5.3 — 176 B records carrying
        # one byte ``record status`` followed by the 175 B TPDU. We use
        # rec_len=176 (0xB0), nb_rec=1.
        descriptor_bytes = bytes.fromhex("422100B001")
        # Status 0x03 = "Received unread", then 175 B FF-padded TPDU.
        record = b"\x03" + b"\xFF" * 175
        self.assertEqual(len(record), 176)
        file_value = [
            ("fileDescriptor", {"fileDescriptor": descriptor_bytes}),
            ("fillFileContent", record),
        ]

        decoded, records = _decode_for_show_file(
            section_key="usim",
            field_path="ef-sms",
            file_value=file_value,
            file_id="6F3C",
        )

        self.assertIsNone(decoded)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertFalse(rec.get("empty"))
        self.assertIn("decoded", rec)
        sms = rec["decoded"]
        self.assertEqual(sms.get("recordStatus"), "0x03")
        self.assertEqual(sms.get("recordState"), "Received unread")


class TestRoundtripEfDispatcherGapsFromTcaSaip(unittest.TestCase):
    """The five EFs decoded by the YggdraSIM roundtrip editor (TCA SAIP
    §6 / TS 31.102) that previously had no dispatcher route.

    The audit script in `Tools/ProfilePackage/saip_ef_wizard_gui_audit`
    diffs the EFs the YggdraSIM roundtrip editor catalogues against
    `_decode_known_ef_payload`'s coverage. The five entries below were
    the residue after the initial sweep and now have explicit
    decoders. The tests pin the minimum payload each decoder accepts so
    regressions surface immediately.
    """

    def setUp(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload

        self._decode = _decode_known_ef_payload

    def test_ef_pst_decodes_service_bitmap(self) -> None:
        # Byte 0 = 0x07 → services 1..3 active.
        result = self._decode(
            ef_key="ef-pst",
            fid=None,
            hex_clean="07",
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.get("format"), "ProSe Service Table")
        self.assertEqual(result.get("activeCount"), 3)

    def test_ef_bst_decodes_service_bitmap(self) -> None:
        # Byte 0 = 0x01 → service 1 (BCAST Service Provider activation).
        result = self._decode(
            ef_key="ef-bst",
            fid=None,
            hex_clean="01",
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.get("format"), "BCAST Service Table")
        self.assertEqual(result.get("activeCount"), 1)

    def test_ef_oplmnwlan_skips_ff_padded_slots(self) -> None:
        # Two 5-byte records — one valid (test PLMN 001/01 = 00F110),
        # one FF-padded (should be skipped).
        result = self._decode(
            ef_key="ef-oplmnwlan",
            fid=None,
            hex_clean="00F110FFFF" + "FF" * 5,
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.get("entryCount"), 1)
        self.assertEqual(result["entries"][0].get("reserved"), "FFFF")

    def test_ef_uplmnwlan_uses_same_layout(self) -> None:
        result = self._decode(
            ef_key="ef-uplmnwlan",
            fid=None,
            hex_clean="00F110FFFF",
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertEqual(
            result.get("format"),
            "User-controlled I-WLAN PLMN selector",
        )
        self.assertEqual(result.get("entryCount"), 1)

    def test_ef_wlrplmn_decodes_single_plmn(self) -> None:
        result = self._decode(
            ef_key="ef-wlrplmn",
            fid=None,
            hex_clean="00F110",
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.get("format"), "I-WLAN Last Registered PLMN")
        self.assertIsNotNone(result.get("plmn"))

    def test_ef_wlrplmn_returns_none_plmn_when_unset(self) -> None:
        # All-FF body — Last Registered PLMN never written.
        result = self._decode(
            ef_key="ef-wlrplmn",
            fid=None,
            hex_clean="FFFFFF",
            parent_hint="usim",
        )
        self.assertIsNotNone(result)
        self.assertIsNone(result.get("plmn"))


class TestDispatcherCoverageManifest(unittest.TestCase):
    """The dispatcher manifest exposes every routed ef-key for the audit."""

    def test_known_dispatcher_ef_keys_covers_arr_and_imsi(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import (
            dispatcher_routes_ef_key,
            known_dispatcher_ef_keys,
        )

        manifest = known_dispatcher_ef_keys()
        self.assertGreater(len(manifest), 100)
        for required in ("ef-arr", "ef-imsi", "ef-adn", "ef-sms", "ef-spn"):
            self.assertIn(required, manifest, required)
        self.assertTrue(dispatcher_routes_ef_key("ef-arr"))
        self.assertTrue(dispatcher_routes_ef_key("ef-csim-foo"))  # prefix branch
        self.assertFalse(dispatcher_routes_ef_key("ef-not-a-real-token"))


if __name__ == "__main__":
    unittest.main()
