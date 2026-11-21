# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Re-encoding a decoded EF must not invent content the original never held."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import _decode_ef_arr, _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    _EF_CONTENT_DISPATCHER,
    RoundtripEncoderError,
    encode_decoded_roundtrip_ef_content,
    encode_ef_service_table,
    roundtrip_capable_ef_keys,
)
from Tools.ProfilePackage.saip_decoded_edit import (
    _HEX_HINTED_EF_KEYS,
    build_decoded_value_roundtrip_model,
)


class ServiceTablePaddingTests(unittest.TestCase):
    """A service table is a bitmap: a padding byte must not enable services.

    3GPP TS 31.102 §4.2.8 (EF.UST) / §4.2.47 (EF.EST) -- a set bit means the
    service is available. Filling the tail with 0xFF the way an opaque record
    is filled would declare every service in those bytes available; EF.EST
    would report FDN, BDN and APN Control List all enabled.
    """

    def test_est_with_nothing_enabled_stays_zero(self) -> None:
        encoded = encode_ef_service_table({"activeServices": []}, target_length=1)
        self.assertEqual(encoded, b"\x00")

    def test_ust_tail_is_zero_filled_not_ff_filled(self) -> None:
        encoded = encode_ef_service_table(
            {"activeServices": ["1: a", "2: b", "3: c"]},
            target_length=4,
        )
        self.assertEqual(encoded, bytes.fromhex("07000000"))

    def test_verbatim_reload_pads_with_zero(self) -> None:
        encoded = encode_ef_service_table({"raw": "07"}, target_length=3)
        self.assertEqual(encoded, bytes.fromhex("070000"))


class DispatcherKeyFoldingTests(unittest.TestCase):
    """Both EF-key tables are probed with an already-lowercased key.

    ``ef-keysPS`` keeps the SAIP ASN.1 spelling, so a table holding only that
    spelling silently answers nothing.
    """

    def test_every_advertised_key_survives_normalisation(self) -> None:
        unreachable = [
            key
            for key in roundtrip_capable_ef_keys()
            if str(key or "").strip().lower() not in _EF_CONTENT_DISPATCHER
        ]
        self.assertEqual(unreachable, [])

    def test_hex_hint_set_answers_the_folded_key(self) -> None:
        mixed = [key for key in _HEX_HINTED_EF_KEYS if key != key.lower()]
        for key in mixed:
            with self.subTest(key=key):
                self.assertIn(key.lower(), _HEX_HINTED_EF_KEYS)

    def test_keysps_roundtrips_byte_exact_under_either_spelling(self) -> None:
        record = "07" + "00" * 16 + "11" * 16
        for spelling in ("ef-keysPS", "ef-keysps"):
            with self.subTest(spelling=spelling):
                decoded = _decode_known_ef_payload(
                    ef_key=spelling, fid=None, hex_clean=record
                )
                self.assertIsNotNone(decoded)
                encoded = encode_decoded_roundtrip_ef_content(
                    spelling, decoded, target_length=33
                )
                self.assertEqual(encoded.hex().upper(), record)


class ArrPartialDecodeTests(unittest.TestCase):
    """EF.ARR holds several linear-fixed records; one decode covers one.

    Handed a whole file the walk runs out of the first record and stops,
    reporting ``parseErrorOffset``. Rebuilding from the rules it did collect
    would drop every record past that point, so the splicer refuses.
    """

    _ONE_RECORD = "8001019000800102A406830101950108"
    _TWO_RECORDS = "8001019000" + "FF" * 11 + "800101A40683010195010880"

    def test_single_record_decodes_completely(self) -> None:
        decoded = _decode_ef_arr(self._ONE_RECORD)
        self.assertIsNotNone(decoded)
        self.assertIsNone(decoded.get("parseErrorOffset"))

    def test_single_record_still_rebuilds_from_rules(self) -> None:
        decoded = _decode_ef_arr(self._ONE_RECORD)
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-arr", dict(decoded), target_length=len(self._ONE_RECORD) // 2
        )
        self.assertEqual(encoded.hex().upper(), self._ONE_RECORD)

    def test_whole_file_decode_reports_where_it_stopped(self) -> None:
        decoded = _decode_ef_arr(self._TWO_RECORDS)
        self.assertIsInstance(decoded.get("parseErrorOffset"), int)

    def test_unedited_whole_file_is_preserved_byte_for_byte(self) -> None:
        decoded = _decode_ef_arr(self._TWO_RECORDS)
        payload = {**decoded, "_ygg_original_hex": self._TWO_RECORDS}
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-arr", payload, target_length=len(self._TWO_RECORDS) // 2
        )
        self.assertEqual(encoded.hex().upper(), self._TWO_RECORDS)

    def test_editor_declines_a_partially_decoded_file(self) -> None:
        """The rule editor must not open on content it could only half save."""
        model = build_decoded_value_roundtrip_model(
            field_name="fillFileContent",
            raw_value={"hex": self._TWO_RECORDS},
            last_ef_key="ef-arr",
            pe_section_key="mf",
        )
        self.assertIsNone(model)

    def test_editor_still_opens_on_a_single_record(self) -> None:
        model = build_decoded_value_roundtrip_model(
            field_name="fillFileContent",
            raw_value={"hex": self._ONE_RECORD},
            last_ef_key="ef-arr",
            pe_section_key="mf",
        )
        self.assertIsNotNone(model)

    def test_editing_a_partially_decoded_file_is_refused(self) -> None:
        decoded = _decode_ef_arr(self._TWO_RECORDS)
        edited = {
            **decoded,
            "rules": [{**decoded["rules"][0], "accessModes": ["UPDATE"]}],
            "_ygg_original_hex": self._TWO_RECORDS,
        }
        with self.assertRaises(RoundtripEncoderError) as caught:
            encode_decoded_roundtrip_ef_content(
                "ef-arr", edited, target_length=len(self._TWO_RECORDS) // 2
            )
        self.assertIn("records that follow", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
