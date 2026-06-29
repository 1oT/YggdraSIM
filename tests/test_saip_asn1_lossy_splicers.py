# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Roundtrip tests for the ADN/SMSP/EF.ARR lossy splicers.

Each splicer must honour two invariants:

1. Identity splice: when the decoded payload is handed back verbatim with
   the ``_ygg_original_hex`` hint, the encoder reproduces the source bytes
   byte-for-byte (no CCI / alpha-padding / opaque sub-TLV drift).
2. Semantic edit splice: when a single semantic field is changed the
   splicer rewrites only the affected bytes and leaves the rest intact.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_adn_like_record,
    _decode_ef_arr,
    _decode_smsp,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_ef_adn_record,
    encode_ef_arr_rules,
    encode_ef_smsp_record,
    encode_decoded_roundtrip_ef_content,
    roundtrip_capable_ef_keys,
)


def _build_adn_record(
    alpha_text: str,
    *,
    number_len: int,
    ton_npi: int,
    bcd_hex: str,
    cci: int,
    ext_id: int,
    alpha_pad: int = 0,
) -> bytes:
    """Assemble a synthetic ADN/FDN/SDN record for the test fixtures."""

    alpha_encoded = alpha_text.encode("utf-8")
    if alpha_pad > 0:
        alpha_encoded = alpha_encoded + (b"\xFF" * alpha_pad)
    footer = (
        bytes([number_len, ton_npi])
        + bytes.fromhex(bcd_hex)
        + bytes([cci, ext_id])
    )
    assert len(bytes.fromhex(bcd_hex)) == 10, "BCD block must be exactly 10 bytes"
    return alpha_encoded + footer


class AdnSplicerRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = _build_adn_record(
            alpha_text="ALICE",
            number_len=7,
            ton_npi=0x81,
            bcd_hex="103254FFFFFFFFFFFFFF",
            cci=0xFF,
            ext_id=0xFF,
            alpha_pad=1,
        )
        self.record_hex = self.record.hex().upper()
        self.decoded = _decode_adn_like_record(self.record_hex)
        assert self.decoded is not None

    def test_identity_splice_is_byte_exact(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        encoded = encode_ef_adn_record(payload)
        self.assertEqual(encoded, self.record)

    def test_edit_number_preserves_alpha_and_cci(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        payload["number"] = "555666"
        payload["numberLength"] = 4
        encoded = encode_ef_adn_record(payload)
        # Alpha bytes (0..alpha_len) must be untouched.
        alpha_len = len(self.record) - 14
        self.assertEqual(encoded[:alpha_len], self.record[:alpha_len])
        # CCI byte (footer[12]) untouched.
        self.assertEqual(encoded[alpha_len + 12], self.record[alpha_len + 12])
        # Dialling number re-encoded.
        redecoded = _decode_adn_like_record(encoded.hex().upper())
        assert redecoded is not None
        self.assertEqual(redecoded["number"], "555666")
        self.assertEqual(redecoded["numberLength"], 4)

    def test_edit_alpha_preserves_cci_and_extension(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        payload["alphaIdentifier"] = "BOB"
        encoded = encode_ef_adn_record(payload)
        alpha_len = len(self.record) - 14
        # Alpha head contains "BOB" + 0xFF padding to alpha_len.
        self.assertTrue(encoded[:3] == b"BOB")
        self.assertTrue(all(byte == 0xFF for byte in encoded[3:alpha_len]))
        self.assertEqual(encoded[alpha_len + 12], self.record[alpha_len + 12])
        self.assertEqual(encoded[alpha_len + 13], self.record[alpha_len + 13])

    def test_preserves_cci_when_decoder_does_not_expose_it(self) -> None:
        # Stamp a non-0xFF CCI in the original and verify it survives even
        # though the decoded payload never contains the byte.
        record = _build_adn_record(
            alpha_text="CAROL",
            number_len=5,
            ton_npi=0x91,
            bcd_hex="1122334455FFFFFFFFFF",
            cci=0xAB,
            ext_id=0x02,
        )
        record_hex = record.hex().upper()
        decoded = _decode_adn_like_record(record_hex)
        assert decoded is not None
        self.assertNotIn("capabilityConfigurationIdentifier", decoded)
        payload = dict(decoded)
        payload["_ygg_original_hex"] = record_hex
        payload["number"] = "999"
        payload["numberLength"] = 3
        encoded = encode_ef_adn_record(payload)
        self.assertEqual(encoded[-2], 0xAB)
        self.assertEqual(encoded[-1], 0x02)

    def test_missing_original_hex_is_rejected(self) -> None:
        payload = dict(self.decoded)
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_adn_record(payload)

    def test_dispatcher_routes_adn_fdn_sdn_to_splicer(self) -> None:
        for ef_key in ("ef-adn", "ef-fdn", "ef-sdn"):
            self.assertIn(ef_key, roundtrip_capable_ef_keys())
            payload = dict(self.decoded)
            payload["_ygg_original_hex"] = self.record_hex
            encoded = encode_decoded_roundtrip_ef_content(ef_key, payload)
            self.assertEqual(encoded, self.record)


class SmspSplicerRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        alpha = b"SMSPA"
        footer = bytes.fromhex(
            "FF"
            + "0102030405060708090A0B0C"
            + "910111223344556677889900"
            + "04"
            + "08"
            + "A7"
        )
        self.record = alpha + footer
        self.record_hex = self.record.hex().upper()
        self.decoded = _decode_smsp(self.record_hex)
        assert self.decoded is not None

    def test_identity_splice_is_byte_exact(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        encoded = encode_ef_smsp_record(payload)
        self.assertEqual(encoded, self.record)

    def test_edit_sc_address_preserves_alpha_and_other_fields(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        payload["serviceCenterAddress"] = "AABBCCDDEEFF001122334455"
        encoded = encode_ef_smsp_record(payload)
        redecoded = _decode_smsp(encoded.hex().upper())
        assert redecoded is not None
        self.assertEqual(
            redecoded["serviceCenterAddress"],
            "AABBCCDDEEFF001122334455",
        )
        self.assertEqual(
            redecoded["tpDestinationAddress"],
            self.decoded["tpDestinationAddress"],
        )
        self.assertEqual(redecoded["alphaIdentifier"], "SMSPA")
        self.assertEqual(redecoded["tpDcs"], self.decoded["tpDcs"])

    def test_edit_tp_bytes_targets_only_the_requested_byte(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        payload["tpPid"] = "0x5A"
        payload["tpValidity"] = "0x00"
        encoded = encode_ef_smsp_record(payload)
        self.assertEqual(encoded[-3], 0x5A)
        self.assertEqual(encoded[-1], 0x00)
        # tpDcs byte (offset -2) untouched.
        self.assertEqual(encoded[-2], self.record[-2])
        # Alpha block intact.
        alpha_len = len(self.record) - 28
        self.assertEqual(encoded[:alpha_len], self.record[:alpha_len])

    def test_tp_dest_address_length_is_validated(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        payload["tpDestinationAddress"] = "DEADBEEF"  # too short
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_smsp_record(payload)

    def test_missing_original_hex_is_rejected(self) -> None:
        payload = dict(self.decoded)
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_smsp_record(payload)

    def test_dispatcher_routes_smsp_to_splicer(self) -> None:
        self.assertIn("ef-smsp", roundtrip_capable_ef_keys())
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self.record_hex
        encoded = encode_decoded_roundtrip_ef_content("ef-smsp", payload)
        self.assertEqual(encoded, self.record)


class ArrSplicerRoundtripTests(unittest.TestCase):
    _FIXTURE_HEX = "8001019000800102A406830101950108"

    def setUp(self) -> None:
        self.record = bytes.fromhex(self._FIXTURE_HEX)
        self.decoded = _decode_ef_arr(self._FIXTURE_HEX)
        assert self.decoded is not None

    def test_identity_splice_returns_original_bytes(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self._FIXTURE_HEX
        encoded = encode_ef_arr_rules(payload)
        self.assertEqual(encoded, self.record)

    def test_add_new_rule_rebuilds_stream(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self._FIXTURE_HEX
        new_rules = list(payload["rules"]) + [
            {"accessModes": ["READ", "UPDATE"], "condition": "Never"}
        ]
        payload["rules"] = new_rules
        encoded = encode_ef_arr_rules(
            payload,
            target_length=len(self.record) + 8,
        )
        redecoded = _decode_ef_arr(encoded.hex().upper())
        assert redecoded is not None
        self.assertEqual(len(redecoded["rules"]), 3)
        self.assertEqual(redecoded["rules"][-1]["condition"], "Never")
        self.assertIn("READ", redecoded["rules"][-1]["accessModes"])
        self.assertIn("UPDATE", redecoded["rules"][-1]["accessModes"])

    def test_remove_rule_rebuilds_stream(self) -> None:
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self._FIXTURE_HEX
        payload["rules"] = [payload["rules"][0]]
        encoded = encode_ef_arr_rules(payload, target_length=len(self.record))
        redecoded = _decode_ef_arr(encoded.hex().upper())
        assert redecoded is not None
        self.assertEqual(len(redecoded["rules"]), 1)
        self.assertEqual(redecoded["rules"][0]["condition"], "Always")

    def test_rules_list_is_required(self) -> None:
        payload = {"_ygg_original_hex": self._FIXTURE_HEX}
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_arr_rules(payload)

    def test_unknown_access_mode_is_rejected(self) -> None:
        payload = {
            "rules": [{"accessModes": ["BANANA"], "condition": "Always"}],
        }
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_arr_rules(payload)

    def test_scratch_rebuild_pads_to_target_length(self) -> None:
        payload = {
            "rules": [{"accessModes": ["READ"], "condition": "Always"}],
        }
        encoded = encode_ef_arr_rules(payload, target_length=16)
        self.assertEqual(len(encoded), 16)
        self.assertTrue(encoded.endswith(b"\xFF"))
        redecoded = _decode_ef_arr(encoded.hex().upper())
        assert redecoded is not None
        self.assertEqual(redecoded["rules"][0]["condition"], "Always")

    def test_dispatcher_routes_arr_to_splicer(self) -> None:
        self.assertIn("ef-arr", roundtrip_capable_ef_keys())
        payload = dict(self.decoded)
        payload["_ygg_original_hex"] = self._FIXTURE_HEX
        encoded = encode_decoded_roundtrip_ef_content("ef-arr", payload)
        self.assertEqual(encoded, self.record)


class LossySplicerEditorIntegrationTests(unittest.TestCase):
    """Exercise the path from ``build_decoded_value_roundtrip_model`` down to
    ``encode_decoded_value_editor_payload`` for each splicer EF."""

    def test_editor_model_carries_original_hex_for_lossy_efs(self) -> None:
        from Tools.ProfilePackage.saip_decoded_edit import (
            build_decoded_value_roundtrip_model,
        )
        record = _build_adn_record(
            alpha_text="ED",
            number_len=3,
            ton_npi=0x81,
            bcd_hex="123456FFFFFFFFFFFFFF",
            cci=0xFF,
            ext_id=0xFF,
        )
        raw_value = {"hex": record.hex().upper()}
        model = build_decoded_value_roundtrip_model(
            field_name="fillFileContent",
            raw_value=raw_value,
            last_ef_key="ef-adn",
        )
        assert model is not None
        self.assertEqual(model["editor_kind"], "roundtrip_decoded")
        self.assertIn("_ygg_original_hex", model["payload"])
        self.assertEqual(
            model["payload"]["_ygg_original_hex"],
            record.hex().upper(),
        )

    def test_editor_save_path_roundtrips_lossy_splicer(self) -> None:
        from Tools.ProfilePackage.saip_decoded_edit import (
            build_decoded_value_roundtrip_model,
            encode_decoded_value_editor_payload,
        )
        record = _build_adn_record(
            alpha_text="FRAN",
            number_len=4,
            ton_npi=0x81,
            bcd_hex="123456FFFFFFFFFFFFFF",
            cci=0xCC,
            ext_id=0x03,
        )
        raw_value = {"hex": record.hex().upper()}
        model = build_decoded_value_roundtrip_model(
            field_name="fillFileContent",
            raw_value=raw_value,
            last_ef_key="ef-adn",
        )
        assert model is not None
        replacement = encode_decoded_value_editor_payload(
            field_name="fillFileContent",
            editor_payload=model["payload"],
            last_ef_key="ef-adn",
            target_length=model["target_length"],
            editor_kind=model["editor_kind"],
        )
        # Replacement is tagged-bytes dict; hex should match original.
        self.assertIn("hex", replacement)
        self.assertEqual(replacement["hex"], record.hex().upper())


if __name__ == "__main__":
    unittest.main()
