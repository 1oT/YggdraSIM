# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Roundtrip tests for the tier-1 and tier-2 gap encoders.

Each encoder is validated against two invariants:

1. Identity roundtrip: ``decode(raw) -> payload -> encode(payload) == raw``
   whenever the decoder is lossless (optionally with the
   ``_ygg_original_hex`` hint to preserve padding / opaque bytes for
   encoders that fall back to verbatim passthrough).
2. Semantic-edit roundtrip: changing an exposed semantic field produces a
   byte stream that round-trips through the decoder again with the new
   value and leaves unrelated bytes untouched where possible.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_ef_dir_record,
    _decode_ecc,
    _decode_eps_nas_security_context,
    _decode_loci,
    _decode_msisdn,
    _decode_opl_record,
    _decode_pcscf_address,
    _decode_pnn_record,
    _decode_puct,
    _decode_service_table,
    _decode_sms_record,
    _decode_sms_status_reports,
    _decode_spdi,
    _decode_spn,
    _UST_SERVICE_NAMES,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_ef_content,
    encode_ef_apn_control_list,
    encode_ef_dir_record,
    encode_ef_ecc,
    encode_ef_eps_nas_security_context,
    encode_ef_gbanl,
    encode_ef_loci,
    encode_ef_msisdn_record,
    encode_ef_opl_record,
    encode_ef_pcscf_address,
    encode_ef_pnn_record,
    encode_ef_puct,
    encode_ef_service_table,
    encode_ef_sms_record,
    encode_ef_sms_status_report,
    encode_ef_spdi,
    encode_ef_spn,
    roundtrip_capable_ef_keys,
)


class SpnEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x01]) + b"Example Mobile"
        decoded = _decode_spn(raw.hex())
        self.assertIsNotNone(decoded)
        encoded = encode_ef_spn(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_change_provider_name(self) -> None:
        raw = bytes([0x01]) + b"Example" + (b"\xFF" * 10)
        decoded = _decode_spn(raw.hex())
        decoded["serviceProviderName"] = "LabName"
        encoded = encode_ef_spn(dict(decoded), target_length=len(raw))
        redecoded = _decode_spn(encoded.hex())
        self.assertEqual(redecoded["serviceProviderName"], "LabName")

    def test_dispatcher_routes_ef_spn(self) -> None:
        self.assertIn("ef-spn", roundtrip_capable_ef_keys())


class MsisdnEncoderTests(unittest.TestCase):
    def setUp(self) -> None:
        alpha = b"HOME"
        footer = (
            bytes([0x07, 0x81])
            + bytes.fromhex("103254FFFFFFFFFFFFFF")
            + bytes([0xFF, 0xFF])
        )
        self.record = alpha + footer

    def test_identity_roundtrip(self) -> None:
        decoded = _decode_msisdn(self.record.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = self.record.hex().upper()
        encoded = encode_ef_msisdn_record(payload, target_length=len(self.record))
        self.assertEqual(encoded, self.record)

    def test_edit_number_field(self) -> None:
        decoded = _decode_msisdn(self.record.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = self.record.hex().upper()
        payload["number"] = "987654"
        encoded = encode_ef_msisdn_record(payload, target_length=len(self.record))
        redecoded = _decode_msisdn(encoded.hex())
        self.assertTrue(redecoded["number"].startswith("987654"))

    def test_dispatcher_routes_ef_msisdn(self) -> None:
        self.assertIn("ef-msisdn", roundtrip_capable_ef_keys())


class EccEncoderTests(unittest.TestCase):
    def setUp(self) -> None:
        # 112 (BCD-swapped 211F) + 911 (19F1FF) + padding FFFFFF
        self.record = bytes.fromhex("211FFF19F1FFFFFFFF")

    def test_identity_roundtrip(self) -> None:
        decoded = _decode_ecc(self.record.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = self.record.hex().upper()
        encoded = encode_ef_ecc(payload, target_length=len(self.record))
        self.assertEqual(encoded, self.record)

    def test_replace_code(self) -> None:
        decoded = _decode_ecc(self.record.hex())
        payload = dict(decoded)
        payload["emergencyCodes"] = ["999", "911"]
        payload["_ygg_original_hex"] = self.record.hex().upper()
        encoded = encode_ef_ecc(payload, target_length=len(self.record))
        redecoded = _decode_ecc(encoded.hex())
        self.assertEqual(redecoded["emergencyCodes"][0], "999")
        self.assertEqual(redecoded["emergencyCodes"][1], "911")

    def test_reject_non_digit_code(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_ecc({"emergencyCodes": ["9A9"]})

    def test_dispatcher_routes_ef_ecc(self) -> None:
        self.assertIn("ef-ecc", roundtrip_capable_ef_keys())


class PuctEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = b"EUR" + bytes([0x12, 0x34])
        decoded = _decode_puct(raw.hex())
        encoded = encode_ef_puct(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_edit_exponent_sign(self) -> None:
        raw = b"USD" + bytes([0x12, 0x04])
        decoded = _decode_puct(raw.hex())
        decoded["exponent"] = -3
        encoded = encode_ef_puct(dict(decoded), target_length=len(raw))
        redecoded = _decode_puct(encoded.hex())
        self.assertEqual(redecoded["exponent"], -3)

    def test_reject_bad_currency(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_puct({"currency": "EU", "eppu": 1, "exponent": 0})

    def test_dispatcher_routes_ef_puct(self) -> None:
        self.assertIn("ef-puct", roundtrip_capable_ef_keys())


class LociEncoderTests(unittest.TestCase):
    def setUp(self) -> None:
        # TMSI 4B + TBCD LAI 3B (240-07) + LAC 2B + reserved FF + status 00
        self.record = bytes.fromhex("DEADBEEF42F070" + "1234" + "FF" + "00")

    def test_identity_roundtrip(self) -> None:
        decoded = _decode_loci(self.record.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = self.record.hex().upper()
        encoded = encode_ef_loci(payload, target_length=len(self.record))
        self.assertEqual(encoded, self.record)

    def test_edit_lac(self) -> None:
        decoded = _decode_loci(self.record.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = self.record.hex().upper()
        payload["lac"] = "ABCD"
        encoded = encode_ef_loci(payload, target_length=len(self.record))
        self.assertEqual(encoded[7:9], b"\xAB\xCD")

    def test_dispatcher_registers_all_loci_variants(self) -> None:
        keys = roundtrip_capable_ef_keys()
        self.assertIn("ef-loci", keys)
        self.assertIn("ef-psloci", keys)
        self.assertIn("ef-epsloci", keys)


class OplEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes.fromhex("42F070" + "0001" + "FFFE" + "01")
        decoded = _decode_opl_record(raw.hex())
        encoded = encode_ef_opl_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_reject_missing_pnn_identifier(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_opl_record({"plmn": "240-07", "lacStart": "0001", "lacEnd": "0002"})

    def test_dispatcher_routes_ef_opl(self) -> None:
        self.assertIn("ef-opl", roundtrip_capable_ef_keys())


class PnnEncoderTests(unittest.TestCase):
    def test_identity_roundtrip_via_original_hex(self) -> None:
        # Real PNN records prefix the full/short name with a coding-scheme
        # byte (0x80). The encoder can't synthesize that prefix, so we
        # rely on the original-hex shortcut to preserve the record byte
        # for byte when the decoded text matches.
        raw = bytes.fromhex("43" + "09" + "80") + b"Example " + bytes.fromhex("45" + "03") + b"ExM"
        decoded = _decode_pnn_record(raw.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_pnn_record(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_synthesized_record_roundtrips(self) -> None:
        encoded = encode_ef_pnn_record({"fullName": "Example", "shortName": "Ex"})
        redecoded = _decode_pnn_record(encoded.hex())
        self.assertEqual(redecoded["fullName"], "Example")
        self.assertEqual(redecoded["shortName"], "Ex")

    def test_dispatcher_routes_ef_pnn(self) -> None:
        self.assertIn("ef-pnn", roundtrip_capable_ef_keys())


class ServiceTableEncoderTests(unittest.TestCase):
    def test_activate_services_bitmap(self) -> None:
        # Enable services 1, 2, and 10.
        encoded = encode_ef_service_table(
            {
                "activeServices": [
                    "1: UICC service 1",
                    "2: UICC service 2",
                    "10: UICC service 10",
                ]
            }
        )
        # Service 1 -> byte 0 bit 0, service 2 -> byte 0 bit 1,
        # service 10 -> byte 1 bit 1.
        self.assertEqual(encoded[0] & 0b11, 0b11)
        self.assertEqual(encoded[1] & 0b10, 0b10)

    def test_raw_passthrough(self) -> None:
        raw_hex = "FF00FF00"
        encoded = encode_ef_service_table(
            {"raw": raw_hex},
            target_length=4,
        )
        self.assertEqual(encoded, bytes.fromhex(raw_hex))

    def test_dispatcher_registers_all_service_tables(self) -> None:
        keys = roundtrip_capable_ef_keys()
        self.assertIn("ef-ust", keys)
        self.assertIn("ef-est", keys)
        self.assertIn("ef-ist", keys)

    def test_bitmap_roundtrips_via_decoder(self) -> None:
        encoded = encode_ef_service_table(
            {"activeServices": ["3: UICC service 3"]}
        )
        decoded = _decode_service_table(encoded.hex(), _UST_SERVICE_NAMES)
        self.assertEqual(decoded["activeCount"], 1)
        self.assertTrue(
            any(entry.startswith("3:") for entry in decoded["activeServices"])
        )


class PcscfEncoderTests(unittest.TestCase):
    def test_identity_roundtrip_fqdn(self) -> None:
        fqdn = b"pcscf.ims.example.com"
        raw = bytes([0x80, 1 + len(fqdn), 0x00]) + fqdn
        decoded = _decode_pcscf_address(raw.hex())
        encoded = encode_ef_pcscf_address(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_ipv4_roundtrip(self) -> None:
        raw = bytes([0x80, 5, 0x01, 10, 0, 0, 1])
        decoded = _decode_pcscf_address(raw.hex())
        encoded = encode_ef_pcscf_address(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_ipv6_roundtrip(self) -> None:
        ipv6_bytes = bytes.fromhex("20010db8000000000000000000000001")
        raw = bytes([0x80, 17, 0x02]) + ipv6_bytes
        decoded = _decode_pcscf_address(raw.hex())
        encoded = encode_ef_pcscf_address(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_dispatcher_routes_ef_pcscf(self) -> None:
        self.assertIn("ef-pcscf", roundtrip_capable_ef_keys())


class SpdiEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        # SPDI: A3 <len> 80 <len> <PLMN list>
        plmn = bytes.fromhex("42F070")  # 240-07
        inner = bytes([0x80, len(plmn)]) + plmn
        raw = bytes([0xA3, len(inner)]) + inner
        decoded = _decode_spdi(raw.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_spdi(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_rebuild_without_hex_hint(self) -> None:
        encoded = encode_ef_spdi(
            {"serviceProviderPlmnList": ["240-07", "240-10"]}
        )
        redecoded = _decode_spdi(encoded.hex())
        self.assertEqual(
            redecoded["serviceProviderPlmnList"], ["240-07", "240-10"]
        )

    def test_dispatcher_routes_ef_spdi(self) -> None:
        self.assertIn("ef-spdi", roundtrip_capable_ef_keys())


class EpsnscEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        kasme = bytes(range(16))
        raw = bytes([0x07]) + kasme + bytes([0xAA, 0xBB])
        decoded = _decode_eps_nas_security_context(raw.hex())
        encoded = encode_ef_eps_nas_security_context(
            dict(decoded), target_length=len(raw)
        )
        self.assertEqual(encoded[: len(raw)], raw)

    def test_reject_bad_kasme_length(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_eps_nas_security_context(
                {"ksiHeader": "0x00", "kasmeFirst16Bytes": "AABB"}
            )

    def test_dispatcher_routes_ef_epsnsc(self) -> None:
        self.assertIn("ef-epsnsc", roundtrip_capable_ef_keys())


class SmsEncoderTests(unittest.TestCase):
    def test_identity_roundtrip_sms(self) -> None:
        raw = bytes([0x03]) + bytes.fromhex("DEADBEEF")
        decoded = _decode_sms_record(raw.hex())
        encoded = encode_ef_sms_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_state_name_to_status_byte(self) -> None:
        encoded = encode_ef_sms_record(
            {"recordState": "Received read", "tpduHex": "AA"}
        )
        self.assertEqual(encoded[0], 0x01)

    def test_identity_roundtrip_smsr(self) -> None:
        raw = bytes([0x02]) + bytes.fromhex("CAFEBABE")
        decoded = _decode_sms_status_reports(raw.hex())
        encoded = encode_ef_sms_status_report(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded[: len(raw)], raw)

    def test_dispatcher_routes_sms_family(self) -> None:
        keys = roundtrip_capable_ef_keys()
        self.assertIn("ef-sms", keys)
        self.assertIn("ef-smsr", keys)


class DirEncoderTests(unittest.TestCase):
    def test_identity_roundtrip_via_hex_hint(self) -> None:
        # Application Template containing an Application Identifier.
        aid = bytes.fromhex("A0000000871002FF86FF00890000")
        inner = bytes([0x4F, len(aid)]) + aid
        raw = bytes([0x61, len(inner)]) + inner
        decoded = _decode_ef_dir_record(raw.hex())
        payload = dict(decoded)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_dir_record(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_rebuild_without_hex_hint(self) -> None:
        payload = {
            "items": [
                {
                    "tag": "61",
                    "items": [
                        {"tag": "4F", "raw": "A000000087"},
                        {"tag": "50", "raw": "55534D"},
                    ],
                }
            ]
        }
        encoded = encode_ef_dir_record(payload)
        redecoded = _decode_ef_dir_record(encoded.hex())
        self.assertIsNotNone(redecoded)
        self.assertEqual(len(redecoded["items"]), 1)

    def test_dispatcher_routes_ef_dir(self) -> None:
        self.assertIn("ef-dir", roundtrip_capable_ef_keys())


class AclEncoderTests(unittest.TestCase):
    def test_identity_roundtrip_raw(self) -> None:
        raw = bytes([0x02]) + bytes.fromhex("DD02A1B2") + bytes.fromhex("DD02C3D4")
        encoded = encode_ef_apn_control_list(
            {"apnCount": 2, "tlvBytes": raw[1:].hex().upper()},
            target_length=len(raw),
        )
        self.assertEqual(encoded[: len(raw)], raw)

    def test_raw_passthrough(self) -> None:
        encoded = encode_ef_apn_control_list(
            {"raw": "03FF00FF", "_ygg_original_hex": "03FF00FF"},
            target_length=4,
        )
        self.assertEqual(encoded, bytes.fromhex("03FF00FF"))

    def test_reject_invalid_count(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_apn_control_list({"apnCount": "two", "tlvBytes": ""})


class GbanlEncoderTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        naf = bytes.fromhex("DEADBEEF")
        btid = bytes.fromhex("CAFEBA")
        raw = bytes([0x80, len(naf)]) + naf + bytes([0x81, len(btid)]) + btid
        encoded = encode_ef_gbanl(
            {"nafId": naf.hex().upper(), "bTid": btid.hex().upper()},
            target_length=len(raw),
        )
        self.assertEqual(encoded[: len(raw)], raw)

    def test_reject_odd_length_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_gbanl({"nafId": "ABC"})


class DispatcherIntegrationTests(unittest.TestCase):
    """Confirm that `encode_decoded_roundtrip_ef_content` picks up every
    new encoder by key."""

    def test_every_new_key_is_routeable(self) -> None:
        expected = {
            "ef-spn",
            "ef-msisdn",
            "ef-ecc",
            "ef-puct",
            "ef-loci",
            "ef-psloci",
            "ef-epsloci",
            "ef-opl",
            "ef-pnn",
            "ef-ust",
            "ef-est",
            "ef-ist",
            "ef-pcscf",
            "ef-spdi",
            "ef-epsnsc",
            "ef-sms",
            "ef-smsr",
            "ef-dir",
            "ef-acl",
            "ef-gbanl",
        }
        keys = set(roundtrip_capable_ef_keys())
        missing = expected - keys
        self.assertEqual(missing, set(), f"missing dispatcher keys: {sorted(missing)}")

    def test_dispatcher_returns_bytes_for_spn(self) -> None:
        result = encode_decoded_roundtrip_ef_content(
            "ef-spn",
            {"displayCondition": "0x01", "serviceProviderName": "Example"},
            target_length=16,
        )
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 16)


if __name__ == "__main__":
    unittest.main()
