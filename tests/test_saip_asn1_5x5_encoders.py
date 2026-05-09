"""Unit tests for the 5x5 batch of pair-encoders added for call-info,
key-material, network-config, 5G-specific, and obscure EFs.

Every encoder is verified with at least:
- a raw-hex identity roundtrip (decode -> encode -> bytes-equal),
- a structured-field rebuild where the decoder exposes semantic fields,
- a dispatcher registration assertion.

Lossy-splicer EFs (ICI/OCI/LND) additionally test the
``_ygg_original_hex`` hint path.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_adn_like_record,
    _decode_ccp_record,
    _decode_extension_record,
    _decode_gsm_kc_record,
    _decode_hidden_key,
    _decode_ici_oci_record,
    _decode_nasconfig,
    _decode_one_byte_indicator,
    _decode_opaque_ef,
    _decode_suci_calc_info,
    _decode_supinai,
    _decode_usim_keys_record,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_ef_content,
    encode_ef_ccp_record,
    encode_ef_extension_record,
    encode_ef_gsm_kc_record,
    encode_ef_hidden_key,
    encode_ef_ici_oci_record,
    encode_ef_lnd_record,
    encode_ef_nasconfig,
    encode_ef_one_byte_indicator,
    encode_ef_opaque,
    encode_ef_suci_calc_info,
    encode_ef_supinai,
    encode_ef_usim_keys_record,
    roundtrip_capable_ef_keys,
)


# ---------------------------------------------------------------------------
# Pass A — call and phonebook records.


class LndRecordEncoderTests(unittest.TestCase):
    def test_adn_like_roundtrip(self) -> None:
        raw = (
            b"ACME"
            + (b"\xFF" * 10)
            + bytes.fromhex("05" + "81" + "1032547698" + ("FF" * 4) + "FF" + "FF")
        )
        decoded = _decode_adn_like_record(raw.hex())
        self.assertIsInstance(decoded, dict)
        payload = dict(decoded)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_lnd_record(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)


class IciOciRecordEncoderTests(unittest.TestCase):
    def _sample_ici(self) -> bytes:
        adn = (
            b"IN"
            + (b"\xFF" * 8)
            + bytes.fromhex("05" + "81" + "1032547698" + "FF" * 4 + "FF" + "FF")
        )
        trailer = bytes.fromhex("210426170800FF" + "000010" + "01" + "0001")
        return adn + trailer

    def test_ici_roundtrip_with_trailer_hex(self) -> None:
        raw = self._sample_ici()
        decoded = _decode_ici_oci_record(
            raw.hex(),
            format_name="ICI",
            trailer_fields=(
                ("dateAndTime", 7),
                ("callDuration", 3),
                ("callStatus", 1),
                ("linkTimer", 2),
            ),
        )
        payload = dict(decoded)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_ici_oci_record(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_ici_rebuild_from_trailer_fields(self) -> None:
        raw = self._sample_ici()
        decoded = _decode_ici_oci_record(
            raw.hex(),
            format_name="ICI",
            trailer_fields=(
                ("dateAndTime", 7),
                ("callDuration", 3),
                ("callStatus", 1),
                ("linkTimer", 2),
            ),
        )
        payload = dict(decoded)
        payload.pop("trailerHex", None)
        payload["_ygg_original_hex"] = raw.hex().upper()
        encoded = encode_ef_ici_oci_record(payload, target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_reject_missing_original_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_ici_oci_record({"trailerHex": "00"})


class ExtensionRecordEncoderTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        raw = bytes([0x02]) + (b"\xAA" * 11) + bytes([0xFF])
        decoded = _decode_extension_record(raw.hex())
        encoded = encode_ef_extension_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_structured_rebuild(self) -> None:
        encoded = encode_ef_extension_record(
            {
                "recordType": "0x01",
                "extensionDataHex": "FF" * 11,
                "identifier": "0x02",
            }
        )
        self.assertEqual(encoded, bytes([0x01]) + (b"\xFF" * 11) + bytes([0x02]))

    def test_reject_bad_data_length(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_extension_record(
                {"recordType": "0x00", "extensionDataHex": "00", "identifier": "0x00"}
            )


class CcpRecordEncoderTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        raw = bytes.fromhex("A0" + ("AA" * 14))
        decoded = _decode_ccp_record(raw.hex())
        encoded = encode_ef_ccp_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_reject_wrong_length(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_ccp_record({"bearerCapabilityHex": "AA"})


# ---------------------------------------------------------------------------
# Pass A — key material.


class UsimKeysRecordEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes([0x07]) + (b"\x11" * 16) + (b"\x22" * 16)
        decoded = _decode_usim_keys_record(raw.hex(), format_name="EF.KEYS")
        encoded = encode_ef_usim_keys_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_structured_rebuild(self) -> None:
        encoded = encode_ef_usim_keys_record(
            {
                "ksi": "0x07",
                "cipheringKeyHex": "11" * 16,
                "integrityKeyHex": "22" * 16,
            }
        )
        self.assertEqual(len(encoded), 33)
        self.assertEqual(encoded[0], 0x07)


class GsmKcRecordEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = (b"\xCA" * 8) + bytes([0x05])
        decoded = _decode_gsm_kc_record(raw.hex(), format_name="EF.KC")
        encoded = encode_ef_gsm_kc_record(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_structured_rebuild(self) -> None:
        encoded = encode_ef_gsm_kc_record(
            {"kcHex": "CA" * 8, "cksn": 5}
        )
        self.assertEqual(encoded, (b"\xCA" * 8) + bytes([0x05]))

    def test_cksn_raw(self) -> None:
        encoded = encode_ef_gsm_kc_record(
            {"kcHex": "00" * 8, "cksnRaw": "0xF7"}
        )
        self.assertEqual(encoded[-1], 0xF7)


class HiddenKeyEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes([0x03]) + (b"\xBB" * 8)
        decoded = _decode_hidden_key(raw.hex())
        encoded = encode_ef_hidden_key(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_structured_rebuild(self) -> None:
        encoded = encode_ef_hidden_key(
            {"attemptsRemaining": 3, "hiddenKeyHex": "BB" * 8}
        )
        self.assertEqual(encoded[0], 0x03)

    def test_reject_short_key(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_hidden_key(
                {"attemptsRemaining": 0, "hiddenKeyHex": "AA"}
            )


# ---------------------------------------------------------------------------
# Pass A — network config.


class OpaqueEncoderTests(unittest.TestCase):
    def test_hex_passthrough(self) -> None:
        raw = bytes.fromhex("DEADBEEFCAFEBABE")
        decoded = _decode_opaque_ef(raw.hex(), format_name="opaque")
        encoded = encode_ef_opaque(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_ascii_recompose_with_padding(self) -> None:
        encoded = encode_ef_opaque({"ascii": "Hi"}, target_length=4)
        self.assertEqual(encoded, b"Hi" + b"\xFF\xFF")

    def test_original_hex_fallback(self) -> None:
        encoded = encode_ef_opaque({"_ygg_original_hex": "0001"})
        self.assertEqual(encoded, b"\x00\x01")

    def test_reject_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_opaque({})


class OneByteIndicatorEncoderTests(unittest.TestCase):
    def test_decimal(self) -> None:
        encoded = encode_ef_one_byte_indicator({"decimal": 0x01}, target_length=1)
        self.assertEqual(encoded, b"\x01")

    def test_hex(self) -> None:
        encoded = encode_ef_one_byte_indicator({"hex": "FF"}, target_length=1)
        self.assertEqual(encoded, b"\xFF")

    def test_roundtrip(self) -> None:
        raw = bytes([0x03])
        decoded = _decode_one_byte_indicator(
            raw.hex(),
            format_name="test",
        )
        encoded = encode_ef_one_byte_indicator(dict(decoded), target_length=1)
        self.assertEqual(encoded, raw)

    def test_reject_wrong_length_target(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_one_byte_indicator({"decimal": 0}, target_length=2)


class NasConfigEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("8001" + "01" + "8101" + "02")
        decoded = _decode_nasconfig(raw.hex())
        encoded = encode_ef_nasconfig(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_rebuild_from_items(self) -> None:
        encoded = encode_ef_nasconfig(
            {
                "items": [
                    {"tag": "80", "raw": "01"},
                    {"tag": "81", "raw": "02"},
                ]
            }
        )
        self.assertEqual(encoded, bytes.fromhex("80010181" + "0102"))


# ---------------------------------------------------------------------------
# Pass A — 5G.


class SuciCalcInfoEncoderTests(unittest.TestCase):
    def test_hex_roundtrip(self) -> None:
        raw = bytes.fromhex("A00A" + "8001" + "02" + "8105" + "0102030405")
        decoded = _decode_suci_calc_info(raw.hex())
        encoded = encode_ef_suci_calc_info(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)


class SupinaiEncoderTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        nai = "user@example.com"
        nai_bytes = nai.encode("utf-8")
        raw = bytes([0x80, len(nai_bytes)]) + nai_bytes
        decoded = _decode_supinai(raw.hex())
        encoded = encode_ef_supinai(dict(decoded), target_length=len(raw))
        self.assertEqual(encoded, raw)

    def test_rebuild_from_nai(self) -> None:
        encoded = encode_ef_supinai({"nai": "abc"})
        self.assertEqual(encoded, bytes([0x80, 0x03]) + b"abc")

    def test_reject_missing_field(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_ef_supinai({})


# ---------------------------------------------------------------------------
# Dispatcher registration sweep.


class DispatcherRegistrationTests(unittest.TestCase):
    def test_all_new_keys_registered(self) -> None:
        keys = roundtrip_capable_ef_keys()
        expected = {
            "ef-lnd",
            "ef-ici",
            "ef-oci",
            "ef-ext1",
            "ef-ext2",
            "ef-ext3",
            "ef-ccp1",
            "ef-ccp2",
            "ef-cmi",
            "ef-keys",
            "ef-keysPS",
            "ef-kc",
            "ef-kcgprs",
            "ef-hiddenkey",
            "ef-netpar",
            "ef-nia",
            "ef-lrplmnsi",
            "ef-nasconfig",
            "ef-sume",
            "ef-suci-calc-info-usim",
            "ef-supinai",
            "ef-pkcs15-acrf",
            "ef-cpbcch",
            "ef-invscan",
            "ef-s7",
        }
        missing = expected - set(keys)
        self.assertFalse(missing, f"missing dispatcher keys: {sorted(missing)}")

    def test_dispatcher_routes_ici_via_splicer(self) -> None:
        adn = (
            b"IN"
            + (b"\xFF" * 8)
            + bytes.fromhex("05" + "81" + "1032547698" + "FF" * 4 + "FF" + "FF")
        )
        trailer = bytes.fromhex("210426170800FF" + "000010" + "01" + "0001")
        raw = adn + trailer
        payload = {
            "_ygg_original_hex": raw.hex().upper(),
            "trailerHex": trailer.hex().upper(),
        }
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-ici",
            payload,
            target_length=len(raw),
        )
        self.assertEqual(encoded, raw)

    def test_dispatcher_routes_opaque_via_netpar(self) -> None:
        raw = bytes.fromhex("DEADBEEF")
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-netpar",
            {"hex": raw.hex().upper()},
            target_length=len(raw),
        )
        self.assertEqual(encoded, raw)


if __name__ == "__main__":
    unittest.main()
