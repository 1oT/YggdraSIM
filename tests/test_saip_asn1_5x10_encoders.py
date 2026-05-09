"""Tests for the 5×10 decoded-edit sweep.

Covers the 40+ EF tokens added in the fifth sweep (5G EFs in DF.5GS,
phonebook family under DF.PHONEBOOK, legacy 3GPP EFs, and ISIM/multimedia
extras). Each EF is verified via:

- decode -> encode identity roundtrip
- structured re-composition where a semantic decoder exists
- dispatcher registration
- hex-hint wiring (where applicable)
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    _EF_CONTENT_DISPATCHER,
    encode_decoded_roundtrip_ef_content,
)
from Tools.ProfilePackage.saip_decoded_edit import (
    _HEX_HINTED_EF_KEYS,
    _LOSSY_SPLICE_EF_KEYS,
)


def _decode_and_roundtrip(
    *, ef_key: str, fid: str, raw: bytes, inject_original: bool = False
) -> bytes:
    decoded = _decode_known_ef_payload(
        ef_key=ef_key, fid=fid, hex_clean=raw.hex()
    )
    assert isinstance(decoded, dict), f"{ef_key}: decoder returned {decoded!r}"
    if inject_original:
        decoded["_ygg_original_hex"] = raw.hex().upper()
    encoded = encode_decoded_roundtrip_ef_content(
        ef_key, decoded, target_length=len(raw)
    )
    assert encoded is not None, f"{ef_key}: no encoder registered"
    return encoded


class RoutingIndicatorTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x21, 0x43, 0x00, 0xFF])
        encoded = _decode_and_roundtrip(
            ef_key="ef-routing-indicator", fid="4F0A", raw=raw
        )
        self.assertEqual(encoded, raw)

    def test_change_ri_digits(self) -> None:
        raw = bytes([0x21, 0x43, 0x00, 0xFF])
        decoded = _decode_known_ef_payload(
            ef_key="ef-routing-indicator", fid="4F0A", hex_clean=raw.hex()
        )
        self.assertIsNotNone(decoded)
        decoded.pop("hex", None)
        decoded["routingIndicator"] = "99"
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-routing-indicator", decoded, target_length=4
        )
        # "99" left-padded with F in high nibbles: byte0 = 0x99, byte1 = 0xFF.
        self.assertEqual(encoded, bytes([0x99, 0xFF, 0x00, 0xFF]))

    def test_rejects_non_digits(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_ef_content(
                "ef-routing-indicator",
                {"routingIndicator": "12A", "flagByte": "0x00"},
                target_length=4,
            )


class UacAicTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x09, 0x80, 0x00, 0x01])
        encoded = _decode_and_roundtrip(
            ef_key="ef-uac-aic", fid="4F06", raw=raw
        )
        self.assertEqual(encoded, raw)

    def test_structured_recomposition(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-uac-aic",
            {"accessIdentities": [0, 15, 31]},
            target_length=4,
        )
        # bit 0 = byte0 0x01; bit 15 = byte1 0x80; bit 31 = byte3 0x80.
        self.assertEqual(encoded, bytes([0x01, 0x80, 0x00, 0x80]))

    def test_rejects_out_of_range(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_ef_content(
                "ef-uac-aic", {"accessIdentities": [32]}
            )


class Opl5gTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = (
            bytes.fromhex("62F220")
            + (1).to_bytes(3, "big")
            + (256).to_bytes(3, "big")
            + bytes([10])
        )
        encoded = _decode_and_roundtrip(ef_key="ef-opl5g", fid="4F08", raw=raw)
        self.assertEqual(encoded, raw)

    def test_structured_recomposition(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-opl5g",
            {
                "plmnHex": "62F220",
                "tacStart": 0,
                "tacEnd": 0xFFFFFF,
                "pnnRecordId": 7,
            },
            target_length=10,
        )
        expected = (
            bytes.fromhex("62F220")
            + bytes.fromhex("000000")
            + bytes.fromhex("FFFFFF")
            + bytes([7])
        )
        self.assertEqual(encoded, expected)


class SuciCalc5gAliasTests(unittest.TestCase):
    """ef-5g-suci-calc-info in DF.5GS shares the USIM encoder."""

    def test_reuses_suci_calc_encoder(self) -> None:
        hex_body = "A003020101"
        raw = bytes.fromhex(hex_body)
        decoded = _decode_known_ef_payload(
            ef_key="ef-5g-suci-calc-info", fid="4F07", hex_clean=raw.hex()
        )
        self.assertIsInstance(decoded, dict)
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-5g-suci-calc-info", decoded, target_length=len(raw)
        )
        self.assertEqual(encoded, raw)


class Opaque5gEfTests(unittest.TestCase):
    """5G-specific EFs — originally opaque passthrough, some are now
    length-strict semantic decoders (5GSxLOCI / 5GSEDRX / 5GNSWO)."""

    # 5GS LOCI layout: 13B 5G-GUTI + 3B TAI-PLMN + 3B TAC + 1B status.
    _LOCI_SAMPLE = bytes.fromhex(
        "00F110" "AA" "BBCC" "11223344" "00FFEE"  # 5G-GUTI
        "00F110"
        "000001"
        "00"
    )
    CASES = (
        ("ef-5gs3gpploci", "4F01", _LOCI_SAMPLE),
        ("ef-5gsn3gpploci", None, _LOCI_SAMPLE),
        ("ef-5gs3gppnsc", "4F03", bytes.fromhex("AA" * 8)),
        ("ef-5gsn3gppnsc", "4F04", bytes.fromhex("BB" * 8)),
        ("ef-5gauthkeys", "4F05", bytes.fromhex("00" * 32)),
        ("ef-ursp", "4F0B", bytes.fromhex("80040102030481028000")),
        # 5GSEDRX is 1-2 bytes; 5GNSWO_CONF is 1 byte. FIDs 4F10/4F11
        # now collide with DF.PHONEBOOK ANR anchors, so tests rely on
        # token-first routing. See dispatcher comment for details.
        ("ef-5gsedrx", None, bytes([0x05])),
        ("ef-5gnswo-conf", None, bytes([0x01])),
    )

    def test_identity_roundtrip(self) -> None:
        for token, fid, raw in self.CASES:
            with self.subTest(token=token):
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw, inject_original=True
                )
                self.assertEqual(encoded, raw)


class Tn3gppSnnTests(unittest.TestCase):
    def test_uri_tlv_roundtrip(self) -> None:
        text = b"ssid.example.net"
        raw = bytes([0x80, len(text)]) + bytes(text)
        encoded = _decode_and_roundtrip(
            ef_key="ef-tn3gppsnn", fid="4F0C", raw=raw
        )
        self.assertEqual(encoded, raw)

    def test_structured_change(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-tn3gppsnn", {"uri": "new.ssid.example.net"}
        )
        self.assertEqual(encoded[0], 0x80)
        self.assertEqual(encoded[1], len("new.ssid.example.net"))


class PbrTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        adn_ref = bytes([0xC0, 0x04, 0x6F, 0x3A, 0x00, 0x01])
        ext1_ref = bytes([0xC2, 0x04, 0x6F, 0x4A, 0x00, 0x02])
        inner = adn_ref + ext1_ref
        raw = bytes([0xA8, len(inner)]) + inner
        encoded = _decode_and_roundtrip(ef_key="ef-pbr", fid="4F30", raw=raw)
        self.assertEqual(encoded, raw)


class AnrTests(unittest.TestCase):
    """ANR / ANRA / ANRB / ANRC all reuse the ADN splicer."""

    CASES = (
        ("ef-anr", "4F11"),
        ("ef-anra", "4F12"),
        ("ef-anrb", "4F13"),
        ("ef-anrc", "4F14"),
    )

    def test_identity_roundtrip(self) -> None:
        raw = (
            b"ANR" + bytes([0xFF] * 11)
            + bytes([0x05, 0x91])
            + bytes.fromhex("121122334455")
            + bytes([0xFF, 0xFF])
            + bytes([0xFF, 0xFF])
        )
        for token, fid in self.CASES:
            with self.subTest(token=token):
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw, inject_original=True
                )
                self.assertEqual(encoded, raw)


class PhonebookOpaqueTests(unittest.TestCase):
    CASES = (
        ("ef-iap", "4F25", bytes([0x01, 0x02, 0x03, 0x04])),
        ("ef-sne", "4F19", bytes([0xFF] * 8)),
        ("ef-snea", "4F1A", bytes([0xAA] * 10)),
        ("ef-sneb", "4F1B", bytes([0x55] * 10)),
        ("ef-email", "4F50", b"alice@example.com" + bytes([0xFF] * 20)),
        ("ef-emailb", "4F51", b"bob@example.com" + bytes([0xFF] * 20)),
        ("ef-gas", "4F4C", b"group1" + bytes([0xFF] * 10)),
        ("ef-grp", "4F26", bytes([0x01, 0x02, 0x00, 0x00])),
        ("ef-psc", "4F22", bytes([0x00, 0x00, 0x00, 0x01])),
        ("ef-cc", "4F23", bytes([0x00, 0x00, 0x00, 0x05])),
        ("ef-puid", "4F24", bytes([0x12, 0x34, 0x56, 0x78])),
    )

    def test_identity_roundtrip(self) -> None:
        for token, fid, raw in self.CASES:
            with self.subTest(token=token):
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw, inject_original=True
                )
                self.assertEqual(encoded, raw)


class PhaseIndicatorTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        for phase_byte in (0x00, 0x02, 0x03):
            with self.subTest(phase=phase_byte):
                raw = bytes([phase_byte])
                encoded = _decode_and_roundtrip(
                    ef_key="ef-phase", fid="6FAE", raw=raw
                )
                self.assertEqual(encoded, raw)


class PlmnSelTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes.fromhex("62F22024008062F230")
        encoded = _decode_and_roundtrip(
            ef_key="ef-plmnsel", fid="6F30", raw=raw
        )
        self.assertEqual(encoded, raw)


class LegacyOpaqueTests(unittest.TestCase):
    CASES = (
        ("ef-bcch", "6F74", bytes.fromhex("0102030405060708") * 2),
        ("ef-locigprs", "6F53", bytes([0xAB] * 14)),
    )

    def test_identity_roundtrip(self) -> None:
        for token, fid, raw in self.CASES:
            with self.subTest(token=token):
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw, inject_original=True
                )
                self.assertEqual(encoded, raw)


class UriEfTests(unittest.TestCase):
    # TS 31.102 Rel-18: FDNURI=6FED, BDNURI=6FEE, SDNURI=6FEF.
    # 6FEC is EF.PWS and MUST NOT be re-used for SDNURI in the FID map.
    CASES = (
        ("ef-fdnuri", "6FED", "sip:fdn@example.com"),
        ("ef-bdnuri", "6FEE", "sip:bdn@example.com"),
        ("ef-sdnuri", "6FEF", "sip:sdn@example.com"),
        ("ef-lnduri", "6FEA", "sip:lnd@example.com"),
        ("ef-muddomain", "6FDF", "mud.example.com"),
        ("ef-uiccsi", "6FE6", "urn:uuid:0000-1111"),
        ("ef-ehuri", "6FE7", "sip:eh@example.com"),
    )

    def test_uri_tlv_roundtrip(self) -> None:
        for token, fid, uri_text in self.CASES:
            with self.subTest(token=token):
                body = uri_text.encode("utf-8")
                raw = bytes([0x80, len(body)]) + body
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw
                )
                self.assertEqual(encoded, raw)


class IsimExtraOpaqueTests(unittest.TestCase):
    CASES = (
        ("ef-psismsc", "6FE5", bytes.fromhex("00112233445566778899AABB")),
        ("ef-impdf", "6F27", bytes.fromhex("AA" * 10)),
        ("ef-nafkca-list", "6FDE", bytes.fromhex("01" * 8)),
        ("ef-earfcnlist", "6FFD", bytes.fromhex("13881770") * 2),
        ("ef-fcst", "6FEE", bytes.fromhex("BB" * 10)),
        ("ef-phist", "6FEF", bytes.fromhex("CC" * 10)),
    )

    def test_identity_roundtrip(self) -> None:
        for token, fid, raw in self.CASES:
            with self.subTest(token=token):
                encoded = _decode_and_roundtrip(
                    ef_key=token, fid=fid, raw=raw, inject_original=True
                )
                self.assertEqual(encoded, raw)


class PcscfUrnTests(unittest.TestCase):
    def test_shares_pcscf_encoder(self) -> None:
        # P-CSCF address TLV: 80 LL <URI>
        body = b"sip:pcscf.example.com"
        raw = bytes([0x80, len(body)]) + body
        decoded = _decode_known_ef_payload(
            ef_key="ef-pcscf-urn", fid=None, hex_clean=raw.hex()
        )
        self.assertIsInstance(decoded, dict)
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-pcscf-urn", decoded, target_length=len(raw)
        )
        self.assertEqual(encoded, raw)


class DispatcherRegistrationTests(unittest.TestCase):
    """All 40+ new EF tokens are registered in the content dispatcher."""

    EXPECTED_KEYS = (
        # Pass A — 5G.
        "ef-5gs3gpploci",
        "ef-5gsn3gpploci",
        "ef-5gs3gppnsc",
        "ef-5gsn3gppnsc",
        "ef-5gauthkeys",
        "ef-uac-aic",
        "ef-5g-suci-calc-info",
        "ef-opl5g",
        "ef-routing-indicator",
        "ef-ursp",
        # Pass B — Phonebook.
        "ef-pbr",
        "ef-iap",
        "ef-anr",
        "ef-anra",
        "ef-anrb",
        "ef-anrc",
        "ef-sne",
        "ef-snea",
        "ef-sneb",
        "ef-email",
        "ef-emailb",
        "ef-gas",
        "ef-grp",
        "ef-psc",
        "ef-cc",
        "ef-puid",
        # Pass C — 5G extras + legacy 3GPP.
        "ef-tn3gppsnn",
        "ef-5gsedrx",
        "ef-5gnswo-conf",
        "ef-phase",
        "ef-plmnsel",
        "ef-bcch",
        "ef-locigprs",
        "ef-fdnuri",
        "ef-bdnuri",
        "ef-sdnuri",
        "ef-lnduri",
        # Pass D — ISIM / multimedia.
        "ef-pcscf-urn",
        "ef-muddomain",
        "ef-psismsc",
        "ef-uiccsi",
        "ef-ehuri",
        "ef-impdf",
        "ef-nafkca-list",
        "ef-earfcnlist",
        "ef-fcst",
        "ef-phist",
    )

    def test_all_keys_registered(self) -> None:
        for key in self.EXPECTED_KEYS:
            with self.subTest(key=key):
                self.assertIn(
                    key,
                    _EF_CONTENT_DISPATCHER,
                    f"{key} is missing from _EF_CONTENT_DISPATCHER",
                )

    def test_hex_hinted_set_covers_opaque_keys(self) -> None:
        required_hex_hinted = (
            "ef-5gs3gpploci",
            "ef-5gsn3gpploci",
            "ef-5gauthkeys",
            "ef-ursp",
            "ef-pbr",
            "ef-iap",
            "ef-sne",
            "ef-email",
            "ef-grp",
            "ef-bcch",
            "ef-locigprs",
            "ef-fdnuri",
            "ef-sdnuri",
            "ef-lnduri",
            "ef-muddomain",
            "ef-phase",
        )
        for key in required_hex_hinted:
            with self.subTest(key=key):
                self.assertIn(key, _HEX_HINTED_EF_KEYS)

    def test_anr_records_are_lossy_splice(self) -> None:
        for key in ("ef-anr", "ef-anra", "ef-anrb", "ef-anrc"):
            with self.subTest(key=key):
                self.assertIn(key, _LOSSY_SPLICE_EF_KEYS)


if __name__ == "__main__":
    unittest.main()
