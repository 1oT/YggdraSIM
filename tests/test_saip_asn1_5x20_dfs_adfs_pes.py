"""Tests for the broad DF / ADF / ProfileElement / field surface.

Covers four groups of decoded-edit additions:

- DF identifier tokens (df-telecom, df-phonebook, df-graphics, df-mms,
  df-solsa, df-mexe, df-wlan, df-hnb, df-oma-bcast, df-ecat, df-mcs,
  df-mcptt, df-mcvideo, df-mcdata, df-v2x, df-prose, df-iot,
  df-5gprose-relay, df-a2x, df-hpsim).
- ADF identifier tokens (adf-hpsim, adf-mcptt, adf-mcvideo, adf-mcdata,
  adf-v2x, adf-prose-ue, adf-prose-relay, adf-5gprose-relay,
  adf-5gprose-disc, adf-iot, adf-dualimsi, adf-cl, adf-a2x, adf-eap,
  adf-test, adf-snpn, adf-orph, adf-mcvdata, adf-v2xrelay,
  adf-a2xrelay).
- PE filesystem hints for new PE base types (usim, opt-usim, csim,
  opt-csim, opt-eap, cdmaParameter, gsm-access, wlan, df-wlan,
  df-prose, df-iot, df-hnb, df-mcs, df-mcptt, df-mcvideo, df-mcdata,
  df-v2x, df-a2x, df-telecom, df-phonebook, df-graphics, df-mms,
  df-solsa, df-mexe, df-oma-bcast, df-ecat, df-5gprose-relay,
  df-hpsim, adf-hpsim, adf-mcptt, adf-mcvideo, adf-mcdata, adf-v2x,
  adf-prose-ue, adf-prose-relay, adf-5gprose-relay,
  adf-5gprose-disc, adf-iot, adf-dualimsi, adf-cl, adf-a2x,
  adf-eap, adf-test, adf-snpn, adf-orph, application, rfm,
  securityDomain, akaParameter, cdma).
- PE-level subtag field encoders (iccid, hashValue, lcsi, efFileSize,
  adfRFMAccess, mappingOptions, mappingSource, processData,
  sdPersoData, proprietaryEFInfo, tlvBytes, profileVersion,
  customFieldOctets, serialNumber, notificationAddress, major-version,
  minor-version, identification, shortEFID, templateID).

Plus a coverage audit + dispatcher registration sanity check.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _EF_KEY_TO_FID,
    _filesystem_hint,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    _BYTES_DISPATCHER,
    _SCALAR_DISPATCHER,
    encode_decoded_roundtrip_bytes,
)


# ---------------------------------------------------------------------------
# DF identifier tokens.


class DfTokenRegistrationTests(unittest.TestCase):
    """All 20 new DF tokens resolve to their standardised FIDs."""

    EXPECTED: dict[str, str] = {
        "df-telecom": "7F10",
        "df-phonebook": "5F3A",
        "df-graphics": "5F50",
        "df-mms": "5F3D",
        "df-solsa": "5F70",
        "df-mexe": "5F3C",
        "df-wlan": "5F40",
        "df-hnb": "5F41",
        "df-oma-bcast": "5F60",
        "df-ecat": "5F80",
        "df-mcs": "5FA0",
        "df-mcptt": "5FA1",
        "df-mcvideo": "5FA2",
        "df-mcdata": "5FA3",
        "df-v2x": "5FA4",
        "df-prose": "5FA5",
        "df-iot": "5FA6",
        "df-5gprose-relay": "5FA7",
        "df-a2x": "5FA8",
        "df-hpsim": "5FA9",
    }

    def test_every_token_resolves(self) -> None:
        for token, fid in self.EXPECTED.items():
            self.assertIn(token, _EF_KEY_TO_FID, f"missing token {token}")
            self.assertEqual(
                _EF_KEY_TO_FID[token],
                fid,
                f"{token}: expected FID {fid}, got {_EF_KEY_TO_FID[token]}",
            )


# ---------------------------------------------------------------------------
# ADF identifier tokens.


class AdfTokenRegistrationTests(unittest.TestCase):
    """All 20 new ADF tokens resolve to their reserved FID slots."""

    EXPECTED: dict[str, str] = {
        "adf-hpsim": "7FF4",
        "adf-mcptt": "7FF5",
        "adf-mcvideo": "7FF6",
        "adf-mcdata": "7FF7",
        "adf-v2x": "7FF8",
        "adf-prose-ue": "7FF9",
        "adf-prose-relay": "7FFA",
        "adf-5gprose-relay": "7FFB",
        "adf-5gprose-disc": "7FFC",
        "adf-iot": "7FFD",
        "adf-dualimsi": "7FFE",
        "adf-cl": "7FFF",
        "adf-a2x": "7FE0",
        "adf-eap": "7FE1",
        "adf-test": "7FE2",
        "adf-snpn": "7FE3",
        "adf-orph": "7FE4",
        "adf-mcvdata": "7FE5",
        "adf-v2xrelay": "7FE6",
        "adf-a2xrelay": "7FE7",
    }

    def test_every_token_resolves(self) -> None:
        for token, fid in self.EXPECTED.items():
            self.assertIn(token, _EF_KEY_TO_FID, f"missing token {token}")
            self.assertEqual(_EF_KEY_TO_FID[token], fid)

    def test_adf_fids_are_in_application_range(self) -> None:
        for token in self.EXPECTED:
            fid = _EF_KEY_TO_FID[token]
            # SAIP / TS 102 221 reserve 7FFx..7FEx for application ADFs.
            self.assertTrue(
                fid.startswith("7FF") or fid.startswith("7FE"),
                f"{token}: FID {fid} is outside ADF range",
            )


# ---------------------------------------------------------------------------
# PE filesystem hint mappings.


class ProfileElementHintTests(unittest.TestCase):
    """New PE base types resolve to documented filesystem paths."""

    EXPECTED: dict[str, str] = {
        "usim": "MF/USIM",
        "opt-usim": "MF/USIM",
        "csim": "MF/CSIM",
        "opt-csim": "MF/CSIM",
        "opt-eap": "MF/USIM/EAP",
        "cdmaParameter": "MF/CSIM",
        "gsm-access": "MF/USIM/GSM-ACCESS",
        "wlan": "MF/USIM/WLAN",
        "df-wlan": "MF/USIM/WLAN",
        "df-prose": "MF/USIM/PROSE",
        "df-iot": "MF/USIM/IOT",
        "df-hnb": "MF/USIM/HNB",
        "df-mcs": "MF/USIM/MCS",
        "df-mcptt": "MF/USIM/MCPTT",
        "df-mcvideo": "MF/USIM/MCVIDEO",
        "df-mcdata": "MF/USIM/MCDATA",
        "df-v2x": "MF/USIM/V2X",
        "df-a2x": "MF/USIM/A2X",
        "df-telecom": "MF/TELECOM",
        "df-phonebook": "MF/TELECOM/PHONEBOOK",
        "df-graphics": "MF/TELECOM/GRAPHICS",
        "df-mms": "MF/TELECOM/MMS",
        "df-solsa": "MF/USIM/SOLSA",
        "df-mexe": "MF/TELECOM/MEXE",
        "df-oma-bcast": "MF/USIM/OMA-BCAST",
        "df-ecat": "MF/USIM/ECAT",
        "df-5gprose-relay": "MF/USIM/5G_PROSE_RELAY",
        "df-hpsim": "MF/HPSIM",
        "adf-hpsim": "MF/ADF_HPSIM",
        "adf-mcptt": "MF/ADF_MCPTT",
        "adf-mcvideo": "MF/ADF_MCVIDEO",
        "adf-mcdata": "MF/ADF_MCDATA",
        "adf-v2x": "MF/ADF_V2X",
        "adf-prose-ue": "MF/ADF_PROSE_UE",
        "adf-prose-relay": "MF/ADF_PROSE_RELAY",
        "adf-5gprose-relay": "MF/ADF_5G_PROSE_RELAY",
        "adf-5gprose-disc": "MF/ADF_5G_PROSE_DISC",
        "adf-iot": "MF/ADF_IOT",
        "adf-dualimsi": "MF/ADF_DUALIMSI",
        "adf-cl": "MF/ADF_CL",
        "adf-a2x": "MF/ADF_A2X",
        "adf-eap": "MF/ADF_EAP",
        "adf-test": "MF/ADF_TEST",
        "adf-snpn": "MF/ADF_SNPN",
        "adf-orph": "MF/ADF_ORPH",
        "application": "MF/APP",
        "rfm": "RFM",
        "securityDomain": "GP_SD",
        "akaParameter": "MF/USIM",
        "cdma": "MF/CSIM",
    }

    def test_every_hint_is_registered(self) -> None:
        for pe_base, expected in self.EXPECTED.items():
            self.assertEqual(
                _filesystem_hint(pe_base),
                expected,
                f"{pe_base}: expected {expected}, got {_filesystem_hint(pe_base)}",
            )

    def test_unknown_pe_base_returns_none(self) -> None:
        self.assertIsNone(_filesystem_hint("not-a-real-pe-type"))


# ---------------------------------------------------------------------------
# PE-level OCTET STRING subtag encoders.


class IccidFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        payload = {"hex": "89880811111111111112"}
        encoded = encode_decoded_roundtrip_bytes("iccid", payload)
        self.assertEqual(encoded.hex().upper(), "89880811111111111112")

    def test_rejects_oversize(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("iccid", {"hex": "00" * 11})

    def test_rejects_missing_hex(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("iccid", {})


class HashValueFieldTests(unittest.TestCase):
    def test_roundtrip_sha256(self) -> None:
        payload = {"hex": "ec" * 32}
        encoded = encode_decoded_roundtrip_bytes("hashValue", payload)
        self.assertEqual(len(encoded), 32)
        self.assertEqual(encoded.hex(), "ec" * 32)

    def test_rejects_empty(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("hashValue", {"hex": ""})


class LcsiFieldTests(unittest.TestCase):
    def test_roundtrip_single_byte(self) -> None:
        encoded = encode_decoded_roundtrip_bytes("lcsi", {"hex": "05"})
        self.assertEqual(encoded, bytes([0x05]))

    def test_rejects_multi_byte(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("lcsi", {"hex": "0504"})


class EfFileSizeFieldTests(unittest.TestCase):
    def test_single_byte(self) -> None:
        encoded = encode_decoded_roundtrip_bytes("efFileSize", {"hex": "06"})
        self.assertEqual(encoded, bytes([0x06]))

    def test_two_byte(self) -> None:
        encoded = encode_decoded_roundtrip_bytes("efFileSize", {"hex": "0100"})
        self.assertEqual(encoded, bytes([0x01, 0x00]))

    def test_rejects_three_byte(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("efFileSize", {"hex": "010203"})


class AdfRfmAccessFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        payload = {"hex": "02030104"}
        encoded = encode_decoded_roundtrip_bytes("adfRFMAccess", payload)
        self.assertEqual(encoded.hex(), "02030104")


class MappingOptionsFieldTests(unittest.TestCase):
    def test_single_byte(self) -> None:
        encoded = encode_decoded_roundtrip_bytes("mappingOptions", {"hex": "03"})
        self.assertEqual(encoded, bytes([0x03]))

    def test_rejects_multi_byte(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes("mappingOptions", {"hex": "0304"})


class MappingSourceFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "mappingSource", {"hex": "deadbeef"}
        )
        self.assertEqual(encoded.hex(), "deadbeef")


class ProcessDataFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "processData", {"hex": "0011223344"}
        )
        self.assertEqual(encoded.hex(), "0011223344")


class SdPersoDataFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "sdPersoData", {"hex": "ff" * 8}
        )
        self.assertEqual(len(encoded), 8)


class ProprietaryEfInfoFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "proprietaryEFInfo", {"hex": "8001ff"}
        )
        self.assertEqual(encoded.hex(), "8001ff")


class TlvBytesFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "tlvBytes", {"hex": "a1050f0102030405"}
        )
        self.assertEqual(encoded.hex(), "a1050f0102030405")


class ProfileVersionFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "profileVersion", {"hex": "0203"}
        )
        self.assertEqual(encoded, bytes([0x02, 0x03]))


class CustomFieldOctetsTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "customFieldOctets", {"hex": "cafe"}
        )
        self.assertEqual(encoded, bytes([0xCA, 0xFE]))


class SerialNumberFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "serialNumber", {"hex": "1234567890"}
        )
        self.assertEqual(encoded, bytes([0x12, 0x34, 0x56, 0x78, 0x90]))


class NotificationAddressFieldTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "notificationAddress", {"hex": "0102"}
        )
        self.assertEqual(encoded, bytes([0x01, 0x02]))


# ---------------------------------------------------------------------------
# PE-level INTEGER subtag encoders.


class MajorVersionFieldTests(unittest.TestCase):
    def test_accepts_byte_range(self) -> None:
        self.assertEqual(_SCALAR_DISPATCHER["major-version"]({"decimal": 2}), 2)

    def test_rejects_overflow(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            _SCALAR_DISPATCHER["major-version"]({"decimal": 256})


class MinorVersionFieldTests(unittest.TestCase):
    def test_accepts_byte_range(self) -> None:
        self.assertEqual(_SCALAR_DISPATCHER["minor-version"]({"decimal": 5}), 5)

    def test_rejects_negative(self) -> None:
        # Routed through _require_int which only enforces int type, so we
        # instead rely on the range check below.
        with self.assertRaises(RoundtripEncoderError):
            _SCALAR_DISPATCHER["minor-version"]({"decimal": -1})


class IdentificationFieldTests(unittest.TestCase):
    def test_accepts_non_negative(self) -> None:
        self.assertEqual(_SCALAR_DISPATCHER["identification"]({"decimal": 1}), 1)

    def test_rejects_negative(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            _SCALAR_DISPATCHER["identification"]({"decimal": -7})


class ShortEfidFieldTests(unittest.TestCase):
    def test_accepts_five_bit_range(self) -> None:
        self.assertEqual(_SCALAR_DISPATCHER["shortEFID"]({"decimal": 0x1F}), 0x1F)

    def test_rejects_overflow(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            _SCALAR_DISPATCHER["shortEFID"]({"decimal": 0x20})


class TemplateIdFieldTests(unittest.TestCase):
    def test_accepts_zero(self) -> None:
        self.assertEqual(_SCALAR_DISPATCHER["templateID"]({"decimal": 0}), 0)

    def test_rejects_negative(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            _SCALAR_DISPATCHER["templateID"]({"decimal": -1})


# ---------------------------------------------------------------------------
# Coverage / dispatcher integration audit.


class DispatcherAuditTests(unittest.TestCase):
    """Sanity checks so future regressions don't silently drop registrations."""

    def test_bytes_dispatcher_includes_all_new_fields(self) -> None:
        expected = {
            "iccid",
            "hashValue",
            "lcsi",
            "efFileSize",
            "adfRFMAccess",
            "mappingOptions",
            "mappingSource",
            "processData",
            "sdPersoData",
            "proprietaryEFInfo",
            "tlvBytes",
            "profileVersion",
            "customFieldOctets",
            "serialNumber",
            "notificationAddress",
        }
        missing = expected - set(_BYTES_DISPATCHER)
        self.assertEqual(missing, set(), f"missing bytes dispatchers: {missing}")

    def test_scalar_dispatcher_includes_all_new_fields(self) -> None:
        expected = {
            "major-version",
            "minor-version",
            "identification",
            "shortEFID",
            "templateID",
        }
        missing = expected - set(_SCALAR_DISPATCHER)
        self.assertEqual(
            missing, set(), f"missing scalar dispatchers: {missing}"
        )

    def test_no_dispatcher_collisions_between_bytes_and_scalar(self) -> None:
        collisions = set(_BYTES_DISPATCHER) & set(_SCALAR_DISPATCHER)
        self.assertEqual(collisions, set())

    def test_df_and_adf_fids_are_unique(self) -> None:
        new_tokens = [
            "df-telecom",
            "df-phonebook",
            "df-graphics",
            "df-mms",
            "df-solsa",
            "df-mexe",
            "df-wlan",
            "df-hnb",
            "df-oma-bcast",
            "df-ecat",
            "df-mcs",
            "df-mcptt",
            "df-mcvideo",
            "df-mcdata",
            "df-v2x",
            "df-prose",
            "df-iot",
            "df-5gprose-relay",
            "df-a2x",
            "df-hpsim",
            "adf-hpsim",
            "adf-mcptt",
            "adf-mcvideo",
            "adf-mcdata",
            "adf-v2x",
            "adf-prose-ue",
            "adf-prose-relay",
            "adf-5gprose-relay",
            "adf-5gprose-disc",
            "adf-iot",
            "adf-dualimsi",
            "adf-cl",
            "adf-a2x",
            "adf-eap",
            "adf-test",
            "adf-snpn",
            "adf-orph",
            "adf-mcvdata",
            "adf-v2xrelay",
            "adf-a2xrelay",
        ]
        resolved = [
            (token, _EF_KEY_TO_FID.get(token)) for token in new_tokens
        ]
        missing = [token for token, fid in resolved if fid is None]
        self.assertEqual(missing, [], f"tokens without FID: {missing}")
        # DFs (df-*) should not collide with each other, ADFs (adf-*) must
        # also remain unique within their own namespace.
        df_fids = [
            fid for token, fid in resolved if token.startswith("df-")
        ]
        adf_fids = [
            fid for token, fid in resolved if token.startswith("adf-")
        ]
        self.assertEqual(
            len(df_fids),
            len(set(df_fids)),
            "DF FIDs contain duplicates",
        )
        self.assertEqual(
            len(adf_fids),
            len(set(adf_fids)),
            "ADF FIDs contain duplicates",
        )


if __name__ == "__main__":
    unittest.main()
