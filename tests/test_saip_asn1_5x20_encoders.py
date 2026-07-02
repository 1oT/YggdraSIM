# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the 5×20 decoded-edit sweep.

Covers 100 additional EF tokens across:
- Pass A (20): Mailbox / CF / VGCS / VBS / eMLPP / DCK / CNL family.
- Pass B (20): CSIM (CDMA SIM) EFs — opaque namespace ``ef-csim-*``.
- Pass C (20): Specialized (ISIM / MCPTT / V2X / ProSe / MCS) EFs.
- Pass D (20): Operator / vendor customs + SCP/OTA auxiliary EFs.
- Pass E: registration + structured-recomposition integration.
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


def _roundtrip(
    *, ef_key: str, fid: str | None, raw: bytes, inject_original: bool = False
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


# ---------------------------------------------------------------------------
# Pass A — Mailbox / CF / VGCS / VBS / eMLPP / DCK / CNL.


class MwisTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x03, 0x03, 0x00, 0x00, 0x00])
        self.assertEqual(_roundtrip(ef_key="ef-mwis", fid="6FCA", raw=raw), raw)

    def test_structured_recomposition(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-mwis",
            {
                "voicemailWaiting": True,
                "faxWaiting": False,
                "emailWaiting": True,
                "otherWaiting": False,
                "voicemailCount": 2,
                "faxCount": 0,
                "emailCount": 5,
                "otherCount": 0,
            },
            target_length=5,
        )
        self.assertEqual(encoded, bytes([0x05, 0x02, 0x00, 0x05, 0x00]))

    def test_rejects_oversize_counter(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_ef_content(
                "ef-mwis", {"voicemailCount": 256}, target_length=5
            )


class MbiTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x01, 0x02, 0x00, 0x00])
        self.assertEqual(_roundtrip(ef_key="ef-mbi", fid="6FC9", raw=raw), raw)

    def test_structured_change(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-mbi",
            {"slots": {"voicemail": 3, "fax": 0, "email": 2, "other": 0}},
            target_length=4,
        )
        self.assertEqual(encoded, bytes([0x03, 0x00, 0x02, 0x00]))


class CfisTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x01, 0x01]) + bytes([0xFF] * 14)
        self.assertEqual(_roundtrip(ef_key="ef-cfis", fid="6FCB", raw=raw), raw)

    def test_cfis2_alias(self) -> None:
        raw = bytes([0x02, 0x0F]) + bytes([0xAA] * 14)
        self.assertEqual(
            _roundtrip(ef_key="ef-cfis2", fid="6FE0", raw=raw), raw
        )

    def test_structured_recomposition(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-cfis",
            {
                "mspNumber": 1,
                "voiceForwardActive": True,
                "faxForwardActive": False,
                "dataForwardActive": True,
                "smsForwardActive": False,
                "tailHex": "FF" * 14,
            },
            target_length=16,
        )
        self.assertEqual(encoded, bytes([0x01, 0x05]) + bytes([0xFF] * 14))


class EmlppTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x19, 0x01])
        self.assertEqual(_roundtrip(ef_key="ef-emlpp", fid="6FB5", raw=raw), raw)

    def test_structured_change(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-emlpp",
            {
                "supportedPriorityLevels": [0, 1, 2, 3],
                "fastCallSetupLevels": [0],
            },
            target_length=2,
        )
        self.assertEqual(encoded, bytes([0x0F, 0x01]))

    def test_rejects_out_of_range(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_ef_content(
                "ef-emlpp", {"supportedPriorityLevels": [8]}
            )


class AaemTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes([0x09])
        self.assertEqual(_roundtrip(ef_key="ef-aaem", fid="6FB6", raw=raw), raw)

    def test_structured_recomposition(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-aaem", {"aaEnabledLevels": [0, 7]}, target_length=1
        )
        self.assertEqual(encoded, bytes([0x81]))


class DckTests(unittest.TestCase):
    def test_identity_roundtrip(self) -> None:
        raw = bytes.fromhex(
            "11111111" + "22222222" + "33333333" + "44444444"
        )
        self.assertEqual(_roundtrip(ef_key="ef-dck", fid="6F2C", raw=raw), raw)

    def test_structured_change(self) -> None:
        encoded = encode_decoded_roundtrip_ef_content(
            "ef-dck",
            {
                "networkKey": "AABBCCDD",
                "networkSubsetKey": "EEFF0011",
                "serviceProviderKey": "22334455",
                "corporateKey": "66778899",
            },
            target_length=16,
        )
        self.assertEqual(
            encoded,
            bytes.fromhex("AABBCCDDEEFF001122334455" + "66778899"),
        )

    def test_rejects_wrong_length(self) -> None:
        with self.assertRaises(RoundtripEncoderError):
            encode_decoded_roundtrip_ef_content(
                "ef-dck",
                {
                    "networkKey": "AABB",
                    "networkSubsetKey": "EEFF0011",
                    "serviceProviderKey": "22334455",
                    "corporateKey": "66778899",
                },
            )


class MbdnTests(unittest.TestCase):
    """EF.MBDN reuses the ADN splicer (lossy)."""

    def test_identity_roundtrip(self) -> None:
        raw = (
            b"VMail" + bytes([0xFF] * 9)
            + bytes([0x05, 0x91])
            + bytes.fromhex("121122334455")
            + bytes([0xFF, 0xFF])
            + bytes([0xFF, 0xFF])
        )
        self.assertEqual(
            _roundtrip(ef_key="ef-mbdn", fid="6FC7", raw=raw, inject_original=True),
            raw,
        )


class ExtensionAliasTests(unittest.TestCase):
    """EF.EXT6 / EF.EXT7 reuse the extension-record encoder."""

    def test_ext6_roundtrip(self) -> None:
        raw = bytes([0x02]) + bytes([0xAA] * 11) + bytes([0xFF])
        self.assertEqual(
            _roundtrip(ef_key="ef-ext6", fid="6FC8", raw=raw, inject_original=True),
            raw,
        )

    def test_ext7_roundtrip(self) -> None:
        raw = bytes([0x01]) + bytes([0x55] * 11) + bytes([0xFE])
        self.assertEqual(
            _roundtrip(ef_key="ef-ext7", fid="6FCC", raw=raw, inject_original=True),
            raw,
        )


class PassAOpaqueTests(unittest.TestCase):
    CASES = (
        ("ef-mbparam", "6FCE", bytes([0xAA] * 8)),
        ("ef-cnl", "6F32", bytes([0x62, 0xF2, 0x20, 0x00])),
        ("ef-vgcs", "6FB1", bytes.fromhex("00112233")),
        ("ef-vgcss", "6FB2", bytes([0x00, 0x00])),
        ("ef-vbs", "6FB3", bytes.fromhex("44556677")),
        ("ef-vbss", "6FB4", bytes([0x01, 0x00])),
        ("ef-anl", "6F2E", bytes([0xBB] * 6)),
        ("ef-mexe-st", None, bytes([0xFF] * 4)),
        ("ef-prose-pfsr", None, bytes([0x12, 0x34, 0x56, 0x78])),
    )

    def test_identity_roundtrip(self) -> None:
        for token, fid, raw in self.CASES:
            with self.subTest(token=token):
                self.assertEqual(
                    _roundtrip(
                        ef_key=token, fid=fid, raw=raw, inject_original=True
                    ),
                    raw,
                )


class VsuriTests(unittest.TestCase):
    def test_uri_tlv_roundtrip(self) -> None:
        body = b"sip:voicemail@example.com"
        raw = bytes([0x80, len(body)]) + body
        self.assertEqual(
            _roundtrip(ef_key="ef-vsuri", fid="6FE9", raw=raw), raw
        )


# ---------------------------------------------------------------------------
# Pass B — CSIM.


class CsimOpaqueTests(unittest.TestCase):
    CSIM_CASES = (
        ("ef-csim-spc", "6F20"),
        ("ef-csim-smscap", "6F21"),
        ("ef-csim-min", "6F22"),
        ("ef-csim-min1", "6F23"),
        ("ef-csim-accolc", "6F24"),
        ("ef-csim-imsi-t", "6F25"),
        ("ef-csim-home-sidnid", "6F26"),
        ("ef-csim-curr-sidnid", "6F27"),
        ("ef-csim-nam-lock", "6F28"),
        ("ef-csim-3gpd", "6F29"),
        ("ef-csim-hpplmnact", "6F2A"),
        ("ef-csim-prl", "6F30"),
        ("ef-csim-eprl", "6F4A"),
        ("ef-csim-namgam", "6F35"),
        ("ef-csim-mdn", "6F40"),
        ("ef-csim-plslpp", "6F46"),
        ("ef-csim-hrpdcap", "4F20"),
        ("ef-csim-ssci", "6F4E"),
        ("ef-csim-mlpl", "6F4F"),
        ("ef-csim-meruiid", "6F5D"),
    )

    def test_all_csim_roundtrip(self) -> None:
        for index, (token, fid) in enumerate(self.CSIM_CASES):
            with self.subTest(token=token):
                raw = bytes([(index + 1) & 0xFF] * 6)
                self.assertEqual(
                    _roundtrip(
                        ef_key=token, fid=fid, raw=raw, inject_original=True
                    ),
                    raw,
                )

    def test_all_csim_registered(self) -> None:
        for token, _fid in self.CSIM_CASES:
            with self.subTest(token=token):
                self.assertIn(token, _EF_CONTENT_DISPATCHER)


# ---------------------------------------------------------------------------
# Pass C — Specialized (ProSe / V2X / MCS / MCPTT).


class SpecializedOpaqueTests(unittest.TestCase):
    CASES = (
        ("ef-prose-pfidg", None),
        ("ef-prose-pfddn", None),
        ("ef-v2x-cfg", None),
        ("ef-v2x-pre-cfg", None),
        ("ef-v2x-cert", None),
        ("ef-v2x-auth-keys", None),
        ("ef-mcs-root", "6FA0"),
        ("ef-mcptt-cfg", "6FA1"),
        ("ef-mcptt-sip", "6FA2"),
        ("ef-mcs-user-id", "6FA3"),
        ("ef-mcs-app-list", "6FA4"),
        ("ef-mcs-gms", "6FA5"),
        ("ef-mcs-cmsi", "6FA6"),
        ("ef-mcs-media-cfg", "6FA7"),
        ("ef-mcs-pub-id", "6FA8"),
        ("ef-mcs-profile", "6FA9"),
        ("ef-mcs-emergency", "6FAA"),
        ("ef-mcs-keyset", "6FAB"),
        ("ef-mcs-stat", "6FAC"),
        ("ef-mcs-sec-profile", "6FAF"),
    )

    def test_all_specialized_roundtrip(self) -> None:
        for index, (token, fid) in enumerate(self.CASES):
            with self.subTest(token=token):
                raw = bytes([((index * 3) + 1) & 0xFF] * 6)
                self.assertEqual(
                    _roundtrip(
                        ef_key=token, fid=fid, raw=raw, inject_original=True
                    ),
                    raw,
                )

    def test_all_specialized_registered(self) -> None:
        for token, _fid in self.CASES:
            with self.subTest(token=token):
                self.assertIn(token, _EF_CONTENT_DISPATCHER)


# ---------------------------------------------------------------------------
# Pass D — Operator / vendor / auxiliary.


class OperatorCustomTests(unittest.TestCase):
    CASES = (
        ("ef-opcust1", "4F90"),
        ("ef-opcust2", "4F91"),
        ("ef-opcust3", "4F92"),
        ("ef-opcust4", "4F93"),
        ("ef-opcust5", "4F94"),
        ("ef-vendor1", "4F95"),
        ("ef-vendor2", "4F96"),
        ("ef-vendor3", "4F97"),
        ("ef-vendor4", "4F98"),
        ("ef-vendor5", "4F99"),
        ("ef-scp11key", "4F61"),
        ("ef-scp80ctr", "4F62"),
        ("ef-simlock-state", "4F67"),
        ("ef-ota-state", "4F68"),
        ("ef-ota-keys", "4F69"),
        ("ef-provconfig", "4F6A"),
        ("ef-selfservice", "4F6B"),
        ("ef-appconfig", "4F6C"),
        ("ef-acmp", "4F6D"),
        ("ef-tui", "4F6E"),
    )

    def test_all_roundtrip(self) -> None:
        for index, (token, fid) in enumerate(self.CASES):
            with self.subTest(token=token):
                raw = bytes([((index + 7) * 5) & 0xFF] * 4)
                self.assertEqual(
                    _roundtrip(
                        ef_key=token, fid=fid, raw=raw, inject_original=True
                    ),
                    raw,
                )

    def test_all_registered(self) -> None:
        for token, _fid in self.CASES:
            with self.subTest(token=token):
                self.assertIn(token, _EF_CONTENT_DISPATCHER)


# ---------------------------------------------------------------------------
# Integration — registration + hex-hint sweep.


class SweepIntegrationTests(unittest.TestCase):
    def test_dispatcher_total_count(self) -> None:
        # The sweep brings the content dispatcher to at least 200 keys.
        self.assertGreaterEqual(len(_EF_CONTENT_DISPATCHER), 200)

    def test_mbdn_is_lossy_splice(self) -> None:
        self.assertIn("ef-mbdn", _LOSSY_SPLICE_EF_KEYS)

    def test_pass_a_hex_hinted(self) -> None:
        for key in (
            "ef-mwis",
            "ef-mbi",
            "ef-cfis",
            "ef-cfis2",
            "ef-emlpp",
            "ef-aaem",
            "ef-dck",
            "ef-vgcs",
            "ef-vbs",
        ):
            with self.subTest(key=key):
                self.assertIn(key, _HEX_HINTED_EF_KEYS)

    def test_csim_hex_hinted(self) -> None:
        for key in (
            "ef-csim-spc",
            "ef-csim-prl",
            "ef-csim-mdn",
            "ef-csim-meruiid",
        ):
            with self.subTest(key=key):
                self.assertIn(key, _HEX_HINTED_EF_KEYS)

    def test_specialized_hex_hinted(self) -> None:
        for key in (
            "ef-prose-pfidg",
            "ef-v2x-cfg",
            "ef-mcs-root",
            "ef-mcs-sec-profile",
        ):
            with self.subTest(key=key):
                self.assertIn(key, _HEX_HINTED_EF_KEYS)

    def test_operator_custom_hex_hinted(self) -> None:
        for key in (
            "ef-opcust1",
            "ef-vendor5",
            "ef-scp11key",
            "ef-tui",
        ):
            with self.subTest(key=key):
                self.assertIn(key, _HEX_HINTED_EF_KEYS)


if __name__ == "__main__":
    unittest.main()
