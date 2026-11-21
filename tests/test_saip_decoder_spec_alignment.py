# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Decoders that had drifted from the structure their spec reference defines.

The vectors are pySim's own ``_test_de_encode`` entries for the same files, so
a divergence here is a divergence from the reference implementation the repo
already treats as authoritative.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import encode_decoded_roundtrip_ef_content


def _decode(token: str, fid: str, hex_clean: str) -> dict:
    decoded = _decode_known_ef_payload(ef_key=token, fid=fid, hex_clean=hex_clean)
    if not isinstance(decoded, dict):
        raise AssertionError(f"{token} did not decode {hex_clean}")
    return decoded


class EfUmpcTests(unittest.TestCase):
    """EF.UMPC is the 5-byte ETSI file at 2F08, not a 2-byte record.

    ETSI TS 102 221 §13.6; pySim ``ts_102_221.EF_UMPC`` reads byte 2 as
    seconds and byte 3 as the additional-information flags. The 5-byte size
    matches ``SCP03/logic/profile_validator.py``.
    """

    def test_pysim_vector_with_suspend_support(self) -> None:
        decoded = _decode("ef-umpc", "2F08", "3CFF02")
        self.assertEqual(decoded["maxCurrentMilliAmps"], 60)
        self.assertEqual(decoded["tOpSeconds"], 255)
        self.assertTrue(decoded["supportsUiccSuspend"])
        self.assertFalse(decoded["requiresIncreasedIdleCurrent"])

    def test_pysim_vector_without_flags(self) -> None:
        decoded = _decode("ef-umpc", "2F08", "320500")
        self.assertEqual(decoded["maxCurrentMilliAmps"], 50)
        self.assertEqual(decoded["tOpSeconds"], 5)
        self.assertFalse(decoded["supportsUiccSuspend"])

    def test_full_file_length_decodes(self) -> None:
        decoded = _decode("ef-umpc", "2F08", "1414000000")
        self.assertEqual(decoded["length"], 5)
        self.assertEqual(decoded["rfuHex"], "0000")

    def test_undefined_max_current_is_reported_as_such(self) -> None:
        decoded = _decode("ef-umpc", "2F08", "FF05")
        self.assertIsNone(decoded["maxCurrentMilliAmps"])
        self.assertIn("undefined", decoded["summary"])

    def test_content_longer_than_the_file_is_refused(self) -> None:
        self.assertIsNone(
            _decode_known_ef_payload(
                ef_key="ef-umpc", fid="2F08", hex_clean="00" * 6
            )
        )


class EfUacAicTests(unittest.TestCase):
    """EF.UAC_AIC byte 1 names two access identities, it is not a free bitmap.

    TS 31.102 §4.4.11.7: b1 Multimedia Priority Service, b2 Mission Critical
    Service, everything else RFU. ``SCP03/core/decoders.py`` and pySim's
    ``ts_31_102.EF_UAC_AIC`` read it the same way.
    """

    def test_pysim_vector_names_both_services(self) -> None:
        decoded = _decode("ef-uac-aic", "4F06", "03")
        self.assertTrue(decoded["multimediaPriorityService"])
        self.assertTrue(decoded["missionCriticalService"])

    def test_only_mps(self) -> None:
        decoded = _decode("ef-uac-aic", "4F06", "01000000")
        self.assertTrue(decoded["multimediaPriorityService"])
        self.assertFalse(decoded["missionCriticalService"])

    def test_nothing_configured(self) -> None:
        decoded = _decode("ef-uac-aic", "4F06", "00000000")
        self.assertEqual(decoded["summary"], "no access identity configured")
        self.assertNotIn("reservedBitsSet", decoded)

    def test_reserved_bits_are_surfaced(self) -> None:
        decoded = _decode("ef-uac-aic", "4F06", "0C000000")
        self.assertTrue(decoded["reservedBitsSet"])
        self.assertEqual(decoded["reservedBitsHex"], "0C000000")

    def test_every_accepted_length_roundtrips(self) -> None:
        for record in ("03", "0300", "030000", "03000000"):
            with self.subTest(record=record):
                decoded = _decode("ef-uac-aic", "4F06", record)
                encoded = encode_decoded_roundtrip_ef_content(
                    "ef-uac-aic", decoded, target_length=len(record) // 2
                )
                self.assertEqual(encoded.hex().upper(), record)


class EfKeyOutranksFileIdentifierTests(unittest.TestCase):
    """4F01..4F09 are reused across eight DFs, so a FID names no single file.

    The dispatcher matches a branch on either the EF key or the identifier,
    and whichever branch came first answered for every file sharing that
    identifier. Each of these decoded as an unrelated DF.5GS file before.
    """

    # token -> (fid, the format its own decoder must produce)
    _COLLIDING = {
        "ef-5g-prose-st": ("4F01", "5G ProSe Service Table"),
        "ef-prose-mon": ("4F01", "ProSe Monitoring Parameters"),
        "ef-vst": ("4F01", "V2X Service Table"),
        "ef-mst": ("4F01", "MCS Service Table"),
        "ef-ast": ("4F01", "A2X Service Table"),
        "ef-eapkeys": ("4F01", "EAP Keys"),
        "ef-v2x-config": ("4F02", "V2X Configuration"),
        "ef-mcs-config": ("4F02", "MCS Configuration"),
        "ef-a2x-config": ("4F02", "A2X Configuration"),
        "ef-eapstatus": ("4F02", "EAP Status"),
        "ef-prosefunc": ("4F03", "HPLMN ProSe Function"),
        "ef-prose-radio-com": ("4F04", "ProSe Direct Communication Radio Parameters"),
        "ef-prose-radio-mon": ("4F05", "ProSe Direct Discovery Monitoring Radio Parameters"),
        "ef-prose-radio-ann": ("4F06", "ProSe Direct Discovery Announcing Radio Parameters"),
        "ef-pbc": ("4F09", "Phonebook Control"),
    }

    def test_key_wins_over_a_colliding_identifier(self) -> None:
        for token, (fid, expected) in self._COLLIDING.items():
            with self.subTest(token=token):
                decoded = None
                for probe in ("03", "800101", "0102030405"):
                    decoded = _decode_known_ef_payload(
                        ef_key=token, fid=fid, hex_clean=probe
                    )
                    if isinstance(decoded, dict):
                        break
                self.assertIsInstance(decoded, dict, f"{token} did not decode")
                self.assertEqual(decoded.get("format"), expected)

    def test_identifier_alone_still_resolves(self) -> None:
        # Callers that know only a FID keep the old behaviour.
        decoded = _decode_known_ef_payload(
            ef_key=None, fid="2FE2", hex_clean="98" + "88" * 9
        )
        self.assertIsInstance(decoded, dict)

    def test_a_declining_key_does_not_inherit_a_neighbours_name(self) -> None:
        # These four have a branch that rejects this content. Before, the
        # colliding identifier answered and the record was labelled as a
        # DF.5GS file it is not.
        for token, fid in (
            ("ef-5gs3gpploci", "4F01"),
            ("ef-eapstatus", "4F02"),
            ("ef-nid", "4F02"),
            ("ef-pws-snpn", "4F01"),
        ):
            with self.subTest(token=token):
                self.assertIsNone(
                    _decode_known_ef_payload(
                        ef_key=token, fid=fid, hex_clean="0102030405060708"
                    )
                )

    def test_identifier_still_answers_for_an_unrecognised_key(self) -> None:
        # A key the dispatcher does not know must not suppress the identifier.
        decoded = _decode_known_ef_payload(
            ef_key="ef-not-a-real-token", fid="2FE2", hex_clean="98" + "88" * 9
        )
        self.assertIsInstance(decoded, dict)


class AddressOctetAndLociByteTests(unittest.TestCase):
    """Two fields the decoders read but never reported.

    The TS 24.008 §10.5.4.7 address octet was surfaced as a bare hex byte by
    the EF.ADN and EF.MSISDN record decoders, although the naming tables
    already existed for the SMSC address. EF.LOCI never read byte 10 at all.
    """

    @staticmethod
    def _adn_record(ton_npi: str) -> str:
        """alpha(10) + len(1) + TON/NPI(1) + digits(10) + CCP(1) + EXT(1)."""
        return "FF" * 10 + "06" + ton_npi + "21436587" + "FF" * 6 + "FF" + "FF"

    def test_international_isdn_is_named(self) -> None:
        # 0x91: extension bit set, TON 1 (international), NPI 1 (E.164).
        decoded = _decode("ef-adn", "6F3A", self._adn_record("91"))
        self.assertEqual(decoded["tonNpi"], "0x91")
        self.assertEqual(decoded["ton"], "International")
        self.assertEqual(decoded["npi"], "ISDN/Telephony (E.164/E.163)")

    def test_national_isdn_is_named(self) -> None:
        # 0xA1: TON 2 (national), NPI 1 (E.164).
        decoded = _decode("ef-adn", "6F3A", self._adn_record("A1"))
        self.assertEqual(decoded["ton"], "National")
        self.assertEqual(decoded["npi"], "ISDN/Telephony (E.164/E.163)")

    def test_smsc_address_still_names_the_octet(self) -> None:
        from Tools.ProfilePackage.saip_asn1_decode import _decode_smsc_address

        decoded = _decode_smsc_address(bytes.fromhex("911234"))
        self.assertEqual(decoded["ton"], "International")
        self.assertEqual(decoded["npi"], "ISDN/Telephony (E.164/E.163)")

    def test_loci_reports_byte_ten(self) -> None:
        # pySim ts_31_102.EF_LOCI vector: byte 10 carries 0x1E.
        decoded = _decode("ef-loci", "6F7E", "47D1264A62F21037211E00")
        self.assertEqual(decoded["tmsiTime"], "0x1E")
        self.assertEqual(decoded["status"], "Updated")

    def test_loci_still_reports_the_other_fields(self) -> None:
        decoded = _decode("ef-loci", "6F7E", "47D1264A62F21037211E00")
        self.assertEqual(decoded["tmsi"], "47D1264A")
        self.assertEqual(decoded["lac"], "3721")


if __name__ == "__main__":
    unittest.main()
