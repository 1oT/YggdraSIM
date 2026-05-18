# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for YRL-* rules derived from the TCA Profile Package TS sweep.

Covers: YRL-JCA-004 (TCA APP-004), YRL-SDM-005 (TCA PP-004),
        YRL-PID-003 (TCA PP TS §4.4 / GSMA TS.48 §6),
        YRL-NAA-005 (TCA PP TS §4.4.1 / 3GPP TS 33.102 §6.3),
        YRL-PIN-005 (TCA PIN-007), YRL-PIN-006 (TCA PIN-006),
        YRL-PIN-007 (ETSI TS 102 221 §9.5 Table 9.3 keyReference range),
        YRL-FIL-015 (TCA FS-015), YRL-FIL-024 (TCA FS-024),
        YRL-HDR-005 (TCA SAIP §A.2 — eUICC-Mandatory-AIDs entry shape),
        YRL-HDR-006 (TCA PP TS §3.1 / §A.2 — version coherence +
        iotOptions gating),
        YRL-HDR-007 (TCA SAIP §A.2 — eUICC-Mandatory-GFSTEList OID),
        YRL-HDR-008 (TCA SAIP §A.2 — profileType length),
        YRL-AKA-001 (TUAK 128/256-bit K acceptance, TS 35.231 Annex F),
        YRL-AKA-005 (PE-AKAParameter mappingSource cross-reference,
        TCA PP TS PE-AKAParameter / ISO 7816-5 §8.5),
        YRL-CDMA-001/-002 (3GPP2 C.S0023 §3.4 / GSMA SAIP Annex D),
        YRL-SSIM-001/-002 (PE-SSIM-EAPTLSParameters / RFC 9190),
        YRL-DEP-SNPN-001 / YRL-DEP-5GPROSE-001
        (TCA DF-SNPN-001 / DF-5GPROSE-001),
        YRL-FIL-040/-041/-042/-043 (ETSI TS 102 222 §6.2 / §6.4 /
        §6.10 / TS 102 221 §11.1.1 file-system PE sweep),
        YRL-JCA-005 / YRL-JCI-005 / YRL-RFM-004 / YRL-RAM-004
        (application PE sweep: instance LP linkage, module AID range,
        MSL byte sanity per ETSI TS 102 225 §5.1.1).
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter

_ICCID = "89882012345678901230"
_SD_AID = "A000000003000000"


def _base_header() -> dict:
    return {
        "iccid": {"hex": _ICCID},
        "eUICC-Mandatory-services": {},
        "profileType": "telecom",
        "identification": 0,
        "type": "header",
    }


def _make_doc(**extra_sections: dict) -> dict:
    sections: dict = {
        "header": _base_header(),
        "mf": {"identification": 1, "type": "mf"},
    }
    sections.update(extra_sections)
    sections["end"] = {"identification": 99, "type": "end"}
    return {"sections": sections}


def _sd_pe(identification: int = 2, sd_aid: str = _SD_AID) -> dict:
    return {
        "identification": identification,
        "type": "securityDomain",
        "keyList": [{"keyVersionNumber": 1}],
        "instance": {"instanceAID": sd_aid},
    }


def _usim_pe(identification: int = 5) -> dict:
    return {"identification": identification, "type": "usim"}


def _aka_pe(identification: int = 6) -> dict:
    return {"identification": identification, "type": "akaParameter"}


def _lint(doc: dict) -> list:
    linter = SaipProfileLinter(strict=False)
    report = linter.lint_decoded_document(
        decoded_document=doc,
        profile_label="test.der",
        check_return_code=None,
        check_stderr="",
        emit_missing_check_finding=False,
    )
    return report.findings


def _codes(doc: dict) -> list[str]:
    return [finding.code for finding in _lint(doc)]


class AppEmptyShellTests(unittest.TestCase):
    """YRL-JCA-004: PE-Application must have loadBlock or instanceList (TCA APP-004)."""

    def test_jca004_fires_on_empty_application_pe(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(),
            application={"identification": 10, "type": "application"},
        )
        self.assertIn("YRL-JCA-004", _codes(doc))

    def test_jca004_quiet_with_load_block(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(),
            application={
                "identification": 10,
                "type": "application",
                "loadBlock": {"loadPackageAID": _SD_AID},
            },
        )
        self.assertNotIn("YRL-JCA-004", _codes(doc))

    def test_jca004_quiet_with_instance_list(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(),
            application={
                "identification": 10,
                "type": "application",
                "instanceList": [{"instanceAID": "A000000003000010"}],
            },
        )
        self.assertNotIn("YRL-JCA-004", _codes(doc))


class ExtraditeSecurityDomainTests(unittest.TestCase):
    """YRL-SDM-005: extraditeSecurityDomainAID must resolve to a declared SD (TCA PP-004)."""

    def test_sdm005_fires_on_unknown_extradite_aid(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(sd_aid=_SD_AID),
            application={
                "identification": 10,
                "type": "application",
                "loadBlock": {"loadPackageAID": _SD_AID},
                "instanceList": [
                    {
                        "instanceAID": "A000000003000010",
                        "extraditeSecurityDomainAID": "BBBBBBBBBBBBBBBB",
                    }
                ],
            },
        )
        self.assertIn("YRL-SDM-005", _codes(doc))

    def test_sdm005_quiet_when_extradite_aid_matches(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(sd_aid=_SD_AID),
            application={
                "identification": 10,
                "type": "application",
                "loadBlock": {"loadPackageAID": _SD_AID},
                "instanceList": [
                    {
                        "instanceAID": "A000000003000010",
                        "extraditeSecurityDomainAID": _SD_AID,
                    }
                ],
            },
        )
        self.assertNotIn("YRL-SDM-005", _codes(doc))

    def test_sdm005_accepts_wrapped_hex_dict_form(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(sd_aid=_SD_AID),
            application={
                "identification": 10,
                "type": "application",
                "loadBlock": {"loadPackageAID": _SD_AID},
                "instanceList": [
                    {
                        "instanceAID": {"hex": "A000000003000010"},
                        "extraditeSecurityDomainAID": {"hex": _SD_AID},
                    }
                ],
            },
        )
        self.assertNotIn("YRL-SDM-005", _codes(doc))


class NaaPresenceTests(unittest.TestCase):
    """YRL-PID-003: profile must declare at least one NAA (TCA PP TS §4.4 / GSMA TS.48 §6)."""

    def test_pid003_fires_on_naa_free_profile(self) -> None:
        doc = _make_doc()
        self.assertIn("YRL-PID-003", _codes(doc))

    def test_pid003_quiet_with_usim_pe(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe())
        self.assertNotIn("YRL-PID-003", _codes(doc))


class NaaAkaParameterTests(unittest.TestCase):
    """YRL-NAA-005: each NAA needs an akaParameter PE (TCA PP TS §4.4.1 / 3GPP TS 33.102 §6.3)."""

    def test_naa005_fires_when_usim_has_no_aka(self) -> None:
        doc = _make_doc(usim=_usim_pe())
        self.assertIn("YRL-NAA-005", _codes(doc))

    def test_naa005_quiet_when_aka_param_present(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe())
        self.assertNotIn("YRL-NAA-005", _codes(doc))


class PinUnblockReferenceTests(unittest.TestCase):
    """YRL-PIN-005: PIN unblockingPINReference must match a PE-PUKCodes keyReference (TCA PIN-007)."""

    def _pin_doc(self, unblock_ref: int, *, with_puk_ref: int | None = None) -> dict:
        pin_entries = [
            {
                "keyReference": 1,
                "maxNumOfAttemps-retryNumLeft": 0x33,
                "pinValue": {"hex": "31323334FFFFFFFF"},
                "unblockingPINReference": unblock_ref,
            }
        ]
        sections: dict = {
            "pinCodes": {
                "identification": 3,
                "type": "pinCodes",
                "pinCodes": {"@": ["pinconfig", pin_entries]},
            },
        }
        if with_puk_ref is not None:
            sections["pukCodes"] = {
                "identification": 4,
                "type": "pukCodes",
                "pukCodes": [
                    {
                        "keyReference": with_puk_ref,
                        "maxNumOfAttemps-retryNumLeft": 0xAA,
                        "pukValue": {"hex": "3030303030303030"},
                    }
                ],
            }
        return _make_doc(**sections, usim=_usim_pe(), akaParameter=_aka_pe())

    def test_pin005_fires_when_unblock_pin_has_no_puk(self) -> None:
        doc = self._pin_doc(unblock_ref=1)
        self.assertIn("YRL-PIN-005", _codes(doc))

    def test_pin005_quiet_with_matching_puk_keyref(self) -> None:
        doc = self._pin_doc(unblock_ref=1, with_puk_ref=1)
        self.assertNotIn("YRL-PIN-005", _codes(doc))

    def test_pin005_fires_when_puk_keyref_mismatches(self) -> None:
        doc = self._pin_doc(unblock_ref=1, with_puk_ref=2)
        self.assertIn("YRL-PIN-005", _codes(doc))


class PinRemainingZeroTests(unittest.TestCase):
    """YRL-PIN-006: ships PIN/PUK with remaining-attempts nibble = 0 (TCA PIN-006)."""

    def test_pin006_warns_when_remaining_is_zero(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            pinCodes={
                "identification": 3,
                "type": "pinCodes",
                "pinCodes": {
                    "@": [
                        "pinconfig",
                        [
                            {
                                "keyReference": 1,
                                "maxNumOfAttemps-retryNumLeft": 0x30,
                                "pinValue": {"hex": "31323334FFFFFFFF"},
                            }
                        ],
                    ]
                },
            },
        )
        self.assertIn("YRL-PIN-006", _codes(doc))

    def test_pin006_quiet_when_remaining_equals_max(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            pinCodes={
                "identification": 3,
                "type": "pinCodes",
                "pinCodes": {
                    "@": [
                        "pinconfig",
                        [
                            {
                                "keyReference": 1,
                                "maxNumOfAttemps-retryNumLeft": 0x33,
                                "pinValue": {"hex": "31323334FFFFFFFF"},
                            }
                        ],
                    ]
                },
            },
        )
        self.assertNotIn("YRL-PIN-006", _codes(doc))


class DfDependencyAfterTests(unittest.TestCase):
    """YRL-DEP-SNPN-001 / YRL-DEP-5GPROSE-001: extra DF templates require USIM."""

    def test_dep_snpn_fires_without_usim(self) -> None:
        df_snpn = {"identification": 8, "type": "df-snpn"}
        doc = _make_doc(**{"df-snpn": df_snpn})
        self.assertIn("YRL-DEP-SNPN-001", _codes(doc))

    def test_dep_5gprose_fires_without_usim(self) -> None:
        df_5gprose = {"identification": 9, "type": "df-5gprose"}
        doc = _make_doc(**{"df-5gprose": df_5gprose})
        self.assertIn("YRL-DEP-5GPROSE-001", _codes(doc))

    def test_dep_snpn_quiet_with_usim_first(self) -> None:
        df_snpn = {"identification": 8, "type": "df-snpn"}
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), **{"df-snpn": df_snpn})
        self.assertNotIn("YRL-DEP-SNPN-001", _codes(doc))


class MandatoryAidsShapeTests(unittest.TestCase):
    """YRL-HDR-005: eUICC-Mandatory-AIDs entry must have valid AID + 2-byte version."""

    def _make_header_with_aids(self, aids: list) -> dict:
        header = _base_header()
        header["eUICC-Mandatory-AIDs"] = aids
        doc: dict = {
            "sections": {
                "header": header,
                "mf": {"identification": 1, "type": "mf"},
                "usim": _usim_pe(),
                "akaParameter": _aka_pe(),
                "end": {"identification": 99, "type": "end"},
            }
        }
        return doc

    def test_hdr005_quiet_with_valid_entry(self) -> None:
        doc = self._make_header_with_aids(
            [{"aid": "A0000000871002", "version": "0100"}]
        )
        self.assertNotIn("YRL-HDR-005", _codes(doc))

    def test_hdr005_fires_on_missing_version(self) -> None:
        doc = self._make_header_with_aids([{"aid": "A0000000871002"}])
        self.assertIn("YRL-HDR-005", _codes(doc))

    def test_hdr005_fires_on_short_aid(self) -> None:
        doc = self._make_header_with_aids(
            [{"aid": "A000", "version": "0100"}]
        )
        self.assertIn("YRL-HDR-005", _codes(doc))

    def test_hdr005_fires_on_wrong_length_version(self) -> None:
        doc = self._make_header_with_aids(
            [{"aid": "A0000000871002", "version": "010002"}]
        )
        self.assertIn("YRL-HDR-005", _codes(doc))

    def test_hdr005_warns_on_duplicate_aid(self) -> None:
        doc = self._make_header_with_aids(
            [
                {"aid": "A0000000871002", "version": "0100"},
                {"aid": "A0000000871002", "version": "0100"},
            ]
        )
        self.assertIn("YRL-HDR-005", _codes(doc))


class LinkedFileForbiddenFieldsTests(unittest.TestCase):
    """YRL-FIL-015: linked files cannot also declare size or content fields (TCA FS-015)."""

    def _ef_with_link(self, *, fill: str | None = None, size_hex: str | None = None) -> dict:
        ef: dict = {
            "type": "fillFileContent" if fill else "linkedEF",
            "fileDescriptor": "4221",
            "fileID": "6F07",
            "shortEFID": "07",
            "linkPath": "3F002F00",
        }
        if fill is not None:
            ef["fillFileContent"] = fill
        if size_hex is not None:
            ef["efFileSize"] = size_hex
        return ef

    def test_fil015_quiet_when_linked_file_has_only_linkpath(self) -> None:
        doc = _make_doc(
            usim={
                **_usim_pe(),
                "ef": self._ef_with_link(),
            },
        )
        self.assertNotIn("YRL-FIL-015", _codes(doc))

    def test_fil015_fires_when_linked_file_carries_eFFileSize(self) -> None:
        doc = _make_doc(
            usim={
                **_usim_pe(),
                "ef": self._ef_with_link(size_hex="0010"),
            },
        )
        self.assertIn("YRL-FIL-015", _codes(doc))

    def test_fil015_fires_when_linked_file_carries_fill_content(self) -> None:
        doc = _make_doc(
            usim={
                **_usim_pe(),
                "ef": self._ef_with_link(fill="FFFFFFFF"),
            },
        )
        self.assertIn("YRL-FIL-015", _codes(doc))


class ProfileHeaderVersionTests(unittest.TestCase):
    """YRL-HDR-006: SAIP version pair coherence + iotOptions gating."""

    def _make_doc_with_version(
        self, *, major: int, minor: int, iot_options: dict | None = None
    ) -> dict:
        header = _base_header()
        header["major-version"] = major
        header["minor-version"] = minor
        if iot_options is not None:
            header["iotOptions"] = iot_options
        return {
            "sections": {
                "header": header,
                "mf": {"identification": 1, "type": "mf"},
                "usim": _usim_pe(),
                "akaParameter": _aka_pe(),
                "end": {"identification": 99, "type": "end"},
            }
        }

    def test_hdr006_quiet_for_supported_version(self) -> None:
        doc = self._make_doc_with_version(major=3, minor=2)
        self.assertNotIn("YRL-HDR-006", _codes(doc))

    def test_hdr006_fires_on_unsupported_version(self) -> None:
        doc = self._make_doc_with_version(major=5, minor=7)
        self.assertIn("YRL-HDR-006", _codes(doc))

    def test_hdr006_warns_on_iot_options_pre_v33(self) -> None:
        doc = self._make_doc_with_version(
            major=3, minor=1, iot_options={"pix": {"hex": "0102030405060708090A0B"}}
        )
        self.assertIn("YRL-HDR-006", _codes(doc))

    def test_hdr006_quiet_on_iot_options_v33(self) -> None:
        doc = self._make_doc_with_version(
            major=3, minor=3, iot_options={"pix": {"hex": "0102030405060708090A0B"}}
        )
        self.assertNotIn("YRL-HDR-006", _codes(doc))


class ProfileHeaderGfsteListTests(unittest.TestCase):
    """YRL-HDR-007: eUICC-Mandatory-GFSTEList dotted-OID validity."""

    def _make_doc_with_gfste(self, entries: list) -> dict:
        header = _base_header()
        header["eUICC-Mandatory-GFSTEList"] = entries
        return {
            "sections": {
                "header": header,
                "mf": {"identification": 1, "type": "mf"},
                "usim": _usim_pe(),
                "akaParameter": _aka_pe(),
                "end": {"identification": 99, "type": "end"},
            }
        }

    def test_hdr007_quiet_for_valid_oids(self) -> None:
        doc = self._make_doc_with_gfste(["2.23.143.1.2.3", "1.2.250.1.999"])
        self.assertNotIn("YRL-HDR-007", _codes(doc))

    def test_hdr007_fires_on_non_dotted(self) -> None:
        doc = self._make_doc_with_gfste(["telecom-gfste"])
        self.assertIn("YRL-HDR-007", _codes(doc))

    def test_hdr007_fires_on_leading_zero_component(self) -> None:
        doc = self._make_doc_with_gfste(["2.23.143.01.2"])
        self.assertIn("YRL-HDR-007", _codes(doc))

    def test_hdr007_warns_on_duplicate_oid(self) -> None:
        doc = self._make_doc_with_gfste(["2.23.143.1.2.3", "2.23.143.1.2.3"])
        self.assertIn("YRL-HDR-007", _codes(doc))


class ProfileHeaderProfileTypeTests(unittest.TestCase):
    """YRL-HDR-008: profileType length (TCA SAIP §A.2)."""

    def _doc_with_profile_type(self, profile_type: str) -> dict:
        header = _base_header()
        header["profileType"] = profile_type
        return {
            "sections": {
                "header": header,
                "mf": {"identification": 1, "type": "mf"},
                "usim": _usim_pe(),
                "akaParameter": _aka_pe(),
                "end": {"identification": 99, "type": "end"},
            }
        }

    def test_hdr008_quiet_for_short_text(self) -> None:
        self.assertNotIn("YRL-HDR-008", _codes(self._doc_with_profile_type("telecom")))

    def test_hdr008_warns_on_empty(self) -> None:
        self.assertIn("YRL-HDR-008", _codes(self._doc_with_profile_type("")))

    def test_hdr008_fires_over_100_bytes(self) -> None:
        oversize = "x" * 101
        self.assertIn("YRL-HDR-008", _codes(self._doc_with_profile_type(oversize)))


def _pin_pe(
    *,
    identification: int = 7,
    key_reference: int = 0x01,
    packed_byte: int = 0x33,
    pin_value: str = "3132333435363738",
) -> dict:
    return {
        "identification": identification,
        "type": "pinCodes",
        "pinCodes": {
            "@": [
                "pinconfig",
                [
                    {
                        "keyReference": key_reference,
                        "maxNumOfAttemps-retryNumLeft": packed_byte,
                        "pinValue": {"hex": pin_value},
                    }
                ],
            ]
        },
    }


class PinKeyReferenceRangeTests(unittest.TestCase):
    """YRL-PIN-007: keyReference inside global / local PIN ranges."""

    def test_pin007_quiet_for_global_pin1(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), pinCodes=_pin_pe(key_reference=0x01))
        self.assertNotIn("YRL-PIN-007", _codes(doc))

    def test_pin007_quiet_for_local_app_pin(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), pinCodes=_pin_pe(key_reference=0x81))
        self.assertNotIn("YRL-PIN-007", _codes(doc))

    def test_pin007_fires_on_out_of_range_global(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), pinCodes=_pin_pe(key_reference=0x09))
        self.assertIn("YRL-PIN-007", _codes(doc))

    def test_pin007_fires_on_out_of_range_local(self) -> None:
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), pinCodes=_pin_pe(key_reference=0x90))
        self.assertIn("YRL-PIN-007", _codes(doc))


def _aka_pe_with(
    *,
    identification: int = 6,
    algorithm_id: int = 1,
    key_hex: str = "00112233445566778899AABBCCDDEEFF",
    op_hex: str = "00112233445566778899AABBCCDDEEFF",
    op_field: str = "opc",
    mapping_source: str | None = None,
) -> dict:
    pe: dict = {
        "identification": identification,
        "type": "akaParameter",
        "algoConfiguration": {
            "@": [
                "algoParameter",
                {
                    "algorithmID": algorithm_id,
                    "key": {"hex": key_hex},
                    op_field: {"hex": op_hex},
                },
            ]
        },
    }
    if mapping_source is not None:
        pe["mappingSource"] = {"hex": mapping_source}
    return pe


class AkaTuakKeyWidthTests(unittest.TestCase):
    """YRL-AKA-001: TUAK accepts 128-bit and 256-bit K (TS 35.231 Annex F)."""

    def test_aka001_quiet_for_tuak_128_bit_key(self) -> None:
        pe = _aka_pe_with(
            algorithm_id=2,
            key_hex="00112233445566778899AABBCCDDEEFF",
            op_hex="00112233445566778899AABBCCDDEEFF",
            op_field="topc",
        )
        doc = _make_doc(usim=_usim_pe(), akaParameter=pe)
        self.assertNotIn("YRL-AKA-001", _codes(doc))

    def test_aka001_quiet_for_tuak_256_bit_key(self) -> None:
        long_hex = "00" * 32
        pe = _aka_pe_with(
            algorithm_id=2, key_hex=long_hex, op_hex=long_hex, op_field="topc"
        )
        doc = _make_doc(usim=_usim_pe(), akaParameter=pe)
        self.assertNotIn("YRL-AKA-001", _codes(doc))

    def test_aka001_fires_on_tuak_192_bit_key(self) -> None:
        odd_hex = "00" * 24
        pe = _aka_pe_with(
            algorithm_id=2, key_hex=odd_hex, op_hex=odd_hex, op_field="topc"
        )
        doc = _make_doc(usim=_usim_pe(), akaParameter=pe)
        self.assertIn("YRL-AKA-001", _codes(doc))


class AkaMappingSourceTests(unittest.TestCase):
    """YRL-AKA-005: mappingSource AID must resolve to a NAA in the profile."""

    def test_aka005_quiet_when_mapping_source_resolves(self) -> None:
        usim = {**_usim_pe(), "dfName": {"hex": "A0000000871002"}}
        pe = _aka_pe_with(mapping_source="A0000000871002")
        doc = _make_doc(usim=usim, akaParameter=pe)
        self.assertNotIn("YRL-AKA-005", _codes(doc))

    def test_aka005_fires_when_mapping_source_unknown(self) -> None:
        usim = {**_usim_pe(), "dfName": {"hex": "A0000000871002"}}
        pe = _aka_pe_with(mapping_source="A0000000999999")
        doc = _make_doc(usim=usim, akaParameter=pe)
        self.assertIn("YRL-AKA-005", _codes(doc))


class CdmaParameterTests(unittest.TestCase):
    """YRL-CDMA-001/-002: CDMA authentication material widths."""

    def _cdma_pe(self, **fields) -> dict:
        pe: dict = {"identification": 12, "type": "cdmaParameter"}
        pe.update(fields)
        return pe

    def test_cdma001_quiet_for_8_byte_akey(self) -> None:
        pe = self._cdma_pe(authenticationKey={"hex": "0011223344556677"})
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), cdmaParameter=pe)
        self.assertNotIn("YRL-CDMA-001", _codes(doc))

    def test_cdma001_fires_for_short_akey(self) -> None:
        pe = self._cdma_pe(authenticationKey={"hex": "00112233"})
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), cdmaParameter=pe)
        self.assertIn("YRL-CDMA-001", _codes(doc))

    def test_cdma001_fires_for_wrong_ssd(self) -> None:
        pe = self._cdma_pe(
            authenticationKey={"hex": "0011223344556677"},
            ssd={"hex": "00112233"},
        )
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), cdmaParameter=pe)
        self.assertIn("YRL-CDMA-001", _codes(doc))

    def test_cdma002_warns_on_empty_hrpd_field(self) -> None:
        pe = self._cdma_pe(
            authenticationKey={"hex": "0011223344556677"},
            hrpdAccessAuthenticationData={"hex": ""},
        )
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), cdmaParameter=pe)
        self.assertIn("YRL-CDMA-002", _codes(doc))


class SsimEaptlsParametersTests(unittest.TestCase):
    """YRL-SSIM-001/-002: PE-SSIM-EAPTLSParameters cert / key presence."""

    def _ssim_pe(self, **fields) -> dict:
        pe: dict = {"identification": 14, "type": "ssim-EAPTLSParameters"}
        pe.update(fields)
        return pe

    def test_ssim001_fires_when_required_field_missing(self) -> None:
        pe = self._ssim_pe(
            ssimTLSCert={"hex": "30"},
            ssimTLSPrivateKey={"hex": "30"},
        )
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), **{"ssim-EAPTLSParameters": pe}
        )
        self.assertIn("YRL-SSIM-001", _codes(doc))

    def test_ssim002_fires_when_required_field_empty(self) -> None:
        pe = self._ssim_pe(
            ssimTLSCert={"hex": "30"},
            ssimTLSPrivateKey={"hex": ""},
            serverRootCACert={"hex": "30"},
        )
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), **{"ssim-EAPTLSParameters": pe}
        )
        self.assertIn("YRL-SSIM-002", _codes(doc))

    def test_ssim_quiet_when_all_fields_populated(self) -> None:
        pe = self._ssim_pe(
            ssimTLSCert={"hex": "30"},
            ssimTLSPrivateKey={"hex": "30"},
            serverRootCACert={"hex": "30"},
        )
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), **{"ssim-EAPTLSParameters": pe}
        )
        codes = _codes(doc)
        self.assertNotIn("YRL-SSIM-001", codes)
        self.assertNotIn("YRL-SSIM-002", codes)


class FileDescriptorKindTests(unittest.TestCase):
    """YRL-FIL-040: fileDescriptor byte 0 must match the file class."""

    def _doc_with_node(self, *, kind: str, descriptor: str) -> dict:
        node = {
            "fileDescriptor": descriptor,
            "fileID": "6F07" if kind == "ef" else None,
        }
        node = {k: v for k, v in node.items() if v is not None}
        if kind == "adf":
            node["dfName"] = "A0000000871002"
        usim = {**_usim_pe(), kind: node}
        return _make_doc(usim=usim, akaParameter=_aka_pe())

    def test_fil040_quiet_for_adf_38(self) -> None:
        self.assertNotIn(
            "YRL-FIL-040", _codes(self._doc_with_node(kind="adf", descriptor="3800"))
        )

    def test_fil040_fires_on_adf_with_ef_descriptor(self) -> None:
        self.assertIn(
            "YRL-FIL-040", _codes(self._doc_with_node(kind="adf", descriptor="4100"))
        )

    def test_fil040_fires_on_ef_with_df_descriptor(self) -> None:
        self.assertIn(
            "YRL-FIL-040", _codes(self._doc_with_node(kind="ef", descriptor="3800"))
        )

    def test_fil040_quiet_for_transparent_ef(self) -> None:
        self.assertNotIn(
            "YRL-FIL-040", _codes(self._doc_with_node(kind="ef", descriptor="4221"))
        )


class LifeCycleStatusTests(unittest.TestCase):
    """YRL-FIL-041: lifeCycleStatus must use registered values."""

    def _doc_with_lcs(self, lcs: str) -> dict:
        ef = {"fileDescriptor": "4221", "fileID": "6F07", "lifeCycleStatus": lcs}
        usim = {**_usim_pe(), "ef": ef}
        return _make_doc(usim=usim, akaParameter=_aka_pe())

    def test_fil041_quiet_for_operational_activated(self) -> None:
        self.assertNotIn("YRL-FIL-041", _codes(self._doc_with_lcs("05")))

    def test_fil041_warns_on_unregistered_byte(self) -> None:
        self.assertIn("YRL-FIL-041", _codes(self._doc_with_lcs("AA")))


class SecurityAttributesMutexTests(unittest.TestCase):
    """YRL-FIL-042: securityAttributesReferenced and Compact are mutex."""

    def test_fil042_fires_when_both_present(self) -> None:
        ef = {
            "fileDescriptor": "4221",
            "fileID": "6F07",
            "securityAttributesReferenced": "0102",
            "securityAttributesCompact": "AABB",
        }
        usim = {**_usim_pe(), "ef": ef}
        doc = _make_doc(usim=usim, akaParameter=_aka_pe())
        self.assertIn("YRL-FIL-042", _codes(doc))

    def test_fil042_quiet_when_only_one_form_present(self) -> None:
        ef = {
            "fileDescriptor": "4221",
            "fileID": "6F07",
            "securityAttributesReferenced": "0102",
        }
        usim = {**_usim_pe(), "ef": ef}
        doc = _make_doc(usim=usim, akaParameter=_aka_pe())
        self.assertNotIn("YRL-FIL-042", _codes(doc))


class DfNamePlacementTests(unittest.TestCase):
    """YRL-FIL-043: dfName placement (ADF only) and AID range."""

    def test_fil043_fires_on_ef_with_dfname(self) -> None:
        ef = {
            "fileDescriptor": "4221",
            "fileID": "6F07",
            "dfName": "A0000000871002",
        }
        usim = {**_usim_pe(), "ef": ef}
        doc = _make_doc(usim=usim, akaParameter=_aka_pe())
        self.assertIn("YRL-FIL-043", _codes(doc))

    def test_fil043_warns_on_short_adf_aid(self) -> None:
        adf = {"fileDescriptor": "38", "dfName": "A000"}
        usim = {**_usim_pe(), "adf": adf}
        doc = _make_doc(usim=usim, akaParameter=_aka_pe())
        self.assertIn("YRL-FIL-043", _codes(doc))


class ApplicationInstanceLoadPackageRefTests(unittest.TestCase):
    """YRL-JCA-005: instance applicationLoadPackageAID must reference a known load package."""

    def test_jca005_quiet_when_instance_matches_parent_load(self) -> None:
        app = {
            "identification": 30,
            "type": "application",
            "loadBlock": {
                "loadPackageAID": "AABBCCDDEE",
                "securityDomainAID": _SD_AID,
            },
            "instanceList": [
                {
                    "instanceAID": "AABBCCDDEE01",
                    "applicationLoadPackageAID": "AABBCCDDEE",
                }
            ],
        }
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(),
            application=app,
        )
        self.assertNotIn("YRL-JCA-005", _codes(doc))

    def test_jca005_fires_when_instance_references_unknown_package(self) -> None:
        app = {
            "identification": 30,
            "type": "application",
            "instanceList": [
                {
                    "instanceAID": "11223344556677",
                    "applicationLoadPackageAID": "99887766",
                }
            ],
        }
        doc = _make_doc(
            usim=_usim_pe(),
            akaParameter=_aka_pe(),
            securityDomain=_sd_pe(),
            application=app,
        )
        self.assertIn("YRL-JCA-005", _codes(doc))


class ApplicationModuleAidRangeTests(unittest.TestCase):
    """YRL-JCI-005: applicationModuleAID must be 5..16 bytes."""

    def test_jci005_quiet_for_valid_module_aid(self) -> None:
        app = {
            "identification": 31,
            "type": "application",
            "loadBlock": {"loadPackageAID": "AABBCCDDEE"},
            "instanceList": [
                {
                    "instanceAID": "AABBCCDDEE01",
                    "applicationLoadPackageAID": "AABBCCDDEE",
                    "applicationModule": [
                        {"applicationModuleAID": "AABBCCDDEEFF"}
                    ],
                }
            ],
        }
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), application=app)
        self.assertNotIn("YRL-JCI-005", _codes(doc))

    def test_jci005_fires_for_short_module_aid(self) -> None:
        app = {
            "identification": 32,
            "type": "application",
            "loadBlock": {"loadPackageAID": "AABBCCDDEE"},
            "instanceList": [
                {
                    "instanceAID": "AABBCCDDEE01",
                    "applicationLoadPackageAID": "AABBCCDDEE",
                    "applicationModule": [
                        {"applicationModuleAID": "AABB"}
                    ],
                }
            ],
        }
        doc = _make_doc(usim=_usim_pe(), akaParameter=_aka_pe(), application=app)
        self.assertIn("YRL-JCI-005", _codes(doc))


class RfmMinimumSecurityLevelTests(unittest.TestCase):
    """YRL-RFM-004: SPI MSL must be 1 byte and not 0x00."""

    def _rfm_pe_with_msl(self, msl_hex: str | None) -> dict:
        pe: dict = {
            "identification": 33,
            "type": "rfm",
            "tarList": [{"hex": "AABBCC"}],
            "keyReference": {"hex": "01"},
        }
        if msl_hex is not None:
            pe["minimumSecurityLevel"] = {"hex": msl_hex}
        return pe

    def test_rfm004_warns_on_zero_msl(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), rfm=self._rfm_pe_with_msl("00")
        )
        self.assertIn("YRL-RFM-004", _codes(doc))

    def test_rfm004_warns_on_multi_byte_msl(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), rfm=self._rfm_pe_with_msl("0102")
        )
        self.assertIn("YRL-RFM-004", _codes(doc))

    def test_rfm004_quiet_on_signed_ciphered_msl(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), rfm=self._rfm_pe_with_msl("16")
        )
        self.assertNotIn("YRL-RFM-004", _codes(doc))


class RamMinimumSecurityLevelTests(unittest.TestCase):
    """YRL-RAM-004: SPI MSL on RAM PE must be 1 byte and not 0x00."""

    def _ram_pe_with_msl(self, msl_hex: str | None) -> dict:
        pe: dict = {
            "identification": 34,
            "type": "ram",
            "securityDomainAID": _SD_AID,
        }
        if msl_hex is not None:
            pe["minimumSecurityLevel"] = {"hex": msl_hex}
        return pe

    def test_ram004_warns_on_zero_msl(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), ram=self._ram_pe_with_msl("00")
        )
        self.assertIn("YRL-RAM-004", _codes(doc))

    def test_ram004_quiet_on_signed_msl(self) -> None:
        doc = _make_doc(
            usim=_usim_pe(), akaParameter=_aka_pe(), ram=self._ram_pe_with_msl("12")
        )
        self.assertNotIn("YRL-RAM-004", _codes(doc))


if __name__ == "__main__":
    unittest.main()
