# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for advanced file, AKA, APDU, service, and tool-check lint rules.

Covers: YRL-AKA-003, YRL-APD-001..003, YRL-CHK-001/002, YRL-DEP-5GS,
        YRL-FIL-012..014/016/023/027/028/029/031/032/035/037/038/067,
        YRL-HEX-001, YRL-IMS-007, YRL-N5G-001, YRL-SVC-010..012,
        YRL-UCR-001.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter

# ---------------------------------------------------------------------------
# Minimal document helpers
# ---------------------------------------------------------------------------

_ICCID = "89882012345678901230"


def _base_sections(extra: dict | None = None) -> dict:
    sections: dict = {
        "header": {
            "iccid": {"hex": _ICCID},
            "eUICC-Mandatory-services": {},
            "profileType": "telecom",
            "identification": 0,
            "type": "header",
        },
        "mf": {"identification": 1, "type": "mf"},
    }
    if extra:
        sections.update(extra)
    sections["end"] = {"identification": 99, "type": "end"}
    return sections


def _make_doc(extra: dict | None = None) -> dict:
    return {"sections": _base_sections(extra)}


def _gfm_cmd(**fcp_fields) -> dict:
    fcp: dict = {}
    for k, v in fcp_fields.items():
        fcp[k] = {"hex": v} if isinstance(v, str) else v
    return {"@": ["createFCP", fcp]}


def _gfm_section(*cmds: dict, identification: int = 20) -> dict:
    return {
        "identification": identification,
        "type": "genericFileManagement",
        "file": {"fileManagementCMD": list(cmds)},
    }


def _lint(
    doc: dict,
    *,
    check_return_code: int | None = None,
    check_stderr: str = "",
    emit_missing: bool = False,
) -> list:
    linter = SaipProfileLinter(strict=False)
    report = linter.lint_decoded_document(
        decoded_document=doc,
        profile_label="test.der",
        check_return_code=check_return_code,
        check_stderr=check_stderr,
        emit_missing_check_finding=emit_missing,
    )
    return report.findings


def _codes(doc: dict, **kw) -> list[str]:
    return [f.code for f in _lint(doc, **kw)]


# ---------------------------------------------------------------------------
# YRL-CHK-001 / YRL-CHK-002 — saip-tool check result
# ---------------------------------------------------------------------------

class ToolCheckResultTests(unittest.TestCase):
    """YRL-CHK-001: result not provided. YRL-CHK-002: non-zero exit."""

    def test_chk001_no_result_provided(self) -> None:
        codes = _codes(_make_doc(), emit_missing=True)
        self.assertIn("YRL-CHK-001", codes)

    def test_chk001_suppressed_when_flag_off(self) -> None:
        codes = _codes(_make_doc(), emit_missing=False)
        self.assertNotIn("YRL-CHK-001", codes)

    def test_chk002_nonzero_exit(self) -> None:
        codes = _codes(
            _make_doc(),
            check_return_code=1,
            check_stderr="integrity check failed",
        )
        self.assertIn("YRL-CHK-002", codes)

    def test_chk002_zero_exit_passes(self) -> None:
        codes = _codes(_make_doc(), check_return_code=0)
        self.assertNotIn("YRL-CHK-002", codes)


# ---------------------------------------------------------------------------
# YRL-IMS-007 — short but valid IMSI (6..14 digits)
# ---------------------------------------------------------------------------

class ImsiShortTests(unittest.TestCase):
    """YRL-IMS-007: IMSI carries fewer than 15 digits (INFO, not FAIL)."""

    def _doc_with_imsi(self, imsi_hex: str) -> dict:
        return _make_doc({
            "usim": {
                "identification": 10,
                "type": "usim",
                "choices": [{
                    "ef-imsi": {
                        "file": {"fileManagementCMD": [{
                            "@": ["createFCP", {"fillFileContent": {"hex": imsi_hex}}]
                        }]}
                    }
                }],
            }
        })

    def test_ims007_12_digit_imsi(self) -> None:
        # 12-digit IMSI (even count -> parity nibble 0x9), padded to 9 bytes.
        # digits: 001010000001, parity byte: (0<<4)|0x9=0x09
        # body: 09 10 10 00 00 00 F1 FF (pad 0xFF to fill 8 body bytes)
        codes = _codes(self._doc_with_imsi("08091010000000f1ff"))
        self.assertIn("YRL-IMS-007", codes)

    def test_ims007_not_triggered_for_15_digit_imsi(self) -> None:
        # 15-digit valid IMSI (odd -> parity 0x1)
        codes = _codes(self._doc_with_imsi("080110100000000010"))
        self.assertNotIn("YRL-IMS-007", codes)


# ---------------------------------------------------------------------------
# YRL-N5G-001 — df-5gs without usim
# ---------------------------------------------------------------------------

class FiveGsWithoutUsimTests(unittest.TestCase):
    """YRL-N5G-001: DF-5GS present without USIM PE."""

    def test_n5g001_df5gs_without_usim(self) -> None:
        doc = _make_doc({"df-5gs": {"identification": 5, "type": "df-5gs"}})
        codes = _codes(doc)
        self.assertIn("YRL-N5G-001", codes)

    def test_n5g001_not_triggered_when_usim_present(self) -> None:
        doc = _make_doc({
            "usim": {"identification": 5, "type": "usim"},
            "df-5gs": {"identification": 6, "type": "df-5gs"},
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-N5G-001", codes)


# ---------------------------------------------------------------------------
# YRL-SVC-010/011/012 — mandatory service without matching PE
# ---------------------------------------------------------------------------

class MandatoryServicePeTests(unittest.TestCase):
    """YRL-SVC-010..012: service flag requires USIM/ISIM PE."""

    def _doc_with_service(self, service_name: str) -> dict:
        return {
            "sections": {
                "header": {
                    "iccid": {"hex": _ICCID},
                    "eUICC-Mandatory-services": {service_name: None},
                    "profileType": "telecom",
                    "identification": 0,
                    "type": "header",
                },
                "mf": {"identification": 1, "type": "mf"},
                "end": {"identification": 99, "type": "end"},
            }
        }

    def test_svc010_get_identity_without_usim_or_isim(self) -> None:
        codes = _codes(self._doc_with_service("get-identity"))
        self.assertIn("YRL-SVC-010", codes)

    def test_svc011_profile_a_x25519_without_usim_or_isim(self) -> None:
        codes = _codes(self._doc_with_service("profile-a-x25519"))
        self.assertIn("YRL-SVC-011", codes)

    def test_svc012_profile_a_p256_without_usim_or_isim(self) -> None:
        codes = _codes(self._doc_with_service("profile-a-p256"))
        self.assertIn("YRL-SVC-012", codes)

    def test_svc010_not_triggered_when_usim_present(self) -> None:
        doc = {
            "sections": {
                "header": {
                    "iccid": {"hex": _ICCID},
                    "eUICC-Mandatory-services": {"get-identity": None},
                    "profileType": "telecom",
                    "identification": 0,
                    "type": "header",
                },
                "mf": {"identification": 1, "type": "mf"},
                "usim": {"identification": 5, "type": "usim"},
                "end": {"identification": 99, "type": "end"},
            }
        }
        codes = _codes(doc)
        self.assertNotIn("YRL-SVC-010", codes)


# ---------------------------------------------------------------------------
# YRL-UCR-001 — USIM missing ef-imsi or ef-ust marker
# ---------------------------------------------------------------------------

class UsimCoreRequirementsTests(unittest.TestCase):
    """YRL-UCR-001: required USIM marker absent from decoded payload."""

    def test_ucr001_ef_imsi_absent(self) -> None:
        doc = _make_doc({"usim": {"identification": 5, "type": "usim", "choices": []}})
        codes = _codes(doc)
        self.assertIn("YRL-UCR-001", codes)

    def test_ucr001_not_triggered_when_markers_present(self) -> None:
        doc = _make_doc({
            "usim": {
                "identification": 5,
                "type": "usim",
                "choices": [
                    {"ef-imsi": {}},
                    {"ef-ust": {}},
                ],
            }
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-UCR-001", codes)


# ---------------------------------------------------------------------------
# YRL-APD-001/002/003 — APDU field encoding
# ---------------------------------------------------------------------------

class ApduFieldTests(unittest.TestCase):
    """YRL-APD-001..003: APDU field not string / not hex / too short."""

    def _doc_with_apdu(self, apdu_value) -> dict:
        return _make_doc({
            "rfm": {
                "identification": 5,
                "type": "rfm",
                "apduScriptCommands": apdu_value,
            }
        })

    def test_apd001_non_string_apdu(self) -> None:
        codes = _codes(self._doc_with_apdu(12345))
        self.assertIn("YRL-APD-001", codes)

    def test_apd002_non_hex_string(self) -> None:
        codes = _codes(self._doc_with_apdu("not-valid-hex!!"))
        self.assertIn("YRL-APD-002", codes)

    def test_apd003_hex_too_short(self) -> None:
        # 3 bytes = 6 hex chars, minimum is 4 bytes (CLA+INS+P1+P2)
        codes = _codes(self._doc_with_apdu("004100"))
        self.assertIn("YRL-APD-003", codes)

    def test_apd_valid_apdu_passes(self) -> None:
        # 5 bytes: CLA INS P1 P2 Lc
        codes = _codes(self._doc_with_apdu("0004000000"))
        self.assertNotIn("YRL-APD-001", codes)
        self.assertNotIn("YRL-APD-002", codes)
        self.assertNotIn("YRL-APD-003", codes)


# ---------------------------------------------------------------------------
# YRL-HEX-001 — oversized hex field
# ---------------------------------------------------------------------------

class LargeHexFieldTests(unittest.TestCase):
    """YRL-HEX-001: hex string exceeds 2048 bytes (4096 nibbles)."""

    def test_hex001_oversized_field(self) -> None:
        # 2049-byte hex string (4098 nibbles) in a plain string field
        big_hex = "AB" * 2049
        doc = _make_doc({
            "rfm": {
                "identification": 5,
                "type": "rfm",
                "rawPayload": big_hex,
            }
        })
        codes = _codes(doc)
        self.assertIn("YRL-HEX-001", codes)

    def test_hex001_not_triggered_for_small_field(self) -> None:
        small_hex = "AB" * 10
        doc = _make_doc({
            "rfm": {
                "identification": 5,
                "type": "rfm",
                "rawPayload": small_hex,
            }
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-HEX-001", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-012 — securityAttributesReferenced bad length
# ---------------------------------------------------------------------------

class SecurityAttrRefTests(unittest.TestCase):
    """YRL-FIL-012: securityAttributesReferenced non-hex or wrong length."""

    def _gfm_with_sec_attr(self, value: str) -> dict:
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "securityAttributesReferenced": {"hex": value},
        }
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil012_too_long(self) -> None:
        # 4 bytes — max is 3
        codes = _codes(self._gfm_with_sec_attr("01020304"))
        self.assertIn("YRL-FIL-012", codes)

    def test_fil012_valid_passes(self) -> None:
        codes = _codes(self._gfm_with_sec_attr("01"))
        self.assertNotIn("YRL-FIL-012", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-013 / YRL-FIL-014 / YRL-FIL-016 — efFileSize checks
# ---------------------------------------------------------------------------

class EfFileSizeTests(unittest.TestCase):
    """YRL-FIL-013: size > 65535. YRL-FIL-014: leading zero. YRL-FIL-016: non-hex."""

    def _gfm_with_size(self, size_hex: str) -> dict:
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "efFileSize": {"hex": size_hex},
        }
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil013_size_exceeds_65535(self) -> None:
        # 0x010000 = 65536
        codes = _codes(self._gfm_with_size("010000"))
        self.assertIn("YRL-FIL-013", codes)

    def test_fil014_leading_zero(self) -> None:
        # 0x0009 = 9, but has a leading zero octet
        codes = _codes(self._gfm_with_size("0009"))
        self.assertIn("YRL-FIL-014", codes)

    def test_fil016_non_hex(self) -> None:
        codes = _codes(self._gfm_with_size("ZZZZ"))
        self.assertIn("YRL-FIL-016", codes)

    def test_valid_size_passes(self) -> None:
        codes = _codes(self._gfm_with_size("09"))
        self.assertNotIn("YRL-FIL-013", codes)
        self.assertNotIn("YRL-FIL-014", codes)
        self.assertNotIn("YRL-FIL-016", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-023 / YRL-FIL-037 — linkPath checks
# ---------------------------------------------------------------------------

class LinkPathTests(unittest.TestCase):
    """YRL-FIL-023: non-hex linkPath. YRL-FIL-037: linkPath > 8 bytes."""

    def _gfm_with_link(self, link_path_hex: str) -> dict:
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "linkPath": {"hex": link_path_hex},
        }
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil023_non_hex_link_path(self) -> None:
        codes = _codes(self._gfm_with_link("XXYY"))
        self.assertIn("YRL-FIL-023", codes)

    def test_fil037_link_path_too_long(self) -> None:
        # 9 bytes > 8 byte limit
        codes = _codes(self._gfm_with_link("3F007FFF6F070000000000"))
        # Note: 11 hex chars is odd, so use 18 hex chars = 9 bytes
        codes = _codes(self._gfm_with_link("3F007FFF6F07000000"))
        self.assertIn("YRL-FIL-037", codes)

    def test_valid_link_path_passes(self) -> None:
        codes = _codes(self._gfm_with_link("3F006F07"))
        self.assertNotIn("YRL-FIL-023", codes)
        self.assertNotIn("YRL-FIL-037", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-027 — duplicate shortEFID within same scope
# ---------------------------------------------------------------------------

class ShortEfidDuplicateTests(unittest.TestCase):
    """YRL-FIL-027: duplicate shortEFID in same DF/ADF scope."""

    def test_fil027_duplicate_short_efid(self) -> None:
        cmd1 = {"@": ["createFCP", {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "shortEFID": {"hex": "08"},
        }]}
        cmd2 = {"@": ["createFCP", {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F08"},
            "shortEFID": {"hex": "08"},
        }]}
        doc = _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [cmd1, cmd2]},
            }
        })
        codes = _codes(doc)
        self.assertIn("YRL-FIL-027", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-031 / YRL-FIL-032 — maximumFileSize checks
# ---------------------------------------------------------------------------

class MaxFileSizeTests(unittest.TestCase):
    """YRL-FIL-031: non-hex maximumFileSize. YRL-FIL-032: leading zero."""

    def _gfm_with_max(self, max_hex: str) -> dict:
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "maximumFileSize": {"hex": max_hex},
        }
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil031_non_hex(self) -> None:
        codes = _codes(self._gfm_with_max("ZZZZ"))
        self.assertIn("YRL-FIL-031", codes)

    def test_fil032_leading_zero(self) -> None:
        codes = _codes(self._gfm_with_max("0009"))
        self.assertIn("YRL-FIL-032", codes)

    def test_valid_max_passes(self) -> None:
        codes = _codes(self._gfm_with_max("09"))
        self.assertNotIn("YRL-FIL-031", codes)
        self.assertNotIn("YRL-FIL-032", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-035 — fileDetails bad encoding
# ---------------------------------------------------------------------------

class FileDetailsTests(unittest.TestCase):
    """YRL-FIL-035: fileDetails non-hex or wrong length."""

    def _gfm_with_details(self, details_hex: str) -> dict:
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "fileDetails": {"hex": details_hex},
        }
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil035_non_hex(self) -> None:
        codes = _codes(self._gfm_with_details("ZZ"))
        self.assertIn("YRL-FIL-035", codes)

    def test_fil035_wrong_length(self) -> None:
        # 2 octets instead of 1
        codes = _codes(self._gfm_with_details("0001"))
        self.assertIn("YRL-FIL-035", codes)

    def test_valid_file_details_passes(self) -> None:
        codes = _codes(self._gfm_with_details("01"))
        self.assertNotIn("YRL-FIL-035", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-067 — efFileSize not multiple of record length
# ---------------------------------------------------------------------------

class RecordLengthAlignmentTests(unittest.TestCase):
    """YRL-FIL-067: efFileSize not multiple of recordLength for linear-fixed EF."""

    def test_fil067_size_not_multiple_of_record_length(self) -> None:
        # 4-byte fileDescriptor: type=linear-fixed(0x42), DF indicator,
        # max record count=5, record length=10 -> size=53 is not a multiple of 10
        # fileDescriptor format: type 0x42, info, max_records, record_len
        # Use 0x42 0x21 0x05 0x0A = "42210A" (wrong — need 4 bytes)
        # linear-fixed: startswith 42 or 46, last 2 nibbles = record length
        # Check: fileDescriptor.startswith("42") and len==8
        # 0x42 0x21 0x05 0x0A: "4221050A"
        # size=0x35 = 53, record_length=0x0A=10 -> 53 % 10 != 0 -> YRL-FIL-067
        fcp: dict = {
            "fileDescriptor": {"hex": "4221050A"},
            "fileID": {"hex": "6F07"},
            "efFileSize": {"hex": "35"},
        }
        doc = _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })
        codes = _codes(doc)
        self.assertIn("YRL-FIL-067", codes)

    def test_fil067_not_triggered_when_aligned(self) -> None:
        # size=50, record_length=10 -> 50 % 10 == 0 -> passes
        fcp: dict = {
            "fileDescriptor": {"hex": "4221050A"},
            "fileID": {"hex": "6F07"},
            "efFileSize": {"hex": "32"},
        }
        doc = _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-FIL-067", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-038 — record count exceeds 254
# ---------------------------------------------------------------------------

class RecordCountTests(unittest.TestCase):
    """YRL-FIL-038: record count > 254 for record-oriented EF."""

    def test_fil038_too_many_records(self) -> None:
        # record_length=1, efFileSize=255 -> 255 records > 254 limit
        fcp: dict = {
            "fileDescriptor": {"hex": "42210101"},
            "fileID": {"hex": "6F07"},
            "efFileSize": {"hex": "FF"},
        }
        doc = _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })
        codes = _codes(doc)
        self.assertIn("YRL-FIL-038", codes)

    def test_fil038_not_triggered_for_valid_count(self) -> None:
        # record_length=10, efFileSize=250 -> 25 records
        fcp: dict = {
            "fileDescriptor": {"hex": "4221050A"},
            "fileID": {"hex": "6F07"},
            "efFileSize": {"hex": "FA"},
        }
        doc = _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-FIL-038", codes)


# ---------------------------------------------------------------------------
# YRL-AKA-003 — fixed-length AKA field out of spec
# ---------------------------------------------------------------------------

class AkaFixedFieldTests(unittest.TestCase):
    """YRL-AKA-003: fixed-length SGP.22 §B.3 AKA field wrong length."""

    def _doc_with_aka(self, field_name: str, value_hex: str) -> dict:
        algo_params: dict = {
            "algorithmID": 1,
            "key": "00" * 16,
            "opc": "00" * 16,
            field_name: value_hex,
        }
        return _make_doc({
            "akaParameter": {
                "identification": 5,
                "type": "akaParameter",
                "algoConfiguration": {
                    "@": ["algoParameter", algo_params]
                },
            }
        })

    def test_aka003_sqn_delta_wrong_length(self) -> None:
        # sqnDelta must be 6 bytes; give 4 bytes
        codes = _codes(self._doc_with_aka("sqnDelta", "00" * 4))
        self.assertIn("YRL-AKA-003", codes)

    def test_aka003_algo_options_wrong_length(self) -> None:
        # algorithmOptions must be 1 byte; give 2 bytes
        codes = _codes(self._doc_with_aka("algorithmOptions", "0000"))
        self.assertIn("YRL-AKA-003", codes)

# ---------------------------------------------------------------------------
# YRL-FIL-028 / YRL-FIL-029 — BER-TLV file content constraints
# ---------------------------------------------------------------------------

class BerTlvContentTests(unittest.TestCase):
    """YRL-FIL-028: no fillFileContent for BER-TLV file.
    YRL-FIL-029: fillFileOffset coexists with BER-TLV fields."""

    def _gfm_with_ber_tlv(self, with_fill_content: bool, with_fill_offset: bool) -> dict:
        # A file def that has 'maximumFileSize' triggers the BER-TLV path.
        fcp: dict = {
            "fileDescriptor": {"hex": "4121"},
            "fileID": {"hex": "6F07"},
            "maximumFileSize": {"hex": "64"},
        }
        if with_fill_content:
            fcp["fillFileContent"] = {"hex": "AABBCC"}
        if with_fill_offset:
            fcp["fillFileOffset"] = {"hex": "0000"}
        return _make_doc({
            "gfm": {
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [{"@": ["createFCP", fcp]}]},
            }
        })

    def test_fil028_no_fill_content_for_ber_tlv_file(self) -> None:
        codes = _codes(self._gfm_with_ber_tlv(with_fill_content=False, with_fill_offset=False))
        self.assertIn("YRL-FIL-028", codes)

    def test_fil029_fill_offset_with_ber_tlv_fields(self) -> None:
        codes = _codes(self._gfm_with_ber_tlv(with_fill_content=True, with_fill_offset=True))
        self.assertIn("YRL-FIL-029", codes)

    def test_fil028_029_not_triggered_when_content_present(self) -> None:
        codes = _codes(self._gfm_with_ber_tlv(with_fill_content=True, with_fill_offset=False))
        self.assertNotIn("YRL-FIL-028", codes)
        self.assertNotIn("YRL-FIL-029", codes)


    def test_aka003_not_triggered_for_correct_lengths(self) -> None:
        doc = _make_doc({
            "akaParameter": {
                "identification": 5,
                "type": "akaParameter",
                "algoConfiguration": {
                    "@": ["algoParameter", {
                        "algorithmID": 1,
                        "key": "00" * 16,
                        "opc": "00" * 16,
                        "sqnDelta": "00" * 6,
                        "algorithmOptions": "00",
                    }]
                },
            }
        })
        codes = _codes(doc)
        self.assertNotIn("YRL-AKA-003", codes)
