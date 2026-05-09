# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for PE-integrity, application, metadata, and file-descriptor lint rules.

Covers: YRL-SEQ-010, YRL-PID-001/002, YRL-SDM-001..004,
        YRL-JCA-001/002/003/010, YRL-JCI-001..004,
        YRL-MET-001/010/011, YRL-FIL-002/003/005/006/019.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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


def _sd_pe(key_list: object = None, identification: int = 2) -> dict:
    payload: dict = {"identification": identification, "type": "securityDomain"}
    if key_list is not None:
        payload["keyList"] = key_list
    return payload


def _app_pe(
    load_package_aid: str | None = _SD_AID,
    security_domain_aid: str | None = None,
    instance_list: list | None = None,
    identification: int = 10,
) -> dict:
    load_block: dict = {}
    if load_package_aid is not None:
        load_block["loadPackageAID"] = load_package_aid
    if security_domain_aid is not None:
        load_block["securityDomainAID"] = security_domain_aid
    payload: dict = {"identification": identification, "loadBlock": load_block, "type": "application"}
    if instance_list is not None:
        payload["instanceList"] = instance_list
    return payload


def _gfm_cmd(file_descriptor: str | None = "41",
             file_id: str | None = "6F07",
             fill_content: str | None = None,
             short_efid: str | None = None) -> dict:
    fcp: dict = {}
    if file_descriptor is not None:
        fcp["fileDescriptor"] = {"hex": file_descriptor}
    if file_id is not None:
        fcp["fileID"] = {"hex": file_id}
    if fill_content is not None:
        fcp["fillFileContent"] = {"hex": fill_content}
    if short_efid is not None:
        fcp["shortEFID"] = {"hex": short_efid}
    return {"@": ["createFCP", fcp]}


def _gfm_section(cmd: dict, identification: int = 20) -> dict:
    return {
        "identification": identification,
        "type": "genericFileManagement",
        "file": {"fileManagementCMD": [cmd]},
    }


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
    return [f.code for f in _lint(doc)]


# ---------------------------------------------------------------------------
# YRL-SEQ-010 — duplicate singleton PE type
# ---------------------------------------------------------------------------

class SingletonDuplicateTests(unittest.TestCase):
    """YRL-SEQ-010: singleton PE type appears more than once."""

    def test_seq010_duplicate_usim(self) -> None:
        # _base_type_from_key strips _N suffix, so usim_1 and usim_2 both map to 'usim'.
        doc = _make_doc(
            usim_1={"identification": 5, "type": "usim"},
            usim_2={"identification": 6, "type": "usim"},
        )
        codes = _codes(doc)
        self.assertIn("YRL-SEQ-010", codes)

    def test_seq010_not_triggered_for_unique_types(self) -> None:
        doc = _make_doc(usim={"identification": 5, "type": "usim"})
        codes = _codes(doc)
        self.assertNotIn("YRL-SEQ-010", codes)


# ---------------------------------------------------------------------------
# YRL-PID-001 / YRL-PID-002 — PE identification integrity
# ---------------------------------------------------------------------------

class PeIdentificationTests(unittest.TestCase):
    """YRL-PID-001: PE missing identification. YRL-PID-002: duplicate values."""

    def test_pid001_missing_identification(self) -> None:
        doc = _make_doc(rfm={"type": "rfm"})
        codes = _codes(doc)
        self.assertIn("YRL-PID-001", codes)

    def test_pid002_duplicate_identification(self) -> None:
        doc = _make_doc(
            rfm1={"identification": 5, "type": "rfm"},
            rfm2={"identification": 5, "type": "rfm"},
        )
        codes = _codes(doc)
        self.assertIn("YRL-PID-002", codes)

    def test_pid001_002_not_triggered_when_clean(self) -> None:
        doc = _make_doc(rfm={"identification": 5, "type": "rfm"})
        codes = _codes(doc)
        self.assertNotIn("YRL-PID-001", codes)
        self.assertNotIn("YRL-PID-002", codes)


# ---------------------------------------------------------------------------
# YRL-SDM-001..004 — securityDomain PE integrity
# ---------------------------------------------------------------------------

class SecurityDomainTests(unittest.TestCase):
    """YRL-SDM-001..004: SD presence and keyList shape."""

    def test_sdm001_no_sd_pe(self) -> None:
        doc = _make_doc()
        codes = _codes(doc)
        self.assertIn("YRL-SDM-001", codes)

    def test_sdm002_sd_without_keylist(self) -> None:
        # Key must be 'securityDomain' so _base_type_from_key returns 'securityDomain'.
        doc = _make_doc(securityDomain=_sd_pe(key_list=None))
        codes = _codes(doc)
        self.assertIn("YRL-SDM-002", codes)

    def test_sdm003_keylist_not_a_list(self) -> None:
        doc = _make_doc(securityDomain=_sd_pe(key_list={"key": "value"}))
        codes = _codes(doc)
        self.assertIn("YRL-SDM-003", codes)

    def test_sdm004_empty_keylist(self) -> None:
        doc = _make_doc(securityDomain=_sd_pe(key_list=[]))
        codes = _codes(doc)
        self.assertIn("YRL-SDM-004", codes)

    def test_sdm_not_triggered_with_valid_sd(self) -> None:
        doc = _make_doc(securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]))
        codes = _codes(doc)
        for rule in ("YRL-SDM-001", "YRL-SDM-002", "YRL-SDM-003", "YRL-SDM-004"):
            self.assertNotIn(rule, codes)


# ---------------------------------------------------------------------------
# YRL-JCA-001/002/003/010 — application load-block integrity
# ---------------------------------------------------------------------------

class AppLoadBlockTests(unittest.TestCase):
    """YRL-JCA-001..010: Application PE load-block field checks."""

    def test_jca001_missing_load_package_aid(self) -> None:
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(load_package_aid=None),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCA-001", codes)

    def test_jca002_non_hex_load_package_aid(self) -> None:
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(load_package_aid="not-hex-at-all"),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCA-002", codes)

    def test_jca003_duplicate_load_package_aid(self) -> None:
        # Use _N suffix so both keys collapse to 'application' via _base_type_from_key.
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application_1=_app_pe(load_package_aid=_SD_AID, identification=10),
            application_2=_app_pe(load_package_aid=_SD_AID, identification=11),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCA-003", codes)

    def test_jca010_sd_aid_not_defined_by_any_sd_pe(self) -> None:
        unknown_aid = "BBBBBBBBBBBBBBBB"
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(load_package_aid=_SD_AID, security_domain_aid=unknown_aid),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCA-010", codes)


# ---------------------------------------------------------------------------
# YRL-JCI-001..004 — application instance integrity
# ---------------------------------------------------------------------------

class AppInstanceTests(unittest.TestCase):
    """YRL-JCI-001..004: Application PE instanceList checks."""

    def test_jci001_instance_missing_aid(self) -> None:
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(instance_list=[{"applicationLoadPackageAID": _SD_AID}]),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCI-001", codes)

    def test_jci002_instance_aid_not_hex(self) -> None:
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(instance_list=[{"instanceAID": "not-hex"}]),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCI-002", codes)

    def test_jci003_duplicate_instance_aid(self) -> None:
        inst_aid = "A000000003000001"
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(instance_list=[
                {"instanceAID": inst_aid},
                {"instanceAID": inst_aid},
            ]),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCI-003", codes)

    def test_jci004_instance_aid_mismatches_load_package_aid(self) -> None:
        wrong_load_aid = "CCCCCCCCCCCCCCCC"
        doc = _make_doc(
            securityDomain=_sd_pe(key_list=[{"keyVersionNumber": 1}]),
            application=_app_pe(
                load_package_aid=_SD_AID,
                instance_list=[{
                    "instanceAID": "A000000003000002",
                    "applicationLoadPackageAID": wrong_load_aid,
                }],
            ),
        )
        codes = _codes(doc)
        self.assertIn("YRL-JCI-004", codes)


# ---------------------------------------------------------------------------
# YRL-MET-001 / YRL-MET-010 / YRL-MET-011 — metadata alignment
# ---------------------------------------------------------------------------

class MetadataAlignmentTests(unittest.TestCase):
    """YRL-MET-001/010/011: metadata vs profile body alignment."""

    def _lint_with_meta(self, metadata: dict) -> list[str]:
        linter = SaipProfileLinter(strict=False)
        doc = {
            "sections": {
                "header": _base_header(),
                "mf": {"identification": 1, "type": "mf"},
                "end": {"identification": 2, "type": "end"},
            },
        }
        report = linter.lint_decoded_document(
            decoded_document=doc,
            profile_label="test.der",
            check_return_code=None,
            check_stderr="",
            metadata=metadata,
            emit_missing_check_finding=False,
        )
        return [f.code for f in report.findings]

    def test_met001_metadata_iccid_mismatch(self) -> None:
        # Metadata carries a different ICCID string — linter compares via str().
        codes = self._lint_with_meta({"profile": {"iccid": "89882099999999991230"}})
        self.assertIn("YRL-MET-001", codes)

    def test_met001_not_triggered_when_matching(self) -> None:
        # Header ICCID is stored as {"hex": _ICCID}; metadata must carry the
        # identical str() representation for the comparison to pass.
        codes = self._lint_with_meta({"profile": {"iccid": {"hex": _ICCID}}})
        self.assertNotIn("YRL-MET-001", codes)

    def test_met010_mcc_not_3_digits(self) -> None:
        codes = self._lint_with_meta({"operator": {"mcc": "99", "mnc": "01"}})
        self.assertIn("YRL-MET-010", codes)

    def test_met011_mnc_not_2_or_3_digits(self) -> None:
        codes = self._lint_with_meta({"operator": {"mcc": "001", "mnc": "1"}})
        self.assertIn("YRL-MET-011", codes)

    def test_met010_011_pass_with_valid_plmn(self) -> None:
        codes = self._lint_with_meta({"operator": {"mcc": "001", "mnc": "01"}})
        self.assertNotIn("YRL-MET-010", codes)
        self.assertNotIn("YRL-MET-011", codes)


# ---------------------------------------------------------------------------
# YRL-FIL-002/003/005/006/019 — GFM file-descriptor and fileID checks
# ---------------------------------------------------------------------------

class FileDescriptorTests(unittest.TestCase):
    """YRL-FIL-002/003: fileDescriptor absent or non-hex / bad length."""

    def test_fil003_missing_file_descriptor(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor=None, file_id="6F07"))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-003", codes)

    def test_fil002_non_hex_file_descriptor(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="ZZZZ", file_id="6F07"))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-002", codes)

    def test_fil002_too_short_file_descriptor(self) -> None:
        # Only 1 octet (min is 2)
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="41", file_id="6F07"))
        )
        codes = _codes(doc)
        # 1 byte fails the 2..4 length gate
        self.assertIn("YRL-FIL-002", codes)

    def test_valid_file_descriptor_passes(self) -> None:
        # 2 octets: transparent EF (0x41 = linear-fixed, typical)
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="4121", file_id="6F07"))
        )
        codes = _codes(doc)
        self.assertNotIn("YRL-FIL-002", codes)
        self.assertNotIn("YRL-FIL-003", codes)


class FileIdTests(unittest.TestCase):
    """YRL-FIL-005/006: fileID absent or malformed."""

    def test_fil005_missing_file_id(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="4121", file_id=None))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-005", codes)

    def test_fil006_non_hex_file_id(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="4121", file_id="XY"))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-006", codes)

    def test_fil006_wrong_length_file_id(self) -> None:
        # 3 octets — must be exactly 2
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="4121", file_id="6F0700"))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-006", codes)

    def test_fil006_duplicate_file_id(self) -> None:
        cmd1 = _gfm_cmd(file_descriptor="4121", file_id="6F07")
        cmd2 = _gfm_cmd(file_descriptor="4121", file_id="6F07")
        doc = _make_doc(
            gfm={
                "identification": 20,
                "type": "genericFileManagement",
                "file": {"fileManagementCMD": [cmd1, cmd2]},
            }
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-006", codes)

    def test_valid_file_id_passes(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(file_descriptor="4121", file_id="6F07"))
        )
        codes = _codes(doc)
        self.assertNotIn("YRL-FIL-005", codes)
        self.assertNotIn("YRL-FIL-006", codes)


class ShortEfidTests(unittest.TestCase):
    """YRL-FIL-019: shortEFID encoding checks."""

    def test_fil019_non_hex_short_efid(self) -> None:
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(
                file_descriptor="4121", file_id="6F07", short_efid="ZZ"
            ))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-019", codes)

    def test_fil019_wrong_length_short_efid(self) -> None:
        # 2 octets — must be exactly 1
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(
                file_descriptor="4121", file_id="6F07", short_efid="0700"
            ))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-019", codes)

    def test_fil019_low_bits_set(self) -> None:
        # 0x07 has low 3 bits set (b3..b1 must be zero per TS 102 222)
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(
                file_descriptor="4121", file_id="6F07", short_efid="07"
            ))
        )
        codes = _codes(doc)
        self.assertIn("YRL-FIL-019", codes)

    def test_valid_short_efid_passes(self) -> None:
        # 0x08 = 0b00001000, low 3 bits clear
        doc = _make_doc(
            gfm=_gfm_section(_gfm_cmd(
                file_descriptor="4121", file_id="6F07", short_efid="08"
            ))
        )
        codes = _codes(doc)
        self.assertNotIn("YRL-FIL-019", codes)
