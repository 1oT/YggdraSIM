# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Cold-attach SELECT coverage for the default ADF.USIM / DF.TELECOM tree.

The HIL trace captured on 2026-04-27 showed the modem walking a fixed
list of FIDs via path-rooted SELECTs (``00A40804047FFF<FID>`` and
``00A40804047F10...``) immediately after USIM activation. Several of
those FIDs returned ``6A82`` even though TS 31.102 §4.2 / CPHS Phase 2
§B.4 require them to be present on a real card -- e.g. EF.FDN (6F3B),
EF.EXT2 (6F4B), EF.EXT3 (6F4C), EF.RPLMNAcTD (6F65), EF.CPHS_INFO
(6F16), EF.ONString (6F14), EF.CSP (6F15), EF.MAILBOX_NUMBERS (6F17)
plus DF.TELECOM/EF.ARR (6F06), DF.TELECOM/DF.PHONEBOOK (5F3A) and
EF.PBR (4F30).

These tests pin the default profile so a cold-attaching modem can
SELECT every entry in the trace and read back a deterministic FCP.
"""

from __future__ import annotations

import unittest

from SIMCARD.etsi_fs import (
    DEFAULT_ARR_RECORDS,
    EtsiFileSystem,
    USIM_AID,
    build_default_state,
    rebuild_runtime_filesystem,
)
from SIMCARD.state import SimProfileEntry, SimProfileFsNode, SimProfileImage
from SIMCARD.utils import encode_imsi_ef


class ColdAttachUsimEfCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.fs = EtsiFileSystem(self.state)

    def _select_by_path_from_mf(self, *fids: str) -> tuple[bytes, int, int]:
        payload = bytes.fromhex("".join(fid.upper() for fid in fids))
        return self.fs.select(payload, p1=0x08)

    def _select_usim_ef_by_path(self, fid: str) -> tuple[bytes, int, int]:
        """SELECT MF/ADF.USIM/<EF> by path (P1=0x08) -- mirrors the
        ``00A40804047FF0<FID>`` shape the modem emits during the
        cold-attach EF walk.
        """
        return self._select_by_path_from_mf("7FF0", fid)

    def test_default_profile_exposes_fdn_and_ext_efs_under_usim(self) -> None:
        for fid in ("6F3B", "6F4B", "6F4C", "6F65"):
            data, sw1, sw2 = self._select_usim_ef_by_path(fid)
            self.assertEqual(
                (sw1, sw2),
                (0x90, 0x00),
                msg=f"ADF.USIM/{fid} expected to exist after SAIP defaults",
            )
            self.assertGreater(len(data), 0)
            self.assertIn(bytes.fromhex("8302" + fid), data)

    def test_default_profile_exposes_cphs_efs_under_usim(self) -> None:
        for fid in ("6F14", "6F15", "6F16", "6F17"):
            data, sw1, sw2 = self._select_usim_ef_by_path(fid)
            self.assertEqual(
                (sw1, sw2),
                (0x90, 0x00),
                msg=f"ADF.USIM/{fid} (CPHS) must be selectable",
            )
            self.assertIn(bytes.fromhex("8302" + fid), data)

    def test_cphs_info_default_indicates_phase_2_no_extra_services(self) -> None:
        data, sw1, sw2 = self._select_usim_ef_by_path("6F16")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        body, read_sw1, read_sw2 = self.fs.read_binary(p1=0x00, p2=0x00)
        self.assertEqual((read_sw1, read_sw2), (0x90, 0x00))
        self.assertEqual(body[:3], bytes((0x02, 0x00, 0x00)))

    def test_default_profile_exposes_telecom_arr_and_phonebook(self) -> None:
        # 7F10 / 6F06 path
        arr_data, arr_sw1, arr_sw2 = self._select_by_path_from_mf("7F10", "6F06")
        self.assertEqual((arr_sw1, arr_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83026F06"), arr_data)

        # 7F10 / 5F3A / 4F30 path
        pbr_data, pbr_sw1, pbr_sw2 = self._select_by_path_from_mf("7F10", "5F3A", "4F30")
        self.assertEqual((pbr_sw1, pbr_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83024F30"), pbr_data)

    def test_gsm_access_ciphering_keys_seed_erased_with_cksn_seven(self) -> None:
        # 3GPP TS 31.102 Annex E and TS 51.011 Annex D both give the
        # pre-personalization value of EF.Kc / EF.KcGPRS as 'FF...FF07',
        # and the TCA SAIP DF GSM-ACCESS template (§9.5.4) ships the same
        # nine bytes. Zeroed key bytes would read as a cached all-zero Kc.
        for fid in ("4F20", "4F52"):
            data, sw1, sw2 = self._select_by_path_from_mf("7FF0", "5F3B", fid)
            self.assertEqual(
                (sw1, sw2),
                (0x90, 0x00),
                msg=f"ADF.USIM/DF.GSM-ACCESS/{fid} must be selectable",
            )
            body, read_sw1, read_sw2 = self.fs.read_binary(p1=0x00, p2=0x00)
            self.assertEqual((read_sw1, read_sw2), (0x90, 0x00))
            self.assertEqual(body, bytes.fromhex("FFFFFFFFFFFFFFFF07"))

    def test_rplmnactd_default_seeds_two_two_byte_records(self) -> None:
        data, sw1, sw2 = self._select_usim_ef_by_path("6F65")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        body, read_sw1, read_sw2 = self.fs.read_binary(p1=0x00, p2=0x00)
        self.assertEqual((read_sw1, read_sw2), (0x90, 0x00))
        self.assertEqual(len(body), 4)
        self.assertEqual(body, bytes.fromhex("00FF00FF"))


class ActiveProfileLocalArrCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        for profile in self.state.profiles:
            profile.state = "disabled"

        image = SimProfileImage(
            iccid="8988000000000000001",
            imsi="001010000000001",
            nodes=[
                SimProfileFsNode(
                    path=("MF", "ADF.USIM"),
                    name="ADF.USIM",
                    kind="adf",
                    fid="7FFF",
                    aid=USIM_AID,
                    label="USIM",
                ),
                SimProfileFsNode(
                    path=("MF", "ADF.USIM", "EF.IMSI"),
                    name="EF.IMSI",
                    kind="ef",
                    fid="6F07",
                    structure="transparent",
                    data=encode_imsi_ef("001010000000001"),
                    sfi=0x07,
                ),
                SimProfileFsNode(
                    path=("MF", "DF.TELECOM"),
                    name="DF.TELECOM",
                    kind="df",
                    fid="7F10",
                ),
                SimProfileFsNode(
                    path=("MF", "DF.TELECOM", "EF.ADN"),
                    name="EF.ADN",
                    kind="ef",
                    fid="6F3A",
                    structure="linear-fixed",
                    records=[b"\xFF" * 28],
                ),
            ],
        )
        forced_aid = "A0000005591010FFFFFFFF8900009900"
        self.state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid,
                state="enabled",
                profile_class="operational",
                profile_name="Synthetic ARR Coverage",
                imsi=image.imsi,
                profile_image=image,
                profile_source="test",
            )
        )
        self.state.active_profile_aid = forced_aid
        rebuild_runtime_filesystem(self.state)
        self.fs = EtsiFileSystem(self.state)

    def _select_by_path_from_mf(self, *fids: str) -> tuple[bytes, int, int]:
        payload = bytes.fromhex("".join(fid.upper() for fid in fids))
        return self.fs.select(payload, p1=0x08)

    def test_active_profile_usim_and_telecom_roots_get_default_arr(self) -> None:
        for fids in (("7FFF", "6F06"), ("7F10", "6F06")):
            with self.subTest(path=fids):
                data, sw1, sw2 = self._select_by_path_from_mf(*fids)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertIn(bytes.fromhex("83026F06"), data)
                body, read_sw1, read_sw2 = self.fs.read_record(1, p2=0x04)
                self.assertEqual((read_sw1, read_sw2), (0x90, 0x00))
                self.assertEqual(body, DEFAULT_ARR_RECORDS[0])

    def test_every_record_an_fcp_can_cite_reads_back(self) -> None:
        # ``_build_security_attributes_referenced`` derives the record byte from
        # a node's write ACL and can cite 0x01, 0x02, 0x06, 0x0A or 0x0E. A
        # reference past the end of the file reads back 6A83 instead of a rule.
        self._select_by_path_from_mf("7FFF", "6F06")
        for record in (0x01, 0x02, 0x06, 0x0A, 0x0E):
            with self.subTest(record=f"0x{record:02X}"):
                body, sw1, sw2 = self.fs.read_record(record, p2=0x04)
                self.assertEqual((sw1, sw2), (0x90, 0x00))
                self.assertEqual(body, DEFAULT_ARR_RECORDS[record - 1])

    def test_active_profile_ef_fcp_references_resolvable_local_arr(self) -> None:
        data, sw1, sw2 = self._select_by_path_from_mf("7FFF", "6F07")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("8B036F0601"), data)


if __name__ == "__main__":
    unittest.main()
