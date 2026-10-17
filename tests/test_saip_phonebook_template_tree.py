# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""DF.PHONEBOOK template files in the FS tree: FIDs, names, placement.

A PE-PHONEBOOK (TCA SAIP v3.4.1 §9.5.3, template 2.23.143.1.2.6) rendered
its EF.PBC as "EF.SIMLOCK-STATE 4F67" under the MF. Three defects met:
pySim's template lists a ranged file once per FID under one ``pe_name`` and
keeps the last row, so EF.PBC read 4F67 instead of the range start 4F60 that
§9.1 prescribes and the profile's own EF.PBR record cites; the reverse FID
lookup fell through to a vendor-extension row registered at 4F67 for another
directory instead of the template's own name; and a DF template placed by
``base_path`` rather than ``parent`` anchored under the MF instead of the
ADF. Stock pySim also names the 4F60..4F67 rows EF.ADN, which leaves
``ef-pbc`` without a template and makes the whole PE fail to decode.
"""

from __future__ import annotations

import copy
import importlib
import os
import tempfile
import unittest
from pathlib import Path

_REFERENCE_PROFILE = Path("Tools/ProfilePackage/profile/reference_test_profile.txt")

# The phonebook PE of an operator profile (no identifiers: header, template
# OID, DF.PHONEBOOK with pinStatusTemplateDO, and eight EFs whose FCP is
# mostly inherited). EF.PBC is member [12]: ARR record 9, 50-byte file, SFI 08,
# no explicit fileDescriptor.
_PHONEBOOK_PE_HEX = (
    "B781B0A0058000810107810667810F010206A207A105C60301810AA32DA10C8204"
    "422100"
    "4E8B010980014E831DA80FC0034F581AC5034F6001C9034F8811AA0AC2034F3802"
    "CB034F981DA412A11082044221000D8B010980020145880110A808A1068B010C88"
    "0198A908A1068B01098801A0AB12A1108204422100288B010C800203E88801D0AC"
    "0BA1098B0109800132880108B10BA1098B0109800132880188B311A10F82044221"
    "000F8B01098001968801E8"
)


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def _pysim_available() -> bool:
    try:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        saip_actions._ensure_pysim_importable()
        importlib.import_module("pySim.esim.saip.templates")
    except Exception:  # noqa: BLE001 -- any import failure means "skip"
        return False
    return True


def _split_top_level_tlvs(raw: bytes) -> list[bytes]:
    """Split a ProfileElementSequence into its PE TLVs (single-byte tags)."""
    items: list[bytes] = []
    offset = 0
    while offset < len(raw):
        start = offset
        offset += 1
        first = raw[offset]
        offset += 1
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            length = int.from_bytes(raw[offset:offset + count], "big")
            offset += count
        offset += length
        items.append(raw[start:offset])
    return items


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class TemplateCompensationTests(unittest.TestCase):
    """The two template compensations state their result and retire cleanly."""

    def setUp(self) -> None:
        self.compat = importlib.import_module("Tools.ProfilePackage.saip_pysim_compat")
        self.templates = importlib.import_module("pySim.esim.saip.templates")

    def test_phonebook_template_resolves_ranged_files_to_the_range_start(self) -> None:
        index = self.templates.FilesUsimDfPhonebook.files_by_pename
        # TCA SAIP v3.4.1 Annex A pages 74-75 and §9.1 (first instance =
        # start of the range).
        self.assertEqual(index["ef-pbc"].fid, 0x4F60)
        self.assertEqual(index["ef-adn"].fid, 0x4F58)
        self.assertEqual(index["ef-uid"].fid, 0x4F88)
        self.assertEqual(index["ef-ext1"].fid, 0x4F38)
        self.assertEqual(index["ef-ccp1"].fid, 0x4F98)
        self.assertEqual(index["ef-pbc"].rec_len, 2)

    def test_every_registered_template_keeps_the_first_row_of_a_range(self) -> None:
        for template in self.compat._registered_templates():
            first_by_name: dict[str, object] = {}
            for row in template.files:
                first_by_name.setdefault(row.pe_name, row)
            for pe_name, row in first_by_name.items():
                self.assertIs(template.files_by_pename[pe_name], row, (template.__name__, pe_name))

    def test_installers_are_idempotent(self) -> None:
        self.assertFalse(self.compat.install_phonebook_pbc_template())
        self.assertFalse(self.compat.install_template_range_start_fids())

    def test_pbc_compensation_repairs_the_upstream_rows(self) -> None:
        # Rebuild the upstream defect on a throwaway template: the PBC
        # range spelled EF.ADN, the index last-row-wins.
        source = self.templates.FilesUsimDfPhonebook
        rows = [copy.copy(row) for row in source.files]
        for row in rows:
            row.parent = None
            row.children = []
            if row.fid in range(0x4F60, 0x4F68):
                row.name = "EF.ADN"
                row.pe_name = "ef-adn"
                row.params = ["nb_rec", "sfi"]
        registry = self.templates.ProfileTemplateRegistry
        oid = "2.23.143.1.2.999"
        self.assertNotIn(oid, registry.by_oid)

        class _UpstreamPhonebook(self.templates.ProfileTemplate):
            # ``__init_subclass__`` registers the class by this OID and
            # builds ``files_by_pename`` last-row-wins, as upstream does.
            oid = "2.23.143.1.2.999"
            created_by_default = False
            files = rows

        self.addCleanup(lambda: registry.by_oid.pop(oid, None))
        self.assertIs(registry.by_oid[oid], _UpstreamPhonebook)
        self.assertNotIn("ef-pbc", _UpstreamPhonebook.files_by_pename)
        self.assertEqual(_UpstreamPhonebook.files_by_pename["ef-adn"].fid, 0x4F67)

        self.assertTrue(self.compat.install_phonebook_pbc_template())
        self.assertEqual(_UpstreamPhonebook.files_by_pename["ef-pbc"].fid, 0x4F60)
        self.assertEqual(_UpstreamPhonebook.files_by_pename["ef-pbc"].params, ["size", "sfi"])
        self.assertEqual(_UpstreamPhonebook.files_by_pename["ef-adn"].fid, 0x4F58)
        self.compat.install_template_range_start_fids()
        self.assertEqual(_UpstreamPhonebook.files_by_pename["ef-uid"].fid, 0x4F88)

    def test_range_compensation_fails_closed_on_a_reordered_range(self) -> None:
        rows = [copy.copy(row) for row in self.templates.FilesUsimDfPhonebook.files]
        for row in rows:
            row.parent = None
            row.children = []
        uid_rows = [row for row in rows if row.pe_name == "ef-uid"]
        uid_rows[0].fid, uid_rows[-1].fid = uid_rows[-1].fid, uid_rows[0].fid
        registry = self.templates.ProfileTemplateRegistry
        oid = "2.23.143.1.2.998"

        class _Reordered(self.templates.ProfileTemplate):
            oid = "2.23.143.1.2.998"
            created_by_default = False
            files = rows

        self.addCleanup(lambda: registry.by_oid.pop(oid, None))
        self.assertIs(registry.by_oid[oid], _Reordered)

        with self.assertRaises(self.compat.SaipTemplateRangeFidMismatch):
            self.compat.install_template_range_start_fids()


@unittest.skipUnless(_pysim_available(), "pySim not importable -- skipping")
class PhonebookTreeRowTests(unittest.TestCase):
    """Rows the FS tree renders for a standalone PE-PHONEBOOK section."""

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.saip._ensure_pysim_importable()

    def _document(self) -> dict:
        return {
            "sections": {
                "phonebook": {
                    "phonebook-header": {"identification": 7},
                    "templateID": "2.23.143.1.2.6",
                    "df-phonebook": [
                        ("fileDescriptor", {"pinStatusTemplateDO": _hex("01810A")}),
                    ],
                    "ef-pbr": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221004E"),
                            "securityAttributesReferenced": _hex("09"),
                            "efFileSize": _hex("4E"),
                        }),
                        ("fillFileContent", _hex("A80FC0034F581AC5034F6001C9034F8811AA0AC2034F3802CB034F981D")),
                    ],
                    "ef-adn": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("42210028"),
                            "securityAttributesReferenced": _hex("0C"),
                            "efFileSize": _hex("03E8"),
                            "shortEFID": _hex("D0"),
                        }),
                    ],
                    "ef-pbc": [
                        ("fileDescriptor", {
                            "securityAttributesReferenced": _hex("09"),
                            "efFileSize": _hex("32"),
                            "shortEFID": _hex("08"),
                        }),
                    ],
                    "ef-uid": [
                        ("fileDescriptor", {
                            "securityAttributesReferenced": _hex("09"),
                            "efFileSize": _hex("32"),
                            "shortEFID": _hex("88"),
                        }),
                    ],
                },
            },
        }

    def _rows(self) -> dict[str, dict]:
        rows = self.saip._filesystem_tree_rows(self._document())
        return {row["field_path"]: row for row in rows if row["section_key"] == "phonebook"}

    def test_pbc_is_named_from_its_template_at_the_range_start(self) -> None:
        pbc = self._rows()["ef-pbc"]
        self.assertEqual(pbc["friendly_name"], "EF.PBC")
        self.assertEqual(pbc["file_id"], "4F60")
        self.assertEqual(pbc["file_id_source"], "template")
        self.assertEqual(pbc["kind"], "ef-lf")

    def test_ranged_siblings_take_the_range_start(self) -> None:
        rows = self._rows()
        self.assertEqual(rows["ef-adn"]["file_id"], "4F58")
        self.assertEqual(rows["ef-adn"]["friendly_name"], "EF.ADN")
        self.assertEqual(rows["ef-uid"]["file_id"], "4F88")
        self.assertEqual(rows["ef-uid"]["friendly_name"], "EF.UID")

    def test_phonebook_hangs_under_adf_usim(self) -> None:
        rows = self._rows()
        self.assertEqual(rows["df-phonebook"]["fid_chain"], "ADF.USIM/5F3A")
        self.assertEqual(rows["df-phonebook"]["parent_path"], "ADF.USIM")
        self.assertEqual(rows["ef-pbc"]["fid_chain"], "ADF.USIM/5F3A/4F60")
        self.assertEqual(rows["ef-pbc"]["parent_path"], "ADF.USIM/5F3A")

    def test_template_descriptor_is_projected_with_its_source(self) -> None:
        rows = self._rows()
        # TS 102 221 v18.4 Table 11.5: shareable DF '78', shareable working
        # linear-fixed EF '42', data coding byte '21', 2-byte record length.
        self.assertEqual(rows["df-phonebook"]["descriptor"], "7821")
        self.assertEqual(rows["df-phonebook"]["descriptor_source"], "template")
        self.assertEqual(rows["df-phonebook"]["pin_status_template"], "01810A")
        self.assertEqual(rows["ef-pbc"]["descriptor"], "42210002")
        self.assertEqual(rows["ef-pbc"]["descriptor_source"], "template")
        self.assertEqual(rows["ef-pbc"]["ef_size"], "32")
        # An explicit descriptor is never replaced by the projection.
        self.assertEqual(rows["ef-adn"]["descriptor"], "42210028")
        self.assertEqual(rows["ef-adn"].get("descriptor_source", ""), "")

    def test_df_graphics_context_still_wins_for_its_own_range(self) -> None:
        # The template name only replaces a candidate from another
        # directory; DF.GRAPHICS keeps its EF.IIDF at 4F67.
        self.assertEqual(
            self.saip._saip_reverse_fid_friendly("4F67", parent_fid_hex="3F00/7F10/5F50"),
            "EF.IIDF",
        )
        self.assertEqual(
            self.saip._saip_reverse_fid_friendly(
                "4F67", parent_fid_hex="3F00/5F3A", template_name="EF.PBC",
            ),
            "EF.PBC",
        )


@unittest.skipUnless(
    _pysim_available() and _REFERENCE_PROFILE.exists(),
    "pySim or the reference profile missing -- skipping end-to-end test",
)
class PhonebookPeDecodeTests(unittest.TestCase):
    """The operator PE decodes and its rows carry the corrected FIDs and names."""

    def setUp(self) -> None:
        self.saip = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.saip._ensure_pysim_importable()
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        from Tools.ProfilePackage.saip_tool import SaipToolBridge

        bridge = SaipToolBridge(Path(".").resolve())
        source = bridge.resolve_input_path(str(_REFERENCE_PROFILE), must_exist=True)
        raw = bridge._prepare_input_for_tool(source).read_bytes()
        elements = _split_top_level_tlvs(raw)
        self.assertEqual(elements[-1][0], 0xAA, "the last PE must be the end PE")
        phonebook = _hex(_PHONEBOOK_PE_HEX)
        self.assertEqual(len(phonebook), 179)
        stitched = b"".join(elements[:-1]) + phonebook + elements[-1]
        handle = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
        handle.write(stitched)
        handle.close()
        self.addCleanup(lambda: os.unlink(handle.name))

        class _Ctx:
            pass

        self.ctx = _Ctx()
        self.opened = self.saip._dispatch_open_package(self.ctx, path=handle.name)
        self.session_id = self.opened["session_id"]
        self.addCleanup(lambda: self.sessions.get_manager().close(self.session_id))

    def test_phonebook_pe_decodes_without_a_load_warning(self) -> None:
        self.assertEqual(self.opened["load_warnings"], [])
        self.assertIn("phonebook", self.opened["pe_types"])

    def test_rows_carry_range_start_fids_and_template_names(self) -> None:
        listed = self.saip._dispatch_list_files(self.ctx, session_id=self.session_id)
        rows = {
            row["field_path"]: row
            for row in listed["rows"]
            if row["section_key"] == "phonebook"
        }
        self.assertEqual(rows["ef-pbc"]["friendly_name"], "EF.PBC")
        self.assertEqual(rows["ef-pbc"]["file_id"], "4F60")
        self.assertEqual(rows["ef-adn"]["file_id"], "4F58")
        self.assertEqual(rows["ef-uid"]["file_id"], "4F88")
        self.assertEqual(rows["ef-ext1"]["file_id"], "4F38")
        self.assertEqual(rows["ef-ccp1"]["file_id"], "4F98")
        self.assertEqual(rows["df-phonebook"]["fid_chain"], "ADF.USIM/5F3A")

    def test_security_attributes_override_on_the_operator_df(self) -> None:
        response = self.saip._dispatch_update_file_field(
            self.ctx,
            session_id=self.session_id,
            section_key="phonebook",
            field_path="df-phonebook",
            sub_key="securityAttributesReferenced",
            hex_value="0E",
        )
        self.assertEqual(response["row"]["security_attrs"], "0E")
        self.assertEqual(response["row"]["pin_status_template"], "01810A")


if __name__ == "__main__":
    unittest.main()
