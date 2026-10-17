# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""PE-IoT / PE-OPT-IoT, cdmaParameter and nonStandard through pySim.

Upstream pySim leaves the four ``ProfileElement`` types unmapped in
``class_for_petype``; ``install_extra_profile_elements`` maps them and
registers the IoT Minimal Profile templates (TCA SAIP v3.4.1 §8.3.4.8,
§9.10.1 and §9.10.2). The tests cover the mapping, the template rows
against the compiled ASN.1, the two-level file-system placement, the
card-image loader, and the quick-add factory.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from SIMCARD.saip_profile import _FILE_SPECS, decode_profile_image
from SIMCARD.utils import encode_iccid_ef, encode_imsi_ef
from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path
from Tools.ProfilePackage.saip_pysim_compat import install_extra_profile_elements

_ICCID = "8988201234567890123"
_IMSI = "001010000000001"
_IOT_TEMPLATE_OID = "2.23.143.1.2.17"
_OPT_IOT_TEMPLATE_OID = "2.23.143.1.2.18"
_EXTRA_TYPES = ("cdmaParameter", "nonStandard", "iot", "opt-iot")


def _iot_profile_der() -> bytes:
    """header, iot, opt-iot, end: the smallest IoT Minimal Profile shape."""
    from pySim.esim.saip import asn1

    iccid_ef = encode_iccid_ef(_ICCID)
    imsi_ef = encode_imsi_ef(_IMSI)
    header = asn1.encode("ProfileElement", ("header", {
        "major-version": 2,
        "minor-version": 3,
        "profileType": "iot-minimal",
        "iccid": iccid_ef,
        "eUICC-Mandatory-services": {"usim": None},
        "eUICC-Mandatory-GFSTEList": [_IOT_TEMPLATE_OID],
    }))
    iot = asn1.encode("ProfileElement", ("iot", {
        "iot-header": {"mandated": None, "identification": 2},
        "templateID": _IOT_TEMPLATE_OID,
        "mf": [],
        "ef-iccid": [("fillFileContent", iccid_ef)],
        "ef-dir": [],
        "ef-arr": [],
        "adf-usim": [],
        "ef-imsi": [("fillFileContent", imsi_ef)],
        "ef-arr-usim": [],
        "ef-ust": [("fillFileContent", bytes.fromhex("000000000100"))],
        "ef-acc": [("fillFileContent", bytes.fromhex("0001"))],
        "ef-ecc": [],
    }))
    opt_iot = asn1.encode("ProfileElement", ("opt-iot", {
        "optiot-header": {"mandated": None, "identification": 3},
        "templateID": _OPT_IOT_TEMPLATE_OID,
        "ef-fdn": [("fillFileContent", b"\xff" * 26)],
        "df-df-5gs": [],
        "ef-5gs3gpploci": [("fillFileContent", b"\xff" * 20)],
        "df-df-saip": [],
        "ef-suci-calc-info-usim": [("fillFileContent", bytes.fromhex("A000"))],
    }))
    end = asn1.encode("ProfileElement", ("end", {
        "end-header": {"mandated": None, "identification": 4},
    }))
    return header + iot + opt_iot + end


class ExtraProfileElementLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_extra_profile_elements()

    def test_lookup_maps_the_four_types(self) -> None:
        from pySim.esim.saip import ProfileElement

        for pe_type in _EXTRA_TYPES:
            with self.subTest(pe_type=pe_type):
                resolved = ProfileElement.class_for_petype(pe_type)
                self.assertIsNotNone(resolved)
                self.assertEqual(resolved.type, pe_type)
                self.assertTrue(issubclass(resolved, ProfileElement))

    def test_upstream_types_keep_their_upstream_class(self) -> None:
        from pySim.esim.saip import ProfileElement, ProfileElementUSIM

        self.assertIs(ProfileElement.class_for_petype("usim"), ProfileElementUSIM)
        self.assertIsNone(ProfileElement.class_for_petype("no-such-type"))

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import ProfileElement, ProfileElementSequence

        lookup = ProfileElement.class_for_petype
        grouping = ProfileElementSequence._rebuild_pes_by_naa
        self.assertFalse(install_extra_profile_elements())
        self.assertEqual(ProfileElement.class_for_petype, lookup)
        self.assertIs(ProfileElementSequence._rebuild_pes_by_naa, grouping)

    def test_upstream_still_lacks_the_four_types(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        from pySim.esim.saip import ProfileElement

        upstream_lookup = ProfileElement.class_for_petype.__wrapped__
        for pe_type in _EXTRA_TYPES:
            with self.subTest(pe_type=pe_type):
                self.assertIsNone(
                    upstream_lookup(ProfileElement, pe_type),
                    msg=(
                        "upstream pySim now maps %r: delete "
                        "install_extra_profile_elements() and "
                        "upstream_patches/osmocom-pysim-saip-extra-profile-elements/"
                        % pe_type
                    ),
                )

    def test_iot_templates_cover_every_file_member(self) -> None:
        """Every ``File`` member of PE-IoT / PE-OPT-IoT has a template row, and no more."""
        from pySim.esim.saip import asn1
        from pySim.esim.saip.templates import ProfileTemplateRegistry

        choice = asn1.types["ProfileElement"].type
        for pe_type, template_oid in (("iot", _IOT_TEMPLATE_OID), ("opt-iot", _OPT_IOT_TEMPLATE_OID)):
            with self.subTest(pe_type=pe_type):
                members = choice.name_to_member[pe_type].root_members
                file_members = {m.name for m in members if m.type_name == "File"}
                template = ProfileTemplateRegistry.get_by_oid(template_oid)
                self.assertIsNotNone(template)
                self.assertEqual(set(template.files_by_pename), file_members)

    def test_iot_template_fixes_the_usim_adf_identifier(self) -> None:
        from pySim.esim.saip.templates import ProfileTemplateRegistry

        template = ProfileTemplateRegistry.get_by_oid(_IOT_TEMPLATE_OID)
        adf = template.files_by_pename["adf-usim"]
        self.assertEqual(adf.fid, 0x7FF1)
        self.assertEqual(template.files_by_pename["mf"].fid, 0x3F00)
        self.assertEqual(template.files_by_pename["ef-imsi"].ppath, [0x7FF1])
        optional = ProfileTemplateRegistry.get_by_oid(_OPT_IOT_TEMPLATE_OID)
        self.assertTrue(optional.optional)
        self.assertEqual(optional.files_by_pename["df-df-5gs"].fid, 0x5FC0)
        self.assertEqual(optional.files_by_pename["ef-5gs3gpploci"].ppath, [0x5FC0])
        self.assertEqual(optional.files_by_pename["df-df-saip"].fid, 0x5FD0)
        self.assertEqual(optional.files_by_pename["ef-suci-calc-info-usim"].ppath, [0x5FD0])


class IotFileSystemPlacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_extra_profile_elements()

    def test_iot_creates_the_mf_and_the_usim_adf(self) -> None:
        from pySim.esim.saip import FsNodeMF, ProfileElementSequence

        der = _iot_profile_der()
        pes = ProfileElementSequence.from_der(der)

        self.assertEqual([pe.type for pe in pes.pe_list], ["header", "iot", "opt-iot", "end"])
        self.assertIsInstance(pes.mf, FsNodeMF)
        self.assertIn(0x2FE2, pes.mf.children)
        adf = pes.mf[0x7FF1]
        self.assertIn(0x6F07, adf.children)
        self.assertIn(0x6F06, adf.children)
        self.assertEqual(pes.pe_list[1].imsi, _IMSI)
        self.assertEqual(pes.to_der(), der)

    def test_opt_iot_places_its_files_under_the_iot_adf(self) -> None:
        from pySim.esim.saip import ProfileElementSequence

        pes = ProfileElementSequence.from_der(_iot_profile_der())
        adf = pes.mf[0x7FF1]
        self.assertIn(0x6F3B, adf.children)
        self.assertIn(0x4F01, adf[0x5FC0].children)
        self.assertIn(0x4F01, adf[0x5FD0].children)
        opt_iot = pes.pe_list[2]
        self.assertIs(opt_iot.files["ef-5gs3gpploci"].node.parent, adf[0x5FC0])
        self.assertIs(opt_iot.files["ef-suci-calc-info-usim"].node.parent, adf[0x5FD0])

    def test_iot_starts_the_usim_naa_group(self) -> None:
        from pySim.esim.saip import ProfileElementSequence

        pes = ProfileElementSequence.from_der(_iot_profile_der())
        grouped = {
            naa: [[pe.type for pe in group] for group in groups]
            for naa, groups in pes.pes_by_naa.items()
        }
        self.assertEqual(grouped, {"usim": [["iot", "opt-iot"]]})

    def test_opt_iot_without_a_usim_adf_is_refused(self) -> None:
        from pySim.esim.saip import ProfileElementSequence, asn1

        header = asn1.encode("ProfileElement", ("header", {
            "major-version": 2,
            "minor-version": 3,
            "profileType": "iot-minimal",
            "iccid": encode_iccid_ef(_ICCID),
            "eUICC-Mandatory-services": {"usim": None},
            "eUICC-Mandatory-GFSTEList": [_OPT_IOT_TEMPLATE_OID],
        }))
        opt_iot = asn1.encode("ProfileElement", ("opt-iot", {
            "optiot-header": {"mandated": None, "identification": 2},
            "templateID": _OPT_IOT_TEMPLATE_OID,
            "ef-fdn": [("fillFileContent", b"\xff" * 26)],
        }))
        end = asn1.encode("ProfileElement", ("end", {
            "end-header": {"mandated": None, "identification": 3},
        }))
        with self.assertRaises(ValueError):
            ProfileElementSequence.from_der(header + opt_iot + end)


class IotCardImageLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_extra_profile_elements()

    def _node(self, image, path: tuple[str, ...]):
        matches = [node for node in image.nodes if node.path == path]
        self.assertEqual(len(matches), 1, msg="expected one node at %r, got %r" % (path, matches))
        return matches[0]

    def test_iot_profile_lands_on_both_levels(self) -> None:
        image = decode_profile_image(_iot_profile_der())
        self.assertIsNotNone(image)

        iccid = self._node(image, ("MF", str(_FILE_SPECS["ef-iccid"]["name"])))
        self.assertEqual(iccid.data, encode_iccid_ef(_ICCID))
        adf = self._node(image, ("MF", "ADF.USIM"))
        self.assertEqual(adf.kind, "adf")
        self.assertEqual(adf.fid, "7FF1")
        imsi = self._node(image, ("MF", "ADF.USIM", str(_FILE_SPECS["ef-imsi"]["name"])))
        self.assertEqual(imsi.data, encode_imsi_ef(_IMSI))
        arr = self._node(image, ("MF", "ADF.USIM", str(_FILE_SPECS["ef-arr"]["name"])))
        self.assertEqual(arr.kind, "ef")

    def test_opt_iot_files_land_under_their_directories(self) -> None:
        image = decode_profile_image(_iot_profile_der())
        self.assertIsNotNone(image)

        fdn = self._node(image, ("MF", "ADF.USIM", str(_FILE_SPECS["ef-fdn"]["name"])))
        self.assertEqual(len(fdn.data) + sum(len(r) for r in fdn.records), 26)
        df_5gs = self._node(image, ("MF", "ADF.USIM", "DF.5GS"))
        self.assertEqual(df_5gs.fid, "5FC0")
        loci = self._node(image, ("MF", "ADF.USIM", "DF.5GS", str(_FILE_SPECS["ef-5gs3gpploci"]["name"])))
        self.assertEqual(loci.data, b"\xff" * 20)
        df_saip = self._node(image, ("MF", "ADF.USIM", "DF.SAIP"))
        self.assertEqual(df_saip.fid, "5FD0")
        suci = self._node(
            image,
            ("MF", "ADF.USIM", "DF.SAIP", str(_FILE_SPECS["ef-suci-calc-info-usim"]["name"])),
        )
        self.assertEqual(suci.data, bytes.fromhex("A000"))
        # No second ADF root: PE-OPT-IoT reuses the ADF PE-IoT created.
        self.assertEqual(sum(1 for node in image.nodes if node.path == ("MF", "ADF.USIM")), 1)


class IotQuickAddTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_extra_profile_elements()

    def test_iot_factories_build_typed_elements(self) -> None:
        from Tools.ProfilePackage.saip_pe_quick_add import _factory_map

        factories = _factory_map()
        iot = factories["iot"]()
        self.assertEqual(iot.type, "iot")
        self.assertEqual(iot.decoded["templateID"], _IOT_TEMPLATE_OID)
        self.assertEqual(iot.decoded["iot-header"]["identification"], 0)
        for pe_name in ("mf", "ef-iccid", "adf-usim", "ef-imsi", "ef-ust", "ef-acc", "ef-ecc"):
            self.assertIn(pe_name, iot.decoded)

        opt_iot = factories["opt-iot"]()
        self.assertEqual(opt_iot.type, "opt-iot")
        self.assertEqual(opt_iot.decoded["templateID"], _OPT_IOT_TEMPLATE_OID)
        self.assertEqual(opt_iot.decoded["optiot-header"]["identification"], 0)

    def test_csim_stays_a_skeleton(self) -> None:
        from Tools.ProfilePackage.saip_pe_quick_add import _factory_map

        csim = _factory_map()["csim"]()
        self.assertEqual(csim.type, "csim")
        self.assertIn("csim-header", csim.decoded)
        self.assertNotIn("adf-csim", csim.decoded)


if __name__ == "__main__":
    unittest.main()
