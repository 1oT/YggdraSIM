# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_asn1_value import parse_asn1_value_profile
from Tools.ProfilePackage.saip_hex_template import substitute_inline_placeholders
from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path
from Tools.ProfilePackage.saip_pysim_compat import (
    _positional_body_tuples,
    _replay_body_tuples,
    install_base_df_path_compatibility,
    install_body_encoding_against_creation_content,
    install_erased_state_file_fill,
    install_gfm_mf_creation,
    install_lossless_security_domain_encoding,
    install_optional_security_domain_key_list,
    install_proprietary_efinfo_without_descriptor,
    install_record_aware_fill_pattern,
    install_record_aware_template_default,
)
from yggdrasim_common.gui_server.actions.saip import _load_package_from_path

_SD_ASN_SOURCE = """\
securityDomain ProfileElement ::= securityDomain :
{
  sd-Header { mandated NULL, identification 1 },
  instance
  {
    applicationLoadPackageAID 'A0000001515350'H,
    classAID 'A000000151535041'H,
    instanceAID 'A000000151000000'H,
    applicationPrivileges '82DC00'H,
    lifeCycleState '0F'H,
    applicationSpecificParametersC9 '81028000810281048201F08701F0'H,
    applicationParameters
    {
      uiccToolkitApplicationSpecificParametersField
        '01001000000201120300000000'H
    }
  },
  keyList
  {
    {
      keyUsageQualifier '38'H,
      keyAccess '01'H,
      keyIdentifier '01'H,
      keyVersionNumber '03'H,
      keyCounterValue '0000000000'H,
      keyCompontents
      {
        {
          keyType '88'H,
          keyData '[SCP80_KICBINARY16]'H
        }
      }
    },
    {
      keyUsageQualifier '34'H,
      keyAccess 'FF'H,
      keyIdentifier '02'H,
      keyVersionNumber '01'H,
      keyCompontents
      {
        {
          keyType '88'H,
          keyData '11111111111111111111111111111111'H
        }
      }
    }
  }
}
"""


class LosslessSecurityDomainEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import FsProfileElement, ProfileElementSD

        install_lossless_security_domain_encoding()
        wrapped = ProfileElementSD._pre_encode
        install_base_df_path_compatibility()
        wrapped_add_file = FsProfileElement.add_file

        self.assertFalse(install_lossless_security_domain_encoding())
        self.assertIs(ProfileElementSD._pre_encode, wrapped)
        self.assertFalse(install_base_df_path_compatibility())
        self.assertIs(FsProfileElement.add_file, wrapped_add_file)

    def test_asn_source_and_varder_roundtrip_keep_optional_key_fields(self) -> None:
        parsed_asn = parse_asn1_value_profile(
            _SD_ASN_SOURCE,
            workspace_root=self.workspace_root,
        )
        asn_der = parsed_asn.pes.to_der()

        self.assertEqual(len(asn_der), 169)
        self.assertEqual(len(parsed_asn.inline_placeholder_records), 1)
        record = parsed_asn.inline_placeholder_records[0]
        varder_token = "{SCP80_KICBINARY16}"
        varder_text = (
            asn_der.hex()
            .upper()
            .replace(
                record.sentinel_hex,
                varder_token,
            )
        )
        self.assertIn(varder_token, varder_text)

        substituted_varder, _records = substitute_inline_placeholders(varder_text)
        varder_der = bytes.fromhex(substituted_varder)
        self.assertEqual(varder_der, asn_der)

        with tempfile.TemporaryDirectory() as temp_dir:
            varder_path = Path(temp_dir) / "security-domain.varder"
            varder_path.write_bytes(b"\xef\xbb\xbf" + varder_text.encode("ascii"))
            parsed_varder = _load_package_from_path(varder_path)

        self.assertEqual(parsed_varder["pes"].to_der(), asn_der)
        sd = parsed_varder["pes"].pe_list[0].decoded
        self.assertEqual(sd["keyList"][0]["keyAccess"], b"\x01")
        self.assertEqual(
            sd["keyList"][0]["keyCounterValue"],
            b"\x00\x00\x00\x00\x00",
        )
        self.assertEqual(sd["keyList"][1]["keyAccess"], b"\xff")
        self.assertNotIn("keyCounterValue", sd["keyList"][1])



# TCA SAIP V3.4.1 §8.1: without PE-MF, the MF is created as the first
# element of the file system by PE-GenericFileManagement.
_MF_FCP = {
    "fileDescriptor": b"\x78\x21",
    "fileID": b"\x3f\x00",
    "securityAttributesReferenced": b"\x01",
}
_EF_ARR_FCP = {
    "fileDescriptor": b"\x42\x21\x00\x20",
    "fileID": b"\x2f\x06",
    "securityAttributesReferenced": b"\x03",
    "efFileSize": b"\x40",
}


def _profile_der(commands: list) -> bytes:
    """Header + one GFM carrying *commands* + end, DER-encoded by pySim."""
    from pySim.esim.saip import asn1

    header = asn1.encode("ProfileElement", ("header", {
        "major-version": 2,
        "minor-version": 3,
        "iccid": bytes.fromhex("988802214365870921F3"),
        "eUICC-Mandatory-services": {},
        "eUICC-Mandatory-GFSTEList": [],
    }))
    gfm = asn1.encode("ProfileElement", ("genericFileManagement", {
        "gfm-header": {"mandated": None, "identification": 1},
        "fileManagementCMD": [commands],
    }))
    end = asn1.encode("ProfileElement", ("end", {
        "end-header": {"mandated": None, "identification": 2},
    }))
    return header + gfm + end



class OptionalSecurityDomainKeyListTests(unittest.TestCase):
    """TCA SAIP v3.4.1 §8.6.1 (page 55): ``keyList SEQUENCE (SIZE (1..MAX)) OF
    KeyObject OPTIONAL`` -- an SD without keys omits the member."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)

    @staticmethod
    def _blank(class_name: str = "ProfileElementSD"):
        import pySim.esim.saip as saip

        element = getattr(saip, class_name)()
        element.decoded[element.header_name] = {"mandated": None, "identification": 1}
        return element

    def _encoded_without_key_list(self) -> bytes:
        from pySim.esim.saip import asn1

        body = dict(self._blank().decoded)
        body.pop("keyList", None)
        return asn1.encode("ProfileElement", ("securityDomain", body))

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import ProfileElementSD

        install_optional_security_domain_key_list()
        post, pre = ProfileElementSD._post_decode, ProfileElementSD._pre_encode
        self.assertFalse(install_optional_security_domain_key_list())
        self.assertIs(ProfileElementSD._post_decode, post)
        self.assertIs(ProfileElementSD._pre_encode, pre)

    def test_an_sd_without_keys_encodes_without_key_list(self) -> None:
        from pySim.esim.saip import asn1

        for class_name in ("ProfileElementSD", "ProfileElementSSD"):
            with self.subTest(class_name=class_name):
                _choice, body = asn1.decode("ProfileElement", self._blank(class_name).to_der())
                self.assertNotIn("keyList", body)

    def test_an_sd_omitting_key_list_decodes_and_keeps_omitting_it(self) -> None:
        from pySim.esim.saip import ProfileElement

        element = ProfileElement.from_der(self._encoded_without_key_list())
        self.assertEqual(list(element.keys), [])
        self.assertNotIn("keyList", element.decoded)

    def test_keys_encode_with_their_optional_fields(self) -> None:
        # The lossless wrapper keeps keyAccess and keyCounterValue beside it.
        from pySim.esim.saip import ProfileElement, ProfileElementSD, asn1

        decoded = dict(self._blank().decoded)
        decoded["keyList"] = [{
            "keyUsageQualifier": b"\x38",
            "keyAccess": b"\x01",
            "keyIdentifier": b"\x01",
            "keyVersionNumber": b"\x03",
            "keyCounterValue": b"\x00" * 5,
            "keyComponents": [{"keyType": b"\x88", "keyData": bytes(16), "macLength": 8}],
        }]
        element = ProfileElementSD(decoded)
        _choice, body = asn1.decode("ProfileElement", element.to_der())
        self.assertEqual(len(body["keyList"]), 1)
        self.assertEqual(body["keyList"][0]["keyAccess"], b"\x01")
        self.assertEqual(body["keyList"][0]["keyCounterValue"], b"\x00" * 5)
        self.assertEqual(len(ProfileElement.from_der(element.to_der()).keys), 1)

    def test_upstream_still_needs_the_compensation(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        import inspect

        from pySim.esim.saip import ProfileElementSD

        upstream_post = inspect.unwrap(ProfileElementSD._post_decode)
        upstream_pre = inspect.unwrap(ProfileElementSD._pre_encode)
        retire = (
            "upstream pySim now treats keyList as optional: delete "
            "install_optional_security_domain_key_list() and "
            "upstream_patches/osmocom-pysim-saip-sd-optional-key-list/"
        )
        element = self._blank()
        element.decoded.pop("keyList", None)
        with self.assertRaises(KeyError, msg=retire):
            upstream_post(element)
        element = self._blank()
        upstream_pre(element)
        self.assertEqual(element.decoded.get("keyList"), [], retire)

class GfmMfCreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        install_gfm_mf_creation()

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import ProfileElementGFM, ProfileElementSequence

        add_file = ProfileElementGFM.add_file
        cd = ProfileElementSequence.cd

        self.assertFalse(install_gfm_mf_creation())
        self.assertIs(ProfileElementGFM.add_file, add_file)
        self.assertIs(ProfileElementSequence.cd, cd)

    def test_gfm_created_mf_roots_the_sequence(self) -> None:
        from pySim.esim.saip import FsNodeMF, ProfileElementSequence

        der = _profile_der([
            ("createFCP", _MF_FCP),
            ("createFCP", _EF_ARR_FCP),
            ("fillFileContent", b"\x80\x01\x00\x90\x00"),
        ])
        pes = ProfileElementSequence.from_der(der)

        self.assertEqual(
            [pe.type for pe in pes.pe_list],
            ["header", "genericFileManagement", "end"],
        )
        gfm = pes.pe_list[1]
        self.assertIsInstance(pes.mf, FsNodeMF)
        self.assertIs(pes.mf.file, gfm.files["3F00/3F00"])
        self.assertIn(0x2F06, pes.mf.children)
        self.assertIs(pes.mf.children[0x2F06].file, gfm.files["3F00/2F06"])
        self.assertEqual(pes.mf.lookup_by_fidpath([0x3F00, 0x2F06]).fid, 0x2F06)
        self.assertEqual(gfm.files["3F00/2F06"].body[:5], b"\x80\x01\x00\x90\x00")
        # The decoded model is untouched: the PE encodes back byte for byte.
        self.assertEqual(pes.to_der(), der)

    def test_gfm_before_any_mf_keeps_its_files_reachable_by_path(self) -> None:
        from pySim.esim.saip import ProfileElementSequence

        der = _profile_der([
            ("filePath", b"\x7f\x20"),
            ("createFCP", _EF_ARR_FCP),
        ])
        pes = ProfileElementSequence.from_der(der)

        gfm = pes.pe_list[1]
        self.assertIsNone(pes.mf)
        self.assertIsNone(pes.cur_df)
        self.assertIn("3F00/7F20/2F06", gfm.files)
        self.assertIsNone(gfm.files["3F00/7F20/2F06"].node)
        self.assertEqual(pes.to_der(), der)

    def test_upstream_still_needs_the_gfm_mf_compensation(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        from pySim.esim.saip import File, ProfileElementGFM, ProfileElementSequence

        upstream_add_file = ProfileElementGFM.add_file.__wrapped__
        sequence = ProfileElementSequence()
        gfm = ProfileElementGFM(pe_sequence=sequence)
        mf = File(None, [("fileDescriptor", dict(_MF_FCP))])
        mf.path = [0x3F00]
        mf.pe_name = "3F00/3F00"

        with self.assertRaises(
            AttributeError,
            msg=(
                "upstream pySim now roots a GFM-created MF: delete "
                "install_gfm_mf_creation() and "
                "upstream_patches/osmocom-pysim-saip-gfm-mf-creation/"
            ),
        ):
            upstream_add_file(gfm, mf, [0x3F00, 0x3F00])
        self.assertIsNone(sequence.mf)


class RecordAwareTemplateDefaultTests(unittest.TestCase):
    """A record template's default value lands in every record (SAIP V3.4.1 section 9)."""

    # EF ICI, SAIP V3.4.1 section 9 page 86: 20 records of 38 B, default
    # 'FF...FF 0000000001FFFF'; two records are enough to see the tiling.
    _RECORD = bytes([0xFF]) * 31 + bytes.fromhex("0000000001FFFF")

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        install_record_aware_template_default()

    @staticmethod
    def _ici(records: int):
        from pySim.esim.saip.templates import FileTemplate

        return FileTemplate(0x6F80, "EF.ICI", "CY", records, 38, 5, 0x14, "FF...FF0000000001FFFF")

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip.templates import FileTemplate

        expand = FileTemplate.expand_default_value_pattern
        self.assertFalse(install_record_aware_template_default())
        self.assertIs(FileTemplate.expand_default_value_pattern, expand)

    def test_default_is_repeated_per_record(self) -> None:
        self.assertEqual(self._ici(2).expand_default_value_pattern(76), self._RECORD * 2)
        self.assertEqual(self._ici(2).expand_default_value_pattern(50), self._RECORD + self._RECORD[:12])

    def test_one_record_and_a_transparent_file_keep_upstream(self) -> None:
        from pySim.esim.saip.templates import FileTemplate

        upstream = FileTemplate.expand_default_value_pattern.__wrapped__
        single = self._ici(1)
        self.assertEqual(single.expand_default_value_pattern(38), upstream(single, 38))
        transparent = FileTemplate(0x6F07, "EF.IMSI", "TR", None, 9, 5, 0x07, "08FF...FF")
        self.assertEqual(transparent.expand_default_value_pattern(9), upstream(transparent, 9))

    def test_file_body_starts_from_the_per_record_default(self) -> None:
        from pySim.esim.saip import File

        image = File("ef-ici", [("fillFileContent", b"\x11")], template=self._ici(2)).body
        self.assertEqual(image, b"\x11" + self._RECORD[1:] + self._RECORD)

    def test_upstream_still_needs_the_template_default_compensation(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        from pySim.esim.saip.templates import FileTemplate

        upstream = FileTemplate.expand_default_value_pattern.__wrapped__
        self.assertNotEqual(
            upstream(self._ici(2), 76),
            self._RECORD * 2,
            msg=(
                "upstream pySim now lays a record template's default into every "
                "record: delete install_record_aware_template_default() and bug 3 "
                "of upstream_patches/osmocom-pysim-saip-fill-file-offset-erased-state/"
            ),
        )


class ProprietaryEfInfoWithoutDescriptorTests(unittest.TestCase):
    """TCA SAIP V3.4.1 section 8.3.3: a PE sets a template file's pattern by
    naming ``proprietaryEFInfo`` alone; pySim reads it only beside a
    ``fileDescriptor``."""

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_erased_state_file_fill()
        install_record_aware_fill_pattern()
        install_proprietary_efinfo_without_descriptor()

    @staticmethod
    def _file(pename: str, fcp: dict, template_file, content: bytes = b""):
        from pySim.esim.saip import File

        tuples = [("fileDescriptor", fcp)]
        if content:
            tuples.append(("fillFileContent", content))
        return File(pename, tuples, template_file)

    @staticmethod
    def _template(holder: str, pename: str):
        from pySim.esim.saip import templates

        return getattr(templates, holder).files_by_pename[pename]

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import File

        reader = File.from_fileDescriptor
        self.assertFalse(install_proprietary_efinfo_without_descriptor())
        self.assertIs(File.from_fileDescriptor, reader)

    def test_pattern_fills_a_template_file_without_a_default(self) -> None:
        umpc = self._template("FilesAtMF", "ef-umpc")
        pe_file = self._file("ef-umpc", {"proprietaryEFInfo": {"fillPattern": b"\x01\xff"}}, umpc)
        self.assertEqual(pe_file.fill_pattern, b"\x01\xff")
        self.assertEqual(pe_file.body, bytes.fromhex("01FFFFFFFF"))

    def test_pattern_replaces_the_template_default_and_content_lands_on_it(self) -> None:
        pl = self._template("FilesAtMF", "ef-pl")
        self.assertEqual(self._file("ef-pl", {"proprietaryEFInfo": {"fillPattern": b"\xaa"}}, pl).body, b"\xaa\xaa")
        repeat = self._file(
            "ef-pl", {"proprietaryEFInfo": {"repeatPattern": b"\x12\x34"}}, pl, content=b"\x65"
        )
        self.assertTrue(repeat.fill_pattern_repeat)
        self.assertEqual(repeat.body, bytes.fromhex("6534"))

    def test_record_file_opens_every_record_with_the_pattern(self) -> None:
        pnn = self._template("FilesUsimOptional", "ef-pnn")
        pe_file = self._file("ef-pnn", {"proprietaryEFInfo": {"fillPattern": b"\x00\xff"}}, pnn)
        self.assertEqual(pe_file.body, (b"\x00" + b"\xff" * (pnn.rec_len - 1)) * pnn.nb_rec)

    def test_special_file_information_is_read_too(self) -> None:
        umpc = self._template("FilesAtMF", "ef-umpc")
        pe_file = self._file("ef-umpc", {"proprietaryEFInfo": {"specialFileInformation": b"\xc0"}}, umpc)
        self.assertTrue(pe_file.high_update)
        self.assertTrue(pe_file.read_and_update_when_deact)

    def test_an_fcp_with_a_descriptor_keeps_upstream(self) -> None:
        from pySim.esim.saip import File

        umpc = self._template("FilesAtMF", "ef-umpc")
        fcp = {"fileDescriptor": b"\x41\x21", "efFileSize": b"\x05",
               "proprietaryEFInfo": {"fillPattern": b"\x07"}}
        compensated = self._file("ef-umpc", dict(fcp), umpc)
        plain = File("ef-umpc", None, umpc)
        File.from_fileDescriptor.__wrapped__(plain, dict(fcp))
        self.assertEqual(compensated.fill_pattern, plain.fill_pattern)
        self.assertEqual(compensated.body, b"\x07" * 5)

    def test_upstream_still_needs_the_compensation(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        from pySim.esim.saip import File

        plain = File("ef-umpc", None, self._template("FilesAtMF", "ef-umpc"))
        File.from_fileDescriptor.__wrapped__(plain, {"proprietaryEFInfo": {"fillPattern": b"\xaa"}})
        self.assertIsNone(
            plain.fill_pattern,
            msg=(
                "upstream pySim now reads proprietaryEFInfo without a fileDescriptor: "
                "delete install_proprietary_efinfo_without_descriptor() and "
                "upstream_patches/osmocom-pysim-saip-proprietary-efinfo-without-descriptor/"
            ),
        )



class BodyEncodingAgainstCreationContentTests(unittest.TestCase):
    """TCA SAIP V3.4.1 sections 8.3.3 and 8.3.5: an optimised body is the
    difference from the content the file is created with, and each
    ``fillFileOffset`` moves the pointer from where the last write left it."""

    _DEFAULT = bytes(range(20))

    @classmethod
    def setUpClass(cls) -> None:
        ensure_workspace_pysim_on_path(Path(__file__).resolve().parents[1])
        install_erased_state_file_fill()
        install_record_aware_fill_pattern()
        install_proprietary_efinfo_without_descriptor()
        install_body_encoding_against_creation_content()

    def _literal(self):
        from pySim.esim.saip.templates import FileTemplate

        return FileTemplate(0x6F99, "EF.TEST", "TR", None, 20, 5, 0x10, self._DEFAULT.hex())

    @staticmethod
    def _file(template_file, body: bytes, fcp: dict | None = None):
        from pySim.esim.saip import File

        pe_file = File("ef-test", [("fileDescriptor", dict(fcp or {}))], template_file)
        pe_file.body = body
        return pe_file

    @staticmethod
    def _decode(template_file, tuples, fcp: dict | None = None) -> bytes:
        from pySim.esim.saip import File

        return bytes(File("decoded", [("fileDescriptor", dict(fcp or {}))] + list(tuples), template_file).body)

    def _three_differences(self) -> bytes:
        body = bytearray(self._DEFAULT)
        body[3], body[10], body[15] = 0xAA, 0xBB, 0xCC
        return bytes(body)

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import File

        encoder = File.file_content_to_tuples
        self.assertFalse(install_body_encoding_against_creation_content())
        self.assertIs(File.file_content_to_tuples, encoder)

    def test_several_differences_rebuild_the_body(self) -> None:
        body = self._three_differences()
        tuples = self._file(self._literal(), body).file_content_to_tuples(optimize=True)
        self.assertEqual(
            tuples,
            [
                ("fillFileOffset", 3), ("fillFileContent", b"\xaa"),
                ("fillFileOffset", 6), ("fillFileContent", b"\xbb"),
                ("fillFileOffset", 4), ("fillFileContent", b"\xcc"),
            ],
        )
        self.assertEqual(self._decode(self._literal(), tuples), body)

    def test_the_fcp_pattern_is_the_baseline(self) -> None:
        from pySim.esim.saip import templates

        pl = templates.FilesAtMF.files_by_pename["ef-pl"]
        fcp = {"proprietaryEFInfo": {"fillPattern": b"\xaa"}}
        # Byte 0 equals the template default 'FF' but not the pattern 'AA'.
        tuples = self._file(pl, b"\xff\xaa", fcp).file_content_to_tuples(optimize=True)
        self.assertEqual(tuples, [("fillFileOffset", 0), ("fillFileContent", b"\xff")])
        self.assertEqual(self._decode(pl, tuples, fcp), b"\xff\xaa")

    def test_the_creation_content_encodes_as_nothing_and_verbatim_stays(self) -> None:
        pe_file = self._file(self._literal(), self._DEFAULT)
        self.assertEqual(pe_file.file_content_to_tuples(optimize=True), [])
        self.assertEqual(pe_file.file_content_to_tuples(optimize=False), [("fillFileContent", self._DEFAULT)])

    def test_an_offset_beyond_uint16_is_split(self) -> None:
        base = b"\xff" * 70000
        body = bytearray(base)
        body[66000] = 0x01
        tuples = _positional_body_tuples(base, bytes(body))
        self.assertEqual(
            tuples,
            [("fillFileOffset", 65535), ("fillFileOffset", 465), ("fillFileContent", b"\x01")],
        )
        self.assertEqual(_replay_body_tuples(base, tuples), bytes(body))

    def test_upstream_still_needs_the_compensation(self) -> None:
        """Pin the upstream gap so the compensation cannot outlive it unnoticed."""
        from pySim.esim.saip import File

        body = self._three_differences()
        upstream = File.file_content_to_tuples.__wrapped__(self._file(self._literal(), body), True)
        self.assertNotEqual(
            _replay_body_tuples(self._DEFAULT, upstream),
            body,
            msg=(
                "upstream pySim now encodes relative offsets: delete "
                "install_body_encoding_against_creation_content() once it also takes "
                "the Fcp pattern as the baseline, and "
                "upstream_patches/osmocom-pysim-saip-optimised-body-encoding/"
            ),
        )


if __name__ == "__main__":
    unittest.main()
