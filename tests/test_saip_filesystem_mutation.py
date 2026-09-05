# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Focused tests for plugin-neutral SAIP filesystem materialization."""

import unittest
from dataclasses import replace
from pathlib import Path

from Tools.ProfilePackage.saip_filesystem_mutation import (
    ElementaryFileStructure,
    FilesystemEntrySpec,
    FilesystemMutationError,
    FilesystemNodeKind,
    NATIVE_TEMPLATE_MENU_IDS,
    NativeFilesystemEntrySpec,
    NativeTemporaryFidAssignment,
    materialize_filesystem_document,
    materialize_native_filesystem_document,
    native_temporary_fid,
)
from Tools.ProfilePackage.saip_json_codec import (
    build_profile_sequence_from_document,
    ensure_workspace_pysim_on_path,
)


class TestSaipFilesystemMutation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)
        from pySim.esim.saip import ProfileElementSequence

        cls._ProfileElementSequence = ProfileElementSequence

    def _decode(self, document: dict):
        sequence = build_profile_sequence_from_document(
            document,
            self.workspace_root,
        )
        return self._ProfileElementSequence.from_der(sequence.to_der())

    @staticmethod
    def _gfm_sections(document: dict) -> list[dict]:
        return [
            section
            for key, section in document["sections"].items()
            if key == "genericFileManagement" or key.startswith("genericFileManagement_")
        ]

    @staticmethod
    def _created_fcps(section: dict) -> list[dict]:
        transaction = section["fileManagementCMD"][0]
        return [value for choice, value in transaction if choice == "createFCP"]

    def test_nested_arbitrary_df_tree_is_deterministic_and_roundtrips(self) -> None:
        entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x7F99,
                kind=FilesystemNodeKind.DF,
                lifecycle=0x07,
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7F99),
                fid=0x5F01,
                kind=FilesystemNodeKind.DF,
                df_name=bytes.fromhex("D000000001"),
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7F99),
                fid=0x6F10,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.LINEAR_FIXED,
                record_length=4,
                record_count=2,
                sfi=3,
                literal_content=b"abcdefgh",
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7F99, 0x5F01),
                fid=0x4F01,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=4,
                literal_content=bytes.fromhex("DEADBEEF"),
            ),
        )

        result = materialize_filesystem_document(
            reversed(entries),
            self.workspace_root,
        )
        forward = materialize_filesystem_document(entries, self.workspace_root)

        self.assertEqual(
            tuple(result.document["sections"]),
            (
                "header",
                "mf",
                "genericFileManagement",
                "genericFileManagement_2",
                "genericFileManagement_3",
                "end",
            ),
        )
        self.assertEqual(
            result.summary.gfm_parent_paths,
            (
                (0x3F00,),
                (0x3F00, 0x7F99),
                (0x3F00, 0x7F99, 0x5F01),
            ),
        )
        reverse_der = build_profile_sequence_from_document(
            result.document,
            self.workspace_root,
        ).to_der()
        forward_der = build_profile_sequence_from_document(
            forward.document,
            self.workspace_root,
        ).to_der()
        self.assertEqual(reverse_der, forward_der)

        sections = self._gfm_sections(result.document)
        expected_file_paths = (b"", bytes.fromhex("7F99"), bytes.fromhex("7F995F01"))
        for section, expected_path in zip(sections, expected_file_paths):
            transaction = section["fileManagementCMD"][0]
            self.assertEqual(transaction[0], ("filePath", expected_path))
            for fcp in self._created_fcps(section):
                self.assertNotIn("securityAttributesReferenced", fcp)
                self.assertFalse(
                    any(value is None for value in fcp.values()),
                    "Absent optional FCP members must be omitted before DER encoding.",
                )
        self.assertEqual(
            [fcp["fileID"] for fcp in self._created_fcps(sections[1])],
            [bytes.fromhex("5F01"), bytes.fromhex("6F10")],
        )
        self.assertEqual(self._created_fcps(sections[0])[0]["lcsi"], b"\x07")

        decoded = self._decode(result.document)
        decoded_files = {}
        for pe in decoded.get_pes_for_type("genericFileManagement"):
            decoded_files.update(pe.files)
        self.assertEqual(
            set(decoded_files),
            {
                "3F00/7F99",
                "3F00/7F99/5F01",
                "3F00/7F99/6F10",
                "3F00/7F99/5F01/4F01",
            },
        )
        record_file = decoded_files["3F00/7F99/6F10"]
        self.assertEqual(record_file.file_type, "LF")
        # pySim's decoded File object currently retains the encoded shortEFID
        # octet rather than exposing the logical SFI.
        self.assertEqual((record_file.rec_len, record_file.nb_rec, record_file.sfi), (4, 2, 0x18))
        self.assertEqual(
            decoded_files["3F00/7F99/5F01"].df_name,
            bytes.fromhex("D000000001"),
        )

    def test_nested_arbitrary_adf_tree_roundtrips(self) -> None:
        aid = bytes.fromhex("A000000999")
        entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x7FF4,
                kind=FilesystemNodeKind.ADF,
                df_name=aid,
                lifecycle=0x07,
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7FF4),
                fid=0x6F20,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.CYCLIC,
                record_length=2,
                record_count=3,
                sfi=2,
                literal_content=b"abcdef",
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7FF4),
                fid=0x6F21,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.BER_TLV,
                file_size=32,
                literal_content=bytes.fromhex("5A02CAFE"),
            ),
        )

        result = materialize_filesystem_document(entries, self.workspace_root)
        sections = self._gfm_sections(result.document)
        self.assertEqual(result.summary.gfm_parent_paths, ((0x3F00,), (0x3F00, 0x7FF4)))
        adf_fcp = self._created_fcps(sections[0])[0]
        self.assertEqual(adf_fcp["fileID"], bytes.fromhex("7FF4"))
        self.assertEqual(adf_fcp["dfName"], aid)
        self.assertEqual(adf_fcp["lcsi"], b"\x07")
        self.assertNotIn("securityAttributesReferenced", adf_fcp)
        self.assertNotIn("pinStatusTemplateDO", adf_fcp)

        decoded = self._decode(result.document)
        decoded_files = {}
        for pe in decoded.get_pes_for_type("genericFileManagement"):
            decoded_files.update(pe.files)
        self.assertEqual(decoded_files["3F00/7FF4"].df_name, aid)
        cyclic = decoded_files["3F00/7FF4/6F20"]
        self.assertEqual((cyclic.file_type, cyclic.rec_len, cyclic.nb_rec), ("CY", 2, 3))
        self.assertEqual(decoded_files["3F00/7FF4/6F21"].file_type, "BT")

        unnamed_result = materialize_filesystem_document(
            (FilesystemEntrySpec((0x3F00,), 0x7FF5, FilesystemNodeKind.ADF),),
            self.workspace_root,
        )
        unnamed_decoded = self._decode(unnamed_result.document)
        unnamed_paths = {
            path
            for pe in unnamed_decoded.get_pes_for_type("genericFileManagement")
            for path in pe.files
        }
        self.assertEqual(unnamed_paths, {"3F00/7FF5"})

    def test_explicit_gfm_arr_reference_is_preserved_without_guessing(self) -> None:
        entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x6F01,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=2,
                literal_content=b"ok",
                arr_file_fid=0x6F06,
                arr_record=10,
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x6F02,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=1,
            ),
        )

        result = materialize_filesystem_document(entries, self.workspace_root)
        fcps = self._created_fcps(self._gfm_sections(result.document)[0])
        by_fid = {fcp["fileID"]: fcp for fcp in fcps}
        self.assertEqual(
            by_fid[bytes.fromhex("6F01")]["securityAttributesReferenced"],
            bytes.fromhex("6F060A"),
        )
        self.assertNotIn(
            "securityAttributesReferenced",
            by_fid[bytes.fromhex("6F02")],
        )

        decoded = self._decode(result.document)
        files = decoded.get_pes_for_type("genericFileManagement")[0].files
        self.assertEqual(files["3F00/6F01"].arr, bytes.fromhex("6F060A"))
        self.assertIsNone(files["3F00/6F02"].arr)

    def test_gfm_arr_reference_requires_a_valid_complete_pair(self) -> None:
        valid = FilesystemEntrySpec(
            parent_fid_path=(0x3F00,),
            fid=0x6F01,
            kind=FilesystemNodeKind.EF,
            structure=ElementaryFileStructure.TRANSPARENT,
            file_size=1,
        )
        invalid_specs = (
            replace(valid, arr_record=1),
            replace(valid, arr_file_fid=0x6F06),
            replace(valid, arr_file_fid=True, arr_record=1),
            replace(valid, arr_file_fid=-1, arr_record=1),
            replace(valid, arr_file_fid=0x10000, arr_record=1),
            replace(valid, arr_file_fid=0x6F06, arr_record=True),
            replace(valid, arr_file_fid=0x6F06, arr_record=0),
            replace(valid, arr_file_fid=0x6F06, arr_record=0xFF),
            replace(valid, arr_file_fid=0x6F06, arr_record=0x100),
        )

        for spec in invalid_specs:
            with self.subTest(spec=spec):
                with self.assertRaises(FilesystemMutationError):
                    materialize_filesystem_document((spec,), self.workspace_root)

    def test_explicit_mf_iccid_binding_preserves_2fe2_without_gfm_duplicate(self) -> None:
        iccid_content = bytes.fromhex("98112233445566778899")
        entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x2FE2,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=10,
                literal_content=iccid_content,
                mf_field_name="ef-iccid",
            ),
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x2F05,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=2,
                literal_content=b"en",
            ),
        )

        result = materialize_filesystem_document(entries, self.workspace_root)
        self.assertEqual(result.summary.reconciled_mf_fids, (0x2FE2,))
        self.assertEqual(result.summary.gfm_parent_paths, ((0x3F00,),))
        mf_iccid = result.document["sections"]["mf"]["ef-iccid"]
        self.assertEqual(mf_iccid[0][0], "fileDescriptor")
        self.assertEqual(mf_iccid[0][1]["fileID"], bytes.fromhex("2FE2"))
        self.assertNotIn("securityAttributesReferenced", mf_iccid[0][1])
        self.assertEqual(mf_iccid[1], ("fillFileContent", iccid_content))

        gfm_fcps = self._created_fcps(self._gfm_sections(result.document)[0])
        self.assertEqual([fcp["fileID"] for fcp in gfm_fcps], [bytes.fromhex("2F05")])

        decoded = self._decode(result.document)
        decoded_mf = decoded.get_pes_for_type("mf")[0].decoded
        self.assertEqual(
            decoded_mf["ef-iccid"][0][1]["fileID"],
            bytes.fromhex("2FE2"),
        )
        decoded_gfm_paths = {
            path for pe in decoded.get_pes_for_type("genericFileManagement") for path in pe.files
        }
        self.assertNotIn("3F00/2FE2", decoded_gfm_paths)

        automatic = materialize_filesystem_document(
            (
                FilesystemEntrySpec(
                    parent_fid_path=(0x3F00,),
                    fid=0x2F02,
                    kind=FilesystemNodeKind.EF,
                    structure=ElementaryFileStructure.TRANSPARENT,
                    file_size=10,
                ),
            ),
            self.workspace_root,
        )
        self.assertEqual(automatic.summary.reconciled_mf_fids, (0x2F02,))
        self.assertEqual(automatic.summary.gfm_parent_paths, ())

        standard_automatic = materialize_filesystem_document(
            (
                FilesystemEntrySpec(
                    parent_fid_path=(0x3F00,),
                    fid=0x2FE2,
                    kind=FilesystemNodeKind.EF,
                    structure=ElementaryFileStructure.TRANSPARENT,
                    file_size=10,
                ),
            ),
            self.workspace_root,
        )
        self.assertEqual(standard_automatic.summary.reconciled_mf_fids, (0x2FE2,))
        self.assertEqual(standard_automatic.summary.gfm_parent_paths, ())

    def test_rejects_invalid_tree_geometry_and_mf_bindings(self) -> None:
        invalid_cases = {
            "duplicate path": (
                FilesystemEntrySpec((0x3F00,), 0x7F10, FilesystemNodeKind.DF),
                FilesystemEntrySpec((0x3F00,), 0x7F10, FilesystemNodeKind.DF),
            ),
            "orphan child": (
                FilesystemEntrySpec(
                    (0x3F00, 0x7F10),
                    0x6F01,
                    FilesystemNodeKind.EF,
                    ElementaryFileStructure.TRANSPARENT,
                    file_size=1,
                ),
            ),
            "short DF name": (
                FilesystemEntrySpec(
                    (0x3F00,),
                    0x7F20,
                    FilesystemNodeKind.ADF,
                    df_name=b"bad",
                ),
            ),
            "record size mismatch": (
                FilesystemEntrySpec(
                    (0x3F00,),
                    0x6F02,
                    FilesystemNodeKind.EF,
                    ElementaryFileStructure.LINEAR_FIXED,
                    file_size=5,
                    record_length=2,
                    record_count=3,
                ),
            ),
            "duplicate MF field": (
                FilesystemEntrySpec(
                    (0x3F00,),
                    0x2F02,
                    FilesystemNodeKind.EF,
                    ElementaryFileStructure.TRANSPARENT,
                    file_size=10,
                ),
                FilesystemEntrySpec(
                    (0x3F00,),
                    0x2FE2,
                    FilesystemNodeKind.EF,
                    ElementaryFileStructure.TRANSPARENT,
                    file_size=10,
                    mf_field_name="ef-iccid",
                ),
            ),
        }

        for label, entries in invalid_cases.items():
            with self.subTest(label=label):
                with self.assertRaises(FilesystemMutationError):
                    materialize_filesystem_document(entries, self.workspace_root)

    def test_native_usim_optional_and_phonebook_tree_uses_no_gfm(self) -> None:
        aid = bytes.fromhex("A0000000871002FF86FFFF89FFFFFFFF")
        imsi_content = bytes.fromhex("081122334455667788")
        pnn_content = bytes(range(32))
        pbr_content = bytes(range(20))
        entries = (
            NativeFilesystemEntrySpec(
                menu_id="usim",
                pe_name="adf-usim",
                fid=None,
                kind=FilesystemNodeKind.ADF,
                df_name=aid,
                arr_record=10,
            ),
            NativeFilesystemEntrySpec(
                menu_id="usim",
                pe_name="ef-imsi",
                fid=0x6F07,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=9,
                sfi=7,
                literal_content=imsi_content,
                arr_record=2,
            ),
            NativeFilesystemEntrySpec(
                menu_id="opt-usim",
                pe_name="ef-pnn",
                fid=0x6FC5,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.LINEAR_FIXED,
                record_length=16,
                record_count=2,
                sfi=25,
                literal_content=pnn_content,
                arr_record=10,
            ),
            NativeFilesystemEntrySpec(
                menu_id="phonebook",
                pe_name="df-phonebook",
                fid=0x5F3A,
                kind=FilesystemNodeKind.DF,
                lifecycle=0x07,
                arr_record=14,
            ),
            NativeFilesystemEntrySpec(
                menu_id="phonebook",
                pe_name="ef-pbr",
                fid=0x4F30,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.LINEAR_FIXED,
                record_length=20,
                record_count=1,
                literal_content=pbr_content,
                arr_record=2,
            ),
        )

        result = materialize_native_filesystem_document(
            reversed(entries),
            self.workspace_root,
        )
        forward = materialize_native_filesystem_document(entries, self.workspace_root)

        self.assertEqual(
            tuple(result.document["sections"]),
            ("header", "mf", "usim", "opt-usim", "phonebook", "end"),
        )
        self.assertFalse(
            any(key.startswith("genericFileManagement") for key in result.document["sections"])
        )
        self.assertEqual(
            result.summary.native_menu_ids,
            ("mf", "usim", "opt-usim", "phonebook"),
        )
        self.assertEqual(result.summary.native_entry_count, 5)
        self.assertEqual(result.summary.fallback_entry_count, 0)
        self.assertEqual(result.summary.gfm_parent_paths, ())
        self.assertEqual(
            result.summary.inherited_temporary_fids,
            (NativeTemporaryFidAssignment("usim", "adf-usim", 0x7FF0),),
        )

        reverse_der = build_profile_sequence_from_document(
            result.document,
            self.workspace_root,
        ).to_der()
        forward_der = build_profile_sequence_from_document(
            forward.document,
            self.workspace_root,
        ).to_der()
        self.assertEqual(reverse_der, forward_der)

        usim = result.document["sections"]["usim"]
        self.assertTrue({"adf-usim", "ef-imsi", "ef-arr", "ef-ust", "ef-spn"}.issubset(usim))
        adf_descriptor = dict(usim["adf-usim"])["fileDescriptor"]
        self.assertEqual(adf_descriptor["fileID"], bytes.fromhex("7FF0"))
        self.assertEqual(adf_descriptor["dfName"], aid)
        self.assertEqual(adf_descriptor["securityAttributesReferenced"], b"\x0a")
        self.assertNotEqual(adf_descriptor["fileID"], bytes.fromhex("7FFF"))
        self.assertNotIn("pinStatusTemplateDO", adf_descriptor)
        imsi_descriptor = dict(usim["ef-imsi"])["fileDescriptor"]
        self.assertEqual(imsi_descriptor["fileID"], bytes.fromhex("6F07"))
        self.assertEqual(imsi_descriptor["shortEFID"], b"\x38")
        self.assertEqual(imsi_descriptor["securityAttributesReferenced"], b"\x02")
        self.assertEqual(dict(usim["ef-imsi"])["fillFileContent"], imsi_content)

        opt_usim = result.document["sections"]["opt-usim"]
        pnn_descriptor = dict(opt_usim["ef-pnn"])["fileDescriptor"]
        self.assertEqual(pnn_descriptor["fileID"], bytes.fromhex("6FC5"))
        self.assertEqual(pnn_descriptor["efFileSize"], b"\x20")
        self.assertEqual(pnn_descriptor["fileDescriptor"], bytes.fromhex("42210010"))
        self.assertEqual(dict(opt_usim["ef-pnn"])["fillFileContent"], pnn_content)

        phonebook = result.document["sections"]["phonebook"]
        phonebook_descriptor = dict(phonebook["df-phonebook"])["fileDescriptor"]
        self.assertEqual(phonebook_descriptor["fileID"], bytes.fromhex("5F3A"))
        self.assertEqual(phonebook_descriptor["lcsi"], b"\x07")
        self.assertNotIn("pinStatusTemplateDO", phonebook_descriptor)
        pbr_descriptor = dict(phonebook["ef-pbr"])["fileDescriptor"]
        self.assertEqual(pbr_descriptor["fileID"], bytes.fromhex("4F30"))
        self.assertEqual(pbr_descriptor["fileDescriptor"], bytes.fromhex("42210014"))
        self.assertEqual(dict(phonebook["ef-pbr"])["fillFileContent"], pbr_content)

        decoded = self._decode(result.document)
        self.assertEqual(
            [pe.type for pe in decoded.pe_list],
            ["header", "mf", "usim", "opt-usim", "phonebook", "end"],
        )
        decoded_usim = decoded.get_pes_for_type("usim")[0]
        self.assertEqual(decoded_usim.files["adf-usim"].fid, 0x7FF0)
        self.assertEqual(decoded_usim.files["ef-imsi"].body, imsi_content)
        decoded_optional = decoded.get_pes_for_type("opt-usim")[0]
        self.assertEqual(decoded_optional.files["ef-pnn"].body, pnn_content)
        decoded_phonebook = decoded.get_pes_for_type("phonebook")[0]
        self.assertEqual(decoded_phonebook.files["ef-pbr"].body, pbr_content)

    def test_logical_sfi_is_wire_encoded_once_for_gfm_and_native_files(self) -> None:
        fallback = materialize_filesystem_document(
            (
                FilesystemEntrySpec(
                    parent_fid_path=(0x3F00,),
                    fid=0x6F07,
                    kind=FilesystemNodeKind.EF,
                    structure=ElementaryFileStructure.TRANSPARENT,
                    file_size=9,
                    sfi=0x07,
                ),
            ),
            self.workspace_root,
        )
        fallback_descriptor = self._created_fcps(self._gfm_sections(fallback.document)[0])[0]
        self.assertEqual(fallback_descriptor["shortEFID"], b"\x38")

        native = materialize_native_filesystem_document(
            (
                NativeFilesystemEntrySpec(
                    menu_id="phonebook",
                    pe_name="ef-adn",
                    fid=0x4F58,
                    kind=FilesystemNodeKind.EF,
                    structure=ElementaryFileStructure.LINEAR_FIXED,
                    record_length=20,
                    record_count=1,
                    sfi=0x1A,
                ),
            ),
            self.workspace_root,
        )
        adn_descriptor = dict(native.document["sections"]["phonebook"]["ef-adn"])["fileDescriptor"]
        self.assertEqual(adn_descriptor["shortEFID"], b"\xd0")

        # DER decode/re-encode consumes an already encoded descriptor.  It
        # must preserve D0 rather than applying the logical-SFI shift again.
        sequence = build_profile_sequence_from_document(native.document, self.workspace_root)
        encoded = sequence.to_der()
        decoded = self._ProfileElementSequence.from_der(encoded)
        decoded_adn_descriptor = dict(decoded.get_pes_for_type("phonebook")[0].decoded["ef-adn"])[
            "fileDescriptor"
        ]
        self.assertEqual(decoded_adn_descriptor["shortEFID"], b"\xd0")
        self.assertEqual(decoded.to_der(), encoded)

    def test_native_mf_preserves_2fe2_and_only_supplied_fallback_uses_gfm(self) -> None:
        iccid_content = bytes.fromhex("98112233445566778899")
        native_entries = (
            NativeFilesystemEntrySpec(
                menu_id="mf",
                pe_name="ef-iccid",
                fid=0x2FE2,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=10,
                literal_content=iccid_content,
                arr_record=1,
            ),
        )
        fallback_entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00,),
                fid=0x2F05,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=2,
                literal_content=b"en",
            ),
        )

        result = materialize_native_filesystem_document(
            native_entries,
            self.workspace_root,
            fallback_entries=fallback_entries,
        )

        self.assertEqual(
            tuple(result.document["sections"]),
            ("header", "mf", "genericFileManagement", "end"),
        )
        self.assertEqual(result.summary.reconciled_mf_fids, (0x2FE2,))
        self.assertEqual(result.summary.native_entry_count, 1)
        self.assertEqual(result.summary.fallback_entry_count, 1)
        self.assertEqual(result.summary.gfm_parent_paths, ((0x3F00,),))
        iccid_descriptor = dict(result.document["sections"]["mf"]["ef-iccid"])["fileDescriptor"]
        self.assertEqual(iccid_descriptor["fileID"], bytes.fromhex("2FE2"))
        self.assertEqual(iccid_descriptor["securityAttributesReferenced"], b"\x01")
        gfm_fcps = self._created_fcps(result.document["sections"]["genericFileManagement"])
        self.assertEqual([fcp["fileID"] for fcp in gfm_fcps], [bytes.fromhex("2F05")])

        decoded = self._decode(result.document)
        decoded_mf = decoded.get_pes_for_type("mf")[0]
        self.assertEqual(decoded_mf.files["ef-iccid"].fid, 0x2FE2)
        decoded_gfm = decoded.get_pes_for_type("genericFileManagement")[0]
        self.assertEqual(set(decoded_gfm.files), {"3F00/2F05"})

    def test_native_mf_root_preserves_source_arr_reference(self) -> None:
        entries = (
            NativeFilesystemEntrySpec(
                menu_id="mf",
                pe_name="mf",
                fid=0x3F00,
                kind=FilesystemNodeKind.MF,
                lifecycle=0x07,
                arr_record=1,
            ),
            NativeFilesystemEntrySpec(
                menu_id="mf",
                pe_name="ef-arr",
                fid=0x2F06,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.LINEAR_FIXED,
                record_length=2,
                record_count=2,
            ),
        )

        result = materialize_native_filesystem_document(entries, self.workspace_root)

        self.assertEqual(tuple(result.document["sections"]), ("header", "mf", "end"))
        root_descriptor = dict(result.document["sections"]["mf"]["mf"])["fileDescriptor"]
        self.assertEqual(root_descriptor["fileID"], bytes.fromhex("3F00"))
        self.assertEqual(root_descriptor["securityAttributesReferenced"], b"\x01")
        self.assertEqual(root_descriptor["lcsi"], b"\x07")
        self.assertEqual(result.summary.reconciled_mf_fids, (0x2F06,))
        self.assertEqual(result.summary.native_entry_count, 2)

        decoded = self._decode(result.document).get_pes_for_type("mf")[0]
        self.assertEqual(decoded.files["mf"].fid, 0x3F00)
        self.assertEqual(decoded.files["mf"].arr, b"\x01")
        decoded_root_descriptor = dict(decoded.decoded["mf"])["fileDescriptor"]
        self.assertEqual(decoded_root_descriptor["lcsi"], b"\x07")

    def test_native_registry_alias_uses_real_asn_field_and_exact_template_fid(self) -> None:
        content = bytes.fromhex("010203")
        spec = NativeFilesystemEntrySpec(
            menu_id="opt-usim",
            pe_name="ef-acmax",
            fid=0x6F37,
            kind=FilesystemNodeKind.EF,
            structure=ElementaryFileStructure.TRANSPARENT,
            file_size=3,
            literal_content=content,
            arr_record=5,
        )

        result = materialize_native_filesystem_document((spec,), self.workspace_root)
        optional = result.document["sections"]["opt-usim"]
        self.assertIn("ef-acmax", optional)
        self.assertNotIn("ef-acmmax", optional)
        descriptor = dict(optional["ef-acmax"])["fileDescriptor"]
        self.assertEqual(descriptor["fileID"], bytes.fromhex("6F37"))
        self.assertEqual(dict(optional["ef-acmax"])["fillFileContent"], content)

        decoded = self._decode(result.document).get_pes_for_type("opt-usim")[0]
        self.assertEqual(decoded.files["ef-acmax"].fid, 0x6F37)
        self.assertEqual(decoded.files["ef-acmax"].body, content)

        wrong_fid = replace(spec, fid=0x6F38)
        with self.assertRaisesRegex(FilesystemMutationError, "template FID 6F37"):
            materialize_native_filesystem_document((wrong_fid,), self.workspace_root)

        wrong_structure = replace(
            spec,
            structure=ElementaryFileStructure.LINEAR_FIXED,
            file_size=None,
            record_length=3,
            record_count=1,
        )
        with self.assertRaisesRegex(FilesystemMutationError, "structure"):
            materialize_native_filesystem_document((wrong_structure,), self.workspace_root)

    def test_gfm_fallback_can_select_inherited_native_adf_context(self) -> None:
        native_entries = (
            NativeFilesystemEntrySpec(
                menu_id="usim",
                pe_name="adf-usim",
                fid=None,
                kind=FilesystemNodeKind.ADF,
                df_name=bytes.fromhex("A0000000871002"),
            ),
        )
        fallback_entries = (
            FilesystemEntrySpec(
                parent_fid_path=(0x3F00, 0x7FF0),
                fid=0x6FFF,
                kind=FilesystemNodeKind.EF,
                structure=ElementaryFileStructure.TRANSPARENT,
                file_size=3,
                literal_content=b"xyz",
            ),
        )

        result = materialize_native_filesystem_document(
            native_entries,
            self.workspace_root,
            fallback_entries=fallback_entries,
        )

        self.assertEqual(
            tuple(result.document["sections"]),
            ("header", "mf", "usim", "genericFileManagement", "end"),
        )
        self.assertEqual(result.summary.gfm_parent_paths, ((0x3F00, 0x7FF0),))
        transaction = result.document["sections"]["genericFileManagement"]["fileManagementCMD"][0]
        self.assertEqual(transaction[0], ("filePath", bytes.fromhex("7FF0")))
        fcp = self._created_fcps(result.document["sections"]["genericFileManagement"])[0]
        self.assertEqual(fcp["fileID"], bytes.fromhex("6FFF"))
        self.assertNotIn("securityAttributesReferenced", fcp)

        decoded = self._decode(result.document)
        decoded_gfm = decoded.get_pes_for_type("genericFileManagement")[0]
        self.assertEqual(set(decoded_gfm.files), {"3F00/7FF0/6FFF"})
        self.assertEqual(decoded_gfm.files["3F00/7FF0/6FFF"].body, b"xyz")

    def test_native_validation_rejects_bad_arr_and_duplicate_fields(self) -> None:
        self.assertIn("usim", NATIVE_TEMPLATE_MENU_IDS)
        self.assertIn("phonebook", NATIVE_TEMPLATE_MENU_IDS)
        self.assertNotIn("csim", NATIVE_TEMPLATE_MENU_IDS)
        self.assertEqual(native_temporary_fid("usim", "adf-usim"), 0x7FF0)
        self.assertEqual(native_temporary_fid("isim", "adf-isim"), 0x7FF2)
        self.assertIsNone(native_temporary_fid("phonebook", "df-phonebook"))

        bad_arr = NativeFilesystemEntrySpec(
            menu_id="opt-usim",
            pe_name="ef-pnn",
            fid=0x6FC5,
            kind=FilesystemNodeKind.EF,
            structure=ElementaryFileStructure.LINEAR_FIXED,
            record_length=16,
            record_count=1,
            arr_record=0,
        )
        with self.assertRaises(FilesystemMutationError):
            materialize_native_filesystem_document((bad_arr,), self.workspace_root)

        invalid_mf = NativeFilesystemEntrySpec(
            menu_id="usim",
            pe_name="mf",
            fid=0x3F00,
            kind=FilesystemNodeKind.MF,
        )
        with self.assertRaisesRegex(FilesystemMutationError, "only as"):
            materialize_native_filesystem_document((invalid_mf,), self.workspace_root)

        fallback_mf = FilesystemEntrySpec(
            parent_fid_path=(0x3F00,),
            fid=0x7F00,
            kind=FilesystemNodeKind.MF,
        )
        with self.assertRaisesRegex(FilesystemMutationError, "fallback/GFM"):
            materialize_filesystem_document((fallback_mf,), self.workspace_root)

        duplicate = NativeFilesystemEntrySpec(
            menu_id="mf",
            pe_name="ef-iccid",
            fid=0x2FE2,
            kind=FilesystemNodeKind.EF,
            structure=ElementaryFileStructure.TRANSPARENT,
            file_size=10,
        )
        with self.assertRaises(FilesystemMutationError):
            materialize_native_filesystem_document(
                (duplicate, duplicate),
                self.workspace_root,
            )

        source_adf = NativeFilesystemEntrySpec(
            menu_id="usim",
            pe_name="adf-usim",
            fid=0x7FFF,
            kind=FilesystemNodeKind.ADF,
            df_name=bytes.fromhex("A0000000871002"),
        )
        source_result = materialize_native_filesystem_document(
            (source_adf,),
            self.workspace_root,
        )
        source_descriptor = dict(source_result.document["sections"]["usim"]["adf-usim"])[
            "fileDescriptor"
        ]
        self.assertEqual(source_descriptor["fileID"], bytes.fromhex("7FFF"))
        self.assertEqual(
            source_descriptor["dfName"],
            bytes.fromhex("A0000000871002"),
        )
        self.assertEqual(source_result.summary.inherited_temporary_fids, ())

        unresolved_source_selector = NativeFilesystemEntrySpec(
            menu_id="usim",
            pe_name="adf-usim",
            fid=0x7FFF,
            kind=FilesystemNodeKind.ADF,
        )
        with self.assertRaisesRegex(FilesystemMutationError, "no concrete DF name/AID"):
            materialize_native_filesystem_document(
                (unresolved_source_selector,),
                self.workspace_root,
            )

        for menu_id in ("csim", "opt-csim", "iot", "opt-iot"):
            with self.subTest(menu_id=menu_id):
                skeleton_entry = NativeFilesystemEntrySpec(
                    menu_id=menu_id,
                    pe_name="ef-placeholder",
                    fid=0x6F01,
                    kind=FilesystemNodeKind.EF,
                    structure=ElementaryFileStructure.TRANSPARENT,
                    file_size=1,
                )
                with self.assertRaisesRegex(FilesystemMutationError, "GFM fallback"):
                    materialize_native_filesystem_document(
                        (skeleton_entry,),
                        self.workspace_root,
                    )

    def test_native_lifecycle_omission_accepts_canonical_der_default(self) -> None:
        spec = NativeFilesystemEntrySpec(
            menu_id="mf",
            pe_name="ef-arr",
            fid=0x2F06,
            kind=FilesystemNodeKind.EF,
            structure=ElementaryFileStructure.LINEAR_FIXED,
            record_length=1,
            record_count=1,
            lifecycle=None,
        )

        result = materialize_native_filesystem_document(
            (spec,),
            self.workspace_root,
        )
        authored_descriptor = dict(result.document["sections"]["mf"]["ef-arr"])["fileDescriptor"]
        self.assertNotIn("lcsi", authored_descriptor)

        decoded = self._decode(result.document)
        decoded_descriptor = dict(decoded.get_pes_for_type("mf")[0].decoded["ef-arr"])[
            "fileDescriptor"
        ]
        self.assertEqual(decoded_descriptor["lcsi"], b"\x05")


if __name__ == "__main__":
    unittest.main()
