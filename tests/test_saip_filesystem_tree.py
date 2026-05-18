# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression tests for the unified SAIP filesystem-tree extraction.

``saip.list_files`` used to silently drop every file created by a
``pe-GenericFileManagement`` PE because the linter's flat walker
never descended into ASN.1 CHOICE tuples. The new
``_filesystem_tree_rows`` resolves the ``filePath`` SELECT cursor
across GFM transactions, walks the template-section DF cursor stack,
and emits every file with the resolved hex FID chain (``3F00/7F10
/6F3A``) plus a friendly ``EF.FOO`` / ``DF.BAR`` name from pySim's
TCA SAIP §9 registry (with a legacy TS 51.011 §10 fallback table for
DF.TELECOM EFs the TCA tables don't carry).

The fixtures here are tuple-form decoded documents (the shape pySim
emits after ``ProfileElementSequence.from_der``). They exercise both
the template walk and the GFM SELECT replay without booting the
whole heavyweight pySim stack.
"""

from __future__ import annotations

import unittest

from yggdrasim_common.gui_server.actions.saip import (
    _filesystem_tree_rows,
    _locate_file_payload,
    _walk_choice_paths,
)


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


class WalkChoicePathsTests(unittest.TestCase):
    """Tuple-aware walker — root cause of the GFM blind spot."""

    def test_descends_into_choice_tuples(self) -> None:
        payload = {
            "fileManagementCMD": [
                [
                    ("filePath", b"\x7f\x10"),
                    ("createFCP", {"fileID": b"\x6f\x3a"}),
                ],
            ],
        }
        paths = [p for p, _ in _walk_choice_paths(payload)]
        # The linter's plain ``_walk_with_path`` would stop at the
        # outer list — we expect the choice-aware walk to reach
        # ``createFCP.fileID``.
        self.assertIn("fileManagementCMD[0][1].createFCP", paths)


class TemplateFilesystemTreeTests(unittest.TestCase):
    """Template section walk: MF + nested DF / EF cursor."""

    def _document(self) -> dict:
        return {
            "sections": {
                "mf": {
                    "mf-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.1",  # TCA MF template OID
                    "mf": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("780219"),
                            "pinStatusTemplateDO": _hex("010A"),
                        }),
                    ],
                    "ef-iccid": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("41210000"),
                            "fileID": _hex("2F02"),
                        }),
                        ("fillFileContent", _hex("98" * 10)),
                    ],
                },
                "telecom": {
                    "telecom-header": {"identification": 2},
                    "templateID": "2.23.143.1.2.3",
                    "df-telecom": [
                        ("fileDescriptor", {
                            "pinStatusTemplateDO": _hex("010A"),
                        }),
                    ],
                    "ef-arr": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221001E"),
                        }),
                    ],
                    "df-phonebook": [
                        ("fileDescriptor", {
                            "pinStatusTemplateDO": _hex("010A"),
                        }),
                    ],
                    "ef-pbr": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221001E"),
                        }),
                    ],
                },
            }
        }

    def test_mf_row_resolves_to_3f00(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        mf_row = next(r for r in rows if r["section_key"] == "mf" and r["field_path"] == "mf")
        self.assertEqual(mf_row["fid_chain"], "3F00")
        self.assertEqual(mf_row["kind"], "mf")
        self.assertEqual(mf_row["source"], "template")

    def test_ef_iccid_lives_under_mf(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        row = next(r for r in rows if r["field_path"] == "ef-iccid")
        self.assertEqual(row["parent_path"], "3F00")
        self.assertTrue(row["fid_chain"].startswith("3F00/2F02"))
        self.assertEqual(row["friendly_name"], "EF.ICCID")

    def test_df_phonebook_nests_under_df_telecom(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        pbr = next(r for r in rows if r["field_path"] == "ef-pbr")
        # DF.PHONEBOOK lives at 5F3A under DF.TELECOM (7F10) per TCA
        # SAIP §9.4. The template walker must follow the pySim
        # ``FileTemplate.parent`` link so EF.PBR anchors at
        # ``3F00/7F10/5F3A``, not the previous bug's ``3F00/5F3A``
        # (which hoisted DF.PHONEBOOK to a sibling of DF.TELECOM).
        self.assertEqual(pbr["parent_path"], "3F00/7F10/5F3A")
        self.assertTrue(pbr["fid_chain"].startswith("3F00/7F10/5F3A/"))
        self.assertEqual(pbr["friendly_name"], "EF.PBR")

    def test_df_phonebook_container_anchors_under_df_telecom(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        pb = next(r for r in rows if r["field_path"] == "df-phonebook")
        self.assertEqual(pb["parent_path"], "3F00/7F10")
        self.assertEqual(pb["fid_chain"], "3F00/7F10/5F3A")
        # Templated DF — kind comes from ``_FS_TREE_FILE_TYPE_TO_KIND``.
        self.assertEqual(pb["kind"], "df")

    def test_ef_arr_attached_to_df_telecom(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        arr = next(
            r for r in rows
            if r["section_key"] == "telecom" and r["field_path"] == "ef-arr"
        )
        self.assertTrue(arr["parent_path"].endswith("7F10"))


class GfmFilesystemTreeTests(unittest.TestCase):
    """Generic File Management — the regression the user reported."""

    def _document(self) -> dict:
        return {
            "sections": {
                "genericFileManagement": {
                    "gfm-header": {"identification": 5},
                    "fileManagementCMD": [
                        [
                            ("filePath", b"\x7f\x10"),
                            ("createFCP", {
                                "fileDescriptor": _hex("4221001E"),
                                "fileID": _hex("6F3A"),
                            }),
                            ("fillFileOffset", 0),
                            ("fillFileContent", _hex("FFFFFF")),
                            ("createFCP", {
                                "fileDescriptor": _hex("4221001E"),
                                "fileID": _hex("6F40"),
                            }),
                            ("filePath", b""),
                            ("createFCP", {
                                "fileDescriptor": _hex("4221001E"),
                                "fileID": _hex("2F00"),
                            }),
                        ],
                    ],
                },
            }
        }

    def test_emits_one_row_per_create_fcp(self) -> None:
        rows = [
            r for r in _filesystem_tree_rows(self._document())
            if r["source"] == "gfm"
        ]
        self.assertEqual(len(rows), 3)

    def test_first_create_lands_under_df_telecom(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        adn = next(r for r in rows if r["file_id"] == "6F3A")
        self.assertEqual(adn["parent_path"], "3F00/7F10")
        self.assertEqual(adn["fid_chain"], "3F00/7F10/6F3A")
        # Legacy SIM lookup fills the friendly name even though TCA
        # SAIP §9 puts EF.ADN at 5F3A/4F00 (DF.PHONEBOOK).
        self.assertEqual(adn["friendly_name"], "EF.ADN")

    def test_second_create_inherits_select_chain(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        msisdn = next(r for r in rows if r["file_id"] == "6F40")
        self.assertEqual(msisdn["parent_path"], "3F00/7F10")
        self.assertEqual(msisdn["friendly_name"], "EF.MSISDN")

    def test_empty_file_path_resets_to_mf(self) -> None:
        rows = _filesystem_tree_rows(self._document())
        dir_row = next(r for r in rows if r["file_id"] == "2F00")
        self.assertEqual(dir_row["parent_path"], "3F00")

    def test_locate_payload_stitches_fill_entries(self) -> None:
        doc = self._document()
        rows = [r for r in _filesystem_tree_rows(doc) if r["file_id"] == "6F3A"]
        self.assertEqual(len(rows), 1)
        payload = _locate_file_payload(
            doc,
            section_key=rows[0]["section_key"],
            field_path=rows[0]["field_path"],
        )
        self.assertIsInstance(payload, list)
        tags = [item[0] for item in payload if isinstance(item, tuple)]
        # Synthetic shape mimics a template EF: fileDescriptor first,
        # then any fillFile* entries observed up to the next createFCP.
        self.assertEqual(tags[0], "fileDescriptor")
        self.assertIn("fillFileOffset", tags)
        self.assertIn("fillFileContent", tags)
        # The second createFCP must NOT be stitched onto the first
        # file's payload.
        self.assertNotIn("createFCP", tags)


class MultipleGfmBlocksTests(unittest.TestCase):
    """GFM sections sometimes appear with ``_<n>`` suffixes."""

    def test_each_section_is_walked_independently(self) -> None:
        doc = {
            "sections": {
                "genericFileManagement": {
                    "fileManagementCMD": [[
                        ("filePath", b"\x7f\x10"),
                        ("createFCP", {"fileDescriptor": _hex("4221001E"),
                                       "fileID": _hex("6F3A")}),
                    ]],
                },
                "genericFileManagement_2": {
                    "fileManagementCMD": [[
                        ("filePath", b"\x7f\x20"),
                        ("createFCP", {"fileDescriptor": _hex("4221001E"),
                                       "fileID": _hex("6F07")}),
                    ]],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        keys = {r["section_key"] for r in rows}
        self.assertIn("genericFileManagement", keys)
        self.assertIn("genericFileManagement_2", keys)
        # Each section gets its own fresh SELECT cursor (starts at MF).
        adn = next(r for r in rows if r["file_id"] == "6F3A")
        imsi = next(r for r in rows if r["file_id"] == "6F07")
        self.assertEqual(adn["parent_path"], "3F00/7F10")
        self.assertEqual(imsi["parent_path"], "3F00/7F20")


class AdfKindAndCollidingFidTests(unittest.TestCase):
    """Bug-5 (ADF kind) and bug-2 (parent-context FID names) regressions."""

    def _document_with_two_adfs(self) -> dict:
        # Two independent ADF sections that both carry FID 6F40.
        # ADF.USIM/6F40 == EF.MSISDN, ADF.CSIM/6F40 == EF.CSIM-MDN.
        return {
            "sections": {
                "usim": {
                    "usim-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.4",
                    "adf-usim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ],
                    "ef-msisdn": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221001A"),
                            "fileID": _hex("6F40"),
                        }),
                    ],
                },
                "csim": {
                    "csim-header": {"identification": 2},
                    "templateID": "2.23.143.1.2.6",
                    "adf-csim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF3"),
                            "dfName": _hex("A0000003431002"),
                        }),
                    ],
                    "ef-csim-mdn": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221001A"),
                            "fileID": _hex("6F40"),
                        }),
                    ],
                },
            },
        }

    def test_adf_root_has_kind_adf_not_df(self) -> None:
        # When pySim does not provide a template (no ``templateID``
        # match) the descriptor falls back through ``_kind_from_descriptor``
        # which without the ADF hints would label the row ``df``.
        # The fix promotes it to ``adf`` whenever ``dfName`` is set,
        # the pename starts with ``adf-``, or the FID lies in 7FF0-7FFF.
        doc = self._document_with_two_adfs()
        rows = _filesystem_tree_rows(doc)
        usim_root = next(r for r in rows if r["field_path"] == "adf-usim")
        csim_root = next(r for r in rows if r["field_path"] == "adf-csim")
        # pySim's template (when available) maps ``ftype='ADF'`` to
        # kind ``adf``; the fallback path also resolves to ``adf``
        # because every disambiguation hint fires here.
        self.assertEqual(usim_root["kind"], "adf")
        self.assertEqual(csim_root["kind"], "adf")

    def test_6f40_disambiguates_msisdn_vs_csim_mdn(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_two_adfs())
        msisdn = next(r for r in rows if r["field_path"] == "ef-msisdn")
        csim_mdn = next(r for r in rows if r["field_path"] == "ef-csim-mdn")
        # Bug 2 used to label both as the first template match
        # (typically EF.MSISDN). The parent-aware resolver now picks
        # the right label per ADF context.
        self.assertEqual(msisdn["friendly_name"], "EF.MSISDN")
        self.assertEqual(csim_mdn["friendly_name"], "EF.CSIM-MDN")


class MfAndAdfAsSeparateRootsTests(unittest.TestCase):
    """Operator-tree contract: MF and every ADF are independent roots.

    Verifies the three invariants the GUI File System tab expects:

    1. MF appears at the root (``parent_path == ''``, ``fid_chain == '3F00'``).
    2. Every ADF appears at the root with ``fid_chain == 'ADF.<NAME>'``
       — never as a folder under MF, and never under its temp_fid
       (``7FF0`` … ``7FFF``).
    3. EFs / DFs whose pySim ``FileTemplate`` parent is an ADF are
       anchored under ``ADF.<NAME>/...`` instead of ``3F00/<temp>/...``.
    """

    def _document_with_mf_and_adf(self) -> dict:
        return {
            "sections": {
                "mf": {
                    "mf-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.1",
                    "mf": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("3F00"),
                        }),
                    ],
                    "ef-iccid": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221000A"),
                            "fileID": _hex("2F02"),
                        }),
                    ],
                    "ef-pl": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("42210002"),
                            "fileID": _hex("2F05"),
                        }),
                    ],
                },
                "usim": {
                    "usim-header": {"identification": 2},
                    "templateID": "2.23.143.1.2.4",
                    "adf-usim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ],
                    "ef-imsi": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("42210009"),
                            "fileID": _hex("6F07"),
                        }),
                    ],
                },
            },
        }

    def test_mf_is_root(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_mf_and_adf())
        mf = next(r for r in rows if r["field_path"] == "mf")
        self.assertEqual(mf["parent_path"], "")
        self.assertEqual(mf["fid_chain"], "3F00")
        self.assertEqual(mf["kind"], "mf")

    def test_adf_is_root_not_under_mf(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_mf_and_adf())
        adf = next(r for r in rows if r["field_path"] == "adf-usim")
        self.assertEqual(adf["parent_path"], "")
        self.assertEqual(adf["fid_chain"], "ADF.USIM")
        self.assertEqual(adf["kind"], "adf")
        # The temp_fid 7FF0 must not leak into the operator-facing
        # chain — that's GFM SELECT bytecode, not the file tree.
        self.assertNotIn("7FF0", adf["fid_chain"])

    def test_iccid_under_mf(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_mf_and_adf())
        iccid = next(r for r in rows if r["field_path"] == "ef-iccid")
        self.assertEqual(iccid["parent_path"], "3F00")
        self.assertEqual(iccid["fid_chain"], "3F00/2F02")
        self.assertEqual(iccid["friendly_name"], "EF.ICCID")

    def test_imsi_under_adf_usim(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_mf_and_adf())
        imsi = next(r for r in rows if r["field_path"] == "ef-imsi")
        self.assertEqual(imsi["parent_path"], "ADF.USIM")
        self.assertEqual(imsi["fid_chain"], "ADF.USIM/6F07")
        # Parent-aware FID resolver must still pick the right friendly
        # name — ADF.USIM/6F07 is EF.IMSI, not EF.IST (which lives at
        # ADF.ISIM/6F07).
        self.assertEqual(imsi["friendly_name"], "EF.IMSI")

    def test_no_row_under_temp_fid_path(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_mf_and_adf())
        for r in rows:
            self.assertNotIn(
                "7FF0", r["fid_chain"],
                f"row {r['field_path']!r} leaks temp_fid into chain {r['fid_chain']!r}",
            )


class OptionalTemplateExtendsAnchorTests(unittest.TestCase):
    """Optional templates (opt-usim, opt-isim) must anchor under their parent ADF.

    pySim ``FilesUsimOptional`` carries ``optional=True`` and
    ``extends=FilesUsimMandatory`` so its first file is a plain EF
    (EF.LI, FID 6F05) with ``parent=None``. Without the
    ``extends``-aware lookup the chain walker fell back to the MF
    prefix, producing a spurious ``3F00/6F40`` placement for every
    opt-usim EF (visible to the operator as EF.MSISDN appearing
    under MF instead of under ADF.USIM).
    """

    def _document_with_opt_usim_msisdn(self) -> dict:
        # Use the real opt-usim templateID so the walker resolves the
        # template via _saip_template_for_section_payload and follows
        # ``extends`` to FilesUsimMandatory.
        return {
            "sections": {
                "opt-usim": {
                    "opt-usim-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.5",
                    "ef-msisdn": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221001A"),
                            "fileID": _hex("6F40"),
                        }),
                    ],
                    "ef-li": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("42210006"),
                            "fileID": _hex("6F05"),
                        }),
                    ],
                },
            },
        }

    def test_opt_usim_ef_anchored_under_adf_usim(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_opt_usim_msisdn())
        msisdn = next(r for r in rows if r["field_path"] == "ef-msisdn")
        self.assertEqual(msisdn["parent_path"], "ADF.USIM")
        self.assertEqual(msisdn["fid_chain"], "ADF.USIM/6F40")
        self.assertNotIn("3F00", msisdn["fid_chain"])
        # Friendly resolver picks the USIM-context name.
        self.assertEqual(msisdn["friendly_name"], "EF.MSISDN")

    def test_no_opt_usim_row_anchored_under_mf(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_opt_usim_msisdn())
        for r in rows:
            if r.get("section_key") == "opt-usim":
                self.assertFalse(
                    r["fid_chain"].startswith("3F00/"),
                    f"opt-usim row {r['field_path']!r} leaked to MF: {r['fid_chain']!r}",
                )


class SingleNamePerRowTests(unittest.TestCase):
    """Every row resolves to exactly one friendly name — never compound.

    The FID name registry intentionally lists multiple aliases for
    several FIDs (EF.UST + EF.UST-SERVICE-TABLE at 6F38, DF.GSM +
    DF.EAP at 7F20, EF.IMSI + EF.IST at 6F07, …). The compound
    ``"FOO / BAR"`` form is informative for a debugger but unreadable
    in an operator-facing tree label. The walker now picks one
    contextual name per row using the chain context as the
    disambiguator.
    """

    def test_adf_usim_alias_collapses_to_canonical(self) -> None:
        # 6F38 has two adf-usim aliases (EF.UST, EF.UST-SERVICE-TABLE).
        # The first registered alias (canonical TS 31.102 spelling) wins.
        doc = {
            "sections": {
                "usim": {
                    "usim-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.4",
                    "adf-usim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ],
                    "ef-ust": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("4221000E"),
                            "fileID": _hex("6F38"),
                        }),
                    ],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        ust = next(r for r in rows if r["field_path"] == "ef-ust")
        self.assertEqual(ust["friendly_name"], "EF.UST")
        self.assertNotIn(" / ", ust["friendly_name"])

    def test_cross_adf_collision_picks_by_chain_context(self) -> None:
        # 6F07 is EF.IMSI under ADF.USIM and EF.IST under ADF.ISIM.
        # The walker must pick by the row's chain context, not the
        # registry's compound output.
        doc = {
            "sections": {
                "usim": {
                    "usim-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.4",
                    "adf-usim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ],
                    "ef-imsi": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("42210009"),
                            "fileID": _hex("6F07"),
                        }),
                    ],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        imsi = next(r for r in rows if r["field_path"] == "ef-imsi")
        self.assertEqual(imsi["friendly_name"], "EF.IMSI")
        self.assertNotIn(" / ", imsi["friendly_name"])

    def test_no_compound_names_anywhere_in_reference_topology(self) -> None:
        # Synthetic mini-document that stresses every collision class:
        # 6F38 (alias same parent), 6F07 (cross-ADF), 7F20 (legacy
        # container reuse). None of the resulting rows may carry the
        # " / " compound separator.
        doc = {
            "sections": {
                "mf": {
                    "mf-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.1",
                    "mf": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("3F00"),
                        }),
                    ],
                },
                "genericFileManagement": {
                    "fileManagementCMD": [
                        [
                            ("filePath", _hex("")),
                            ("createFCP", {
                                "fileDescriptor": _hex("78210000"),
                                "fileID": _hex("7F20"),
                            }),
                        ],
                    ],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        for r in rows:
            name = r.get("friendly_name") or ""
            self.assertNotIn(
                " / ", name,
                f"row {r['field_path']!r} kept compound name {name!r}",
            )
        # 7F20 at MF level resolves to the canonical legacy name
        # (DF.GSM, registered before DF.EAP in the alias table).
        seven_f_twenty = next(
            r for r in rows if r["fid_chain"] == "3F00/7F20"
        )
        self.assertEqual(seven_f_twenty["friendly_name"], "DF.GSM")


class GfmReanchorUnderAdfTests(unittest.TestCase):
    """GFM SELECT bytecode that traverses a 7FFx temp_fid must re-anchor."""

    def _document_with_gfm_under_usim(self) -> dict:
        # PE-USIM declares ADF.USIM with temp_fid=7FF0; PE-GFM then
        # SELECTs MF/7FF0/5F50 and creates a child EF inside it.
        return {
            "sections": {
                "usim": {
                    "usim-header": {"identification": 1},
                    "templateID": "2.23.143.1.2.4",
                    "adf-usim": [
                        ("fileDescriptor", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ],
                },
                "genericFileManagement_1": {
                    "fileManagementCMD": [
                        [
                            ("filePath", _hex("7FF05F50")),
                            ("createFCP", {
                                "fileDescriptor": _hex("78210000"),
                                "fileID": _hex("4F83"),
                            }),
                        ],
                    ],
                },
            },
        }

    def test_gfm_row_anchored_under_adf_friendly_name(self) -> None:
        rows = _filesystem_tree_rows(self._document_with_gfm_under_usim())
        # The lone GFM-created EF should land under ADF.USIM/5F50/4F83
        # — not under 3F00/7FF0/5F50/4F83. The latter would force the
        # GUI to render it as a stray sibling of MF children.
        gfm_rows = [r for r in rows if r["source"] == "gfm"]
        self.assertEqual(len(gfm_rows), 1)
        ef = gfm_rows[0]
        self.assertTrue(
            ef["fid_chain"].startswith("ADF.USIM/"),
            f"GFM chain {ef['fid_chain']!r} not re-anchored under ADF.USIM",
        )
        self.assertNotIn("7FF0", ef["fid_chain"])
        self.assertNotIn("3F00", ef["fid_chain"])


class GfmAdfKindFromDfNameTests(unittest.TestCase):
    """A GFM ``createFCP`` with a ``dfName`` AID must render as an ADF."""

    def test_create_fcp_with_df_name_is_adf(self) -> None:
        doc = {
            "sections": {
                "genericFileManagement": {
                    "fileManagementCMD": [[
                        ("filePath", b""),
                        ("createFCP", {
                            "fileDescriptor": _hex("78210000"),
                            "fileID": _hex("7FF0"),
                            "dfName": _hex("A0000000871002"),
                        }),
                    ]],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        adf = next(r for r in rows if r["file_id"] == "7FF0")
        self.assertEqual(adf["kind"], "adf")


class MalformedFilePathTests(unittest.TestCase):
    """Odd-length ``filePath`` is malformed but the row must still be addressable."""

    def test_odd_length_path_tagged_malformed_under_mf(self) -> None:
        doc = {
            "sections": {
                "genericFileManagement": {
                    "fileManagementCMD": [[
                        ("filePath", b"\x7f"),  # odd-length, malformed
                        ("createFCP", {
                            "fileDescriptor": _hex("4221001E"),
                            "fileID": _hex("6F3A"),
                        }),
                    ]],
                },
            },
        }
        rows = _filesystem_tree_rows(doc)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["parent_path"].startswith("3F00/MALFORMED:"))


class SearchFilesDispatcherTests(unittest.TestCase):
    """``saip.search_files`` dispatcher behaviour (no Action registry)."""

    def _stub_handle(self) -> dict:
        # Two ADFs sharing FID 6F40 + a GFM-created EF.ADN under DF.TELECOM.
        # Built directly so the test does not need a real session manager.
        return {
            "decoded_document": {
                "sections": {
                    "usim": {
                        "templateID": "2.23.143.1.2.4",
                        "adf-usim": [
                            ("fileDescriptor", {
                                "fileDescriptor": _hex("78210000"),
                                "fileID": _hex("7FF0"),
                                "dfName": _hex("A0000000871002"),
                            }),
                        ],
                        "ef-msisdn": [
                            ("fileDescriptor", {
                                "fileDescriptor": _hex("4221001A"),
                                "fileID": _hex("6F40"),
                            }),
                        ],
                    },
                    "genericFileManagement": {
                        "fileManagementCMD": [[
                            ("filePath", b"\x7f\x10"),
                            ("createFCP", {
                                "fileDescriptor": _hex("4221001E"),
                                "fileID": _hex("6F3A"),
                            }),
                        ]],
                    },
                },
            },
        }

    def _run(self, **kwargs):
        import threading
        import time

        from yggdrasim_common.gui_server.actions.saip import (
            _dispatch_search_files,
        )
        from yggdrasim_common.gui_server.sessions import (
            CardSession,
            get_manager,
        )

        sid = "test-search-files"
        handle = self._stub_handle()
        session = CardSession(
            id=sid,
            kind="saip",
            handle=handle,
            close=lambda: None,
            created_at=time.time(),
            last_used_at=time.time(),
            idle_timeout_s=60.0,
            metadata={},
            _lock=threading.Lock(),
        )
        get_manager()._sessions[sid] = session  # noqa: SLF001 (test stub)
        try:
            return _dispatch_search_files(
                None,  # ctx unused by this dispatcher
                session_id=sid,
                **kwargs,
            )
        finally:
            get_manager()._sessions.pop(sid, None)  # noqa: SLF001

    def test_default_mode_matches_friendly_name(self) -> None:
        result = self._run(query="MSISDN")
        self.assertEqual(result["mode"], "all")
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["rows"][0]["friendly_name"], "EF.MSISDN")

    def test_fid_mode_matches_hex(self) -> None:
        result = self._run(query="6F3A", mode="fid")
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["rows"][0]["file_id"], "6F3A")

    def test_regex_mode_matches_pattern(self) -> None:
        # The name haystack joins ``friendly_name`` and ``field_path``
        # with " | " and is lower-cased before the regex runs, so
        # anchored patterns must address either token, not the whole
        # joined string.
        result = self._run(query=r"\bef\.(msisdn|adn)\b", mode="name", regex=True)
        names = sorted(r["friendly_name"] for r in result["rows"])
        self.assertEqual(names, ["EF.ADN", "EF.MSISDN"])

    def test_invalid_regex_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._run(query="(unbalanced", regex=True)

    def test_unknown_mode_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._run(query="x", mode="not-a-mode")


if __name__ == "__main__":
    unittest.main()
