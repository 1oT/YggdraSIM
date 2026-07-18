# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end regressions for dynamic Excel filesystem PE partitioning."""

from __future__ import annotations

from pathlib import Path

import pytest

from plugins.saip_profile_generator.provider import SaipFilesystemGeneratorProvider
from yggdrasim_common.gui_server.actions.saip import _load_package_from_path

openpyxl = pytest.importorskip("openpyxl")


def _repeated_phonebook_workbook(path: Path) -> None:
    """Write a layout-neutral workbook with two native EF.ADN slots."""

    workbook = openpyxl.Workbook()
    definitions = workbook.active
    definitions.title = "arbitrary-definition-table"
    access = workbook.create_sheet("arbitrary-access-table")
    definitions.append(
        (
            "File ID",
            "File Name",
            "Type",
            "Rec Nb",
            "Rec Size",
            "Body File Size",
            "Contents",
            "AID",
        )
    )
    for row in (
        ("3F00", "MF", "MF", None, None, None, None, None),
        ("2F06", "EF.ARR", "LF", 4, 4, 16, "FF" * 16, None),
        ("7FFF", "ADF.USIM", "ADF", None, None, None, None, "A0000000871002"),
        ("6F06", "EF.ARR", "LF", 12, 4, 48, "FF" * 48, None),
        ("5F3A", "DF.PHONEBOOK", "DF", None, None, None, None, None),
        ("4F30", "EF.PBR", "LF", 1, 32, 32, "FF" * 32, None),
        ("4F58", "EF.ADN", "LF", 2, 40, 80, "FF" * 80, None),
        ("4F59", "EF.ADN", "LF", 3, 40, 120, "FF" * 120, None),
        # Phonebook files are allocated dynamically through EF.PBR.  The
        # source must retain the semantic ef-pbc ASN.1 member even when the
        # active GFSTE revision exposes 4F60 as a generic allocatable slot.
        ("4F60", "EF.PBC", "LF", 3, 2, 6, "00" * 6, None),
    ):
        definitions.append(row)

    access.append(("File ID", "File Name", "Type", "Path", "ARR"))
    for row in (
        ("3F00", "MF", "MF", None, "2F06#1"),
        ("2F06", "EF.ARR", "LF", "3F00/", "2F06#1"),
        ("7FFF", "ADF.USIM", "ADF", "3F00/", "2F06#1"),
        ("6F06", "EF.ARR", "LF", "7FFF/", "6F06#1"),
        ("5F3A", "DF.PHONEBOOK", "DF", "7FFF/", "6F06#1"),
        ("4F30", "EF.PBR", "LF", "7FFF/5F3A/", "6F06#1"),
        ("4F58", "EF.ADN", "LF", "7FFF/5F3A/", "6F06#2"),
        ("4F59", "EF.ADN", "LF", "7FFF/5F3A/", "6F06#3"),
        ("4F60", "EF.PBC", "LF", "7FFF/5F3A/", "6F06#4"),
    ):
        access.append(row)

    workbook.save(path)
    workbook.close()


def test_excel_generation_partitions_repeated_native_slots_and_round_trips(
    tmp_path: Path,
) -> None:
    source = tmp_path / "generic-filesystem.xlsx"
    target = tmp_path / "generic-template.varder"
    _repeated_phonebook_workbook(source)

    result = SaipFilesystemGeneratorProvider()._dispatch_inspect_workbook(
        ctx=None,
        workbook_path=source,
        output_path=target,
        open_authoring_session=False,
    )

    assert result["materialization_state"] == "WROTE_VARDER_TEMPLATE"
    assert result["has_blocking_diagnostics"] is False
    assert result["materialization_summary"]["fallback_entry_count"] == 0
    assert result["materialization_summary"]["native_menu_instances"] == [
        "mf",
        "usim",
        "phonebook",
        "phonebook",
    ]
    assert result["baseline_summary"]["pe_types"].count("phonebook") == 2

    phonebook_rows = [
        row
        for row in result["filesystem_plan"]["placements"]
        if row["menu_id"] == "phonebook"
    ]
    assert [row["pe_name"] for row in phonebook_rows].count("ef-adn") == 2
    pbc = next(row for row in phonebook_rows if row["display_name"] == "EF.PBC")
    assert pbc["pe_name"] == "ef-pbc"
    assert pbc["fid_hex"] == "4F60"
    # The pinned package catalogues PBC at 4F09 and therefore records a
    # source-FID override; newer supported developer checkouts expose the
    # dynamic 4F60 slot directly.  Both paths must preserve the same semantic
    # member and source FID, which the round-trip assertions below enforce.
    assert pbc["match_kind"] in {"EXACT", "NAME_STRUCTURE_FID_OVERRIDE"}

    loaded = _load_package_from_path(target)
    phonebook_pes = loaded["pes"].get_pes_for_type("phonebook")
    assert len(phonebook_pes) == 2
    adn_fids = {
        dict(pe.decoded["ef-adn"])["fileDescriptor"]["fileID"].hex().upper()
        for pe in phonebook_pes
        if pe.decoded.get("ef-adn")
    }
    assert adn_fids == {"4F58", "4F59"}
    pbc_fids = {
        dict(pe.decoded["ef-pbc"])["fileDescriptor"]["fileID"].hex().upper()
        for pe in phonebook_pes
        if pe.decoded.get("ef-pbc")
    }
    assert pbc_fids == {"4F60"}
