# SPDX-License-Identifier: GPL-3.0-or-later
"""Spreadsheet-injection and active-content regressions for SAIP export."""

from __future__ import annotations

import io
import zipfile

import pytest

from plugins.saip_excel_export.exporter import (
    ExportSource,
    _build_workbook,
    _serialize_workbook,
)

openpyxl = pytest.importorskip("openpyxl")


def test_profile_token_and_operator_text_never_becomes_active_excel_content() -> None:
    risky_values = (
        "=HYPERLINK(\"https://invalid.example\",\"profile\")",
        "+1+1",
        "-2+3",
        "@SUM(1,2)",
    )
    decoded = {
        "intro": list(risky_values),
        "__ygg_variable_catalog__": {
            "variables": [
                {
                    "id": risky_values[0],
                    "token": risky_values[1],
                    "definition_id": risky_values[2],
                    "aliases": [risky_values[3]],
                }
            ]
        },
        "sections": {
            "header": {
                "profileType": risky_values[0],
                "operator-note": risky_values[1],
                "dash-note": risky_values[2],
                "at-note": risky_values[3],
            }
        },
    }
    source = ExportSource(
        decoded_document=decoded,
        tagged_document=decoded,
        inline_records=(),
        filesystem_rows=(),
        source_name="@operator-source.der",
        source_format="json",
        source_sha256="",
        semantic_sha256="0" * 64,
        strict_complete=True,
        warning_count=0,
        session_dirty=False,
        artifact_kind="concrete",
        token_occurrence_count=0,
    )

    build = _build_workbook(
        source,
        value_policy="full",
        include_empty_fields=True,
        workbook_title="=OPERATOR_WORKBOOK_TITLE",
    )
    payload = _serialize_workbook(build.workbook)

    workbook = openpyxl.load_workbook(
        io.BytesIO(payload),
        data_only=False,
        keep_links=False,
    )
    try:
        risky_cells = []
        for sheet in workbook.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    assert cell.data_type != "f"
                    if isinstance(cell.value, str) and cell.value.startswith(
                        ("=", "+", "-", "@")
                    ):
                        risky_cells.append(cell)
        assert risky_cells
        assert {cell.value for cell in risky_cells}.issuperset(risky_values)
        assert all(cell.quotePrefix for cell in risky_cells)
        assert not getattr(workbook, "_external_links", ())
    finally:
        workbook.close()

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = set(archive.namelist())
        assert not any(name.startswith("xl/externalLinks/") for name in names)
        assert not any(name.casefold().endswith("vbaproject.bin") for name in names)
        assert not any(name.casefold().endswith(".bin") for name in names)
        worksheet_xml = b"".join(
            archive.read(name)
            for name in names
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        )
        assert b"<f>" not in worksheet_xml
        assert b"<f " not in worksheet_xml
