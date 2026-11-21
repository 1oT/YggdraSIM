# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""BER tags in the generated GSMA context-tag index (``scripts/convert_tel_docs.py``).

An implicit context tag keeps the primitive form of its base type, so
``UpdateMetadataResponse ::= [42] INTEGER`` encodes as '9F2A', not 'BF2A'
(SGP.22 v3.1 p. 287). The library-backed checks run only where
``docs/tel-docs/converted`` is present.
"""

from __future__ import annotations

import re

import pytest

from scripts.convert_tel_docs import (
    CONTEXT_TAG_RE,
    GSMA_TAG_INDEX,
    SPEC_TAG_COMMENT_RE,
    TYPE_ASSIGNMENT_RE,
    context_tag_hex,
    converted_folders,
    document_tag_default,
    tagged_type_is_constructed,
)
from Tools.Asn1TlvDecode.context import _ES10_FALLBACK

_library_present = pytest.mark.skipif(not GSMA_TAG_INDEX.exists(), reason="spec library not on disk")


@pytest.mark.parametrize(
    ("number", "constructed", "expected"),
    [
        (0, False, "80"),
        (0, True, "A0"),
        (2, False, "82"),
        (30, True, "BE"),
        (31, True, "BF1F"),
        (42, False, "9F2A"),
        (42, True, "BF2A"),
        (127, True, "BF7F"),
        (128, True, "BF8100"),
        (16383, False, "9FFF7F"),
    ],
)
def test_context_tag_hex(number: int, constructed: bool, expected: str) -> None:
    assert context_tag_hex(number, constructed) == expected


@pytest.mark.parametrize(
    ("keyword", "tagging", "tag_default", "expected"),
    [
        ("SEQUENCE", "", "AUTOMATIC", True),
        ("SET", "", "AUTOMATIC", True),
        ("CHOICE", "", "AUTOMATIC", True),
        ("INTEGER", "", "AUTOMATIC", False),
        ("OCTET", "", "IMPLICIT", False),
        ("UTF8String", "", "AUTOMATIC", False),
        ("INTEGER", "EXPLICIT", "AUTOMATIC", True),
        ("INTEGER", "", "EXPLICIT", True),
        ("INTEGER", "IMPLICIT", "EXPLICIT", False),
    ],
)
def test_tag_form_follows_x680_tagging(keyword: str, tagging: str, tag_default: str, expected: bool) -> None:
    assert tagged_type_is_constructed(keyword, tagging, tag_default, {}) is expected


def test_tag_form_resolves_type_references() -> None:
    text = (
        "Octet16 ::= OCTET STRING (SIZE (16))\n"
        "Iccid ::= [APPLICATION 26] OCTET STRING\n"
        "Wrapped ::= [3] CHOICE { a INTEGER, b NULL }\n"
        "Payload ::= SEQUENCE { x INTEGER }\n"
    )
    assignments = {name: (bool(tag), tagging, keyword) for name, tag, tagging, keyword in TYPE_ASSIGNMENT_RE.findall(text)}
    assert tagged_type_is_constructed("Octet16", "", "AUTOMATIC", assignments) is False
    assert tagged_type_is_constructed("Iccid", "", "AUTOMATIC", assignments) is False
    assert tagged_type_is_constructed("Wrapped", "", "AUTOMATIC", assignments) is True
    assert tagged_type_is_constructed("Payload", "", "AUTOMATIC", assignments) is True
    assert tagged_type_is_constructed("Unknown", "", "AUTOMATIC", assignments) is None


def _index_rows() -> set[tuple[str, str, str]]:
    rows = set()
    for line in GSMA_TAG_INDEX.read_text(encoding="utf-8").splitlines():
        if line.startswith("| SGP."):
            columns = [column.strip().strip("`") for column in line.strip().strip("|").split("|")]
            rows.add((columns[0], columns[1], columns[2]))
    return rows


@_library_present
def test_index_lists_primitive_context_tags_in_primitive_form() -> None:
    rows = _index_rows()
    assert ("SGP.22-v3.1", "9F2A", "UpdateMetadataResponse") in rows
    assert ("SGP.22-v3.1", "BF2A", "UpdateMetadataRequest") in rows
    assert ("SGP.32-v1.3", "80", "SequenceNumber") in rows


@_library_present
def test_computed_tags_match_every_specification_tag_comment() -> None:
    checked = 0
    for folder in converted_folders():
        if not folder.name.upper().startswith("SGP."):
            continue
        texts = [path.read_text(encoding="utf-8", errors="replace") for path in sorted((folder / "asn1").glob("*.asn"))]
        if not texts:
            continue
        tag_default = document_tag_default(folder)
        assignments: dict[str, tuple[bool, str, str]] = {}
        for text in texts:
            for name, tag, tagging, keyword in TYPE_ASSIGNMENT_RE.findall(text):
                assignments.setdefault(name, (bool(tag), tagging, keyword))
        for text in texts:
            for name, number, tagging, keyword, rest in CONTEXT_TAG_RE.findall(text):
                stated = SPEC_TAG_COMMENT_RE.search(rest)
                if not stated:
                    continue
                constructed = tagged_type_is_constructed(keyword, tagging, tag_default, assignments)
                assert constructed is not None, f"{folder.name} {name}"
                assert context_tag_hex(int(number), constructed) == stated.group(1).upper(), f"{folder.name} {name}"
                checked += 1
    assert checked > 100


@_library_present
def test_decoder_fallback_rows_mirror_the_generated_index() -> None:
    rows = _index_rows()
    stale = [row for row in _ES10_FALLBACK if row not in rows]
    assert stale == []
    assert all(re.fullmatch(r"BF[0-9A-F]{2}", tag) for _, tag, _ in _ES10_FALLBACK)


def test_fallback_has_no_constructed_tag_for_a_primitive_response() -> None:
    assert ("SGP.22-v3.1", "BF2A", "UpdateMetadataResponse") not in _ES10_FALLBACK
