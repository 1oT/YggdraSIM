# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest
from types import SimpleNamespace

from SCP11.shared.profile_targeting import resolve_profile_target_identifier


def _encode_iccid_for_command(iccid_digits: str) -> str:
    digits = "".join(character for character in str(iccid_digits or "").strip() if character.isdigit())
    if len(digits) == 0:
        return ""
    if len(digits) % 2 != 0:
        digits += "F"
    swapped = []
    index = 0
    while index < len(digits):
        swapped.append(digits[index + 1] + digits[index])
        index += 2
    return "".join(swapped).upper()


def _extract_decimal_iccid(value: str):
    clean = str(value or "").strip().upper()
    if len(clean) < 18:
        return None
    if clean.isdigit() is False:
        return None
    return clean


def _is_hex(value: str) -> bool:
    clean = str(value or "").strip().upper()
    if len(clean) == 0:
        return False
    if len(clean) % 2 != 0:
        return False
    try:
        bytes.fromhex(clean)
    except ValueError:
        return False
    return True


class SharedProfileTargetingTests(unittest.TestCase):
    def test_alias_match_short_circuits_profile_lookup(self) -> None:
        alias_hits: list[str] = []

        def resolve_aid_from_alias(alias: str):
            alias_hits.append(alias)
            if alias == "ISDP1":
                return "A0000005591010FFFFFFFF8900001100"
            return None

        def fetch_profiles():
            raise AssertionError("alias match should not fetch profiles")

        resolved = resolve_profile_target_identifier(
            "isdp1",
            tag_aid="AID",
            tag_iccid="ICCID",
            resolve_aid_from_alias=resolve_aid_from_alias,
            is_hex=_is_hex,
            extract_decimal_iccid=_extract_decimal_iccid,
            encode_iccid_for_command=_encode_iccid_for_command,
            fetch_profiles=fetch_profiles,
        )

        self.assertEqual(alias_hits, ["ISDP1"])
        self.assertEqual(resolved, ("AID", "A0000005591010FFFFFFFF8900001100"))

    def test_decimal_iccid_prefers_profile_metadata_encoding(self) -> None:
        row = SimpleNamespace(
            iccid="89460811111111111112",
            aid="A0000005591010FFFFFFFF8900001303",
        )

        resolved = resolve_profile_target_identifier(
            "89460811111111111112",
            tag_aid="AID",
            tag_iccid="ICCID",
            resolve_aid_from_alias=lambda alias: None,
            is_hex=_is_hex,
            extract_decimal_iccid=_extract_decimal_iccid,
            encode_iccid_for_command=_encode_iccid_for_command,
            fetch_profiles=lambda: [row],
        )

        self.assertEqual(resolved, ("ICCID", "98648011111111111121"))

    def test_profile_fetch_failure_still_allows_decimal_fallback(self) -> None:
        def fetch_profiles():
            raise RuntimeError("reader offline")

        resolved = resolve_profile_target_identifier(
            "89460811111111111112",
            tag_aid="AID",
            tag_iccid="ICCID",
            resolve_aid_from_alias=lambda alias: None,
            is_hex=_is_hex,
            extract_decimal_iccid=_extract_decimal_iccid,
            encode_iccid_for_command=_encode_iccid_for_command,
            fetch_profiles=fetch_profiles,
        )

        self.assertEqual(resolved, ("ICCID", "98648011111111111121"))
