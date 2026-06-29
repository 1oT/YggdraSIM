# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for PE dependency-ordering lint rules.

Covers: YRL-DEP-OPTUSIM-001, YRL-DEP-OPTISIM-001, YRL-DEP-GSM-001,
        YRL-DEP-PBOOK-001, YRL-DEP-5GS-001, YRL-DEP-SAIP-001.

Each rule fires when a dependent PE appears before its required PE,
or when the required PE is absent entirely.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.lint_engine import SaipProfileLinter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lint(doc: dict) -> list:
    linter = SaipProfileLinter(strict=False)
    report = linter.lint_decoded_document(
        decoded_document=doc,
        profile_label="dep-test.der",
        check_return_code=None,
        check_stderr="",
        emit_missing_check_finding=False,
    )
    return report.findings


def _codes(doc: dict) -> list[str]:
    return [f.code for f in _lint(doc)]


def _doc(*ordered_types: str) -> dict:
    """Build a minimal profile document from an ordered sequence of PE type strings.

    The linter derives PE type from the section *key* via _base_type_from_key,
    so each key must be the type string itself (with a numeric suffix to allow
    multiple PEs of the same type without key collision).
    """
    sections: dict = {}
    type_count: dict[str, int] = {}
    for idx, pe_type in enumerate(ordered_types):
        count = type_count.get(pe_type, 0)
        type_count[pe_type] = count + 1
        key = pe_type if count == 0 else f"{pe_type}{count}"
        sections[key] = {"identification": idx, "type": pe_type}
    return {"sections": sections}


def _valid_base() -> tuple[str, ...]:
    """Return the smallest valid PE ordering that satisfies SEQ rules."""
    return ("header", "mf", "usim", "end")


# ---------------------------------------------------------------------------
# YRL-DEP-OPTUSIM-001  opt-usim requires usim
# ---------------------------------------------------------------------------

class DepOptUsimTests(unittest.TestCase):
    """YRL-DEP-OPTUSIM-001: opt-usim must appear after usim."""

    def test_opt_usim_without_usim_fires(self) -> None:
        doc = _doc("header", "mf", "opt-usim", "end")
        self.assertIn("YRL-DEP-OPTUSIM-001", _codes(doc))

    def test_opt_usim_before_usim_fires(self) -> None:
        doc = _doc("header", "mf", "opt-usim", "usim", "end")
        self.assertIn("YRL-DEP-OPTUSIM-001", _codes(doc))

    def test_opt_usim_after_usim_passes(self) -> None:
        doc = _doc("header", "mf", "usim", "opt-usim", "end")
        self.assertNotIn("YRL-DEP-OPTUSIM-001", _codes(doc))


# ---------------------------------------------------------------------------
# YRL-DEP-OPTISIM-001  opt-isim requires isim
# ---------------------------------------------------------------------------

class DepOptIsimTests(unittest.TestCase):
    """YRL-DEP-OPTISIM-001: opt-isim must appear after isim."""

    def test_opt_isim_without_isim_fires(self) -> None:
        doc = _doc("header", "mf", "opt-isim", "end")
        self.assertIn("YRL-DEP-OPTISIM-001", _codes(doc))

    def test_opt_isim_before_isim_fires(self) -> None:
        doc = _doc("header", "mf", "opt-isim", "isim", "end")
        self.assertIn("YRL-DEP-OPTISIM-001", _codes(doc))

    def test_opt_isim_after_isim_passes(self) -> None:
        doc = _doc("header", "mf", "isim", "opt-isim", "end")
        self.assertNotIn("YRL-DEP-OPTISIM-001", _codes(doc))


# ---------------------------------------------------------------------------
# YRL-DEP-GSM-001  gsm-access requires usim
# ---------------------------------------------------------------------------

class DepGsmAccessTests(unittest.TestCase):
    """YRL-DEP-GSM-001: gsm-access must appear after usim."""

    def test_gsm_access_without_usim_fires(self) -> None:
        doc = _doc("header", "mf", "gsm-access", "end")
        self.assertIn("YRL-DEP-GSM-001", _codes(doc))

    def test_gsm_access_before_usim_fires(self) -> None:
        doc = _doc("header", "mf", "gsm-access", "usim", "end")
        self.assertIn("YRL-DEP-GSM-001", _codes(doc))

    def test_gsm_access_after_usim_passes(self) -> None:
        doc = _doc("header", "mf", "usim", "gsm-access", "end")
        self.assertNotIn("YRL-DEP-GSM-001", _codes(doc))


# ---------------------------------------------------------------------------
# YRL-DEP-PBOOK-001  phonebook requires usim
# ---------------------------------------------------------------------------

class DepPhonebookTests(unittest.TestCase):
    """YRL-DEP-PBOOK-001: phonebook must appear after usim."""

    def test_phonebook_without_usim_fires(self) -> None:
        doc = _doc("header", "mf", "phonebook", "end")
        self.assertIn("YRL-DEP-PBOOK-001", _codes(doc))

    def test_phonebook_before_usim_fires(self) -> None:
        doc = _doc("header", "mf", "phonebook", "usim", "end")
        self.assertIn("YRL-DEP-PBOOK-001", _codes(doc))

    def test_phonebook_after_usim_passes(self) -> None:
        doc = _doc("header", "mf", "usim", "phonebook", "end")
        self.assertNotIn("YRL-DEP-PBOOK-001", _codes(doc))


# ---------------------------------------------------------------------------
# YRL-DEP-5GS-001  df-5gs requires usim
# ---------------------------------------------------------------------------

class DepDf5gsTests(unittest.TestCase):
    """YRL-DEP-5GS-001: df-5gs must appear after usim."""

    def test_df_5gs_without_usim_fires(self) -> None:
        doc = _doc("header", "mf", "df-5gs", "end")
        self.assertIn("YRL-DEP-5GS-001", _codes(doc))

    def test_df_5gs_before_usim_fires(self) -> None:
        doc = _doc("header", "mf", "df-5gs", "usim", "end")
        self.assertIn("YRL-DEP-5GS-001", _codes(doc))

    def test_df_5gs_after_usim_passes(self) -> None:
        doc = _doc("header", "mf", "usim", "df-5gs", "end")
        self.assertNotIn("YRL-DEP-5GS-001", _codes(doc))


# ---------------------------------------------------------------------------
# YRL-DEP-SAIP-001  df-saip requires usim
# ---------------------------------------------------------------------------

class DepDfSaipTests(unittest.TestCase):
    """YRL-DEP-SAIP-001: df-saip must appear after usim."""

    def test_df_saip_without_usim_fires(self) -> None:
        doc = _doc("header", "mf", "df-saip", "end")
        self.assertIn("YRL-DEP-SAIP-001", _codes(doc))

    def test_df_saip_before_usim_fires(self) -> None:
        doc = _doc("header", "mf", "df-saip", "usim", "end")
        self.assertIn("YRL-DEP-SAIP-001", _codes(doc))

    def test_df_saip_after_usim_passes(self) -> None:
        doc = _doc("header", "mf", "usim", "df-saip", "end")
        self.assertNotIn("YRL-DEP-SAIP-001", _codes(doc))


# ---------------------------------------------------------------------------
# Combined: multiple dependents with a single usim
# ---------------------------------------------------------------------------

class DepCombinedTests(unittest.TestCase):
    """Combination checks: several dependent PEs all placed correctly after usim."""

    def test_all_deps_after_usim_produces_no_dep_findings(self) -> None:
        doc = _doc(
            "header", "mf", "usim",
            "opt-usim", "gsm-access", "phonebook", "df-5gs", "df-saip",
            "end",
        )
        codes = _codes(doc)
        for rule in (
            "YRL-DEP-OPTUSIM-001",
            "YRL-DEP-GSM-001",
            "YRL-DEP-PBOOK-001",
            "YRL-DEP-5GS-001",
            "YRL-DEP-SAIP-001",
        ):
            self.assertNotIn(rule, codes)

    def test_all_deps_before_usim_fires_all_rules(self) -> None:
        doc = _doc(
            "header", "mf",
            "opt-usim", "gsm-access", "phonebook", "df-5gs", "df-saip",
            "usim", "end",
        )
        codes = _codes(doc)
        for rule in (
            "YRL-DEP-OPTUSIM-001",
            "YRL-DEP-GSM-001",
            "YRL-DEP-PBOOK-001",
            "YRL-DEP-5GS-001",
            "YRL-DEP-SAIP-001",
        ):
            self.assertIn(rule, codes)


if __name__ == "__main__":
    unittest.main()
