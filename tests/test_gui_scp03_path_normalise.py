# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``_normalise_fs_path`` in the SCP03 dispatcher.

Pinned bug: top-level EFs under MF (e.g. ``EF.ICCID``) arrived at
``FileSystemController.select()`` as bare names. That routed through
the no-slash select branch, which issues a direct ``00A4000402<FID>``
against whatever DF the card is currently sitting on. If the previous
action (scan walker, ADF select, …) left the card on an ADF, the
follow-up bare select would fail with 6A82 — "file not found in the
current DF" — even though the file exists under MF.

The user-visible symptom was *"clicking EF.ICCID does nothing the first
time; I have to click MF first and then EF.ICCID"*. The fix is to
normalise non-slash, non-hex, non-index names to ``MF/<name>`` before
dispatching to ``select()``, so the path-walk branch pre-selects MF
first — matching ETSI TS 102 221 SELECT semantics regardless of the
card's current DF.

These tests guard against future regressions of that normalisation
contract. Keep them dependency-free: no PC/SC, no pySim, no side-effects.
"""

from __future__ import annotations


def _load_normaliser():
    """Lazy-import so collecting tests never touches PC/SC."""
    from yggdrasim_common.gui_server.actions.scp03 import _normalise_fs_path
    return _normalise_fs_path


def test_bare_ef_name_gets_mf_prefix():
    normalise = _load_normaliser()
    assert normalise("EF.ICCID") == "MF/EF.ICCID"
    assert normalise("EF.DIR") == "MF/EF.DIR"
    assert normalise("ef.imsi") == "MF/ef.imsi"


def test_already_qualified_paths_are_left_alone():
    normalise = _load_normaliser()
    assert normalise("MF/EF.ICCID") == "MF/EF.ICCID"
    assert normalise("MF/ADF_USIM/EF_IMSI") == "MF/ADF_USIM/EF_IMSI"
    assert normalise("MF") == "MF"
    # An explicit non-MF root the caller supplied — trust it.
    assert normalise("ADF_USIM/EF_IMSI") == "ADF_USIM/EF_IMSI"


def test_hex_fids_are_not_touched():
    # Hex FIDs are card-internal relative selects; the caller knows
    # what they're doing. Touching these would break the bare-FID
    # workflow that predates the GUI scan tree.
    normalise = _load_normaliser()
    assert normalise("3F00") == "3F00"
    assert normalise("2FE2") == "2FE2"
    assert normalise("7FFF") == "7FFF"


def test_aid_strings_are_not_touched():
    # AIDs are long hex — SELECT-by-AID already resolves globally
    # on the card, so the MF prefix would be a no-op at best and a
    # bug at worst.
    normalise = _load_normaliser()
    aid = "A0000000871002FFFFFFFF8907090000"
    assert normalise(aid) == aid


def test_numeric_scan_cache_indices_are_not_touched():
    # Scan-cache indices (e.g. "5") resolve inside select() via the
    # controller's scan_cache dict. The leading "MF/" would poison
    # that lookup.
    normalise = _load_normaliser()
    assert normalise("5") == "5"
    assert normalise("42") == "42"


def test_empty_and_whitespace_paths_are_preserved():
    normalise = _load_normaliser()
    assert normalise("") == ""
    assert normalise("   ") == ""


def test_mixed_case_mf_prefix_is_recognised():
    normalise = _load_normaliser()
    # Case-insensitive MF detection — the historical path format is
    # upper-case, but hand-typed input may drift.
    assert normalise("mf/ef.iccid") == "mf/ef.iccid"
    assert normalise("Mf") == "Mf"
