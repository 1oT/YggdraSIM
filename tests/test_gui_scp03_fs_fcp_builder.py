# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``_build_fcp_template_fields``.

The GUI CREATE FILE wizard composes its FCP via this helper so the GUI
wire is byte-for-byte identical to the CLI
``SCP03.interface.shell_wizards._build_fcp_template``. The helper is
pure — no card, no pySim, no PC/SC — so these tests exercise it
directly.

Reference vectors are cross-checked against ETSI TS 102 222 §6.1
examples and the existing CLI wizard implementation (the CLI version
uses numeric ``type_choice`` strings 1/2/3; the GUI enum maps them to
``DF_ADF`` / ``TRANSPARENT_EF`` / ``LINEAR_FIXED_EF``).
"""

from __future__ import annotations

import pytest


def _build():
    from yggdrasim_common.gui_server.actions.scp03 import (
        _build_fcp_template_fields,
    )

    return _build_fcp_template_fields


# ----------------------------------------------------------------------
# DF / ADF
# ----------------------------------------------------------------------


def test_df_basic_builds_expected_fcp_wire():
    build = _build()
    # Minimal DF: full_path=3F007F10 (parent 3F00, FID 7F10), size=0400
    # (1 KiB quota), PIN status template = hand-rolled C6 TLV
    # "C609 90 01 01 83 01 01 95 01 08" (9 bytes inner, tag C6).
    out = build(
        file_type="DF_ADF",
        full_path="3F007F10",
        sec_attr_hex="8C0140",  # AM=01 (ALWAYS) for demo
        file_size_hex="0400",
        c6_hex="C609900101830101950108",
    )
    assert out["file_type"] == "DF_ADF"
    assert out["fid"] == "7F10"
    assert out["parent_path"] == "3F00"
    assert out["file_size"] == 0x0400
    assert out["rec_len"] == 0
    # Outer tag 62 + length byte; body matches the CLI wizard's concat
    # order: 82 83 84 8A (sec) (size) 88 C6 A5.
    assert out["fcp_hex"].startswith("62")
    # Decode outer length and verify body length matches.
    body = out["fcp_hex"][4:]
    declared_len = int(out["fcp_hex"][2:4], 16)
    assert len(body) // 2 == declared_len
    # Tag 82 for DF = 82 02 78 21
    assert "82027821" in out["fcp_hex"]
    # Tag 83 carries the FID.
    assert "83027F10" in out["fcp_hex"]
    # Tag 8A = LCS 05.
    assert "8A0105" in out["fcp_hex"]
    # Tag 81 size = 02 04 00 (2 bytes, value 0400).
    assert "81020400" in out["fcp_hex"]
    # C6 TLV pass-through.
    assert "C609900101830101950108" in out["fcp_hex"]


def test_df_requires_c6():
    build = _build()
    with pytest.raises(ValueError, match="c6_hex"):
        build(
            file_type="DF_ADF",
            full_path="3F007F10",
            sec_attr_hex="8C0140",
            file_size_hex="0400",
            c6_hex="",  # missing
        )


def test_df_with_adf_aid_includes_tag_84():
    build = _build()
    out = build(
        file_type="DF_ADF",
        full_path="3F007FFF",
        sec_attr_hex="8C0140",
        file_size_hex="0200",
        aid_hex="A0000000871002FF33FFFF8900000100",
        c6_hex="C603900180",
    )
    # Tag 84 length = len(aid)//2 = 16 bytes.
    assert "8410A0000000871002FF33FFFF8900000100" in out["fcp_hex"]


# ----------------------------------------------------------------------
# Transparent EF
# ----------------------------------------------------------------------


def test_transparent_ef_default_sfi_is_88_00():
    build = _build()
    out = build(
        file_type="TRANSPARENT_EF",
        full_path="3F002F00",
        sec_attr_hex="8C0140",
        file_size_hex="0020",
    )
    assert out["file_type"] == "TRANSPARENT_EF"
    assert out["fid"] == "2F00"
    # Tag 82 for transparent EF = 82 02 41 21.
    assert "82024121" in out["fcp_hex"]
    # Tag 80 size (transparent uses 80).
    assert "80020020" in out["fcp_hex"]
    # No SFI → 88 00.
    assert "8800" in out["fcp_hex"]
    # Should NOT have 88 01 ... (the explicit-SFI wire).
    assert "8801" not in out["fcp_hex"]


def test_transparent_ef_with_explicit_sfi():
    build = _build()
    out = build(
        file_type="TRANSPARENT_EF",
        full_path="3F002F05",
        sec_attr_hex="8C0140",
        file_size_hex="0010",
        sfi_hex="05",
    )
    assert "880105" in out["fcp_hex"]


def test_transparent_ef_rejects_two_byte_sfi():
    build = _build()
    with pytest.raises(ValueError, match="sfi_hex must be exactly 1 byte"):
        build(
            file_type="TRANSPARENT_EF",
            full_path="3F002F05",
            sec_attr_hex="8C0140",
            file_size_hex="0010",
            sfi_hex="0005",  # 2 bytes — should reject
        )


def test_transparent_ef_requires_size():
    build = _build()
    with pytest.raises(ValueError, match="file_size_hex is required"):
        build(
            file_type="TRANSPARENT_EF",
            full_path="3F002F00",
            sec_attr_hex="8C0140",
            # no size
        )


# ----------------------------------------------------------------------
# Linear Fixed EF
# ----------------------------------------------------------------------


def test_linear_fixed_ef_computes_total_from_rec_len_times_num_rec():
    build = _build()
    out = build(
        file_type="LINEAR_FIXED_EF",
        full_path="3F007F206F3A",
        sec_attr_hex="8C0140",
        rec_len_hex="14",      # 20 bytes per record
        num_rec_hex="0A",      # 10 records
    )
    assert out["file_type"] == "LINEAR_FIXED_EF"
    assert out["fid"] == "6F3A"
    assert out["parent_path"] == "3F007F20"
    assert out["rec_len"] == 0x14
    assert out["num_rec"] == 0x0A
    assert out["file_size"] == 0x14 * 0x0A  # 200 = 0xC8
    # Tag 82 linear = 82 04 42 21 <RECLEN_16>.
    assert "8204422100" in out["fcp_hex"]  # 82 04 42 21 00 14
    assert "0014" in out["fcp_hex"]
    # Tag 80 size = 2 bytes carrying 0x00C8.
    assert "800200C8" in out["fcp_hex"]


def test_linear_fixed_ef_rejects_zero_records():
    build = _build()
    with pytest.raises(ValueError, match="positive"):
        build(
            file_type="LINEAR_FIXED_EF",
            full_path="3F006F3A",
            sec_attr_hex="8C0140",
            rec_len_hex="10",
            num_rec_hex="00",
        )


# ----------------------------------------------------------------------
# Breakdown payload for the wizard preview UI
# ----------------------------------------------------------------------


def test_breakdown_contains_every_emitted_tlv_with_description():
    build = _build()
    out = build(
        file_type="TRANSPARENT_EF",
        full_path="3F002F05",
        sec_attr_hex="8C0140",
        file_size_hex="0010",
        sfi_hex="05",
        prop_a5_hex="C10100",
    )
    tags = [row["tag"] for row in out["breakdown"]]
    # Expect 82, 83, 8A, 8C (from sec), 80, 88, A5.
    assert "82" in tags
    assert "83" in tags
    assert "8A" in tags
    assert "8C" in tags
    assert "80" in tags
    assert "88" in tags
    assert "A5" in tags
    # Each row has a human-readable description.
    for row in out["breakdown"]:
        assert isinstance(row["description"], str)
        assert len(row["description"]) > 0
        assert isinstance(row["hex"], str)
        assert len(row["hex"]) % 2 == 0


# ----------------------------------------------------------------------
# Input hardening — the GUI forwards raw strings, so garbage in → clear
# ValueError out (the dispatcher layer maps these onto API 400s).
# ----------------------------------------------------------------------


def test_unknown_file_type_raises():
    build = _build()
    with pytest.raises(ValueError, match="file_type must be one of"):
        build(
            file_type="CYCLIC_EF",
            full_path="3F002F00",
            sec_attr_hex="8C0140",
            file_size_hex="0010",
        )


def test_full_path_must_be_2_byte_aligned():
    build = _build()
    # 10 hex chars = 5 bytes — even-length so it clears _normalize_hex,
    # but not a multiple of 4 (one FID) so the 2-byte alignment check
    # must fire from _build_fcp_template_fields itself.
    with pytest.raises(ValueError, match="2-byte aligned"):
        build(
            file_type="TRANSPARENT_EF",
            full_path="3F007F1011",
            sec_attr_hex="8C0140",
            file_size_hex="0010",
        )


def test_full_path_empty_rejected():
    build = _build()
    # ``_normalize_hex`` rejects empty required hex before the alignment
    # check — the wizard relies on that early error so the preview UI
    # highlights the first missing field rather than downstream ones.
    with pytest.raises(ValueError, match="full_path is required"):
        build(
            file_type="TRANSPARENT_EF",
            full_path="",
            sec_attr_hex="8C0140",
            file_size_hex="0010",
        )


def test_fcp_body_longer_than_127_bytes_errors_cleanly():
    build = _build()
    # Force a pathological security-attribute TLV to overflow short-form.
    huge_sec = "8C" + f"{120:02X}" + ("FF" * 120)  # 122 bytes
    with pytest.raises(ValueError, match="short-form length"):
        build(
            file_type="TRANSPARENT_EF",
            full_path="3F002F00",
            sec_attr_hex=huge_sec,
            file_size_hex="0010",
        )


# ----------------------------------------------------------------------
# CLI wire-level parity — the key reason this helper exists.
# ----------------------------------------------------------------------


def test_wire_matches_cli_wizard_for_transparent_ef():
    """Cross-check a representative DER against the CLI wizard output.

    The CLI wizard's ``_build_fcp_template`` emits
    ``62 XX 82 02 41 21 83 02 <FID> 8A 01 05 <sec> <80 02 <size>> <88 00>
    <tag_c6=''> <tag_a5=''>`` for a Transparent EF with no SFI / no A5.
    Any drift between the CLI and GUI here would silently send different
    FCP wires to the card, which we absolutely do not want.
    """
    build = _build()
    out = build(
        file_type="TRANSPARENT_EF",
        full_path="3F002F00",
        sec_attr_hex="8C0140",
        file_size_hex="0010",
    )
    # Body: 82 02 41 21 | 83 02 2F 00 | 8A 01 05 | 8C 01 40 |
    #       80 02 00 10 | 88 00
    # Total body = 2+2+3+3+3+3+3+2 = ... let's just recompute from the hex.
    expected_body = (
        "82024121"     # tag 82 transparent EF descriptor
        + "83022F00"   # tag 83 FID
        + "8A0105"     # tag 8A LCS
        + "8C0140"     # tag 8C sec attr
        + "80020010"   # tag 80 size
        + "8800"       # tag 88 no SFI
    )
    expected_len = len(expected_body) // 2
    expected = f"62{expected_len:02X}{expected_body}"
    assert out["fcp_hex"] == expected
