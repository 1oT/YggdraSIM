# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``scp03.send_apdu`` — the raw APDU console.

Pinned contract:

1. ``_normalise_apdu_hex`` accepts whitespace / 0x / dashes / underscores,
   folds to upper-case, and rejects non-hex, odd-length, and short-header
   inputs.

2. ``_parse_apdu_breakdown`` classifies APDUs as ISO 7816-4
   case 1/2/3/4 (plus a "malformed" fallback) and returns the correct
   slice of Data / Le given the declared Lc byte.

3. ``_apdu_with_corrected_le`` implements the 6Cxx retry rule:
   replace the trailing Le byte for case-2/4, append for case-1/3.

4. ``_dispatch_send_apdu``:
   * Transmits the normalised APDU verbatim.
   * Auto-follows 61xx with GET RESPONSE (``00C00000xx``) until SW
     changes, appending the returned bytes to the response buffer.
   * Retries 6Cxx once with the card-suggested Le and replaces the
     response buffer (same logical read, correct length).
   * Respects ``follow_61=False`` / ``retry_6c=False`` toggles.
   * Does **not** restore MF afterwards — the whole point of this
     dispatcher is to leave the card wherever the operator's APDU
     put it. The file-tree click will re-anchor MF later.
   * Returns a decoded breakdown, ASCII preview, SW meaning from
     ``StatusWordTranslator.translate``, and a ``chain`` list of
     implicit follow-up APDUs.

Tests are dependency-free: no PC/SC, no pySim, no real card. The
fake transporter records every ``transmit`` call and serves scripted
replies keyed by APDU hex.
"""

from __future__ import annotations

from typing import Any

import pytest


# ----------------------------------------------------------------------
# Fakes
# ----------------------------------------------------------------------


class _FakeTransporter:
    """Records transmit() calls; returns scripted replies."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.script: dict[str, tuple[bytes, int, int]] = {}
        self.default_reply: tuple[bytes, int, int] = (b"", 0x90, 0x00)

    def transmit(
        self, cmd: str, silent: bool = False
    ) -> tuple[bytes, int, int]:
        cmd_up = str(cmd).upper()
        self.calls.append(cmd_up)
        if cmd_up in self.script:
            return self.script[cmd_up]
        return self.default_reply


class _FakeFsController:
    def __init__(self) -> None:
        self.current_fid = "A000000559"
        self.current_path_hint = "ISD-R"
        self.current_fcp: dict[str, Any] = {}


class _FakeSession:
    def __init__(self, tp: _FakeTransporter, fs: _FakeFsController) -> None:
        self.kind = "scp03"
        self.handle = {"transporter": tp, "fs": fs}
        self.id = "sess-apdu-fake"


class _FakeManager:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def get(self, sid: str) -> _FakeSession:
        assert sid == self._session.id
        return self._session


def _install_fake_manager(monkeypatch, session: _FakeSession) -> None:
    from yggdrasim_common.gui_server import sessions as sessions_mod

    monkeypatch.setattr(
        sessions_mod, "get_manager", lambda: _FakeManager(session)
    )


class _Ctx:
    """Minimal action-context stand-in (dispatcher only reads kwargs)."""


# ----------------------------------------------------------------------
# _normalise_apdu_hex
# ----------------------------------------------------------------------


def test_normalise_accepts_spaces_and_dashes():
    from yggdrasim_common.gui_server.actions.scp03 import _normalise_apdu_hex

    assert _normalise_apdu_hex("00 A4 00 04 02 3F 00") == "00A40004023F00"
    assert _normalise_apdu_hex("00-A4-00-04-02-3F-00") == "00A40004023F00"
    assert _normalise_apdu_hex("00_A4_00_04_02_3F_00") == "00A40004023F00"


def test_normalise_strips_0x_prefix_and_folds_upper():
    from yggdrasim_common.gui_server.actions.scp03 import _normalise_apdu_hex

    assert _normalise_apdu_hex("0x00a40004023f00") == "00A40004023F00"


def test_normalise_rejects_empty_and_odd_and_non_hex():
    from yggdrasim_common.gui_server.actions.scp03 import _normalise_apdu_hex

    with pytest.raises(ValueError, match="apdu is required"):
        _normalise_apdu_hex("")
    with pytest.raises(ValueError, match="apdu is required"):
        _normalise_apdu_hex("   ")
    with pytest.raises(ValueError, match="even-length hex"):
        _normalise_apdu_hex("00A4000")
    with pytest.raises(ValueError, match="non-hex character"):
        _normalise_apdu_hex("00A4ZZ00")


def test_normalise_rejects_short_header():
    from yggdrasim_common.gui_server.actions.scp03 import _normalise_apdu_hex

    with pytest.raises(ValueError, match="at least 4 bytes"):
        _normalise_apdu_hex("00A4")


# ----------------------------------------------------------------------
# _parse_apdu_breakdown
# ----------------------------------------------------------------------


def test_parse_case1_select_no_data_no_le():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    bd = _parse_apdu_breakdown("80F28002")
    assert bd["case"] == "1"
    assert bd["cla"] == "80"
    assert bd["ins"] == "F2"
    assert bd["p1"] == "80"
    assert bd["p2"] == "02"
    assert bd["lc"] == ""
    assert bd["data_hex"] == ""
    assert bd["le"] == ""
    assert bd["byte_count"] == 4


def test_parse_case2_get_data_with_le():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    # Case 2 = CLA INS P1 P2 Le (5 bytes). ``80CA5A0000`` is
    # GET DATA, tag 0x5A (EID), with Le=00 → "send me everything".
    bd = _parse_apdu_breakdown("80CA5A0000")
    assert bd["case"] == "2"
    assert bd["le"] == "00"
    assert bd["data_length"] == 0


def test_parse_case3_select_by_aid_no_le():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    apdu = "00A40404" + "05" + "A000000151"
    bd = _parse_apdu_breakdown(apdu)
    assert bd["case"] == "3"
    assert bd["lc"] == "05"
    assert bd["data_hex"] == "A000000151"
    assert bd["data_length"] == 5
    assert bd["le"] == ""


def test_parse_case4_install_with_le():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    apdu = "80E60C00" + "03" + "AABBCC" + "00"
    bd = _parse_apdu_breakdown(apdu)
    assert bd["case"] == "4"
    assert bd["lc"] == "03"
    assert bd["data_hex"] == "AABBCC"
    assert bd["data_length"] == 3
    assert bd["le"] == "00"


def test_parse_malformed_lc_mismatch():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    apdu = "00A40404" + "05" + "A000"
    bd = _parse_apdu_breakdown(apdu)
    assert bd["case"] == "malformed"


# ----------------------------------------------------------------------
# _apdu_with_corrected_le
# ----------------------------------------------------------------------


def test_corrected_le_case1_appends():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    assert _apdu_with_corrected_le("80F28002", 0x20) == "80F2800220"


def test_corrected_le_case2_replaces():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    # Case 2 APDU: CLA INS P1 P2 Le — retry replaces the trailing Le.
    assert _apdu_with_corrected_le("80CA5A0000", 0x30) == "80CA5A0030"


def test_corrected_le_case3_appends():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    apdu = "00A40404" + "05" + "A000000151"
    assert _apdu_with_corrected_le(apdu, 0x40) == apdu + "40"


def test_corrected_le_case4_replaces_trailing_byte():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    apdu = "80E60C00" + "03" + "AABBCC" + "00"
    expected = "80E60C00" + "03" + "AABBCC" + "50"
    assert _apdu_with_corrected_le(apdu, 0x50) == expected


# ----------------------------------------------------------------------
# _dispatch_send_apdu — happy path (no chain)
# ----------------------------------------------------------------------


def test_send_apdu_happy_path_no_chain(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["80CA5A00"] = (bytes.fromhex("5A0998000000000000000F"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="80 CA 5A 00",
        follow_61=True,
        retry_6c=True,
    )

    assert out["apdu"] == "80CA5A00"
    assert out["sw"] == "9000"
    assert out["ok"] is True
    assert out["response_hex"] == "5A0998000000000000000F"
    assert out["response_length"] == 11
    assert out["chain"] == []
    # Did NOT restore MF — the whole point of this dispatcher.
    assert "00A40004023F00" not in tp.calls
    # Exactly one APDU on the wire.
    assert tp.calls == ["80CA5A00"]


# ----------------------------------------------------------------------
# _dispatch_send_apdu — 61xx auto-follow
# ----------------------------------------------------------------------


def test_send_apdu_follows_61xx_with_get_response(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    # Initial returns 61 0A — 10 bytes ready to be fetched.
    tp.script["80F240020243C0000000"] = (b"", 0x61, 0x0A)
    # GET RESPONSE for 10 bytes returns the payload + 9000.
    tp.script["00C000000A"] = (bytes.fromhex("AABBCCDDEEFF00112233"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="80F240020243C0000000",
        follow_61=True,
        retry_6c=True,
    )

    assert out["sw"] == "9000"
    assert out["ok"] is True
    assert out["response_hex"] == "AABBCCDDEEFF00112233"
    assert out["response_length"] == 10
    assert len(out["chain"]) == 1
    step = out["chain"][0]
    assert step["apdu"] == "00C000000A"
    assert step["reason"] == "GET RESPONSE"
    assert step["sw"] == "9000"
    # Wire order: original APDU then GET RESPONSE.
    assert tp.calls == ["80F240020243C0000000", "00C000000A"]


def test_send_apdu_chains_multiple_61xx(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["80CA9F7F00"] = (b"", 0x61, 0x04)
    tp.script["00C0000004"] = (bytes.fromhex("AABBCCDD"), 0x61, 0x02)
    tp.script["00C0000002"] = (bytes.fromhex("EEFF"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="80CA9F7F00",
        follow_61=True,
        retry_6c=True,
    )

    assert out["sw"] == "9000"
    # Concatenated across both GET RESPONSE steps.
    assert out["response_hex"] == "AABBCCDDEEFF"
    assert out["response_length"] == 6
    assert len(out["chain"]) == 2
    assert tp.calls == [
        "80CA9F7F00",
        "00C0000004",
        "00C0000002",
    ]


def test_send_apdu_follow_61_false_leaves_it_to_caller(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["80F280020243C0000000"] = (b"", 0x61, 0x10)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="80F280020243C0000000",
        follow_61=False,
        retry_6c=True,
    )

    assert out["sw"] == "6110"
    assert out["ok"] is False
    assert out["chain"] == []
    assert tp.calls == ["80F280020243C0000000"]


# ----------------------------------------------------------------------
# _dispatch_send_apdu — 6Cxx retry
# ----------------------------------------------------------------------


def test_send_apdu_retries_6cxx_with_corrected_le(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    # Initial READ BINARY with Le=00 — card says 6C10 (need Le=10).
    tp.script["00B0000000"] = (b"", 0x6C, 0x10)
    # Retry replaces the Le byte: 00B0000010 returns 16 bytes + 9000.
    tp.script["00B0000010"] = (
        bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
        0x90,
        0x00,
    )
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00B0000000",
        follow_61=True,
        retry_6c=True,
    )

    assert out["sw"] == "9000"
    assert out["response_hex"] == "00112233445566778899AABBCCDDEEFF"
    assert out["response_length"] == 16
    assert len(out["chain"]) == 1
    step = out["chain"][0]
    assert step["apdu"] == "00B0000010"
    assert "corrected Le" in step["reason"]
    assert tp.calls == ["00B0000000", "00B0000010"]


def test_send_apdu_retry_6c_false_leaves_sw_as_is(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["00B0000000"] = (b"", 0x6C, 0x10)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00B0000000",
        follow_61=True,
        retry_6c=False,
    )

    assert out["sw"] == "6C10"
    assert out["ok"] is False
    assert out["chain"] == []
    assert tp.calls == ["00B0000000"]


# ----------------------------------------------------------------------
# _dispatch_send_apdu — result shape / metadata
# ----------------------------------------------------------------------


def test_send_apdu_returns_breakdown_and_sw_meaning(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["00A40004023F00"] = (bytes.fromhex("623A8202782183023F00"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00A40004023F00",
    )

    bd = out["breakdown"]
    assert bd["case"] == "3"
    assert bd["cla"] == "00"
    assert bd["ins"] == "A4"
    assert bd["lc"] == "02"
    assert bd["data_hex"] == "3F00"
    assert out["sw_meaning"] == "Success"
    # Printable-byte ASCII preview for FCP — mostly binary so most
    # bytes decode to "."; just assert the length matches the hex.
    assert len(out["response_ascii"]) == len(bytes.fromhex(out["response_hex"]))


def test_send_apdu_ascii_preview_for_printable_response(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    # Contrived APDU → response "Hello!" (48 65 6C 6C 6F 21).
    tp.script["00B0000006"] = (b"Hello!", 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00B0000006",
    )

    assert out["response_hex"] == "48656C6C6F21"
    assert out["response_ascii"] == "Hello!"


def test_send_apdu_no_mf_restore_after_call(monkeypatch):
    """Dispatcher must NOT restore MF — operator owns the card state."""
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    # Script a raw SELECT-by-AID which would naturally leave the DF
    # on ISD-R. If the dispatcher quietly called the restore helper
    # we'd see 00A40004023F00 in tp.calls after the initial APDU.
    tp.script["00A4040010A0000005591010FFFFFFFF8900000100"] = (
        bytes.fromhex("6F108408A000000559101083025A01"),
        0x90,
        0x00,
    )
    _install_fake_manager(monkeypatch, sess)

    mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00A4040010A0000005591010FFFFFFFF8900000100",
    )

    assert "00A40004023F00" not in tp.calls, (
        "send_apdu must NOT restore MF — operator owns the card state; "
        f"got calls {tp.calls!r}"
    )


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


def test_send_apdu_spec_registered():
    from yggdrasim_common.gui_server.actions.registry import get_registry
    from yggdrasim_common.gui_server.actions import scp03  # noqa: F401

    spec = get_registry().get("scp03.send_apdu")
    assert spec is not None
    assert spec.subsystem == "SCP03"
    assert spec.requires_card is True
    field_names = {f.name for f in spec.inputs}
    assert {"session_id", "apdu", "follow_61", "retry_6c"}.issubset(field_names)
