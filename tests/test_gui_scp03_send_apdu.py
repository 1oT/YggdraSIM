# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for ``scp03.send_apdu`` — the raw APDU console.

Pinned contract:

1. ``_normalise_apdu_hex`` accepts whitespace / 0x / dashes / underscores,
   folds to upper-case, and rejects non-hex, odd-length, and short-header
   inputs.

2. ``_parse_apdu_breakdown`` classifies short case 1/2/3/4 and extended
   case 2E/3E/4E framing (plus a "malformed" fallback), including the
   special zero-Le values 256 and 65,536.

3. ``_apdu_with_corrected_le`` implements the 6Cxx retry rule for short
   and extended APDUs without corrupting malformed command data.

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
    assert _normalise_apdu_hex("00 A4 00 04\n02 3F 00") == "00A40004023F00"


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
    assert bd["valid"] is False
    assert "exceeds supplied data" in bd["error"]


def test_parse_case2e_and_zero_le_semantics():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    bd = _parse_apdu_breakdown("00C00000000100")
    assert bd["case"] == "2E"
    assert bd["extended"] is True
    assert bd["lc"] == ""
    assert bd["le"] == "0100"
    assert bd["le_value"] == 256
    assert bd["data_hex"] == ""

    maximum = _parse_apdu_breakdown("00C00000000000")
    assert maximum["case"] == "2E"
    assert maximum["le"] == "0000"
    assert maximum["le_value"] == 65536


def test_parse_case3e_slices_two_byte_lc_and_data():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    data_hex = "AB" * 256
    bd = _parse_apdu_breakdown("00DA0000000100" + data_hex)
    assert bd["case"] == "3E"
    assert bd["lc"] == "0100"
    assert bd["data_length"] == 256
    assert bd["data_hex"] == data_hex
    assert bd["le"] == ""


def test_parse_case4e_requires_exactly_two_le_bytes():
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    bd = _parse_apdu_breakdown("00DA0000000002AABB0100")
    assert bd["case"] == "4E"
    assert bd["lc"] == "0002"
    assert bd["data_hex"] == "AABB"
    assert bd["le"] == "0100"
    assert bd["le_value"] == 256

    one_byte_le = _parse_apdu_breakdown("00DA0000000002AABB10")
    assert one_byte_le["case"] == "malformed"
    assert "expected 0 or 2" in one_byte_le["error"]


@pytest.mark.parametrize(
    ("apdu", "message"),
    [
        ("00DA00000001", "missing the two-byte"),
        ("00DA0000000000AA", "extended Lc=0"),
    ],
)
def test_parse_rejects_malformed_extended_framing(apdu, message):
    from yggdrasim_common.gui_server.actions.scp03 import _parse_apdu_breakdown

    bd = _parse_apdu_breakdown(apdu)
    assert bd["case"] == "malformed"
    assert bd["valid"] is False
    assert message in bd["error"]


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


def test_corrected_le_extended_cases_preserve_two_byte_framing():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    case2e = "00C00000000010"
    assert _apdu_with_corrected_le(case2e, 0x20) == "00C00000000020"

    case3e = "00DA0000000002AABB"
    assert _apdu_with_corrected_le(case3e, 0x20) == case3e + "0020"

    case4e = case3e + "0100"
    assert _apdu_with_corrected_le(case4e, 0x20) == case3e + "0020"


def test_corrected_extended_le_6c00_encodes_256_not_65536():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    # SW2=00 means exact Le=256. In extended framing that is 0100;
    # 0000 would request 65,536 bytes.
    assert _apdu_with_corrected_le("00C00000000010", 0x00) == "00C00000000100"


def test_corrected_le_refuses_malformed_framing():
    from yggdrasim_common.gui_server.actions.scp03 import _apdu_with_corrected_le

    with pytest.raises(ValueError, match="malformed APDU"):
        _apdu_with_corrected_le("00DA0000000002AABB10", 0x20)


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


def test_send_apdu_malformed_6c_does_not_corrupt_or_retry(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    malformed = "00DA0000000002AABB10"
    tp.script[malformed] = (b"", 0x6C, 0x20)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu=malformed,
        retry_6c=True,
    )

    assert out["sw"] == "6C20"
    assert out["chain"] == []
    assert "malformed APDU" in out["retry_warning"]
    assert tp.calls == [malformed]


@pytest.mark.parametrize(
    ("apdu", "get_response"),
    [
        ("01CA5A0000", "01C0000002"),
        ("42CA5A0000", "42C0000002"),
        ("80CA5A0000", "00C0000002"),
        ("81CA5A0000", "01C0000002"),
    ],
)
def test_send_apdu_get_response_preserves_logical_channel(
    monkeypatch,
    apdu,
    get_response,
):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script[apdu] = (b"", 0x61, 0x02)
    tp.script[get_response] = (bytes.fromhex("AABB"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(_Ctx(), session_id=sess.id, apdu=apdu)

    assert out["response_hex"] == "AABB"
    assert tp.calls == [apdu, get_response]


def test_send_apdu_corrects_get_response_le_instead_of_replaying_original(
    monkeypatch,
):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    original = "81CA5A0000"
    first_get_response = "01C0000010"
    corrected_get_response = "01C0000002"
    tp.script[original] = (b"", 0x61, 0x10)
    tp.script[first_get_response] = (b"", 0x6C, 0x02)
    tp.script[corrected_get_response] = (bytes.fromhex("AABB"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(_Ctx(), session_id=sess.id, apdu=original)

    assert out["response_hex"] == "AABB"
    assert tp.calls == [original, first_get_response, corrected_get_response]
    assert [step["reason"] for step in out["chain"]] == [
        "GET RESPONSE",
        "retry with corrected Le",
    ]


def test_send_apdu_follows_legacy_9f_continuation(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    tp.script["A0A40000023F00"] = (b"", 0x9F, 0x02)
    tp.script["00C0000002"] = (bytes.fromhex("CAFE"), 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="A0A40000023F00",
    )

    assert out["response_hex"] == "CAFE"
    assert tp.calls == ["A0A40000023F00", "00C0000002"]


def test_send_apdu_redacts_credential_command_from_result(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    verify = "002000010831323334FFFFFFFF"
    tp.script[verify] = (b"", 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(_Ctx(), session_id=sess.id, apdu=verify)

    assert tp.calls == [verify]
    assert out["apdu_redacted"] is True
    assert "31323334" not in out["apdu"]
    assert "31323334" not in str(out["breakdown"])


def test_send_apdu_redacts_authenticate_response_material(monkeypatch):
    from yggdrasim_common.gui_server.actions import scp03 as mod

    tp = _FakeTransporter()
    fs = _FakeFsController()
    sess = _FakeSession(tp, fs)
    authenticate = "0088008010" + ("AA" * 16) + "00"
    sensitive_response = bytes.fromhex(
        "DB04A1A2A3A410" + ("11" * 16) + "10" + ("22" * 16)
    )
    tp.script[authenticate] = (sensitive_response, 0x90, 0x00)
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu=authenticate,
    )

    assert out["response_redacted"] is True
    assert out["response_hex"] == ""
    assert out["response_length"] == len(sensitive_response)
    assert "A1A2A3A4" not in str(out)


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
    assert {
        "session_id",
        "apdu",
        "follow_61",
        "retry_6c",
        "include_wire_trace",
    }.issubset(field_names)


def test_send_apdu_uses_secure_transport_policy_for_followups(monkeypatch):
    from types import SimpleNamespace

    from SCP03.transport.card import ApduExchangeTrace, ApduTransmitResult
    from yggdrasim_common.gui_server.actions import scp03 as mod

    class _DetailedTransport:
        def __init__(self) -> None:
            self.session = SimpleNamespace(is_authenticated=True)
            self.calls: list[str] = []
            self.policy = None

        def transmit_detailed(self, command: str, *, policy):
            self.calls.append(command)
            self.policy = policy
            trace = (
                ApduExchangeTrace(
                    sequence=1,
                    phase="command",
                    command_length=5,
                    wire_command_length=13,
                    response_length=0,
                    clear_response_length=0,
                    sw1=0x61,
                    sw2=0x02,
                    secure_messaging=True,
                    response_verified=True,
                ),
                ApduExchangeTrace(
                    sequence=2,
                    phase="get-response",
                    command_length=5,
                    wire_command_length=13,
                    response_length=10,
                    clear_response_length=2,
                    sw1=0x90,
                    sw2=0x00,
                    secure_messaging=True,
                    response_verified=True,
                ),
            )
            return ApduTransmitResult(
                data=bytes.fromhex("CAFE"),
                sw1=0x90,
                sw2=0x00,
                trace=trace,
            )

    tp = _DetailedTransport()
    sess = _FakeSession(tp, _FakeFsController())
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00CA5A0000",
        follow_61=False,
        retry_6c=False,
    )

    assert tp.calls == ["00CA5A0000"]
    assert tp.policy.follow_response_data is False
    assert tp.policy.retry_wrong_length is False
    assert tp.policy.capture_apdu_bytes is False
    assert out["response_hex"] == "CAFE"
    assert out["chain"][0]["phase"] == "get-response"
    assert out["chain"][0]["secure_messaging"] is True
    assert out["chain"][0]["response_verified"] is True
    assert out["chain"][0]["apdu"].endswith("bytes hidden]")


def test_send_apdu_detailed_trace_redacts_pin_and_wire_command(monkeypatch):
    from types import SimpleNamespace

    from SCP03.transport.card import ApduExchangeTrace, ApduTransmitResult
    from yggdrasim_common.gui_server.actions import scp03 as mod

    verify = "002000010831323334FFFFFFFF"

    class _DetailedTransport:
        session = SimpleNamespace(is_authenticated=True)

        def transmit_detailed(self, command: str, *, policy):
            assert policy.capture_apdu_bytes is True
            trace = (
                ApduExchangeTrace(
                    sequence=1,
                    phase="command",
                    command_length=len(bytes.fromhex(command)),
                    wire_command_length=29,
                    response_length=8,
                    clear_response_length=0,
                    sw1=0x90,
                    sw2=0x00,
                    secure_messaging=True,
                    response_verified=True,
                    command_hex=command,
                    wire_command_hex="84" + ("AA" * 28),
                    wire_response_hex="11" * 8,
                    clear_response_hex="",
                ),
            )
            return ApduTransmitResult(b"", 0x90, 0x00, trace)

    tp = _DetailedTransport()
    sess = _FakeSession(tp, _FakeFsController())
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu=verify,
        include_wire_trace=True,
    )

    assert out["apdu_redacted"] is True
    assert "31323334" not in str(out)
    assert out["transport_trace"][0]["wire_apdu_hex"] == "[REDACTED]"


def test_send_apdu_detailed_rmac_failure_is_fail_closed(monkeypatch):
    from types import SimpleNamespace

    from SCP03.transport.card import ApduExchangeTrace, ApduTransportError
    from yggdrasim_common.gui_server.actions import scp03 as mod

    class _DetailedTransport:
        def __init__(self) -> None:
            self.session = SimpleNamespace(is_authenticated=True)

        def transmit_detailed(self, command: str, *, policy):
            self.session.is_authenticated = False
            trace = (
                ApduExchangeTrace(
                    sequence=1,
                    phase="command",
                    command_length=len(bytes.fromhex(command)),
                    wire_command_length=13,
                    response_length=12,
                    clear_response_length=0,
                    sw1=0x90,
                    sw2=0x00,
                    secure_messaging=True,
                    response_verified=False,
                    command_hex=command,
                    wire_command_hex="84" + ("AA" * 12),
                    wire_response_hex="DEADBEEF0011223344556677",
                    clear_response_hex=None,
                    error="Scp03ResponseProtectionError",
                ),
            )
            raise ApduTransportError(
                "R-MAC verification failed",
                trace=trace,
                cause_type="Scp03ResponseProtectionError",
            )

    tp = _DetailedTransport()
    sess = _FakeSession(tp, _FakeFsController())
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00CA5A0000",
        include_wire_trace=True,
    )

    assert out["ok"] is False
    assert out["sw"] == "6F00"
    assert out["response_hex"] == ""
    assert "DEADBEEF" not in str(out)
    assert out["transport_trace"][0]["response_verified"] is False
    assert out["session_invalidated"] is True
    assert "re-authentication" in out["session_invalidation_reason"]


def test_send_apdu_reports_select_session_invalidation(monkeypatch):
    from types import SimpleNamespace

    from SCP03.transport.card import ApduExchangeTrace, ApduTransmitResult
    from yggdrasim_common.gui_server.actions import scp03 as mod

    reason = "Successful SELECT terminated SCP03; re-authentication is required."

    class _DetailedTransport:
        def __init__(self) -> None:
            self.session = SimpleNamespace(is_authenticated=True)

        def transmit_detailed(self, command: str, *, policy):
            self.session.is_authenticated = False
            trace = (
                ApduExchangeTrace(
                    sequence=1,
                    phase="command",
                    command_length=len(bytes.fromhex(command)),
                    wire_command_length=13,
                    response_length=0,
                    clear_response_length=0,
                    sw1=0x90,
                    sw2=0x00,
                    secure_messaging=True,
                    response_verified=True,
                ),
            )
            return ApduTransmitResult(
                b"",
                0x90,
                0x00,
                trace,
                session_invalidated=True,
                invalidation_reason=reason,
            )

    tp = _DetailedTransport()
    sess = _FakeSession(tp, _FakeFsController())
    _install_fake_manager(monkeypatch, sess)

    out = mod._dispatch_send_apdu(
        _Ctx(),
        session_id=sess.id,
        apdu="00A4040000",
    )

    assert out["ok"] is True
    assert out["session_invalidated"] is True
    assert out["session_invalidation_reason"] == reason
