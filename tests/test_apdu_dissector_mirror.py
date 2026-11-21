# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Lua the decode surfaces hand to tshark, and what the line then says.

Wireshark ships an AppArmor profile on some distributions that denies
tshark every read under ``$HOME``. The plugin lives in the checkout, so
tshark refuses to load it and decodes without it -- and a refused ``-X``
is a warning on stderr, not an error, so the only symptom is a thinner
Info column and a permission line in the status chip.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from Tools.ApduDissector.tshark_runner import (
    DISSECTOR_FILENAME,
    dissector_arguments,
    mirrored_lua_directory,
)
from Tools.HilBridge.live_decode_state import _suffix_adds_nothing


def test_the_lua_is_mirrored_somewhere_tshark_may_read() -> None:
    """The mirror carries the whole tree, not just the entry point."""
    mirror = mirrored_lua_directory()
    assert mirror is not None
    assert (mirror / DISSECTOR_FILENAME).is_file()
    # The entry point requires its submodules beside it.
    assert (mirror / "yggdrasim_apdu").is_dir()
    assert list((mirror / "yggdrasim_apdu").glob("*.lua"))

    # tshark executes what it finds there, so it must not be writable by
    # anyone else.
    mode = mirror.stat().st_mode
    assert mode & 0o022 == 0, oct(mode)
    assert mirror.stat().st_uid == os.getuid()

    # And that is the path handed to tshark.
    args = dissector_arguments()
    assert args[0] == "-X"
    assert args[1] == f"lua_script:{mirror / DISSECTOR_FILENAME}"


def test_the_mirror_is_refreshed_when_the_checkout_changes() -> None:
    """A stale mirror would decode with yesterday's dissector, silently."""
    mirror = mirrored_lua_directory()
    assert mirror is not None
    entry = mirror / DISSECTOR_FILENAME
    original = entry.read_bytes()

    entry.write_bytes(b"-- stale\n")
    refreshed = mirrored_lua_directory()
    assert refreshed is not None
    assert (refreshed / DISSECTOR_FILENAME).read_bytes() == original


def test_a_mirror_owned_by_somebody_else_is_refused(tmp_path: Path) -> None:
    """Rather than execute Lua from a directory this user does not own."""
    from Tools.ApduDissector import tshark_runner

    foreign = tmp_path / "foreign"
    foreign.mkdir()

    class _Stat:
        st_uid = os.getuid() + 1
        st_mode = 0o755

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tshark_runner.tempfile, "gettempdir", lambda: str(tmp_path))
        patch.setattr(
            tshark_runner.Path,
            "stat",
            lambda self, **_kwargs: _Stat(),
            raising=False,
        )
        # The directory name the helper derives must already exist for the
        # ownership branch to be the one under test.
        (tmp_path / f"yggdrasim-apdu-dissector-{os.getuid()}").mkdir(exist_ok=True)
        assert mirrored_lua_directory() is None


@pytest.mark.parametrize(
    ("line", "suffix", "redundant"),
    [
        # The suffix was written against the stock dissector, which named
        # little more than the instruction. Ours names the command, the
        # file and the status word, so these now say it twice.
        ("FETCH PROVIDE LOCAL INFORMATION -> 9000 Success", "STK PROVIDE LOCAL INFORMATION", True),
        ("TERMINAL_RESPONSE PROVIDE LOCAL INFORMATION: ok", "STK TERMINAL RESPONSE", True),
        ("SELECT MF / EF.ARR -> 9000", "FS MF/EF.ARR", True),
        # These carry something the line does not, and must survive.
        ("GET_STATUS scope 0x00 -> 910B. 11 bytes of proactive data.", "FETCH PENDING 11B", False),
        ("SELECT MF / EF.ICCID -> 6119 Success.", "ICCID 8988201234567890123", False),
        ("READ BINARY", "SCP03 decrypted: 9000", False),
        ("GET RESPONSE", "STK REFRESH UICC RESET", False),
        ("SELECT MF", "FS MF/DF.TELECOM/EF.ADN", False),
    ],
)
def test_an_annotation_is_dropped_only_when_it_repeats_the_line(
    line: str, suffix: str, redundant: bool
) -> None:
    assert _suffix_adds_nothing(line, suffix) is redundant
