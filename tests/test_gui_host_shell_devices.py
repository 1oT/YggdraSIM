# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Coverage for the serial-device enumerator backing ``/api/host-shell/devices``."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def _make_dev_layout(root: Path) -> None:
    """Build a fake ``/dev`` tree with a couple of serial nodes.

    The enumerator walks both the ``serial/by-id/`` symlinks and the
    flat ``ttyUSB*`` / ``ttyACM*`` device files. We reproduce that here
    with regular files (the helper does not require character-special
    semantics; it only inspects path names).
    """
    (root / "ttyUSB0").write_bytes(b"")
    (root / "ttyUSB1").write_bytes(b"")
    (root / "ttyACM0").write_bytes(b"")
    (root / "ttyS0").write_bytes(b"")
    by_id = root / "serial" / "by-id"
    by_id.mkdir(parents=True, exist_ok=True)
    # symlink targeting the flat ttyUSB0 — the enumerator should
    # de-duplicate so the same canonical path doesn't appear twice.
    (by_id / "usb-Quectel_EG25-G-if02-port0").symlink_to(root / "ttyUSB0")


def test_enumerate_serial_devices_basic(tmp_path):
    from yggdrasim_common.gui_server import host_shell

    _make_dev_layout(tmp_path)

    rows = host_shell.enumerate_serial_devices(root=tmp_path)
    paths = [row["path"] for row in rows]
    # Expect: by-id symlink + ttyUSB1, ttyACM0, ttyS0. ttyUSB0 was
    # de-duplicated by the by-id entry pointing at the same canonical
    # target.
    assert any(p.endswith("/serial/by-id/usb-Quectel_EG25-G-if02-port0") for p in paths)
    assert any(p.endswith("/ttyUSB1") for p in paths)
    assert any(p.endswith("/ttyACM0") for p in paths)
    assert any(p.endswith("/ttyS0") for p in paths)


def test_enumerate_serial_devices_empty(tmp_path):
    from yggdrasim_common.gui_server import host_shell

    rows = host_shell.enumerate_serial_devices(root=tmp_path)
    assert rows == []


def test_enumerate_serial_devices_label_hint(tmp_path):
    from yggdrasim_common.gui_server import host_shell

    (tmp_path / "ttyUSB0").write_bytes(b"")
    (tmp_path / "ttyACM0").write_bytes(b"")
    (tmp_path / "ttyS0").write_bytes(b"")
    rows = host_shell.enumerate_serial_devices(root=tmp_path)
    by_label = {row["path"]: row["label"] for row in rows}
    assert by_label[str(tmp_path / "ttyUSB0")] == "USB-serial"
    assert by_label[str(tmp_path / "ttyACM0")] == "CDC-ACM"
    assert by_label[str(tmp_path / "ttyS0")] == "UART / built-in"


def test_enumerate_serial_devices_resolves_link_target(tmp_path):
    from yggdrasim_common.gui_server import host_shell

    _make_dev_layout(tmp_path)
    rows = host_shell.enumerate_serial_devices(root=tmp_path)
    for row in rows:
        if row["path"].endswith("/usb-Quectel_EG25-G-if02-port0"):
            assert row["link_target"] is not None
            assert row["link_target"].endswith("/ttyUSB0")
            return
    pytest.fail("by-id entry was missing from the enumerator output")
