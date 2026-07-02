# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit coverage for ``yggdrasim_common.gui_server.host_shell`` capability gates.

Exercises:

* :func:`is_enabled` honours the ``YGGDRASIM_GUI_HOST_SHELL`` truthy
  set and stays default-off when the flag is unset.
* :func:`resolve_shell` rejects ``$SHELL`` values that are not listed
  in ``/etc/shells`` (or its in-test equivalent), accepts well-known
  paths, and falls back to ``/bin/bash`` / ``/bin/sh``.
* :func:`describe_capability` produces the JSON shape consumed by the
  SPA, with an explanation when disabled.
* :func:`is_safe_device_path` accepts the conventional
  ``/dev/ttyUSB*`` / ``/dev/ttyACM*`` / ``/dev/serial/by-id/*`` shapes
  and rejects anything that smells like shell injection.

The PTY spawn helper itself is not exercised here — it forks a real
child and is covered by the route tests when those run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_host_shell_env(monkeypatch, tmp_path):
    """Default-off posture mirrors a fresh shell."""
    monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    yield


def test_is_enabled_default_off(monkeypatch):
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.is_enabled() is False


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "On"])
def test_is_enabled_truthy_strings(monkeypatch, truthy):
    from yggdrasim_common.gui_server import host_shell

    monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", truthy)
    assert host_shell.is_enabled() is True


@pytest.mark.parametrize("falsey", ["", "0", "false", "no", "off", "maybe"])
def test_is_enabled_falsey_strings(monkeypatch, falsey):
    from yggdrasim_common.gui_server import host_shell

    monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", falsey)
    assert host_shell.is_enabled() is False


def test_resolve_shell_accepts_listed_shell(monkeypatch, tmp_path):
    from yggdrasim_common.gui_server import host_shell

    fake_etc = tmp_path / "etc_shells"
    fake_etc.write_text("/bin/bash\n/bin/sh\n# comment\n", encoding="utf-8")
    monkeypatch.setattr(host_shell, "_ETC_SHELLS", fake_etc)
    # /bin/bash typically exists on the test host. If it doesn't, the
    # fallback chain still produces a valid shell.
    chosen = host_shell.resolve_shell({"SHELL": "/bin/bash"})
    assert chosen is not None
    assert chosen.startswith("/")


def test_resolve_shell_rejects_unlisted(monkeypatch, tmp_path):
    from yggdrasim_common.gui_server import host_shell

    fake_etc = tmp_path / "etc_shells"
    fake_etc.write_text("/bin/bash\n/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(host_shell, "_ETC_SHELLS", fake_etc)
    chosen = host_shell.resolve_shell({"SHELL": "/usr/bin/curl"})
    # Must not echo the attacker-supplied path back; falls back to one
    # of the bundled defaults if available, else None.
    assert chosen != "/usr/bin/curl"


def test_resolve_shell_rejects_relative(monkeypatch, tmp_path):
    from yggdrasim_common.gui_server import host_shell

    fake_etc = tmp_path / "etc_shells"
    fake_etc.write_text("/bin/bash\n/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(host_shell, "_ETC_SHELLS", fake_etc)
    chosen = host_shell.resolve_shell({"SHELL": "bash"})
    assert chosen != "bash"


def test_resolve_shell_falls_back_when_unset(monkeypatch, tmp_path):
    from yggdrasim_common.gui_server import host_shell

    fake_etc = tmp_path / "etc_shells"
    fake_etc.write_text("/bin/bash\n/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(host_shell, "_ETC_SHELLS", fake_etc)
    chosen = host_shell.resolve_shell({})
    # In a stripped container both fallbacks may be absent, in which
    # case None is the correct answer; otherwise we expect /bin/bash or
    # /bin/sh.
    if chosen is not None:
        assert chosen in ("/bin/bash", "/bin/sh")


def test_describe_capability_disabled(monkeypatch):
    from yggdrasim_common.gui_server import host_shell

    snapshot = host_shell.describe_capability()
    assert snapshot["supported"] in (True, False)
    assert snapshot["enabled"] is False
    assert snapshot["shell"] is None
    assert "YGGDRASIM_GUI_HOST_SHELL" in (snapshot["reason"] or "")


def test_describe_capability_enabled(monkeypatch):
    from yggdrasim_common.gui_server import host_shell

    monkeypatch.setenv("YGGDRASIM_GUI_HOST_SHELL", "1")
    snapshot = host_shell.describe_capability()
    assert snapshot["enabled"] is True
    assert snapshot["reason"] is None
    if snapshot["supported"]:
        assert snapshot["shell"] is None or snapshot["shell"].startswith("/")


def test_describe_hil_modem_capability_does_not_require_full_host_shell(monkeypatch):
    from yggdrasim_common.gui_server import host_shell

    monkeypatch.delenv("YGGDRASIM_GUI_HOST_SHELL", raising=False)
    snapshot = host_shell.describe_hil_modem_capability()
    assert snapshot["scope"] == "hil-modem"
    if snapshot["supported"]:
        assert snapshot["enabled"] is True
        assert "tio" in snapshot["allowed_commands"]
        assert snapshot["default_command"] == "sudo tio /dev/ttyUSB2"
        assert snapshot["default_command_source"] == "local"


def test_describe_hil_modem_capability_prefers_remote_card_bridge_target() -> None:
    from yggdrasim_common.gui_server import host_shell
    from yggdrasim_common.gui_server.actions import card_bridge

    card_bridge._write_remote_rig_state({
        "ssh_target": "pi@example.test",
        "identity_file": "~/.ssh/id_rpi",
    })
    snapshot = host_shell.describe_hil_modem_capability()

    if snapshot["supported"]:
        assert snapshot["default_command_source"] == "remote-card-bridge"
        assert snapshot["remote_target"] == "pi@example.test"
        assert "ssh -tt" in snapshot["default_command"]
        assert "pi@example.test" in snapshot["default_command"]
        assert "sudo tio /dev/ttyUSB2" in snapshot["default_command"]


def test_parse_hil_modem_command_accepts_sudo_tio() -> None:
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.parse_hil_modem_command("sudo tio /dev/ttyUSB2") == [
        "sudo",
        "tio",
        "/dev/ttyUSB2",
    ]


def test_parse_hil_modem_command_accepts_remote_ssh_tio() -> None:
    from yggdrasim_common.gui_server import host_shell

    command = (
        "ssh -tt -o BatchMode=yes -o ConnectTimeout=8 "
        "-i /home/user/.ssh/id_rpi pi@example.test sudo tio /dev/ttyUSB2"
    )
    assert host_shell.parse_hil_modem_command(command) == [
        "ssh",
        "-tt",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-i",
        "/home/user/.ssh/id_rpi",
        "pi@example.test",
        "sudo",
        "tio",
        "/dev/ttyUSB2",
    ]


@pytest.mark.parametrize("command", [
    "bash",
    "sudo bash",
    "tio /etc/passwd",
    "python -c print(1)",
    "ssh -tt pi@example.test sudo bash",
    "ssh -tt -o ProxyCommand=sh pi@example.test sudo tio /dev/ttyUSB2",
    "ssh -tt pi@example.test sudo tio /etc/passwd",
])
def test_parse_hil_modem_command_rejects_non_serial_commands(command: str) -> None:
    from yggdrasim_common.gui_server import host_shell

    with pytest.raises(ValueError):
        host_shell.parse_hil_modem_command(command)


@pytest.mark.parametrize("path", [
    "/dev/ttyUSB0",
    "/dev/ttyUSB12",
    "/dev/ttyACM0",
    "/dev/ttyS3",
    "/dev/serial/by-id/usb-Telit_HE910-D_0123456789AB-if02",
])
def test_is_safe_device_path_accepts_real_shapes(path):
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.is_safe_device_path(path) is True


@pytest.mark.parametrize("path", [
    "",
    "/dev/null",
    "/dev/ttyUSB0; rm -rf /",
    "/etc/passwd",
    "../etc/passwd",
    "/dev/ttyUSB0\nls",
    "/dev/serial/by-id/../../etc/passwd",
    "/dev/ttyUSB0$(reboot)",
])
def test_is_safe_device_path_rejects_injections(path):
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.is_safe_device_path(path) is False


def test_is_safe_device_path_length_cap():
    from yggdrasim_common.gui_server import host_shell

    very_long = "/dev/serial/by-id/" + ("A" * 300)
    assert host_shell.is_safe_device_path(very_long) is False


def test_parse_host_command_splits_tio_launch():
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.parse_host_command("sudo tio /dev/ttyUSB2") == [
        "sudo",
        "tio",
        "/dev/ttyUSB2",
    ]


def test_parse_host_command_preserves_quoted_args():
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.parse_host_command('tio -m "INLCRNL,ONLCRNL" /dev/ttyUSB2') == [
        "tio",
        "-m",
        "INLCRNL,ONLCRNL",
        "/dev/ttyUSB2",
    ]


def test_parse_host_command_empty_means_login_shell():
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.parse_host_command("") == []


@pytest.mark.parametrize("command", ['tio "unterminated', "tio " + ("A" * 600), "tio\0/dev/ttyUSB2"])
def test_parse_host_command_rejects_invalid(command):
    from yggdrasim_common.gui_server import host_shell

    with pytest.raises(ValueError):
        host_shell.parse_host_command(command)
