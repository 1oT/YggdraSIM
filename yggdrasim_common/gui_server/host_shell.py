# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Host-shell PTY bridge for the GUI ``Advanced > Host shell`` tab.

Operationally this is a sibling of :mod:`yggdrasim_common.gui_server.terminal`,
but the trust posture is different: the existing terminal bridge restricts
``execvpe`` to ``python -m <module>`` against
:data:`yggdrasim_common.registry.CLI_MODULES`, while this module spawns
the operator's interactive login shell with no argv allow-list. Anyone
holding the bearer token therefore gets a capability comparable to an
SSH session as the user that launched ``yggdrasim``.

Because of that, the surface is gated behind
``YGGDRASIM_GUI_HOST_SHELL=1`` — :func:`is_enabled` is the single source
of truth and is consulted both at app-factory time (to skip route
registration) and at WebSocket-handshake time (to refuse late-flipped
config). The frontend reads :func:`describe_capability` via
``/api/host-shell/capabilities`` so it can hide the sidebar entry when
the flag is off without leaking a 404.

Helper surface
--------------

* :func:`is_supported` — POSIX gate (the underlying
  :class:`~yggdrasim_common.gui_server.terminal.PtySession` only works
  through ``pty.fork``).
* :func:`is_enabled` — env-flag gate.
* :func:`resolve_shell` — pick the operator's login shell, validated
  against ``/etc/shells`` to keep ``SHELL=/usr/bin/curl`` style abuse
  out of the spawn argv.
* :func:`spawn_host_shell` — async wrapper over
  :class:`PtySession` that bypasses :func:`PtySession.spawn`'s module
  allow-list. By default it launches the operator login shell; callers
  may provide an explicit argv-style command for modem tools.
* :func:`enumerate_serial_devices` — best-effort enumeration of
  ``/dev/ttyUSB*`` / ``/dev/ttyACM*`` / ``/dev/serial/by-id/*`` so the
  frontend can offer a convenient "insert this path at the cursor"
  dropdown.

See :file:`guides/GUI_HOST_SHELL_GUIDE.md` for the operator-facing
walkthrough: enabling the env flag, sidebar UX, capability / device /
WebSocket reference, modem-CLI recipes, threat model, and the
troubleshooting matrix.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import logging
import os
import re
import shlex
import struct
import sys
import termios
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from yggdrasim_common.gui_server.terminal import (
    PtySession,
    _DEFAULT_COLS,
    _DEFAULT_ROWS,
    _set_nonblocking,
    is_supported as _pty_is_supported,
)


_LOGGER = logging.getLogger("yggdrasim.gui.host_shell")


_ENV_FLAG_NAME = "YGGDRASIM_GUI_HOST_SHELL"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

_DEFAULT_SHELL_FALLBACK = "/bin/bash"
_DEFAULT_SHELL_FALLBACK_2 = "/bin/sh"

_ETC_SHELLS = Path("/etc/shells")

_SERIAL_PATH_RE = re.compile(
    r"^/dev/("
    r"tty(USB|ACM|S)\d+"
    r"|serial/by-id/[A-Za-z0-9._:\-+]+"
    r")$"
)

_MAX_COMMAND_LENGTH = 512
_HIL_MODEM_DEFAULT_DEVICE = "/dev/ttyUSB2"
_HIL_MODEM_DEFAULT_COMMAND = f"sudo tio {_HIL_MODEM_DEFAULT_DEVICE}"
_HIL_MODEM_TERMINAL_COMMANDS = frozenset({"tio", "minicom", "picocom", "screen"})
_HIL_MODEM_PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas"})
_HIL_MODEM_SSH_FLAGS = frozenset({"-t", "-tt"})
_HIL_MODEM_SSH_ALLOWED_OPTIONS = frozenset({
    "BatchMode=yes",
    "ConnectTimeout=8",
    "ServerAliveInterval=30",
    "ServerAliveCountMax=3",
})


# ---------------------------------------------------------------------------
# Capability gates
# ---------------------------------------------------------------------------


def is_supported() -> bool:
    """POSIX gate matching :func:`yggdrasim_common.gui_server.terminal.is_supported`."""
    return _pty_is_supported()


def is_enabled() -> bool:
    """Return ``True`` when ``YGGDRASIM_GUI_HOST_SHELL`` is truthy.

    The env flag is read on every call (rather than cached at import)
    so test harnesses can flip it via ``monkeypatch.setenv`` without a
    process restart.
    """
    raw = os.environ.get(_ENV_FLAG_NAME)
    if raw is None:
        return False
    return str(raw).strip().lower() in _TRUTHY


def describe_capability() -> dict:
    """Snapshot the host-shell capability for ``/api/host-shell/capabilities``.

    The response is intentionally minimal — it only needs to drive the
    sidebar entry visibility and tell the frontend which shell will be
    spawned. ``shell`` is ``None`` when the platform cannot resolve a
    valid shell at all (e.g. neither ``/bin/bash`` nor ``/bin/sh`` is
    present, which would only happen in extremely stripped containers).
    """
    if not is_supported():
        return {
            "supported": False,
            "enabled": False,
            "shell": None,
            "reason": "PTY bridge is not supported on this platform.",
        }
    enabled = is_enabled()
    shell_path = resolve_shell() if enabled else None
    return {
        "supported": True,
        "enabled": enabled,
        "shell": shell_path,
        "reason": (
            None
            if enabled
            else (
                "Host shell is opt-in. Set YGGDRASIM_GUI_HOST_SHELL=1 to "
                "enable; restart yggdrasim-gui / yggdrasim-web-server afterwards."
            )
        ),
    }


def describe_hil_modem_capability() -> dict:
    """Snapshot the constrained HIL modem-shell capability.

    Unlike the general Host shell surface, this scope does not launch an
    arbitrary login shell. It accepts only known serial terminal
    commands with an explicit serial device path and is therefore safe
    to expose from the HIL module without enabling the full host-shell
    tab.
    """
    if not is_supported():
        return {
            "supported": False,
            "enabled": False,
            "shell": None,
            "scope": "hil-modem",
            "reason": "PTY bridge is not supported on this platform.",
        }
    command_payload = _hil_modem_default_command_payload()
    return {
        "supported": True,
        "enabled": True,
        "shell": None,
        "scope": "hil-modem",
        "reason": None,
        "command_policy": "serial-terminal-only",
        "allowed_commands": sorted(_HIL_MODEM_TERMINAL_COMMANDS),
        **command_payload,
    }


def _hil_modem_default_command_payload() -> dict[str, str]:
    """Return the modem-shell command preference for the current rig."""
    remote_command = _remote_card_bridge_modem_command()
    if remote_command:
        return {
            "default_command": remote_command["command"],
            "default_command_source": "remote-card-bridge",
            "remote_target": remote_command["target"],
        }
    return {
        "default_command": _HIL_MODEM_DEFAULT_COMMAND,
        "default_command_source": "local",
        "remote_target": "",
    }


def _remote_card_bridge_modem_command() -> Optional[dict[str, str]]:
    """Build a constrained SSH terminal command from saved Card Bridge state."""
    try:
        from yggdrasim_common.gui_server.actions import card_bridge

        state = card_bridge._load_remote_rig_state()
        target = card_bridge._validate_ssh_target(state.get("ssh_target"))
        ssh_command = card_bridge._ssh_base_command(
            ssh_target=target,
            identity_file=state.get("identity_file"),
            connect_timeout=8,
        )
    except Exception:
        return None
    if len(ssh_command) == 0:
        return None
    ssh_command.insert(1, "-tt")
    ssh_command.extend(["sudo", "tio", _HIL_MODEM_DEFAULT_DEVICE])
    return {
        "command": shlex.join(ssh_command),
        "target": target,
    }


# ---------------------------------------------------------------------------
# Shell resolution
# ---------------------------------------------------------------------------


def _read_etc_shells() -> tuple[str, ...]:
    """Return the absolute shell paths listed in ``/etc/shells``.

    Comments and blank lines are skipped. Falls back to a small built-in
    list when ``/etc/shells`` is missing (the file is not always present
    on minimal images).
    """
    fallback = (_DEFAULT_SHELL_FALLBACK, _DEFAULT_SHELL_FALLBACK_2)
    if not _ETC_SHELLS.is_file():
        return fallback
    try:
        raw = _ETC_SHELLS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback
    paths: list[str] = []
    for line in raw.splitlines():
        candidate = line.strip()
        if len(candidate) == 0:
            continue
        if candidate.startswith("#"):
            continue
        if not candidate.startswith("/"):
            continue
        paths.append(candidate)
    if len(paths) == 0:
        return fallback
    return tuple(paths)


def resolve_shell(env: Optional[dict[str, str]] = None) -> Optional[str]:
    """Return an absolute shell path safe to ``execvpe``.

    Resolution order:

    1. ``$SHELL`` from *env* (or :data:`os.environ`) — accepted only if
       it's an absolute path that exists, is executable, and is listed
       in ``/etc/shells``. The ``/etc/shells`` check rules out
       ``SHELL=/usr/bin/curl`` style abuse where an attacker has
       polluted the env.
    2. ``/bin/bash`` if executable.
    3. ``/bin/sh`` if executable.
    4. ``None`` — caller must refuse the spawn.
    """
    source = env if env is not None else dict(os.environ)
    raw_shell = source.get("SHELL", "")
    candidate = str(raw_shell or "").strip()
    allowed = _read_etc_shells()
    if (
        len(candidate) > 0
        and candidate.startswith("/")
        and candidate in allowed
        and os.path.isfile(candidate)
        and os.access(candidate, os.X_OK)
    ):
        return candidate
    for fallback in (_DEFAULT_SHELL_FALLBACK, _DEFAULT_SHELL_FALLBACK_2):
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback
    return None


# ---------------------------------------------------------------------------
# Serial-device enumeration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SerialDevice:
    """One row in the host-shell device picker."""

    path: str
    link_target: Optional[str]
    label: str


def enumerate_serial_devices(root: Optional[Path] = None) -> list[dict]:
    """Return a JSON-serialisable list of serial devices.

    *root* is exposed for tests so a fixture directory can stand in for
    ``/dev/``. Production calls leave it as ``None``.

    Sources scanned:

    * ``/dev/serial/by-id/*`` — symlinks named after the USB
      vendor/product/serial; the most stable identifier and what
      operators usually paste into ``socat`` / ``tio``.
    * ``/dev/ttyUSB*`` — USB-serial adapters (FTDI, CP210x, CH34x).
    * ``/dev/ttyACM*`` — CDC-ACM modems (Telit, Sierra, Quectel).
    * ``/dev/ttyS*`` — built-in UART / pass-through ports.

    Devices that resolve to the same underlying ``/dev/ttyUSB*`` /
    ``/dev/ttyACM*`` are de-duplicated by canonical path; the
    ``by-id`` entry wins because its path is more readable.
    """
    base = Path(root) if root is not None else Path("/dev")

    seen_canonical: dict[str, dict] = {}

    def _record(path: Path, label_hint: str) -> None:
        try:
            real = path.resolve(strict=False)
        except OSError:
            real = path
        canonical = str(real)
        link_target: Optional[str] = None
        if str(path) != canonical:
            link_target = canonical
        entry = {
            "path": str(path),
            "link_target": link_target,
            "label": label_hint,
        }
        prior = seen_canonical.get(canonical)
        if prior is None:
            seen_canonical[canonical] = entry
            return
        if prior.get("path", "").startswith(str(base / "ttyUSB")) or prior.get("path", "").startswith(str(base / "ttyACM")):
            seen_canonical[canonical] = entry

    by_id_dir = base / "serial" / "by-id"
    if by_id_dir.is_dir():
        try:
            entries = sorted(by_id_dir.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            entries = []
        for entry in entries:
            _record(entry, label_hint=f"by-id · {entry.name}")

    for prefix, label in (
        ("ttyUSB", "USB-serial"),
        ("ttyACM", "CDC-ACM"),
        ("ttyS", "UART / built-in"),
    ):
        try:
            siblings = sorted(base.glob(prefix + "*"), key=lambda p: p.name)
        except OSError:
            siblings = []
        for entry in siblings:
            try:
                if entry.is_dir():
                    continue
            except OSError:
                continue
            _record(entry, label_hint=label)

    rows = list(seen_canonical.values())
    rows.sort(key=lambda row: row["path"])
    return rows


def is_safe_device_path(candidate: str) -> bool:
    """Validate a serial-device path before passing it back into stdin.

    The path is only used for the "insert at cursor" affordance — the
    PTY transport is byte-for-byte raw — but the validator keeps the
    sidebar from helpfully pasting ``/dev/ttyUSB0; rm -rf ~`` into the
    operator's shell prompt. Pure interactive shell input bypass is the
    operator's own responsibility.
    """
    text = str(candidate or "").strip()
    if len(text) == 0 or len(text) > 256:
        return False
    return _SERIAL_PATH_RE.match(text) is not None


# ---------------------------------------------------------------------------
# Spawn helper
# ---------------------------------------------------------------------------


@dataclass
class HostShellStartSpec:
    """Parameters consumed by :func:`spawn_host_shell`.

    Mirrors :class:`yggdrasim_common.gui_server.terminal.PtyStartSpec`
    but drops the ``module`` / ``extra_args`` fields. The default argv
    is ``[shell, "-i"]``; GUI surfaces may provide an explicit command
    string for modem-shell tools such as ``tio``.
    """

    rows: int = _DEFAULT_ROWS
    cols: int = _DEFAULT_COLS
    cwd: Optional[str] = None
    env: Optional[dict[str, str]] = None
    command: Optional[str] = None
    hil_modem: bool = False


def parse_host_command(command: Optional[str]) -> list[str]:
    """Split a GUI-configured command into an argv vector.

    The host-shell surface is already opt-in and shell-equivalent, but
    configured launches should still avoid implicit ``shell=True``
    expansion. A command such as ``sudo tio /dev/ttyUSB2`` becomes
    ``["sudo", "tio", "/dev/ttyUSB2"]`` and is passed directly to
    ``execvpe``.
    """
    text = str(command or "").strip()
    if len(text) == 0:
        return []
    if len(text) > _MAX_COMMAND_LENGTH:
        raise ValueError("Host-shell command is too long.")
    if "\x00" in text:
        raise ValueError("Host-shell command contains a NUL byte.")
    try:
        argv = shlex.split(text, posix=True)
    except ValueError as error:
        raise ValueError(f"Host-shell command could not be parsed: {error}") from error
    if len(argv) == 0:
        raise ValueError("Host-shell command is empty.")
    return argv


def parse_hil_modem_command(command: Optional[str]) -> list[str]:
    """Parse and validate a constrained HIL modem terminal command."""
    argv = parse_host_command(command)
    if len(argv) == 0:
        raise ValueError("HIL modem shell command is required.")
    if Path(argv[0]).name == "ssh":
        _validate_hil_modem_ssh_command(argv)
        return argv
    _validate_hil_modem_terminal_command(argv)
    return argv


def _validate_hil_modem_terminal_command(argv: list[str]) -> None:
    """Validate a direct serial-terminal argv vector."""
    command_index = 0
    executable = Path(argv[command_index]).name
    if executable in _HIL_MODEM_PRIVILEGE_WRAPPERS:
        command_index = 1
        if len(argv) <= command_index:
            raise ValueError("HIL modem shell privilege wrapper is missing a command.")
        executable = Path(argv[command_index]).name
    if executable not in _HIL_MODEM_TERMINAL_COMMANDS:
        allowed = ", ".join(sorted(_HIL_MODEM_TERMINAL_COMMANDS))
        raise ValueError(
            "HIL modem shell only accepts serial terminal commands: "
            + allowed
            + "."
        )
    if not any(is_safe_device_path(arg) for arg in argv[command_index + 1:]):
        raise ValueError(
            "HIL modem shell command must include a serial device path "
            "under /dev/ttyUSB*, /dev/ttyACM*, /dev/ttyS*, or /dev/serial/by-id/*."
        )


def _validate_hil_modem_ssh_command(argv: list[str]) -> None:
    """Validate the SSH form generated for remote Card Bridge rigs."""
    if len(argv) < 4:
        raise ValueError("HIL modem SSH command is incomplete.")

    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in _HIL_MODEM_SSH_FLAGS:
            index += 1
            continue
        if arg == "-o":
            if index + 1 >= len(argv):
                raise ValueError("HIL modem SSH -o option is missing a value.")
            _validate_hil_modem_ssh_option(argv[index + 1])
            index += 2
            continue
        if arg.startswith("-o") and len(arg) > 2:
            _validate_hil_modem_ssh_option(arg[2:])
            index += 1
            continue
        if arg == "-i":
            if index + 1 >= len(argv):
                raise ValueError("HIL modem SSH identity option is missing a path.")
            _validate_hil_modem_ssh_identity(argv[index + 1])
            index += 2
            continue
        if arg.startswith("-"):
            raise ValueError("HIL modem SSH command contains an unsupported SSH option.")
        break

    if index >= len(argv):
        raise ValueError("HIL modem SSH command is missing a target.")
    target = argv[index]
    _validate_hil_modem_ssh_target(target)
    remote_argv = argv[index + 1:]
    if len(remote_argv) == 0:
        raise ValueError("HIL modem SSH command is missing the remote terminal command.")
    _validate_hil_modem_terminal_command(remote_argv)


def _validate_hil_modem_ssh_option(value: str) -> None:
    if value not in _HIL_MODEM_SSH_ALLOWED_OPTIONS:
        raise ValueError("HIL modem SSH command contains an unsupported SSH option.")


def _validate_hil_modem_ssh_identity(value: str) -> None:
    text = str(value or "").strip()
    if len(text) == 0 or len(text) > 256:
        raise ValueError("HIL modem SSH identity path is invalid.")
    if text.startswith("-") or "\x00" in text or any(ord(ch) < 32 for ch in text):
        raise ValueError("HIL modem SSH identity path is invalid.")


def _validate_hil_modem_ssh_target(value: str) -> None:
    text = str(value or "").strip()
    if len(text) == 0 or len(text) > 256:
        raise ValueError("HIL modem SSH target is invalid.")
    if text.startswith("-") or "\x00" in text or any(ord(ch) < 32 for ch in text):
        raise ValueError("HIL modem SSH target is invalid.")


async def spawn_host_shell(spec: HostShellStartSpec) -> PtySession:
    """Fork an interactive host shell inside a fresh PTY.

    The function does not consult :data:`CLI_MODULES`. Callers must
    have already verified :func:`is_enabled` and :func:`is_supported`;
    if either gate is open, this raises :class:`RuntimeError` so the
    caller emits a clean WS error instead of leaving a half-spawned
    PID lying around.
    """
    if not is_supported():
        raise RuntimeError("Host shell PTY bridge is not supported on this platform.")
    if not is_enabled() and not spec.hil_modem:
        raise RuntimeError(
            "Host shell is disabled. Set YGGDRASIM_GUI_HOST_SHELL=1 and "
            "restart yggdrasim-gui or yggdrasim-web-server to enable it."
        )

    if spec.hil_modem:
        command_argv = parse_hil_modem_command(spec.command)
    else:
        command_argv = parse_host_command(spec.command)
    shell_path: Optional[str] = None
    if len(command_argv) > 0:
        argv = command_argv
    else:
        shell_path = resolve_shell(spec.env)
        if shell_path is None:
            raise RuntimeError(
                "Could not resolve a usable login shell. $SHELL must point "
                "to an entry listed in /etc/shells, or /bin/bash / /bin/sh "
                "must be available."
            )
        argv = [shell_path, "-i"]

    import pty  # POSIX-only — guarded above by is_supported().

    base_env = dict(os.environ)
    if spec.env:
        base_env.update(spec.env)
    base_env.setdefault("PYTHONUNBUFFERED", "1")
    # Leave PS1 alone — the operator's login files own their prompt; we
    # are not a chroot. We do force TERM to a known sane value so xterm
    # interactive features (CR handling, cursor motion) come through
    # before the shell's rc files have a chance to override it.
    base_env.setdefault("TERM", "xterm-256color")

    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            if spec.cwd:
                os.chdir(spec.cwd)
            os.execvpe(argv[0], argv, base_env)
        except Exception as error:  # pragma: no cover - child-side fallback
            sys.stderr.write(f"exec failed: {error}\n")
            os._exit(1)
        os._exit(0)

    session = PtySession()
    # Re-create what PtySession.spawn would have set up internally,
    # without going through its module allow-list. We deliberately use
    # the same private attribute names so PtySession.read_once /
    # PtySession.send / PtySession.close keep working unchanged.
    session._pid = int(pid)  # type: ignore[attr-defined]
    session._master_fd = int(master_fd)  # type: ignore[attr-defined]
    _set_nonblocking(int(master_fd))
    session.resize(spec.rows, spec.cols)

    _LOGGER.info(
        "gui.host_shell.spawned argv0=%s pid=%s rows=%s cols=%s",
        argv[0],
        session.pid,
        spec.rows,
        spec.cols,
    )
    return session


# ---------------------------------------------------------------------------
# Internal helpers re-exported for tests
# ---------------------------------------------------------------------------


__all__ = [
    "HostShellStartSpec",
    "SerialDevice",
    "describe_capability",
    "describe_hil_modem_capability",
    "enumerate_serial_devices",
    "is_enabled",
    "is_safe_device_path",
    "is_supported",
    "parse_hil_modem_command",
    "parse_host_command",
    "resolve_shell",
    "spawn_host_shell",
]
