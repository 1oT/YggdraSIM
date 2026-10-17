# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Locate the bundled Lua dissector and build tshark invocations.

Command construction is kept out of the CLI layer so it can be unit
tested without invoking tshark, following the pattern
``Tools/EumDiag/tshark_runner.py`` established. That matters here for the
same reason it did there: a misplaced ``-X`` breaks the Lua loader
silently on some builds, and the failure looks like a dissector bug
rather than an argv bug.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

DEFAULT_TSHARK_BINARY = "tshark"
DISSECTOR_FILENAME = "yggdrasim_apdu.lua"
LUA_DIRNAME = "lua"

#: The GSMTAP decode rule the HIL bridge already passes. Kept here so the
#: two callers cannot drift apart.
GSMTAP_DECODE_RULE = "udp.port==4729,gsmtap"

#: Points the dissector at a decrypted-payload sidecar; see sidecar.py.
SIDECAR_ENV_VAR = "YGGDRASIM_APDU_SIDECAR"

#: Set to "0" to keep the dissector out of the HIL bridge's tshark calls.
ENABLED_ENV_VAR = "YGGDRASIM_APDU_DISSECTOR"


class TsharkMissingError(RuntimeError):
    """Raised when the tshark binary cannot be located on PATH."""


@dataclass(frozen=True)
class TsharkInvocation:
    """A tshark command line and the environment it needs."""

    command: tuple[str, ...]
    env: Mapping[str, str]


def lua_directory(module_dir: Path | None = None) -> Path:
    """Return the directory holding the Lua tree."""
    base = Path(module_dir) if module_dir is not None else Path(__file__).parent
    return (base / LUA_DIRNAME).resolve()


def locate_dissector(module_dir: Path | None = None) -> Path:
    """Resolve the bundled entry-point script."""
    return lua_directory(module_dir) / DISSECTOR_FILENAME


def dissector_is_available(module_dir: Path | None = None) -> bool:
    """True when the bundled Lua is present and readable.

    A partial install must not stop a capture from starting, so every
    caller checks this before adding the ``-X`` argument.
    """
    try:
        return locate_dissector(module_dir).is_file()
    except OSError:
        return False


# Wireshark on some distributions ships an AppArmor profile that denies
# tshark every read under $HOME. The plugin lives in the checkout, so
# tshark cannot load it and decodes without it -- silently, because a
# refused -X is a warning on stderr and not an error. /tmp is the one
# place both sides can reach (the profile allows it, and the user-owned
# runtime dir is denied like $HOME), so the Lua is mirrored there.
def _lua_tree_signature(source: Path) -> str:
    """Identify a Lua tree by its files, so a stale copy is detectable."""
    parts: list[str] = []
    for path in sorted(source.rglob("*.lua")):
        try:
            stat = path.stat()
        except OSError:
            continue
        parts.append(f"{path.relative_to(source)}:{stat.st_size}:{int(stat.st_mtime)}")
    return "\n".join(parts)


def mirrored_lua_directory(module_dir: Path | None = None) -> Path | None:
    """A copy of the Lua tree in a directory tshark is allowed to read.

    Returns None when the mirror cannot be made safely, in which case the
    caller uses the original path and tshark decides. The directory is
    owned by this user and is not group- or world-writable, because
    tshark executes whatever Lua it finds there.
    """
    try:
        source = lua_directory(module_dir)
        if source.is_dir() is False:
            return None
        root = Path(tempfile.gettempdir()) / f"yggdrasim-apdu-dissector-{os.getuid()}"
        if root.is_symlink():
            return None
        if root.exists():
            stat = root.stat()
            if stat.st_uid != os.getuid() or root.is_dir() is False:
                return None
            if stat.st_mode & 0o022:
                root.chmod(0o755)
        else:
            root.mkdir(mode=0o755, parents=True, exist_ok=True)

        # Compare the mirror against the source rather than a marker the
        # mirror carries: a marker only records what was copied, so a
        # mirror edited underneath us would keep claiming to be current
        # and tshark would decode with whatever is actually there.
        # copytree preserves mtimes, so the two signatures match exactly
        # while the copy is faithful.
        if _lua_tree_signature(root) != _lua_tree_signature(source):
            for existing in root.iterdir():
                if existing.is_dir() and existing.is_symlink() is False:
                    shutil.rmtree(existing, ignore_errors=True)
                else:
                    existing.unlink(missing_ok=True)
            shutil.copytree(source, root, dirs_exist_ok=True)
            # copytree carries the source directory's mode across, and a
            # checkout is often group-writable. Tighten afterwards, not
            # before: tshark executes this Lua.
            for path in [root, *root.rglob("*")]:
                path.chmod(0o755 if path.is_dir() else 0o644)
        if (root / DISSECTOR_FILENAME).is_file() is False:
            return None
        return root
    except OSError:
        return None


def dissector_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """False when the operator has switched the dissector off."""
    source = environ if environ is not None else os.environ
    return str(source.get(ENABLED_ENV_VAR, "") or "").strip() != "0"


def dissector_arguments(
    *,
    module_dir: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Return ``["-X", "lua_script:..."]``, or ``[]``.

    Returns an empty list when the dissector is disabled or missing, so a
    caller can splat it into an argv list unconditionally.
    """
    if not dissector_enabled(environ):
        return []
    if not dissector_is_available(module_dir):
        return []
    mirror = mirrored_lua_directory(module_dir)
    if mirror is not None:
        return ["-X", f"lua_script:{mirror / DISSECTOR_FILENAME}"]
    return ["-X", f"lua_script:{locate_dissector(module_dir)}"]


def build_tshark_invocation(
    *,
    pcap_path: Path,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    dissector_path: Path | None = None,
    sidecar_path: Path | None = None,
    decode_rule: str = GSMTAP_DECODE_RULE,
    extra_args: Sequence[str] = (),
    existing_env: Mapping[str, str] | None = None,
) -> TsharkInvocation:
    """Return the exact argv and environment for a decode run."""
    resolved = (
        Path(dissector_path).resolve()
        if dissector_path is not None
        else locate_dissector()
    )
    env = dict(existing_env if existing_env is not None else os.environ)
    if sidecar_path is not None:
        env[SIDECAR_ENV_VAR] = str(Path(sidecar_path).resolve())

    command = [
        str(tshark_binary or DEFAULT_TSHARK_BINARY),
        "-X",
        f"lua_script:{resolved}",
        "-r",
        str(Path(pcap_path).resolve()),
    ]
    normalized_rule = str(decode_rule or "").strip()
    if len(normalized_rule) > 0:
        command.extend(["-d", normalized_rule])
    command.extend(str(token) for token in extra_args)
    return TsharkInvocation(command=tuple(command), env=env)


def ensure_tshark_on_path(binary: str = DEFAULT_TSHARK_BINARY) -> str:
    """Verify tshark is reachable, or raise with an install hint."""
    resolved = shutil.which(binary)
    if resolved is None:
        raise TsharkMissingError(
            f"{binary!r} was not found on PATH. Install Wireshark/tshark "
            "(Debian/Ubuntu: `sudo apt install tshark`; macOS: "
            "`brew install wireshark`) before running the APDU dissector."
        )
    return resolved


def run_tshark(
    invocation: TsharkInvocation,
    *,
    timeout_seconds: float | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Execute *invocation*.

    Does not raise on a non-zero exit: tshark uses non-zero for benign
    outcomes such as a display filter matching nothing, so interpreting
    the code is the caller's job.
    """
    ensure_tshark_on_path(invocation.command[0])
    return subprocess.run(
        list(invocation.command),
        env=dict(invocation.env),
        timeout=timeout_seconds,
        capture_output=capture_output,
        check=False,
    )


def running_as_root() -> bool:
    """True when Wireshark will refuse to load the Lua script.

    Wireshark declines ``-X lua_script:`` for a superuser process and
    says nothing about it, so the dissector simply never loads. Callers
    warn rather than let an operator conclude the dissector is broken.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows has no geteuid; the restriction does not apply there.
        return False
