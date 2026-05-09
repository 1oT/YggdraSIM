# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Subprocess wrapper around tshark + the EUM-BPP Lua dissector.

The runner keeps the command construction + environment shaping out
of the CLI layer so it can be unit-tested without actually invoking
tshark. Each public function returns a plain argv list or a
``subprocess.CompletedProcess`` — no global state.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .session_keys import SESSION_KEYS_ENV_VAR


DEFAULT_TSHARK_BINARY: str = "tshark"
DEFAULT_DISSECTOR_FILENAME: str = "dissector.lua"


@dataclass(frozen=True)
class TsharkInvocation:
    """Declarative representation of a tshark invocation.

    Keeping the representation value-typed lets the unit tests lock
    in the exact argv / env that the CLI layer will hand to
    :func:`subprocess.run`. That matters because a misplaced
    ``-X`` flag silently breaks the Lua loader on older tshark
    versions.
    """

    command: tuple[str, ...]
    env: Mapping[str, str]


def locate_dissector(module_dir: Path | None = None) -> Path:
    """Resolve the bundled ``dissector.lua`` path.

    The default location is next to this module. Tests override
    ``module_dir`` to point at a tmpdir copy when they want to
    assert against a known good checksum.
    """
    if module_dir is not None:
        return (Path(module_dir) / DEFAULT_DISSECTOR_FILENAME).resolve()
    return (Path(__file__).parent / DEFAULT_DISSECTOR_FILENAME).resolve()


def build_tshark_invocation(
    *,
    pcap_path: Path,
    keys_path: Path,
    dissector_path: Path | None = None,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
    extra_args: Sequence[str] = (),
    existing_env: Mapping[str, str] | None = None,
) -> TsharkInvocation:
    """Return the exact argv + env for a ``tshark`` decode run."""
    resolved_dissector = (
        Path(dissector_path).resolve()
        if dissector_path is not None
        else locate_dissector()
    )
    env = dict(existing_env if existing_env is not None else os.environ)
    env[SESSION_KEYS_ENV_VAR] = str(Path(keys_path).resolve())
    command = [
        str(tshark_binary or DEFAULT_TSHARK_BINARY),
        "-X",
        f"lua_script:{resolved_dissector}",
        "-r",
        str(Path(pcap_path).resolve()),
    ]
    command.extend(str(token) for token in extra_args)
    return TsharkInvocation(command=tuple(command), env=env)


class TsharkMissingError(RuntimeError):
    """Raised when the ``tshark`` binary cannot be located on PATH."""


def ensure_tshark_on_path(binary: str = DEFAULT_TSHARK_BINARY) -> str:
    """Verify that tshark is available on PATH and raise ``RuntimeError`` if not found."""
    resolved = shutil.which(binary)
    if resolved is None:
        raise TsharkMissingError(
            f"{binary!r} was not found on PATH. Install Wireshark/tshark "
            "(Debian/Ubuntu: `sudo apt install tshark`; macOS: "
            "`brew install wireshark`) before invoking the EUM diag runner."
        )
    return resolved


def run_tshark(
    invocation: TsharkInvocation,
    *,
    timeout_seconds: float | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Execute the invocation and return the ``CompletedProcess``.

    The call deliberately does NOT raise on non-zero exit — tshark
    uses non-zero for benign cases (e.g. no matching packets) so the
    caller is responsible for interpreting the return code.
    """
    ensure_tshark_on_path(invocation.command[0])
    return subprocess.run(
        list(invocation.command),
        env=dict(invocation.env),
        timeout=timeout_seconds,
        capture_output=capture_output,
        check=False,
    )
