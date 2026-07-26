# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Portability regressions that only bite on a non-Linux host.

These run everywhere by simulating the platform difference rather than
requiring it, so a Linux CI leg still protects the Windows and macOS
bundles the release matrix ships.
"""

from __future__ import annotations

import ast
import os
import subprocess
from pathlib import Path

import pytest

from yggdrasim_common.gui_server import lifecycle


REPO_ROOT = Path(__file__).resolve().parents[1]


class _FakeProcess:
    pid = 4321

    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


@pytest.fixture()
def windows_like(monkeypatch: pytest.MonkeyPatch):
    """No ``os.killpg`` and no real ``SIGKILL``, as on native Windows."""

    monkeypatch.delattr(os, "killpg", raising=False)
    monkeypatch.setattr(lifecycle, "_SIGKILL", "kill", raising=True)
    return lifecycle


def test_escalation_reaches_kill_when_sigkill_is_absent(windows_like) -> None:
    """The bug: ``signal.SIGKILL`` is evaluated at the call site.

    Windows has no ``SIGKILL``, so the AttributeError fired before the
    guard inside the callee could run, was swallowed by a broad except,
    and a child that ignored SIGTERM was never killed.
    """
    process = _FakeProcess()
    windows_like._send_process_signal(process, windows_like._SIGKILL)
    assert process.killed is True
    assert process.terminated is False


def test_terminate_still_routes_to_terminate(windows_like) -> None:
    process = _FakeProcess()
    windows_like._send_process_signal(process, windows_like.signal.SIGTERM)
    assert process.terminated is True
    assert process.killed is False


def test_sigkill_constant_is_defined_defensively() -> None:
    """It must resolve on a platform that has no SIGKILL at all."""

    source = (REPO_ROOT / "yggdrasim_common/gui_server/lifecycle.py").read_text(
        encoding="utf-8"
    )
    assert 'getattr(signal, "SIGKILL"' in source


# Reachable only on POSIX: the PTY session is created behind
# ``host_shell.is_supported()``, which is False where ``pty`` is absent.
_SIGKILL_CALL_SITE_ALLOWLIST = {"yggdrasim_common/gui_server/terminal.py"}


def test_no_shipped_call_site_evaluates_signal_sigkill() -> None:
    """Passing ``signal.SIGKILL`` as an argument raises before any guard."""

    offenders: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith(("tests/", ".venv/", "build/", "pysim/", "plugins/")):
            continue
        if rel in _SIGKILL_CALL_SITE_ALLOWLIST:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for arg in list(node.args) + [k.value for k in node.keywords]:
                if (
                    isinstance(arg, ast.Attribute)
                    and arg.attr == "SIGKILL"
                    and isinstance(arg.value, ast.Name)
                    and arg.value.id == "signal"
                ):
                    offenders.append(f"{rel}:{node.lineno}")
    assert offenders == [], (
        "use a getattr-guarded constant; signal.SIGKILL does not exist on "
        f"Windows: {offenders}"
    )


def test_scp80_bundled_config_survives_a_non_ascii_header() -> None:
    """The bundled ini carries a non-ASCII copyright line.

    Reading it through the platform default codec raised
    UnicodeDecodeError on cp932 and cp874 hosts, and ``except OSError``
    does not catch it because it is a ValueError.
    """
    source = (REPO_ROOT / "SCP80/config.py").read_text(encoding="utf-8")
    assert 'read_text (encoding ="utf-8")' in source
    assert "except (OSError ,ValueError )" in source

    raw = (REPO_ROOT / "SCP80/ota_config.ini").read_bytes()
    assert raw.decode("utf-8")
    for hostile in ("cp932", "cp874"):
        with pytest.raises(UnicodeDecodeError):
            raw.decode(hostile)


def _text_io_without_encoding(rel: str, tree: ast.AST) -> list[str]:
    """Calls that fall back to the locale codec.

    ``encoding`` is the 4th positional of ``open`` and the 1st/2nd of
    ``Path.read_text``/``write_text``, so a positional form is fine.
    """
    positional = {"read_text": 0, "write_text": 1}
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        keywords = {k.arg for k in node.keywords if k.arg}
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = str(keyword.value.value)
            if "b" in mode or "encoding" in keywords or len(node.args) > 3:
                continue
            found.append(f"{rel}:{node.lineno} open()")
        elif isinstance(node.func, ast.Attribute) and node.func.attr in positional:
            if "encoding" in keywords or len(node.args) > positional[node.func.attr]:
                continue
            found.append(f"{rel}:{node.lineno} .{node.func.attr}()")
    return found


def test_shipped_code_never_relies_on_the_locale_codec() -> None:
    """Windows defaults to cp1252, so text I/O must pin its encoding."""

    files = subprocess.run(
        ["git", "ls-files", "*.py"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    ).stdout.split()
    assert files, "expected a git checkout"
    offenders: list[str] = []
    for rel in files:
        if rel.startswith("tests/"):
            continue
        try:
            tree = ast.parse((REPO_ROOT / rel).read_text(encoding="utf-8"), filename=rel)
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        offenders.extend(_text_io_without_encoding(rel, tree))
    assert offenders == [], offenders[:10]
