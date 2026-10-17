# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Windowless launchers and the standard streams they start without.

The ``console=False`` PyInstaller executable, the ``pythonw -m main.gui``
shortcut fallback and the ``pythonw``-backed ``yggdrasim-desktop`` start
with ``sys.stdin``, ``sys.stdout`` and ``sys.stderr`` set to ``None``. Each
entry repairs them before the launcher is imported: the v2.1.0 windowed
executable did not, and exited on the plugin-loading notice it writes on
every start.
"""

from __future__ import annotations

import io
import sys
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from yggdrasim_common import console_scripts

ROOT = Path(__file__).resolve().parent.parent


class _Descriptor(io.StringIO):
    """What ``open()`` returns for descriptors 0-2 in these tests."""

    def close(self) -> None:
        self.flush()


@contextmanager
def _started_without_streams() -> Iterator[dict[int, _Descriptor]]:
    descriptors = {0: _Descriptor(), 1: _Descriptor(), 2: _Descriptor()}

    def _open(target, *_args, **_kwargs):
        return descriptors[int(target)]

    with (
        mock.patch("builtins.open", side_effect=_open),
        mock.patch.object(sys, "stdin", None),
        mock.patch.object(sys, "stdout", None),
        mock.patch.object(sys, "stderr", None),
    ):
        yield descriptors


def test_windowed_executable_repairs_the_streams_before_the_launcher_loads() -> None:
    from main import gui

    seen: dict[str, object] = {}

    def run_cli(argv):
        seen["argv"] = list(argv)
        sys.stderr.write("notice\n")
        return 0

    def load_run_cli():
        seen["streams"] = (sys.stdin, sys.stdout, sys.stderr)
        return run_cli

    with _started_without_streams() as descriptors:
        with mock.patch.object(gui, "_load_run_cli", load_run_cli):
            assert gui.main([]) == 0

    assert seen["streams"] == (descriptors[0], descriptors[1], descriptors[2])
    assert seen["argv"] == ["--gui"]
    assert descriptors[2].getvalue() == "notice\n"


def test_desktop_entry_point_repairs_the_streams_before_the_launcher_loads() -> None:
    seen: dict[str, object] = {}

    def invoke_launcher(default_mode=None):
        seen["streams"] = (sys.stdin, sys.stdout, sys.stderr)
        seen["mode"] = default_mode
        return 0

    with _started_without_streams() as descriptors:
        with mock.patch.object(console_scripts, "_invoke_launcher", invoke_launcher):
            assert console_scripts.gui() == 0

    assert seen["streams"] == (descriptors[0], descriptors[1], descriptors[2])
    assert seen["mode"] == "--gui"


def test_plugin_notice_without_a_console_is_dropped() -> None:
    from main import main as launcher

    errors = {"__gate__": "Plugin loading disabled by default."}
    with (
        mock.patch.object(launcher, "_PLUGIN_LOAD_BANNER_EMITTED", False),
        mock.patch.object(launcher, "plugin_load_errors", return_value=errors),
        mock.patch.object(sys, "stderr", None),
    ):
        launcher._emit_plugin_load_banner()

    shown = io.StringIO()
    with (
        mock.patch.object(launcher, "_PLUGIN_LOAD_BANNER_EMITTED", False),
        mock.patch.object(launcher, "plugin_load_errors", return_value=errors),
    ):
        launcher._emit_plugin_load_banner(shown)
    assert "  - gate: Plugin loading disabled by default.\n" in shown.getvalue()


def test_the_windowless_entries_are_the_ones_tested_here() -> None:
    # A new windowless entry starts without streams as well: give it the
    # repair and a test like the two above before adding it here.
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["gui-scripts"] == {"yggdrasim-desktop": "yggdrasim_common.console_scripts:gui"}

    spec = (ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
    executables = [block.split("\n)\n", 1)[0] for block in spec.split(" = EXE(")[1:]]
    windowed = [block for block in executables if "console=False," in block]
    assert len(executables) == 2
    assert len(windowed) == 1
    assert "gui_analysis.scripts," in windowed[0]
    assert '_analysis_for(ROOT / "main" / "gui.py",' in spec

    shortcuts = (ROOT / "scripts" / "install_shortcuts.py").read_text(encoding="utf-8")
    assert 'FALLBACK_MODULE = "main.gui"' in shortcuts
