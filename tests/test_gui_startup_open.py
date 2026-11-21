# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A file named on the launcher command line opens in the SAIP workbench.

``yggdrasim --gui FILE`` is what the desktop launcher's Open With entry
runs (``scripts/install_shortcuts.py``). The path travels through the
argparse positional, the GUI config, the once-only ``/api/gui/startup``
route and the page bootstrap that mounts the SAIP subsystem and feeds
the workbench's open entry point. Each hop is pinned here so a change to
one of them cannot silently drop the file on the floor.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

from yggdrasim_common.gui_server import config

_ROOT = Path(__file__).resolve().parents[1]
_TRAILING_JS = _ROOT / "gui_frontend" / "src" / "js" / "trailing.js"
_COMMAND_CENTER_JS = _ROOT / "gui_frontend" / "src" / "js" / "command-center.js"
_WORKBENCH_JS = _ROOT / "gui_frontend" / "src" / "js" / "saip-workbench.js"

try:
    import fastapi as _fastapi  # noqa: F401
    import starlette as _starlette  # noqa: F401

    _GUI_STACK = True
except ImportError:
    _GUI_STACK = False

_needs_gui_stack = pytest.mark.skipif(
    not _GUI_STACK, reason="GUI stack (fastapi / starlette) not installed"
)


def _load_launcher():
    """Load ``main/main.py`` by path; ``main`` is also a directory here."""
    path = _ROOT / "main" / "main.py"
    spec = importlib.util.spec_from_file_location("launcher_startup_open_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _mk_args(**overrides):
    namespace = types.SimpleNamespace(
        host=None,
        port=None,
        token_file=None,
        tls_cert=None,
        tls_key=None,
        tls_self_signed=False,
        allow_origin=[],
        open_paths=[],
    )
    for key, value in overrides.items():
        setattr(namespace, key, value)
    return namespace


# -- launcher ---------------------------------------------------------------


def test_launcher_parser_takes_files_after_the_gui_flag() -> None:
    launcher = _load_launcher()
    args = launcher._build_cli_parser().parse_args(
        ["--gui", "/tmp/a.varder", "/tmp/b.txt"]
    )
    assert args.gui is True
    assert args.open_paths == ["/tmp/a.varder", "/tmp/b.txt"]


def test_launcher_parser_takes_files_before_the_gui_flag() -> None:
    launcher = _load_launcher()
    args = launcher._build_cli_parser().parse_args(["/tmp/a.varder", "--web-server"])
    assert args.web_server is True
    assert args.open_paths == ["/tmp/a.varder"]


def test_launcher_parser_defaults_to_no_files() -> None:
    launcher = _load_launcher()
    assert launcher._build_cli_parser().parse_args(["--gui"]).open_paths == []


def test_route_gui_modes_refuses_a_file_without_a_gui_mode(capsys) -> None:
    launcher = _load_launcher()
    args = launcher._build_cli_parser().parse_args(["/tmp/a.varder"])
    assert launcher._route_gui_modes(args) == 2
    printed = capsys.readouterr().out
    assert "--gui" in printed
    assert "yggdrasim-desktop FILE" in printed


def test_route_gui_modes_falls_through_without_files() -> None:
    launcher = _load_launcher()
    args = launcher._build_cli_parser().parse_args([])
    assert launcher._route_gui_modes(args) is None


# -- config -----------------------------------------------------------------


def test_desktop_config_resolves_files_to_absolute_unique_paths(monkeypatch, tmp_path) -> None:
    for flag in ("YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE"):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.chdir(tmp_path)
    resolved = config.build_desktop_config(
        _mk_args(open_paths=["a.varder", "./a.varder", "  ", "~/b.txt"])
    )
    expected_a = str(tmp_path / "a.varder")
    expected_b = os.path.abspath(os.path.expanduser("~/b.txt"))
    assert resolved.startup_open_paths == (expected_a, expected_b)
    assert resolved.redacted()["startup_open_paths"] == [expected_a, expected_b]


def test_desktop_config_without_the_attribute_has_no_startup_files(monkeypatch) -> None:
    for flag in ("YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE"):
        monkeypatch.delenv(flag, raising=False)
    namespace = _mk_args()
    del namespace.open_paths
    assert config.build_desktop_config(namespace).startup_open_paths == ()


def test_web_server_config_carries_the_startup_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("YGGDRASIM_GUI_TOKEN", "A" * 48)
    target = tmp_path / "p.txt"
    resolved = config.build_web_server_config(_mk_args(open_paths=[str(target)]))
    assert resolved.startup_open_paths == (str(target),)


def test_config_dataclass_defaults_to_no_startup_files() -> None:
    resolved = config.GuiServerConfig(
        mode=config.MODE_DESKTOP, host="127.0.0.1", port=0, token="x" * 40
    )
    assert resolved.startup_open_paths == ()


# -- route ------------------------------------------------------------------


@_needs_gui_stack
def test_startup_route_hands_the_files_over_once() -> None:
    from starlette.testclient import TestClient

    from yggdrasim_common.gui_server.app import create_app

    token = "t" * 40
    app = create_app(
        config.GuiServerConfig(
            mode=config.MODE_DESKTOP,
            host="127.0.0.1",
            port=0,
            token=token,
            startup_open_paths=("/tmp/a.varder", "/tmp/b.txt"),
        )
    )
    headers = {"Authorization": f"Bearer {token}"}
    client = TestClient(app)
    assert client.get("/api/gui/startup").status_code == 401
    first = client.get("/api/gui/startup", headers=headers)
    assert first.status_code == 200
    assert first.json() == {"open_paths": ["/tmp/a.varder", "/tmp/b.txt"]}
    second = client.get("/api/gui/startup", headers=headers)
    assert second.status_code == 200
    assert second.json() == {"open_paths": []}


@_needs_gui_stack
def test_startup_route_answers_empty_without_files() -> None:
    from starlette.testclient import TestClient

    from yggdrasim_common.gui_server.app import create_app

    token = "t" * 40
    app = create_app(
        config.GuiServerConfig(
            mode=config.MODE_DESKTOP, host="127.0.0.1", port=0, token=token
        )
    )
    client = TestClient(app)
    response = client.get("/api/gui/startup", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"open_paths": []}


# -- page -------------------------------------------------------------------


def test_page_bootstrap_opens_the_startup_files_in_the_saip_workbench() -> None:
    body = _TRAILING_JS.read_text(encoding="utf-8")
    start = body.index("  async function startupOpenBootstrap() {")
    end = body.index("  function init() {", start)
    bootstrap = body[start:end]
    assert 'apiFetch("/api/gui/startup")' in bootstrap
    assert 'openCommandSubsystem("SAIP", { leafId: "leaf-tool-saip" })' in bootstrap
    assert "saipDropOpenPath(" in bootstrap
    init_body = body[end:body.index("\n  }\n", end)]
    assert "loadCommandCatalogue().then(startupOpenBootstrap)" in init_body


def test_page_bootstrap_targets_exist() -> None:
    command_center = _COMMAND_CENTER_JS.read_text(encoding="utf-8")
    workbench = _WORKBENCH_JS.read_text(encoding="utf-8")
    assert 'id: "leaf-tool-saip"' in command_center
    assert "function openCommandSubsystem(subsystem, options)" in command_center
    assert "function saipDropOpenPath(path)" in workbench
