# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression coverage for the Linux arm64 desktop-GUI dependency path."""
from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parents[1]


def _selected_gui_requirements(machine: str) -> list[Requirement]:
    project = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    environment = default_environment()
    environment.update(
        {
            "platform_machine": machine,
            "sys_platform": "linux",
        }
    )
    requirements = [
        Requirement(item)
        for item in project["project"]["optional-dependencies"]["gui"]
    ]
    return [
        requirement
        for requirement in requirements
        if requirement.marker is None
        or requirement.marker.evaluate(environment=environment)
    ]


def test_linux_x86_64_gui_keeps_self_contained_qt_extra() -> None:
    selected = _selected_gui_requirements("x86_64")
    pywebview = [
        requirement for requirement in selected if requirement.name == "pywebview"
    ]

    assert len(pywebview) == 1
    assert pywebview[0].extras == {"qt"}
    assert all(requirement.name != "qtpy" for requirement in selected)


def test_linux_arm64_gui_uses_system_binding_bridge_without_qt6_extra() -> None:
    for machine in ("aarch64", "arm64"):
        selected = _selected_gui_requirements(machine)
        pywebview = [
            requirement
            for requirement in selected
            if requirement.name == "pywebview"
        ]

        assert len(pywebview) == 1
        assert pywebview[0].extras == set()
        assert any(requirement.name == "qtpy" for requirement in selected)


def test_arm64_bundle_jobs_provide_and_verify_system_pyqt5() -> None:
    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count(
        "python3-pyqt5 python3-pyqt5.qtwebengine python3-pyqt5.qtwebchannel"
    ) == 2
    assert workflow.count(
        "python3 -m venv --system-site-packages /opt/venv"
    ) == 2
    assert workflow.count(
        "from qtpy import QtWebEngineWidgets; print(QtWebEngineWidgets.__name__)"
    ) == 2
    assert "DOCTOR_OUTPUT=$(dist/yggdrasim-clean --doctor || true)" in workflow
    assert "DOCTOR_OUTPUT=$(dist/yggdrasim-full --doctor || true)" in workflow
