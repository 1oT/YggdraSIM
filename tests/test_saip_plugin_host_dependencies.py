# SPDX-License-Identifier: GPL-3.0-or-later
"""Packaging contracts for optional SAIP spreadsheet extensions."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _dependency_names(entries: list[str]) -> set[str]:
    return {
        re.split(r"[<>=!~ ;@\\[]", entry, maxsplit=1)[0].strip().casefold()
        for entry in entries
    }


def test_saip_and_full_extras_include_hardened_workbook_dependencies() -> None:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)

    extras = project["project"]["optional-dependencies"]
    for extra_name in ("saip", "full"):
        names = _dependency_names(extras[extra_name])
        assert {"openpyxl", "defusedxml"} <= names


def test_frozen_plugin_host_collects_workbook_dependencies_without_plugins() -> None:
    spec_text = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")

    assert '"openpyxl"' in spec_text
    assert '"defusedxml"' in spec_text
    assert re.search(r"['\"]plugins['\"]", spec_text) is None


def test_clean_release_builds_install_saip_extra() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "build.yml"
    ).read_text(encoding="utf-8")

    # Linux x86_64, Linux arm64, Windows, and macOS clean build environments
    # must all resolve the workbook dependencies before PyInstaller runs.
    assert workflow.count("--extra saip") >= 6


def test_source_installers_select_saip_or_full_dependency_profile() -> None:
    common = (
        REPO_ROOT / "scripts" / "install" / "_common.sh"
    ).read_text(encoding="utf-8")
    windows = (
        REPO_ROOT / "scripts" / "install" / "install-windows.ps1"
    ).read_text(encoding="utf-8")

    assert "'.[saip]'" in common
    assert "'.[saip,gui]'" in common
    assert "'.[full]'" in common
    assert "'.[full,gui]'" in common
    assert "'.[saip]'" in windows
    assert "'.[saip,gui]'" in windows
