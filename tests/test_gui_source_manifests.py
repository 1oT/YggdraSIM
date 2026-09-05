# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Keep GUI source modules visible to the deterministic production build."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _manifest_entries(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _strip_repeated_source_header(text: str, *, suffix: str) -> str:
    if suffix == ".js":
        lines = text.splitlines(keepends=True)
        if lines and lines[0].startswith("// SPDX-License-Identifier:"):
            return "".join(lines[3:])
        return text
    lines = text.splitlines(keepends=True)
    if (
        len(lines) >= 5
        and lines[0].strip() == "/*"
        and "SPDX-License-Identifier:" in lines[1]
    ):
        return "".join(lines[5:])
    return text


def test_every_modular_gui_source_is_in_its_build_manifest() -> None:
    source = ROOT / "gui_frontend" / "src"
    for directory, suffix, manifest_name in (
        (source / "css", ".css", ".css_order"),
        (source / "js", ".js", ".js_order"),
    ):
        discovered = {
            path.relative_to(directory).as_posix()
            for path in directory.rglob(f"*{suffix}")
            if path.is_file()
        }
        entries = _manifest_entries(directory / manifest_name)
        assert len(entries) == len(set(entries)), f"duplicate entries in {manifest_name}"
        assert set(entries) == discovered


def test_modular_sources_reconstruct_the_served_bundle_exactly() -> None:
    source = ROOT / "gui_frontend" / "src"
    served = ROOT / "yggdrasim_common" / "gui_server" / "static"
    for directory, suffix, manifest_name, output_name in (
        (source / "css", ".css", ".css_order", "app.css"),
        (source / "js", ".js", ".js_order", "app.js"),
    ):
        chunks: list[str] = []
        for index, entry in enumerate(
            _manifest_entries(directory / manifest_name)
        ):
            text = (directory / entry).read_text(encoding="utf-8")
            chunks.append(
                text
                if index == 0
                else _strip_repeated_source_header(text, suffix=suffix)
            )
        assert "".join(chunks) == (served / output_name).read_text(
            encoding="utf-8"
        )

    for filename in ("index.html", "theme-init.js"):
        assert (source / filename).read_bytes() == (served / filename).read_bytes()


def test_protected_gui_source_and_tests_are_not_ignored() -> None:
    protected = [
        ROOT / "gui_frontend" / "src",
        ROOT / "yggdrasim_common" / "gui_server",
        ROOT / "tests",
    ]
    candidates = sorted(
        path.relative_to(ROOT).as_posix()
        for directory in protected
        for path in directory.rglob("*")
        if path.is_file()
        and path.suffix in {".css", ".html", ".js", ".json", ".py"}
        and "__pycache__" not in path.parts
        and not path.is_relative_to(ROOT / "tests" / "plugins")
    )
    result = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=ROOT,
        input="\n".join(candidates),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode in {0, 1}
    ignored = [line for line in result.stdout.splitlines() if line]
    assert ignored == []


def test_remote_lab_styles_are_present_in_served_bundle() -> None:
    source_css = (
        ROOT / "gui_frontend" / "src" / "css" / "views" / "remote-lab.css"
    ).read_text(encoding="utf-8")
    served_css = (
        ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.css"
    ).read_text(encoding="utf-8")
    assert ".remote-lab-toolbar" in source_css
    assert ".remote-lab-toolbar" in served_css
