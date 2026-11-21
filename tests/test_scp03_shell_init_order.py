# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Order and import rules the SCP03 shell's constructor and OTA hand-off keep.

Read from the syntax tree: building a ``ShellDispatcher`` connects to a card.
"""

from __future__ import annotations

import ast
from pathlib import Path

_SOURCE = Path(__file__).resolve().parents[1] / "SCP03" / "interface" / "shell.py"


def _shell_method(name: str) -> ast.FunctionDef:
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "ShellDispatcher":
            for member in node.body:
                if isinstance(member, ast.FunctionDef) and member.name == name:
                    return member
    raise AssertionError(f"ShellDispatcher.{name} not found")


def _is_self_commands(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "commands"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def test_plugins_extend_the_shell_after_its_command_table_exists() -> None:
    # A plugin verb is an entry in ``self.commands``. A hook that runs before
    # the table is built raises on the missing attribute, and a table built
    # after the hook drops whatever the plugin added.
    init = _shell_method("__init__")
    hook_lines = [
        node.lineno
        for node in ast.walk(init)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "extend_target_with_plugins"
    ]
    table_lines = []
    for node in ast.walk(init):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if _is_self_commands(target):
                table_lines.append(node.lineno)
            elif isinstance(target, ast.Subscript) and _is_self_commands(target.value):
                table_lines.append(node.lineno)

    assert len(hook_lines) == 1
    assert len(table_lines) >= 2
    assert hook_lines[0] > max(table_lines)


def test_ota_hand_off_imports_scp80_by_package_name() -> None:
    # ``SCP80/`` on ``sys.path`` makes ``SCP80/main.py`` answer ``import main``,
    # which is the launcher package in every other entry point.
    hand_off = _shell_method("_run_scp80_tool")
    bare_main_imports = [
        node.lineno
        for node in ast.walk(hand_off)
        if isinstance(node, ast.Import) and any(alias.name == "main" for alias in node.names)
    ]
    path_inserts = [
        node.lineno
        for node in ast.walk(hand_off)
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "sys.path.insert"
    ]
    package_imports = [
        node.module
        for node in ast.walk(hand_off)
        if isinstance(node, ast.ImportFrom) and node.level == 0
    ]

    assert bare_main_imports == []
    assert path_inserts == []
    assert "SCP80.cli" in package_imports
