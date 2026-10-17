# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Verbs a plugin installs on the SCP03 admin shell receive their argument line."""
from __future__ import annotations

from SCP03.interface.shell import ShellDispatcher


def _bare_shell() -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.command_map = {}
    shell.commands = {}
    shell.debug_mode = False
    shell.transport = None
    shell._update_prompt_state = lambda: None
    shell._clear_prompt_context_tracking = lambda: None
    return shell


def test_plugin_verb_outside_the_registry_gets_its_argument_line():
    shell = _bare_shell()
    seen: list[str] = []
    shell.commands["PLUGVERB"] = lambda argument="": seen.append(argument)
    shell._exec_line("plugverb hello  world")
    shell._exec_line("PLUGVERB")
    assert seen == ["hello  world", ""]


def test_registry_verb_without_arguments_is_still_called_bare():
    shell = _bare_shell()
    calls: list[tuple] = []

    def verb(*args):
        calls.append(args)

    shell.command_map["BARE"] = (verb,)
    shell.commands["BARE"] = verb
    shell._exec_line("BARE")
    assert calls == [()]
