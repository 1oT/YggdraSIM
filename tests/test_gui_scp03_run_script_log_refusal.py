# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP03 Run script from the GUI refuses the shell's file-writing modifiers.

The SCP03 line executor honours ``--log <file>`` and ``TRACE START [file]``,
which write a file on the server host. The SCP11 console's GUI path refuses
``--log`` for that reason; the SCP03 Run script action does the same, before
any line reaches the engine.
"""

from __future__ import annotations

import pytest

from yggdrasim_common.gui_server.actions import scp03
from yggdrasim_common.gui_server.actions.registry import ActionContext


@pytest.fixture()
def engine_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _fake_entry_cmd(cmd_line: str, yaml_out: str | None = None, reader_name: str = "") -> None:
        calls.append(cmd_line)

    monkeypatch.setattr("SCP03.main.entry_cmd", _fake_entry_cmd)
    return calls


@pytest.mark.parametrize(
    "script",
    [
        "STATUS --log /tmp/scp03.log",
        "ATR; LIST --log=/tmp/scp03.log",
        "LIST --log",
        "TRACE START /tmp/trace.log",
        "trace stop",
    ],
)
def test_run_script_refuses_lines_that_write_a_file(engine_calls: list[str], script: str) -> None:
    with pytest.raises(ValueError, match="terminal command line only"):
        scp03._dispatch_run_script(ActionContext(), script_text=script)
    assert engine_calls == []


def test_run_script_runs_other_lines(engine_calls: list[str]) -> None:
    result = scp03._dispatch_run_script(ActionContext(), script_text="ATR\nLIST")
    assert engine_calls == ["ATR; LIST"]
    assert result["command_count"] == 2
