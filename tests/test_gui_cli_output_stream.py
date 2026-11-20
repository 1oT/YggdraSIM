# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A stream action in terminal mode shows a command as the shell prints it.

``cli_spans.line_spans`` reads a coloured line back into CLI palette roles;
the console stream's capture answers as a terminal, forwards every line
(blank ones too) with its spans and never as a hidden error level; channels
built inside ``shell_output()`` keep the shell's own logging mode; the page
paints each role with the token the terminal palettes are transcribed from.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from yggdrasim_common import cli_theme
from yggdrasim_common.gui_server import cli_spans, live_trace
from yggdrasim_common.gui_server.actions import scp11_live

REPO = Path(__file__).resolve().parents[1]
BOLD = "\x1b[1m"
RESET = "\x1b[0m"


@pytest.fixture(autouse=True)
def _one_palette():
    previous = cli_theme.active_theme()
    cli_theme.set_active_theme("oneot-dark")
    yield
    cli_theme.set_active_theme(previous)


def test_every_palette_role_reads_back_as_a_role() -> None:
    palette = cli_theme.active_palette()
    for role in cli_spans.ROLES:
        escape = cli_spans.role_escape(role)
        if len(escape) == 0:
            continue
        spans = cli_spans.line_spans(f"{escape}text{RESET}")
        assert len(spans) == 1 and spans[0]["text"] == "text"
        # Roles that share a colour read back as the first of them.
        assert palette[spans[0]["role"].upper()] == palette[role.upper()]


def test_line_spans_styles_resets_and_other_escapes() -> None:
    green = cli_spans.role_escape("green")
    red = cli_spans.role_escape("red")
    line = f"{green}{BOLD}YggdraSIM:{RESET} poll {red}failed{RESET}\x1b[2K \x1b[38;2;1;2;3mx{RESET}"
    spans = cli_spans.line_spans(line)
    assert [(span["text"], span["role"], span["bold"]) for span in spans] == [
        ("YggdraSIM:", "green", True), (" poll ", "", False), ("failed", "red", False), (" x", "", False),
    ]
    assert cli_spans.plain_text(spans) == "YggdraSIM: poll failed x"
    assert cli_spans.line_spans("") == []
    assert cli_spans.plain_text(cli_spans.line_spans("10%\r100%")) == "100%"
    assert cli_spans.line_spans("\x1b[")[0]["text"] == "\x1b["


def test_terminal_capture_forwards_lines_as_printed() -> None:
    posted: list[tuple[str, str, dict]] = []
    stream = scp11_live._CapturingStream(lambda level, message, **extra: posted.append((level, message, extra)),
                                         terminal=True)
    assert stream.isatty() is True
    red = cli_spans.role_escape("red")
    stream.write(f"first\n\n{red}error: failed{RESET}\ntail")
    stream.flush()
    assert [(level, message) for level, message, _ in posted] == [
        ("info", "first"), ("info", ""), ("info", "error: failed"), ("info", "tail"),
    ]
    assert posted[1][2]["spans"] == []
    assert posted[2][2]["spans"][0]["role"] == "red"

    plain: list[tuple[str, str]] = []
    default = scp11_live._CapturingStream(lambda level, message, **extra: plain.append((level, message)))
    assert default.isatty() is False
    default.write("first\n\nerror: failed\n")
    assert plain == [("info", "first"), ("error", "error: failed")]


def test_security_domain_view_names_the_protocol_and_lets_the_wheel_through() -> None:
    workbench = (REPO / "gui_frontend" / "src" / "js" / "saip-workbench.js").read_text(encoding="utf-8")
    assert '(key.key_version_protocol ? " (" + String(key.key_version_protocol) + ")" : "")' in workbench
    css = (REPO / "gui_frontend" / "src" / "css" / "views" / "saip" / "typed-pe-editor.css").read_text(encoding="utf-8")
    pane = css[css.index(".saip-sd-param-pane {", css.index(".saip-sd-param-tree {")):]
    pane = pane[:pane.index("}")]
    # The parameters box at the top of a security domain must not trap the wheel.
    assert "overscroll-behavior" not in pane.replace("/* No scroll containment", "")


def test_failure_lines_fail_the_done_frame() -> None:
    assert scp11_live._is_failure_line("[!] FLOW failed: Provider initiateAuthentication failed: x")
    assert scp11_live._is_failure_line("  [-] refused")
    for line in ("[*] Phase: Authenticate Server with eUICC", "[!] placeholder ES9 host still configured.",
                 "[*] 0 errors, nothing failed", ""):
        assert scp11_live._is_failure_line(line) is False


def test_shell_output_leaves_channels_as_built() -> None:
    class Channel:
        def __init__(self) -> None:
            self.calls: list[tuple[str, bool]] = []

        def set_quiet_apdu_logging(self, enabled: bool) -> None:
            self.calls.append(("quiet", enabled))

        def set_milestone_apdu_logging(self, enabled: bool) -> None:
            self.calls.append(("milestone", enabled))

        def set_raw_apdu_logging(self, enabled: bool) -> None:
            self.calls.append(("raw", enabled))

    inside = Channel()
    with live_trace.shell_output():
        assert live_trace.configure_channel_trace(inside) is inside
    assert inside.calls == []
    outside = Channel()
    live_trace.configure_channel_trace(outside)
    assert [name for name, _ in outside.calls] == ["quiet", "milestone", "raw"]


def test_page_paints_every_role_with_its_token() -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_cli_palettes", REPO / "scripts" / "generate_cli_palettes.py")
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    token_by_role = next(
        value for value in vars(generator).values()
        if isinstance(value, dict) and value.get("GREEN") == "ok" and value.get("RED") == "fail"
    )
    css = (REPO / "gui_frontend" / "src" / "css" / "views" / "cli-output.css").read_text(encoding="utf-8")
    rules: dict[str, str] = {}
    for block in css.split("}"):
        if "{" not in block:
            continue
        selectors, body = block.split("{", 1)
        for selector in selectors.split(","):
            rules[selector.strip().splitlines()[-1].strip()] = body
    for role in cli_spans.ROLES:
        body = rules.get(f".cc-cli-role--{role}")
        assert body is not None, role
        token = token_by_role.get(role.upper())
        if token is not None and role not in ("guide",):
            assert f"var(--{token})" in body, (role, token)
    order = (REPO / "gui_frontend" / "src" / "css" / ".css_order").read_text(encoding="utf-8")
    assert "views/cli-output.css" in order

    center = (REPO / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
    assert "if (Array.isArray(msg.spans)) {" in center
    assert "var follow = ccScrollIsAtEnd(block);" in center
    assert "if (follow) ccScrollToEnd(block);" in center
