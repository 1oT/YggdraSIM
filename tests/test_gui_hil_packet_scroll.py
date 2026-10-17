# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for scroll handling in the HIL Bridge packet list.

The list is virtualised: a top spacer, a window of real rows and a bottom
spacer, all sized from ``HIL_PACKET_VIRTUAL_ROW_HEIGHT``. Two defects made a
wheel gesture move the list a few percent of its own distance.

1. ``hilRestorePacketScroll`` captured ``scrollTop`` during the render and
   wrote it back from a ``requestAnimationFrame`` callback. The compositor
   applies another frame of the gesture in between, so every render snapped
   the list back to where it had been a frame earlier. Measured against the
   shipped bundle, a 2400 px gesture moved the list 80 px.

2. The write was bracketed by a flag cleared from ``setTimeout(..., 0)``. The
   scroll event for a programmatic write is dispatched with the next
   rendering update, by which time the flag has been cleared, so the write
   was read back as user input: it refreshed ``lastPacketScrollAt``,
   recomputed ``followTail`` and re-armed the render.

Both are pinned here, along with the premise the scheme rests on: the spacer
heights only keep ``scrollHeight`` constant -- and therefore only leave the
position alone -- while the assumed row height matches the CSS one.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


_REPO = Path(__file__).resolve().parents[1]
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_WORKBENCH_CSS = (
    _REPO
    / "gui_frontend"
    / "src"
    / "css"
    / "views"
    / "command-center-compact-workbench.css"
)


def _condensed(text: str) -> str:
    """Source with every run of whitespace removed.

    These assertions look for a construct, not for the formatting around it,
    so a reflow of the bundle must not read as a behaviour change.
    """
    return re.sub(r"\s+", "", text)


def _function_source(source: str, name: str) -> str:
    """The full text of ``function <name>(...) { ... }``, braces matched."""
    match = re.search(r"^[ \t]*function %s\(" % re.escape(name), source, re.M)
    if match is None:
        raise AssertionError("function %s not found in the bundle" % name)
    start = source.index("{", match.end() - 1)
    depth = 0
    index = start
    while index < len(source):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
        index += 1
    raise AssertionError("unbalanced braces in %s" % name)


def _css_block_height(css: str, selector: str) -> int:
    match = re.search(
        re.escape(selector) + r"\s*\{(.*?)\}",
        css,
        re.S,
    )
    if match is None:
        raise AssertionError("selector %s not found" % selector)
    height = re.search(r"(?<!min-)height:\s*(\d+)px", match.group(1))
    if height is None:
        raise AssertionError("no height declared on %s" % selector)
    return int(height.group(1))


class PacketScrollCorrection(unittest.TestCase):
    """``hilRestorePacketScroll`` corrects synchronously, and only on drift."""

    def setUp(self) -> None:
        self.app_js = _APP_JS.read_text(encoding="utf-8")
        self.restore = _function_source(self.app_js, "hilRestorePacketScroll")

    def test_correction_is_not_deferred_to_a_later_frame(self) -> None:
        # A write scheduled here lands after the user has scrolled further,
        # which is the whole defect.
        self.assertNotIn("requestAnimationFrame", self.restore)
        self.assertNotIn("setTimeout", self.restore)

    def test_correction_only_runs_when_the_position_actually_moved(self) -> None:
        condensed = _condensed(self.restore)
        self.assertIn("Math.abs(Number(list.scrollTop||0)-want)>1", condensed)
        # The one write in the function sits behind that guard.
        self.assertEqual(self.restore.count("list.scrollTop = "), 1)

    def test_a_written_position_is_recorded_for_the_scroll_listener(self) -> None:
        self.assertIn("state.packetProgrammaticTop = want;", self.restore)

    def test_tail_following_still_pins_the_list_to_the_bottom(self) -> None:
        condensed = _condensed(self.restore)
        self.assertIn("if(!opts.preserveExactScroll&&state.followTail){want=maxTop;", condensed)


class ProgrammaticScrollSentinel(unittest.TestCase):
    """The code's own writes are told apart by position, not by timing."""

    def setUp(self) -> None:
        self.app_js = _APP_JS.read_text(encoding="utf-8")

    def test_the_timing_flag_is_gone(self) -> None:
        # Cleared from setTimeout(..., 0), it was always stale by the time the
        # scroll event for the write was dispatched.
        self.assertNotIn("packetScrollRestoring", self.app_js)

    def test_the_sentinel_matches_on_position_and_is_consumed_once(self) -> None:
        consume = _function_source(self.app_js, "hilConsumePacketProgrammaticScroll")
        condensed = _condensed(consume)
        self.assertIn("Math.abs(Number(list.scrollTop||0)-expected)>1", condensed)
        self.assertIn("state.packetProgrammaticTop=null;", condensed)

    def test_a_programmatic_scroll_neither_re_arms_nor_steers_follow_tail(self) -> None:
        remember = _condensed(_function_source(self.app_js, "hilRememberPacketScroll"))
        self.assertIn("varprogrammatic=hilConsumePacketProgrammaticScroll(list);", remember)
        self.assertIn("hilStorePacketScroll(list,!programmatic);", remember)
        self.assertIn("returnprogrammatic;", remember)
        self.assertIn(
            _condensed(
                """
                list.addEventListener("scroll", function () {
                  if (hilRememberPacketScroll(list)) return;
                  hilSchedulePacketVirtualRender(list);
                });
                """
            ),
            _condensed(self.app_js),
        )


class PacketVirtualWindow(unittest.TestCase):
    """A scroll inside the overscan does no work."""

    def setUp(self) -> None:
        self.app_js = _APP_JS.read_text(encoding="utf-8")

    def test_the_scroll_driven_render_identifies_itself(self) -> None:
        schedule = _condensed(
            _function_source(self.app_js, "hilSchedulePacketVirtualRender")
        )
        self.assertIn("scrollOnly:true", schedule)

    def test_an_unmoved_window_skips_the_reconcile(self) -> None:
        render = _condensed(_function_source(self.app_js, "hilRenderPacketItems"))
        self.assertIn(
            "opts.scrollOnly&&state.packetVirtualStart===start"
            "&&state.packetVirtualCount===items.length",
            render,
        )
        self.assertIn("state.packetVirtualStart=start;", render)
        self.assertIn("state.packetVirtualCount=items.length;", render)

    def test_the_flag_reaches_the_window_from_the_render_entry_point(self) -> None:
        entry = _condensed(_function_source(self.app_js, "renderHilPacketList"))
        self.assertIn("scrollOnly:!!opts.scrollOnly", entry)


class PacketRowHeightAgreement(unittest.TestCase):
    """Leaving the position alone is only safe while the heights agree.

    Equal-height rows behind exact spacers hold ``scrollHeight`` at
    ``items.length * rowHeight`` whatever the window shows, so swapping the
    window cannot move the position. A CSS row taller or shorter than the
    constant breaks that and the list starts drifting under its own renders.
    """

    def test_the_virtual_row_height_matches_both_css_row_kinds(self) -> None:
        app_js = _APP_JS.read_text(encoding="utf-8")
        match = re.search(r"HIL_PACKET_VIRTUAL_ROW_HEIGHT\s*=\s*(\d+)", app_js)
        self.assertIsNotNone(match)
        assumed = int(match.group(1))

        css = _WORKBENCH_CSS.read_text(encoding="utf-8")
        self.assertEqual(_css_block_height(css, ".cc-hil-packet-row"), assumed)
        self.assertEqual(_css_block_height(css, ".cc-hil-context-title"), assumed)

    def test_both_css_row_kinds_are_border_box_and_height_pinned(self) -> None:
        css = _WORKBENCH_CSS.read_text(encoding="utf-8")
        for selector in (".cc-hil-packet-row", ".cc-hil-context-title"):
            block = re.search(re.escape(selector) + r"\s*\{(.*?)\}", css, re.S)
            self.assertIsNotNone(block, selector)
            body = block.group(1)
            self.assertIn("box-sizing: border-box", body, selector)
            self.assertIn("min-height:", body, selector)


if __name__ == "__main__":
    unittest.main()
