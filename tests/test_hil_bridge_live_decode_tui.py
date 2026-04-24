from __future__ import annotations

import asyncio
import importlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from Tools.HilBridge.live_decode_view import PacketSummary


class HilBridgeLiveDecodeTuiTests(unittest.TestCase):
    @staticmethod
    def _summary_row(number: int, *, info: str = "APDU") -> PacketSummary:
        return PacketSummary(
            number=number,
            time_text=f"{number / 1000:.6f}",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info=info,
        )

    def _build_app(self, layout_preferences=None, capture_path: str = "/tmp/live_capture.pcap"):
        from textual.app import App

        from Tools.HilBridge.live_decode_tui import default_tui_layout_preferences, run_live_decode_tui

        captured: dict[str, App] = {}
        original_run = App.run
        if layout_preferences is None:
            layout_preferences = default_tui_layout_preferences()

        def fake_run(app_self: App, *args: object, **kwargs: object) -> None:
            del args
            del kwargs
            captured["app"] = app_self

        App.run = fake_run
        try:
            with mock.patch(
                "Tools.HilBridge.live_decode_tui.load_tui_layout_preferences",
                return_value=layout_preferences,
            ):
                run_live_decode_tui(
                    capture_path,
                    service_name="demo.service",
                    capture_filter="udp port 4729",
                    startup_state={"activation_complete": True},
                    tshark_binary="/usr/bin/tshark",
                )
        finally:
            App.run = original_run
        self.assertIn("app", captured)
        return captured["app"]

    def test_module_imports_without_textual_side_effects(self) -> None:
        module = importlib.import_module("Tools.HilBridge.live_decode_tui")

        self.assertTrue(hasattr(module, "run_live_decode_tui"))
        self.assertTrue(hasattr(module, "PaneVisibility"))

    def test_toggled_pane_visibility_keeps_last_visible_pane(self) -> None:
        from Tools.HilBridge.live_decode_tui import PaneVisibility, toggled_pane_visibility

        visibility = PaneVisibility(summary=False, detail=False, bytes=True)

        self.assertEqual(toggled_pane_visibility(visibility, "bytes"), visibility)

    def test_visible_pane_order_reflects_current_visibility(self) -> None:
        from Tools.HilBridge.live_decode_tui import PaneVisibility, toggled_pane_visibility, visible_pane_order

        visibility = PaneVisibility()
        visibility = toggled_pane_visibility(visibility, "detail")

        self.assertEqual(visible_pane_order(visibility), ("summary", "bytes"))

    def test_preferred_textual_term_value_replaces_dumb_terminal(self) -> None:
        from Tools.HilBridge.live_decode_tui import _preferred_textual_term_value

        with mock.patch.dict(os.environ, {"TERM": "dumb"}, clear=False):
            self.assertNotEqual(_preferred_textual_term_value(), "dumb")

    def test_preferred_textual_term_value_keeps_supported_current_term(self) -> None:
        from Tools.HilBridge.live_decode_tui import _preferred_textual_term_value

        with mock.patch("Tools.HilBridge.live_decode_tui._terminfo_supports", return_value=True):
            with mock.patch.dict(os.environ, {"TERM": "linux", "TMUX": "", "STY": ""}, clear=False):
                self.assertEqual(_preferred_textual_term_value(), "linux")

    def test_preferred_textual_term_value_avoids_screen_fallback_without_tmux(self) -> None:
        from Tools.HilBridge.live_decode_tui import _preferred_textual_term_value

        def _fake_support(term_name: str) -> bool:
            return term_name in {"screen-256color", "xterm-256color"}

        with mock.patch("Tools.HilBridge.live_decode_tui._terminfo_supports", side_effect=_fake_support):
            with mock.patch.dict(os.environ, {"TERM": "dumb", "TMUX": "", "STY": ""}, clear=False):
                self.assertEqual(_preferred_textual_term_value(), "xterm-256color")

    def test_default_layout_preferences_start_with_decoded_pane_hidden(self) -> None:
        from Tools.HilBridge.live_decode_tui import default_tui_layout_preferences

        preferences = default_tui_layout_preferences()

        self.assertTrue(preferences.visibility.summary)
        self.assertFalse(preferences.visibility.detail)
        self.assertTrue(preferences.visibility.bytes)

    def test_save_and_load_tui_layout_preferences_round_trip(self) -> None:
        from Tools.HilBridge.live_decode_tui import (
            PaneVisibility,
            TuiLayoutPreferences,
            load_tui_layout_preferences,
            save_tui_layout_preferences,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap")
            expected = TuiLayoutPreferences(
                visibility=PaneVisibility(summary=True, detail=True, bytes=False),
                summary_height=18,
                detail_width=72,
                summary_view_mode="flat",
                theme_name="gruvbox",
                last_export_directory=str(Path(temp_dir) / "exports"),
                last_capture_open_directory=str(Path(temp_dir) / "captures"),
            )

            save_tui_layout_preferences(str(capture_path), expected)
            loaded = load_tui_layout_preferences(str(capture_path))

        self.assertEqual(loaded, expected)

    def test_theme_helpers_default_to_nord_and_follow_saip_cycle(self) -> None:
        from Tools.HilBridge.live_decode_tui import _THEME_CYCLE, _next_theme_name, _normalize_theme_name
        from Tools.ProfilePackage.saip_transcode_tui_prefs import THEME_CYCLE as SAIP_THEME_CYCLE

        self.assertEqual(_normalize_theme_name(""), "nord")
        self.assertEqual(_normalize_theme_name("tokyonight"), "tokyo-night")
        self.assertEqual(_next_theme_name("nord"), "dracula")
        self.assertEqual(_THEME_CYCLE, SAIP_THEME_CYCLE)

    def test_keybind_help_text_lists_f1_and_clear_view_shortcuts(self) -> None:
        from Tools.HilBridge.live_decode_tui import _hil_decode_keybind_help_text

        help_text = _hil_decode_keybind_help_text()

        self.assertIn("F1          Show keybinds", help_text)
        self.assertIn("Ctrl+F8    Toggle expert details", help_text)
        self.assertIn("Ctrl+F11   Clear current view", help_text)
        self.assertIn("Ctrl+Space Toggle all children in detail tree", help_text)
        self.assertIn("Left/Right  Collapse/expand tree nodes", help_text)

    def test_summary_group_name_classifies_generic_stk_filesystem_authentication_and_euicc_apdus(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_group_name

        self.assertEqual(_summary_group_name(self._summary_row(1, info="ENVELOPE"), None), "STK")
        self.assertEqual(_summary_group_name(self._summary_row(2, info="SELECT"), None), "ETSI FS")
        self.assertEqual(_summary_group_name(self._summary_row(3, info="TERMINAL RESPONSE"), None), "STK")
        self.assertEqual(
            _summary_group_name(self._summary_row(4, info="SEARCH RECORD"), None),
            "ETSI FS",
        )
        self.assertEqual(
            _summary_group_name(self._summary_row(5, info="VERIFY CHV"), None),
            "Authentication",
        )
        self.assertEqual(
            _summary_group_name(self._summary_row(6, info="RUN GSM ALGORITHM / AUTHENTICATE"), None),
            "Authentication",
        )
        self.assertEqual(
            _summary_group_name(self._summary_row(7, info="STORE DATA"), None),
            "eUICC",
        )
        self.assertEqual(
            _summary_group_name(
                self._summary_row(8, info="STORE DATA"),
                StatefulFrameAnnotation(frame_number=8, channel_session_id=1),
            ),
            "Channels",
        )

    def test_summary_partition_channel_rows_groups_channel_lifecycle_under_open_channel_session(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_channel_session_title,
            _summary_partition_channel_rows,
        )

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="SELECT"),
            self._summary_row(3, info="ENVELOPE"),
            self._summary_row(4, info="FETCH"),
            self._summary_row(5, info="STATUS"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix="FS MF/ISD-R SELECT",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix="CH1 DATA AVAILABLE 12B",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix="STK CLOSE CHANNEL | CH1 CLOSE",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
        }

        sessions, unbound_rows = _summary_partition_channel_rows(rows, annotations)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0][0], 1)
        self.assertEqual([int(row.number) for row in sessions[0][1]], [1, 2, 3, 4])
        self.assertEqual([int(row.number) for row in unbound_rows], [5])
        self.assertEqual(
            _summary_channel_session_title(1, sessions[0][1], annotations),
            "Poll 1",
        )

    def test_summary_partition_channel_poll_rows_pairs_dns_lookup_and_fqdn_sessions(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_channel_session_title,
            _summary_partition_channel_poll_rows,
        )

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="FETCH"),
            self._summary_row(3, info="FETCH"),
            self._summary_row(4, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-client-remote://8.8.8.8:53",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix=(
                    "CH1 SEND 33B | DNS Query: id=0x1234 "
                    "qname=eim.sm.1ot.com type=A class=IN"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix="STK OPEN CHANNEL | CH2 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=2,
                channel_number=1,
                channel_poll_index=2,
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix=(
                    "CH2 SEND 87B | TLS Handshake: ClientHello "
                    "sni=eim.sm.1ot.com (67 byte(s))"
                ),
                channel_session_id=2,
                channel_number=1,
                channel_poll_index=2,
            ),
        }
        session_buckets = [
            (1, [rows[0], rows[1]]),
            (2, [rows[2], rows[3]]),
        ]

        poll_buckets = _summary_partition_channel_poll_rows(session_buckets, annotations)

        self.assertEqual([poll_index for poll_index, _poll_sessions in poll_buckets], [1])
        self.assertEqual(
            [session_title for _session_id, session_title, _session_rows in poll_buckets[0][1]],
            [
                "DNS Lookup - eim.sm.1ot.com",
                "eIM - eim.sm.1ot.com",
            ],
        )
        self.assertEqual(
            _summary_channel_session_title(2, session_buckets[1][1], annotations),
            "Poll 1",
        )

    def test_summary_partition_channel_rows_bumps_untagged_rows_into_enclosing_session(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_partition_channel_rows

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="ENVELOPE"),
            self._summary_row(3, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=1,
                channel_number=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix="ETSI TS 102.221 ENVELOPE Event Download Data available",
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix="STK CLOSE CHANNEL | CH1 CLOSE",
                channel_session_id=1,
                channel_number=1,
            ),
        }

        sessions, unbound_rows = _summary_partition_channel_rows(rows, annotations)

        self.assertEqual(len(sessions), 1)
        self.assertEqual(int(sessions[0][0]), 1)
        self.assertEqual(
            [int(row.number) for row in sessions[0][1]],
            [1, 2, 3],
            msg=(
                "Frame 2 (ENVELOPE Data Available) must be bumped into "
                "session 1 via OPEN->CLOSE frame-range fallback even "
                "without an explicit CH tag."
            ),
        )
        self.assertEqual(len(unbound_rows), 0)

    def test_summary_partition_group_poll_rows_flattens_across_channels_without_channel_layer(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_partition_group_poll_rows

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="FETCH"),
            self._summary_row(3, info="FETCH"),
            self._summary_row(4, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-client-remote://8.8.8.8:53",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix="CH1 SEND 33B | DNS Query: id=0x1234 qname=eim.sm.1ot.com",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix="STK OPEN CHANNEL | CH2 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=2,
                channel_number=2,
                channel_poll_index=1,
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix="CH2 SEND 87B | TLS Handshake: ClientHello sni=eim.sm.1ot.com",
                channel_session_id=2,
                channel_number=2,
                channel_poll_index=1,
            ),
        }
        session_buckets = [
            (1, [rows[0], rows[1]]),
            (2, [rows[2], rows[3]]),
        ]

        poll_buckets = _summary_partition_group_poll_rows(session_buckets, annotations)

        self.assertEqual([poll_index for poll_index, _poll_sessions in poll_buckets], [1])
        self.assertEqual(
            [session_title for _session_id, session_title, _session_rows in poll_buckets[0][1]],
            [
                "DNS Lookup - eim.sm.1ot.com (CH1)",
                "eIM - eim.sm.1ot.com (CH2)",
            ],
        )

    def test_summary_partition_channel_session_context_rows_groups_tls_and_eim_contexts(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_channel_session_context_title,
            _summary_partition_channel_session_context_rows,
        )

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="FETCH"),
            self._summary_row(3, info="FETCH"),
            self._summary_row(4, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix=(
                    "CH1 SEND 87B | TLS Handshake: ClientHello "
                    "sni=tls.eim.1ot.com (67 byte(s))"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix=(
                    "CH1 SEND 33B | DNS Query: id=0x1234 "
                    "qname=eim.sm.1ot.com type=A class=IN"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix="CH1 SEND 22B | HTTP Request: POST /gsma/rsp2/es9plus/initiateAuthentication",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
        }

        context_buckets, unbound_rows = _summary_partition_channel_session_context_rows(rows, annotations)

        self.assertEqual(
            [_summary_channel_session_context_title(context_label) for context_label, _context_rows in context_buckets],
            ["TLS - tls.eim.1ot.com", "eIM - eim.sm.1ot.com"],
        )
        self.assertEqual(
            [[int(row.number) for row in context_rows] for _context_label, context_rows in context_buckets],
            [[2], [3, 4]],
        )
        self.assertEqual([int(row.number) for row in unbound_rows], [1])

    def test_summary_partition_channel_session_context_rows_keeps_tls_fqdn_for_follow_up_rows(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_channel_session_context_title,
            _summary_partition_channel_session_context_rows,
        )

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="FETCH"),
            self._summary_row(3, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix=(
                    "CH1 SEND 87B | TLS Handshake: ClientHello "
                    "sni=tls.eim.1ot.com (67 byte(s))"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix="CH1 RECEIVE 91B | TLS Handshake: ServerHello (68 byte(s))",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
        }

        context_buckets, unbound_rows = _summary_partition_channel_session_context_rows(rows, annotations)

        self.assertEqual(len(context_buckets), 1)
        self.assertEqual(
            _summary_channel_session_context_title(context_buckets[0][0]),
            "TLS - tls.eim.1ot.com",
        )
        self.assertEqual([int(row.number) for row in context_buckets[0][1]], [2, 3])
        self.assertEqual([int(row.number) for row in unbound_rows], [1])

    def test_summary_partition_channel_session_context_rows_prioritizes_tls_before_eim(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_channel_session_context_title,
            _summary_partition_channel_session_context_rows,
        )

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="FETCH"),
            self._summary_row(3, info="FETCH"),
            self._summary_row(4, info="FETCH"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix=(
                    "CH1 SEND 33B | DNS Query: id=0x1234 "
                    "qname=eim.sm.1ot.com type=A class=IN"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix=(
                    "CH1 SEND 87B | TLS Handshake: ClientHello "
                    "sni=tls.eim.1ot.com (67 byte(s))"
                ),
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix="CH1 SEND 22B | HTTP Request: POST /gsma/rsp2/es9plus/initiateAuthentication",
                channel_session_id=1,
                channel_number=1,
                channel_poll_index=1,
            ),
        }

        context_buckets, unbound_rows = _summary_partition_channel_session_context_rows(rows, annotations)

        self.assertEqual(
            [_summary_channel_session_context_title(context_label) for context_label, _context_rows in context_buckets],
            ["TLS - tls.eim.1ot.com", "eIM - eim.sm.1ot.com"],
        )
        self.assertEqual(
            [[int(row.number) for row in context_rows] for _context_label, context_rows in context_buckets],
            [[3], [2, 4]],
        )
        self.assertEqual([int(row.number) for row in unbound_rows], [1])

    def test_filter_detail_tree_lines_hides_expert_subtrees_when_disabled(self) -> None:
        from Tools.HilBridge.live_decode_tui import _filter_detail_tree_lines

        detail_lines = [
            "Frame 7: 81 bytes on wire",
            "  GSM SIM",
            "    Instruction: FETCH",
            "  [Malformed Packet: GSM SIM]",
            "    [Expert Info (Error/Malformed): Malformed Packet (Exception occurred)]",
            "      [Malformed Packet (Exception occurred)]",
            "      [Severity level: Error]",
            "  UDP",
            "    Source Port: 4729",
        ]

        self.assertEqual(
            _filter_detail_tree_lines(detail_lines, show_expert_details=False),
            [
                "Frame 7: 81 bytes on wire",
                "  GSM SIM",
                "    Instruction: FETCH",
                "  UDP",
                "    Source Port: 4729",
            ],
        )

    def test_summary_partition_channel_number_rows_groups_rows_by_channel_number(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_partition_channel_number_rows

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="SELECT"),
            self._summary_row(3, info="FETCH"),
            self._summary_row(4, info="TERMINAL RESPONSE"),
            self._summary_row(5, info="STORE DATA"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(frame_number=1, channel_session_id=1, channel_number=1, channel_poll_index=1),
            2: StatefulFrameAnnotation(frame_number=2, channel_session_id=1, channel_number=1, channel_poll_index=1),
            3: StatefulFrameAnnotation(frame_number=3, channel_session_id=2, channel_number=1, channel_poll_index=2),
            4: StatefulFrameAnnotation(frame_number=4, channel_session_id=2, channel_number=1, channel_poll_index=2),
            5: StatefulFrameAnnotation(frame_number=5, channel_session_id=3, channel_number=2, channel_poll_index=1),
        }

        channels, unbound_rows = _summary_partition_channel_number_rows(rows, annotations)

        self.assertEqual([channel_number for channel_number, _channel_rows in channels], [1, 2])
        self.assertEqual([int(row.number) for row in channels[0][1]], [1, 2, 3, 4])
        self.assertEqual([int(row.number) for row in channels[1][1]], [5])
        self.assertEqual(unbound_rows, [])

    def test_summary_secondary_text_prefers_original_apdu_info_prefix(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_secondary_text

        row = self._summary_row(1, info="FETCH")
        decorated_row = self._summary_row(1, info="FETCH | STK OPEN CHANNEL")
        annotation = StatefulFrameAnnotation(frame_number=1, summary_suffix="STK OPEN CHANNEL")

        self.assertEqual(_summary_secondary_text(row, annotation), "FETCH")
        self.assertEqual(_summary_secondary_text(decorated_row, annotation), "FETCH")

    def test_summary_display_label_text_drops_channel_prefix_segments(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_display_label_text

        self.assertEqual(
            _summary_display_label_text("STK OPEN CHANNEL | CH12 OPEN tcp-client-remote://1.2.3.4:443"),
            "STK OPEN CHANNEL | OPEN tcp-client-remote://1.2.3.4:443",
        )
        self.assertEqual(
            _summary_display_label_text(
                "CH12 SEND 87B | TLS Handshake: ClientHello sni=tls.eim.1ot.com (67 byte(s))"
            ),
            "SEND 87B | TLS Handshake: ClientHello sni=tls.eim.1ot.com (67 byte(s))",
        )
        self.assertEqual(
            _summary_display_label_text("CH12 CLOSED"),
            "CLOSED",
        )

    def test_summary_visible_text_parts_hide_top_pane_expert_details_when_disabled(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_visible_text_parts

        row = self._summary_row(1, info="FETCH | CH1 SEND 33B | DNS Query: qname=eim.sm.1ot.com")
        annotation = StatefulFrameAnnotation(
            frame_number=1,
            summary_suffix="CH1 SEND 33B | DNS Query: qname=eim.sm.1ot.com",
        )

        shown_primary, shown_secondary = _summary_visible_text_parts(
            row,
            annotation,
            show_expert_details=True,
        )
        hidden_primary, hidden_secondary = _summary_visible_text_parts(
            row,
            annotation,
            show_expert_details=False,
        )

        self.assertEqual(shown_primary, "SEND 33B | DNS Query: qname=eim.sm.1ot.com")
        self.assertEqual(shown_secondary, "FETCH")
        self.assertEqual(hidden_primary, "FETCH")
        self.assertIsNone(hidden_secondary)

    def test_summary_visible_text_parts_fall_back_to_primary_when_no_protocol_summary_exists(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_visible_text_parts

        row = self._summary_row(1, info="")
        annotation = StatefulFrameAnnotation(
            frame_number=1,
            summary_suffix="CH1 CLOSED",
        )

        hidden_primary, hidden_secondary = _summary_visible_text_parts(
            row,
            annotation,
            show_expert_details=False,
        )

        self.assertEqual(hidden_primary, "CLOSED")
        self.assertIsNone(hidden_secondary)

    def test_packet_route_text_hides_loopback_endpoints(self) -> None:
        from Tools.HilBridge.live_decode_tui import _packet_route_text

        row = self._summary_row(1, info="STATUS")

        self.assertIsNone(_packet_route_text(row))

    def test_summary_secondary_text_skips_loopback_route_and_uses_protocol_fallback(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_secondary_text

        row = PacketSummary(
            number=1,
            time_text="0.001000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="UDP",
            length_text="32",
            info="",
        )

        self.assertEqual(_summary_secondary_text(row, None), "UDP")

    def test_summary_selection_cursor_target_preserves_collapsed_ancestors(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_selection_cursor_target

        class FakeNode:
            def __init__(self, label: str, *, data=None, parent=None) -> None:
                self.label = label
                self.data = data
                self.parent = parent
                self.children: list[FakeNode] = []

        root = FakeNode("root")
        group = FakeNode("Channels", data={"kind": "group", "group_name": "Channels"}, parent=root)
        root.children.append(group)
        channel = FakeNode(
            "Channel 1",
            data={"kind": "channel", "group_name": "Channels", "expand_key": "Channels::CH1"},
            parent=group,
        )
        group.children.append(channel)
        poll = FakeNode(
            "Poll 2",
            data={"kind": "session", "group_name": "Channels", "expand_key": "Channels::SESSION2"},
            parent=channel,
        )
        channel.children.append(poll)
        frame = FakeNode(
            "#7",
            data={"kind": "frame", "frame_number": 7, "expand_key": "Channels::SESSION2"},
            parent=poll,
        )
        poll.children.append(frame)

        self.assertIs(_summary_selection_cursor_target(frame, set()), group)
        self.assertIs(_summary_selection_cursor_target(frame, {"Channels"}), channel)
        self.assertIs(
            _summary_selection_cursor_target(frame, {"Channels", "Channels::CH1"}),
            poll,
        )
        self.assertIs(
            _summary_selection_cursor_target(
                frame,
                {"Channels", "Channels::CH1", "Channels::SESSION2"},
            ),
            frame,
        )

    def test_move_summary_selection_cursor_targets_selected_frame_when_path_is_expanded(self) -> None:
        from Tools.HilBridge.live_decode_tui import _move_summary_selection_cursor

        class FakeNode:
            def __init__(self, label: str, *, data=None, parent=None) -> None:
                self.label = label
                self.data = data
                self.parent = parent
                self.children: list[FakeNode] = []

        class FakeTree:
            def __init__(self) -> None:
                self.cursor_node = None
                self.moved_to = None
                self.scrolled_to = None

            def move_cursor(self, node, animate: bool = False) -> None:
                del animate
                self.cursor_node = node
                self.moved_to = node

            def scroll_to_node(self, node, animate: bool = False) -> None:
                del animate
                self.scrolled_to = node

        root = FakeNode("root")
        group = FakeNode("Channels", data={"kind": "group", "group_name": "Channels"}, parent=root)
        root.children.append(group)
        channel = FakeNode(
            "Channel 1",
            data={"kind": "channel", "group_name": "Channels", "expand_key": "Channels::CH1"},
            parent=group,
        )
        group.children.append(channel)
        session = FakeNode(
            "DNS Lookup",
            data={"kind": "session", "group_name": "Channels", "expand_key": "Channels::SESSION2"},
            parent=channel,
        )
        channel.children.append(session)
        frame = FakeNode(
            "#7",
            data={"kind": "frame", "frame_number": 7, "expand_key": "Channels::SESSION2"},
            parent=session,
        )
        session.children.append(frame)
        tree = FakeTree()

        moved = _move_summary_selection_cursor(
            tree,
            {7: frame},
            7,
            {"Channels", "Channels::CH1", "Channels::SESSION2"},
        )

        self.assertTrue(moved)
        self.assertIs(tree.moved_to, frame)
        self.assertIs(tree.scrolled_to, frame)

    def test_move_summary_selection_cursor_falls_back_to_visible_ancestor_when_collapsed(self) -> None:
        from Tools.HilBridge.live_decode_tui import _move_summary_selection_cursor

        class FakeNode:
            def __init__(self, label: str, *, data=None, parent=None) -> None:
                self.label = label
                self.data = data
                self.parent = parent
                self.children: list[FakeNode] = []

        class FakeTree:
            def __init__(self) -> None:
                self.cursor_node = None
                self.moved_to = None
                self.scrolled_to = None

            def move_cursor(self, node, animate: bool = False) -> None:
                del animate
                self.cursor_node = node
                self.moved_to = node

            def scroll_to_node(self, node, animate: bool = False) -> None:
                del animate
                self.scrolled_to = node

        root = FakeNode("root")
        group = FakeNode("Channels", data={"kind": "group", "group_name": "Channels"}, parent=root)
        root.children.append(group)
        channel = FakeNode(
            "Channel 1",
            data={"kind": "channel", "group_name": "Channels", "expand_key": "Channels::CH1"},
            parent=group,
        )
        group.children.append(channel)
        poll = FakeNode(
            "Poll 2",
            data={"kind": "poll", "group_name": "Channels", "expand_key": "Channels::CH1::POLL2"},
            parent=channel,
        )
        channel.children.append(poll)
        session = FakeNode(
            "eIM",
            data={"kind": "session", "group_name": "Channels", "expand_key": "Channels::SESSION4"},
            parent=poll,
        )
        poll.children.append(session)
        frame = FakeNode(
            "#9",
            data={"kind": "frame", "frame_number": 9, "expand_key": "Channels::SESSION4"},
            parent=session,
        )
        session.children.append(frame)
        tree = FakeTree()

        moved = _move_summary_selection_cursor(
            tree,
            {9: frame},
            9,
            {"Channels", "Channels::CH1"},
        )

        self.assertTrue(moved)
        self.assertIs(tree.moved_to, poll)
        self.assertIs(tree.scrolled_to, poll)

    def test_apply_summary_tree_expand_state_change_ignores_rebuild_events(self) -> None:
        from Tools.HilBridge.live_decode_tui import _apply_summary_tree_expand_state_change

        expanded_group_names = {"Channels", "Channels::CH1", "Channels::SESSION2"}

        changed = _apply_summary_tree_expand_state_change(
            expanded_group_names,
            {"kind": "session", "expand_key": "Channels::SESSION2"},
            expanded=False,
            sync_inflight=True,
        )

        self.assertFalse(changed)
        self.assertEqual(
            expanded_group_names,
            {"Channels", "Channels::CH1", "Channels::SESSION2"},
        )

    def test_apply_summary_tree_expand_state_change_updates_saved_expansions_when_not_rebuilding(self) -> None:
        from Tools.HilBridge.live_decode_tui import _apply_summary_tree_expand_state_change

        expanded_group_names = {"Channels"}

        changed_expand = _apply_summary_tree_expand_state_change(
            expanded_group_names,
            {"kind": "channel", "expand_key": "Channels::CH1"},
            expanded=True,
            sync_inflight=False,
        )
        changed_collapse = _apply_summary_tree_expand_state_change(
            expanded_group_names,
            {"kind": "channel", "expand_key": "Channels::CH1"},
            expanded=False,
            sync_inflight=False,
        )

        self.assertTrue(changed_expand)
        self.assertTrue(changed_collapse)
        self.assertEqual(expanded_group_names, {"Channels"})

    def test_summary_highlighted_frame_number_ignores_stale_highlight_node(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_highlighted_frame_number

        current_node = SimpleNamespace(data={"kind": "frame", "frame_number": 7})
        stale_node = SimpleNamespace(data={"kind": "frame", "frame_number": 1})
        tree = SimpleNamespace(cursor_node=current_node)

        self.assertIsNone(_summary_highlighted_frame_number(tree, stale_node))
        self.assertEqual(_summary_highlighted_frame_number(tree, current_node), 7)

    def test_reset_capture_runtime_state_clears_rows_selection_and_caches(self) -> None:
        from Tools.HilBridge.live_decode_tui import _reset_capture_runtime_state

        app = SimpleNamespace(
            _capture_generation=3,
            _last_capture_size=1024,
            _last_error="boom",
            _latest_capture_time_seconds=1.25,
            _latest_capture_monotonic=42.0,
            _base_rows=[self._summary_row(1)],
            _rows=[self._summary_row(2)],
            _state_annotations={2: object()},
            _interesting_frame_numbers=[2],
            _summary_tree_frame_nodes={2: object()},
            _summary_tree_expanded_groups={"Channels", "Channels::CH1"},
            _selected_frame_number=2,
            _requested_detail_frame=2,
            _detail_cache={2: "decoded"},
            _bytes_cache={2: "bytes"},
            _displayed_detail_key=(2, "a", "b", ()),
            _displayed_bytes_key=(2, "a", "b"),
            _refresh_inflight=True,
            _detail_inflight=True,
            _follow_tail=False,
        )

        _reset_capture_runtime_state(app)

        self.assertEqual(app._capture_generation, 4)
        self.assertEqual(app._last_capture_size, -1)
        self.assertEqual(app._last_error, "")
        self.assertIsNone(app._latest_capture_time_seconds)
        self.assertIsNone(app._latest_capture_monotonic)
        self.assertEqual(app._base_rows, [])
        self.assertEqual(app._rows, [])
        self.assertEqual(app._state_annotations, {})
        self.assertEqual(app._interesting_frame_numbers, [])
        self.assertEqual(app._summary_tree_frame_nodes, {})
        self.assertEqual(app._summary_tree_expanded_groups, set())
        self.assertIsNone(app._selected_frame_number)
        self.assertIsNone(app._requested_detail_frame)
        self.assertEqual(app._detail_cache, {})
        self.assertEqual(app._bytes_cache, {})
        self.assertIsNone(app._displayed_detail_key)
        self.assertIsNone(app._displayed_bytes_key)
        self.assertFalse(app._refresh_inflight)
        self.assertFalse(app._detail_inflight)
        self.assertTrue(app._follow_tail)

    def test_handle_tree_arrow_key_expands_current_node_and_collapses_parent_from_leaf(self) -> None:
        from Tools.HilBridge.live_decode_tui import _handle_tree_arrow_key

        class FakeNode:
            def __init__(self, label: str, *, parent=None) -> None:
                self.label = label
                self.parent = parent
                self.children: list[FakeNode] = []
                self.is_expanded = False

            def expand(self) -> None:
                self.is_expanded = True

            def collapse(self) -> None:
                self.is_expanded = False

        class FakeTree:
            def __init__(self, root: FakeNode, cursor_node: FakeNode) -> None:
                self.root = root
                self.cursor_node = cursor_node
                self.moved_to = None

            def move_cursor(self, node, animate: bool = False) -> None:
                del animate
                self.moved_to = node
                self.cursor_node = node

        root = FakeNode("root")
        parent = FakeNode("parent", parent=root)
        leaf = FakeNode("leaf", parent=parent)
        parent.children.append(leaf)

        tree = FakeTree(root, parent)

        self.assertTrue(_handle_tree_arrow_key(tree, "right"))
        self.assertTrue(parent.is_expanded)

        tree.cursor_node = leaf
        self.assertTrue(_handle_tree_arrow_key(tree, "left"))
        self.assertFalse(parent.is_expanded)
        self.assertIs(tree.moved_to, parent)

    def test_toggle_tree_subtree_expands_and_collapses_descendants(self) -> None:
        from Tools.HilBridge.live_decode_tui import _toggle_tree_subtree

        class FakeNode:
            def __init__(self, label: str, *, parent=None) -> None:
                self.label = label
                self.parent = parent
                self.children: list[FakeNode] = []
                self.is_expanded = False

            def expand(self) -> None:
                self.is_expanded = True

            def collapse(self) -> None:
                self.is_expanded = False

        root = FakeNode("root")
        parent = FakeNode("parent", parent=root)
        child = FakeNode("child", parent=parent)
        grandchild = FakeNode("grandchild", parent=child)
        parent.children.append(child)
        child.children.append(grandchild)

        self.assertTrue(_toggle_tree_subtree(parent))
        self.assertTrue(parent.is_expanded)
        self.assertTrue(child.is_expanded)

        self.assertTrue(_toggle_tree_subtree(parent))
        self.assertFalse(parent.is_expanded)
        self.assertFalse(child.is_expanded)

    def test_default_saved_trace_path_prefers_last_export_directory(self) -> None:
        from Tools.HilBridge.live_decode_tui import _default_saved_trace_path

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcapng"
            remembered_directory = Path(temp_dir) / "exports" / "recent"

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                suggested_path = _default_saved_trace_path(
                    str(capture_path),
                    str(remembered_directory),
                )

        self.assertEqual(
            suggested_path,
            remembered_directory.resolve() / "live_capture_20260414_120000.pcapng",
        )

    def test_pick_capture_file_path_prefers_last_open_directory_when_available(self) -> None:
        from Tools.HilBridge.live_decode_tui import pick_capture_file_path

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"live")
            remembered_directory = Path(temp_dir) / "captures" / "recent"
            selected_path = remembered_directory / "offline_capture.pcapng"
            selected_path.parent.mkdir(parents=True, exist_ok=True)
            selected_path.write_bytes(b"offline")
            completed = SimpleNamespace(
                returncode=0,
                stdout=f"{selected_path}\n",
                stderr="",
            )

            with mock.patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.shutil.which",
                    side_effect=lambda name: "/usr/bin/zenity" if name == "zenity" else None,
                ):
                    with mock.patch(
                        "Tools.HilBridge.live_decode_tui.subprocess.run",
                        return_value=completed,
                    ) as run_picker:
                        result = pick_capture_file_path(
                            str(capture_path),
                            last_open_directory=str(remembered_directory),
                        )

            self.assertEqual(result, selected_path.resolve())
            run_picker.assert_called_once()
            self.assertIn(
                f"--filename={remembered_directory.resolve()}/",
                run_picker.call_args.args[0],
            )

    def test_save_live_capture_trace_copies_into_saved_traces_and_avoids_collisions(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcapng"
            capture_path.write_bytes(b"pcap-bytes")

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                first_saved = save_live_capture_trace(str(capture_path))
                second_saved = save_live_capture_trace(str(capture_path))

            self.assertEqual(first_saved.parent.name, "saved_traces")
            self.assertEqual(first_saved.name, "live_capture_20260414_120000.pcapng")
            self.assertEqual(second_saved.name, "live_capture_20260414_120000_01.pcapng")
            self.assertEqual(first_saved.read_bytes(), b"pcap-bytes")
            self.assertEqual(second_saved.read_bytes(), b"pcap-bytes")

    def test_save_live_capture_trace_accepts_directory_target(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")
            export_directory = Path(temp_dir) / "exports"

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                saved_path = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(export_directory),
                )

            self.assertEqual(saved_path.parent, export_directory)
            self.assertEqual(saved_path.name, "live_capture_20260414_120000.pcap")
            self.assertEqual(saved_path.read_bytes(), b"pcap-bytes")

    def test_build_app_applies_loaded_layout_preferences(self) -> None:
        from Tools.HilBridge.live_decode_tui import PaneVisibility, TuiLayoutPreferences

        preferences = TuiLayoutPreferences(
            visibility=PaneVisibility(summary=True, detail=True, bytes=False),
            summary_height=17,
            detail_width=68,
            summary_view_mode="flat",
        )

        app = self._build_app(layout_preferences=preferences)

        self.assertEqual(app._visibility, preferences.visibility)
        self.assertEqual(app._summary_height, 17)
        self.assertEqual(app._detail_width, 68)
        self.assertEqual(app._summary_view_mode, "flat")
        self.assertEqual(app._theme_name, "nord")

    def test_hil_tui_css_uses_nord_selectors_for_tmux_lists_and_modal_controls(self) -> None:
        app = self._build_app()

        self.assertIn("PaneLayoutPicker, TraceSavePicker, CaptureOpenPicker, KeybindHelpScreen", app.CSS)
        self.assertIn("#summary_tree > .tree--cursor", app.CSS)
        self.assertIn("Input > .input--cursor", app.CSS)
        self.assertIn("Button.-primary", app.CSS)

    def test_save_trace_action_opens_picker_with_suggested_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot")
            app = self._build_app(capture_path=str(capture_path))
            captured: dict[str, object] = {}

            def fake_push_screen(screen, callback=None):
                captured["screen"] = screen
                captured["callback"] = callback

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                with mock.patch.object(app, "push_screen", side_effect=fake_push_screen):
                    app.action_save_trace_snapshot()

            self.assertIn("screen", captured)
            self.assertTrue(callable(captured["callback"]))
            self.assertEqual(getattr(captured["callback"], "__name__", ""), "_on_trace_save_choice")
            self.assertEqual(
                getattr(captured["screen"], "_suggested_path_text", ""),
                str(capture_path.parent / "saved_traces" / "live_capture_20260414_120000.pcap"),
            )

    def test_save_trace_action_prefers_remembered_export_directory(self) -> None:
        from Tools.HilBridge.live_decode_tui import PaneVisibility, TuiLayoutPreferences

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot")
            remembered_directory = Path(temp_dir) / "exports" / "recent"
            preferences = TuiLayoutPreferences(
                visibility=PaneVisibility(summary=True, detail=False, bytes=True),
                summary_height=14,
                detail_width=56,
                last_export_directory=str(remembered_directory),
            )
            app = self._build_app(
                layout_preferences=preferences,
                capture_path=str(capture_path),
            )
            captured: dict[str, object] = {}

            def fake_push_screen(screen, callback=None):
                captured["screen"] = screen
                captured["callback"] = callback

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                with mock.patch.object(app, "push_screen", side_effect=fake_push_screen):
                    app.action_save_trace_snapshot()

            self.assertIn("screen", captured)
            self.assertEqual(
                getattr(captured["screen"], "_suggested_path_text", ""),
                str(remembered_directory / "live_capture_20260414_120000.pcap"),
            )

    def test_trace_save_choice_reports_saved_snapshot_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot")
            app = self._build_app(capture_path=str(capture_path))
            captured_messages: list[tuple[str | None, bool | None]] = []

            def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
                captured_messages.append((message, error))

            with mock.patch("Tools.HilBridge.live_decode_tui.time.strftime", return_value="20260414_120000"):
                with mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
                    app._on_trace_save_choice(str(capture_path.parent / "exports"))

            saved_path = capture_path.parent / "exports" / "live_capture_20260414_120000.pcap"
            self.assertTrue(saved_path.is_file())
            self.assertEqual(saved_path.read_bytes(), b"pcap-snapshot")
            self.assertEqual(captured_messages[-1][1], False)
            self.assertIn("Trace snapshot saved:", str(captured_messages[-1][0]))
            self.assertIn("exports", str(captured_messages[-1][0]))
            self.assertEqual(app._last_trace_export_directory, str((capture_path.parent / "exports").resolve()))

    def test_resolve_editcap_binary_prefers_sibling_of_tshark_then_falls_back_to_path(self) -> None:
        from Tools.HilBridge.live_decode_tui import resolve_editcap_binary

        with tempfile.TemporaryDirectory() as temp_dir:
            tshark_dir = Path(temp_dir) / "bin"
            tshark_dir.mkdir(parents=True, exist_ok=True)
            tshark_path = tshark_dir / "tshark"
            tshark_path.write_text("#!/bin/sh\n")
            tshark_path.chmod(0o755)
            editcap_sibling = tshark_dir / "editcap"
            editcap_sibling.write_text("#!/bin/sh\n")
            editcap_sibling.chmod(0o755)

            self.assertEqual(
                resolve_editcap_binary(str(tshark_path)),
                str(editcap_sibling),
            )

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.shutil.which",
            side_effect=lambda name: "/usr/bin/editcap" if name == "editcap" else None,
        ):
            self.assertEqual(resolve_editcap_binary(""), "/usr/bin/editcap")

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.shutil.which",
            return_value=None,
        ):
            self.assertEqual(resolve_editcap_binary(""), "")

    def test_save_live_capture_trace_uses_editcap_to_clip_packet_count_when_requested(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes-with-queued-tail")
            target_directory = Path(temp_dir) / "exports"

            captured_commands: list[list[str]] = []

            def fake_run(command, *_args, **_kwargs):
                captured_commands.append(list(command))
                Path(command[3]).write_bytes(b"editcap-trimmed")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=25,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run",
                side_effect=fake_run,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ):
                saved_path = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(target_directory),
                    packet_count=17,
                    tshark_binary="/usr/bin/tshark",
                )

            self.assertEqual(len(captured_commands), 1)
            command = captured_commands[0]
            self.assertEqual(command[0], "/usr/bin/editcap")
            self.assertEqual(command[1], "-r")
            self.assertEqual(command[2], str(capture_path.resolve()))
            self.assertEqual(command[3], str(saved_path))
            self.assertEqual(command[4], "1-17")
            self.assertEqual(saved_path.read_bytes(), b"editcap-trimmed")

    def test_save_live_capture_trace_falls_back_to_copy_when_packet_count_is_none_or_zero(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot")
            target_directory = Path(temp_dir) / "exports"

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run"
            ) as run_mock, mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ):
                none_saved = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(target_directory),
                    packet_count=None,
                    tshark_binary="/usr/bin/tshark",
                )
                zero_saved = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(target_directory),
                    packet_count=0,
                    tshark_binary="/usr/bin/tshark",
                )

            run_mock.assert_not_called()
            self.assertEqual(none_saved.read_bytes(), b"pcap-snapshot")
            self.assertEqual(zero_saved.read_bytes(), b"pcap-snapshot")

    def test_save_live_capture_trace_raises_when_editcap_is_missing(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=-1,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run"
            ) as run_mock:
                with self.assertRaises(RuntimeError) as caught:
                    save_live_capture_trace(
                        str(capture_path),
                        target_path=str(Path(temp_dir) / "exports"),
                        packet_count=5,
                    )

            run_mock.assert_not_called()
            self.assertIn("editcap", str(caught.exception))

    def test_save_live_capture_trace_raises_when_editcap_returns_nonzero(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=1,
                    stdout=b"",
                    stderr=b"editcap: range out of bounds",
                ),
            ):
                with self.assertRaises(RuntimeError) as caught:
                    save_live_capture_trace(
                        str(capture_path),
                        target_path=str(Path(temp_dir) / "exports"),
                        packet_count=100,
                        tshark_binary="/usr/bin/tshark",
                    )

            self.assertIn("editcap", str(caught.exception).lower())
            self.assertIn("range out of bounds", str(caught.exception))

    def test_on_trace_save_choice_clips_to_base_rows_only_when_ingest_paused(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot-full")
            app = self._build_app(capture_path=str(capture_path))
            app._base_rows = [self._summary_row(i) for i in range(1, 6)]
            app._ingest_paused = True

            calls: list[dict[str, object]] = []

            def fake_save(capture_path_arg, *, target_path, packet_count, tshark_binary):
                calls.append(
                    {
                        "capture_path": str(capture_path_arg),
                        "target_path": str(target_path),
                        "packet_count": packet_count,
                        "tshark_binary": str(tshark_binary or ""),
                    }
                )
                resolved_target = Path(str(target_path)) / "live_capture_20260414_120000.pcap"
                resolved_target.parent.mkdir(parents=True, exist_ok=True)
                resolved_target.write_bytes(b"paused-subset")
                return resolved_target

            captured_messages: list[tuple[str | None, bool | None]] = []

            def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
                captured_messages.append((message, error))

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.save_live_capture_trace",
                side_effect=fake_save,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ), mock.patch.object(
                app, "_refresh_status_line", side_effect=capture_status
            ), mock.patch.object(
                app, "_save_layout_preferences"
            ):
                app._on_trace_save_choice(str(capture_path.parent / "exports"))

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["packet_count"], 5)
            self.assertIn("paused context", str(captured_messages[-1][0]))
            self.assertIn("5 packets", str(captured_messages[-1][0]))

    def test_on_trace_save_choice_leaves_packet_count_unset_when_not_paused(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot-full")
            app = self._build_app(capture_path=str(capture_path))
            app._base_rows = [self._summary_row(i) for i in range(1, 6)]
            app._ingest_paused = False

            calls: list[dict[str, object]] = []

            def fake_save(capture_path_arg, *, target_path, packet_count, tshark_binary):
                calls.append(
                    {
                        "capture_path": str(capture_path_arg),
                        "target_path": str(target_path),
                        "packet_count": packet_count,
                        "tshark_binary": str(tshark_binary or ""),
                    }
                )
                resolved_target = Path(str(target_path)) / "live_capture_20260414_120000.pcap"
                resolved_target.parent.mkdir(parents=True, exist_ok=True)
                resolved_target.write_bytes(b"full-copy")
                return resolved_target

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.save_live_capture_trace",
                side_effect=fake_save,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ), mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
                app, "_save_layout_preferences"
            ):
                app._on_trace_save_choice(str(capture_path.parent / "exports"))

            self.assertEqual(len(calls), 1)
            self.assertIsNone(calls[0]["packet_count"])

    def test_pick_capture_file_path_uses_zenity_when_available(self) -> None:
        from Tools.HilBridge.live_decode_tui import pick_capture_file_path

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"live")
            selected_path = Path(temp_dir) / "saved_traces" / "offline_capture.pcapng"
            selected_path.parent.mkdir(parents=True, exist_ok=True)
            selected_path.write_bytes(b"offline")
            completed = SimpleNamespace(
                returncode=0,
                stdout=f"{selected_path}\n",
                stderr="",
            )

            with mock.patch.dict(os.environ, {"DISPLAY": ":0"}, clear=False):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.shutil.which",
                    side_effect=lambda name: "/usr/bin/zenity" if name == "zenity" else None,
                ):
                    with mock.patch(
                        "Tools.HilBridge.live_decode_tui.subprocess.run",
                        return_value=completed,
                    ) as run_picker:
                        result = pick_capture_file_path(str(capture_path))

            self.assertEqual(result, selected_path.resolve())
            run_picker.assert_called_once()
            self.assertEqual(run_picker.call_args.args[0][0], "zenity")

    def test_open_capture_action_falls_back_to_prompt_when_native_picker_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"live")
            app = self._build_app(capture_path=str(capture_path))
            captured: dict[str, object] = {}

            def fake_push_screen(screen, callback=None):
                captured["screen"] = screen
                captured["callback"] = callback

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.pick_capture_file_path",
                side_effect=RuntimeError("No desktop display is available for the native file picker."),
            ):
                with mock.patch.object(app, "push_screen", side_effect=fake_push_screen):
                    app.action_open_capture_file()

            self.assertIn("screen", captured)
            self.assertEqual(type(captured["screen"]).__name__, "CaptureOpenPicker")
            self.assertTrue(callable(captured["callback"]))
            self.assertEqual(getattr(captured["callback"], "__name__", ""), "_on_open_capture_choice")

    def test_open_capture_choice_switches_capture_and_resets_cached_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            live_capture_path = Path(temp_dir) / "live_capture.pcap"
            live_capture_path.write_bytes(b"live")
            offline_capture_path = Path(temp_dir) / "saved_traces" / "offline_capture.pcapng"
            offline_capture_path.parent.mkdir(parents=True, exist_ok=True)
            offline_capture_path.write_bytes(b"offline")
            app = self._build_app(capture_path=str(live_capture_path))
            app._capture_generation = 3
            app._rows = [self._summary_row(7)]
            app._base_rows = [self._summary_row(7)]
            app._state_annotations = {7: object()}  # type: ignore[assignment]
            app._interesting_frame_numbers = [7]
            app._summary_tree_frame_nodes = {7: object()}
            app._selected_frame_number = 7
            app._detail_cache = {7: "detail"}
            app._bytes_cache = {7: "bytes"}
            app._displayed_detail_key = (7, "detail", ())
            app._displayed_bytes_key = (7, "bytes")
            captured_messages: list[tuple[str | None, bool | None]] = []

            def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
                captured_messages.append((message, error))

            with mock.patch.object(app, "_set_detail_views") as set_detail_views:
                with mock.patch.object(app, "_refresh_captions") as refresh_captions:
                    with mock.patch.object(app, "_rebuild_summary_view") as rebuild_summary:
                        with mock.patch.object(app, "_schedule_summary_refresh") as schedule_refresh:
                            with mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
                                app._on_open_capture_choice(str(offline_capture_path))

            self.assertEqual(app._capture_path, str(offline_capture_path.resolve()))
            self.assertEqual(app._capture_generation, 4)
            self.assertEqual(app._rows, [])
            self.assertEqual(app._base_rows, [])
            self.assertEqual(app._interesting_frame_numbers, [])
            self.assertEqual(app._summary_tree_frame_nodes, {})
            self.assertIsNone(app._selected_frame_number)
            self.assertEqual(app._detail_cache, {})
            self.assertEqual(app._bytes_cache, {})
            self.assertIsNone(app._displayed_detail_key)
            self.assertIsNone(app._displayed_bytes_key)
            self.assertEqual(app._last_capture_open_directory, str(offline_capture_path.parent.resolve()))
            self.assertTrue(app._follow_tail)
            set_detail_views.assert_called_once_with(
                "Loading decoded fields...",
                "Loading byte view...",
            )
            refresh_captions.assert_called_once()
            rebuild_summary.assert_called_once()
            schedule_refresh.assert_called_once()
            self.assertEqual(captured_messages[-1][1], False)
            self.assertIn("Opened capture:", str(captured_messages[-1][0]))
            self.assertIn("offline_capture.pcapng", str(captured_messages[-1][0]))

    def test_apply_detail_refresh_ignores_stale_capture_generation(self) -> None:
        app = self._build_app()
        app._capture_generation = 5
        app._detail_inflight = True

        app._apply_detail_refresh(
            4,
            9,
            "Frame 9 detail",
            "DE AD BE EF",
            "",
            "",
        )

        self.assertFalse(app._detail_inflight)
        self.assertEqual(app._detail_cache, {})
        self.assertEqual(app._bytes_cache, {})

    def test_apply_split_sizes_keeps_loaded_preferences_until_geometry_exists(self) -> None:
        from Tools.HilBridge.live_decode_tui import PaneVisibility, TuiLayoutPreferences

        preferences = TuiLayoutPreferences(
            visibility=PaneVisibility(summary=True, detail=True, bytes=True),
            summary_height=31,
            detail_width=92,
        )
        app = self._build_app(layout_preferences=preferences)

        body = SimpleNamespace(
            size=SimpleNamespace(height=0),
            region=SimpleNamespace(height=0),
        )
        upper = SimpleNamespace(
            styles=SimpleNamespace(height=None),
            size=SimpleNamespace(height=0),
            region=SimpleNamespace(height=0),
        )
        bottom_row = SimpleNamespace(
            styles=SimpleNamespace(height=None),
            size=SimpleNamespace(width=0),
            region=SimpleNamespace(width=0),
        )
        detail_col = SimpleNamespace(
            styles=SimpleNamespace(width=None),
            size=SimpleNamespace(width=0),
            region=SimpleNamespace(width=0),
        )
        bytes_col = SimpleNamespace(
            styles=SimpleNamespace(width=None),
            size=SimpleNamespace(width=0),
            region=SimpleNamespace(width=0),
        )

        def fake_query_one(selector: str, *_args):
            if selector == "#body":
                return body
            if selector == "#upper":
                return upper
            if selector == "#bottom_row":
                return bottom_row
            if selector == "#detail_col":
                return detail_col
            if selector == "#bytes_col":
                return bytes_col
            raise AssertionError(f"Unexpected query_one request: {selector!r}")

        app.query_one = fake_query_one
        app._apply_split_sizes()

        self.assertEqual(app._summary_height, 31)
        self.assertEqual(app._detail_width, 92)
        self.assertEqual(upper.styles.height, 31)
        self.assertEqual(detail_col.styles.width, 92)
        self.assertEqual(bottom_row.styles.height, "1fr")
        self.assertEqual(bytes_col.styles.width, "1fr")

    def test_decoded_pane_mounts_as_tree_and_supports_expand_toggle(self) -> None:
        from textual.widgets import RichLog, Tree
        from Tools.HilBridge.live_decode_tui import PaneVisibility, TuiLayoutPreferences

        preferences = TuiLayoutPreferences(
            visibility=PaneVisibility(summary=True, detail=True, bytes=True),
            summary_height=17,
            detail_width=68,
        )

        async def scenario() -> None:
            app = self._build_app(layout_preferences=preferences)
            sample_row = PacketSummary(
                number=7,
                time_text="0.000000",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info="FETCH",
            )
            with mock.patch(
                "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                return_value=([sample_row], ""),
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_detail",
                    return_value=("Frame 7: 80 bytes on wire\n  Source: modem\n  Destination: card", ""),
                ):
                    with mock.patch(
                        "Tools.HilBridge.live_decode_tui.read_packet_hex",
                        return_value=("0000  A0 A4 00 00 02 3F 00   ......?.", ""),
                    ):
                        async with app.run_test() as pilot:
                            detail_view = app.query_one("#detail_view", Tree)
                            bytes_view = app.query_one("#bytes_view", RichLog)

                            app._apply_summary_refresh([sample_row], "")
                            await pilot.pause()
                            app.action_cycle_focus()
                            await pilot.pause()

                            top_level_nodes = list(detail_view.root.children)

                            self.assertIsInstance(detail_view, Tree)
                            self.assertIsInstance(bytes_view, RichLog)
                            self.assertEqual(getattr(app.focused, "id", None), "detail_view")
                            self.assertEqual(len(top_level_nodes), 1)
                            self.assertGreater(len(top_level_nodes[0].children), 0)
                            self.assertFalse(top_level_nodes[0].is_expanded)

                            await pilot.press("space")
                            await pilot.pause()

                            self.assertTrue(top_level_nodes[0].is_expanded)

        asyncio.run(scenario())

    def test_summary_tree_groups_channel_poll_sessions_under_channels_node(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="FETCH"),
                self._summary_row(3, info="FETCH"),
                self._summary_row(4, info="FETCH"),
                self._summary_row(5, info="FETCH"),
                self._summary_row(6, info="FETCH"),
                self._summary_row(7, info="FETCH"),
                self._summary_row(8, info="FETCH"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-client-remote://8.8.8.8:53",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="CH1 SEND 33B | DNS Query: id=0x1234 qname=eim.sm.1ot.com type=A class=IN",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                ),
                3: StatefulFrameAnnotation(
                    frame_number=3,
                    summary_suffix="STK CLOSE CHANNEL | CH1 CLOSE",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                4: StatefulFrameAnnotation(
                    frame_number=4,
                    summary_suffix="CH1 CLOSED",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                5: StatefulFrameAnnotation(
                    frame_number=5,
                    summary_suffix="STK OPEN CHANNEL | CH2 OPEN tcp-client-remote://1.2.3.4:443",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=2,
                    state_event=True,
                ),
                6: StatefulFrameAnnotation(
                    frame_number=6,
                    summary_suffix="CH2 SEND 87B | TLS Handshake: ClientHello sni=tls.eim.1ot.com (67 byte(s))",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=2,
                ),
                7: StatefulFrameAnnotation(
                    frame_number=7,
                    summary_suffix="STK CLOSE CHANNEL | CH2 CLOSE",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=2,
                    state_event=True,
                ),
                8: StatefulFrameAnnotation(
                    frame_number=8,
                    summary_suffix="CH2 CLOSED",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=2,
                    state_event=True,
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_level_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]
                        self.assertFalse(
                            any(
                                label.startswith("Channels ") or label.startswith("Channel 1")
                                for label in top_level_labels
                            ),
                            msg="Channels wrapper / Channel N layer should not appear at top level",
                        )
                        self.assertTrue(
                            any(
                                label.startswith("Poll 1")
                                for label in top_level_labels
                            ),
                            msg="Poll 1 must be a top-level sibling of STK/ETSI FS/Timer groups",
                        )

                        poll_node = next(
                            node
                            for node in summary_tree.root.children
                            if "Poll 1" in getattr(node.label, "plain", str(node.label))
                        )
                        poll_child_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in poll_node.children
                        ]
                        self.assertTrue(
                            any(
                                label.startswith("DNS ")
                                for label in poll_child_labels
                            )
                        )
                        self.assertTrue(
                            any(
                                label.startswith("eIM ")
                                for label in poll_child_labels
                            )
                        )
                        dns_node = next(
                            node
                            for node in poll_node.children
                            if getattr(node.label, "plain", str(node.label)).startswith("DNS ")
                        )
                        fqdn_node = next(
                            node
                            for node in poll_node.children
                            if getattr(node.label, "plain", str(node.label)).startswith("eIM ")
                        )
                        dns_frame_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in dns_node.children
                        ]
                        fqdn_frame_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in fqdn_node.children
                        ]
                        self.assertEqual(len(dns_frame_labels), 4)
                        self.assertEqual(len(fqdn_frame_labels), 4)
                        self.assertTrue(
                            any(
                                "STK OPEN CHANNEL | OPEN udp-client-remote://8.8.8.8:53" in label
                                for label in dns_frame_labels
                            )
                        )
                        self.assertTrue(
                            any(
                                "SEND 33B | DNS Query: id=0x1234 qname=eim.sm.1ot.com" in label
                                for label in dns_frame_labels
                            )
                        )
                        self.assertTrue(
                            any(
                                "SEND 87B | TLS Handshake: ClientHello sni=tls.eim.1ot.com" in label
                                for label in fqdn_frame_labels
                            )
                        )
                        self.assertTrue(
                            any(
                                "STK CLOSE CHANNEL | CLOSE" in label
                                for label in fqdn_frame_labels
                            )
                        )

        asyncio.run(scenario())

    def test_summary_tree_nests_open_close_session_under_inferred_dns_lookup_context(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="ENVELOPE"),
                self._summary_row(3, info="FETCH"),
                self._summary_row(4, info="TERMINAL RESPONSE"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp-client-remote://1.2.3.4:443",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="CH1 DATA AVAILABLE 12B",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                3: StatefulFrameAnnotation(
                    frame_number=3,
                    summary_suffix="STK CLOSE CHANNEL | CH1 CLOSE",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                4: StatefulFrameAnnotation(
                    frame_number=4,
                    summary_suffix="CH1 CLOSED",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        poll_node = next(
                            node
                            for node in summary_tree.root.children
                            if "Poll 1" in getattr(node.label, "plain", str(node.label))
                        )
                        # The test endpoint is tcp://1.2.3.4:443, which is
                        # classified as an eIM leg (port 443 / TCP) rather
                        # than a DNS lookup. The orphan eIM still gets a
                        # standalone poll; we simply look up the session by
                        # its eIM label instead of a DNS one.
                        session_node = next(
                            node
                            for node in poll_node.children
                            if getattr(node.label, "plain", str(node.label)).startswith("eIM ")
                        )
                        session_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in session_node.children
                        ]

                        self.assertEqual(len(session_labels), 4)
                        self.assertIn("STK OPEN CHANNEL | OPEN tcp-client-remote://1.2.3.4:443", session_labels[0])
                        self.assertIn("DATA AVAILABLE 12B", session_labels[1])
                        self.assertIn("STK CLOSE CHANNEL | CLOSE", session_labels[2])
                        self.assertIn("CLOSED", session_labels[3])

        asyncio.run(scenario())

    def test_summary_tree_reclassifies_stk_bip_and_euicc_out_of_other_apdu(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="STATUS"),
                self._summary_row(2, info="ENVELOPE"),
                self._summary_row(3, info="GetEuiccChallenge"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="FETCH PENDING 21B",
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="DATA AVAILABLE 127B",
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_level_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]

                        self.assertIn("STK (1)", top_level_labels)
                        # The ENVELOPE Data Available row used to land in a
                        # "Channels (1)" wrapper. After the Poll-first
                        # restructure, the envelope is either nested under a
                        # Poll node (when enclosed by an OPEN/CLOSE range) or
                        # rendered as a channel frame at the tail. Either way
                        # the legacy "Channels (n)" group node must not exist.
                        self.assertFalse(
                            any(
                                label.startswith("Channels ")
                                for label in top_level_labels
                            ),
                            msg="Channels wrapper must not reappear at top level",
                        )
                        self.assertIn("eUICC (1)", top_level_labels)
                        self.assertNotIn("Other APDU (3)", top_level_labels)

        asyncio.run(scenario())

    def test_cycle_summary_view_switches_to_flat_chronological_packet_list(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="READ BINARY"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="STK OPEN CHANNEL",
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="FS MF/EF.ICCID READ BINARY 10B @0",
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        context_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]
                        self.assertIn("STK (1)", context_labels)
                        self.assertEqual(app._selected_frame_number, 2)

                        app.action_cycle_summary_view()
                        await pilot.pause()
                        # Cycle now toggles only context <-> flat; a single
                        # F4 press from the default context mode reaches the
                        # flat chronological list.

                        flat_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]
                        self.assertEqual(app._summary_view_mode, "flat")
                        self.assertEqual(len(flat_labels), 2)
                        self.assertTrue(any("FETCH" in label for label in flat_labels))
                        self.assertTrue(any("READ BINARY" in label for label in flat_labels))
                        self.assertFalse(any("STK OPEN CHANNEL" in label for label in flat_labels))
                        self.assertIn("View Flat packet list", app._build_status_text())
                        self.assertEqual(app._selected_frame_number, 2)
                        self.assertIn(2, app._summary_tree_frame_nodes)

        asyncio.run(scenario())

    def test_build_status_text_formats_live_timer_countdown_as_clock(self) -> None:
        from Tools.HilBridge.live_decode_state import ActiveTimerSnapshot, StatefulFrameAnnotation

        app = self._build_app()
        sample_row = self._summary_row(1, info="TIMER MANAGEMENT")
        app._base_rows = [sample_row]
        app._rows = [sample_row]
        app._selected_frame_number = 1
        app._state_annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                active_timer_count=1,
                active_timers=(
                    ActiveTimerSnapshot(
                        timer_id=1,
                        configured_seconds=70,
                        remaining_seconds=70,
                    ),
                ),
                capture_time_seconds=1.0,
            ),
        }
        app._latest_capture_time_seconds = 1.0
        app._latest_capture_monotonic = 100.0

        with mock.patch("Tools.HilBridge.live_decode_tui.time.monotonic", return_value=101.2):
            status_text = app._build_status_text()

        self.assertIn("Countdown T1 00:01:09", status_text)

    def test_jump_next_state_event_selects_next_annotated_frame(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        app = self._build_app()
        app._rows = [
            self._summary_row(1),
            self._summary_row(2),
            self._summary_row(3),
            self._summary_row(4),
        ]
        app._state_annotations = {
            2: StatefulFrameAnnotation(frame_number=2, summary_suffix="STK OPEN CHANNEL"),
            4: StatefulFrameAnnotation(frame_number=4, summary_suffix="T1 EXPIRED"),
        }
        app._interesting_frame_numbers = [2, 4]
        app._selected_frame_number = 1
        captured_messages: list[str | None] = []

        def capture_status(message: str | None = None, **_kwargs) -> None:
            captured_messages.append(message)

        with mock.patch.object(app, "_sync_summary_selection") as sync_selection:
            with mock.patch.object(app, "_schedule_detail_refresh") as detail_refresh:
                with mock.patch.object(app, "_refresh_captions") as refresh_captions:
                    with mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
                        app.action_jump_next_state_event()

        self.assertEqual(app._selected_frame_number, 2)
        self.assertFalse(app._follow_tail)
        sync_selection.assert_called_once_with(scroll=True)
        detail_refresh.assert_called_once()
        refresh_captions.assert_called_once()
        self.assertIn("state frame #2", str(captured_messages[-1]))
        self.assertIn("STK OPEN CHANNEL", str(captured_messages[-1]))

    def test_jump_prev_state_event_wraps_to_last_annotated_frame(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        app = self._build_app()
        app._rows = [
            self._summary_row(1),
            self._summary_row(2),
            self._summary_row(3),
            self._summary_row(4),
        ]
        app._state_annotations = {
            2: StatefulFrameAnnotation(frame_number=2, summary_suffix="STK OPEN CHANNEL"),
            4: StatefulFrameAnnotation(frame_number=4, summary_suffix="T1 EXPIRED"),
        }
        app._interesting_frame_numbers = [2, 4]
        app._selected_frame_number = 2
        captured_messages: list[str | None] = []

        def capture_status(message: str | None = None, **_kwargs) -> None:
            captured_messages.append(message)

        with mock.patch.object(app, "_sync_summary_selection") as sync_selection:
            with mock.patch.object(app, "_schedule_detail_refresh") as detail_refresh:
                with mock.patch.object(app, "_refresh_captions") as refresh_captions:
                    with mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
                        app.action_jump_prev_state_event()

        self.assertEqual(app._selected_frame_number, 4)
        self.assertTrue(app._follow_tail)
        sync_selection.assert_called_once_with(scroll=True)
        detail_refresh.assert_called_once()
        refresh_captions.assert_called_once()
        self.assertIn("Wrapped to state frame #4", str(captured_messages[-1]))
        self.assertIn("T1 EXPIRED", str(captured_messages[-1]))

    def test_run_live_decode_tui_preserves_existing_colorterm(self) -> None:
        from textual.app import App
        from Tools.HilBridge.live_decode_tui import run_live_decode_tui

        captured: dict[str, str | None] = {}
        original_run = App.run

        def fake_run(app_self: App, *args: object, **kwargs: object) -> None:
            del app_self
            del args
            del kwargs
            captured["TERM"] = os.environ.get("TERM")
            captured["COLORTERM"] = os.environ.get("COLORTERM")

        App.run = fake_run
        try:
            with mock.patch.dict(
                os.environ,
                {"TERM": "xterm-256color", "COLORTERM": "24bit"},
                clear=False,
            ):
                run_live_decode_tui(
                    "/tmp/live_capture.pcap",
                    service_name="demo.service",
                    capture_filter="udp port 4729",
                    startup_state={"activation_complete": True},
                    tshark_binary="/usr/bin/tshark",
                )
                self.assertEqual(captured["TERM"], "xterm-256color")
                self.assertEqual(captured["COLORTERM"], "24bit")
                self.assertEqual(os.environ.get("TERM"), "xterm-256color")
                self.assertEqual(os.environ.get("COLORTERM"), "24bit")
        finally:
            App.run = original_run

    def test_schedule_summary_refresh_recovers_when_read_fails(self) -> None:
        app = self._build_app()

        with mock.patch("Tools.HilBridge.live_decode_tui.read_packet_summaries", side_effect=RuntimeError("boom")):
            with mock.patch.object(app, "_refresh_status_line"):
                app._schedule_summary_refresh()

        self.assertFalse(app._refresh_inflight)
        self.assertIn("Summary refresh failed", app._last_error)

    def test_schedule_summary_refresh_recovers_when_apply_fails(self) -> None:
        app = self._build_app()

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.read_packet_summaries",
            return_value=(
                [
                    PacketSummary(
                        number=1,
                        time_text="0.000000",
                        source="127.0.0.1",
                        destination="127.0.0.1",
                        protocol="GSM SIM",
                        length_text="80",
                        info="SELECT",
                    )
                ],
                "",
            ),
        ):
            with mock.patch.object(app, "_apply_summary_refresh", side_effect=RuntimeError("ui boom")):
                with mock.patch.object(app, "_refresh_status_line"):
                    app._schedule_summary_refresh()

        self.assertFalse(app._refresh_inflight)
        self.assertIn("Summary UI refresh failed", app._last_error)

    def test_summary_refresh_ignores_transient_first_packet_highlight_during_rebuild(self) -> None:
        app = self._build_app()
        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(7, info="READ BINARY"),
            self._summary_row(8, info="STATUS"),
        ]
        app._selected_frame_number = 7
        app._follow_tail = False

        transient_highlight = SimpleNamespace(
            control=SimpleNamespace(id="summary_tree"),
            node=SimpleNamespace(data={"kind": "frame", "frame_number": 1}),
        )

        def fake_populate_summary_tree(*_args: object, **_kwargs: object) -> dict[int, object]:
            app.on_tree_node_highlighted(transient_highlight)
            return {}

        # Detached app has no screen stack, so any DOM walk raises. Provide
        # a stand-in Tree-like widget and bypass the scroll-position capture
        # path so the test can focus on the transient-highlight suppression.
        fake_tree = SimpleNamespace(root=SimpleNamespace(), show_root=False)

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
            return_value={},
        ):
            with mock.patch(
                "Tools.HilBridge.live_decode_tui._populate_summary_tree",
                side_effect=fake_populate_summary_tree,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui._capture_summary_tree_scroll_offset",
                    return_value=None,
                ):
                    with mock.patch(
                        "Tools.HilBridge.live_decode_tui._summary_tree_batch_update_context",
                    ) as batch_cm:
                        batch_cm.return_value.__enter__ = lambda *_: None
                        batch_cm.return_value.__exit__ = lambda *_: None
                        with mock.patch.object(app, "_summary_widget", return_value=fake_tree):
                            with mock.patch.object(app, "_scroll_summary_tree_to_tail"):
                                with mock.patch.object(app, "_sync_summary_selection") as sync_selection:
                                    with mock.patch.object(app, "_schedule_detail_refresh"):
                                        with mock.patch.object(app, "_refresh_captions"):
                                            with mock.patch.object(app, "_refresh_status_line"):
                                                app._apply_summary_refresh(rows, "")

        self.assertEqual(app._selected_frame_number, 7)
        self.assertFalse(app._follow_tail)
        # Frame-7 remains the selection target, so at least one scroll=False
        # sync fires; the exact call count depends on the internal rebuild
        # pipeline and is not the property under test.
        self.assertTrue(sync_selection.called)

    def test_summary_tree_highlight_uses_leaf_frame_data(self) -> None:
        app = self._build_app()
        app._rows = [
            PacketSummary(
                number=7,
                time_text="0.000000",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info="FETCH",
            )
        ]
        event = mock.Mock()
        event.control = mock.Mock()
        event.control.id = "summary_tree"
        event.node = mock.Mock()
        event.node.data = {"kind": "frame", "frame_number": 7}
        # The highlight handler guards against stale events by comparing
        # event.node to tree_widget.cursor_node; aligning them keeps the
        # unit test focused on the leaf-data projection.
        event.control.cursor_node = event.node

        with mock.patch.object(app, "_schedule_detail_refresh"):
            with mock.patch.object(app, "_refresh_captions"):
                with mock.patch.object(app, "_refresh_status_line"):
                    app.on_tree_node_highlighted(event)

        self.assertEqual(app._selected_frame_number, 7)
        self.assertTrue(app._follow_tail)

    def test_resolve_live_stream_fifo_path_defaults_to_sibling_fifo(self) -> None:
        app = self._build_app(capture_path="/tmp/hil/live_capture.pcap")
        self.assertEqual(
            app._resolve_live_stream_fifo_path(),
            "/tmp/hil/live_capture.fifo",
        )

    def test_resolve_live_stream_fifo_path_honours_explicit_override(self) -> None:
        from textual.app import App

        from Tools.HilBridge.live_decode_tui import (
            default_tui_layout_preferences,
            run_live_decode_tui,
        )

        captured: dict[str, App] = {}
        original_run = App.run

        def fake_run(app_self: App, *args: object, **kwargs: object) -> None:
            del args
            del kwargs
            captured["app"] = app_self

        App.run = fake_run
        try:
            with mock.patch(
                "Tools.HilBridge.live_decode_tui.load_tui_layout_preferences",
                return_value=default_tui_layout_preferences(),
            ):
                run_live_decode_tui(
                    "/tmp/hil/live_capture.pcap",
                    service_name="demo.service",
                    capture_filter="udp port 4729",
                    startup_state={"activation_complete": True},
                    tshark_binary="/usr/bin/tshark",
                    mirror_fifo_path="/tmp/alt/custom.fifo",
                )
        finally:
            App.run = original_run

        app = captured["app"]
        self.assertEqual(
            app._resolve_live_stream_fifo_path(),
            "/tmp/alt/custom.fifo",
        )

    def test_offline_review_mode_skips_live_stream(self) -> None:
        # Offline review must never synthesise a sidecar FIFO or start a
        # `tshark -i` subprocess. _ensure_live_stream_started should fall
        # through to the disabled branch on the very first tick, and the
        # status-line suffix should switch to the compact offline label
        # instead of the "live: off (reason)" text.
        from textual.app import App

        from Tools.HilBridge.live_decode_tui import (
            default_tui_layout_preferences,
            run_live_decode_tui,
        )

        captured: dict[str, App] = {}
        original_run = App.run

        def fake_run(app_self: App, *args: object, **kwargs: object) -> None:
            del args
            del kwargs
            captured["app"] = app_self

        App.run = fake_run
        try:
            with mock.patch(
                "Tools.HilBridge.live_decode_tui.load_tui_layout_preferences",
                return_value=default_tui_layout_preferences(),
            ):
                run_live_decode_tui(
                    "/tmp/hil/old_session.pcap",
                    service_name="offline-review",
                    capture_filter="udp port 4729",
                    startup_state={"activation_complete": True},
                    tshark_binary="/usr/bin/tshark",
                    live_capture=False,
                    keybag_path="/tmp/hil/old_session.keys.json",
                )
        finally:
            App.run = original_run

        app = captured["app"]
        self.assertFalse(app._live_capture_mode)
        self.assertTrue(app._live_stream_disabled)
        self.assertEqual(
            app._keybag_path,
            "/tmp/hil/old_session.keys.json",
        )
        self.assertEqual(app._resolve_live_stream_fifo_path(), "")
        app._ensure_live_stream_started()
        self.assertIsNone(app._live_stream)
        self.assertFalse(app._live_stream_started)
        self.assertEqual(app._live_stream_status_suffix(), " | offline review")

    def test_seed_live_stream_from_base_rows_primes_keys_and_counter(self) -> None:
        app = self._build_app()

        class _StubStream:
            def is_alive(self) -> bool:
                return True

            def drain(self) -> list:
                return []

        app._live_stream = _StubStream()
        app._base_rows = [
            self._summary_row(1, info="SELECT"),
            self._summary_row(2, info="READ BINARY"),
            self._summary_row(3, info="STATUS"),
        ]
        app._seed_live_stream_from_base_rows()

        self.assertEqual(app._live_next_frame_number, 4)
        self.assertEqual(len(app._live_seen_keys), 3)
        self.assertIn(app._live_row_key(app._base_rows[0]), app._live_seen_keys)

    def test_drain_live_stream_tick_dedups_and_appends_new_rows(self) -> None:
        app = self._build_app()

        original_rows = [
            self._summary_row(1, info="SELECT"),
            self._summary_row(2, info="READ BINARY"),
        ]
        duplicate_of_row_2 = self._summary_row(2, info="READ BINARY")
        brand_new_live_row = PacketSummary(
            number=1,
            time_text="0.500000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="UPDATE BINARY",
            udp_payload_hex="BEEF",
        )

        class _ScriptedStream:
            def __init__(self, rows: list) -> None:
                self._rows = list(rows)
                self.stopped = False

            def is_alive(self) -> bool:
                return self.stopped is False

            def drain(self) -> list:
                rows = list(self._rows)
                self._rows = []
                return rows

            def stop(self, *, timeout: float = 0.0) -> None:
                self.stopped = True

        app._base_rows = list(original_rows)
        app._rows = app._decorate_summary_rows(app._base_rows)
        stream = _ScriptedStream([duplicate_of_row_2, brand_new_live_row])
        app._live_stream = stream
        app._seed_live_stream_from_base_rows()

        with mock.patch.object(app, "_refresh_summary_tree_visual"):
            with mock.patch.object(app, "_refresh_captions"):
                with mock.patch.object(app, "_schedule_detail_refresh"):
                    with mock.patch.object(app, "_refresh_status_line"):
                        app._drain_live_stream_tick()

        self.assertEqual(len(app._base_rows), 3)
        appended_row = app._base_rows[-1]
        self.assertEqual(appended_row.info, "UPDATE BINARY")
        self.assertEqual(appended_row.number, 3)
        self.assertEqual(app._live_next_frame_number, 4)

    def test_live_row_key_is_stable_across_tshark_relative_time_variants(self) -> None:
        app = self._build_app()
        polling_row = PacketSummary(
            number=7,
            time_text="4.321987",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="OPEN CHANNEL",
            wall_time_text="12:34:56.789",
            udp_payload_hex="DEADBEEF",
            epoch_time_text="1713272127.456789000",
        )
        stream_row = PacketSummary(
            number=1,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="OPEN CHANNEL",
            wall_time_text="12:34:56.789",
            udp_payload_hex="DEADBEEF",
            epoch_time_text="1713272127.456789000",
        )

        self.assertEqual(app._live_row_key(polling_row), app._live_row_key(stream_row))

    def test_drain_live_stream_tick_dedups_same_packet_with_different_relative_times(self) -> None:
        app = self._build_app()

        polling_row = PacketSummary(
            number=5,
            time_text="2.500000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="OPEN CHANNEL",
            udp_payload_hex="CAFE",
            epoch_time_text="1713272127.500000000",
        )
        stream_duplicate_row = PacketSummary(
            number=1,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="OPEN CHANNEL",
            udp_payload_hex="CAFE",
            epoch_time_text="1713272127.500000000",
        )

        class _ScriptedStream:
            def __init__(self, rows: list) -> None:
                self._rows = list(rows)

            def is_alive(self) -> bool:
                return True

            def drain(self) -> list:
                rows = list(self._rows)
                self._rows = []
                return rows

            def stop(self, *, timeout: float = 0.0) -> None:
                return None

        app._base_rows = [polling_row]
        app._rows = app._decorate_summary_rows(app._base_rows)
        app._live_stream = _ScriptedStream([stream_duplicate_row])
        app._seed_live_stream_from_base_rows()

        with mock.patch.object(app, "_refresh_summary_tree_visual"):
            with mock.patch.object(app, "_refresh_captions"):
                with mock.patch.object(app, "_schedule_detail_refresh"):
                    with mock.patch.object(app, "_refresh_status_line"):
                        app._drain_live_stream_tick()

        self.assertEqual(len(app._base_rows), 1)
        self.assertEqual(int(app._base_rows[0].number), 5)

    def test_summary_tree_rebuild_is_throttled_between_calls(self) -> None:
        app = self._build_app()
        render_calls: list[bool] = []

        def _record_render(*, scroll: bool) -> None:
            render_calls.append(bool(scroll))

        app._render_summary_tree_now = _record_render  # type: ignore[assignment]
        app._summary_rebuild_throttle_seconds = 0.5

        app._request_summary_tree_rebuild(scroll=False)
        self.assertEqual(len(render_calls), 1)
        self.assertFalse(app._summary_rebuild_pending)

        app._request_summary_tree_rebuild(scroll=True)
        self.assertEqual(len(render_calls), 1)
        self.assertTrue(app._summary_rebuild_pending)
        self.assertTrue(app._summary_rebuild_pending_scroll)

        app._flush_pending_summary_tree_rebuild()
        self.assertEqual(len(render_calls), 1)

        app._last_summary_rebuild_monotonic = app._last_summary_rebuild_monotonic - 1.0
        app._flush_pending_summary_tree_rebuild()
        self.assertEqual(len(render_calls), 2)
        self.assertTrue(render_calls[1])
        self.assertFalse(app._summary_rebuild_pending)

    def test_drain_live_stream_tick_stops_stream_when_not_alive(self) -> None:
        app = self._build_app()

        class _DeadStream:
            def is_alive(self) -> bool:
                return False

            def drain(self) -> list:
                return []

            def stop(self, *, timeout: float = 0.0) -> None:
                self.stopped = True

        dead_stream = _DeadStream()
        app._live_stream = dead_stream
        app._live_stream_started = True

        app._drain_live_stream_tick()

        self.assertIsNone(app._live_stream)
        self.assertFalse(app._live_stream_started)

    def test_action_toggle_ingest_pause_toggles_flag_and_surfaces_status_suffix(self) -> None:
        app = self._build_app()
        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._paused_live_rows, [])
        self.assertEqual(app._ingest_pause_status_suffix(), "")

        with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
            app, "_refresh_captions"
        ):
            app.action_toggle_ingest_pause()

        self.assertTrue(app._ingest_paused)
        self.assertIn("paused", app._ingest_pause_status_suffix())
        self.assertIn("0 queued", app._ingest_pause_status_suffix())

        with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
            app, "_refresh_captions"
        ), mock.patch.object(app, "_schedule_summary_refresh"):
            app.action_toggle_ingest_pause()

        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._ingest_pause_status_suffix(), "")

    def test_drain_live_stream_tick_diverts_rows_into_pause_queue_when_paused(self) -> None:
        app = self._build_app()

        original_rows = [
            self._summary_row(1, info="SELECT"),
            self._summary_row(2, info="READ BINARY"),
        ]

        live_row_a = PacketSummary(
            number=1,
            time_text="0.500000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="UPDATE BINARY",
            udp_payload_hex="AAAA",
        )
        live_row_b = PacketSummary(
            number=1,
            time_text="0.600000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="ENVELOPE",
            udp_payload_hex="BBBB",
        )

        class _ScriptedStream:
            def __init__(self, rows: list) -> None:
                self._rows = list(rows)
                self.stopped = False

            def is_alive(self) -> bool:
                return self.stopped is False

            def drain(self) -> list:
                rows = list(self._rows)
                self._rows = []
                return rows

            def stop(self, *, timeout: float = 0.0) -> None:
                self.stopped = True

        app._base_rows = list(original_rows)
        app._rows = app._decorate_summary_rows(app._base_rows)
        app._live_stream = _ScriptedStream([live_row_a, live_row_b])
        app._seed_live_stream_from_base_rows()
        app._ingest_paused = True

        with mock.patch.object(app, "_apply_live_stream_additions") as apply_mock, mock.patch.object(
            app, "_refresh_status_line"
        ):
            app._drain_live_stream_tick()

        apply_mock.assert_not_called()
        self.assertEqual(len(app._paused_live_rows), 2)
        self.assertEqual(app._paused_live_rows[0].info, "UPDATE BINARY")
        self.assertEqual(app._paused_live_rows[1].info, "ENVELOPE")
        self.assertEqual(len(app._base_rows), 2)
        self.assertEqual(app._live_stream_delivered_count, 0)

    def test_schedule_summary_refresh_short_circuits_when_paused(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._refresh_inflight = False
        app._capture_path = "/tmp/live_capture.pcap"

        with mock.patch(
            "Tools.HilBridge.live_decode_tui._file_size",
            return_value=4096,
        ), mock.patch("threading.Thread") as thread_mock, mock.patch.object(
            app, "_run_summary_refresh_inline"
        ) as inline_mock, mock.patch.object(app, "_refresh_captions"), mock.patch.object(
            app, "_refresh_status_line"
        ):
            app._schedule_summary_refresh()

        thread_mock.assert_not_called()
        inline_mock.assert_not_called()
        self.assertFalse(app._refresh_inflight)

    def test_apply_summary_refresh_discards_worker_results_when_paused(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._refresh_inflight = True
        app._base_rows = []
        app._rows = []

        late_rows = [
            self._summary_row(1, info="SELECT"),
            self._summary_row(2, info="READ BINARY"),
        ]

        with mock.patch.object(
            app, "_merge_polling_rows_with_live_tail"
        ) as merge_mock, mock.patch.object(app, "_refresh_summary_tree_visual"):
            app._apply_summary_refresh(
                late_rows,
                "",
                pre_parse_size=0,
                capture_generation=int(app._capture_generation),
            )

        merge_mock.assert_not_called()
        self.assertEqual(app._base_rows, [])
        self.assertEqual(app._rows, [])
        self.assertFalse(app._refresh_inflight)

    def test_action_toggle_ingest_pause_on_resume_flushes_queue_and_schedules_refresh(self) -> None:
        app = self._build_app()
        queued_row = PacketSummary(
            number=99,
            time_text="1.500000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="STATUS",
            udp_payload_hex="CCCC",
        )
        app._ingest_paused = True
        app._paused_live_rows = [queued_row]
        starting_delivered = int(app._live_stream_delivered_count)

        with mock.patch.object(
            app, "_apply_live_stream_additions"
        ) as apply_mock, mock.patch.object(
            app, "_schedule_summary_refresh"
        ) as schedule_mock, mock.patch.object(
            app, "_refresh_status_line"
        ), mock.patch.object(app, "_refresh_captions"):
            app.action_toggle_ingest_pause()

        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._paused_live_rows, [])
        apply_mock.assert_called_once()
        forwarded_rows = apply_mock.call_args[0][0]
        self.assertEqual(len(forwarded_rows), 1)
        self.assertEqual(forwarded_rows[0].info, "STATUS")
        schedule_mock.assert_called_once()
        self.assertEqual(
            app._live_stream_delivered_count,
            starting_delivered + 1,
        )

    def test_reset_capture_runtime_state_clears_pause_flag_and_queue(self) -> None:
        from Tools.HilBridge.live_decode_tui import _reset_capture_runtime_state

        app = SimpleNamespace(
            _capture_generation=1,
            _last_capture_size=4096,
            _last_error="",
            _latest_capture_time_seconds=None,
            _latest_capture_monotonic=None,
            _base_rows=[],
            _rows=[],
            _state_annotations={},
            _interesting_frame_numbers=[],
            _summary_tree_frame_nodes={},
            _summary_tree_header_nodes={},
            _summary_tree_expanded_groups=set(),
            _selected_frame_number=None,
            _displayed_selected_frame_number=None,
            _highlighted_node_key=None,
            _last_parse_completed_monotonic=None,
            _last_parse_row_count=0,
            _requested_detail_frame=None,
            _detail_cache={},
            _bytes_cache={},
            _displayed_detail_key=None,
            _displayed_bytes_key=None,
            _refresh_inflight=False,
            _detail_inflight=False,
            _follow_tail=False,
            _ingest_paused=True,
            _paused_live_rows=[self._summary_row(1)],
        )

        _reset_capture_runtime_state(app)

        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._paused_live_rows, [])

    def test_keybind_help_text_includes_f2_pause_entry(self) -> None:
        from Tools.HilBridge.live_decode_tui import _hil_decode_keybind_help_text

        help_text = _hil_decode_keybind_help_text()

        self.assertIn("F2          Pause / resume packet ingest", help_text)

    def _poll_row(
        self,
        number: int,
        *,
        info: str = "APDU",
        time_seconds: float | None = None,
    ) -> PacketSummary:
        if time_seconds is None:
            time_seconds = number / 1000.0
        return PacketSummary(
            number=number,
            time_text=f"{time_seconds:.6f}",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info=info,
        )

    def test_poll_view_mode_remains_a_known_view_but_is_not_in_f4_cycle(self) -> None:
        from Tools.HilBridge.live_decode_tui import (
            _SUMMARY_VIEW_CONTEXT,
            _SUMMARY_VIEW_CYCLE,
            _SUMMARY_VIEW_FLAT,
            _SUMMARY_VIEW_ORDER,
            _SUMMARY_VIEW_POLL,
            _normalize_summary_view_mode,
            _summary_view_cycle_hint,
            _summary_view_title,
        )

        self.assertEqual(
            _SUMMARY_VIEW_ORDER,
            (_SUMMARY_VIEW_CONTEXT, _SUMMARY_VIEW_POLL, _SUMMARY_VIEW_FLAT),
        )
        self.assertEqual(
            _SUMMARY_VIEW_CYCLE,
            (_SUMMARY_VIEW_CONTEXT, _SUMMARY_VIEW_FLAT),
        )
        self.assertNotIn(_SUMMARY_VIEW_POLL, _SUMMARY_VIEW_CYCLE)
        self.assertEqual(_normalize_summary_view_mode("poll-cycle"), _SUMMARY_VIEW_POLL)
        self.assertEqual(_normalize_summary_view_mode("polls"), _SUMMARY_VIEW_POLL)
        self.assertEqual(_summary_view_title(_SUMMARY_VIEW_POLL), "Poll cycles")
        self.assertIn("Space toggle poll", _summary_view_cycle_hint(_SUMMARY_VIEW_POLL))

    def test_classify_session_role_uses_port_and_transport_over_ordering(self) -> None:
        from Tools.HilBridge.live_decode_tui import (
            _SESSION_ROLE_DNS,
            _SESSION_ROLE_EIM,
            _SESSION_ROLE_UNKNOWN,
            _classify_session_role,
        )

        self.assertEqual(
            _classify_session_role("8.8.8.8:53", "udp-client-remote"),
            _SESSION_ROLE_DNS,
        )
        self.assertEqual(
            _classify_session_role("194.29.54.4:443", "tcp-client-remote"),
            _SESSION_ROLE_EIM,
        )
        # Port 443 over UDP (QUIC/DTLS-style) still classifies as eIM.
        self.assertEqual(
            _classify_session_role("1.2.3.4:443", "udp-client-remote"),
            _SESSION_ROLE_EIM,
        )
        # Missing port falls back to the transport hint.
        self.assertEqual(
            _classify_session_role("example.test", "tcp-client-remote"),
            _SESSION_ROLE_EIM,
        )
        self.assertEqual(
            _classify_session_role("example.test", "udp-client-remote"),
            _SESSION_ROLE_DNS,
        )
        # No transport, no recognizable port -> unknown.
        self.assertEqual(
            _classify_session_role("example.test", ""),
            _SESSION_ROLE_UNKNOWN,
        )

    def test_summary_partition_poll_labels_use_port_when_eim_arrives_before_dns(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_partition_poll_rows_with_labels,
        )

        # The capture starts mid-poll: the DNS leg's OPEN was missed, so
        # the first session we see is already the TLS/eIM endpoint on
        # :443. The partitioner must still label it "eIM - ..." and the
        # later DNS leg on :53 must read "DNS - ..." rather than flipping
        # the labels based on arrival order.
        eim_rows = [self._summary_row(10)]
        dns_rows = [self._summary_row(20)]
        annotations = {
            10: StatefulFrameAnnotation(
                frame_number=10,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH1 OPEN "
                    "tcp-client-remote://194.29.54.4:443 APN:Terminal.apn"
                ),
            ),
            20: StatefulFrameAnnotation(
                frame_number=20,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH2 OPEN "
                    "udp-client-remote://8.8.8.8:53 APN:Terminal.apn"
                ),
            ),
        }

        polls = _summary_partition_poll_rows_with_labels(
            [(1, eim_rows), (2, dns_rows)],
            annotations,
        )

        self.assertEqual(len(polls), 2)
        poll_1_index, poll_1_sessions = polls[0]
        poll_2_index, poll_2_sessions = polls[1]
        self.assertEqual(poll_1_index, 1)
        self.assertEqual(poll_2_index, 2)
        self.assertEqual(len(poll_1_sessions), 1)
        self.assertEqual(len(poll_2_sessions), 1)
        self.assertTrue(
            poll_1_sessions[0][1].startswith("eIM - 194.29.54.4:443"),
            msg=f"Unexpected first-poll label: {poll_1_sessions[0][1]!r}",
        )
        self.assertTrue(
            poll_2_sessions[0][1].startswith("DNS - 8.8.8.8:53"),
            msg=f"Unexpected second-poll label: {poll_2_sessions[0][1]!r}",
        )

    def test_summary_partition_pairs_dns_and_eim_into_same_poll(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import (
            _summary_partition_poll_rows_with_labels,
        )

        dns_rows = [self._summary_row(1)]
        eim_rows = [self._summary_row(2)]
        dns_rows_2 = [self._summary_row(3)]
        eim_rows_2 = [self._summary_row(4)]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH1 OPEN "
                    "udp-client-remote://8.8.8.8:53 APN:Terminal.apn"
                ),
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH2 OPEN "
                    "tcp-client-remote://1.2.3.4:443 APN:Terminal.apn"
                ),
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH1 OPEN "
                    "udp-client-remote://8.8.8.8:53 APN:Terminal.apn"
                ),
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                summary_suffix=(
                    "STK OPEN CHANNEL | CH2 OPEN "
                    "tcp-client-remote://5.6.7.8:443 APN:Terminal.apn"
                ),
            ),
        }

        polls = _summary_partition_poll_rows_with_labels(
            [(1, dns_rows), (2, eim_rows), (3, dns_rows_2), (4, eim_rows_2)],
            annotations,
        )

        self.assertEqual([index for index, _sessions in polls], [1, 2])
        self.assertEqual(len(polls[0][1]), 2)
        self.assertEqual(len(polls[1][1]), 2)
        self.assertTrue(polls[0][1][0][1].startswith("DNS - 8.8.8.8:53"))
        self.assertTrue(polls[0][1][1][1].startswith("eIM - 1.2.3.4:443"))
        self.assertTrue(polls[1][1][0][1].startswith("DNS - 8.8.8.8:53"))
        self.assertTrue(polls[1][1][1][1].startswith("eIM - 5.6.7.8:443"))

    def test_summary_partition_rows_by_card_session_groups_in_capture_order(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_partition_rows_by_card_session

        rows = [
            self._summary_row(1, info="FETCH"),
            self._summary_row(2, info="TERMINAL RESPONSE"),
            self._summary_row(3, info="SELECT"),
            self._summary_row(4, info="SELECT"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(
                frame_number=1,
                card_session_index=1,
                card_session_iccid="8946000000000000001",
            ),
            2: StatefulFrameAnnotation(
                frame_number=2,
                card_session_index=1,
                card_session_iccid="8946000000000000001",
            ),
            3: StatefulFrameAnnotation(
                frame_number=3,
                card_session_index=2,
                card_session_reset_reason="REFRESH UICC Reset",
                card_session_iccid="8946000000000000002",
            ),
            4: StatefulFrameAnnotation(
                frame_number=4,
                card_session_index=2,
                card_session_iccid="8946000000000000002",
            ),
        }

        session_rows, reasons, iccids = _summary_partition_rows_by_card_session(
            rows, annotations
        )

        self.assertEqual([entry[0] for entry in session_rows], [1, 2])
        self.assertEqual([row.number for row in session_rows[0][1]], [1, 2])
        self.assertEqual([row.number for row in session_rows[1][1]], [3, 4])
        self.assertEqual(reasons.get(2), "REFRESH UICC Reset")
        self.assertNotIn(1, reasons)
        self.assertEqual(iccids.get(1), "8946000000000000001")
        self.assertEqual(iccids.get(2), "8946000000000000002")

    def test_summary_card_session_title_includes_iccid_and_reset_reason_when_present(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_card_session_title

        self.assertEqual(
            _summary_card_session_title(1, "", ""),
            "Card Session 1",
        )
        self.assertEqual(
            _summary_card_session_title(2, "idle 42s", ""),
            "Card Session 2 - idle 42s",
        )
        self.assertEqual(
            _summary_card_session_title(3, "", "8946000000000000003"),
            "Card Session 3 - [8946000000000000003]",
        )
        self.assertEqual(
            _summary_card_session_title(
                4, "REFRESH UICC Reset", "8946000000000000004"
            ),
            "Card Session 4 - [8946000000000000004] - REFRESH UICC Reset",
        )

    def test_summary_tree_renders_card_session_wrappers_when_reset_detected(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="TERMINAL RESPONSE"),
                self._summary_row(3, info="FETCH"),
                self._summary_row(4, info="TERMINAL RESPONSE"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-remote://8.8.8.8:53",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=1,
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="CH1 OPEN OK",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=1,
                ),
                3: StatefulFrameAnnotation(
                    frame_number=3,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-remote://8.8.8.8:53",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=2,
                    card_session_reset_reason="REFRESH UICC Reset",
                    card_session_iccid="8946000000000000002",
                ),
                4: StatefulFrameAnnotation(
                    frame_number=4,
                    summary_suffix="CH1 OPEN OK",
                    channel_session_id=2,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=2,
                    card_session_iccid="8946000000000000002",
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]

                        self.assertTrue(
                            any(label.startswith("Card Session 1") for label in top_labels),
                            msg=f"Expected a 'Card Session 1' wrapper, got {top_labels!r}",
                        )
                        self.assertTrue(
                            any(
                                label.startswith("Card Session 2")
                                and "REFRESH UICC Reset" in label
                                and "[8946000000000000002]" in label
                                for label in top_labels
                            ),
                            msg=f"Expected a 'Card Session 2' wrapper tagged with ICCID and REFRESH reason, got {top_labels!r}",
                        )

                        session_2_node = next(
                            node
                            for node in summary_tree.root.children
                            if getattr(node.label, "plain", str(node.label)).startswith(
                                "Card Session 2"
                            )
                        )
                        session_2_poll_labels = [
                            getattr(child.label, "plain", str(child.label))
                            for child in session_2_node.children
                        ]
                        self.assertTrue(
                            any(
                                label.startswith("Poll 1")
                                for label in session_2_poll_labels
                            ),
                            msg=f"Expected Poll 1 inside Card Session 2, got {session_2_poll_labels!r}",
                        )

        asyncio.run(scenario())

    def test_summary_tree_skips_card_session_wrapper_when_only_one_session(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="TERMINAL RESPONSE"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN udp-remote://8.8.8.8:53",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=1,
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="CH1 OPEN OK",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                    card_session_index=1,
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]

                        self.assertFalse(
                            any(label.startswith("Card Session") for label in top_labels),
                            msg=f"Expected no 'Card Session' wrappers for a single-session trace, got {top_labels!r}",
                        )
                        self.assertTrue(
                            any(label.startswith("Poll 1") for label in top_labels),
                            msg=f"Expected Poll 1 at the top level when no reset has occurred, got {top_labels!r}",
                        )

        asyncio.run(scenario())

    def test_suppress_tree_scroll_side_effects_replaces_and_restores_scroll_hooks(self) -> None:
        from Tools.HilBridge.live_decode_tui import _suppress_tree_scroll_side_effects

        call_log: list[str] = []

        def region_hook(*_args, **_kwargs):
            call_log.append("region")
            return "real-region"

        def line_hook(*_args, **_kwargs):
            call_log.append("line")
            return "real-line"

        def node_hook(*_args, **_kwargs):
            call_log.append("node")
            return "real-node"

        tree_widget = SimpleNamespace(
            scroll_to_region=region_hook,
            scroll_to_line=line_hook,
            scroll_to_node=node_hook,
        )

        with _suppress_tree_scroll_side_effects(tree_widget):
            self.assertIsNot(tree_widget.scroll_to_region, region_hook)
            self.assertIsNot(tree_widget.scroll_to_line, line_hook)
            self.assertIsNot(tree_widget.scroll_to_node, node_hook)
            # The replacements must return benign values without calling
            # the original scroll machinery, otherwise Textual would
            # queue a deferred jump that defeats the flutter mitigation.
            self.assertIsNone(tree_widget.scroll_to_line(0))
            self.assertIsNone(tree_widget.scroll_to_node(object()))
            tree_widget.scroll_to_region(object())
            self.assertEqual(call_log, [])

        self.assertIs(tree_widget.scroll_to_region, region_hook)
        self.assertIs(tree_widget.scroll_to_line, line_hook)
        self.assertIs(tree_widget.scroll_to_node, node_hook)

    def test_move_summary_selection_cursor_suppresses_scroll_when_should_scroll_false(self) -> None:
        from Tools.HilBridge.live_decode_tui import _move_summary_selection_cursor

        invoked: list[str] = []

        def move_cursor(_node, **_kwargs) -> None:
            invoked.append("move_cursor")

        def scroll_to_node(_node, **_kwargs) -> None:
            invoked.append("scroll_to_node")

        def scroll_to_region(*_args, **_kwargs) -> None:
            invoked.append("scroll_to_region")
            return None

        def scroll_to_line(*_args, **_kwargs) -> None:
            invoked.append("scroll_to_line")
            return None

        target_node = SimpleNamespace(
            parent=None,
            data={"kind": "frame", "frame_number": 1, "expand_key": "POLL::1"},
        )
        tree_widget = SimpleNamespace(
            move_cursor=move_cursor,
            scroll_to_node=scroll_to_node,
            scroll_to_region=scroll_to_region,
            scroll_to_line=scroll_to_line,
            scroll_offset=SimpleNamespace(x=0.0, y=0.0),
        )

        result = _move_summary_selection_cursor(
            tree_widget,
            frame_nodes={1: target_node},
            selected_frame_number=1,
            expanded_group_names={"POLL::1"},
            should_scroll=False,
        )

        self.assertTrue(result)
        self.assertIn("move_cursor", invoked)
        self.assertNotIn("scroll_to_node", invoked)
        self.assertNotIn("scroll_to_region", invoked)
        self.assertNotIn("scroll_to_line", invoked)

    def test_summary_highlighted_node_key_returns_expand_key_for_header_nodes(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_highlighted_node_key

        poll_header = SimpleNamespace(
            data={"kind": "poll", "expand_key": "CARDSESSION::1/POLL::2"},
        )
        card_session_header = SimpleNamespace(
            data={"kind": "card_session", "expand_key": "CARDSESSION::3"},
        )
        group_header = SimpleNamespace(
            data={"kind": "group", "group_name": "STK"},
        )
        tree = SimpleNamespace(cursor_node=poll_header)
        self.assertEqual(
            _summary_highlighted_node_key(tree, poll_header),
            "CARDSESSION::1/POLL::2",
        )
        tree.cursor_node = card_session_header
        self.assertEqual(
            _summary_highlighted_node_key(tree, card_session_header),
            "CARDSESSION::3",
        )
        tree.cursor_node = group_header
        self.assertEqual(
            _summary_highlighted_node_key(tree, group_header),
            "STK",
        )

    def test_summary_highlighted_node_key_returns_none_for_frame_leaves_and_stale_nodes(self) -> None:
        from Tools.HilBridge.live_decode_tui import _summary_highlighted_node_key

        frame_leaf = SimpleNamespace(
            data={"kind": "frame", "frame_number": 7, "expand_key": "POLL::1"},
        )
        header_node = SimpleNamespace(
            data={"kind": "poll", "expand_key": "POLL::1"},
        )
        stale_header = SimpleNamespace(
            data={"kind": "poll", "expand_key": "POLL::2"},
        )
        tree = SimpleNamespace(cursor_node=frame_leaf)
        self.assertIsNone(_summary_highlighted_node_key(tree, frame_leaf))
        tree.cursor_node = header_node
        self.assertIsNone(_summary_highlighted_node_key(tree, stale_header))
        self.assertEqual(
            _summary_highlighted_node_key(tree, header_node),
            "POLL::1",
        )

    def test_collect_summary_tree_header_nodes_indexes_every_non_frame_node(self) -> None:
        from Tools.HilBridge.live_decode_tui import _collect_summary_tree_header_nodes

        class FakeNode:
            def __init__(self, label: str, *, data=None) -> None:
                self.label = label
                self.data = data
                self.children: list[FakeNode] = []

        root = FakeNode("root")
        card_session = FakeNode(
            "Card Session 1",
            data={"kind": "card_session", "expand_key": "CARDSESSION::1"},
        )
        root.children.append(card_session)
        poll = FakeNode(
            "Poll 1",
            data={"kind": "poll", "expand_key": "CARDSESSION::1/POLL::1"},
        )
        card_session.children.append(poll)
        session = FakeNode(
            "DNS",
            data={"kind": "session", "expand_key": "CARDSESSION::1/SESSION::2"},
        )
        poll.children.append(session)
        frame = FakeNode(
            "#12",
            data={"kind": "frame", "frame_number": 12, "expand_key": "CARDSESSION::1/SESSION::2"},
        )
        session.children.append(frame)
        stk_group = FakeNode(
            "STK",
            data={"kind": "group", "group_name": "STK"},
        )
        root.children.append(stk_group)

        tree = SimpleNamespace(root=root)
        header_nodes = _collect_summary_tree_header_nodes(tree)

        self.assertIs(header_nodes.get("CARDSESSION::1"), card_session)
        self.assertIs(header_nodes.get("CARDSESSION::1/POLL::1"), poll)
        self.assertIs(header_nodes.get("CARDSESSION::1/SESSION::2"), session)
        self.assertIs(header_nodes.get("STK"), stk_group)
        self.assertNotIn("12", header_nodes)
        self.assertNotIn(12, header_nodes)

    def test_move_summary_cursor_to_node_key_targets_header_and_suppresses_scroll(self) -> None:
        from Tools.HilBridge.live_decode_tui import _move_summary_cursor_to_node_key

        invoked: list[str] = []

        def move_cursor(_node, **_kwargs) -> None:
            invoked.append("move_cursor")

        def scroll_to_node(_node, **_kwargs) -> None:
            invoked.append("scroll_to_node")

        def scroll_to_region(*_args, **_kwargs) -> None:
            invoked.append("scroll_to_region")
            return None

        def scroll_to_line(*_args, **_kwargs) -> None:
            invoked.append("scroll_to_line")
            return None

        header_node = SimpleNamespace(
            data={"kind": "poll", "expand_key": "CARDSESSION::1/POLL::2"},
        )
        tree_widget = SimpleNamespace(
            move_cursor=move_cursor,
            scroll_to_node=scroll_to_node,
            scroll_to_region=scroll_to_region,
            scroll_to_line=scroll_to_line,
        )

        moved = _move_summary_cursor_to_node_key(
            tree_widget,
            {"CARDSESSION::1/POLL::2": header_node},
            "CARDSESSION::1/POLL::2",
            should_scroll=False,
        )

        self.assertTrue(moved)
        self.assertIn("move_cursor", invoked)
        self.assertNotIn("scroll_to_node", invoked)
        self.assertNotIn("scroll_to_region", invoked)
        self.assertNotIn("scroll_to_line", invoked)

    def test_move_summary_cursor_to_node_key_returns_false_when_key_missing_or_none(self) -> None:
        from Tools.HilBridge.live_decode_tui import _move_summary_cursor_to_node_key

        def move_cursor(_node, **_kwargs) -> None:
            raise AssertionError("move_cursor must not be called when key is unresolved")

        tree_widget = SimpleNamespace(move_cursor=move_cursor)
        header_nodes = {"CARDSESSION::1/POLL::1": object()}

        self.assertFalse(
            _move_summary_cursor_to_node_key(tree_widget, header_nodes, None),
        )
        self.assertFalse(
            _move_summary_cursor_to_node_key(tree_widget, header_nodes, ""),
        )
        self.assertFalse(
            _move_summary_cursor_to_node_key(
                tree_widget,
                header_nodes,
                "CARDSESSION::99/POLL::7",
            ),
        )

    def test_on_tree_node_highlighted_records_header_key_without_touching_selected_frame(self) -> None:
        app = self._build_app()
        app._selected_frame_number = 42
        app._highlighted_node_key = None
        app._summary_tree_sync_inflight = False
        app._rows = [self._summary_row(42)]

        header_node = SimpleNamespace(
            data={"kind": "poll", "expand_key": "CARDSESSION::1/POLL::2"},
        )
        tree_widget = SimpleNamespace(id="summary_tree", cursor_node=header_node)
        event = SimpleNamespace(control=tree_widget, node=header_node)

        with mock.patch.object(app, "_refresh_captions"), mock.patch.object(
            app, "_refresh_status_line"
        ), mock.patch.object(app, "_schedule_detail_refresh") as scheduled_detail:
            app.on_tree_node_highlighted(event)

        self.assertEqual(app._highlighted_node_key, "CARDSESSION::1/POLL::2")
        self.assertEqual(app._selected_frame_number, 42)
        scheduled_detail.assert_not_called()

    def test_on_tree_node_highlighted_clears_header_key_when_frame_leaf_is_highlighted(self) -> None:
        app = self._build_app()
        app._selected_frame_number = None
        app._highlighted_node_key = "CARDSESSION::1/POLL::2"
        app._summary_tree_sync_inflight = False
        app._rows = [self._summary_row(7)]

        frame_node = SimpleNamespace(
            data={"kind": "frame", "frame_number": 7, "expand_key": "CARDSESSION::1/POLL::1"},
        )
        tree_widget = SimpleNamespace(id="summary_tree", cursor_node=frame_node)
        event = SimpleNamespace(control=tree_widget, node=frame_node)

        with mock.patch.object(app, "_refresh_captions"), mock.patch.object(
            app, "_refresh_status_line"
        ), mock.patch.object(app, "_schedule_detail_refresh"):
            app.on_tree_node_highlighted(event)

        self.assertEqual(app._selected_frame_number, 7)
        self.assertIsNone(app._highlighted_node_key)

    def test_reset_capture_runtime_state_clears_highlighted_node_key_and_header_lookup(self) -> None:
        from Tools.HilBridge.live_decode_tui import _reset_capture_runtime_state

        app = SimpleNamespace(
            _capture_generation=1,
            _last_capture_size=512,
            _last_error="",
            _latest_capture_time_seconds=None,
            _latest_capture_monotonic=None,
            _base_rows=[],
            _rows=[],
            _state_annotations={},
            _interesting_frame_numbers=[],
            _summary_tree_frame_nodes={1: object()},
            _summary_tree_header_nodes={"POLL::1": object()},
            _summary_tree_expanded_groups={"POLL::1"},
            _selected_frame_number=1,
            _displayed_selected_frame_number=1,
            _highlighted_node_key="POLL::1",
            _last_parse_completed_monotonic=None,
            _last_parse_row_count=0,
            _requested_detail_frame=None,
            _detail_cache={},
            _bytes_cache={},
            _displayed_detail_key=None,
            _displayed_bytes_key=None,
            _refresh_inflight=False,
            _detail_inflight=False,
            _follow_tail=False,
        )

        _reset_capture_runtime_state(app)

        self.assertEqual(app._summary_tree_header_nodes, {})
        self.assertIsNone(app._highlighted_node_key)

    def test_cycle_summary_view_action_toggles_between_context_and_flat_only(self) -> None:
        from Tools.HilBridge.live_decode_tui import (
            _SUMMARY_VIEW_CONTEXT,
            _SUMMARY_VIEW_FLAT,
            _SUMMARY_VIEW_POLL,
        )

        app = self._build_app()
        self.assertEqual(app._summary_view_mode, _SUMMARY_VIEW_CONTEXT)
        with mock.patch.object(app, "_refresh_summary_tree_visual"), mock.patch.object(
            app, "_refresh_captions"
        ), mock.patch.object(app, "_save_layout_preferences"), mock.patch.object(
            app, "_refresh_status_line"
        ), mock.patch.object(
            app, "_visibility", SimpleNamespace(summary=False, detail=True, bytes=True)
        ):
            app.action_cycle_summary_view()
            self.assertEqual(app._summary_view_mode, _SUMMARY_VIEW_FLAT)
            app.action_cycle_summary_view()
            self.assertEqual(app._summary_view_mode, _SUMMARY_VIEW_CONTEXT)

            # Manually entering the poll view (e.g. via a saved preference or
            # explicit configuration) must not silently keep the F4 cycle
            # wedged there. The next cycle press should escape back to the
            # first entry of the cycle.
            app._summary_view_mode = _SUMMARY_VIEW_POLL
            app.action_cycle_summary_view()
            self.assertEqual(app._summary_view_mode, _SUMMARY_VIEW_CONTEXT)

    def test_summary_row_is_status_apdu_detects_variants(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_row_is_status_apdu

        fetch_pending_annotation = StatefulFrameAnnotation(
            frame_number=1,
            summary_suffix="FETCH PENDING 9B",
        )
        self.assertTrue(
            _summary_row_is_status_apdu(self._poll_row(1), fetch_pending_annotation)
        )

        fs_status_annotation = StatefulFrameAnnotation(
            frame_number=2,
            summary_suffix="FS MF STATUS 0B",
        )
        self.assertTrue(
            _summary_row_is_status_apdu(self._poll_row(2), fs_status_annotation)
        )

        plain_info_row = self._poll_row(3, info="STATUS")
        self.assertTrue(_summary_row_is_status_apdu(plain_info_row, None))

        unrelated_row = self._poll_row(4, info="SELECT")
        self.assertFalse(_summary_row_is_status_apdu(unrelated_row, None))

    def test_assign_poll_group_indices_splits_cycles_on_status_and_idle_gaps(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _assign_poll_group_indices

        rows = [
            self._poll_row(1, info="STATUS", time_seconds=10.0),
            self._poll_row(2, info="FETCH", time_seconds=10.05),
            self._poll_row(3, info="TERMINAL RESPONSE", time_seconds=10.10),
            self._poll_row(4, info="STATUS", time_seconds=15.0),
            self._poll_row(5, info="FETCH", time_seconds=15.05),
            self._poll_row(6, info="SELECT", time_seconds=30.0),
        ]
        annotations = {
            1: StatefulFrameAnnotation(frame_number=1, summary_suffix="FETCH PENDING 9B"),
            2: StatefulFrameAnnotation(frame_number=2, summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp://smdp.gsma.com"),
            3: StatefulFrameAnnotation(frame_number=3, summary_suffix="CH1 OPEN OK"),
            4: StatefulFrameAnnotation(frame_number=4, summary_suffix="FETCH PENDING 5B"),
            5: StatefulFrameAnnotation(frame_number=5, summary_suffix="STK SEND DATA | CH1 SEND 5B"),
            6: StatefulFrameAnnotation(frame_number=6, summary_suffix="FS MF SELECT"),
        }

        assignments = _assign_poll_group_indices(rows, annotations)

        self.assertEqual(assignments[1], 1)
        self.assertEqual(assignments[2], 1)
        self.assertEqual(assignments[3], 1)
        self.assertEqual(assignments[4], 2)
        self.assertEqual(assignments[5], 2)
        self.assertEqual(assignments[6], 3)

    def test_summary_poll_cycle_highlight_tokens_extract_bip_activity(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_poll_cycle_highlight_tokens

        rows = [
            self._poll_row(1, info="STATUS"),
            self._poll_row(2, info="FETCH"),
            self._poll_row(3, info="TERMINAL RESPONSE"),
            self._poll_row(4, info="FETCH"),
            self._poll_row(5, info="TERMINAL RESPONSE"),
            self._poll_row(6, info="FETCH"),
            self._poll_row(7, info="TERMINAL RESPONSE"),
        ]
        annotations = {
            1: StatefulFrameAnnotation(frame_number=1, summary_suffix="FETCH PENDING 9B"),
            2: StatefulFrameAnnotation(
                frame_number=2,
                summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp://smdp.example",
            ),
            3: StatefulFrameAnnotation(frame_number=3, summary_suffix="CH1 OPEN OK"),
            4: StatefulFrameAnnotation(frame_number=4, summary_suffix="STK SEND DATA | CH1 SEND 5B"),
            5: StatefulFrameAnnotation(frame_number=5, summary_suffix="CH1 SEND OK rem=5"),
            6: StatefulFrameAnnotation(frame_number=6, summary_suffix="STK RECEIVE DATA | CH1 RECEIVE 5B"),
            7: StatefulFrameAnnotation(frame_number=7, summary_suffix="CH1 RX 5B rem=0"),
        }

        tokens = _summary_poll_cycle_highlight_tokens(rows, annotations)

        self.assertIn("SEND", tokens)
        self.assertIn("RECV", tokens)
        self.assertTrue(any(token.startswith("OPEN") for token in tokens))
        self.assertTrue(
            any("tcp://smdp.example" in token.lower() for token in tokens),
            msg=f"Expected endpoint token in {tokens!r}",
        )

    def test_summary_poll_cycle_highlight_tokens_defaults_to_idle_for_pure_status(self) -> None:
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation
        from Tools.HilBridge.live_decode_tui import _summary_poll_cycle_highlight_tokens

        rows = [self._poll_row(1, info="STATUS")]
        annotations = {
            1: StatefulFrameAnnotation(frame_number=1, summary_suffix="FETCH PENDING 0B"),
        }

        tokens = _summary_poll_cycle_highlight_tokens(rows, annotations)

        self.assertEqual(tokens, ["idle"])

    def test_summary_tree_emits_poll_fqdn_and_endpoint_labels_at_top_level(self) -> None:
        from textual.widgets import Tree
        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._summary_row(1, info="FETCH"),
                self._summary_row(2, info="FETCH"),
                self._summary_row(3, info="FETCH"),
                self._summary_row(4, info="FETCH"),
                self._summary_row(5, info="FETCH"),
                self._summary_row(6, info="FETCH"),
            ]
            annotations = {
                1: StatefulFrameAnnotation(
                    frame_number=1,
                    summary_suffix=(
                        "STK OPEN CHANNEL | CH1 OPEN "
                        "udp-client-remote://8.8.8.8:53 APN:Terminal.apn"
                    ),
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix=(
                        "CH1 SEND 33B | DNS Query: id=0x1234 "
                        "qname=eim.sm.1ot.com type=A class=IN"
                    ),
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                ),
                3: StatefulFrameAnnotation(
                    frame_number=3,
                    summary_suffix="STK CLOSE CHANNEL | CH1 CLOSE",
                    channel_session_id=1,
                    channel_number=1,
                    channel_poll_index=1,
                    state_event=True,
                ),
                4: StatefulFrameAnnotation(
                    frame_number=4,
                    summary_suffix=(
                        "STK OPEN CHANNEL | CH2 OPEN "
                        "tcp-client-remote://1.2.3.4:443 APN:Terminal.apn"
                    ),
                    channel_session_id=2,
                    channel_number=2,
                    channel_poll_index=1,
                    state_event=True,
                ),
                5: StatefulFrameAnnotation(
                    frame_number=5,
                    summary_suffix=(
                        "CH2 SEND 87B | TLS Handshake: ClientHello "
                        "sni=eim.sm.1ot.com (67 byte(s))"
                    ),
                    channel_session_id=2,
                    channel_number=2,
                    channel_poll_index=1,
                ),
                6: StatefulFrameAnnotation(
                    frame_number=6,
                    summary_suffix="STK CLOSE CHANNEL | CH2 CLOSE",
                    channel_session_id=2,
                    channel_number=2,
                    channel_poll_index=1,
                    state_event=True,
                ),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_level_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]
                        self.assertFalse(
                            any(label.startswith("Channels ") for label in top_level_labels),
                            msg=f"Channels wrapper must not appear, got {top_level_labels!r}",
                        )
                        poll_label_candidates = [
                            label
                            for label in top_level_labels
                            if label.startswith("Poll 1")
                        ]
                        self.assertEqual(len(poll_label_candidates), 1)
                        self.assertIn("eim.sm.1ot.com", poll_label_candidates[0])

                        poll_node = next(
                            node
                            for node in summary_tree.root.children
                            if "Poll 1" in getattr(node.label, "plain", str(node.label))
                        )
                        child_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in poll_node.children
                        ]
                        self.assertEqual(len(child_labels), 2)
                        self.assertTrue(
                            child_labels[0].startswith("DNS - 8.8.8.8:53 - Terminal.apn"),
                            msg=f"DNS session label wrong: {child_labels[0]!r}",
                        )
                        self.assertTrue(
                            child_labels[1].startswith("eIM - 1.2.3.4:443 - Terminal.apn"),
                            msg=f"eIM session label wrong: {child_labels[1]!r}",
                        )

        asyncio.run(scenario())

    def test_rebuild_summary_view_in_poll_mode_groups_rows_by_poll_cycle(self) -> None:
        import asyncio

        from textual.widgets import Tree

        from Tools.HilBridge.live_decode_state import StatefulFrameAnnotation

        async def scenario() -> None:
            app = self._build_app()
            rows = [
                self._poll_row(1, info="STATUS", time_seconds=1.0),
                self._poll_row(2, info="FETCH", time_seconds=1.05),
                self._poll_row(3, info="TERMINAL RESPONSE", time_seconds=1.10),
                self._poll_row(4, info="STATUS", time_seconds=10.0),
                self._poll_row(5, info="SELECT", time_seconds=10.05),
            ]
            annotations = {
                1: StatefulFrameAnnotation(frame_number=1, summary_suffix="FETCH PENDING 9B"),
                2: StatefulFrameAnnotation(
                    frame_number=2,
                    summary_suffix="STK OPEN CHANNEL | CH1 OPEN tcp://smdp.example",
                ),
                3: StatefulFrameAnnotation(frame_number=3, summary_suffix="CH1 OPEN OK"),
                4: StatefulFrameAnnotation(frame_number=4, summary_suffix="FETCH PENDING 0B"),
                5: StatefulFrameAnnotation(frame_number=5, summary_suffix="FS MF SELECT"),
            }

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.build_stateful_packet_annotations",
                return_value=annotations,
            ):
                with mock.patch(
                    "Tools.HilBridge.live_decode_tui.read_packet_summaries",
                    return_value=(rows, ""),
                ):
                    async with app.run_test() as pilot:
                        app._summary_view_mode = "poll"
                        app._schedule_summary_refresh()
                        await pilot.pause()

                        summary_tree = app.query_one("#summary_tree", Tree)
                        top_level_labels = [
                            getattr(node.label, "plain", str(node.label))
                            for node in summary_tree.root.children
                        ]
                        self.assertEqual(len(top_level_labels), 2)
                        self.assertTrue(top_level_labels[0].startswith("Poll 1"))
                        self.assertTrue(top_level_labels[1].startswith("Poll 2"))
                        self.assertIn("OPEN", top_level_labels[0])
                        self.assertIn("(3 frames)", top_level_labels[0])
                        self.assertIn("(2 frames)", top_level_labels[1])
                        for node in summary_tree.root.children:
                            node_data = getattr(node, "data", None)
                            self.assertIsInstance(node_data, dict)
                            self.assertEqual(node_data.get("kind"), "poll_cycle")
                        for frame_number in (1, 2, 3, 4, 5):
                            self.assertIn(frame_number, app._summary_tree_frame_nodes)

        asyncio.run(scenario())

    # ------------------------------------------------------------------
    # Pause/resume hardening: bounded queue, telemetry, banners,
    # confirmation, clip export, auto-hint, capture switch, detail
    # preservation, and a handful of helper coverage tests. Each test
    # targets exactly one invariant documented in the corresponding
    # feature ticket so regressions tend to land on a single assert.
    # ------------------------------------------------------------------

    def test_paused_queue_enforces_hard_cap_and_drops_oldest(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._paused_queue_cap = 3

        class _ScriptedStream:
            def __init__(self, rows: list) -> None:
                self._rows = list(rows)

            def is_alive(self) -> bool:
                return True

            def drain(self) -> list:
                drained = list(self._rows)
                self._rows = []
                return drained

            def stop(self, *, timeout: float = 0.0) -> None:
                del timeout

        flood = [
            PacketSummary(
                number=i,
                time_text=f"{i * 0.01:.6f}",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info=f"APDU {i}",
                udp_payload_hex="AA",
            )
            for i in range(1, 6)
        ]
        app._live_stream = _ScriptedStream(flood)
        app._seed_live_stream_from_base_rows()

        with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
            app, "_refresh_captions"
        ):
            app._drain_live_stream_tick()

        self.assertEqual(len(app._paused_live_rows), 3)
        self.assertEqual(app._paused_queue_dropped, 2)
        self.assertGreaterEqual(app._paused_queue_high_water_mark, 3)
        self.assertEqual(
            [row.info for row in app._paused_live_rows],
            ["APDU 3", "APDU 4", "APDU 5"],
        )

    def test_paused_queue_tracks_protocol_breakdown_in_status_suffix(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        stk_row = PacketSummary(
            number=1,
            time_text="0.100000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM SAT",
            length_text="80",
            info="PROACTIVE COMMAND",
        )
        fs_row = PacketSummary(
            number=2,
            time_text="0.200000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="SELECT",
        )

        app._enqueue_paused_row(stk_row)
        app._enqueue_paused_row(fs_row)
        app._enqueue_paused_row(fs_row)

        breakdown_text = app._paused_queue_protocol_breakdown_text()

        self.assertIn("APDU:2", breakdown_text)
        self.assertIn("STK:1", breakdown_text)
        suffix_text = app._ingest_pause_status_suffix()
        self.assertIn("3 queued", suffix_text)
        self.assertIn("APDU:2", suffix_text)

    def test_action_toggle_ingest_pause_discard_drops_queue_on_resume(self) -> None:
        app = self._build_app()
        queued_rows = [self._summary_row(i) for i in (1, 2, 3)]
        app._ingest_paused = True
        app._paused_live_rows = list(queued_rows)
        app._paused_queue_protocol_counts = {"APDU": 3}

        with mock.patch.object(
            app, "_apply_live_stream_additions"
        ) as apply_mock, mock.patch.object(
            app, "_schedule_summary_refresh"
        ) as schedule_mock, mock.patch.object(
            app, "_refresh_status_line"
        ) as status_mock, mock.patch.object(app, "_refresh_captions"):
            app.action_toggle_ingest_pause_discard()

        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._paused_live_rows, [])
        self.assertEqual(app._paused_queue_protocol_counts, {})
        apply_mock.assert_not_called()
        schedule_mock.assert_called_once()
        self.assertGreaterEqual(status_mock.call_count, 1)
        message_texts = [
            str((call.kwargs.get("message") or (call.args[0] if call.args else "")) or "")
            for call in status_mock.call_args_list
        ]
        joined_messages = " | ".join(message_texts)
        self.assertIn("discarded 3", joined_messages)

    def test_pause_generation_increments_on_enter_and_exit(self) -> None:
        app = self._build_app()
        starting_generation = int(app._ingest_pause_generation)

        with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
            app, "_refresh_captions"
        ), mock.patch.object(app, "_schedule_summary_refresh"):
            app.action_toggle_ingest_pause()
            mid_generation = int(app._ingest_pause_generation)
            app.action_toggle_ingest_pause()
            final_generation = int(app._ingest_pause_generation)

        self.assertEqual(mid_generation, starting_generation + 1)
        self.assertEqual(final_generation, starting_generation + 2)
        telemetry = app.pause_telemetry_snapshot()
        self.assertEqual(telemetry["pause_generation"], final_generation)
        self.assertGreaterEqual(telemetry["pause_event_count"], 1)

    def test_pause_telemetry_snapshot_tracks_cumulative_duration(self) -> None:
        app = self._build_app()
        monotonic_values = iter([100.0, 104.25])

        with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
            app, "_refresh_captions"
        ), mock.patch.object(app, "_schedule_summary_refresh"), mock.patch.object(
            app, "_refresh_chrome_title"
        ), mock.patch(
            "Tools.HilBridge.live_decode_tui.time.monotonic",
            side_effect=lambda: next(monotonic_values),
        ):
            app.action_toggle_ingest_pause()
            app.action_toggle_ingest_pause()

        telemetry = app.pause_telemetry_snapshot()
        self.assertAlmostEqual(
            float(telemetry["pause_total_duration_seconds"]), 4.25, places=3
        )
        self.assertFalse(bool(telemetry["pause_currently_active"]))
        self.assertEqual(int(telemetry["pause_event_count"]), 1)

    def test_ingest_pause_status_suffix_reports_elapsed_seconds(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._pause_started_monotonic = 100.0

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.time.monotonic",
            return_value=137.0,
        ):
            suffix_text = app._ingest_pause_status_suffix()

        self.assertIn("37s", suffix_text)
        self.assertIn("F2 resume", suffix_text)

    def test_action_clear_capture_view_requires_confirm_when_paused_queue_has_rows(self) -> None:
        app = self._build_app(capture_path="/tmp/live_capture.pcap")
        app._ingest_paused = True
        app._paused_live_rows = [self._summary_row(1)]
        captured_status: list[tuple[str | None, bool | None]] = []

        def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
            captured_status.append((message, error))

        monotonic_values = iter([1000.0, 1001.0, 1010.0])

        with mock.patch.object(
            app, "_refresh_status_line", side_effect=capture_status
        ), mock.patch.object(app, "_refresh_captions"), mock.patch.object(
            app, "_refresh_chrome_title"
        ), mock.patch.object(app, "_rebuild_summary_view"), mock.patch.object(
            app, "_set_detail_views"
        ), mock.patch(
            "Tools.HilBridge.live_decode_tui.time.monotonic",
            side_effect=lambda: next(monotonic_values),
        ):
            app.action_clear_capture_view()
            self.assertEqual(app._capture_path, "/tmp/live_capture.pcap")
            self.assertIn("Press Ctrl+F11 again", str(captured_status[-1][0]))
            app.action_clear_capture_view()

        self.assertEqual(app._capture_path, "")

    def test_action_save_trace_snapshot_clipped_forces_packet_count_when_unpaused(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-snapshot-full")
            app = self._build_app(capture_path=str(capture_path))
            app._base_rows = [self._summary_row(i) for i in range(1, 4)]
            app._ingest_paused = False

            calls: list[dict[str, object]] = []

            def fake_save(capture_path_arg, *, target_path, packet_count, tshark_binary):
                calls.append(
                    {
                        "packet_count": packet_count,
                        "target_path": str(target_path),
                        "tshark_binary": str(tshark_binary or ""),
                    }
                )
                resolved_target = Path(str(target_path)) / "live_capture_20260414_120000_paused.pcap"
                resolved_target.parent.mkdir(parents=True, exist_ok=True)
                resolved_target.write_bytes(b"clip")
                return resolved_target

            captured_status: list[tuple[str | None, bool | None]] = []

            def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
                captured_status.append((message, error))

            with mock.patch.object(
                app, "_open_trace_save_picker"
            ) as picker_mock, mock.patch.object(
                app, "_refresh_status_line", side_effect=capture_status
            ), mock.patch.object(
                app, "_save_layout_preferences"
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.save_live_capture_trace",
                side_effect=fake_save,
            ):
                app.action_save_trace_snapshot_clipped()
                picker_mock.assert_called_once()
                self.assertTrue(app._force_clip_next_save)
                app._on_trace_save_choice(str(capture_path.parent / "exports"))

            self.assertFalse(app._force_clip_next_save)
            self.assertEqual(calls[0]["packet_count"], 3)
            status_text = str(captured_status[-1][0] or "")
            self.assertIn("clipped", status_text)
            self.assertIn("3 packets", status_text)

    def test_action_save_trace_snapshot_clipped_refuses_when_base_rows_empty(self) -> None:
        app = self._build_app(capture_path="/tmp/live_capture.pcap")
        app._base_rows = []
        captured_status: list[tuple[str | None, bool | None]] = []

        def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
            captured_status.append((message, error))

        with mock.patch.object(
            app, "_open_trace_save_picker"
        ) as picker_mock, mock.patch.object(
            app, "_refresh_status_line", side_effect=capture_status
        ):
            app.action_save_trace_snapshot_clipped()

        picker_mock.assert_not_called()
        self.assertFalse(app._force_clip_next_save)
        self.assertEqual(captured_status[-1][1], True)
        self.assertIn("No packets", str(captured_status[-1][0] or ""))

    def test_save_live_capture_trace_injects_paused_filename_marker(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")

            captured_command: list[list[str]] = []

            def fake_run(command, *, check, capture_output, timeout):
                del check, capture_output, timeout
                captured_command.append(list(command))
                Path(command[3]).write_bytes(b"clip")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=5,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run",
                side_effect=fake_run,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ):
                saved_path = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(capture_path.parent / "exports"),
                    packet_count=3,
                    tshark_binary="/usr/bin/tshark",
                )

            self.assertTrue(saved_path.name.endswith("_paused.pcap"))
            self.assertIn("_paused", saved_path.name)
            self.assertEqual(len(captured_command), 1)
            self.assertEqual(captured_command[0][-1], "1-3")

    def test_save_live_capture_trace_clamps_packet_count_to_pcap_probe(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcapng"
            capture_path.write_bytes(b"pcapng-bytes")
            captured_command: list[list[str]] = []

            def fake_run(command, *, check, capture_output, timeout):
                del check, capture_output, timeout
                captured_command.append(list(command))
                Path(command[3]).write_bytes(b"clip")
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=4,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run",
                side_effect=fake_run,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.time.strftime",
                return_value="20260414_120000",
            ):
                saved_path = save_live_capture_trace(
                    str(capture_path),
                    target_path=str(capture_path.parent / "exports"),
                    packet_count=50,
                    tshark_binary="/usr/bin/tshark",
                )

            self.assertTrue(saved_path.name.endswith("_paused.pcapng"))
            self.assertEqual(len(captured_command), 1)
            self.assertEqual(captured_command[0][-1], "1-4")

    def test_save_live_capture_trace_raises_friendly_message_for_editcap_range_error(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")

            def fake_run(command, *, check, capture_output, timeout):
                del command, check, capture_output, timeout
                return SimpleNamespace(
                    returncode=2,
                    stdout=b"",
                    stderr=b"editcap: record number 50 out of range\n",
                )

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=-1,
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui.subprocess.run",
                side_effect=fake_run,
            ):
                with self.assertRaises(RuntimeError) as caught:
                    save_live_capture_trace(
                        str(capture_path),
                        target_path=str(capture_path.parent / "exports"),
                        packet_count=50,
                        tshark_binary="/usr/bin/tshark",
                    )

        self.assertIn("clip range", str(caught.exception))
        self.assertIn("out of range", str(caught.exception))

    def test_save_live_capture_trace_raises_when_source_pcap_is_empty(self) -> None:
        from Tools.HilBridge.live_decode_tui import save_live_capture_trace

        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"empty-pcap-header")

            with mock.patch(
                "Tools.HilBridge.live_decode_tui.resolve_editcap_binary",
                return_value="/usr/bin/editcap",
            ), mock.patch(
                "Tools.HilBridge.live_decode_tui._count_pcap_packets",
                return_value=0,
            ):
                with self.assertRaises(RuntimeError) as caught:
                    save_live_capture_trace(
                        str(capture_path),
                        target_path=str(capture_path.parent / "exports"),
                        packet_count=5,
                        tshark_binary="/usr/bin/tshark",
                    )

        self.assertIn("no packets", str(caught.exception).lower())

    def test_resolve_capinfos_binary_mirrors_editcap_resolution(self) -> None:
        from Tools.HilBridge.live_decode_tui import resolve_capinfos_binary

        with tempfile.TemporaryDirectory() as temp_dir:
            tshark_dir = Path(temp_dir) / "bin"
            tshark_dir.mkdir(parents=True, exist_ok=True)
            tshark_path = tshark_dir / "tshark"
            tshark_path.write_text("#!/bin/sh\n")
            os.chmod(tshark_path, 0o755)
            capinfos_sibling = tshark_dir / "capinfos"
            capinfos_sibling.write_text("#!/bin/sh\n")
            os.chmod(capinfos_sibling, 0o755)

            self.assertEqual(
                resolve_capinfos_binary(str(tshark_path)),
                str(capinfos_sibling),
            )

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.shutil.which",
            side_effect=lambda name: "/usr/bin/capinfos" if name == "capinfos" else None,
        ):
            self.assertEqual(resolve_capinfos_binary(""), "/usr/bin/capinfos")

    def test_count_pcap_packets_parses_capinfos_machine_readable_output(self) -> None:
        from Tools.HilBridge.live_decode_tui import _count_pcap_packets

        completed = SimpleNamespace(
            returncode=0,
            stdout=b"Number of packets = 12\n",
            stderr=b"",
        )

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.resolve_capinfos_binary",
            return_value="/usr/bin/capinfos",
        ), mock.patch(
            "Tools.HilBridge.live_decode_tui.subprocess.run",
            return_value=completed,
        ):
            self.assertEqual(_count_pcap_packets(Path("/tmp/live.pcap"), tshark_binary=""), 12)

    def test_count_pcap_packets_returns_negative_when_capinfos_missing(self) -> None:
        from Tools.HilBridge.live_decode_tui import _count_pcap_packets

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.resolve_capinfos_binary",
            return_value="",
        ):
            self.assertEqual(_count_pcap_packets(Path("/tmp/live.pcap")), -1)

    def test_auto_pause_hint_emits_when_rate_exceeds_threshold(self) -> None:
        app = self._build_app()
        app._ingest_paused = False
        base_monotonic = 200.0
        app._auto_pause_hint_samples = [
            (base_monotonic + 0.0, 80),
            (base_monotonic + 1.0, 80),
            (base_monotonic + 2.0, 80),
        ]

        captured_status: list[tuple[str | None, bool | None]] = []

        def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
            captured_status.append((message, error))

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.time.monotonic",
            return_value=base_monotonic + 2.5,
        ), mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
            app._maybe_emit_auto_pause_hint()

        self.assertEqual(len(captured_status), 1)
        self.assertIn("pkt/s", str(captured_status[0][0] or ""))
        self.assertIn("F2", str(captured_status[0][0] or ""))

    def test_auto_pause_hint_respects_cooldown(self) -> None:
        app = self._build_app()
        app._ingest_paused = False
        base_monotonic = 500.0
        app._auto_pause_hint_samples = [
            (base_monotonic + 0.0, 80),
            (base_monotonic + 1.0, 80),
        ]
        app._auto_pause_hint_last_emitted_monotonic = base_monotonic + 1.2

        captured_status: list[tuple[str | None, bool | None]] = []

        def capture_status(message: str | None = None, *, error: bool | None = None) -> None:
            captured_status.append((message, error))

        with mock.patch(
            "Tools.HilBridge.live_decode_tui.time.monotonic",
            return_value=base_monotonic + 1.5,
        ), mock.patch.object(app, "_refresh_status_line", side_effect=capture_status):
            app._maybe_emit_auto_pause_hint()

        self.assertEqual(len(captured_status), 0)

    def test_auto_pause_hint_ignored_when_ingest_already_paused(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._auto_pause_hint_samples = [(100.0, 80), (101.0, 80)]

        with mock.patch.object(app, "_refresh_status_line") as status_mock:
            app._maybe_emit_auto_pause_hint()

        status_mock.assert_not_called()

    def test_resume_still_schedules_summary_refresh_when_live_stream_died_while_paused(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._paused_live_rows = [self._summary_row(1)]
        app._live_stream = None
        app._live_stream_started = False

        with mock.patch.object(
            app, "_apply_live_stream_additions"
        ), mock.patch.object(
            app, "_schedule_summary_refresh"
        ) as schedule_mock, mock.patch.object(
            app, "_refresh_status_line"
        ), mock.patch.object(app, "_refresh_captions"):
            app.action_toggle_ingest_pause()

        schedule_mock.assert_called_once()
        self.assertFalse(app._ingest_paused)

    def test_capture_switch_resets_pause_state_and_queue(self) -> None:
        app = self._build_app(capture_path="/tmp/live_capture.pcap")
        app._ingest_paused = True
        app._paused_live_rows = [self._summary_row(1), self._summary_row(2)]
        app._paused_queue_dropped = 5
        app._paused_queue_high_water_mark = 7
        app._paused_queue_protocol_counts = {"APDU": 2}
        app._pause_started_monotonic = 1000.0

        with tempfile.TemporaryDirectory() as temp_dir:
            next_capture_path = Path(temp_dir) / "different.pcap"
            next_capture_path.write_bytes(b"pcap")

            with mock.patch.object(app, "_refresh_status_line"), mock.patch.object(
                app, "_refresh_captions"
            ), mock.patch.object(app, "_refresh_chrome_title"), mock.patch.object(
                app, "_rebuild_summary_view"
            ), mock.patch.object(app, "_schedule_summary_refresh"), mock.patch.object(
                app, "_set_detail_views"
            ), mock.patch.object(app, "_apply_theme_preference"):
                app._switch_capture_path(str(next_capture_path))

        self.assertFalse(app._ingest_paused)
        self.assertEqual(app._paused_live_rows, [])
        self.assertEqual(app._paused_queue_dropped, 0)
        self.assertEqual(app._paused_queue_high_water_mark, 0)
        self.assertEqual(app._paused_queue_protocol_counts, {})
        self.assertIsNone(app._pause_started_monotonic)

    def test_detail_refresh_can_still_fetch_rows_while_paused(self) -> None:
        app = self._build_app()
        app._ingest_paused = True
        app._base_rows = [self._summary_row(1, info="SELECT"), self._summary_row(2, info="READ")]
        app._rows = app._decorate_summary_rows(app._base_rows)
        app._selected_frame_number = 2

        with mock.patch.object(app, "_schedule_detail_refresh") as detail_mock:
            selected_row = app._selected_summary_row()
            app._schedule_detail_refresh()

        self.assertIsNotNone(selected_row)
        self.assertEqual(int(selected_row.number), 2)
        detail_mock.assert_called_once()

    def test_chrome_title_toggles_paused_banner_class_on_pause_state_change(self) -> None:
        app = self._build_app()

        class _FakeChrome:
            def __init__(self) -> None:
                self.classes: set[str] = set()
                self.rendered: list[object] = []

            def update(self, value: object) -> None:
                self.rendered.append(value)

            def add_class(self, name: str) -> None:
                self.classes.add(name)

            def remove_class(self, name: str) -> None:
                self.classes.discard(name)

        chrome = _FakeChrome()

        with mock.patch.object(app, "query_one", return_value=chrome), mock.patch.object(
            app, "_active_palette"
        ) as palette_mock:
            palette_mock.return_value = SimpleNamespace(
                primary="",
                secondary="",
                bip="",
                timer="yellow",
            )
            app._ingest_paused = True
            app._paused_live_rows = [self._summary_row(1)]
            app._refresh_chrome_title()
            self.assertIn("paused-banner", chrome.classes)

            app._ingest_paused = False
            app._paused_live_rows = []
            app._refresh_chrome_title()

        self.assertNotIn("paused-banner", chrome.classes)

    def test_summary_caption_prefixes_paused_badge_when_paused(self) -> None:
        from textual.widgets import Tree as _TreeType

        del _TreeType

        async def scenario() -> None:
            app = self._build_app()

            async with app.run_test() as pilot:
                app._base_rows = [self._summary_row(1), self._summary_row(2)]
                app._rows = app._decorate_summary_rows(app._base_rows)
                app._ingest_paused = True
                app._paused_live_rows = [self._summary_row(3), self._summary_row(4)]
                app._paused_queue_dropped = 2
                app._refresh_captions()
                await pilot.pause()

                caption_widget = app.query_one("#summary_caption")
                caption_text = caption_widget.content
                caption_plain = str(getattr(caption_text, "plain", caption_text))

                self.assertIn("PAUSED", caption_plain)
                self.assertIn("2 queued", caption_plain)
                self.assertIn("2 dropped", caption_plain)

        asyncio.run(scenario())

    def test_format_duration_text_covers_seconds_minutes_and_hours(self) -> None:
        from Tools.HilBridge.live_decode_tui import _format_duration_text

        self.assertEqual(_format_duration_text(0.4), "0s")
        self.assertEqual(_format_duration_text(5), "5s")
        self.assertEqual(_format_duration_text(65), "1m 05s")
        self.assertEqual(_format_duration_text(3725), "1h 02m 05s")

    def test_classify_queued_row_bucket_maps_common_protocols(self) -> None:
        from Tools.HilBridge.live_decode_tui import _classify_queued_row_bucket

        self.assertEqual(
            _classify_queued_row_bucket(self._summary_row(1, info="ENVELOPE (STK)")),
            "STK",
        )
        self.assertEqual(
            _classify_queued_row_bucket(self._summary_row(2, info="SELECT")),
            "APDU",
        )
        dns_row = PacketSummary(
            number=3,
            time_text="0.1",
            source="127.0.0.1",
            destination="8.8.8.8",
            protocol="DNS",
            length_text="80",
            info="Standard query",
        )
        self.assertEqual(_classify_queued_row_bucket(dns_row), "DNS")

    def test_keybind_help_text_includes_discard_and_clipped_entries(self) -> None:
        from Tools.HilBridge.live_decode_tui import _hil_decode_keybind_help_text

        help_text = _hil_decode_keybind_help_text()

        self.assertIn("Ctrl+F2", help_text)
        self.assertIn("discard", help_text.lower())
        self.assertIn("Shift+F11", help_text)
        self.assertIn("clipped", help_text.lower())


if __name__ == "__main__":
    unittest.main()
