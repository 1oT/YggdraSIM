from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from Tools.HilBridge.live_decode_view import (
    _compute_pane_specs,
    _run_tshark_text_command,
    _summary_row_text,
    build_packet_detail_command,
    build_packet_hex_command,
    build_summary_command,
    parse_summary_output,
)


class HilBridgeLiveDecodeViewTests(unittest.TestCase):
    def test_build_summary_command_requests_gsmtap_decode_columns(self) -> None:
        command = build_summary_command("/tmp/live_capture.pcap", tshark_binary="/usr/bin/tshark")

        self.assertEqual(command[:3], ["/usr/bin/tshark", "-r", "/tmp/live_capture.pcap"])
        self.assertIn("frame.time_epoch", command)
        self.assertIn("_ws.col.Info", command)
        self.assertIn("udp.payload", command)
        self.assertIn("udp.port==4729,gsmtap", command)

    def test_build_packet_commands_target_single_frame(self) -> None:
        detail_command = build_packet_detail_command(
            "/tmp/live_capture.pcap",
            17,
            tshark_binary="/usr/bin/tshark",
        )
        hex_command = build_packet_hex_command(
            "/tmp/live_capture.pcap",
            17,
            tshark_binary="/usr/bin/tshark",
        )

        self.assertIn("(frame.number >= 17) and (frame.number < 18)", detail_command)
        self.assertIn("-V", detail_command)
        self.assertIn("(frame.number >= 17) and (frame.number < 18)", hex_command)
        self.assertIn("-x", hex_command)

    def test_parse_summary_output_handles_tabular_tshark_rows(self) -> None:
        rows = parse_summary_output(
            '"1"\t"0.000000"\t"0.000000"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"74"\t"SELECT FILE"\t"AA55"\n'
            '"2"\t"0.001000"\t"1.234567"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"72"\t"STATUS"\t"BB66"'
        )

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].number, 1)
        self.assertEqual(
            rows[0].wall_time_text,
            datetime.fromtimestamp(0.0).strftime("%H:%M:%S.") + "000",
        )
        self.assertEqual(rows[0].protocol, "GSMTAP")
        self.assertEqual(rows[0].info, "SELECT FILE")
        self.assertEqual(rows[0].udp_payload_hex, "AA55")
        self.assertEqual(rows[1].number, 2)
        self.assertEqual(
            rows[1].wall_time_text,
            datetime.fromtimestamp(1.234567).strftime("%H:%M:%S.") + "234",
        )
        self.assertEqual(rows[1].length_text, "72")
        self.assertEqual(rows[1].udp_payload_hex, "BB66")

    def test_parse_summary_output_keeps_legacy_rows_without_epoch_support(self) -> None:
        rows = parse_summary_output(
            '"7"\t"0.007000"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"72"\t"STATUS"\t"BB66"'
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].number, 7)
        self.assertEqual(rows[0].wall_time_text, "")
        self.assertEqual(rows[0].time_text, "0.007000")
        self.assertEqual(rows[0].source, "127.0.0.1")

    def test_summary_row_text_hides_loopback_route_column(self) -> None:
        rows = parse_summary_output(
            '"1"\t"0.000000"\t"0.000000"\t"127.0.0.1"\t"127.0.0.1"\t"GSMTAP"\t"74"\t"SELECT FILE"\t"AA55"'
        )

        rendered = _summary_row_text(rows[0], 120)

        self.assertNotIn("127.0.0.1 -> 127.0.0.1", rendered)
        self.assertIn("SELECT FILE", rendered)

    def test_run_tshark_text_command_streams_capture_via_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture_path = Path(temp_dir) / "live_capture.pcap"
            capture_path.write_bytes(b"pcap-bytes")
            observed: dict[str, object] = {}

            def fake_run(*args: object, **kwargs: object):
                command = list(args[0])
                observed["command"] = command
                observed["env"] = dict(kwargs["env"])
                observed["stdin_bytes"] = kwargs["stdin"].read()

                class Completed:
                    returncode = 0
                    stdout = '"1"\n'
                    stderr = ""

                return Completed()

            with mock.patch("Tools.HilBridge.live_decode_view.subprocess.run", side_effect=fake_run):
                stdout_text, stderr_text = _run_tshark_text_command(
                    ["/usr/bin/tshark", "-r", str(capture_path), "-T", "fields", "-e", "frame.number"],
                    capture_path=str(capture_path),
                )

        self.assertEqual(stdout_text, '"1"\n')
        self.assertEqual(stderr_text, "")
        self.assertEqual(observed["command"], ["/usr/bin/tshark", "-r", "-", "-T", "fields", "-e", "frame.number"])
        self.assertEqual(observed["stdin_bytes"], b"pcap-bytes")
        self.assertTrue(str(observed["env"]["XDG_CONFIG_HOME"]).endswith("tshark_cfg"))

    def test_compute_pane_specs_uses_compact_layout_for_short_terminal(self) -> None:
        panes = _compute_pane_specs(12, "detail")

        self.assertEqual([pane.kind for pane in panes], ["summary", "detail"])
        self.assertEqual(sum(pane.height for pane in panes), 10)

    def test_compute_pane_specs_uses_three_panes_when_height_allows(self) -> None:
        panes = _compute_pane_specs(24, "summary")

        self.assertEqual([pane.kind for pane in panes], ["summary", "detail", "bytes"])
        self.assertEqual(sum(pane.height for pane in panes), 22)


if __name__ == "__main__":
    unittest.main()
