# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from Tools.HilBridge import termshark_capture_mirror


class HilBridgeTermsharkCaptureMirrorTests(unittest.TestCase):
    def test_parse_capture_args_extracts_input_and_output_paths(self) -> None:
        input_path, output_path = termshark_capture_mirror._parse_capture_args(
            ["--log-level", "MESSAGE", "-i", "/dev/fd/0", "-w", "/tmp/out.pcap"]
        )

        self.assertEqual(input_path, "/dev/fd/0")
        self.assertEqual(output_path, "/tmp/out.pcap")

    def test_mirror_input_to_output_copies_binary_stream(self) -> None:
        workspace_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            input_path = Path(temp_dir) / "input.pcap"
            output_path = Path(temp_dir) / "output.pcap"
            payload = b"\xd4\xc3\xb2\xa1" + bytes(range(32))
            input_path.write_bytes(payload)

            exit_code = termshark_capture_mirror.mirror_input_to_output(
                str(input_path),
                str(output_path),
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(output_path.read_bytes(), payload)

    def test_mirror_input_to_output_reads_named_pipe_path(self) -> None:
        workspace_root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            input_path = Path(temp_dir) / "input.pipe"
            output_path = Path(temp_dir) / "output.pcap"
            payload = b"\xd4\xc3\xb2\xa1" + bytes(range(16))
            os.mkfifo(input_path)

            def _write_payload() -> None:
                with open(input_path, "wb", buffering=0) as handle:
                    handle.write(payload)

            writer_thread = threading.Thread(target=_write_payload)
            writer_thread.start()
            exit_code = termshark_capture_mirror.mirror_input_to_output(
                str(input_path),
                str(output_path),
            )
            writer_thread.join(timeout=1.0)

            self.assertEqual(exit_code, 0)
            self.assertFalse(writer_thread.is_alive())
            self.assertEqual(output_path.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
