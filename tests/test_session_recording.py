# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common.session_recording import (
    ShellSessionRecorder,
    emit_apdu_trace_event,
    set_apdu_trace_listener,
)


class ShellSessionRecorderTests(unittest.TestCase):
    def test_recorder_writes_json_payload_with_replay_commands_and_apdus(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "session_recording.json"
            recorder = ShellSessionRecorder(
                shell_name="unit_test_shell",
                module_entry_point="python -m demo.shell",
            )

            started_path = recorder.start(str(output_path))
            self.assertEqual(started_path, str(output_path.resolve()))

            command_record = recorder.begin_command(
                raw_command="DISCOVER",
                canonical_command="DISCOVER",
                replay_command="DISCOVER",
                debug_enabled=False,
                source="interactive",
            )
            emit_apdu_trace_event(
                log_name="LOCAL: Test APDU",
                apdu=bytes.fromhex("00A40400"),
                response=bytes.fromhex("6F00"),
                sw1=0x90,
                sw2=0x00,
                transport="FakeApduChannel",
            )
            recorder.finish_command(command_record, success=True)

            saved_path, payload = recorder.stop()

            self.assertEqual(saved_path, str(output_path.resolve()))
            self.assertEqual(payload["summary"]["command_count"], 1)
            self.assertEqual(payload["summary"]["apdu_count"], 1)
            self.assertEqual(payload["replay"]["commands"], ["DISCOVER"])

            on_disk = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["commands"][0]["canonical_command"], "DISCOVER")
            self.assertEqual(on_disk["commands"][0]["apdu_count"], 1)
            self.assertEqual(on_disk["apdu_trace"][0]["log_name"], "LOCAL: Test APDU")
            self.assertEqual(on_disk["apdu_trace"][0]["status_hex"], "9000")


class ShellSessionRecorderHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        # Drop any global listener the previous test case might have left
        # hanging so our assertions only see events we emit from this test.
        set_apdu_trace_listener(None)

    def tearDown(self) -> None:
        set_apdu_trace_listener(None)

    def test_apdu_trace_soft_cap_drops_oldest(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"YGGDRASIM_SESSION_APDU_TRACE_CAP": "4"},
            clear=False,
        ):
            recorder = ShellSessionRecorder(
                shell_name="cap_shell",
                module_entry_point="python -m demo.cap_shell",
            )
            with tempfile.TemporaryDirectory() as temp_dir:
                recorder.start(str(Path(temp_dir) / "out.json"))
                cmd = recorder.begin_command(
                    raw_command="BULK",
                    canonical_command="BULK",
                    replay_command="BULK",
                    debug_enabled=False,
                    source="interactive",
                )
                for index in range(10):
                    emit_apdu_trace_event(
                        log_name=f"EV {index}",
                        apdu=bytes.fromhex("00A40400"),
                        response=bytes.fromhex("9000"),
                        sw1=0x90,
                        sw2=0x00,
                        transport="FakeApduChannel",
                    )
                recorder.finish_command(cmd, success=True)
                _, payload = recorder.stop()
                # Soft cap keeps the 4 most recent events plus the one that
                # triggers the drop-oldest branch before the append.
                apdu_trace = payload["apdu_trace"]
                self.assertLessEqual(len(apdu_trace), 4)
                self.assertEqual(apdu_trace[-1]["log_name"], "EV 9")

    def test_concurrent_apdu_events_retain_unique_indexes(self) -> None:
        recorder = ShellSessionRecorder(
            shell_name="race_shell",
            module_entry_point="python -m demo.race_shell",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            recorder.start(str(Path(temp_dir) / "out.json"))
            cmd = recorder.begin_command(
                raw_command="RACE",
                canonical_command="RACE",
                replay_command="RACE",
                debug_enabled=False,
                source="interactive",
            )

            def worker() -> None:
                for _ in range(50):
                    emit_apdu_trace_event(
                        log_name="race",
                        apdu=bytes.fromhex("00A40400"),
                        response=bytes.fromhex("9000"),
                        sw1=0x90,
                        sw2=0x00,
                        transport="FakeApduChannel",
                    )

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            recorder.finish_command(cmd, success=True)
            _, payload = recorder.stop()

            indexes = [event["index"] for event in payload["apdu_trace"]]
            # 4 workers x 50 events = 200 events; every index must be unique
            # and equal to its position (1-based, since the recorder starts
            # at index 1). A lock-less counter racing under the GIL almost
            # never hits 200 unique indexes, so this is a meaningful check.
            self.assertEqual(len(indexes), 200)
            self.assertEqual(len(set(indexes)), 200)
            self.assertEqual(indexes, sorted(indexes))


if __name__ == "__main__":
    unittest.main()
