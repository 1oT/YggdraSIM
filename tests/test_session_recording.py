import json
import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.session_recording import (
    ShellSessionRecorder,
    emit_apdu_trace_event,
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


if __name__ == "__main__":
    unittest.main()
