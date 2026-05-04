import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from yggdrasim_common import hil_bridge_runtime


class HilBridgeRuntimeTests(unittest.TestCase):
    def test_extract_remsim_extra_args_skips_default_and_usb_selector_flags(self) -> None:
        supervisor_state = {
            "remsimClientCommand": [
                "osmo-remsim-client-st2",
                "-i",
                "127.0.0.1",
                "-p",
                "9997",
                "-c",
                "0",
                "-n",
                "0",
                "-V",
                "0x1d50",
                "-P",
                "0x60e3",
                "-A",
                "52",
                "-C",
                "1",
                "-I",
                "0",
                "-S",
                "0",
                "-H",
                "3-3",
                "-d",
                "DMAIN:DEBUG",
            ]
        }

        extra_args = hil_bridge_runtime.extract_remsim_extra_args_from_supervisor_state(supervisor_state)

        self.assertEqual(extra_args, ("-d", "DMAIN:DEBUG"))

    def test_render_user_service_unit_includes_remsim_args(self) -> None:
        options = hil_bridge_runtime.HilBridgeUserServiceOptions(
            python_executable="/opt/ygg/bin/python3",
            working_directory="/work/YggdraSIM",
            reader_index=1,
            port=9997,
            usb_vidpid="1d50:60e3",
            remsim_args=("-H", "3-3"),
            documentation_path="/work/YggdraSIM/guides/HIL_BRIDGE_GUIDE.md",
            environment_overrides=(
                ("YGGDRASIM_CARD_BACKEND", "sim"),
                ("YGGDRASIM_SIM_QUIRKS", "/work/YggdraSIM/SIMCARD/sim_quirks.py"),
            ),
        )

        unit_text = hil_bridge_runtime.render_user_service_unit(options)

        self.assertIn("Documentation=file:/work/YggdraSIM/guides/HIL_BRIDGE_GUIDE.md", unit_text)
        self.assertIn("WorkingDirectory=/work/YggdraSIM", unit_text)
        self.assertIn("Environment=YGGDRASIM_CARD_BACKEND=sim", unit_text)
        self.assertIn("Environment=YGGDRASIM_SIM_QUIRKS=/work/YggdraSIM/SIMCARD/sim_quirks.py", unit_text)
        self.assertIn("ExecStart=/opt/ygg/bin/python3 -m Tools.HilBridge.supervisor", unit_text)
        self.assertIn("--remsim-arg=-H --remsim-arg=3-3", unit_text)

    def test_render_user_service_unit_can_disable_gsmtap(self) -> None:
        options = hil_bridge_runtime.HilBridgeUserServiceOptions(
            python_executable="/opt/ygg/bin/python3",
            working_directory="/work/YggdraSIM",
            gsmtap_enabled=False,
        )

        unit_text = hil_bridge_runtime.render_user_service_unit(options)

        self.assertIn("--no-gsmtap", unit_text)

    def test_render_user_service_unit_can_forward_gsmtap_capture_path(self) -> None:
        options = hil_bridge_runtime.HilBridgeUserServiceOptions(
            python_executable="/opt/ygg/bin/python3",
            working_directory="/work/YggdraSIM",
            gsmtap_capture_path="/work/YggdraSIM/state/hil_termshark/live_capture.pcap",
        )

        unit_text = hil_bridge_runtime.render_user_service_unit(options)

        self.assertIn("--gsmtap-capture-path", unit_text)
        self.assertIn("/work/YggdraSIM/state/hil_termshark/live_capture.pcap", unit_text)

    def test_install_user_service_writes_unit_under_user_systemd_dir(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            written_path = hil_bridge_runtime.install_user_service(
                "[Unit]\nDescription=Demo\n",
                home_dir=temp_dir,
            )

            self.assertTrue(written_path.endswith(".config/systemd/user/yggdrasim-hil-supervisor.service"))
            self.assertEqual(Path(written_path).read_text(encoding="utf-8"), "[Unit]\nDescription=Demo\n")

    def test_write_user_service_if_changed_reports_first_write_and_idempotent_rewrite(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            unit_text = "[Unit]\nDescription=Initial\n"
            first_path, first_changed = hil_bridge_runtime.write_user_service_if_changed(
                unit_text,
                home_dir=temp_dir,
            )

            self.assertTrue(first_changed)
            self.assertTrue(Path(first_path).is_file())

            second_path, second_changed = hil_bridge_runtime.write_user_service_if_changed(
                unit_text,
                home_dir=temp_dir,
            )

            self.assertEqual(first_path, second_path)
            self.assertFalse(second_changed)

            third_path, third_changed = hil_bridge_runtime.write_user_service_if_changed(
                "[Unit]\nDescription=Updated\nEnvironment=YGGDRASIM_CARD_BACKEND=sim\n",
                home_dir=temp_dir,
            )

            self.assertEqual(first_path, third_path)
            self.assertTrue(third_changed)
            self.assertIn(
                "Environment=YGGDRASIM_CARD_BACKEND=sim",
                Path(third_path).read_text(encoding="utf-8"),
            )

    def test_clear_card_relay_state_removes_marker_when_present(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            with mock.patch.dict("os.environ", {"YGGDRASIM_RUNTIME_ROOT": temp_dir}, clear=False):
                marker_path = Path(hil_bridge_runtime.card_relay_state_path())
                marker_path.parent.mkdir(parents=True, exist_ok=True)
                marker_path.write_text("{\"statusUrl\": \"http://127.0.0.1:1/old\"}\n", encoding="utf-8")

                hil_bridge_runtime.clear_card_relay_state()

                self.assertFalse(marker_path.exists())

                # Subsequent calls must be no-ops.
                hil_bridge_runtime.clear_card_relay_state()
                self.assertFalse(marker_path.exists())

    def test_query_user_service_state_parses_systemctl_show_output(self) -> None:
        completed = subprocess.CompletedProcess(
            ["systemctl", "--user", "show"],
            0,
            stdout=(
                "LoadState=loaded\n"
                "UnitFileState=enabled\n"
                "ActiveState=active\n"
                "SubState=running\n"
                "FragmentPath=/home/test/.config/systemd/user/yggdrasim-hil-supervisor.service\n"
            ),
            stderr="",
        )
        with mock.patch.object(hil_bridge_runtime, "run_systemctl_user", return_value=completed):
            payload = hil_bridge_runtime.query_user_service_state()

        self.assertEqual(payload["loadState"], "loaded")
        self.assertEqual(payload["unitFileState"], "enabled")
        self.assertEqual(payload["activeState"], "active")
        self.assertEqual(payload["subState"], "running")
        self.assertEqual(
            payload["fragmentPath"],
            "/home/test/.config/systemd/user/yggdrasim-hil-supervisor.service",
        )

    def test_read_bridge_status_uses_marker_status_url(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "status": "ok",
                "bankdConnected": True,
                "controlConnected": True,
            }
        ).encode("utf-8")

        with mock.patch.object(
            hil_bridge_runtime,
            "read_card_relay_state",
            return_value={"statusUrl": "http://127.0.0.1:44215/status"},
        ):
            with mock.patch.object(hil_bridge_runtime.request, "urlopen", return_value=response) as mocked_urlopen:
                payload = hil_bridge_runtime.read_bridge_status()

        request_object = mocked_urlopen.call_args.args[0]
        self.assertEqual(request_object.full_url, "http://127.0.0.1:44215/status")
        self.assertEqual(request_object.get_method(), "GET")
        self.assertIsNone(request_object.data)
        self.assertTrue(bool(payload["bankdConnected"]))

    def test_hil_bridge_warning_text_reports_shared_state_risk(self) -> None:
        with mock.patch.object(
            hil_bridge_runtime,
            "read_supervisor_state",
            return_value={"bridgeRunning": True, "remsimClientRunning": True},
        ):
            warning_text = hil_bridge_runtime.hil_bridge_warning_text()

        self.assertIn("YggdraSIM HIL is running", warning_text)
        self.assertIn("concurrent traffic", warning_text)

    def test_wait_for_bridge_ready_returns_live_status_payload(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "status": "ok",
                "apduUrl": "http://127.0.0.1:44215/apdu",
            }
        ).encode("utf-8")

        with mock.patch.object(
            hil_bridge_runtime,
            "read_card_relay_state",
            return_value={"statusUrl": "http://127.0.0.1:44215/status"},
        ):
            with mock.patch.object(hil_bridge_runtime.request, "urlopen", return_value=response):
                payload = hil_bridge_runtime.wait_for_bridge_ready()

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["apduUrl"], "http://127.0.0.1:44215/apdu")


if __name__ == "__main__":
    unittest.main()
