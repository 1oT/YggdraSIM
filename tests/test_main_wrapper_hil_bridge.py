import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_hil_bridge_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)


class MainWrapperHilBridgeRouteTests(unittest.TestCase):
    def test_termshark_environment_uses_color_term_and_writes_local_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(main_wrapper.os.environ, {"TERM": "dumb"}, clear=False):
                with mock.patch.object(main_wrapper, "_hil_bridge_termshark_runtime_root", return_value=temp_dir):
                    with mock.patch.object(
                        main_wrapper,
                        "_hil_bridge_terminfo_supports",
                        side_effect=lambda value: value == "screen-256color",
                    ):
                        with mock.patch.object(
                            main_wrapper,
                            "_hil_bridge_termshark_capture_command",
                            return_value="/tmp/termshark_capture_pcap.py",
                        ):
                            with mock.patch.object(
                                main_wrapper,
                                "_hil_bridge_termshark_dumpcap_command",
                                return_value="/usr/bin/dumpcap",
                            ):
                                environment = main_wrapper._hil_bridge_termshark_environment()
            config_path = Path(temp_dir) / "config" / "termshark" / "termshark.toml"

            self.assertEqual(environment["TERM"], "screen-256color")
            self.assertEqual(environment["COLORTERM"], "truecolor")
            self.assertEqual(environment["XDG_CONFIG_HOME"], str(Path(temp_dir) / "config"))
            self.assertEqual(environment["XDG_CACHE_HOME"], str(Path(temp_dir) / "cache"))
            self.assertTrue(config_path.is_file())
            self.assertIn('term = "screen-256color"', config_path.read_text(encoding="utf-8"))
            self.assertIn('capture-command = "/tmp/termshark_capture_pcap.py"', config_path.read_text(encoding="utf-8"))
            self.assertIn('dumpcap = "/usr/bin/dumpcap"', config_path.read_text(encoding="utf-8"))
            self.assertIn("colors = false", config_path.read_text(encoding="utf-8"))
            self.assertIn('tshark-args = ["-d", "udp.port==4729,gsmtap"]', config_path.read_text(encoding="utf-8"))

    def test_termshark_wake_packet_uses_udp_gsmtap_frame(self) -> None:
        class _FakeSocket:
            def __init__(self) -> None:
                self.sent: list[tuple[bytes, tuple[str, int]]] = []
                self.closed = False

            def sendto(self, payload: bytes, address: tuple[str, int]) -> None:
                self.sent.append((payload, address))

            def close(self) -> None:
                self.closed = True

        fake_socket = _FakeSocket()

        with mock.patch("socket.socket", return_value=fake_socket):
            with mock.patch.object(main_wrapper.time, "sleep") as mocked_sleep:
                main_wrapper._hil_bridge_send_termshark_wake_packet()

        self.assertEqual(len(fake_socket.sent), 2)
        self.assertEqual(fake_socket.sent[0][1], ("127.0.0.1", 4729))
        self.assertEqual(fake_socket.sent[1][1], ("127.0.0.1", 4729))
        self.assertGreater(len(fake_socket.sent[0][0]), 16)
        self.assertEqual(fake_socket.sent[0][0], fake_socket.sent[1][0])
        self.assertTrue(fake_socket.closed)
        self.assertEqual(mocked_sleep.call_count, 2)

    def test_prime_termshark_for_bridge_start_waits_for_iface_and_capture_bytes(self) -> None:
        with mock.patch.object(
            main_wrapper,
            "_hil_bridge_wait_for_termshark_log_marker",
            return_value=True,
        ) as mocked_wait:
            with mock.patch.object(
                main_wrapper,
                "_hil_bridge_wait_for_termshark_capture_bytes",
                return_value=True,
            ) as mocked_capture_wait:
                with mock.patch.object(main_wrapper, "_hil_bridge_send_termshark_wake_packet") as mocked_wake:
                    with mock.patch.object(main_wrapper.time, "sleep") as mocked_sleep:
                        main_wrapper._hil_bridge_prime_termshark_for_bridge_start(2.5)

        mocked_wait.assert_called_once_with("Started Iface command", 2.5, cancel_event=None)
        mocked_capture_wait.assert_called_once_with(2.5, cancel_event=None)
        mocked_wake.assert_called_once_with(cancel_event=None)
        mocked_sleep.assert_called_once_with(0.4)

    def test_live_hil_stream_ctrl_c_stops_service(self) -> None:
        class _InterruptingStdout:
            def __iter__(self):
                return self

            def __next__(self):
                raise KeyboardInterrupt()

        class _FakeProcess:
            def __init__(self) -> None:
                self.stdout = _InterruptingStdout()
                self.terminate_calls = 0
                self.kill_calls = 0
                self.wait_timeouts: list[float] = []

            def terminate(self) -> None:
                self.terminate_calls += 1

            def wait(self, timeout=None):
                self.wait_timeouts.append(float(timeout or 0.0))
                return 0

            def kill(self) -> None:
                self.kill_calls += 1

        fake_process = _FakeProcess()

        with mock.patch.object(main_wrapper.subprocess, "Popen", return_value=fake_process):
            with mock.patch.object(main_wrapper.hil_bridge_runtime, "stop_user_service") as mocked_stop:
                with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                    with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                        main_wrapper._view_hil_bridge_live_stream("demo.service")

        mocked_stop.assert_called_once_with("demo.service")
        mocked_pause.assert_called_once_with()
        self.assertEqual(fake_process.terminate_calls, 1)
        self.assertIn("Stopping the HIL session", captured.getvalue())
        self.assertIn("HIL session stopped", captured.getvalue())

    def test_main_menu_routes_hil_bridge_page(self) -> None:
        with mock.patch.object(main_wrapper, "manage_hil_bridge") as mocked_hil_bridge:
            main_wrapper._dispatch_main_menu_choice("B")

        mocked_hil_bridge.assert_called_once_with()

    def test_launch_hil_bridge_wireshark_uses_dark_adwaita_style(self) -> None:
        with mock.patch.object(main_wrapper, "_hil_bridge_wireshark_binary_path", return_value="/usr/bin/wireshark"):
            with mock.patch.object(main_wrapper, "_hil_bridge_capture_interface", return_value="lo"):
                with mock.patch.object(main_wrapper.subprocess, "Popen") as mocked_popen:
                    main_wrapper._launch_hil_bridge_wireshark()

        mocked_popen.assert_called_once()
        self.assertEqual(
            mocked_popen.call_args.args[0],
            [
                "/usr/bin/wireshark",
                "-k",
                "-i",
                "lo",
                "-f",
                "udp port 4729",
                "-style",
                "Adwaita-Dark",
            ],
        )

    def test_start_hil_bridge_session_starts_service_and_attaches_live_view(self) -> None:
        with mock.patch.object(main_wrapper, "_ensure_hil_bridge_user_service", return_value=("/tmp/ygg.service", True)):
            with mock.patch.object(main_wrapper.hil_bridge_runtime, "read_supervisor_state", return_value={}):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "inactive"},
                ):
                    with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                        with mock.patch.object(
                            main_wrapper.hil_bridge_runtime,
                            "wait_for_bridge_ready",
                            return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                        ):
                            with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream") as mocked_view:
                                with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                                    main_wrapper._start_hil_bridge_session("raw")

        mocked_start.assert_called_once_with(main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME)
        mocked_view.assert_called_once_with(
            main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME,
            gsmtap_enabled=False,
        )
        self.assertIn("HIL session started", captured.getvalue())
        self.assertIn("Attaching to the live APDU stream view", captured.getvalue())

    def test_start_hil_bridge_session_reuses_active_session_and_attaches_live_view(self) -> None:
        with mock.patch.object(main_wrapper, "_ensure_hil_bridge_user_service", return_value=("/tmp/ygg.service", False)):
            with mock.patch.object(
                main_wrapper.hil_bridge_runtime,
                "read_supervisor_state",
                return_value={"bridgeCommand": ["python3", "-m", "Tools.HilBridge.main", "--no-gsmtap"]},
            ):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "active"},
                ):
                    with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                        with mock.patch.object(
                            main_wrapper.hil_bridge_runtime,
                            "wait_for_bridge_ready",
                            return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                        ):
                            with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream") as mocked_view:
                                with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                                    main_wrapper._start_hil_bridge_session("raw")

        mocked_start.assert_not_called()
        mocked_view.assert_called_once_with(
            main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME,
            gsmtap_enabled=False,
        )
        self.assertIn("already active", captured.getvalue())

    def test_start_hil_bridge_session_restarts_active_session_when_capture_mode_changes(self) -> None:
        with mock.patch.object(main_wrapper, "_ensure_hil_bridge_user_service", return_value=("/tmp/ygg.service", False)):
            with mock.patch.object(
                main_wrapper.hil_bridge_runtime,
                "read_supervisor_state",
                return_value={"bridgeCommand": ["python3", "-m", "Tools.HilBridge.main"]},
            ):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "active"},
                ):
                    with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                        with mock.patch.object(main_wrapper.hil_bridge_runtime, "restart_user_service") as mocked_restart:
                            with mock.patch.object(
                                main_wrapper.hil_bridge_runtime,
                                "wait_for_bridge_ready",
                                return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                            ):
                                with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream") as mocked_view:
                                    with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                                        main_wrapper._start_hil_bridge_session("raw")

        mocked_start.assert_not_called()
        mocked_restart.assert_called_once_with(main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME)
        mocked_view.assert_called_once_with(
            main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME,
            gsmtap_enabled=False,
        )
        self.assertIn("restarted to apply the requested capture mode", captured.getvalue())

    def test_start_hil_bridge_session_restarts_active_session_when_unit_changed(self) -> None:
        # Toggling YGGDRASIM_CARD_BACKEND between active sessions
        # rewrites the unit file. Even when the requested capture
        # mode matches the current bridge command, the wizard must
        # honour the unit-file change and restart so systemd picks
        # up the new Environment= block.
        existing_bridge_command = [
            "python3",
            "-m",
            "Tools.HilBridge.main",
        ]
        with mock.patch.object(
            main_wrapper,
            "_ensure_hil_bridge_user_service",
            return_value=("/tmp/ygg.service", True),
        ):
            with mock.patch.object(
                main_wrapper.hil_bridge_runtime,
                "read_supervisor_state",
                return_value={"bridgeCommand": existing_bridge_command},
            ):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "active"},
                ):
                    with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                        with mock.patch.object(main_wrapper.hil_bridge_runtime, "restart_user_service") as mocked_restart:
                            with mock.patch.object(
                                main_wrapper.hil_bridge_runtime,
                                "wait_for_bridge_ready",
                                return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                            ):
                                with mock.patch.object(
                                    main_wrapper.hil_bridge_runtime,
                                    "clear_card_relay_state",
                                ) as mocked_clear:
                                    with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream"):
                                        main_wrapper._start_hil_bridge_session("raw")

        mocked_start.assert_not_called()
        mocked_restart.assert_called_once_with(main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME)
        mocked_clear.assert_called_once()

    def test_start_hil_bridge_session_launches_wireshark_when_requested(self) -> None:
        with mock.patch.object(main_wrapper, "_ensure_hil_bridge_user_service", return_value=("/tmp/ygg.service", True)):
            with mock.patch.object(main_wrapper.hil_bridge_runtime, "read_supervisor_state", return_value={}):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "inactive"},
                ):
                    with mock.patch.object(main_wrapper, "_hil_bridge_wireshark_binary_path", return_value="/usr/bin/wireshark"):
                        with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                            with mock.patch.object(
                                main_wrapper.hil_bridge_runtime,
                                "wait_for_bridge_ready",
                                return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                            ):
                                with mock.patch.object(main_wrapper, "_launch_hil_bridge_wireshark") as mocked_launch:
                                    with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream") as mocked_view:
                                        main_wrapper._start_hil_bridge_session("raw_wireshark")

        mocked_start.assert_called_once_with(main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME)
        mocked_launch.assert_called_once_with()
        mocked_view.assert_called_once_with(
            main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME,
            gsmtap_enabled=True,
        )

    def test_start_hil_bridge_session_attaches_termshark_when_requested(self) -> None:
        with mock.patch.object(main_wrapper, "_ensure_hil_bridge_user_service", return_value=("/tmp/ygg.service", True)) as mocked_ensure:
            with mock.patch.object(main_wrapper.hil_bridge_runtime, "read_supervisor_state", return_value={}):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "query_user_service_state",
                    return_value={"activeState": "inactive"},
                ):
                    with mock.patch.object(main_wrapper, "_hil_bridge_tshark_binary_path", return_value="/usr/bin/tshark"):
                        with mock.patch.object(main_wrapper, "_hil_bridge_termshark_warmup_seconds", return_value=2.5):
                            with mock.patch.object(main_wrapper.hil_bridge_runtime, "start_user_service") as mocked_start:
                                with mock.patch.object(
                                    main_wrapper.hil_bridge_runtime,
                                    "wait_for_bridge_ready",
                                    return_value={"apduUrl": "http://127.0.0.1:44215/apdu"},
                                ):
                                    with mock.patch.object(main_wrapper, "_view_hil_bridge_termshark_stream") as mocked_termshark:
                                        with mock.patch.object(main_wrapper, "_view_hil_bridge_live_stream") as mocked_raw:
                                            main_wrapper._start_hil_bridge_session("termshark")
                                            mocked_ensure.assert_called_once_with(
                                                gsmtap_enabled=True,
                                                gsmtap_capture_path=main_wrapper._hil_bridge_termshark_capture_path(),
                                            )
                                            mocked_start.assert_not_called()
                                            mocked_termshark.assert_called_once()
                                            call_args = mocked_termshark.call_args
                                            self.assertEqual(
                                                call_args.args[0],
                                                main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME,
                                            )
                                            self.assertTrue(callable(call_args.kwargs["startup_callback"]))
                                            self.assertEqual(call_args.kwargs["startup_delay_seconds"], 2.5)
                                            call_args.kwargs["startup_callback"]()
                                            mocked_start.assert_called_once_with(
                                                main_wrapper.hil_bridge_runtime.DEFAULT_SERVICE_NAME
                                            )
                                            mocked_raw.assert_not_called()

    def test_termshark_view_uses_terminal_decode_tui(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(main_wrapper, "_hil_bridge_termshark_runtime_root", return_value=temp_dir):
                with mock.patch("Tools.HilBridge.live_decode_view.resolve_tshark_binary", return_value="/usr/bin/tshark"):
                    with mock.patch("Tools.HilBridge.live_decode_tui.run_live_decode_tui") as mocked_viewer:
                        with mock.patch.object(main_wrapper, "_stop_hil_bridge_from_attached_view") as mocked_stop:
                            with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                                main_wrapper._view_hil_bridge_termshark_stream("demo.service")

        mocked_viewer.assert_called_once()
        self.assertEqual(
            mocked_viewer.call_args.args[0],
            str(Path(temp_dir) / "live_capture.pcap"),
        )
        self.assertEqual(mocked_viewer.call_args.kwargs["service_name"], "demo.service")
        self.assertEqual(mocked_viewer.call_args.kwargs["capture_filter"], "udp port 4729")
        self.assertEqual(mocked_viewer.call_args.kwargs["tshark_binary"], "/usr/bin/tshark")
        self.assertTrue(bool(mocked_viewer.call_args.kwargs["startup_state"]["activation_complete"]))
        mocked_stop.assert_called_once_with("demo.service", "Terminal decode view exited. Stopping the HIL session...")
        mocked_pause.assert_called_once_with()

    def test_build_hil_bridge_service_options_exports_active_backend_environment(self) -> None:
        supervisor_state = {
            "readerIndex": 3,
            "bridgePort": 4477,
        }
        with mock.patch.object(main_wrapper.hil_bridge_runtime, "read_supervisor_state", return_value=supervisor_state):
            with mock.patch.object(
                main_wrapper.hil_bridge_runtime,
                "guess_bridge_python_executable",
                return_value="/opt/ygg/bin/python3",
            ):
                with mock.patch.object(
                    main_wrapper.hil_bridge_runtime,
                    "extract_remsim_extra_args_from_supervisor_state",
                    return_value=("--flag",),
                ):
                    with mock.patch.object(main_wrapper, "get_card_backend", return_value="sim"):
                        with mock.patch.object(main_wrapper, "get_sim_isdr_config_path", return_value="/tmp/isdr.json"):
                            with mock.patch.object(main_wrapper, "get_sim_quirks_path", return_value="/tmp/quirks.py"):
                                with mock.patch.object(
                                    main_wrapper,
                                    "get_sim_eim_identity_path",
                                    return_value="/tmp/eim.json",
                                ):
                                    with mock.patch.object(
                                        main_wrapper,
                                        "get_sim_euicc_store_root",
                                        return_value="/tmp/euicc",
                                    ):
                                        with mock.patch.object(
                                            main_wrapper,
                                            "get_sim_profile_store_path",
                                            return_value="/tmp/profile-store",
                                        ):
                                            options = main_wrapper._build_hil_bridge_service_options(
                                                gsmtap_capture_path="/tmp/live_capture.pcap"
                                            )

        self.assertEqual(options.python_executable, "/opt/ygg/bin/python3")
        self.assertEqual(options.reader_index, 3)
        self.assertEqual(options.port, 4477)
        self.assertEqual(options.remsim_args, ("--flag",))
        self.assertIn((main_wrapper.CARD_BACKEND_ENV, "sim"), options.environment_overrides)
        self.assertIn((main_wrapper.SIM_ISDR_CONFIG_ENV, "/tmp/isdr.json"), options.environment_overrides)
        self.assertIn((main_wrapper.SIM_QUIRKS_ENV, "/tmp/quirks.py"), options.environment_overrides)
        self.assertIn((main_wrapper.SIM_EIM_IDENTITY_ENV, "/tmp/eim.json"), options.environment_overrides)
        self.assertIn((main_wrapper.SIM_EUICC_STORE_ENV, "/tmp/euicc"), options.environment_overrides)
        self.assertIn((main_wrapper.SIM_PROFILE_STORE_ENV, "/tmp/profile-store"), options.environment_overrides)
        self.assertEqual(options.gsmtap_capture_path, "/tmp/live_capture.pcap")

    def test_stop_hil_bridge_session_stops_service(self) -> None:
        with mock.patch.object(
            main_wrapper.hil_bridge_runtime,
            "query_user_service_state",
            return_value={"activeState": "active"},
        ):
            with mock.patch.object(main_wrapper.hil_bridge_runtime, "stop_user_service") as mocked_stop:
                with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                    with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                        main_wrapper._stop_hil_bridge_session()

        mocked_stop.assert_called_once_with()
        mocked_pause.assert_called_once_with()
        self.assertIn("HIL session stopped", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
