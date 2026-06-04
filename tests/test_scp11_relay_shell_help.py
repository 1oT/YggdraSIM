import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
LIVE_CONSOLE_PATH = ROOT / "SCP11" / "live" / "console.py"
TEST_CONSOLE_PATH = ROOT / "SCP11" / "test" / "console.py"


def _load_module(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _eid_response(module) -> bytes:
    return module._build_tlv(bytes.fromhex("BF3E"), module._build_tlv(bytes.fromhex("5A"), bytes.fromhex("89044045930000000000001492294428")))


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _tlv(tag: bytes, value: bytes) -> bytes:
    return tag + _encode_length(len(value)) + value


def _notification_list_response(sequences):
    entries = b""
    for seq in sequences:
        seq_bytes = bytes([seq])
        entry = _tlv(bytes.fromhex("80"), seq_bytes)
        entries += _tlv(bytes.fromhex("BF2F"), entry)
    return _tlv(bytes.fromhex("BF2B"), entries)


def _nested_notification_list_response(sequences):
    entries = b""
    for seq in sequences:
        seq_bytes = bytes([seq])
        entry = _tlv(bytes.fromhex("80"), seq_bytes)
        entries += _tlv(bytes.fromhex("BF2F"), entry)
    nested = _tlv(bytes.fromhex("A0"), entries)
    return _tlv(bytes.fromhex("BF2B"), nested)


def _octet_wrapped_notification_list_response(sequences):
    entries = b""
    for seq in sequences:
        seq_bytes = bytes([seq])
        entry = _tlv(bytes.fromhex("80"), seq_bytes)
        entries += _tlv(bytes.fromhex("BF2F"), entry)
    wrapped = _tlv(bytes.fromhex("04"), entries)
    return _tlv(bytes.fromhex("BF2B"), wrapped)


def _large_realistic_notification_list_response(sequences):
    entries = b""
    for seq in sequences:
        seq_bytes = bytes([seq])
        entry = b""
        entry += _tlv(bytes.fromhex("80"), seq_bytes)
        entry += _tlv(bytes.fromhex("81"), bytes.fromhex("0410"))
        entry += _tlv(bytes.fromhex("0C"), b"dpp1.example.test")
        entry += _tlv(bytes.fromhex("5A"), bytes.fromhex("98010300004077369781"))
        entries += _tlv(bytes.fromhex("BF2F"), entry)
        entries += _tlv(bytes.fromhex("5F37"), bytes(range(64)))
        entries += _tlv(bytes.fromhex("30"), b"X" * 300)
    payload = _tlv(bytes.fromhex("30"), entries)
    wrapped = _tlv(bytes.fromhex("A0"), payload)
    return _tlv(bytes.fromhex("BF2B"), wrapped)


def _profile_metadata_response_with_extra_field():
    entry = b""
    entry += _tlv(bytes.fromhex("5A"), bytes.fromhex("98103000000477637736"))
    entry += _tlv(bytes.fromhex("4F"), bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
    entry += _tlv(bytes.fromhex("9F70"), b"\x01")
    entry += _tlv(bytes.fromhex("95"), b"\x02")
    entry += _tlv(bytes.fromhex("91"), b"Lab (EU 01)")
    entry += _tlv(bytes.fromhex("92"), b"Lab (Domain-A 01)")
    entry += _tlv(bytes.fromhex("8B"), b"\x02")
    return _tlv(bytes.fromhex("E3"), entry)


class DummyCfg:
    RSP_SERVER_URL = "rsp.default.example"
    ES9_BASE_URL = "https://rsp.default.example"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


class DummyApduChannel:
    def __init__(self, eid_response: bytes):
        self._eid_response = eid_response
        self.send_calls = []
        self.notification_responses = []
        self.disconnect_calls = 0
        self.reset_calls = 0
        self._raw_apdu_logging = False

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def reset(self) -> bool:
        self.reset_calls += 1
        return True

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self._raw_apdu_logging = bool(enabled)

    def get_raw_apdu_logging(self) -> bool:
        return bool(self._raw_apdu_logging)

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "GET: EID":
            return self._eid_response
        if log_name == "GET: RetrieveNotificationsList":
            if len(self.notification_responses) == 0:
                return _notification_list_response([])
            return self.notification_responses.pop(0)
        if log_name.startswith("CMD: RemoveNotificationFromList seq="):
            return _tlv(bytes.fromhex("BF30"), _tlv(bytes.fromhex("80"), b"\x00"))
        return b""


class DummyProfileProvider:
    def __init__(self):
        self.base_url = DummyCfg.ES9_BASE_URL

    def set_base_url(self, base_url: str) -> None:
        self.base_url = base_url


class DummyOrchestrator:
    def __init__(self):
        self.sync_calls = []
        self.run_flow_calls = []
        self.eim_poll_calls = []
        self.phase_connect_calls = 0
        self.profile_provider = DummyProfileProvider()

    def _phase_connect(self) -> None:
        self.phase_connect_calls += 1

    def _sync_pending_notifications(self, response: bytes = b"") -> None:
        self.sync_calls.append(response)

    def run_flow(self, matching_id: str = "", smdp_address: str = "") -> None:
        self.run_flow_calls.append((matching_id, smdp_address))

    def run_eim_poll(self, matching_id: str = "", entry_index: int = 0) -> None:
        self.eim_poll_calls.append((matching_id, entry_index))


class RelayShellHelpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live_module = _load_module("live_console_help_module", LIVE_CONSOLE_PATH)
        cls.test_module = _load_module("test_console_help_module", TEST_CONSOLE_PATH)

    def _build_console(self, module):
        client = SimpleNamespace(
            cfg=DummyCfg(),
            apdu_channel=DummyApduChannel(_eid_response(module)),
            orchestrator=DummyOrchestrator(),
        )
        console = module.SCP11Console(client)
        console._style = module.ConsoleStyle("", "", "", "", "", "", "")
        return console

    def _capture_help(self, console, argument: str = "") -> str:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            console._cmd_help(argument)
        return buffer.getvalue()

    def test_live_default_help_hides_expert_commands(self):
        console = self._build_console(self.live_module)

        rendered = self._capture_help(console)

        self.assertIn("Relay Utilities:", rendered)
        self.assertIn("LPAd:", rendered)
        self.assertIn("IPAd:", rendered)
        self.assertNotIn("IPAe:", rendered)
        self.assertIn("HELP [EXPERT]", rendered)
        self.assertIn("METADATA <id|aid|alias>", rendered)
        self.assertIn("DOWNLOAD-PROFILE <activation>", rendered)
        self.assertIn("ENABLE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DISABLE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DELETE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DISCOVER", rendered)
        self.assertIn("DOWNLOAD", rendered)
        self.assertNotIn("POLL", rendered)
        self.assertNotIn("DOWNLOAD [matchingId]", rendered)
        self.assertNotIn("POLL [legacy-profile]", rendered)
        self.assertNotIn("FLOW [matchingId]", rendered)
        self.assertNotIn("DOWNLOAD-AC <activation>", rendered)
        self.assertNotIn("EIM-POLL [legacy-profile]", rendered)
        self.assertNotIn("GET-EID", rendered)
        self.assertNotIn("SET-ES9 [--persist] <url>", rendered)
        self.assertNotIn("GET-EUICC-INFO1", rendered)
        self.assertNotIn("EIM-AUTHENTICATE [matchingId]", rendered)

    def test_live_expert_help_includes_hidden_commands(self):
        console = self._build_console(self.live_module)

        rendered = self._capture_help(console, "EXPERT")

        self.assertIn("Expert / Compatibility:", rendered)
        self.assertIn("GET-EID", rendered)
        self.assertIn("CLEAR-NOTIFICATIONS", rendered)
        self.assertIn("GET-ALL-DATA", rendered)
        self.assertIn("SET-ES9 [--persist] <url>", rendered)
        self.assertIn("GET-EUICC-INFO1", rendered)
        self.assertIn("EIM-AUTHENTICATE [matchingId]", rendered)
        self.assertIn("FLOW [matchingId]", rendered)

    def test_test_default_help_omits_eim_poll(self):
        console = self._build_console(self.test_module)

        rendered = self._capture_help(console)

        self.assertIn("DOWNLOAD-PROFILE <activation>", rendered)
        self.assertIn("METADATA <id|aid|alias>", rendered)
        self.assertIn("ENABLE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DISABLE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DELETE-PROFILE <iccid-or-aid>", rendered)
        self.assertIn("DISCOVER", rendered)
        self.assertIn("DOWNLOAD", rendered)
        self.assertNotIn("DOWNLOAD [matchingId]", rendered)
        self.assertNotIn("IPAe:", rendered)
        self.assertNotIn("EIM-POLL [legacy-profile]", rendered)
        self.assertNotIn("GET-EID", rendered)

    def test_legacy_aliases_remain_registered(self):
        live_console = self._build_console(self.live_module)
        test_console = self._build_console(self.test_module)

        self.assertIn("DOWNLOAD-AC", live_console._commands)
        self.assertIn("GET-METADATA", live_console._commands)
        self.assertIn("METADATA", live_console._commands)
        self.assertIn("EIM-DISCOVER", live_console._commands)
        self.assertIn("EIM-DOWNLOAD", live_console._commands)
        self.assertNotIn("EIM-POLL", live_console._commands)
        self.assertIn("DOWNLOAD-AC", test_console._commands)
        self.assertIn("GET-METADATA", test_console._commands)
        self.assertIn("METADATA", test_console._commands)
        self.assertIn("EIM-DISCOVER", test_console._commands)
        self.assertIn("EIM-DOWNLOAD", test_console._commands)
        self.assertNotIn("EIM-POLL", test_console._commands)

    def test_hidden_command_remains_callable(self):
        console = self._build_console(self.live_module)
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            keep_running = console._commands["GET-EID"].handler("")

        rendered = buffer.getvalue()
        self.assertTrue(keep_running)
        self.assertIn("EID: 89044045930000000000001492294428", rendered)
        self.assertEqual(console.apdu_channel.send_calls[0][0], "GET: EID")

    def test_soft_command_rebuilds_bootstraps_and_disconnects_transport(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            original_channel = console.apdu_channel
            replacement_channel = DummyApduChannel(_eid_response(module))
            built_channels = []

            def build_channel(_cfg):
                built_channels.append(replacement_channel)
                return replacement_channel

            console.client._build_apdu_channel = build_channel

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                keep_running = console._run_command_line("GET-EID")

            self.assertTrue(keep_running)
            self.assertEqual(original_channel.disconnect_calls, 1)
            self.assertEqual(built_channels, [replacement_channel])
            self.assertEqual(console.orchestrator.phase_connect_calls, 1)
            self.assertEqual(replacement_channel.send_calls[0][0], "GET: EID")
            self.assertEqual(replacement_channel.disconnect_calls, 1)

    def test_download_rebuilds_transport_without_preconnect(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            original_channel = console.apdu_channel
            original_channel.set_raw_apdu_logging(True)
            replacement_channel = DummyApduChannel(_eid_response(module))
            built_channels = []
            phase_connect_calls = []
            phase_load_calls = []

            def build_channel(_cfg):
                built_channels.append(replacement_channel)
                return replacement_channel

            console.client._build_apdu_channel = build_channel
            console.orchestrator._phase_connect = lambda: phase_connect_calls.append(True)
            console.orchestrator._phase_load_credentials = lambda: phase_load_calls.append(True)
            console._session_dirty = True

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                keep_running = console._run_command_line("DOWNLOAD")

            self.assertTrue(keep_running)
            self.assertEqual(original_channel.reset_calls, 0)
            self.assertEqual(original_channel.disconnect_calls, 1)
            self.assertEqual(built_channels, [replacement_channel])
            self.assertIs(console.apdu_channel, replacement_channel)
            self.assertIs(console.client.apdu_channel, replacement_channel)
            self.assertIs(console.orchestrator.apdu_channel, replacement_channel)
            self.assertTrue(replacement_channel.get_raw_apdu_logging())
            self.assertEqual(phase_connect_calls, [])
            self.assertEqual(phase_load_calls, [])
            self.assertEqual(console.orchestrator.eim_poll_calls, [("", 0)])
            self.assertEqual(replacement_channel.disconnect_calls, 1)

    def test_get_notifications_uses_logical_fallback_helper(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            fallback_calls = []

            def fake_send(payload: bytes, log_name: str) -> bytes:
                fallback_calls.append((payload, log_name))
                return _large_realistic_notification_list_response([154])

            console._send_store_data_with_logical_fallback = fake_send
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["GET-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertEqual(
                fallback_calls,
                [(bytes.fromhex("BF2B00"), "GET: RetrieveNotificationsList")],
            )
            self.assertIn("Notification Entries : 1", rendered)
            self.assertIn("Seq Number           : 154", rendered)

    def test_notification_count_uses_logical_fallback_helper(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            fallback_calls = []

            def fake_send(payload: bytes, log_name: str) -> bytes:
                fallback_calls.append((payload, log_name))
                return _notification_list_response([154])

            console._send_store_data_with_logical_fallback = fake_send

            count = console._get_notification_count()

            self.assertEqual(count, 1)
            self.assertEqual(
                fallback_calls,
                [(bytes.fromhex("BF2B00"), "GET: RetrieveNotificationsList")],
            )

    def test_clear_notifications_drains_queue_in_live_and_test_shells(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _notification_list_response([7, 9]),
                _notification_list_response([]),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["CLEAR-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("removed 2 notification(s)", rendered)
            send_logs = [entry[0] for entry in console.apdu_channel.send_calls]
            self.assertIn("GET: RetrieveNotificationsList", send_logs)
            self.assertIn("CMD: RemoveNotificationFromList seq=7", send_logs)
            self.assertIn("CMD: RemoveNotificationFromList seq=9", send_logs)

    def test_clear_notifications_encodes_high_bit_sequences_with_positive_integer_prefix(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _notification_list_response([0x94]),
                _notification_list_response([]),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["CLEAR-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            remove_calls = [
                entry for entry in console.apdu_channel.send_calls
                if entry[0] == "CMD: RemoveNotificationFromList seq=148"
            ]

            self.assertTrue(keep_running)
            self.assertIn("removed 1 notification(s)", rendered)
            self.assertEqual(len(remove_calls), 1)
            self.assertEqual(remove_calls[0][1], bytes.fromhex("80E2910007BF300480020094"))

    def test_remove_notification_reports_nothing_to_delete_for_bf30_code_one(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            original_send = console.apdu_channel.send

            def send_with_delete_status_one(apdu: bytes, log_name: str) -> bytes:
                if log_name.startswith("CMD: RemoveNotificationFromList seq="):
                    console.apdu_channel.send_calls.append((log_name, apdu))
                    return _tlv(bytes.fromhex("BF30"), _tlv(bytes.fromhex("80"), b"\x01"))
                return original_send(apdu, log_name)

            console.apdu_channel.send = send_with_delete_status_one
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["REMOVE-NOTIFICATION"].handler("148")

            rendered = buffer.getvalue()
            remove_calls = [
                entry for entry in console.apdu_channel.send_calls
                if entry[0] == "CMD: RemoveNotificationFromList seq=148"
            ]

            self.assertTrue(keep_running)
            self.assertIn("nothingToDelete(1)", rendered)
            self.assertNotIn("iccidOrAidNotFound", rendered)
            self.assertEqual(len(remove_calls), 1)
            self.assertEqual(remove_calls[0][1], bytes.fromhex("80E2910007BF300480020094"))

    def test_clear_notifications_handles_nested_notification_entries(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _nested_notification_list_response([7, 9]),
                _nested_notification_list_response([]),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["CLEAR-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("removed 2 notification(s)", rendered)
            send_logs = [entry[0] for entry in console.apdu_channel.send_calls]
            self.assertIn("CMD: RemoveNotificationFromList seq=7", send_logs)
            self.assertIn("CMD: RemoveNotificationFromList seq=9", send_logs)

    def test_clear_notifications_handles_octet_wrapped_notification_entries(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _octet_wrapped_notification_list_response([7, 9]),
                _octet_wrapped_notification_list_response([]),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["CLEAR-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("removed 2 notification(s)", rendered)
            send_logs = [entry[0] for entry in console.apdu_channel.send_calls]
            self.assertIn("CMD: RemoveNotificationFromList seq=7", send_logs)
            self.assertIn("CMD: RemoveNotificationFromList seq=9", send_logs)

    def test_clear_notifications_handles_large_length_notification_entries(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _large_realistic_notification_list_response([0x37, 0x39]),
                _large_realistic_notification_list_response([]),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["CLEAR-NOTIFICATIONS"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("removed 2 notification(s)", rendered)
            send_logs = [entry[0] for entry in console.apdu_channel.send_calls]
            self.assertIn("CMD: RemoveNotificationFromList seq=55", send_logs)
            self.assertIn("CMD: RemoveNotificationFromList seq=57", send_logs)

    def test_get_all_data_sequences_relay_retrieval_steps(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            call_order = []

            console._cmd_get_eid = lambda argument: call_order.append("eid") or True
            console._cmd_list = lambda argument: call_order.append("list") or True
            console._cmd_status = lambda argument: call_order.append("status") or True
            console._cmd_get_euicc_info1 = lambda argument: call_order.append("info1") or True
            console._cmd_get_euicc_info2 = lambda argument: call_order.append("info2") or True
            console._cmd_get_rat = lambda argument: call_order.append("rat") or True
            console._cmd_get_notifications = lambda argument: call_order.append("notifications") or True
            console._cmd_get_eim_config = lambda argument: call_order.append("eim_config") or True
            console._cmd_get_certs = lambda argument: call_order.append("certs") or True

            keep_running = console._commands["GET-ALL-DATA"].handler("")

            self.assertTrue(keep_running)
            self.assertEqual(
                call_order,
                ["eid", "list", "status", "info1", "info2", "rat", "notifications", "eim_config", "certs"],
            )

    def test_get_all_data_prints_clean_consolidated_headings(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._cmd_get_eid = lambda argument: True
            console._cmd_list = lambda argument: True
            console._cmd_status = lambda argument: True
            console._cmd_get_euicc_info1 = lambda argument: True
            console._cmd_get_euicc_info2 = lambda argument: True
            console._cmd_get_rat = lambda argument: True
            console._cmd_get_notifications = lambda argument: True
            console._cmd_get_eim_config = lambda argument: True
            console._cmd_get_certs = lambda argument: True
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["GET-ALL-DATA"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("=== SGP.32 Consolidated Data Retrieval ===", rendered)
            self.assertIn("=== Running SGP.22/SGP.32 Scan ===", rendered)

    def test_discover_and_get_all_data_use_expected_scp03_suites(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            call_order = []

            console._run_scp03_sgp32_get_all_data = lambda: call_order.append("discover") or True
            console._run_consolidated_discovery_suite = lambda: call_order.append("consolidated") or True

            keep_running = console._commands["DISCOVER"].handler("")
            self.assertTrue(keep_running)
            self.assertEqual(call_order, ["discover"])

            call_order.clear()
            keep_running = console._commands["GET-ALL-DATA"].handler("")
            self.assertTrue(keep_running)
            self.assertEqual(call_order, ["consolidated"])

    def test_discover_prints_scp03_consolidated_headings(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._run_scp03_sgp32_get_all_data = lambda: (
                print("=== SGP.32 Consolidated Data Retrieval ==="),
                print("=== Running SGP.22/SGP.32 Scan ==="),
                True,
            )[-1]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._commands["DISCOVER"].handler("")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("=== SGP.32 Consolidated Data Retrieval ===", rendered)
            self.assertIn("=== Running SGP.22/SGP.32 Scan ===", rendered)

    def test_execute_command_discover_does_not_trigger_notification_sync_or_auto_clear(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            invoked = []
            console._commands["DISCOVER"].handler = lambda argument: invoked.append("discover") or True
            console._sync_notifications_after_success = lambda response=b"": invoked.append("sync")
            console._clear_notifications_internal = lambda quiet=False: invoked.append(f"clear:{quiet}") or 0

            keep_running = console._execute_command("DISCOVER", "")

            self.assertTrue(keep_running)
            self.assertEqual(invoked, ["discover"])

    def test_remove_notification_success_does_not_retrigger_notification_sync(self):
        """
        Regression: ``_execute_result_command`` must not call
        ``_sync_notifications_after_success`` when the command itself is
        ``RemoveNotificationFromList``. The outer profile state flow
        already runs a notification sync after success — letting the
        remove recursion re-enter it causes the noisy ``listNotifications
        failed (APDU Failed: 6881)`` log seen after DISABLE-PROFILE.
        """
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            sync_calls: list[bytes] = []
            console._sync_notifications_after_success = (
                lambda response=b"", _log=sync_calls: _log.append(response)
            )

            remove_payload = console._build_remove_notification_payload(281)
            success = console._execute_result_command(
                title="RemoveNotificationFromList seq=281",
                payload=remove_payload,
                result_outer_tag=console.TAG_REMOVE_NOTIFICATION,
            )

            self.assertTrue(success)
            self.assertEqual(sync_calls, [])

    def test_profile_state_success_still_triggers_notification_sync(self):
        """
        Companion regression: profile state commands (DisableProfile etc.)
        must continue to trigger ``_sync_notifications_after_success`` so
        the inline notification path keeps working. Only the
        RemoveNotification recursion is suppressed by the fix above.
        """
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            sync_calls: list[bytes] = []
            console._sync_notifications_after_success = (
                lambda response=b"", _log=sync_calls: _log.append(response)
            )
            module_self = module

            class DisableProfileChannel:
                def __init__(self) -> None:
                    self.send_calls: list[tuple[str, bytes]] = []

                def send(self, apdu: bytes, log_name: str) -> bytes:
                    self.send_calls.append((log_name, apdu))
                    return module_self._build_tlv(
                        bytes.fromhex("BF32"),
                        module_self._build_tlv(bytes.fromhex("80"), b"\x00"),
                    )

            console.apdu_channel = DisableProfileChannel()

            disable_payload = console._build_profile_command_payload(
                console.TAG_DISABLE_PROFILE,
                console.TAG_ICCID,
                "98103000000477637736",
            )
            success = console._execute_result_command(
                title="DisableProfile",
                payload=disable_payload,
                result_outer_tag=console.TAG_DISABLE_PROFILE,
            )

            self.assertTrue(success)
            self.assertEqual(len(sync_calls), 1)

    def test_profile_state_result_command_uses_orchestrator_store_data_sender(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)

            class ActiveChannelOrchestrator(DummyOrchestrator):
                def __init__(self) -> None:
                    super().__init__()
                    self.store_data_calls: list[tuple[bytes, str, bool]] = []

                def _send_es10b_store_data(
                    self,
                    payload: bytes,
                    log_name: str,
                    *,
                    allow_stk_retry: bool = False,
                ) -> bytes:
                    self.store_data_calls.append((payload, log_name, allow_stk_retry))
                    return module._build_tlv(
                        bytes.fromhex("BF32"),
                        module._build_tlv(bytes.fromhex("80"), b"\x00"),
                    )

            orchestrator = ActiveChannelOrchestrator()
            console.orchestrator = orchestrator
            disable_payload = console._build_profile_command_payload(
                console.TAG_DISABLE_PROFILE,
                console.TAG_AID,
                "A0000005591010FFFFFFFF8900001200",
            )

            success = console._execute_result_command(
                title="DisableProfile",
                payload=disable_payload,
                result_outer_tag=console.TAG_DISABLE_PROFILE,
            )

            self.assertTrue(success)
            self.assertEqual(
                orchestrator.store_data_calls,
                [(disable_payload, "CMD: DisableProfile", True)],
            )
            self.assertEqual(console.apdu_channel.send_calls, [])
            self.assertEqual(orchestrator.sync_calls, [bytes.fromhex("BF3203800100")])

    def test_snapshot_collects_notification_count(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._get_eid = lambda: "89044045930000000000001492294428"
            console._get_ecasd_issuer_identity = lambda eid="": {
                "issuer_number": "89044045",
                "issuer_name": "Kigen",
            }
            console._get_configured_addresses_raw = lambda: b""
            console._decode_euicc_configured_data = lambda raw: {}
            console._fetch_profiles = lambda: []
            console.apdu_channel.notification_responses = [_notification_list_response([7, 9])]
            console._collect_discovery_snapshot_summary = lambda: ({}, {})

            snapshot = console._collect_snapshot()
            console._latest_snapshot = snapshot
            lines = console._build_snapshot_pane_lines(120)

            self.assertEqual(snapshot.notification_count, 2)
            self.assertTrue(any("Queued Notifications" in line and "2" in line for line in lines))

    def test_snapshot_includes_silent_discovery_summary(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._get_eid = lambda: "89044045930000000000001492294428"
            console._get_ecasd_issuer_identity = lambda eid="": {
                "issuer_number": "89044045",
                "issuer_name": "Kigen",
            }
            console._get_configured_addresses_raw = lambda: b""
            console._decode_euicc_configured_data = lambda raw: {}
            console._fetch_profiles = lambda: []
            console.apdu_channel.notification_responses = [_notification_list_response([])]
            console._collect_discovery_snapshot_summary = lambda: (
                {
                    "profile_version": "v2.3.1 (020301)",
                    "supported_version": "v2.5.0 (020500)",
                    "firmware_version": "931100",
                },
                {
                    "eim_fqdn": "yggdrasim.eim.test.1ot.com",
                    "eim_id": "2.25.311782205282738360923618091971140414400",
                },
            )

            snapshot = console._collect_snapshot()
            console._latest_snapshot = snapshot
            lines = console._build_snapshot_pane_lines(120)

            self.assertEqual(snapshot.euicc_info2_summary["profile_version"], "v2.3.1 (020301)")
            self.assertEqual(snapshot.eim_summary["eim_fqdn"], "yggdrasim.eim.test.1ot.com")
            self.assertEqual(snapshot.issuer_name, "Kigen")
            self.assertTrue(any("Issuer" in line and "Kigen" in line for line in lines))
            self.assertTrue(any("Profile Version" in line and "v2.3.1 (020301)" in line for line in lines))
            self.assertTrue(any("eIM FQDN" in line and "yggdrasim.eim.test.1ot.com" in line for line in lines))
            self.assertFalse(any("Active Flow Target" in line for line in lines))
            self.assertFalse(any("Active ES9 URL" in line for line in lines))

    def test_start_snapshot_prints_underlying_apdu_trace_output(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._collect_snapshot = lambda: (
                console._run_with_stdout_suppressed(lambda: print("NESTED-TRACE-LINE")),
                print("NOISY-TRACE-LINE"),
                module.CardSnapshot(
                    eid="89044045930000000000001492294428",
                    issuer_number="89044045",
                    issuer_name="Kigen",
                    configured_raw=b"",
                    configured_decoded={},
                    profiles=[],
                    notification_count=0,
                    euicc_info2_summary={},
                    eim_summary={},
                ),
            )[2]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                console._print_start_snapshot()

            rendered = buffer.getvalue()
            self.assertIn("SCP11 Session Ready", rendered)
            self.assertIn("--- SCP11 Init Banner APDU Trace ---", rendered)
            self.assertIn("NESTED-TRACE-LINE", rendered)
            self.assertIn("NOISY-TRACE-LINE", rendered)
            self.assertIn("--- End SCP11 Init Banner APDU Trace ---", rendered)

    def test_start_snapshot_forces_basic_channel_before_reads(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.orchestrator._es10b_logical_channel = 1

            def collect_snapshot():
                console._send_store_data_with_logical_fallback(bytes.fromhex("BF3E00"), "GET: EID")
                return module.CardSnapshot(
                    eid="89044045930000000000001492294428",
                    issuer_number="89044045",
                    issuer_name="Kigen",
                    configured_raw=b"",
                    configured_decoded={},
                    profiles=[],
                    notification_count=0,
                    euicc_info2_summary={},
                    eim_summary={},
                )

            console._collect_snapshot = collect_snapshot

            with redirect_stdout(io.StringIO()):
                console._print_start_snapshot()

            send_calls = console.apdu_channel.send_calls
            send_logs = [entry[0] for entry in send_calls]
            self.assertIn("INIT-BANNER: CLOSE LOGICAL CHANNEL 1", send_logs)
            self.assertIn("INIT-BANNER: SELECT ISD-R CH0", send_logs)
            self.assertIn("INIT-BANNER: STATUS CH0", send_logs)
            get_call = next(entry for entry in send_calls if entry[0] == "GET: EID")
            self.assertEqual(get_call[1], bytes.fromhex("80E2910003BF3E00"))
            self.assertEqual(console.orchestrator._es10b_logical_channel, 0)
            self.assertTrue(console._session_dirty)

    def test_start_snapshot_prints_hil_warning_when_bridge_is_running(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._collect_snapshot = lambda: module.CardSnapshot(
                eid="89044045930000000000001492294428",
                issuer_number="89044045",
                issuer_name="Kigen",
                configured_raw=b"",
                configured_decoded={},
                profiles=[],
                notification_count=0,
                euicc_info2_summary={},
                eim_summary={},
            )
            buffer = io.StringIO()

            with mock.patch.object(module, "hil_bridge_warning_text", return_value="Synthetic HIL warning"):
                with redirect_stdout(buffer):
                    console._print_start_snapshot()

            rendered = buffer.getvalue()
            self.assertIn("Synthetic HIL warning", rendered)

    def test_console_store_data_uses_orchestrator_es10b_sender_first(self):
        class ActiveEs10bOrchestrator(DummyOrchestrator):
            def __init__(self):
                super().__init__()
                self.store_data_calls = []

            def _send_es10b_store_data(self, payload: bytes, log_name: str, *, allow_stk_retry: bool = False) -> bytes:
                self.store_data_calls.append((payload, log_name, allow_stk_retry))
                return b"\xBF\x3E\x00"

        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            orchestrator = ActiveEs10bOrchestrator()
            console.orchestrator = orchestrator

            response = console._send_store_data_with_logical_fallback(
                bytes.fromhex("BF3E00"),
                "GET: EID",
            )

            self.assertEqual(response, b"\xBF\x3E\x00")
            self.assertEqual(
                orchestrator.store_data_calls,
                [(bytes.fromhex("BF3E00"), "GET: EID", True)],
            )
            self.assertEqual(console.apdu_channel.send_calls, [])

    def test_execute_command_keeps_read_only_action_free_of_notification_side_effects(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._commands["LIST"].handler = lambda argument: True

            keep_running = console._execute_command("LIST", "")

            self.assertTrue(keep_running)
            self.assertEqual(console.orchestrator.sync_calls, [])
            self.assertEqual(console.apdu_channel.send_calls, [])

    def test_execute_command_triggers_single_notification_sync_for_transaction_action(self):
        """
        Post-transaction commands trigger one notification sync. The
        sync path owns forwarding/removal; the console must not run a
        second quiet ListNotifications sweep after DOWNLOAD because the
        command may already have closed or rebound the ES10 channel.
        """
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [
                _notification_list_response([7, 9]),
                _notification_list_response([]),
            ]
            console._commands["DOWNLOAD"].handler = lambda argument: True

            keep_running = console._execute_command("DOWNLOAD", "")

            self.assertTrue(keep_running)
            self.assertEqual(console.orchestrator.sync_calls, [b""])
            send_logs = [entry[0] for entry in console.apdu_channel.send_calls]
            self.assertNotIn("GET: RetrieveNotificationsList", send_logs)
            self.assertNotIn("CMD: RemoveNotificationFromList seq=7", send_logs)
            self.assertNotIn("CMD: RemoveNotificationFromList seq=9", send_logs)

    def test_download_profile_uses_activation_code_server_for_es9_target(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)

            console._download_activation_code("1$dpp1.esim.example.test$MATCH-55$1.2.3")

            self.assertEqual(console.current_smdp_address, "dpp1.esim.example.test")
            self.assertEqual(console.current_es9_base_url, "https://dpp1.esim.example.test")
            self.assertEqual(console.orchestrator.run_flow_calls, [("MATCH-55", "dpp1.esim.example.test")])
            self.assertEqual(console.orchestrator.profile_provider.base_url, "https://dpp1.esim.example.test")

    def test_download_redirects_activation_code_into_profile_flow(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)

            keep_running = console._cmd_eim_download("1$dpp1.esim.example.test$MATCH-55$1.2.3")

            self.assertTrue(keep_running)
            self.assertEqual(console.orchestrator.eim_poll_calls, [])
            self.assertEqual(console.orchestrator.run_flow_calls, [("MATCH-55", "dpp1.esim.example.test")])
            self.assertEqual(console.current_es9_base_url, "https://dpp1.esim.example.test")

    def test_execute_command_does_not_double_sync_when_handler_already_synced(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console.apdu_channel.notification_responses = [_notification_list_response([])]

            def handler(argument):
                console._sync_notifications_after_success(b"\xAA")
                return True

            console._commands["DOWNLOAD"].handler = handler
            keep_running = console._execute_command("DOWNLOAD", "")

            self.assertTrue(keep_running)
            self.assertEqual(console.orchestrator.sync_calls, [b"\xAA"])

    def test_profile_table_colors_enabled_green_and_disabled_red(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            console._style = module.ConsoleStyle("", "", "<G>", "", "<R>", "", "</>")
            rows = [
                module.ProfileRow(
                    iccid="89103000000477637736",
                    state="ENABLED",
                    profile_class="OPER",
                    nickname="One",
                    aid="A0000005591010FFFFFFFF8900001100",
                ),
                module.ProfileRow(
                    iccid="89103000000477637737",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Two",
                    aid="A0000005591010FFFFFFFF8900001101",
                ),
            ]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                console._print_profiles_table(rows, title="Profiles on Card")

            rendered = buffer.getvalue()
            self.assertIn("<G>ENABLED", rendered)
            self.assertIn("<R>DISABLED", rendered)
            self.assertIn("A0000005591010FFFFFFFF8900001100 (ISDP1)", rendered)

    def test_get_metadata_prints_additional_profile_fields(self):
        for module in [self.live_module, self.test_module]:
            console = self._build_console(module)
            metadata_rows = console._decode_profile_metadata_rows(_profile_metadata_response_with_extra_field())
            self.assertEqual(len(metadata_rows), 1)
            self.assertIn(("8B", "02"), metadata_rows[0].additional_fields)
            console._find_profile_metadata = lambda _: metadata_rows[0]
            buffer = io.StringIO()

            with redirect_stdout(buffer):
                keep_running = console._cmd_get_metadata("dummy")

            rendered = buffer.getvalue()
            self.assertTrue(keep_running)
            self.assertIn("Additional Fields", rendered)
            self.assertIn("8B", rendered)
            self.assertIn("02", rendered)


if __name__ == "__main__":
    unittest.main()
