import unittest
import importlib.util
import sys
import io
import contextlib
from pathlib import Path
from unittest import mock

CONSOLE_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "console.py"
LIVE_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "live" / "console.py"
TEST_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "test" / "console.py"
spec = importlib.util.spec_from_file_location("scp11_console_module", CONSOLE_PATH)
console_module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
sys.modules[spec.name] = console_module
spec.loader.exec_module(console_module)
SCP11Console = console_module.SCP11Console


def _load_console_module(module_name: str, module_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + encode_length(len(value)) + value


class DummyCfg:
    RSP_SERVER_URL = "rsp.default.example"
    ES9_BASE_URL = "https://rsp.default.example"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


class DummyApduChannel:
    def __init__(self):
        self.send_calls = []
        self.response = bytes.fromhex("BF3203800100")
        self.configured_data_response = tlv(
            bytes.fromhex("BF3C"),
            tlv(bytes.fromhex("80"), b"rsp.default.example"),
        )

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "GET: EuiccConfiguredData":
            return self.configured_data_response
        if log_name == "SET: Default SM-DP+ Address":
            return bytes.fromhex("BF3F03800100")
        return self.response


class DummyProfileProvider:
    def __init__(self):
        self.base_url = DummyCfg.ES9_BASE_URL

    def set_base_url(self, base_url: str) -> None:
        self.base_url = base_url


class DummyOrchestrator:
    def __init__(self):
        self.sync_calls = []
        self.eim_poll_calls = []
        self.run_flow_calls = []
        self.profile_provider = DummyProfileProvider()

    def _sync_pending_notifications(self, response: bytes = b"") -> None:
        self.sync_calls.append(response)

    def run_eim_poll(self, matching_id: str = "", entry_index: int = 0) -> None:
        self.eim_poll_calls.append((matching_id, entry_index))

    def run_flow(self, matching_id: str = "", smdp_address: str = "") -> None:
        self.run_flow_calls.append((matching_id, smdp_address))


class DummyClient:
    def __init__(self):
        self.cfg = DummyCfg()
        self.apdu_channel = DummyApduChannel()
        self.orchestrator = DummyOrchestrator()


class DummyModuleStateStore:
    def __init__(self):
        self.replaced: list[tuple[str, dict]] = []

    def get_module_state(self, module_name: str) -> dict:
        _ = module_name
        return {}

    def replace_module_state(self, module_name: str, payload: dict) -> dict:
        stored_payload = dict(payload)
        self.replaced.append((module_name, stored_payload))
        return stored_payload


class SCP11ConsoleStatusDecodeTests(unittest.TestCase):
    def setUp(self):
        self.console = SCP11Console(DummyClient())
        self.console._aid_registry = {
            "ISDP1": "A0000005591010FFFFFFFF8900001100",
            "ISDP2": "A0000005591010FFFFFFFF8900001200",
        }

    def test_decode_euicc_configured_data_extracts_addresses(self):
        default_smdp = b"rsp.example.com"
        primary_smds = b"lpa.ds.gsma.com"
        additional_smds_1 = b"smds1.example.com"
        additional_smds_2 = b"smds2.example.com"
        allowed_ci_pkid = b"\xAA\xBB\xCC\xDD"

        nested_additional = tlv(bytes.fromhex("82"), additional_smds_1) + tlv(
            bytes.fromhex("82"),
            additional_smds_2,
        )
        inner = (
            tlv(bytes.fromhex("80"), default_smdp)
            + tlv(bytes.fromhex("81"), primary_smds)
            + tlv(bytes.fromhex("A2"), nested_additional)
            + tlv(bytes.fromhex("83"), allowed_ci_pkid)
        )
        payload = tlv(bytes.fromhex("BF3C"), inner)

        decoded = self.console._decode_euicc_configured_data(payload)

        self.assertEqual(decoded["default_smdp"], "rsp.example.com")
        self.assertEqual(decoded["root_smds_primary"], "lpa.ds.gsma.com")
        self.assertEqual(
            decoded["root_smds_additional"],
            ["smds1.example.com", "smds2.example.com"],
        )
        self.assertEqual(decoded["allowed_ci_pkid"], ["AABBCCDD"])

    def test_decode_accepts_inner_payload_without_bf3c_wrapper(self):
        inner = tlv(bytes.fromhex("80"), b"rsp.inner.example")
        decoded = self.console._decode_euicc_configured_data(inner)
        self.assertEqual(decoded["default_smdp"], "rsp.inner.example")

    def test_print_euicc_info2_compact_uses_sgp32_field_mapping(self):
        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.console._print_euicc_info2_compact(response)

        rendered = output.getvalue()

        self.assertIn("Forbidden Profile Policy Rules", rendered)
        self.assertIn("PP Version", rendered)
        self.assertIn("v255.255.255 (FFFFFF)", rendered)
        self.assertIn("IPA Mode", rendered)
        self.assertIn("ipae (IPAe is active)", rendered)
        self.assertIn("IoT Specific Info", rendered)
        self.assertIn("eCall Supported", rendered)
        self.assertIn("SGP.32 Validation", rendered)
        self.assertNotIn("PP Rules", rendered)
        self.assertNotIn("eUICC Category       : v2.3.0", rendered)

    def test_build_enable_profile_payload_matches_expected_shape(self):
        payload = self.console._build_profile_command_payload(
            func_tag=self.console.TAG_ENABLE_PROFILE,
            tag_type=self.console.TAG_ICCID,
            value_hex="981032547698103254F6",
        )
        self.assertEqual(payload.hex().upper(), "BF3111A00C5A0A981032547698103254F6810100")

    def test_build_delete_profile_payload_matches_expected_shape(self):
        payload = self.console._build_profile_command_payload(
            func_tag=self.console.TAG_DELETE_PROFILE,
            tag_type=self.console.TAG_AID,
            value_hex="A0000005591010FFFFFFFF8900001100",
        )
        self.assertEqual(payload.hex().upper(), "BF33124F10A0000005591010FFFFFFFF8900001100")

    def test_queue_modem_refresh_stays_silent_when_hil_bridge_is_unavailable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with mock.patch.object(console_module, "trigger_card_relay_modem_refresh", return_value=None):
                self.console._queue_modem_refresh("DeleteProfile")

        self.assertEqual(output.getvalue(), "")

    def test_build_remove_notification_payload(self):
        payload = self.console._build_remove_notification_payload(7)
        self.assertEqual(payload.hex().upper(), "BF3003800107")

    def test_build_remove_notification_payload_encodes_high_bit_sequence_as_positive_integer(self):
        payload = self.console._build_remove_notification_payload(148)
        self.assertEqual(payload.hex().upper(), "BF300480020094")

    def test_remove_notification_uses_delete_notification_status_labels(self):
        self.console.apdu_channel.response = bytes.fromhex("BF3003800101")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            keep_running = self.console._cmd_remove_notification("148")

        rendered = output.getvalue()

        self.assertTrue(keep_running)
        self.assertIn("nothingToDelete(1)", rendered)
        self.assertEqual(
            self.console.apdu_channel.send_calls[-1][1],
            bytes.fromhex("80E2910007BF300480020094"),
        )

    def test_encode_iccid_for_command(self):
        encoded = self.console._encode_iccid_for_command("8901234567890123456")
        self.assertEqual(encoded, "981032547698103254F6")

    def test_resolve_profile_target_by_alias(self):
        resolved = self.console._resolve_profile_target("isdp1")
        self.assertEqual(resolved, (self.console.TAG_AID, "A0000005591010FFFFFFFF8900001100"))

    def test_resolve_profile_target_by_decimal_iccid_prefers_encoded_metadata_value(self):
        self.console._fetch_profiles = lambda: [
            console_module.ProfileMetadataView(
                iccid="89880811111111111112",
                aid="A0000005591010FFFFFFFF8900001303",
                state="DISABLED",
                profile_class="OPER",
                nickname="Sample Lab",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            )
        ]

        resolved = self.console._resolve_profile_target("89880811111111111112")

        self.assertEqual(
            resolved,
            (self.console.TAG_ICCID, "98888011111111111121"),
        )

    def test_live_and_test_console_resolve_decimal_and_encoded_iccid_consistently(self):
        live_module = _load_console_module("scp11_live_console_target_resolution", LIVE_CONSOLE_PATH)
        test_module = _load_console_module("scp11_test_console_target_resolution", TEST_CONSOLE_PATH)

        for module in (live_module, test_module):
            console = module.SCP11Console(DummyClient())
            console._aid_registry = {
                "ISDP1": "A0000005591010FFFFFFFF8900001100",
            }
            console._fetch_profiles = lambda module=module: [
                module.ProfileMetadataView(
                    iccid="89880811111111111112",
                    aid="A0000005591010FFFFFFFF8900001303",
                    state="DISABLED",
                    profile_class="OPER",
                    nickname="Sample Lab",
                    service_provider="",
                    profile_name="",
                    profile_policy_rules_hex="",
                )
            ]

            self.assertEqual(
                console._resolve_profile_target("89880811111111111112"),
                (console.TAG_ICCID, "98888011111111111121"),
            )
            self.assertEqual(
                console._resolve_profile_target("98888011111111111121"),
                (console.TAG_ICCID, "98888011111111111121"),
            )
            self.assertEqual(
                console._resolve_profile_target("A0000005591010FFFFFFFF8900001303"),
                (console.TAG_AID, "A0000005591010FFFFFFFF8900001303"),
            )

    def test_persist_config_line_uses_runtime_module_state_without_eid(self):
        store = DummyModuleStateStore()
        self.console._inventory.store = store
        self.console.current_eid = ""
        self.console.current_es9_base_url = "https://persist.example.com"

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.console._persist_config_line(
                "ES9_BASE_URL: str =",
                '"https://persist.example.com"',
                "ES9_BASE_URL",
            )

        self.assertEqual(len(store.replaced), 1)
        module_name, payload = store.replaced[0]
        self.assertEqual(module_name, self.console.MODULE_STATE_NAME)
        self.assertEqual(payload["es9_base_url"], "https://persist.example.com")
        self.assertIn("runtime state", output.getvalue())

    def test_enable_profile_auto_disables_current_enabled_profile(self):
        profiles = [
            console_module.ProfileMetadataView(
                iccid="8901000000000000001",
                aid="A0000005591010FFFFFFFF8900001100",
                state="ENABLED",
                profile_class="OPER",
                nickname="Primary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
            console_module.ProfileMetadataView(
                iccid="8901000000000000002",
                aid="A0000005591010FFFFFFFF8900001200",
                state="DISABLED",
                profile_class="OPER",
                nickname="Secondary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
        ]
        executed = []
        self.console._collect_profile_metadata = lambda: profiles
        self.console._execute_profile_state_command = lambda resolved, func_tag, action_label: executed.append(
            (resolved, func_tag, action_label)
        ) or True

        self.console._run_profile_state_command(
            identifier="8901000000000000002",
            func_tag=self.console.TAG_ENABLE_PROFILE,
            action_label="EnableProfile",
            command_name="ENABLE-PROFILE",
        )

        self.assertEqual(
            executed,
            [
                ((self.console.TAG_AID, "A0000005591010FFFFFFFF8900001100"), self.console.TAG_DISABLE_PROFILE, "DisableProfile"),
                ((self.console.TAG_ICCID, "981000000000000000F2"), self.console.TAG_ENABLE_PROFILE, "EnableProfile"),
            ],
        )

    def test_enable_profile_refuses_auto_disable_when_active_profile_ppr1_forbids_disable(self):
        profiles = [
            console_module.ProfileMetadataView(
                iccid="8901000000000000001",
                aid="A0000005591010FFFFFFFF8900001100",
                state="ENABLED",
                profile_class="OPER",
                nickname="Primary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="0640",
            ),
            console_module.ProfileMetadataView(
                iccid="8901000000000000002",
                aid="A0000005591010FFFFFFFF8900001200",
                state="DISABLED",
                profile_class="OPER",
                nickname="Secondary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
        ]
        executed = []
        self.console._collect_profile_metadata = lambda: profiles
        self.console._execute_profile_state_command = lambda resolved, func_tag, action_label: executed.append(
            (resolved, func_tag, action_label)
        ) or True

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.console._run_profile_state_command(
                identifier="8901000000000000002",
                func_tag=self.console.TAG_ENABLE_PROFILE,
                action_label="EnableProfile",
                command_name="ENABLE-PROFILE",
            )

        self.assertEqual(executed, [])
        self.assertIn("guarded mode refused to auto-disable active profile", output.getvalue())
        self.assertIn("ppr1-disable-not-allowed", output.getvalue())

    def test_disable_profile_noops_when_target_already_disabled(self):
        profiles = [
            console_module.ProfileMetadataView(
                iccid="8901000000000000002",
                aid="A0000005591010FFFFFFFF8900001200",
                state="DISABLED",
                profile_class="OPER",
                nickname="Secondary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
        ]
        executed = []
        self.console._collect_profile_metadata = lambda: profiles
        self.console._execute_profile_state_command = lambda resolved, func_tag, action_label: executed.append(
            (resolved, func_tag, action_label)
        ) or True

        self.console._run_profile_state_command(
            identifier="8901000000000000002",
            func_tag=self.console.TAG_DISABLE_PROFILE,
            action_label="DisableProfile",
            command_name="DISABLE-PROFILE",
        )

        self.assertEqual(executed, [])

    def test_delete_enabled_profile_auto_switches_before_delete(self):
        profiles = [
            console_module.ProfileMetadataView(
                iccid="8901000000000000001",
                aid="A0000005591010FFFFFFFF8900001100",
                state="ENABLED",
                profile_class="OPER",
                nickname="Primary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
            console_module.ProfileMetadataView(
                iccid="8901000000000000002",
                aid="A0000005591010FFFFFFFF8900001200",
                state="DISABLED",
                profile_class="OPER",
                nickname="Secondary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
        ]
        executed = []
        self.console._collect_profile_metadata = lambda: profiles
        self.console._execute_profile_state_command = lambda resolved, func_tag, action_label: executed.append(
            (resolved, func_tag, action_label)
        ) or True

        self.console._run_profile_state_command(
            identifier="8901000000000000001",
            func_tag=self.console.TAG_DELETE_PROFILE,
            action_label="DeleteProfile",
            command_name="DELETE-PROFILE",
        )

        self.assertEqual(
            executed,
            [
                ((self.console.TAG_AID, "A0000005591010FFFFFFFF8900001100"), self.console.TAG_DISABLE_PROFILE, "DisableProfile"),
                ((self.console.TAG_AID, "A0000005591010FFFFFFFF8900001200"), self.console.TAG_ENABLE_PROFILE, "EnableProfile"),
                ((self.console.TAG_ICCID, "981000000000000000F1"), self.console.TAG_DELETE_PROFILE, "DeleteProfile"),
            ],
        )

    def test_enable_profile_sequence_queues_single_modem_refresh_after_success(self):
        profiles = [
            console_module.ProfileMetadataView(
                iccid="8901000000000000001",
                aid="A0000005591010FFFFFFFF8900001100",
                state="ENABLED",
                profile_class="OPER",
                nickname="Primary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
            console_module.ProfileMetadataView(
                iccid="8901000000000000002",
                aid="A0000005591010FFFFFFFF8900001200",
                state="DISABLED",
                profile_class="OPER",
                nickname="Secondary",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            ),
        ]
        executed = []
        refreshes = []
        self.console._collect_profile_metadata = lambda: profiles
        self.console._execute_profile_state_command = lambda resolved, func_tag, action_label: executed.append(
            (resolved, func_tag, action_label)
        ) or True
        self.console._queue_modem_refresh = lambda action_label, mode="": refreshes.append((action_label, mode))

        self.console._run_profile_state_command(
            identifier="8901000000000000002",
            func_tag=self.console.TAG_ENABLE_PROFILE,
            action_label="EnableProfile",
            command_name="ENABLE-PROFILE",
        )

        self.assertEqual(
            executed,
            [
                ((self.console.TAG_AID, "A0000005591010FFFFFFFF8900001100"), self.console.TAG_DISABLE_PROFILE, "DisableProfile"),
                ((self.console.TAG_ICCID, "981000000000000000F2"), self.console.TAG_ENABLE_PROFILE, "EnableProfile"),
            ],
        )
        self.assertEqual(refreshes, [("EnableProfile", "")])

    def test_refresh_modem_command_delegates_to_queue_helper(self):
        calls = []
        self.console._queue_modem_refresh = lambda action_label, mode="": calls.append((action_label, mode))

        keep_running = self.console._cmd_refresh_modem("uicc-reset")

        self.assertTrue(keep_running)
        self.assertEqual(calls, [("RefreshModem", "uicc-reset")])

    def test_execute_result_command_syncs_notifications_on_success(self):
        self.console._execute_result_command(
            title="DisableProfile",
            payload=bytes.fromhex("BF3200"),
            result_outer_tag=self.console.TAG_DISABLE_PROFILE,
        )

        self.assertEqual(len(self.console.apdu_channel.send_calls), 1)
        self.assertEqual(self.console.apdu_channel.send_calls[0][0], "CMD: DisableProfile")
        self.assertEqual(
            self.console.orchestrator.sync_calls,
            [bytes.fromhex("BF3203800100")],
        )

    def test_set_smdp_address_uses_verified_card_value(self):
        self.console.apdu_channel.configured_data_response = tlv(
            bytes.fromhex("BF3C"),
            tlv(bytes.fromhex("80"), b"smdpplus.example.test"),
        )

        self.console._set_smdp_address("wrong-input.example.test")

        self.assertEqual(self.console.current_smdp_address, "smdpplus.example.test")

    def test_eim_download_routes_into_orchestrator_flow(self):
        self.console._cmd_eim_download("MATCH-55")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("MATCH-55", 0)])

    def test_download_activation_code_updates_es9_base_url_from_server(self):
        self.console._download_activation_code("1$smdpplus.example.test$MATCH-55$1.2.3")

        self.assertEqual(self.console.current_smdp_address, "smdpplus.example.test")
        self.assertEqual(self.console.current_es9_base_url, "https://smdpplus.example.test")
        self.assertEqual(
            self.console.orchestrator.run_flow_calls,
            [("MATCH-55", "smdpplus.example.test")],
        )
        self.assertEqual(
            self.console.orchestrator.profile_provider.base_url,
            "https://smdpplus.example.test",
        )


if __name__ == "__main__":
    unittest.main()
