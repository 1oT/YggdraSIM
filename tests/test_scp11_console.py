# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest
import importlib.util
import sys
import io
import contextlib
from pathlib import Path

CONSOLE_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "live" / "console.py"
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
        self.raw_apdu_logging = False
        self.raw_logging_updates = []
        self.response = bytes.fromhex("BF3203800100")
        self.configured_data_response = tlv(
            bytes.fromhex("BF3C"),
            tlv(bytes.fromhex("80"), b"rsp.default.example"),
        )

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self.raw_apdu_logging = bool(enabled)
        self.raw_logging_updates.append(bool(enabled))

    def get_raw_apdu_logging(self) -> bool:
        return bool(self.raw_apdu_logging)

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
        primary_smds = b"root-smds.example.com"
        additional_smds_1 = b"smds1.example.com"
        additional_smds_2 = b"smds2.example.com"
        allowed_ci_pkid = b"\xAA\xBB\xCC\xDD"

        nested_additional = tlv(bytes.fromhex("0C"), additional_smds_1) + tlv(
            bytes.fromhex("0C"),
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
        self.assertEqual(decoded["root_smds_primary"], "root-smds.example.com")
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
        self.assertIn("LPA/IPA Mode", rendered)
        self.assertIn("IPAe active", rendered)
        self.assertIn("IoT Specific Info", rendered)
        self.assertIn("eCall Supported", rendered)
        self.assertIn("SGP.32 Validation", rendered)
        self.assertNotIn("PP Rules", rendered)
        self.assertNotIn("eUICC Category       : v2.3.0", rendered)

    def test_print_get_certs_compact_includes_full_der_hex(self):
        eum = bytes.fromhex("3003020101")
        euicc = bytes.fromhex("3003020102")
        response = tlv(
            bytes.fromhex("BF56"),
            tlv(bytes.fromhex("A5"), eum) + tlv(bytes.fromhex("A6"), euicc),
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.console._print_get_certs_compact(response)

        rendered = output.getvalue()

        self.assertIn("EUM Cert Bytes", rendered)
        self.assertIn("eUICC Cert Bytes", rendered)
        self.assertIn(f"EUM Cert DER Hex     : {eum.hex().upper()}", rendered)
        self.assertIn(f"eUICC Cert DER Hex   : {euicc.hex().upper()}", rendered)

    def test_print_get_certs_compact_renders_the_certificate_view(self):
        from tests.certificate_view_support import build_chain, get_certs_response

        chain = build_chain()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.console._print_get_certs_compact(get_certs_response(chain.eum, chain.euicc))

        rendered = output.getvalue()

        self.assertIn("Permitted EINs", rendered)
        self.assertIn("`-- eUICC Certificate", rendered)
        self.assertIn("signature valid", rendered)
        self.assertIn(f"EUM Cert DER Hex     : {chain.eum.hex().upper()}", rendered)

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
                iccid="89880811111111111111",
                aid="A0000005591010FFFFFFFF8900001303",
                state="DISABLED",
                profile_class="OPER",
                nickname="Sample Lab",
                service_provider="",
                profile_name="",
                profile_policy_rules_hex="",
            )
        ]

        resolved = self.console._resolve_profile_target("89880811111111111111")

        self.assertEqual(
            resolved,
            (self.console.TAG_ICCID, "98888011111111111111"),
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
                    iccid="89880811111111111111",
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
                console._resolve_profile_target("89880811111111111111"),
                (console.TAG_ICCID, "98888011111111111111"),
            )
            self.assertEqual(
                console._resolve_profile_target("98888011111111111111"),
                (console.TAG_ICCID, "98888011111111111111"),
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

    def test_delete_enabled_profile_auto_disables_before_delete(self):
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

        # SGP.22 v3.1 section 5.7.18 answers DeleteProfile on an enabled
        # Profile with profileNotInDisabledState, so the shared profile_actions
        # contract disables the target first and then deletes it; no other
        # Profile is enabled on its behalf.
        self.assertEqual(
            executed,
            [
                ((self.console.TAG_ICCID, "981000000000000000F1"), self.console.TAG_DISABLE_PROFILE, "DisableProfile"),
                ((self.console.TAG_ICCID, "981000000000000000F1"), self.console.TAG_DELETE_PROFILE, "DeleteProfile"),
            ],
        )

    def test_enable_profile_sequence_runs_without_refresh_side_effect(self):
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
            tlv(bytes.fromhex("80"), b"smdpplus2.smdpp.example.test"),
        )

        self.console._set_smdp_address("smdpplus2.esim.tst.1ot")

        self.assertEqual(self.console.current_smdp_address, "smdpplus2.smdpp.example.test")

    def test_eim_download_routes_into_orchestrator_flow(self):
        self.console._cmd_eim_download("MATCH-55")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("MATCH-55", 0)])

    def test_eim_download_selector_narrows_the_sweep_to_one_entry(self):
        self.console._cmd_eim_download("--2")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("", [1])])

    def test_eim_download_selector_keeps_a_matching_id(self):
        self.console._cmd_eim_download("MATCH-55 --1,2")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("MATCH-55", [0, 1])])

    def test_eim_download_selector_deduplicates_repeated_entries(self):
        self.console._cmd_eim_download("--2,2,1")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("", [1, 0])])

    def test_eim_download_rejects_a_malformed_selector_instead_of_polling(self):
        self.console._cmd_eim_download("--nope")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [])

    def test_eim_download_rejects_entry_zero(self):
        self.console._cmd_eim_download("--0")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [])

    def test_download_activation_code_updates_es9_base_url_from_server(self):
        self.console._download_activation_code("1$smdpplus2.smdpp.example.test$MATCH-55$1.2.3")

        self.assertEqual(self.console.current_smdp_address, "smdpplus2.smdpp.example.test")
        self.assertEqual(self.console.current_es9_base_url, "https://smdpplus2.smdpp.example.test")
        self.assertEqual(
            self.console.orchestrator.run_flow_calls,
            [("MATCH-55", "smdpplus2.smdpp.example.test")],
        )
        self.assertEqual(
            self.console.orchestrator.profile_provider.base_url,
            "https://smdpplus2.smdpp.example.test",
        )


class LiveConsoleCommandDebugFlagTests(unittest.TestCase):
    """``--debug`` is consumed by the dispatcher, not by each handler.

    Before this, ``DOWNLOAD --debug`` reached ``_cmd_eim_download`` as a
    positional and was relayed upstream as a matchingId.
    """

    def setUp(self):
        import os

        self._os = os
        self._env_key = "YGGDRASIM_GLOBAL_DEBUG"
        self._previous_env = os.environ.get(self._env_key)
        os.environ.pop(self._env_key, None)
        module = _load_console_module("scp11_live_console_debug_flag", LIVE_CONSOLE_PATH)
        self.console = module.SCP11Console(DummyClient())

    def tearDown(self):
        if self._previous_env is None:
            self._os.environ.pop(self._env_key, None)
        else:
            self._os.environ[self._env_key] = self._previous_env

    def test_debug_flag_is_stripped_instead_of_becoming_a_matching_id(self):
        self.console._execute_command("DOWNLOAD", "--debug")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("", 0)])

    def test_debug_flag_preserves_a_real_matching_id(self):
        self.console._execute_command("DOWNLOAD", "MATCH-55 --debug")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("MATCH-55", 0)])

    def test_entry_selector_survives_the_debug_flag_split(self):
        self.console._execute_command("DOWNLOAD", "--1,3 --debug")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("", [0, 2])])

    def test_rejected_entry_selector_does_not_reach_the_card(self):
        self.console._execute_command("DOWNLOAD", "--nope")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [])
        self.assertEqual(self.console.orchestrator.sync_calls, [])
        self.assertEqual(self.console.apdu_channel.send_calls, [])

    def test_debug_flag_latches_raw_apdu_logging_only_for_the_command(self):
        from yggdrasim_common.process_debug import is_global_debug_enabled

        channel = self.console.apdu_channel
        observed = {}

        def recording_poll(matching_id: str = "", entry_index: int = 0) -> None:
            observed["global_debug"] = is_global_debug_enabled()
            observed["raw_apdu"] = channel.get_raw_apdu_logging()

        self.console.orchestrator.run_eim_poll = recording_poll

        self.console._execute_command("DOWNLOAD", "--debug")

        self.assertTrue(observed["global_debug"])
        self.assertTrue(observed["raw_apdu"])
        self.assertFalse(channel.get_raw_apdu_logging())
        self.assertIsNone(self._os.environ.get(self._env_key))

    def test_absent_debug_flag_leaves_the_argument_and_the_flag_alone(self):
        channel = self.console.apdu_channel

        self.console._execute_command("DOWNLOAD", "MATCH-55")

        self.assertEqual(self.console.orchestrator.eim_poll_calls, [("MATCH-55", 0)])
        self.assertEqual(channel.raw_logging_updates, [])
        self.assertIsNone(self._os.environ.get(self._env_key))


class LiveConsoleFallbackAttributeTests(unittest.TestCase):
    """SGP.32 fallbackAttribute must survive into the profile listing.

    ES10b.ExecuteFallbackMechanism answers fallbackNotAvailable unless some
    Profile carries tag '9F26', so the listing is where an operator finds out
    whether the Fallback Mechanism can run on a given card at all.
    """

    @staticmethod
    def _tlv(tag_hex: str, value: bytes) -> bytes:
        tag = bytes.fromhex(tag_hex)
        return tag + bytes([len(value)]) + value

    def _profile(self, iccid_hex: str, state: int, fallback) -> bytes:
        body = (
            self._tlv("5A", bytes.fromhex(iccid_hex))
            + self._tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
            + self._tlv("9F70", bytes([state]))
            + self._tlv("95", bytes([2]))
            + self._tlv("90", b"Profile")
        )
        if fallback is not None:
            body += self._tlv("9F26", bytes([0xFF if fallback else 0x00]))
        return self._tlv("E3", body)

    def test_profile_rows_carry_the_fallback_attribute(self) -> None:
        module = _load_console_module("scp11_live_console_fallback_attr", LIVE_CONSOLE_PATH)
        console = object.__new__(module.SCP11Console)
        console._profile_info_tag_list_honoured = True
        raw = (
            self._profile("8988201234567890123F", 1, None)
            + self._profile("8988209876543210987F", 0, True)
            + self._profile("8988205555555555555F", 0, False)
        )

        rows = module.SCP11Console._decode_profiles_with_local_parser(console, raw)

        self.assertEqual([row.fallback for row in rows], [False, True, False])

    def test_an_untagged_read_reports_the_attribute_as_unknown(self) -> None:
        """A default-set response is silent about '9F26', not a denial of it.

        SGP.22 v3.1 §5.7.15 omits every tag-gated member from an untagged
        ProfileInfoListRequest, so absence there says nothing about whether a
        Fallback Profile exists.
        """
        module = _load_console_module("scp11_live_console_fallback_untagged", LIVE_CONSOLE_PATH)
        console = object.__new__(module.SCP11Console)
        raw = self._profile("8988201234567890123F", 1, None)

        rows = module.SCP11Console._decode_profiles_with_local_parser(console, raw)

        self.assertIsNone(rows[0].fallback)

    def test_the_profiles_request_names_the_fallback_tag(self) -> None:
        """The '5C' tag list is the only way '9F26' can reach the listing."""
        module = _load_console_module("scp11_live_console_fallback_request", LIVE_CONSOLE_PATH)
        console = object.__new__(module.SCP11Console)
        sent: list[bytes] = []

        def _capture(payload: bytes, log_name: str) -> bytes:
            sent.append(payload)
            return b""

        console._send_store_data_with_logical_fallback = _capture

        module.SCP11Console._fetch_profiles_raw(console)

        self.assertEqual(len(sent), 1)
        request = sent[0].hex().upper()
        self.assertTrue(request.startswith("BF2D"))
        self.assertIn("5C", request)
        self.assertIn("9F26", request)
        self.assertTrue(console._profile_info_tag_list_honoured)

    def test_a_refused_tag_list_falls_back_to_the_default_set(self) -> None:
        module = _load_console_module("scp11_live_console_fallback_refused", LIVE_CONSOLE_PATH)
        console = object.__new__(module.SCP11Console)
        sent: list[bytes] = []

        def _capture(payload: bytes, log_name: str) -> bytes:
            sent.append(payload)
            if len(sent) == 1:
                raise RuntimeError("APDU Failed: 6A80")
            return b""

        console._send_store_data_with_logical_fallback = _capture

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            module.SCP11Console._fetch_profiles_raw(console)

        self.assertEqual(sent[1], bytes.fromhex("BF2D00"))
        self.assertFalse(console._profile_info_tag_list_honoured)

    def test_the_listing_shows_a_fallback_column(self) -> None:
        module = _load_console_module("scp11_live_console_fallback_table", LIVE_CONSOLE_PATH)
        console = object.__new__(module.SCP11Console)
        console._profile_info_tag_list_honoured = True
        rows = module.SCP11Console._decode_profiles_with_local_parser(
            console,
            self._profile("8988209876543210987F", 0, True),
        )
        console._resolve_display_alias_for_aid = lambda aid: None
        console._format_profile_state = lambda state, width: f"{state:<{width}}"

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            module.SCP11Console._print_profiles_table(console, rows, "Profiles")
        output = buffer.getvalue()

        self.assertIn("FB", output.splitlines()[2])
        self.assertIn("yes", output)


if __name__ == "__main__":
    unittest.main()
