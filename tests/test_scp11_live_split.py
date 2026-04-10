import base64
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "live_split_main_wrapper",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)
import SCP11.live.main as scp11_live_main
from SCP11.live.config import SGPConfig as LiveConfig
from SCP11.live.es9_client import Es9LikeClient
from SCP11.live.models import EimPollRequest
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.test.config import SGPConfig as RelayTestConfig


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_der_length(len(value)) + value


class MinimalApduChannel:
    def __init__(
        self,
        configured_data_response: bytes,
        eim_configuration_response: bytes,
        eid_response: bytes,
    ):
        self.configured_data_response = configured_data_response
        self.eim_configuration_response = eim_configuration_response
        self.eid_response = eid_response
        self.send_calls = []

    def reset(self) -> bool:
        return False

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if "GetEuiccConfiguredData" in log_name:
            return self.configured_data_response
        if "GetEimConfigurationData" in log_name:
            return self.eim_configuration_response
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccInfo2" in log_name:
            return bytes.fromhex("BF2200")
        if "GetEID" in log_name:
            return self.eid_response
        return b""


class HandshakeStkBootstrapApduChannel:
    def __init__(self):
        self.send_calls = []
        self._fail_info1_once = True

    def reset(self) -> bool:
        return False

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "HANDSHAKE: GetEuiccInfo1" and self._fail_info1_once:
            self._fail_info1_once = False
            raise IOError("APDU Failed: 6985")
        if "[STK MODE TERMINAL CAPABILITY]" in log_name:
            return b""
        if "[STK MODE SELECT ISD-R]" in log_name:
            return b""
        if "[STK MODE TERMINAL PROFILE]" in log_name:
            return b""
        if "[STK MODE CH1]" in log_name and "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "[STK MODE CH1]" in log_name and "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        return b""


class ResetTrackingApduChannel(MinimalApduChannel):
    def __init__(self):
        super().__init__(
            configured_data_response=b"",
            eim_configuration_response=b"",
            eid_response=b"",
        )
        self.reset_calls = 0

    def reset(self) -> bool:
        self.reset_calls += 1
        return True


class TimeoutProvider:
    def __init__(self):
        self.poll_eim_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        raise TimeoutError("The read operation timed out")


class NoPackageProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        return SimpleNamespace(
            transaction_id="",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {}


class SequencedPollProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        return SimpleNamespace(
            transaction_id="TX-1",
            euicc_package_list=["BF5103800101"],
            package_format="",
            polling_complete=False,
            retry_after_seconds=0,
            eim_result_code=None,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        if len(self.provide_eim_package_result_calls) == 1:
            return {
                "transactionId": "TX-2",
                "euiccPackageList": ["BF5103800102"],
                "pollingComplete": False,
                "retryAfterSeconds": 0,
            }
        return {
            "transactionId": "TX-2",
            "euiccPackageList": [],
            "pollingComplete": True,
            "retryAfterSeconds": 0,
        }


class StagedPollApduChannel:
    def __init__(
        self,
        configured_data_response: bytes,
        eim_configuration_response: bytes,
        eid_response: bytes,
        fetch_data: bytes = bytes.fromhex("D009810301260082028182"),
    ):
        self.configured_data_response = configured_data_response
        self.eim_configuration_response = eim_configuration_response
        self.eid_response = eid_response
        self.fetch_data = fetch_data
        self.send_calls = []
        self.exchange_calls = []

    def reset(self) -> bool:
        return False

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if "GetEuiccConfiguredData" in log_name:
            return self.configured_data_response
        if "GetEimConfigurationData" in log_name:
            return self.eim_configuration_response
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccInfo2" in log_name:
            return bytes.fromhex("BF2208810362F210840100")
        if "GetEID" in log_name:
            return self.eid_response
        return b""

    def exchange(self, apdu: bytes, log_name: str):
        self.exchange_calls.append((log_name, apdu))
        if "STATUS" in log_name:
            return b"", 0x91, 0x09
        if "FETCH" in log_name:
            return self.fetch_data, 0x90, 0x00
        return b"", 0x90, 0x00


class InstallCaptureApduChannel:
    def __init__(self):
        self.send_calls = []

    def reset(self) -> bool:
        return False

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "LoadBoundProfilePackage" in log_name:
            return b""
        return b""


class LogicalChannelCaptureApduChannel:
    def __init__(self):
        self.send_calls = []
        self.send_chunked_calls = []

    def reset(self) -> bool:
        return False

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "INIT: OPEN LOGICAL CHANNEL":
            return b"\x01"
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        return b""

    def send_chunked(self, cla, ins, p1, p2_start, payload, log_name, chunk_size=250):
        self.send_chunked_calls.append((cla, ins, p1, p2_start, payload, log_name, chunk_size))
        if "PrepareDownload" in log_name:
            return bytes.fromhex("BF2100")
        if "AuthenticateServer" in log_name:
            return bytes.fromhex("BF3800")
        return b""


class LiveSplitTests(unittest.TestCase):
    def test_live_config_paths_resolve_inside_live_tree(self):
        cfg = LiveConfig()
        self.assertIn(os.path.join("Workspace", "SCP11", "live"), cfg.CERT_PATH_AUTH)
        self.assertIn(os.path.join("Workspace", "SCP11", "live"), cfg.KEY_PATH_PB)

    def test_test_config_paths_resolve_inside_test_tree(self):
        cfg = RelayTestConfig()
        self.assertIn(os.path.join("Workspace", "SCP11", "test"), cfg.CERT_PATH_AUTH)
        self.assertIn(os.path.join("Workspace", "SCP11", "test"), cfg.KEY_PATH_PB)

    def test_main_wrapper_launches_live_shell(self):
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("SCP11.live.main.SGP22Client.run_shell") as mocked:
                main_wrapper.run_scp11_live()
        mocked.assert_called_once_with()

    def test_main_wrapper_launches_test_shell(self):
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("SCP11.test.main.SGP22Client.run_shell") as mocked:
                main_wrapper.run_scp11_test()
        mocked.assert_called_once_with()

    def test_live_client_applies_global_debug_to_transport(self):
        fake_channel = SimpleNamespace(set_raw_apdu_logging=mock.Mock())
        client = scp11_live_main.SGP22Client.__new__(scp11_live_main.SGP22Client)
        client.cfg = SimpleNamespace()
        client.apdu_channel = None
        client.profile_provider = None
        client.orchestrator = None
        client._build_apdu_channel = mock.Mock(return_value=fake_channel)
        client._build_profile_provider = mock.Mock(return_value=object())
        client._orchestrator_cls = lambda **kwargs: SimpleNamespace()

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            scp11_live_main.SGP22Client._build_runtime(client)

        fake_channel.set_raw_apdu_logging.assert_called_once_with(True)

    def test_main_wrapper_launches_local_entry(self):
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("SCP11.local_access.main.entry") as mocked:
                main_wrapper.run_scp11_local()
        mocked.assert_called_once_with()

    def test_main_wrapper_launches_local_eim_entry(self):
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("SCP11.eim_local.main.entry") as mocked:
                main_wrapper.run_scp11_eim_local()
        mocked.assert_called_once_with()

    def test_main_menu_alpha_choices_route_esim_and_local_shells(self):
        with mock.patch.object(main_wrapper, "run_scp11_live") as mocked_live:
            main_wrapper._dispatch_main_menu_choice("3A")
        mocked_live.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp11_test") as mocked_test:
            main_wrapper._dispatch_main_menu_choice("3B")
        mocked_test.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp11_local") as mocked_local:
            main_wrapper._dispatch_main_menu_choice("3C")
        mocked_local.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp11_eim_local") as mocked_eim_local:
            main_wrapper._dispatch_main_menu_choice("3D")
        mocked_eim_local.assert_called_once_with()

    def test_main_menu_alpha_choices_route_automation_entries(self):
        with mock.patch.object(main_wrapper, "run_scp03_script") as mocked_script:
            main_wrapper._dispatch_main_menu_choice("9A")
        mocked_script.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp03_report") as mocked_report:
            main_wrapper._dispatch_main_menu_choice("9B")
        mocked_report.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp80_script") as mocked_ota_script:
            main_wrapper._dispatch_main_menu_choice("9C")
        mocked_ota_script.assert_called_once_with()

    def test_main_menu_legacy_numeric_choices_remain_compatible(self):
        with mock.patch.object(main_wrapper, "run_scp11_live") as mocked_live:
            main_wrapper._dispatch_main_menu_choice("3")
        mocked_live.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp03_report") as mocked_report:
            main_wrapper._dispatch_main_menu_choice("10")
        mocked_report.assert_called_once_with()

    def test_live_build_eim_poll_request_uses_minimal_bf4f(self):
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com"))
        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    b"".join(
                        [
                            wrap_tlv("80", b"manager-1"),
                            wrap_tlv("81", b"eim1.sm.1ot.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        apdu_channel = MinimalApduChannel(
            configured_data_response=configured_data,
            eim_configuration_response=eim_configuration,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        cfg = SimpleNamespace(
            AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            EIM_EUICC_CHALLENGE_ASN1=True,
        )
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_eim_card_challenge()
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(
            request.raw_body,
            bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
        )
        self.assertNotEqual(request.euicc_challenge, "")

    def test_live_profile_download_trigger_keeps_localized_bridge_base_url(self):
        provider = SimpleNamespace(set_base_url=mock.Mock())
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=SimpleNamespace(),
            profile_provider=provider,
        )
        orchestrator.localized_poll_bridge = SimpleNamespace(
            smdp_base_url="https://127.0.0.1:19443"
        )
        orchestrator.state.load_bpp_response = bytes.fromhex("BF3700")
        captured: dict[str, str] = {}

        def fake_run_flow(matching_id: str = "", smdp_address: str = "") -> None:
            captured["matching_id"] = matching_id
            captured["smdp_address"] = smdp_address

        orchestrator.run_flow = fake_run_flow
        package = wrap_tlv(
            "BF54",
            wrap_tlv("82", b"\x01\x02\x03\x04")
            + wrap_tlv("30", wrap_tlv("80", b"LPA:1$yggdrasim.smdpp.test.1ot.com$MATCH-54")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        provider.set_base_url.assert_called_once_with("https://127.0.0.1:19443")
        self.assertEqual(captured["matching_id"], "MATCH-54")
        self.assertEqual(captured["smdp_address"], "yggdrasim.smdpp.test.1ot.com")
        self.assertEqual(response, bytes.fromhex("BF5409820401020304BF3700"))

    def test_live_phase_connect_matches_test_certificate_bootstrap(self):
        apdu_channel = MinimalApduChannel(
            configured_data_response=b"",
            eim_configuration_response=b"",
            eid_response=b"",
        )
        cfg = SimpleNamespace(
            AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
        )
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_connect()

        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "INIT: TERMINAL CAPABILITY",
                "INIT: SELECT ISD-R",
            ],
        )
        self.assertEqual(
            apdu_channel.send_calls[0][1],
            bytes.fromhex("80AA000007A9058303170000"),
        )
        self.assertEqual(
            apdu_channel.send_calls[1][1],
            bytes.fromhex("00A4040010A0000005591010FFFFFFFF8900000100"),
        )

    def test_live_phase_connect_bootstraps_logical_channel_when_enabled(self):
        apdu_channel = LogicalChannelCaptureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                ES10B_USE_LOGICAL_CHANNEL=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_connect()

        self.assertEqual(orchestrator._es10b_logical_channel, 1)
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "INIT: TERMINAL CAPABILITY",
                "INIT: SELECT ISD-R",
                "INIT: EXTENDED TERMINAL CAPABILITY",
                "INIT: OPEN LOGICAL CHANNEL",
                "INIT: SELECT ISD-R CH1",
                "INIT: STATUS",
                "INIT: TERMINAL PROFILE",
            ],
        )
        self.assertEqual(apdu_channel.send_calls[3][1], bytes.fromhex("0070000001"))
        self.assertEqual(
            apdu_channel.send_calls[4][1],
            bytes.fromhex("01A4040010A0000005591010FFFFFFFF8900000100"),
        )
        self.assertEqual(apdu_channel.send_calls[5][1], bytes.fromhex("80F2000C00"))
        self.assertEqual(apdu_channel.send_calls[6][1], bytes.fromhex("80100000010C"))

    def test_live_phase_connect_does_not_reset_card_by_default(self):
        apdu_channel = ResetTrackingApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_connect()

        self.assertEqual(apdu_channel.reset_calls, 0)

    def test_live_phase_connect_can_opt_in_to_reset(self):
        apdu_channel = ResetTrackingApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                RESET_CARD_BEFORE_FLOW=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_connect()

        self.assertEqual(apdu_channel.reset_calls, 1)

    def test_live_authentication_seed_retries_with_stk_mode_after_6985(self):
        apdu_channel = HandshakeStkBootstrapApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        mocked_auth = mock.Mock(return_value={"provider": "live"})
        orchestrator._initiate_authentication_with_provider = mocked_auth

        orchestrator._phase_connect()
        auth_seed = orchestrator._phase_authentication_seed(
            matching_id="MATCH-LIVE-6985",
            smdp_address="rsp.example.com",
        )

        mocked_auth.assert_called_once_with(bytes.fromhex("BF2000"), smdp_address="rsp.example.com")
        self.assertEqual(auth_seed["provider"], "live")
        self.assertEqual(auth_seed["matching_id"], "MATCH-LIVE-6985")
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "INIT: TERMINAL CAPABILITY",
                "INIT: SELECT ISD-R",
                "HANDSHAKE: GetEuiccInfo1",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE TERMINAL CAPABILITY]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE SELECT ISD-R]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE TERMINAL PROFILE]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE CH1]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE TERMINAL CAPABILITY]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE SELECT ISD-R]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE TERMINAL PROFILE]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE CH1]",
            ],
        )

    def test_live_get_eim_package_timeout_raises_without_retry_logic(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=TimeoutProvider(),
        )
        request = EimPollRequest(
            eim_fqdn="eim1.sm.1ot.com",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            eid="89044045930000000000001492294428",
            raw_body=bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
        )

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._get_eim_package(request)

        self.assertIn("timed out", str(raised.exception))
        self.assertEqual(len(orchestrator.profile_provider.poll_eim_calls), 1)

    def test_live_es9_client_requires_binary_eim_body(self):
        client = Es9LikeClient(base_url="https://rsp.example.com")
        request = EimPollRequest(
            eim_fqdn="eim1.sm.1ot.com",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
        )

        with self.assertRaises(ValueError) as raised:
            client._dispatch_eim_request(request)

        self.assertIn("binary ASN.1 request body", str(raised.exception))

    def test_live_build_get_eim_package_tlv_supports_notify_and_rplmn(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=None,
        )

        payload = orchestrator._build_get_eim_package_tlv(
            "89044045930000000000001492294428",
            notify_state_change=True,
            state_change_cause=3,
            rplmn_bytes=bytes.fromhex("62F210"),
        )

        self.assertEqual(
            payload,
            bytes.fromhex(
                "BF4F1C5A1089044045930000000000001492294428"
                "8000"
                "810103"
                "820362F210"
            ),
        )

    def test_live_run_eim_poll_drains_follow_up_provide_result_rounds(self):
        provider = SequencedPollProvider()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=provider,
        )
        relayed_packages = []

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            if package_index == 1:
                return bytes.fromhex("BF3700")
            return bytes.fromhex("BF3701")

        orchestrator._relay_eim_package_to_card = fake_relay
        request = EimPollRequest(
            eim_fqdn="eim1.sm.1ot.com",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            eid="89044045930000000000001492294428",
            raw_body=bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
        )

        orchestrator._run_single_eim_poll_round(request)

        self.assertEqual(len(provider.poll_eim_calls), 1)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 2)
        self.assertEqual(provider.provide_eim_package_result_calls[0].transaction_id, "TX-1")
        self.assertEqual(provider.provide_eim_package_result_calls[1].transaction_id, "TX-2")
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
                (bytes.fromhex("BF5103800102"), 2, 1),
            ],
        )

    def test_live_install_preserves_bpp_section_framing_by_default(self):
        bf23_value = b"".join(
            [
                wrap_tlv("82", b"\x01"),
                wrap_tlv("80", b"\x10" * 8),
                wrap_tlv(
                    "A6",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x88"),
                            wrap_tlv("81", b"\x10"),
                            wrap_tlv("84", b"HOST"),
                        ]
                    ),
                ),
                wrap_tlv("5F49", b"\x04" * 65),
                wrap_tlv("5F37", b"\x05" * 64),
            ]
        )
        a0_member = wrap_tlv("87", b"\xAA\xBB")
        a1_member = wrap_tlv("88", b"\x01" * 4)
        a3_first_member = wrap_tlv("86", b"\xCC")
        a3_second_member = wrap_tlv("86", b"\xDD")
        bpp_bytes = wrap_tlv(
            "BF36",
            wrap_tlv("BF23", bf23_value)
            + wrap_tlv("A0", a0_member)
            + wrap_tlv("A1", a1_member)
            + wrap_tlv("A3", a3_first_member + a3_second_member),
        )
        euicc_signed2 = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"\x10" * 8),
                    wrap_tlv("5F49", b"\x06" * 65),
                ]
            ),
        )
        prepare_download_ok = wrap_tlv("30", euicc_signed2 + wrap_tlv("5F37", b"\x07" * 64))
        prepare_download_response = wrap_tlv("BF21", wrap_tlv("A0", prepare_download_ok))

        apdu_channel = InstallCaptureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                BPP_INSTALL_USE_SECTION_FRAMING=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        orchestrator.state.bpp_bytes = bpp_bytes
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        install_complete = orchestrator._phase_install_package()

        self.assertTrue(install_complete)
        load_calls = [call for call in apdu_channel.send_calls if call[0].startswith("DOWNLOAD: LoadBoundProfilePackage")]
        self.assertEqual(load_calls[2][0], "DOWNLOAD: LoadBoundProfilePackage [2/7] [Block 0]")
        self.assertEqual(
            load_calls[2][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(wrap_tlv("A0", a0_member))]) + wrap_tlv("A0", a0_member),
        )
        a1_header = bytes.fromhex("A1") + encode_der_length(len(a1_member))
        self.assertEqual(load_calls[3][0], "DOWNLOAD: LoadBoundProfilePackage [3/7] [Block 0]")
        self.assertEqual(
            load_calls[3][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(a1_header)]) + a1_header,
        )
        self.assertEqual(load_calls[4][0], "DOWNLOAD: LoadBoundProfilePackage [4/7] [Block 0]")
        self.assertEqual(
            load_calls[4][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(a1_member)]) + a1_member,
        )
        a3_header = bytes.fromhex("A3") + encode_der_length(len(a3_first_member + a3_second_member))
        self.assertEqual(load_calls[5][0], "DOWNLOAD: LoadBoundProfilePackage [5/7] [Block 0]")
        self.assertEqual(
            load_calls[5][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(a3_header)]) + a3_header,
        )
        self.assertEqual(load_calls[6][0], "DOWNLOAD: LoadBoundProfilePackage [6/7] [Block 0]")
        self.assertEqual(
            load_calls[6][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(a3_first_member)]) + a3_first_member,
        )
        self.assertEqual(load_calls[7][0], "DOWNLOAD: LoadBoundProfilePackage [7/7] [Block 0]")
        self.assertEqual(
            load_calls[7][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(a3_second_member)]) + a3_second_member,
        )

    def test_live_decode_prepare_download_response_extracts_nested_euicc_otpk_raw(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=None,
        )
        euicc_signed2 = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"\x10" * 8),
                    wrap_tlv("5F49", b"\x06" * 65),
                ]
            ),
        )
        prepare_download_ok = wrap_tlv("30", euicc_signed2 + wrap_tlv("5F37", b"\x07" * 64))
        prepare_download_response = wrap_tlv("BF21", wrap_tlv("A0", prepare_download_ok))

        decoded = orchestrator._decode_prepare_download_response_ok(prepare_download_response)

        self.assertEqual(decoded["transactionId"], b"\x10" * 8)
        self.assertEqual(decoded["euiccOtpk"], b"\x06" * 65)
        self.assertEqual(decoded["euiccOtpkRaw"], wrap_tlv("5F49", b"\x06" * 65))

    def test_live_prepare_download_uses_logical_channel_cla_when_active(self):
        apdu_channel = LogicalChannelCaptureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                ES10B_USE_LOGICAL_CHANNEL=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        orchestrator._phase_connect()
        orchestrator._get_prepare_download_payload_from_provider = lambda smdp_address: b"\xAA"

        orchestrator._phase_prepare_download(smdp_address="rsp.example.com")

        self.assertEqual(len(apdu_channel.send_chunked_calls), 1)
        cla, ins, p1, p2_start, payload, log_name, chunk_size = apdu_channel.send_chunked_calls[0]
        self.assertEqual((cla, ins, p1, p2_start), (0x81, 0xE2, 0x91, 0x00))
        self.assertEqual(payload, b"\xAA")
        self.assertEqual(log_name, "DOWNLOAD: PrepareDownload")
        self.assertEqual(chunk_size, 250)

    def test_live_install_uses_logical_channel_cla_when_active(self):
        bf23_value = b"".join(
            [
                wrap_tlv("82", b"\x01"),
                wrap_tlv("80", b"\x10" * 8),
                wrap_tlv(
                    "A6",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x88"),
                            wrap_tlv("81", b"\x10"),
                            wrap_tlv("84", b"HOST"),
                        ]
                    ),
                ),
                wrap_tlv("5F49", b"\x04" * 65),
                wrap_tlv("5F37", b"\x05" * 64),
            ]
        )
        a0_member = wrap_tlv("87", b"\xAA\xBB")
        a1_member = wrap_tlv("88", b"\x01" * 4)
        a3_member = wrap_tlv("86", b"\xCC")
        bpp_bytes = wrap_tlv(
            "BF36",
            wrap_tlv("BF23", bf23_value)
            + wrap_tlv("A0", a0_member)
            + wrap_tlv("A1", a1_member)
            + wrap_tlv("A3", a3_member),
        )
        euicc_signed2 = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"\x10" * 8),
                    wrap_tlv("5F49", b"\x06" * 65),
                ]
            ),
        )
        prepare_download_ok = wrap_tlv("30", euicc_signed2 + wrap_tlv("5F37", b"\x07" * 64))
        prepare_download_response = wrap_tlv("BF21", wrap_tlv("A0", prepare_download_ok))
        apdu_channel = InstallCaptureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                BPP_INSTALL_USE_SECTION_FRAMING=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        orchestrator._es10b_logical_channel = 1
        orchestrator.state.bpp_bytes = bpp_bytes
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        orchestrator._phase_install_package()

        load_calls = [call for call in apdu_channel.send_calls if call[0].startswith("DOWNLOAD: LoadBoundProfilePackage")]
        self.assertTrue(all(call[1][0] == 0x81 for call in load_calls))

if __name__ == "__main__":
    unittest.main()
