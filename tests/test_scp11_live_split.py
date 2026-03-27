import os
import unittest
from types import SimpleNamespace
from unittest import mock

from main import main as main_wrapper
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


class LiveSplitTests(unittest.TestCase):
    def test_live_config_paths_resolve_inside_live_tree(self):
        cfg = LiveConfig()
        self.assertIn(os.path.join("SCP11", "live"), cfg.CERT_PATH_AUTH)
        self.assertIn(os.path.join("SCP11", "live"), cfg.KEY_PATH_PB)

    def test_test_config_paths_resolve_inside_test_tree(self):
        cfg = RelayTestConfig()
        self.assertIn(os.path.join("SCP11", "test"), cfg.CERT_PATH_AUTH)
        self.assertIn(os.path.join("SCP11", "test"), cfg.KEY_PATH_PB)

    def test_main_wrapper_launches_live_shell(self):
        with mock.patch("main.main.importlib.reload", side_effect=lambda module: module):
            with mock.patch("SCP11.live.main.SGP22Client.run_shell") as mocked:
                main_wrapper.run_scp11_live()
        mocked.assert_called_once_with()

    def test_main_wrapper_launches_test_shell(self):
        with mock.patch("main.main.importlib.reload", side_effect=lambda module: module):
            with mock.patch("SCP11.test.main.SGP22Client.run_shell") as mocked:
                main_wrapper.run_scp11_test()
        mocked.assert_called_once_with()

    def test_main_wrapper_launches_local_entry(self):
        with mock.patch("main.main.importlib.reload", side_effect=lambda module: module):
            with mock.patch("SCP11.local_access.main.entry") as mocked:
                main_wrapper.run_scp11_local()
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

if __name__ == "__main__":
    unittest.main()
