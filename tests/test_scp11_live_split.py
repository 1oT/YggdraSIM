import base64
import datetime
import io
import importlib.util
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


def build_self_signed_cert_der(common_name: str = "rsp.example.com") -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
        ]
    )
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        )
        .add_extension(
            crypto_x509.SubjectAlternativeName(
                [crypto_x509.DNSName(common_name)]
            ),
            critical=False,
        )
        .add_extension(
            crypto_x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


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

    def exchange(self, apdu: bytes, log_name: str) -> tuple[bytes, int, int]:
        self.send_calls.append((log_name, apdu))
        return b"", 0x90, 0x00

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if "GetEuiccConfiguredData" in log_name:
            return self.configured_data_response
        if "GetEimConfigurationData" in log_name:
            return self.eim_configuration_response
        if "InspectEimConfigurationData" in log_name:
            return self.eim_configuration_response
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccInfo2" in log_name:
            return bytes.fromhex("BF2200")
        if "GetEID" in log_name:
            return self.eid_response
        return b""


class HandshakeStkBootstrapApduChannel:
    """Stub apdu_channel that fails ES10b GetEuiccInfo1 with 6985 once and
    refuses the MANAGE CHANNEL recovery path so the orchestrator must
    fall through to the STK mode bootstrap. Mirrors the failure mode
    seen on terminals that reject supplementary channels entirely.
    """

    def __init__(self):
        self.send_calls = []
        self._fail_info1_once = True

    def reset(self) -> bool:
        return False

    def exchange(self, apdu: bytes, log_name: str) -> tuple[bytes, int, int]:
        self.send_calls.append((log_name, apdu))
        return b"", 0x90, 0x00

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "[OPEN LOGICAL CHANNEL]" in log_name:
            raise IOError("APDU Failed: 6881")
        if log_name == "HANDSHAKE: GetEuiccInfo1" and self._fail_info1_once:
            self._fail_info1_once = False
            raise IOError("APDU Failed: 6985")
        if "[STK MODE TERMINAL CAPABILITY]" in log_name:
            return b""
        if "[STK MODE SELECT ISD-R]" in log_name:
            return b""
        if "[STK MODE TERMINAL PROFILE]" in log_name:
            return b""
        if "[STK MODE BASIC]" in log_name and "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "[STK MODE BASIC]" in log_name and "GetEuiccChallenge" in log_name:
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


class _DummyEimBinaryResponseHandle:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._payload


class RecordingPinnedBypassEimClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_contexts = []
        self.open_pinned_spki_args = []
        self._verified_context = object()
        self._response_payload = b"{}"

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ):
        return self._verified_context

    def _open_http_response(
        self,
        request,
        ssl_context,
        endpoint: str,
        label: str,
        timeout_seconds: int | None = None,
        pinned_tls_spki: bytes | None = None,
    ):
        self.open_contexts.append(ssl_context)
        self.open_pinned_spki_args.append(pinned_tls_spki)
        return _DummyEimBinaryResponseHandle(self._response_payload)


class DynamicRetryEimClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_contexts = []
        self.use_configured_ca_bundle_flags = []
        self.dynamic_retry_calls = []
        self.bundle_paths = []
        self._initial_context = object()
        self._retry_context = object()
        self._response_payload = b"{}"

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ):
        self.use_configured_ca_bundle_flags.append(use_configured_ca_bundle)
        return self._initial_context

    def _resolve_dynamic_ca_bundle_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str,
        initial_error: Exception,
    ) -> str:
        self.dynamic_retry_calls.append(
            (endpoint, trust_hint_ci_pkid, str(initial_error))
        )
        return "/tmp/live-eim-dynamic-ca.pem"

    def _create_default_context_with_bundle(self, bundle_path: str):
        self.bundle_paths.append(bundle_path)
        return self._retry_context

    def _open_http_response(
        self,
        request,
        ssl_context,
        endpoint: str,
        label: str,
        timeout_seconds: int | None = None,
        pinned_tls_spki: bytes | None = None,
    ):
        self.open_contexts.append(ssl_context)
        if ssl_context is self._initial_context:
            raise IOError("certificate verify failed")
        return _DummyEimBinaryResponseHandle(self._response_payload)


class LeafFallbackEimClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.persisted_bundles = []
        self.handshake_bundle_paths = []
        self._leaf_bundle_path = "/tmp/live-eim-leaf.pem"

    def _fetch_server_certificate_chain_der(self, hostname: str, port: int) -> list[bytes]:
        return [build_self_signed_cert_der(hostname)]

    def _candidate_ca_bundle_paths(self, trust_hint_ci_pkid: str) -> list[str]:
        return []

    def _persist_presented_leaf_bundle(self, hostname: str, leaf_certificate):
        return self._leaf_bundle_path

    def _bundle_verifies_tls_handshake(
        self,
        endpoint: str,
        bundle_path: str,
        log_label: str = "ES9",
    ) -> bool:
        self.handshake_bundle_paths.append(bundle_path)
        return bundle_path == self._leaf_bundle_path

    def _remember_dynamic_ca_bundle(
        self,
        hostname: str,
        candidate_path: str,
        leaf_certificate,
        matched_subject: str,
        trust_hint_ci_pkid: str,
        chain_paths: list[str] | None = None,
        note: str = "",
    ) -> None:
        self.persisted_bundles.append(
            {
                "hostname": hostname,
                "candidate_path": candidate_path,
                "matched_subject": matched_subject,
                "trust_hint_ci_pkid": trust_hint_ci_pkid,
                "chain_paths": chain_paths,
                "note": note,
            }
        )


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


class MixedFailureSweepProvider:
    def __init__(self):
        self.poll_eim_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        call_index = len(self.poll_eim_calls)
        if call_index == 2:
            raise RuntimeError("certificate verify failed")
        return SimpleNamespace(
            transaction_id=f"tx-{call_index}",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )


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


class AcknowledgedPackageProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        if len(self.poll_eim_calls) == 1:
            return SimpleNamespace(
                transaction_id="TX-ACK",
                euicc_package_list=["BF5103800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return SimpleNamespace(
            transaction_id="TX-ACK",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "packageFormat": "eimAcknowledgements",
            "pollingComplete": True,
        }


class EmptyResponsePackageProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        if len(self.poll_eim_calls) == 1:
            return SimpleNamespace(
                transaction_id="TX-EMPTY",
                euicc_package_list=["BF5203800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return SimpleNamespace(
            transaction_id="TX-EMPTY",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "packageFormat": "emptyResponse",
            "pollingComplete": True,
        }


class DrainRoundSkipProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []
        self._per_fqdn_call_counts = {}

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        fqdn = str(getattr(request_obj, "eim_fqdn", "") or "").strip()
        call_count = self._per_fqdn_call_counts.get(fqdn, 0) + 1
        self._per_fqdn_call_counts[fqdn] = call_count
        if fqdn == "eim1.example.com":
            return SimpleNamespace(
                transaction_id="TX-DRAIN-1",
                euicc_package_list=[],
                package_format="",
                polling_complete=True,
                retry_after_seconds=0,
                eim_result_code=1,
            )
        if fqdn == "eim2.example.com" and call_count == 1:
            return SimpleNamespace(
                transaction_id="TX-DRAIN-2A",
                euicc_package_list=["BF5103800101"],
                package_format="",
                polling_complete=False,
                retry_after_seconds=0,
                eim_result_code=None,
            )
        return SimpleNamespace(
            transaction_id="TX-DRAIN-2B",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=1,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return {
            "pollingComplete": True,
            "retryAfterSeconds": 0,
        }


class TerminalProvideResultProvider:
    def __init__(self):
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(request_obj)
        return SimpleNamespace(
            transaction_id="TX-TERMINAL",
            euicc_package_list=["BF5103800101"],
            package_format="",
            polling_complete=False,
            retry_after_seconds=0,
            eim_result_code=None,
        )

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(request_obj)
        return SimpleNamespace(
            transaction_id="TX-TERMINAL",
            euicc_package_list=[],
            package_format="",
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=127,
        )


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

    def exchange(self, apdu: bytes, log_name: str) -> tuple[bytes, int, int]:
        self.send_calls.append((log_name, apdu))
        return b"", 0x90, 0x00

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


class LogicalChannelSelectFailureApduChannel(LogicalChannelCaptureApduChannel):
    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if log_name == "INIT: OPEN LOGICAL CHANNEL":
            return b"\x01"
        if log_name == "INIT: SELECT ISD-R CH1":
            raise IOError("APDU Failed: 6999")
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
                            wrap_tlv("81", b"eim1.example.test"),
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
        # The polling plugin seeds this override on the orchestrator in
        # plugin-driven flows. Core ES9+ code reads it as an opaque
        # string without knowing about the bridge.
        orchestrator._profile_download_base_url_override = "https://127.0.0.1:19443"
        orchestrator.state.load_bpp_response = bytes.fromhex("BF3700")
        captured: dict[str, str] = {}

        def fake_run_flow(matching_id: str = "", smdp_address: str = "") -> None:
            captured["matching_id"] = matching_id
            captured["smdp_address"] = smdp_address

        orchestrator.run_flow = fake_run_flow
        package = wrap_tlv(
            "BF54",
            wrap_tlv("82", b"\x01\x02\x03\x04")
            + wrap_tlv("30", wrap_tlv("80", b"LPA:1$yggdrasim.smdpp.example.test$MATCH-54")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        provider.set_base_url.assert_called_once_with("https://127.0.0.1:19443")
        self.assertEqual(captured["matching_id"], "MATCH-54")
        self.assertEqual(captured["smdp_address"], "yggdrasim.smdpp.example.test")
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

        call_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("INIT: TERMINAL CAPABILITY", call_names)
        self.assertEqual(
            apdu_channel.send_calls[0][1],
            bytes.fromhex("80AA00000DA90B8100820101830107840101"),
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
        all_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("INIT: TERMINAL CAPABILITY", all_names)
        self.assertIn("INIT: OPEN LOGICAL CHANNEL", all_names)
        self.assertIn("INIT: SELECT ISD-R CH1", all_names)
        self.assertEqual(apdu_channel.send_calls[0][1], bytes.fromhex("80AA00000DA90B8100820101830107840101"))
        open_channel_call = next(call for call in apdu_channel.send_calls if call[0] == "INIT: OPEN LOGICAL CHANNEL")
        self.assertEqual(open_channel_call[1], bytes.fromhex("0070000000"))
        select_isd_r_ch1_call = next(call for call in apdu_channel.send_calls if call[0] == "INIT: SELECT ISD-R CH1")
        self.assertEqual(select_isd_r_ch1_call[1], bytes.fromhex("01A4040010A0000005591010FFFFFFFF8900000100"))
        status_ch0_call = next(call for call in apdu_channel.send_calls if call[0] == "INIT: STATUS CH0")
        self.assertEqual(status_ch0_call[1], bytes.fromhex("80F2000C00"))
        self.assertNotIn("INIT: TERMINAL PROFILE CH1", all_names)

    def test_live_phase_connect_closes_open_channel_after_failed_bootstrap(self):
        apdu_channel = LogicalChannelSelectFailureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
                ES10B_USE_LOGICAL_CHANNEL=True,
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        orchestrator._phase_connect()

        self.assertEqual(orchestrator._es10b_logical_channel, 0)
        call_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("INIT: SELECT ISD-R CH1", call_names)
        self.assertIn("INIT: CLOSE LOGICAL CHANNEL 1 AFTER FAILED BOOTSTRAP", call_names)
        self.assertIn("INIT: SELECT ISD-R", call_names)
        close_call = next(
            call for call in apdu_channel.send_calls
            if call[0] == "INIT: CLOSE LOGICAL CHANNEL 1 AFTER FAILED BOOTSTRAP"
        )
        self.assertEqual(close_call[1], bytes.fromhex("0070800100"))

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

    def test_live_phase_connect_ignores_legacy_reset_flag(self):
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

        self.assertEqual(apdu_channel.reset_calls, 0)

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
        call_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("INIT: TERMINAL CAPABILITY", call_names)
        self.assertIn("HANDSHAKE: GetEuiccInfo1", call_names)
        self.assertIn("HANDSHAKE: GetEuiccInfo1 [STK MODE BASIC]", call_names)
        self.assertIn("HANDSHAKE: GetEuiccChallenge [STK MODE BASIC]", call_names)

    def test_live_get_eim_package_timeout_raises_without_retry_logic(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=TimeoutProvider(),
        )
        request = EimPollRequest(
            eim_fqdn="eim1.example.test",
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
            eim_fqdn="eim1.example.test",
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

    def test_live_binary_bf50_result_error_sets_result_code(self):
        client = Es9LikeClient(base_url="https://rsp.example.com")

        decoded = client._parse_eim_binary_response(bytes.fromhex("BF500302017F"))

        self.assertEqual(decoded["packageFormat"], "provideEimPackageResultError")
        self.assertEqual(decoded["eimResultCode"], 127)
        self.assertTrue(decoded["pollingComplete"])

    def test_live_provide_eim_package_result_rejects_raw_es10b_response(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=None,
        )

        payload = orchestrator._build_provide_eim_package_result_tlv(
            bytes.fromhex("BF2D00"),
            eid="89044045930000000000001492294428",
        )

        self.assertEqual(
            payload,
            bytes.fromhex("BF50195A108904404593000000000000149229442880053003020101"),
        )

    def test_live_profile_state_package_relays_signed_bf51_to_card(self):
        signed_package = wrap_tlv(
            "BF51",
            wrap_tlv("30", wrap_tlv("A0", wrap_tlv("BF2D", b"")))
            + wrap_tlv("5F37", b"\x11" * 64),
        )
        signed_result = wrap_tlv("BF51", wrap_tlv("A0", wrap_tlv("80", b"\x01")))
        apdu_channel = MinimalApduChannel(
            configured_data_response=b"",
            eim_configuration_response=b"",
            eid_response=b"",
        )
        original_send = apdu_channel.send

        def send_with_signed_result(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name.startswith("EIM: RelayPackage"):
                return signed_result
            return original_send(apdu, log_name)

        apdu_channel.send = send_with_signed_result
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        response = orchestrator._relay_eim_package_to_card(
            signed_package,
            poll_round=1,
            package_index=1,
        )

        self.assertEqual(response, signed_result)
        relay_calls = [
            call for call in apdu_channel.send_calls
            if call[0].startswith("EIM: RelayPackage")
        ]
        self.assertEqual(len(relay_calls), 1)
        self.assertEqual(relay_calls[0][1][0], 0x80)
        self.assertEqual(relay_calls[0][1][1], 0xE2)
        self.assertEqual(relay_calls[0][1][2], 0x91)
        self.assertEqual(relay_calls[0][1][5:], signed_package)

    def test_live_profile_state_package_chunks_large_signed_bf51(self):
        signed_package = wrap_tlv(
            "BF51",
            wrap_tlv("30", wrap_tlv("A8", b"\x22" * 300))
            + wrap_tlv("5F37", b"\x11" * 64),
        )
        signed_result = wrap_tlv("BF51", wrap_tlv("A0", wrap_tlv("80", b"\x01")))
        apdu_channel = MinimalApduChannel(
            configured_data_response=b"",
            eim_configuration_response=b"",
            eid_response=b"",
        )
        original_send = apdu_channel.send

        def send_with_signed_result(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name.startswith("EIM: RelayPackage"):
                return signed_result
            return original_send(apdu, log_name)

        apdu_channel.send = send_with_signed_result
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        response = orchestrator._relay_eim_package_to_card(
            signed_package,
            poll_round=1,
            package_index=1,
        )

        self.assertEqual(response, signed_result)
        relay_calls = [
            call for call in apdu_channel.send_calls
            if call[0].startswith("EIM: RelayPackage")
        ]
        self.assertGreater(len(relay_calls), 1)
        self.assertTrue(all(call[1][0] == 0x80 for call in relay_calls))
        self.assertTrue(all(call[1][1] == 0xE2 for call in relay_calls))
        self.assertEqual([call[1][2] for call in relay_calls[:-1]], [0x11] * (len(relay_calls) - 1))
        self.assertEqual(relay_calls[-1][1][2], 0x91)
        self.assertEqual([call[1][3] for call in relay_calls], list(range(len(relay_calls))))
        self.assertTrue(all(call[1][4] <= 120 for call in relay_calls))
        self.assertEqual(b"".join(call[1][5:] for call in relay_calls), signed_package)

    def test_live_eim_poll_request_uses_init_banner_metadata_cache(self):
        class NoReadApduChannel:
            def send(self, apdu: bytes, log_name: str) -> bytes:
                raise AssertionError(f"unexpected APDU read: {log_name}")

        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    b"".join(
                        [
                            wrap_tlv("80", b"manager-1"),
                            wrap_tlv("81", b"eim1.example.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com"))
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=NoReadApduChannel(),
            profile_provider=None,
        )
        orchestrator.cache_eim_poll_metadata(
            eid="89044045930000000000001492294428",
            euicc_configured_data=configured_data,
            eim_configuration_data=eim_configuration,
            euicc_info1=wrap_tlv("BF20", b"\x82\x03\x02\x05\x00"),
            euicc_info2=wrap_tlv("BF22", b"\x81\x03\x02\x03\x01"),
        )

        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(request.eid, "89044045930000000000001492294428")
        self.assertEqual(request.eim_fqdn, "eim1.example.com")
        self.assertEqual(request.eim_id, "manager-1")
        self.assertTrue(len(request.euicc_configured_data) > 0)
        self.assertTrue(len(request.eim_configuration_data) > 0)

    def test_live_eim_binary_logs_full_provide_result_body(self):
        client = RecordingPinnedBypassEimClient(base_url="https://rsp.example.com")
        body = bytes.fromhex("BF5041") + bytes(range(65))
        stdout = io.StringIO()

        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}):
            with redirect_stdout(stdout):
                response = client._post_eim_binary("https://eim1.example.test", body, b"")

        self.assertEqual(response, {})
        self.assertIn(
            f"[*] eIM request full ProvideEimPackageResult hex={body.hex().upper()}",
            stdout.getvalue(),
        )

    def test_live_eim_binary_can_bypass_bf55_direct_tls_pin(self):
        client = RecordingPinnedBypassEimClient(base_url="https://rsp.example.com")
        client.set_eim_tls_public_key_pinning_enabled(False)

        response = client._post_eim_binary(
            "https://127.0.0.1:18443",
            bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
            b"\x01\x02",
        )

        self.assertEqual(response, {})
        self.assertEqual(client.open_pinned_spki_args, [None])
        self.assertEqual(len(client.open_contexts), 1)
        self.assertIs(client.open_contexts[0], client._verified_context)

    def test_live_eim_binary_retries_with_dynamic_ca_bundle_when_tls_verify_fails(self):
        client = DynamicRetryEimClient(base_url="https://rsp.example.com")

        response = client._post_eim_binary(
            "https://eim1.example.test",
            bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
            b"",
        )

        self.assertEqual(response, {})
        self.assertEqual(client.use_configured_ca_bundle_flags, [False])
        self.assertEqual(
            client.dynamic_retry_calls,
            [
                (
                    "https://eim1.example.test/gsma/rsp2/asn1",
                    "",
                    "certificate verify failed",
                )
            ],
        )
        self.assertEqual(client.bundle_paths, ["/tmp/live-eim-dynamic-ca.pem"])
        self.assertEqual(
            client.open_contexts,
            [client._initial_context, client._retry_context],
        )

    def test_live_dynamic_tls_can_fallback_to_presented_leaf_bundle(self):
        client = LeafFallbackEimClient(base_url="https://rsp.example.com")

        resolved_bundle = client._resolve_dynamic_ca_bundle_for_endpoint(
            "https://eim1.example.test/gsma/rsp2/asn1",
            trust_hint_ci_pkid="",
            initial_error=IOError("certificate verify failed"),
        )

        self.assertEqual(resolved_bundle, client._leaf_bundle_path)
        self.assertEqual(client.handshake_bundle_paths, [client._leaf_bundle_path])
        self.assertEqual(len(client.persisted_bundles), 1)
        self.assertEqual(
            client.persisted_bundles[0]["candidate_path"],
            client._leaf_bundle_path,
        )
        self.assertIn(
            "live TLS leaf certificate",
            client.persisted_bundles[0]["note"],
        )

    def test_live_certificate_form_a1_does_not_become_direct_tls_pin(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=None,
        )

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A1", b"\x30\x00")
        )

        self.assertEqual(extracted, b"")

    def test_live_direct_spki_form_a0_still_extracts_pin(self):
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=None,
        )
        tls_key_material = bytes.fromhex(
            "301306072A8648CE3D020106082A8648CE3D03010703420004" + "22" * 64
        )

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A0", tls_key_material)
        )

        self.assertEqual(extracted, wrap_tlv("30", tls_key_material))

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

    def test_live_run_eim_poll_continues_after_intermediate_entry_failure(self):
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com"))
        eim_configuration = wrap_tlv(
            "BF55",
            b"".join(
                [
                    wrap_tlv(
                        "A0",
                        wrap_tlv(
                            "30",
                            b"".join(
                                [
                                    wrap_tlv("80", b"manager-1"),
                                    wrap_tlv("81", b"eim1.example.com"),
                                    wrap_tlv("82", b"\x01"),
                                ]
                            ),
                        ),
                    ),
                    wrap_tlv(
                        "A0",
                        wrap_tlv(
                            "30",
                            b"".join(
                                [
                                    wrap_tlv("80", b"manager-2"),
                                    wrap_tlv("81", b"eim2.example.com"),
                                    wrap_tlv("82", b"\x01"),
                                ]
                            ),
                        ),
                    ),
                    wrap_tlv(
                        "A0",
                        wrap_tlv(
                            "30",
                            b"".join(
                                [
                                    wrap_tlv("80", b"manager-3"),
                                    wrap_tlv("81", b"eim3.example.com"),
                                    wrap_tlv("82", b"\x01"),
                                ]
                            ),
                        ),
                    ),
                ]
            ),
        )
        provider = MixedFailureSweepProvider()
        apdu_channel = MinimalApduChannel(
            configured_data_response=configured_data,
            eim_configuration_response=eim_configuration,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        cfg = SimpleNamespace(
            AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            EIM_EUICC_CHALLENGE_ASN1=True,
            RESET_CARD_BEFORE_FLOW=False,
            EIM_MAX_POLL_ROUNDS=4,
        )
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(len(provider.poll_eim_calls), 3)
        self.assertEqual(provider.poll_eim_calls[0].eim_fqdn, "eim1.example.com")
        self.assertEqual(provider.poll_eim_calls[1].eim_fqdn, "eim2.example.com")
        self.assertEqual(provider.poll_eim_calls[2].eim_fqdn, "eim3.example.com")

    def test_live_run_eim_poll_skips_no_package_entries_in_later_drain_rounds(self):
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com"))
        eim_configuration = wrap_tlv(
            "BF55",
            b"".join(
                [
                    wrap_tlv(
                        "A0",
                        wrap_tlv(
                            "30",
                            b"".join(
                                [
                                    wrap_tlv("80", b"manager-1"),
                                    wrap_tlv("81", b"eim1.example.com"),
                                    wrap_tlv("82", b"\x01"),
                                ]
                            ),
                        ),
                    ),
                    wrap_tlv(
                        "A0",
                        wrap_tlv(
                            "30",
                            b"".join(
                                [
                                    wrap_tlv("80", b"manager-2"),
                                    wrap_tlv("81", b"eim2.example.com"),
                                    wrap_tlv("82", b"\x01"),
                                ]
                            ),
                        ),
                    ),
                ]
            ),
        )
        provider = DrainRoundSkipProvider()
        apdu_channel = MinimalApduChannel(
            configured_data_response=configured_data,
            eim_configuration_response=eim_configuration,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        cfg = SimpleNamespace(
            AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            EIM_EUICC_CHALLENGE_ASN1=True,
            RESET_CARD_BEFORE_FLOW=False,
            EIM_MAX_POLL_ROUNDS=4,
            EIM_MAX_DRAIN_ROUNDS=3,
        )
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        relayed_packages = []

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF3700")

        orchestrator._relay_eim_package_to_card = fake_relay

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(
            [call.eim_fqdn for call in provider.poll_eim_calls],
            [
                "eim1.example.com",
                "eim2.example.com",
                "eim2.example.com",
            ],
        )
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
            ],
        )

    def test_live_run_eim_poll_does_not_repoll_after_terminal_provide_result(self):
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
                            wrap_tlv("81", b"eim1.example.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        provider = TerminalProvideResultProvider()
        apdu_channel = MinimalApduChannel(
            configured_data_response=configured_data,
            eim_configuration_response=eim_configuration,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        cfg = SimpleNamespace(
            AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            EIM_EUICC_CHALLENGE_ASN1=True,
            RESET_CARD_BEFORE_FLOW=False,
            EIM_MAX_POLL_ROUNDS=4,
            EIM_MAX_DRAIN_ROUNDS=2,
        )
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        relayed_packages = []

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF2D00")

        orchestrator._relay_eim_package_to_card = fake_relay

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(len(provider.poll_eim_calls), 1)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
            ],
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
            eim_fqdn="eim1.example.test",
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

    def test_live_run_eim_poll_repolls_after_acknowledged_package_result(self):
        provider = AcknowledgedPackageProvider()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=provider,
        )
        relayed_packages = []

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF3700")

        orchestrator._relay_eim_package_to_card = fake_relay
        request = EimPollRequest(
            eim_fqdn="eim1.example.test",
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

        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(provider.provide_eim_package_result_calls[0].transaction_id, "TX-ACK")
        self.assertEqual(provider.poll_eim_calls[1].transaction_id, "TX-ACK")
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5103800101"), 1, 1),
            ],
        )

    def test_live_run_eim_poll_repolls_after_empty_package_result_response(self):
        provider = EmptyResponsePackageProvider()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(),
            apdu_channel=None,
            profile_provider=provider,
        )
        relayed_packages = []

        def fake_relay(package_bytes, poll_round, package_index):
            relayed_packages.append((package_bytes, poll_round, package_index))
            return bytes.fromhex("BF5280")

        orchestrator._relay_eim_package_to_card = fake_relay
        request = EimPollRequest(
            eim_fqdn="eim1.esim.example.test",
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

        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        self.assertEqual(provider.provide_eim_package_result_calls[0].transaction_id, "TX-EMPTY")
        self.assertEqual(provider.poll_eim_calls[1].transaction_id, "TX-EMPTY")
        self.assertEqual(
            relayed_packages,
            [
                (bytes.fromhex("BF5203800101"), 1, 1),
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
        # BF23 (segment 1) is 170 bytes → 2 blocks with 120-byte chunking.
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

    def test_phase_install_package_advances_progress_bar_per_segment_and_sync(self):
        """
        Regression: when a progress bar is supplied the live install
        phase must expand the total to cover every ES10b segment plus
        the trailing notification sync, so the sticky footer keeps
        moving instead of parking at 100 % while the segments stream
        in.
        """

        class _FakeProgressBar:
            def __init__(self, total: int) -> None:
                self.total = int(total)
                self.completed = 0
                self.advance_calls: list[tuple[str, int]] = []
                self.set_total_calls: list[int] = []

            def set_total(self, new_total: int) -> None:
                self.total = int(new_total)
                self.set_total_calls.append(int(new_total))
                if self.completed > self.total:
                    self.completed = self.total

            def advance(self, label: str = "", count: int = 1) -> None:
                step_count = int(count)
                if step_count < 0:
                    step_count = 0
                self.completed = self.completed + step_count
                if self.completed > self.total:
                    self.completed = self.total
                self.advance_calls.append((str(label or ""), step_count))

        apdu_channel = InstallCaptureApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        orchestrator.state.bpp_bytes = b"\x01\x02\x03"
        orchestrator._segment_bound_profile_package = lambda _: [b"\xAA", b"\xBB", b"\xCC"]
        orchestrator._send_personalization_store_data = lambda *_a, **_kw: b""
        orchestrator._sync_pending_notifications = lambda *_a, **_kw: None
        orchestrator._inspect_install_bootstrap = lambda _segments: None

        # Caller has advanced 6 pre-install slots (connect..get-bpp).
        bar = _FakeProgressBar(total=6)
        bar.completed = 6

        result = orchestrator._phase_install_package(bar)

        self.assertTrue(result)
        advance_labels = [label for label, _count in bar.advance_calls]
        self.assertEqual(
            advance_labels,
            [
                "install segment 1/3",
                "install segment 2/3",
                "install segment 3/3",
                "sync notifications",
            ],
        )
        self.assertIn(10, bar.set_total_calls)
        # 6 pre-install slots + 3 segments + 1 sync = 10 → counter
        # must land at 100 % only after the final sync advance.
        self.assertEqual(bar.total, 10)
        self.assertEqual(bar.completed, 10)

    def test_should_retry_with_stk_bootstrap_covers_channel_fault_class(self):
        """
        SGP.22 §5.7.10 + ETSI TS 102 221 §11.1.17: 6985 / 6E00 / 6881 /
        6882 are the recoverable status-word class for an ISD-R binding
        that has been invalidated by a profile state change. All four
        flow through the same logical-channel-recovery → STK-mode-fallback
        chain in ``_send_es10b_store_data``.
        """
        should_retry = SGP22Orchestrator._should_retry_with_stk_bootstrap
        self.assertTrue(should_retry(IOError("APDU Failed: 6985")))
        self.assertTrue(should_retry(IOError("APDU Failed: 6E00")))
        self.assertTrue(should_retry(IOError("APDU Failed: 6881")))
        self.assertTrue(should_retry(IOError("APDU Failed: 6882")))
        self.assertTrue(should_retry(IOError("apdu failed: 6e00")))
        self.assertFalse(should_retry(IOError("APDU Failed: 6A82")))
        self.assertFalse(should_retry(IOError("something else entirely")))

    def test_list_pending_notifications_recovers_via_fresh_logical_channel(self):
        """
        Regression for the ``EnableProfile`` → ``ListNotifications``
        cascade observed on a freshly inserted card:

        * BF28 on the base channel returns 6E00 (CLA not supported on
          this channel — the supplementary CH was dropped during the
          profile state change).
        * The orchestrator MUST then open a fresh logical channel via
          MANAGE CHANNEL, SELECT ISD-R on the new channel, and replay the
          StoreData with the matching CLA.

        This mirrors the console-side ``_send_store_data_with_logical_fallback``
        that already protects BF2B (RetrieveNotificationsList).
        """
        send_log: list[tuple[str, str]] = []
        attempts = {"count": 0}

        def fake_send(apdu: bytes, log_name: str = "") -> bytes:
            send_log.append((apdu.hex().upper(), log_name))
            if apdu[:2].hex().upper() == "0070":
                if apdu[2] == 0x00:
                    return b"\x01\x90\x00"
                return b""
            if apdu[1] == 0xA4:
                return b""
            if apdu[1] == 0xE2:
                attempts["count"] += 1
                if attempts["count"] == 1:
                    raise IOError("APDU Failed: 6E00")
                return b"\xBF\x28\x00\x90\x00"
            return b""

        reset_calls = {"count": 0}

        def fake_reset() -> bool:
            reset_calls["count"] += 1
            return True

        apdu_channel = SimpleNamespace(send=fake_send, reset=fake_reset)
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )

        result = orchestrator._list_pending_notifications_with_context_recovery()

        self.assertEqual(result, b"\xBF\x28\x00\x90\x00")
        self.assertEqual(attempts["count"], 2)
        self.assertEqual(reset_calls["count"], 1)
        self.assertEqual(orchestrator._es10b_logical_channel, 0)

        kinds = [entry[1] for entry in send_log]
        self.assertIn("DOWNLOAD: ListNotifications", kinds)
        self.assertTrue(any("OPEN LOGICAL CHANNEL" in name for name in kinds))
        self.assertTrue(any("SELECT ISD-R CH1" in name for name in kinds))
        self.assertTrue(any(name.endswith("[TERMINAL CAPABILITY]") for name in kinds))
        self.assertTrue(any("STATUS CH0" in name for name in kinds))
        self.assertTrue(any("TERMINAL PROFILE CH1" in name for name in kinds))
        self.assertTrue(any(name.endswith("[CH1]") for name in kinds))
        self.assertTrue(any("CLOSE LOGICAL CHANNEL 1" in name for name in kinds))

        # TERMINAL CAPABILITY must precede TERMINAL PROFILE on the
        # recovery channel (TS 102 221 §11.1.19).
        terminal_capability_index = next(
            index
            for index, name in enumerate(kinds)
            if name.endswith("[TERMINAL CAPABILITY]")
        )
        terminal_profile_index = next(
            index
            for index, name in enumerate(kinds)
            if "TERMINAL PROFILE CH1" in name
        )
        self.assertLess(terminal_capability_index, terminal_profile_index)

    def test_list_pending_notifications_primes_active_logical_channel_first(self):
        send_log: list[tuple[str, str]] = []
        attempts = {"count": 0}
        response = bytes.fromhex("BF2802A000")

        def fake_send(apdu: bytes, log_name: str = "") -> bytes:
            send_log.append((apdu.hex().upper(), log_name))
            if log_name == "DOWNLOAD: ListNotifications":
                attempts["count"] += 1
                raise IOError("APDU Failed: 6985")
            if log_name == "DOWNLOAD: ListNotifications [OPEN LOGICAL CHANNEL]":
                raise AssertionError("active channel recovery should run before opening a new channel")
            if log_name == "DOWNLOAD: ListNotifications [ACTIVE CH1]":
                return response
            return b""

        reset_calls = {"count": 0}

        def fake_reset() -> bool:
            reset_calls["count"] += 1
            return True

        apdu_channel = SimpleNamespace(send=fake_send, reset=fake_reset)
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        orchestrator._es10b_logical_channel = 1

        result = orchestrator._list_pending_notifications_with_context_recovery()

        self.assertEqual(result, response)
        self.assertEqual(attempts["count"], 1)
        self.assertEqual(reset_calls["count"], 0)
        self.assertEqual(orchestrator._es10b_logical_channel, 1)
        kinds = [entry[1] for entry in send_log]
        self.assertEqual(
            kinds,
            [
                "DOWNLOAD: ListNotifications",
                "DOWNLOAD: ListNotifications [TERMINAL CAPABILITY]",
                "DOWNLOAD: ListNotifications [STATUS CH0]",
                "DOWNLOAD: ListNotifications [TERMINAL PROFILE CH1]",
                "DOWNLOAD: ListNotifications [ACTIVE CH1]",
            ],
        )
        self.assertEqual(bytes.fromhex(send_log[-1][0])[:2], bytes.fromhex("81E2"))

    def test_live_notification_sync_falls_back_to_bf2b_after_bf28_6a88(self):
        pending_notification = wrap_tlv(
            "BF37",
            wrap_tlv(
                "BF27",
                b"".join(
                    [
                        wrap_tlv("80", bytes.fromhex("0100000000000345")),
                        wrap_tlv(
                            "BF2F",
                            b"".join(
                                [
                                    wrap_tlv("80", b"\x6A"),
                                    wrap_tlv("81", bytes.fromhex("0780")),
                                    wrap_tlv("0C", b"dpp1.example.test"),
                                    wrap_tlv("5A", bytes.fromhex("98010300003017672747")),
                                ]
                            ),
                        ),
                        wrap_tlv("06", bytes.fromhex("2B0601040183A40F0104")),
                        wrap_tlv("A2", bytes.fromhex("A106800105810108")),
                    ]
                ),
            )
            + wrap_tlv("5F37", b"\x44" * 64),
        )
        notification_retrieve_response = wrap_tlv(
            "BF2B",
            wrap_tlv("A0", pending_notification),
        )
        apdu_channel = MinimalApduChannel(
            configured_data_response=wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com")),
            eim_configuration_response=wrap_tlv("BF55", b""),
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        original_send = apdu_channel.send

        def send_with_bf28_6a88(apdu: bytes, log_name: str) -> bytes:
            if log_name == "DOWNLOAD: ListNotifications":
                apdu_channel.send_calls.append((log_name, apdu))
                raise IOError("APDU Failed: 6A88")
            if log_name == "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)":
                apdu_channel.send_calls.append((log_name, apdu))
                return notification_retrieve_response
            if log_name == "DOWNLOAD: RetrieveNotification [106]":
                apdu_channel.send_calls.append((log_name, apdu))
                return notification_retrieve_response
            if log_name == "DOWNLOAD: RemoveNotificationFromList [106]":
                apdu_channel.send_calls.append((log_name, apdu))
                return bytes.fromhex("BF3000")
            return original_send(apdu, log_name)

        class NotificationProvider:
            def __init__(self):
                self.handle_notification_calls = []

            def handle_notification(self, request):
                self.handle_notification_calls.append(request)
                return {}

        provider = NotificationProvider()
        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        apdu_channel.send = send_with_bf28_6a88

        orchestrator._sync_pending_notifications()

        self.assertEqual(len(provider.handle_notification_calls), 1)
        expected_notification = base64.b64encode(pending_notification).decode("utf-8")
        self.assertEqual(provider.handle_notification_calls[0].pending_notification, expected_notification)
        send_logs = [entry[0] for entry in apdu_channel.send_calls]
        self.assertIn("DOWNLOAD: RetrieveNotificationsList (BF28 fallback)", send_logs)
        self.assertIn("DOWNLOAD: RetrieveNotification [106]", send_logs)
        self.assertIn("DOWNLOAD: RemoveNotificationFromList [106]", send_logs)
        self.assertIs(orchestrator._last_notification_sync_succeeded, True)

    def test_sync_pending_notifications_marks_failure_when_listnotifications_unrecoverable(self):
        """
        SGP.22 §5.6.4: pending profile-state notifications MUST be
        forwarded to the recipient SM-DP+ before the LPA removes them
        from the eUICC queue. When listNotifications cannot complete,
        the orchestrator records the outcome on
        ``_last_notification_sync_succeeded`` so the console layer can
        suppress the post-command auto-clear and preserve the queue
        for a later sweep.
        """
        provider = SimpleNamespace(handle_notification=lambda *_a, **_kw: {})

        def always_fail(*_args, **_kwargs):
            raise IOError("APDU Failed: 6985")

        apdu_channel = SimpleNamespace(send=always_fail, reset=lambda: True)

        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications(b"")

        self.assertIs(orchestrator._last_notification_sync_succeeded, False)

    def test_sync_pending_notifications_marks_success_on_empty_queue(self):
        """Empty queue still counts as a successful sync round-trip."""
        provider = SimpleNamespace(handle_notification=lambda *_a, **_kw: {})

        def respond(apdu: bytes, log_name: str = "") -> bytes:
            if apdu[1] == 0xE2:
                return b"\xBF\x28\x02\x30\x00"
            return b""

        apdu_channel = SimpleNamespace(send=respond, reset=lambda: True)

        orchestrator = SGP22Orchestrator(
            cfg=SimpleNamespace(
                AID_ISD_R=bytes.fromhex("A0000005591010FFFFFFFF8900000100"),
            ),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications(b"")

        self.assertIs(orchestrator._last_notification_sync_succeeded, True)


if __name__ == "__main__":
    unittest.main()
