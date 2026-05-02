import datetime
import base64
import copy
import unittest
from dataclasses import dataclass
from unittest import mock

from asn1crypto import core, x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import SCP11.live.pysim_support as live_pysim_support
import SCP11.test.pysim_support as test_pysim_support
from SCP11.asn1_registry import ASN1Registry
from SCP11.models import BACKEND_MODE_LOCAL_SGP26, EimPollRequest, EimPollResponse
from SCP11.orchestrator import SGP22Orchestrator

try:
    from pySim.esim import compile_asn1_subdir
except ImportError:
    compile_asn1_subdir = None


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_der_length(len(value)) + value


def _read_test_tlv(data: bytes, offset: int):
    tag_start = offset
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while offset < len(data) and data[offset] & 0x80:
            offset += 1
        offset += 1
    tag_bytes = data[tag_start:offset]
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num_len = length_byte & 0x7F
        length = 0
        for _ in range(num_len):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = length_byte
    value = data[offset:offset + length]
    return tag_bytes, value, data[tag_start:offset + length], offset + length


def build_self_signed_cert():
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Flow Test Cert"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    asn1_cert = x509.Certificate.load(der)
    return asn1_cert


class FakeApduChannel:
    def __init__(
        self,
        fail_load: bool = False,
        notification_list_response: bytes = b"",
        notification_retrieve_response: bytes = b"",
        euicc_package_result_list_response: bytes = b"",
        load_bpp_response: bytes = bytes.fromhex("BF3700"),
        load_bpp_response_sequence = None,
        eim_configuration_response: bytes = b"",
        configured_data_response: bytes = b"",
        euicc_info2_response: bytes = bytes.fromhex("BF2200"),
        certs_response: bytes = bytes.fromhex("BF5600"),
        eid_response: bytes = b"\x89" * 10,
        eim_package_response: bytes = bytes.fromhex("BF3700"),
    ):
        self.chunked_calls = []
        self.send_calls = []
        self.fail_load = fail_load
        self.notification_list_response = notification_list_response
        self.notification_retrieve_response = notification_retrieve_response
        self.euicc_package_result_list_response = euicc_package_result_list_response
        self.load_bpp_response = load_bpp_response
        self.load_bpp_response_sequence = list(load_bpp_response_sequence or [])
        self.eim_configuration_response = eim_configuration_response
        self.configured_data_response = configured_data_response
        self.euicc_info2_response = euicc_info2_response
        self.certs_response = certs_response
        self.eid_response = eid_response
        self.eim_package_response = eim_package_response
        self.auth_response = self._build_auth_response()

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, apdu))
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "EuiccConfiguredData" in log_name:
            return self.configured_data_response
        if "EimConfigurationData" in log_name:
            return self.eim_configuration_response
        if "GetEuiccInfo2" in log_name:
            return self.euicc_info2_response
        if "GetCerts" in log_name:
            return self.certs_response
        if "RetrieveNotificationsList" in log_name:
            return self.notification_retrieve_response
        if "RetrieveEuiccPackageResults" in log_name:
            return self.euicc_package_result_list_response
        if "GetEID" in log_name:
            return self.eid_response
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        if "DOWNLOAD: CancelSession" in log_name:
            return bytes.fromhex("BF4103810102")
        if "ListNotifications" in log_name:
            return self.notification_list_response
        if "RetrieveNotification" in log_name:
            return self.notification_retrieve_response
        if "RemoveNotificationFromList" in log_name:
            return bytes.fromhex("BF3000")
        if "LoadBoundProfilePackage" in log_name:
            if self.fail_load:
                raise IOError("APDU Failed: 6982")
            if len(self.load_bpp_response_sequence) > 0:
                return self.load_bpp_response_sequence.pop(0)
            return self.load_bpp_response
        if "EIM: RelayPackage" in log_name:
            return self.eim_package_response
        return b""

    def send_chunked(self, cla, ins, p1, p2_start, payload, log_name, chunk_size=250):
        self.chunked_calls.append((log_name, payload))
        if "AuthenticateServer" in log_name:
            return self.auth_response
        return b"\xBF\x21\x00"

    def _build_auth_response(self) -> bytes:
        cert = build_self_signed_cert()
        cert_der = cert.dump()
        if compile_asn1_subdir is not None:
            try:
                asn1 = compile_asn1_subdir("rsp")
                decoded_cert = asn1.decode("Certificate", cert_der)
                payload = {
                    "euiccSigned1": {
                        "transactionId": b"\x11" * 16,
                        "serverAddress": "rsp.example.com",
                        "serverChallenge": b"\x22" * 16,
                        "ctxParams1": (
                            "ctxParamsForCommonAuthentication",
                            {
                                "deviceInfo": {
                                    "tac": b"\x01\x02\x03\x04",
                                    "deviceCapabilities": {
                                        "gsmSupportedRelease": b"\x99\x00\x00",
                                    },
                                }
                            },
                        ),
                    },
                    "euiccSignature1": b"\x33" * 64,
                    "euiccCertificate": decoded_cert,
                    "eumCertificate": decoded_cert,
                }
                response = asn1.encode("AuthenticateServerResponse", ("authenticateResponseOk", payload))
                return wrap_tlv("BF38", response)
            except Exception:
                pass

        ctx = ASN1Registry.CtxParams1(
            name="ctxParamsForCommonAuthentication",
            value=ASN1Registry.CtxParamsForCommonAuthentication(
                {
                    "deviceInfo": {
                        "tac": b"\x01\x02\x03\x04",
                        "deviceCapabilities": {
                            "gsmSupportedRelease": b"\x99\x00\x00",
                        },
                    }
                }
            ),
        )
        euicc_signed1 = ASN1Registry.EuiccSigned1(
            {
                "transactionId": ASN1Registry.TransactionId(b"\x11" * 16),
                "serverAddress": ASN1Registry.ServerAddress("rsp.example.com"),
                "serverChallenge": ASN1Registry.ServerChallenge(b"\x22" * 16),
                "euiccInfo2": core.Any(core.OctetString(b"\x00")),
                "ctxParams1": ctx,
            }
        )
        response_ok = ASN1Registry.AuthenticateResponseOk(
            {
                "euiccSigned1": euicc_signed1,
                "euiccSignature1": ASN1Registry.EuiccSignature1(b"\x33" * 64),
                "euiccCertificate": cert,
                "nextCertInChain": cert,
            }
        )
        choice = ASN1Registry.AuthenticateServerResponse(
            name="authenticateResponseOk",
            value=response_ok,
        )
        choice_bytes = choice.dump()
        outer = bytes.fromhex("BF38") + encode_der_length(len(choice_bytes)) + choice_bytes
        return outer


class StkBootstrapRetryApduChannel(FakeApduChannel):
    def __init__(self):
        super().__init__()
        self._fail_info1_once = True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        if log_name == "HANDSHAKE: GetEuiccInfo1" and self._fail_info1_once:
            self.send_calls.append((log_name, apdu))
            self._fail_info1_once = False
            raise IOError("APDU Failed: 6985")
        if "[STK MODE TERMINAL CAPABILITY]" in log_name:
            self.send_calls.append((log_name, apdu))
            return b""
        if "[STK MODE SELECT ISD-R]" in log_name:
            self.send_calls.append((log_name, apdu))
            return b""
        if "[STK MODE TERMINAL PROFILE]" in log_name:
            self.send_calls.append((log_name, apdu))
            return b""
        if "[STK MODE CH1]" in log_name and "GetEuiccInfo1" in log_name:
            self.send_calls.append((log_name, apdu))
            return bytes.fromhex("BF2000")
        if "[STK MODE CH1]" in log_name and "GetEuiccChallenge" in log_name:
            self.send_calls.append((log_name, apdu))
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        return super().send(apdu, log_name)


@dataclass
class FakeCfg:
    AID_ISD_R: bytes = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
    CERT_PATH_AUTH: str = ""
    KEY_PATH_AUTH: str = ""
    CERT_PATH_PB: str = ""
    KEY_PATH_PB: str = ""
    RSP_SERVER_URL: str = "rsp.example.com"
    TAC: bytes = bytes.fromhex("01020304")
    CAPABILITIES: dict = None
    ROOT_CI_ID: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    BACKEND_MODE: str = BACKEND_MODE_LOCAL_SGP26
    EIM_REQUEST_VARIANT: int = 0
    EIM_GET_PACKAGE_NOTIFY_STATE_CHANGE: bool = False
    EIM_GET_PACKAGE_RPLMN: str = ""


class FakeProvider:
    def __init__(self, bpp_bytes: bytes, eim_poll_responses=None, eim_poll_errors=None):
        self._bpp_bytes = bpp_bytes
        self.cancel_session_calls = []
        self.handle_notification_calls = []
        self.poll_eim_calls = []
        self.provide_eim_package_result_calls = []
        self._eim_poll_responses = list(eim_poll_responses or [])
        self._eim_poll_errors = list(eim_poll_errors or [])
        self.base_url_calls = []

    def get_bound_profile_package(self, request_obj):
        class Response:
            def __init__(self, bound_profile_package: str):
                self.bound_profile_package = bound_profile_package

        return Response(base64.b64encode(self._bpp_bytes).decode("utf-8"))

    def cancel_session(self, request_obj):
        self.cancel_session_calls.append(request_obj)
        return {}

    def handle_notification(self, request_obj):
        self.handle_notification_calls.append(request_obj)
        return {}

    def set_base_url(self, base_url: str):
        self.base_url_calls.append(base_url)

    def get_eim_package(self, request_obj):
        self.poll_eim_calls.append(copy.deepcopy(request_obj))
        if len(self._eim_poll_errors) > 0:
            error = self._eim_poll_errors.pop(0)
            if error is not None:
                raise error
        if len(self._eim_poll_responses) == 0:
            return EimPollResponse()
        return self._eim_poll_responses.pop(0)

    def provide_eim_package_result(self, request_obj):
        self.provide_eim_package_result_calls.append(copy.deepcopy(request_obj))
        return {}

    def poll_eim(self, request_obj):
        return self.get_eim_package(request_obj)


class OrchestratorFlowTests(unittest.TestCase):
    @staticmethod
    def _tag_of_segment(segment: bytes) -> bytes:
        if len(segment) == 0:
            return b""
        if (segment[0] & 0x1F) != 0x1F:
            return segment[:1]
        offset = 1
        while offset < len(segment) and (segment[offset] & 0x80) != 0:
            offset += 1
        if offset < len(segment):
            offset += 1
        return segment[:offset]

    def test_flow_runs_local_paths(self):
        cfg = FakeCfg()
        cfg.CAPABILITIES = {
            "gsmSupportedRelease": b"\x99\x00\x00",
            "utranSupportedRelease": b"\x99\x00\x00",
            "eutranEpcSupportedRelease": b"\x99\x00\x00",
        }
        cert = build_self_signed_cert()
        private_key = ec.generate_private_key(ec.SECP256R1())

        orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=FakeApduChannel(), profile_provider=None)
        orchestrator.cert_auth = cert
        orchestrator.key_auth = private_key
        orchestrator.cert_pb = cert
        orchestrator.key_pb = private_key
        orchestrator._local_credentials_loaded = True

        orchestrator._phase_connect()
        orchestrator._phase_authentication_seed(matching_id="", smdp_address=cfg.RSP_SERVER_URL)
        auth_seed = orchestrator._build_local_auth_seed(smdp_address=cfg.RSP_SERVER_URL)
        orchestrator._phase_authenticate_server(auth_seed, matching_id="")
        orchestrator._phase_prepare_download(smdp_address=cfg.RSP_SERVER_URL)

        self.assertTrue(len(orchestrator.state.euicc_signature1) == 64)
        self.assertTrue(len(orchestrator.state.prepare_download_response_b64) > 0)

    def test_authentication_seed_retries_with_stk_mode_after_6985(self):
        apdu_channel = StkBootstrapRetryApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=None,
        )
        mocked_auth = mock.Mock(return_value={"provider": "mock"})
        orchestrator._initiate_authentication_with_provider = mocked_auth

        orchestrator._phase_connect()
        auth_seed = orchestrator._phase_authentication_seed(
            matching_id="MATCH-6985",
            smdp_address="rsp.example.com",
        )

        mocked_auth.assert_called_once_with(bytes.fromhex("BF2000"), smdp_address="rsp.example.com")
        self.assertEqual(auth_seed["provider"], "mock")
        self.assertEqual(auth_seed["matching_id"], "MATCH-6985")
        self.assertEqual(
            orchestrator.state.card_challenge,
            bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55"),
        )
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

    def test_prepare_download_error_response_raises(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        with self.assertRaises(PermissionError) as raised:
            orchestrator._parse_prepare_download_response(
                bytes.fromhex("BF210FA10D800801000000000002CC020102")
            )

        self.assertIn("PrepareDownload refused by card", str(raised.exception))
        self.assertIn("downloadErrorCode=2", str(raised.exception))

    def test_format_sima_response_expands_tlv_structure(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        formatted = orchestrator._format_sima_response(bytes.fromhex("3007A0053003800100"))

        self.assertIn("3007A0053003800100", formatted)
        self.assertIn("30(len=7, simaResponse)", formatted)
        self.assertIn("A0(len=5, finalResult.successResult)", formatted)
        self.assertIn("30(len=3, resultData)", formatted)
        self.assertIn("80(len=1, resultCode)=00", formatted)
        self.assertIn("successResult.resultCode=0", formatted)

    def test_format_sima_response_shows_failure_detail(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        formatted = orchestrator._format_sima_response(bytes.fromhex("3008A106800105810108"))

        self.assertIn("A1(len=6, finalResult.failureResult)", formatted)
        self.assertIn("80(len=1, resultCode)=05", formatted)
        self.assertIn("81(len=1, resultDetail)=08", formatted)
        self.assertIn("failureResult.resultCode=5", formatted)
        self.assertIn("failureResult.resultDetail=8", formatted)

    def test_successful_terminal_profile_install_result_is_not_described_as_failure(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        meaning = orchestrator._describe_profile_installation_result_code(5, 0, b"\xA0")

        self.assertEqual(meaning, "card completed the final profile installation step")

    def test_duplicate_iccid_profile_install_result_is_described_clearly(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        meaning = orchestrator._describe_profile_installation_result_code(5, 9, b"\xA1")

        self.assertEqual(meaning, "card rejected the profile because its ICCID is already installed")

    def test_notification_metadata_decodes_iccid_in_semi_octet_order(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        details = orchestrator._decode_notification_metadata_fields(wrap_tlv("5A", bytes.fromhex("980103")))

        self.assertEqual(details["iccid"], "891030")

    def test_install_bootstrap_rejects_transaction_id_mismatch(self):
        bf23_value = b"".join(
            [
                wrap_tlv("82", b"\x01"),
                wrap_tlv("80", b"\xAA" * 8),
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
        bpp_bytes = wrap_tlv("BF36", wrap_tlv("BF23", bf23_value))

        euicc_signed2 = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"\xBB" * 8),
                    wrap_tlv("5F49", b"\x06" * 65),
                ]
            ),
        )
        prepare_download_ok = wrap_tlv("30", euicc_signed2 + wrap_tlv("5F37", b"\x07" * 64))
        prepare_download_response = wrap_tlv("BF21", wrap_tlv("A0", prepare_download_ok))

        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)
        orchestrator.state.bpp_bytes = bpp_bytes
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._inspect_install_bootstrap(orchestrator._segment_bound_profile_package(bpp_bytes))

        self.assertIn("transactionId does not match PrepareDownloadResponse", str(raised.exception))

    def test_install_package_uses_bound_profile_package_bytes(self):
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
        bf23_tlv = wrap_tlv("BF23", bf23_value)
        a0_tlv = wrap_tlv("A0", wrap_tlv("87", b"\xAA\xBB"))
        a1_value = wrap_tlv("88", b"\x01" * 247) + wrap_tlv("89", b"\x02")
        a1_tlv = wrap_tlv("A1", a1_value)
        a3_value = wrap_tlv("86", b"\xCC\xDD")
        a3_tlv = wrap_tlv("A3", a3_value)
        bpp_bytes = wrap_tlv("BF36", bf23_tlv + a0_tlv + a1_tlv + a3_tlv)
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
        inline_notification = wrap_tlv(
            "BF37",
            wrap_tlv(
                "BF27",
                wrap_tlv("80", b"\x10" * 8)
                + wrap_tlv(
                    "BF2F",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x01\xFD"),
                            wrap_tlv("81", b"\x07\x80"),
                            wrap_tlv("0C", b"rsp.example.com"),
                            wrap_tlv("5A", b"\x89" * 10),
                        ]
                    ),
                )
                + wrap_tlv("06", bytes.fromhex("2B0601040183A40F0004"))
                + wrap_tlv(
                    "A2",
                    wrap_tlv(
                        "A0",
                        wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                        + wrap_tlv("04", bytes.fromhex("3007A0053003800100")),
                    ),
                )
                + wrap_tlv("5F37", b"\x22" * 64),
            ),
        )
        tmp_orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=None,
        )
        expected_segments = tmp_orchestrator._segment_bound_profile_package(bpp_bytes)
        expected_block_count = 0
        for segment in expected_segments:
            expected_block_count += max(1, (len(segment) + 119) // 120)
        apdu_channel = FakeApduChannel(
            load_bpp_response_sequence=[b""] * (expected_block_count - 1) + [inline_notification],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes),
        )
        orchestrator.state.transaction_id = b"\x10" * 16
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        bpp_ready = orchestrator._phase_get_bound_profile_package(smdp_address="rsp.example.com")
        install_complete = orchestrator._phase_install_package()

        self.assertTrue(bpp_ready)
        self.assertTrue(install_complete)
        self.assertEqual(orchestrator.state.bpp_bytes, bpp_bytes)
        self.assertEqual(orchestrator.state.load_bpp_response, inline_notification)
        self.assertEqual(len(orchestrator.profile_provider.handle_notification_calls), 1)
        self.assertEqual(
            orchestrator.profile_provider.handle_notification_calls[0].pending_notification,
            base64.b64encode(inline_notification).decode("utf-8"),
        )
        self.assertEqual(orchestrator.state.load_bpp_aid, bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
        self.assertEqual(orchestrator.state.load_bpp_sima_response, bytes.fromhex("3007A0053003800100"))
        remove_calls = [call for call in apdu_channel.send_calls if "RemoveNotificationFromList" in call[0]]
        self.assertEqual(len(remove_calls), 1)
        self.assertEqual(remove_calls[0][1], bytes.fromhex("80E2910007BF3004800201FD"))
        load_calls = [call for call in apdu_channel.send_calls if call[0].startswith("DOWNLOAD: LoadBoundProfilePackage")]
        self.assertEqual(len(load_calls), expected_block_count)

        # Per SGP.22 Annex M the BPP must split into 7 StoreData chains:
        # BF36-wrapped bootstrap, A0 (wrapped), A1 header, two A1 members,
        # A3 header, one A3 member. Assert the segment boundaries rather
        # than each individual APDU to keep the test chunk-size-agnostic.
        self.assertEqual(len(expected_segments), 7)
        self.assertEqual(self._tag_of_segment(expected_segments[0]), b"\xBF\x36")
        self.assertEqual(self._tag_of_segment(expected_segments[1]), b"\xA0")
        self.assertEqual(self._tag_of_segment(expected_segments[2]), b"\xA1")
        self.assertEqual(self._tag_of_segment(expected_segments[3]), b"\x88")
        self.assertEqual(self._tag_of_segment(expected_segments[4]), b"\x89")
        self.assertEqual(self._tag_of_segment(expected_segments[5]), b"\xA3")
        self.assertEqual(self._tag_of_segment(expected_segments[6]), b"\x86")

        call_index = 0
        for segment_index, segment in enumerate(expected_segments, start=1):
            total_segment_len = len(segment)
            offset = 0
            block_number = 0
            while offset < total_segment_len:
                end_offset = offset + 120
                chunk = segment[offset:end_offset]
                is_last = end_offset >= total_segment_len
                expected_p1 = 0x91 if is_last else 0x11
                expected_label = f"DOWNLOAD: LoadBoundProfilePackage [{segment_index}/{len(expected_segments)}] [Block {block_number}]"
                expected_apdu = bytes([0x80, 0xE2, expected_p1, block_number & 0xFF, len(chunk)]) + chunk
                self.assertEqual(load_calls[call_index][0], expected_label)
                self.assertEqual(load_calls[call_index][1], expected_apdu)
                call_index += 1
                offset += 120
                block_number += 1
        self.assertEqual(call_index, expected_block_count)

    def test_install_package_stops_on_terminal_profile_installation_failure(self):
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
        bf23_tlv = wrap_tlv("BF23", bf23_value)
        bpp_bytes = wrap_tlv("BF36", bf23_tlv + wrap_tlv("A3", wrap_tlv("86", b"\xCC\xDD")))
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
        inline_failure = wrap_tlv(
            "BF37",
            wrap_tlv(
                "BF27",
                wrap_tlv("80", b"\x10" * 8)
                + wrap_tlv(
                    "BF2F",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x01"),
                            wrap_tlv("81", bytes.fromhex("0780")),
                            wrap_tlv("0C", b"rsp.example.com"),
                            wrap_tlv("5A", b"\x89" * 10),
                        ]
                    ),
                )
                + wrap_tlv("06", bytes.fromhex("2B0601040183A40F0004"))
                + wrap_tlv(
                    "A2",
                    wrap_tlv(
                        "A1",
                        wrap_tlv("80", b"\x05") + wrap_tlv("81", b"\x08"),
                    ),
                )
                + wrap_tlv("5F37", b"\x22" * 64),
            ),
        )
        apdu_channel = FakeApduChannel(
            load_bpp_response_sequence=[b"", inline_failure],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes),
        )
        orchestrator.state.transaction_id = b"\x10" * 16
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        bpp_ready = orchestrator._phase_get_bound_profile_package(smdp_address="rsp.example.com")
        self.assertTrue(bpp_ready)

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._phase_install_package()

        self.assertIn("resultCode=5", str(raised.exception))
        self.assertIn("resultDetail=8", str(raised.exception))
        self.assertEqual(orchestrator.state.load_bpp_response, inline_failure)
        load_calls = [call for call in apdu_channel.send_calls if call[0].startswith("DOWNLOAD: LoadBoundProfilePackage")]
        self.assertEqual(len(load_calls), 2)

    def test_install_failure_triggers_cancel_session_cleanup(self):
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
        bf23_tlv = wrap_tlv("BF23", bf23_value)
        bpp_bytes = wrap_tlv("BF36", bf23_tlv + wrap_tlv("A3", wrap_tlv("86", b"\x00")))
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
        provider = FakeProvider(bpp_bytes)
        apdu_channel = FakeApduChannel(fail_load=True)
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        orchestrator.state.transaction_id = b"\x10" * 16
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        bpp_ready = orchestrator._phase_get_bound_profile_package(smdp_address="rsp.example.com")
        self.assertTrue(bpp_ready)

        with self.assertRaises(IOError):
            try:
                orchestrator._phase_install_package()
            except Exception as error:
                orchestrator._attempt_install_failure_cleanup(error)
                raise

        cancel_session_calls = [call for call in apdu_channel.send_calls if call[0] == "DOWNLOAD: CancelSession"]
        self.assertEqual(len(cancel_session_calls), 1)
        self.assertEqual(cancel_session_calls[0][1], bytes.fromhex("80E2910010BF410D80081010101010101010810102"))
        self.assertEqual(len(provider.cancel_session_calls), 1)
        self.assertEqual(provider.cancel_session_calls[0].transaction_id, "EBAQEBAQEBAQEBAQEBAQEA==")
        self.assertEqual(
            provider.cancel_session_calls[0].cancel_session_response,
            base64.b64encode(bytes.fromhex("BF4103810102")).decode("utf-8"),
        )

    def test_install_failure_syncs_notification_list(self):
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
        bf23_tlv = wrap_tlv("BF23", bf23_value)
        bpp_bytes = wrap_tlv("BF36", bf23_tlv + wrap_tlv("A3", wrap_tlv("86", b"\x00")))
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
        notification_list_response = wrap_tlv(
            "BF28",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "BF2F",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x02"),
                            wrap_tlv("81", b"\x80"),
                            wrap_tlv("0C", b"rsp.example.com"),
                            wrap_tlv("5A", b"\x89" * 10),
                        ]
                    ),
                ),
            ),
        )
        notification_cert = build_self_signed_cert().dump()
        pending_notification = wrap_tlv(
            "30",
            wrap_tlv(
                "BF2F",
                b"".join(
                    [
                        wrap_tlv("80", b"\x02"),
                        wrap_tlv("81", b"\x80"),
                        wrap_tlv("0C", b"rsp.example.com"),
                        wrap_tlv("5A", b"\x89" * 10),
                    ]
                ),
            )
            + wrap_tlv("5F37", b"\x44" * 64)
            + notification_cert
            + notification_cert,
        )
        notification_retrieve_response = wrap_tlv(
            "BF2B",
            wrap_tlv("A0", pending_notification),
        )
        provider = FakeProvider(bpp_bytes)
        apdu_channel = FakeApduChannel(
            fail_load=True,
            notification_list_response=notification_list_response,
            notification_retrieve_response=notification_retrieve_response,
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        orchestrator.state.transaction_id = b"\x10" * 16
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        with self.assertRaises(IOError):
            try:
                orchestrator._phase_get_bound_profile_package(smdp_address="rsp.example.com")
                orchestrator._phase_install_package()
            except Exception as error:
                orchestrator._attempt_install_failure_cleanup(error)
                raise

        self.assertEqual(len(provider.handle_notification_calls), 1)
        expected_notification = base64.b64encode(pending_notification).decode("utf-8")
        self.assertEqual(provider.handle_notification_calls[0].pending_notification, expected_notification)
        retrieve_calls = [call for call in apdu_channel.send_calls if "RetrieveNotification" in call[0]]
        self.assertEqual(len(retrieve_calls), 1)
        self.assertEqual(retrieve_calls[0][1], bytes.fromhex("80E2910008BF2B05A003800102"))
        remove_calls = [call for call in apdu_channel.send_calls if "RemoveNotificationFromList" in call[0]]
        self.assertEqual(len(remove_calls), 1)
        self.assertEqual(remove_calls[0][1], bytes.fromhex("80E2910006BF3003800102"))

    def test_install_failure_cleanup_forwards_direct_bf37_pending_notification(self):
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
                            wrap_tlv("84", b"HOST-ID"),
                        ]
                    ),
                ),
                wrap_tlv("5F49", b"\x04" * 65),
                wrap_tlv("5F37", b"\x05" * 64),
            ]
        )
        bf23_tlv = wrap_tlv("BF23", bf23_value)
        bpp_bytes = wrap_tlv("BF36", bf23_tlv + wrap_tlv("A3", wrap_tlv("86", b"\x00")))
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
        notification_list_response = wrap_tlv(
            "BF28",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "BF2F",
                    b"".join(
                        [
                            wrap_tlv("80", b"\x6A"),
                            wrap_tlv("81", bytes.fromhex("0780")),
                            wrap_tlv("0C", b"dpp.example.test"),
                            wrap_tlv("5A", bytes.fromhex("98010300003017672747")),
                        ]
                    ),
                ),
            ),
        )
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
                                    wrap_tlv("0C", b"dpp.example.test"),
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
        provider = FakeProvider(bpp_bytes)
        apdu_channel = FakeApduChannel(
            fail_load=True,
            notification_list_response=notification_list_response,
            notification_retrieve_response=notification_retrieve_response,
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        orchestrator.state.transaction_id = b"\x10" * 16
        orchestrator.state.prepare_download_response_b64 = base64.b64encode(prepare_download_response).decode("utf-8")

        with self.assertRaises(IOError):
            try:
                orchestrator._phase_get_bound_profile_package(smdp_address="rsp.example.com")
                orchestrator._phase_install_package()
            except Exception as error:
                orchestrator._attempt_install_failure_cleanup(error)
                raise

        self.assertEqual(len(provider.handle_notification_calls), 1)
        expected_notification = base64.b64encode(pending_notification).decode("utf-8")
        self.assertEqual(provider.handle_notification_calls[0].pending_notification, expected_notification)

    def test_notification_sync_reselects_isd_r_and_retries_after_6e00(self):
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel(notification_list_response=bytes.fromhex("BF2800"))
        original_send = apdu_channel.send
        list_attempts = {"count": 0}

        def send_with_retry(apdu: bytes, log_name: str) -> bytes:
            if log_name == "DOWNLOAD: ListNotifications":
                apdu_channel.send_calls.append((log_name, apdu))
                list_attempts["count"] += 1
                if list_attempts["count"] == 1:
                    raise IOError("APDU Failed: 6E00")
                return apdu_channel.notification_list_response
            return original_send(apdu, log_name)

        apdu_channel.send = send_with_retry
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertEqual(list_attempts["count"], 2)
        self.assertEqual(provider.handle_notification_calls, [])
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "DOWNLOAD: ListNotifications",
                "DOWNLOAD: RESELECT ISD-R",
                "DOWNLOAD: ListNotifications",
            ],
        )
        self.assertEqual(
            apdu_channel.send_calls[1][1],
            bytes([0x00, 0xA4, 0x04, 0x00, len(cfg.AID_ISD_R)]) + cfg.AID_ISD_R,
        )

    def test_decode_eim_configuration_entries_extracts_bf55_fields(self):
        tls_key_material = bytes.fromhex(
            "301306072A8648CE3D020106082A8648CE3D03010703420004"
            + "11" * 64
        )
        eim_entry = wrap_tlv(
            "A0",
            wrap_tlv(
                "30",
                b"".join(
                    [
                        wrap_tlv("80", b"manager-1"),
                        wrap_tlv("81", b"eim.example.com"),
                        wrap_tlv("82", b"\x03"),
                        wrap_tlv("83", b"\x04"),
                        wrap_tlv("84", bytes.fromhex("A1B2C3D4")),
                        wrap_tlv("87", b"\x02"),
                        wrap_tlv("88", bytes.fromhex("01020304")),
                        wrap_tlv("89", b"\x01"),
                        wrap_tlv("A6", wrap_tlv("A0", tls_key_material)),
                    ]
                ),
            ),
        )
        response = wrap_tlv("BF55", eim_entry)
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        entries = orchestrator._decode_eim_configuration_entries(response)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["eim_fqdn"], "eim.example.com")
        self.assertEqual(entries[0]["eim_id"], "manager-1")
        self.assertEqual(entries[0]["eim_id_type"], "eimIdTypeProprietary (3)")
        self.assertEqual(entries[0]["counter_value"], "4")
        self.assertEqual(entries[0]["association_token"], "2712847316")
        self.assertEqual(entries[0]["supported_protocol"], "02 (set: none)")
        self.assertEqual(entries[0]["euicc_ci_pkid"], "01020304")
        self.assertEqual(entries[0]["indirect_profile_download"], "Present")
        self.assertEqual(
            entries[0]["trusted_tls_public_key_data"],
            wrap_tlv("30", tls_key_material),
        )

    def test_decode_eim_configuration_entries_extracts_spki_from_certificate_a6(self):
        certificate_der = build_self_signed_cert().dump()
        expected_spki = crypto_x509.load_der_x509_certificate(certificate_der).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        eim_entry = wrap_tlv(
            "A0",
            wrap_tlv(
                "30",
                b"".join(
                    [
                        wrap_tlv("80", b"manager-1"),
                        wrap_tlv("81", b"eim.example.com"),
                        wrap_tlv("82", b"\x03"),
                        wrap_tlv("A6", wrap_tlv("A1", certificate_der)),
                    ]
                ),
            ),
        )
        response = wrap_tlv("BF55", eim_entry)
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        entries = orchestrator._decode_eim_configuration_entries(response)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["trusted_tls_public_key_data"], expected_spki)

    def test_build_eim_poll_request_uses_tlv_eid_value(self):
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
                            wrap_tlv("81", b"eim.example.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator._phase_eim_card_challenge()
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)
        expected_body = orchestrator._build_get_eim_package_tlv(request.eid)

        self.assertEqual(request.eid, "89044045930000000000001492294428")
        self.assertEqual(request.raw_body, expected_body)
        self.assertTrue(
            any(call[0] == "EIM: RESELECT ISD-R" for call in apdu_channel.send_calls),
            "ISD-R must be reselected after reading EID from ECASD.",
        )

    def test_build_eim_poll_request_variant_one_includes_challenge(self):
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
                            wrap_tlv("81", b"eim.example.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(EIM_REQUEST_VARIANT=1),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator._phase_eim_card_challenge()
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(
            request.raw_body,
            orchestrator._build_get_eim_package_tlv(
                request.eid,
                orchestrator.state.card_challenge,
            ),
        )

    def test_build_eim_poll_request_includes_challenge_for_live_1ot_endpoint(self):
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
                            wrap_tlv("81", b"eim.example.test"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator._phase_eim_card_challenge()
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(
            request.raw_body,
            orchestrator._build_get_eim_package_tlv(
                request.eid,
                euicc_challenge_bytes=orchestrator.state.card_challenge,
            ),
        )

    def test_build_get_eim_package_tlv_supports_notify_and_rplmn(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        payload = orchestrator._build_get_eim_package_tlv(
            "89044045930000000000001492294428",
            euicc_challenge_bytes=bytes.fromhex("5B2C6EF395AFB69CBFB3212E6427A16E"),
            notify_state_change=True,
            rplmn_bytes=bytes.fromhex("262901"),
        )

        self.assertEqual(
            payload,
            bytes.fromhex(
                "BF4F195A1089044045930000000000001492294428"
                "8000"
                "8203262901"
            ),
        )

    def test_build_provide_eim_package_result_uses_single_choice_wrapper(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        card_response = wrap_tlv("BF51", wrap_tlv("80", b"\x01"))

        payload = orchestrator._build_provide_eim_package_result_tlv(
            card_response,
            eid="89044045930000000000001492294428",
        )

        self.assertEqual(
            payload,
            bytes.fromhex("BF50185A1089044045930000000000001492294428BF5103800101"),
        )

    def test_run_eim_poll_builds_request_and_relays_package(self):
        tls_key_material = bytes.fromhex(
            "301306072A8648CE3D020106082A8648CE3D03010703420004"
            + "22" * 64
        )
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
                            wrap_tlv("81", b"eim.example.com"),
                            wrap_tlv("82", b"\x01"),
                            wrap_tlv("83", b"\x05"),
                            wrap_tlv("84", bytes.fromhex("DEADBEEF")),
                            wrap_tlv("87", b"\x02"),
                            wrap_tlv("88", bytes.fromhex("01020304")),
                            wrap_tlv("89", b"\x01"),
                            wrap_tlv("A6", wrap_tlv("A0", tls_key_material)),
                        ]
                    ),
                ),
            ),
        )
        card_package = wrap_tlv("BF70", wrap_tlv("80", b"\x01\x02"))
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[base64.b64encode(card_package).decode("utf-8")],
                    polling_complete=False,
                ),
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[],
                    polling_complete=True,
                    eim_result_code=1,
                ),
            ],
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
            eim_package_response=bytes.fromhex("BF3700"),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(len(provider.poll_eim_calls), 1)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        first_request = provider.poll_eim_calls[0]
        self.assertEqual(first_request.eim_fqdn, "eim.example.com")
        self.assertEqual(first_request.eim_id, "manager-1")
        self.assertEqual(first_request.matching_id, "MATCH-1")
        self.assertEqual(first_request.association_token, "3735928559")
        self.assertEqual(first_request.euicc_configured_data, base64.b64encode(configured_data).decode("utf-8"))
        self.assertEqual(first_request.eim_configuration_data, base64.b64encode(eim_configuration).decode("utf-8"))
        self.assertEqual(first_request.euicc_package_result, "")
        self.assertNotEqual(first_request.euicc_challenge, "", "eIM poll must send euiccChallenge (card challenge).")
        self.assertEqual(first_request.trusted_tls_public_key_data, wrap_tlv("30", tls_key_material))
        self.assertEqual(
            first_request.raw_body,
            orchestrator._build_get_eim_package_tlv(first_request.eid),
        )

        provide_request = provider.provide_eim_package_result_calls[0]
        self.assertEqual(provide_request.euicc_package_result, "")
        self.assertEqual(
            provide_request.raw_body,
            bytes.fromhex("BF50185A1089044045930000000000001492294428BF5103BF3700"),
        )

        relay_calls = [call for call in apdu_channel.send_calls if call[0].startswith("EIM: RelayPackage")]
        self.assertEqual(len(relay_calls), 1)
        self.assertEqual(
            relay_calls[0][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(card_package)]) + card_package,
        )

    def test_poll_eim_timeout_does_not_retry(self):
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_errors=[TimeoutError("The read operation timed out")],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        orchestrator.state.card_challenge = bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        challenge_b64 = orchestrator._eim_euicc_challenge_b64(orchestrator.state.card_challenge)
        request = EimPollRequest(
            eim_fqdn="eim.example.com",
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
            euicc_challenge=challenge_b64,
            raw_body=bytes.fromhex("BF4F125A1089044045930000000000001492294428"),
        )

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._poll_eim(request)

        self.assertIn("Provider getEimPackage failed", str(raised.exception))
        self.assertEqual(len(provider.poll_eim_calls), 1)
        self.assertEqual(provider.poll_eim_calls[0].raw_body, request.raw_body)

    def test_build_get_eim_package_variant_requests_includes_alternatives(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        request = EimPollRequest(
            eim_fqdn="eim.example.test",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            euicc_info2=base64.b64encode(bytes.fromhex("BF2208810302600116840100")).decode("utf-8"),
            eid="89044045930000000000001492294428",
            euicc_challenge=orchestrator._eim_euicc_challenge_b64(bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")),
            raw_body=bytes.fromhex(
                "BF4F195A1089044045930000000000001492294428"
                "8000"
                "8203260116"
            ),
        )

        variants = orchestrator._build_get_eim_package_variant_requests(request)

        variant_names = [name for name, _ in variants]
        self.assertIn("eid-only", variant_names)
        self.assertIn("notify-state-change", variant_names)
        self.assertNotIn("notify-state-change-cause", variant_names)
        self.assertNotIn("challenge", variant_names)

    def test_get_eim_package_probes_variants_after_undefined_error(self):
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(eim_result_code=127, polling_complete=True),
                EimPollResponse(eim_result_code=1, polling_complete=True),
            ],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        request = EimPollRequest(
            eim_fqdn="eim.example.test",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            euicc_info2=base64.b64encode(bytes.fromhex("BF2208810302600116840100")).decode("utf-8"),
            eid="89044045930000000000001492294428",
            euicc_challenge=orchestrator._eim_euicc_challenge_b64(bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")),
            raw_body=bytes.fromhex(
                "BF4F195A1089044045930000000000001492294428"
                "8000"
                "8203260116"
            ),
        )
        response = orchestrator._get_eim_package(request)

        self.assertEqual(response.eim_result_code, 1)
        self.assertEqual(len(provider.poll_eim_calls), 2)

    def test_get_eim_package_timeout_probes_variants(self):
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_errors=[TimeoutError("The read operation timed out")],
            eim_poll_responses=[EimPollResponse(eim_result_code=1, polling_complete=True)],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        request = EimPollRequest(
            eim_fqdn="eim.example.test",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            euicc_info2=base64.b64encode(bytes.fromhex("BF2208810302600116840100")).decode("utf-8"),
            eid="89044045930000000000001492294428",
            euicc_challenge=orchestrator._eim_euicc_challenge_b64(bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")),
            raw_body=bytes.fromhex(
                "BF4F1C5A1089044045930000000000001492294428"
                "80008101038203260116"
            ),
        )

        response = orchestrator._get_eim_package(request)

        self.assertEqual(response.eim_result_code, 1)
        self.assertEqual(len(provider.poll_eim_calls), 2)

    def test_run_eim_poll_raises_on_explicit_undefined_error_127(self):
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(eim_result_code=127, polling_complete=True),
            ],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        orchestrator._phase_connect = lambda: None
        orchestrator._phase_eim_card_challenge = lambda: None
        orchestrator._resolve_eim_poll_entry_indices = lambda entry_index=None: [0]
        orchestrator._build_eim_poll_request = lambda matching_id="", entry_index=0: EimPollRequest(
            eim_fqdn="eim.example.test",
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
            orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertIn("undefinedError(127)", str(raised.exception))
        self.assertEqual(len(provider.poll_eim_calls), 2)

    def test_relay_profile_download_trigger_runs_profile_download_flow(self):
        provider = FakeProvider(bpp_bytes=b"")
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        orchestrator.state.load_bpp_response = bytes.fromhex("BF3700")
        captured = {}

        def fake_run_flow(matching_id: str = "", smdp_address: str = ""):
            captured["matching_id"] = matching_id
            captured["smdp_address"] = smdp_address

        orchestrator.run_flow = fake_run_flow
        package = wrap_tlv(
            "BF54",
            wrap_tlv("82", b"\x01\x02\x03\x04")
            + wrap_tlv("30", wrap_tlv("80", b"LPA:1$rsp.example.com$MATCH-54")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertEqual(captured["matching_id"], "MATCH-54")
        self.assertEqual(captured["smdp_address"], "rsp.example.com")
        self.assertEqual(provider.base_url_calls, ["https://rsp.example.com"])
        self.assertEqual(response, bytes.fromhex("BF5409820401020304BF3700"))

    def test_provider_certificate_payload_supported_accepts_raw_der_x509(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=None,
        )

        self.assertTrue(
            orchestrator._provider_certificate_payload_supported(build_self_signed_cert().dump())
        )
        self.assertFalse(orchestrator._provider_certificate_payload_supported(b"not-a-certificate"))

    def test_relay_ipa_euicc_data_request_builds_local_bf52_response(self):
        configured_data = wrap_tlv(
            "BF3C",
            b"".join(
                [
                    wrap_tlv("80", b"rsp.example.com"),
                    wrap_tlv("81", b"lpa.ds.gsma.com"),
                ]
            ),
        )
        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    b"".join(
                        [
                            wrap_tlv("80", b"manager-1"),
                            wrap_tlv("81", b"eim.example.com"),
                            wrap_tlv("82", b"\x01"),
                            wrap_tlv("84", bytes.fromhex("DEADBEEF")),
                        ]
                    ),
                ),
            ),
        )
        euicc_info2 = wrap_tlv("BF22", wrap_tlv("83", b"\x01\x02\x03"))
        notification_item = wrap_tlv(
            "A0",
            wrap_tlv(
                "BF2F",
                b"".join(
                    [
                        wrap_tlv("80", b"\x02"),
                        wrap_tlv("81", b"\x80"),
                        wrap_tlv("0C", b"rsp.example.com"),
                    ]
                ),
            ),
        )
        notification_list = wrap_tlv("BF2B", notification_item)
        euicc_package_result_list = wrap_tlv("BF2B", wrap_tlv("A2", b""))
        eum_cert = wrap_tlv("A5", wrap_tlv("30", b"\x01\x02\x03"))
        euicc_cert = wrap_tlv("A6", wrap_tlv("30", b"\x04\x05\x06"))
        certs_response = wrap_tlv("BF56", eum_cert + euicc_cert)
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(
                notification_retrieve_response=notification_list,
                euicc_package_result_list_response=euicc_package_result_list,
                eim_configuration_response=eim_configuration,
                configured_data_response=configured_data,
                euicc_info2_response=euicc_info2,
                certs_response=certs_response,
            ),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        package = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A081A2BF20BF228384A5A6A8A9"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A1")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertTrue(response.startswith(bytes.fromhex("BF52")))
        _, bf52_value, _, _ = _read_test_tlv(response, 0)
        self.assertTrue(
            bf52_value.startswith(b"\xA0"),
            "IpaEuiccDataResponse CHOICE ipaEuiccData requires [0] (0xA0) tag",
        )
        self.assertIn(notification_item, response)
        self.assertIn(wrap_tlv("81", b"rsp.example.com"), response)
        self.assertIn(wrap_tlv("A2", b""), response)
        self.assertIn(bytes.fromhex("BF2000"), response)
        self.assertIn(euicc_info2, response)
        self.assertIn(wrap_tlv("83", b"lpa.ds.gsma.com"), response)
        self.assertIn(bytes.fromhex("8404DEADBEEF"), response)
        self.assertIn(eum_cert, response)
        self.assertIn(euicc_cert, response)
        self.assertIn(bytes.fromhex("A808800202C481020780"), response)
        self.assertNotIn(bytes.fromhex("A9"), response)
        self.assertIn(bytes.fromhex("870800000000000004A1"), response)
        relay_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if call[0] == "EIM: RelayPackage [poll=1 package=1]"
        ]
        self.assertEqual(relay_calls, [])
        notification_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if "RetrieveNotificationsList" in call[0]
        ]
        self.assertEqual(len(notification_calls), 1)
        self.assertEqual(notification_calls[0][1], bytes.fromhex("80E2910003BF2B00"))
        package_result_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if "RetrieveEuiccPackageResults" in call[0]
        ]
        self.assertEqual(len(package_result_calls), 1)
        self.assertEqual(package_result_calls[0][1], bytes.fromhex("80E2910005BF2B028200"))

    def test_relay_ipa_euicc_data_request_returns_empty_a2_when_card_returns_other_choice(self):
        configured_data = wrap_tlv(
            "BF3C",
            b"".join(
                [
                    wrap_tlv("80", b"rsp.example.com"),
                    wrap_tlv("81", b"lpa.ds.gsma.com"),
                ]
            ),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(
                configured_data_response=configured_data,
                euicc_package_result_list_response=wrap_tlv("BF2B", wrap_tlv("A0", b"")),
            ),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        package = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("81A2A8"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A4")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertTrue(response.startswith(bytes.fromhex("BF52")))
        _, bf52_value, _, _ = _read_test_tlv(response, 0)
        self.assertTrue(
            bf52_value.startswith(b"\xA0"),
            "IpaEuiccDataResponse CHOICE ipaEuiccData requires [0] (0xA0) tag",
        )
        self.assertIn(wrap_tlv("81", b"rsp.example.com"), response)
        self.assertIn(wrap_tlv("A2", b""), response)
        self.assertIn(bytes.fromhex("A808800202C481020780"), response)
        self.assertIn(bytes.fromhex("870800000000000004A4"), response)

    def test_relay_ipa_euicc_data_request_filters_package_results_by_sequence_number(self):
        euicc_package_result = wrap_tlv("BF51", bytes.fromhex("010203"))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(
                euicc_package_result_list_response=wrap_tlv("BF2B", wrap_tlv("A2", euicc_package_result)),
            ),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        package = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A2"))
            + wrap_tlv("A2", wrap_tlv("80", b"\x02"))
            + wrap_tlv("83", bytes.fromhex("00000000000004A5")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertIn(wrap_tlv("A2", euicc_package_result), response)
        package_result_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if "RetrieveEuiccPackageResults" in call[0]
        ]
        self.assertEqual(len(package_result_calls), 1)
        self.assertEqual(package_result_calls[0][1], bytes.fromhex("80E2910008BF2B05A003800102"))

    def test_run_eim_poll_finishes_on_no_package_result(self):
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
                            wrap_tlv("81", b"eim.example.com"),
                            wrap_tlv("82", b"\x01"),
                        ]
                    ),
                ),
            ),
        )
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[],
                    polling_complete=True,
                    eim_result_code=1,
                ),
            ],
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(len(provider.poll_eim_calls), 1)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 0)
        relay_calls = [call for call in apdu_channel.send_calls if call[0].startswith("EIM: RelayPackage")]
        self.assertEqual(relay_calls, [])

    def test_run_eim_poll_processes_multiple_eim_entries_sequentially(self):
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
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[],
                    polling_complete=True,
                    eim_result_code=1,
                ),
                EimPollResponse(
                    transaction_id="tx-2",
                    euicc_package_list=[],
                    polling_complete=True,
                    eim_result_code=1,
                ),
            ],
        )
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89044045930000000000001492294428")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(provider.poll_eim_calls[0].eim_fqdn, "eim1.example.com")
        self.assertEqual(provider.poll_eim_calls[1].eim_fqdn, "eim2.example.com")
        self.assertEqual(provider.poll_eim_calls[0].eim_id, "manager-1")
        self.assertEqual(provider.poll_eim_calls[1].eim_id, "manager-2")


class PySimSupportTests(unittest.TestCase):
    def test_test_and_live_pysim_support_decode_certificate_with_vendored_repo_path(self):
        certificate_der = build_self_signed_cert().dump()

        self.assertTrue(test_pysim_support.pysim_available())
        self.assertTrue(live_pysim_support.pysim_available())
        self.assertIsNotNone(test_pysim_support.decode_certificate(certificate_der))
        self.assertIsNotNone(live_pysim_support.decode_certificate(certificate_der))

    def test_test_and_live_pysim_support_missing_aki_returns_empty_bytes(self):
        certificate_der = build_self_signed_cert().dump()

        self.assertEqual(test_pysim_support.get_certificate_authority_key_identifier(certificate_der), b"")
        self.assertEqual(live_pysim_support.get_certificate_authority_key_identifier(certificate_der), b"")


if __name__ == "__main__":
    unittest.main()
