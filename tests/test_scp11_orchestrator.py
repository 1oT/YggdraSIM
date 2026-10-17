# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import datetime
import base64
import contextlib
import copy
import io
import os
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
from SCP11.live.models import BACKEND_MODE_LOCAL_SGP26, EimPollRequest, EimPollResponse
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.shared.trace_dump import split_tlv_aware_chunks

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


def _euicc_package_result_entry(seq_number: int) -> bytes:
    """One SGP.32 §2.11.2.1 EuiccPackageResult carrying ``seqNumber [3]``."""
    result_data_signed = wrap_tlv(
        "30",
        b"".join(
            [
                wrap_tlv("80", b"manager-1"),
                wrap_tlv("81", b"\x01"),
                wrap_tlv("83", bytes([seq_number])),
                wrap_tlv("30", b""),
            ]
        ),
    )
    signed = wrap_tlv("A0", result_data_signed + wrap_tlv("5F37", bytes([seq_number]) * 64))
    return wrap_tlv("BF51", signed)


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

    def send_chunked(self, cla, ins, p1, p2_start, payload, log_name, chunk_size=0xFF):
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
    """Fails the first GetEuiccInfo1 with 6985 and refuses MANAGE CHANNEL
    OPEN so the orchestrator must fall through the new logical-channel
    recovery layer and reach the STK mode bootstrap. This still
    exercises the original 6985 → STK contract once the chained
    fallback exhausts the safer recovery options.
    """

    def __init__(self):
        super().__init__()
        self._fail_info1_once = True

    def send(self, apdu: bytes, log_name: str) -> bytes:
        if "[OPEN LOGICAL CHANNEL]" in log_name:
            self.send_calls.append((log_name, apdu))
            raise IOError("APDU Failed: 6881")
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
        if "[STK MODE BASIC]" in log_name and "GetEuiccInfo1" in log_name:
            self.send_calls.append((log_name, apdu))
            return bytes.fromhex("BF2000")
        if "[STK MODE BASIC]" in log_name and "GetEuiccChallenge" in log_name:
            self.send_calls.append((log_name, apdu))
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        return super().send(apdu, log_name)


class DecliningRelayApduChannel(FakeApduChannel):
    """Raises ``declined_error`` for a relayed eIM package under ``declined_tag``.

    Every other relayed package gets the configured ``eim_package_response``.
    """

    def __init__(self, declined_tag: bytes, declined_error: Exception, **kwargs):
        super().__init__(**kwargs)
        self.declined_tag = declined_tag
        self.declined_error = declined_error

    def send(self, apdu: bytes, log_name: str) -> bytes:
        if "EIM: RelayPackage" in log_name and apdu[5:].startswith(self.declined_tag):
            self.send_calls.append((log_name, apdu))
            raise self.declined_error
        return super().send(apdu, log_name)


class NotificationQueueApduChannel(FakeApduChannel):
    """An eUICC Pending Notifications List behind ES10b List / Retrieve / Remove (SGP.22 v3.1 §5.7.9-§5.7.11).

    ``pending`` maps a seqNumber to the PendingNotification the card holds.
    MANAGE CHANNEL OPEN returns CH1, so a flow that opens its own channel
    can be told apart from one that inherited it.
    """

    def __init__(self, pending=None, **kwargs):
        super().__init__(**kwargs)
        self.pending = dict(pending or {})

    def send(self, apdu: bytes, log_name: str) -> bytes:
        if log_name == "INIT: OPEN LOGICAL CHANNEL":
            self.send_calls.append((log_name, apdu))
            return b"\x01"
        if log_name == "DOWNLOAD: ListNotifications":
            self.send_calls.append((log_name, apdu))
            metadata = b""
            for notification in self.pending.values():
                metadata += _read_test_tlv(notification, notification.find(bytes.fromhex("BF2F")))[2]
            return wrap_tlv("BF28", wrap_tlv("A0", metadata))
        if log_name.startswith("DOWNLOAD: RetrieveNotification ["):
            self.send_calls.append((log_name, apdu))
            seq_number = int(log_name[len("DOWNLOAD: RetrieveNotification ["):-1])
            return wrap_tlv("BF2B", wrap_tlv("A0", self.pending.get(seq_number, b"")))
        if "RemoveNotificationFromList" in log_name:
            self.send_calls.append((log_name, apdu))
            _tag, request_value, _raw, _end = _read_test_tlv(apdu[5:], 0)
            _tag, seq_bytes, _raw, _end = _read_test_tlv(request_value, 0)
            if self.pending.pop(int.from_bytes(seq_bytes, "big"), None) is not None:
                return bytes.fromhex("BF3003800100")
            return bytes.fromhex("BF3003800101")
        return super().send(apdu, log_name)


# SGP.26 v3.0.2 test eUICC EID (page 11, the Test eUICC certificate serialNumber).
TEST_EID = "89049032123451234512345678901235"


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
    EIM_VENDOR_QUIRK_FQDN_SUFFIXES: tuple = ("example.test",)


class FakeProvider:
    def __init__(self, bpp_bytes: bytes, eim_poll_responses=None, eim_poll_errors=None):
        self._bpp_bytes = bpp_bytes
        self.cancel_session_calls = []
        self.handle_notification_calls = []
        self.handle_notification_esipa_calls = []
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

    def handle_notification_esipa(self, request_obj):
        self.handle_notification_esipa_calls.append(copy.deepcopy(request_obj))
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

    def _seed_local_credentials(self, orchestrator: SGP22Orchestrator) -> None:
        cert = build_self_signed_cert()
        private_key = ec.generate_private_key(ec.SECP256R1())
        orchestrator.cert_auth = cert
        orchestrator.key_auth = private_key
        orchestrator.cert_pb = cert
        orchestrator.key_pb = private_key
        orchestrator._local_credentials_loaded = True

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

    def test_direct_download_gets_challenge_for_smdp_authentication(self):
        cfg = FakeCfg()
        cfg.CAPABILITIES = {
            "gsmSupportedRelease": b"\x99\x00\x00",
            "utranSupportedRelease": b"\x99\x00\x00",
            "eutranEpcSupportedRelease": b"\x99\x00\x00",
        }
        apdu_channel = FakeApduChannel()
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        self._seed_local_credentials(orchestrator)

        orchestrator.run_flow(matching_id="MATCH-DIRECT", smdp_address="rsp.example.com")

        call_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("HANDSHAKE: GetEuiccChallenge", call_names)
        self.assertFalse(any(name == "EIM: GetEuiccChallenge" for name in call_names))
        self.assertEqual(
            orchestrator.state.card_challenge,
            bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55"),
        )

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
                "HANDSHAKE: GetEuiccInfo1 [OPEN LOGICAL CHANNEL]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE TERMINAL CAPABILITY]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE SELECT ISD-R]",
                "HANDSHAKE: GetEuiccInfo1 [STK MODE BASIC]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE TERMINAL CAPABILITY]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE SELECT ISD-R]",
                "HANDSHAKE: GetEuiccChallenge [STK MODE BASIC]",
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

        # TCA eUICC Profile Package V3.4.1 section 8.11 EUICCResponse.
        self.assertIn("3007A0053003800100", formatted)
        self.assertIn("30(len=7, EUICCResponse)", formatted)
        self.assertIn("A0(len=5, peStatus)", formatted)
        self.assertIn("30(len=3, PEStatus)", formatted)
        self.assertIn("80(len=1, status)=00", formatted)
        self.assertIn("peStatus[0].status=ok(0)", formatted)

    def test_format_sima_response_shows_failure_detail(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        formatted = orchestrator._format_sima_response(
            bytes.fromhex("3026A016300980010381010583010C30098001068101078201028100820A6261642076616C756573")
        )

        self.assertIn("30(len=9, PEStatus)", formatted)
        self.assertIn("80(len=1, status)=03", formatted)
        self.assertIn("81(len=1, identification)=05", formatted)
        self.assertIn("83(len=1, offset)=0C", formatted)
        self.assertIn("81(len=0, profileInstallationAborted)=", formatted)
        self.assertIn("82(len=10, statusMessage)=", formatted)
        self.assertIn("peStatus[0].status=bad-values(3) identification=5 offset=12", formatted)
        self.assertIn("peStatus[1].status=invalid-parameter(6) identification=7 additional-information=2", formatted)
        self.assertIn("profileInstallationAborted", formatted)
        self.assertIn("statusMessage='bad values'", formatted)

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
        chunk_size = 0xFF
        expected_block_count = 0
        for segment in expected_segments:
            expected_block_count += len(split_tlv_aware_chunks(segment, chunk_size))
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
            chunks = split_tlv_aware_chunks(segment, chunk_size)
            for block_number, chunk in enumerate(chunks):
                is_last = block_number == len(chunks) - 1
                expected_p1 = 0x91 if is_last else 0x11
                expected_label = f"DOWNLOAD: LoadBoundProfilePackage [{segment_index}/{len(expected_segments)}] [Block {block_number}]"
                expected_apdu = bytes([0x80, 0xE2, expected_p1, block_number & 0xFF, len(chunk)]) + chunk
                self.assertEqual(load_calls[call_index][0], expected_label)
                self.assertEqual(load_calls[call_index][1], expected_apdu)
                call_index += 1
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
                            wrap_tlv("0C", b"dpp1.example.test"),
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

    def test_notification_sync_uses_bf2b_fallback_when_bf28_returns_6a88(self):
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
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel(notification_retrieve_response=notification_retrieve_response)
        original_send = apdu_channel.send

        def send_with_bf28_quirk(apdu: bytes, log_name: str) -> bytes:
            if log_name == "DOWNLOAD: ListNotifications":
                apdu_channel.send_calls.append((log_name, apdu))
                raise IOError("APDU Failed: 6A88")
            return original_send(apdu, log_name)

        apdu_channel.send = send_with_bf28_quirk
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertEqual(len(provider.handle_notification_calls), 1)
        expected_notification = base64.b64encode(pending_notification).decode("utf-8")
        self.assertEqual(provider.handle_notification_calls[0].pending_notification, expected_notification)
        send_logs = [entry[0] for entry in apdu_channel.send_calls]
        self.assertIn("DOWNLOAD: RetrieveNotificationsList (BF28 fallback)", send_logs)
        self.assertIn("DOWNLOAD: RetrieveNotification [106]", send_logs)
        self.assertIn("DOWNLOAD: RemoveNotificationFromList [106]", send_logs)
        self.assertIs(orchestrator._last_notification_sync_succeeded, True)

    def test_list_notifications_bf2b_fallback_notice_is_hidden_when_debug_off(self):
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        notification_retrieve_response = wrap_tlv("BF2B", wrap_tlv("A0", b""))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(notification_retrieve_response=notification_retrieve_response),
            profile_provider=FakeProvider(b""),
        )
        buffer = io.StringIO()

        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "0"}, clear=False):
            with contextlib.redirect_stdout(buffer):
                result = orchestrator._list_pending_notifications_via_retrieve_fallback(
                    IOError("APDU Failed: 6985")
                )

        self.assertEqual(result, bytes.fromhex("BF2802A000"))
        self.assertNotIn("ListNotifications rejected", buffer.getvalue())

    def test_list_notifications_bf2b_fallback_notice_surfaces_when_debug_on(self):
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        notification_retrieve_response = wrap_tlv("BF2B", wrap_tlv("A0", b""))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(notification_retrieve_response=notification_retrieve_response),
            profile_provider=FakeProvider(b""),
        )
        buffer = io.StringIO()

        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "1"}, clear=False):
            with contextlib.redirect_stdout(buffer):
                result = orchestrator._list_pending_notifications_via_retrieve_fallback(
                    IOError("APDU Failed: 6985")
                )

        self.assertEqual(result, bytes.fromhex("BF2802A000"))
        self.assertIn("ListNotifications rejected", buffer.getvalue())

    def test_list_notifications_recovery_notices_are_hidden_when_debug_off(self):
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        response = bytes.fromhex("BF2B02A000")

        def fake_send(apdu: bytes, log_name: str = "") -> bytes:
            if log_name.startswith("DOWNLOAD: ListNotifications"):
                raise IOError("APDU Failed: 6985")
            if log_name == "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)":
                raise IOError("APDU Failed: 6985")
            if log_name.endswith("(BF28 fallback) [ACTIVE CH1]"):
                return response
            return b""

        apdu_channel = FakeApduChannel()
        apdu_channel.send = fake_send
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(b""),
        )
        orchestrator._es10b_logical_channel = 1
        buffer = io.StringIO()

        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "0"}, clear=False):
            with contextlib.redirect_stdout(buffer):
                result = orchestrator._list_pending_notifications_with_context_recovery()

        self.assertEqual(result, bytes.fromhex("BF2802A000"))
        self.assertNotIn("priming active logical channel", buffer.getvalue())

    def test_list_notifications_recovery_notices_surface_when_debug_on(self):
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        response = bytes.fromhex("BF2B02A000")

        def fake_send(apdu: bytes, log_name: str = "") -> bytes:
            if log_name.startswith("DOWNLOAD: ListNotifications"):
                raise IOError("APDU Failed: 6985")
            if log_name == "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)":
                raise IOError("APDU Failed: 6985")
            if log_name.endswith("(BF28 fallback) [ACTIVE CH1]"):
                return response
            return b""

        apdu_channel = FakeApduChannel()
        apdu_channel.send = fake_send
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(b""),
        )
        orchestrator._es10b_logical_channel = 1
        buffer = io.StringIO()

        with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: "1"}, clear=False):
            with contextlib.redirect_stdout(buffer):
                result = orchestrator._list_pending_notifications_with_context_recovery()

        self.assertEqual(result, bytes.fromhex("BF2802A000"))
        self.assertIn("priming active logical channel 1", buffer.getvalue())

    def test_retrieve_notification_reports_bf2b_result_error(self):
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel(notification_retrieve_response=bytes.fromhex("BF2B0381017F"))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        with mock.patch("builtins.print") as print_mock:
            result = orchestrator._retrieve_pending_notification(186)

        rendered = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if len(call.args) > 0)
        self.assertEqual(result, b"")
        self.assertIn("notificationsListResultError=undefinedError(127)", rendered)
        self.assertIn("seq=186", rendered)
        self.assertNotIn("no decodable pending notification", rendered)
        retrieve_calls = [call for call in apdu_channel.send_calls if call[0] == "DOWNLOAD: RetrieveNotification [186]"]
        self.assertEqual(len(retrieve_calls), 1)
        self.assertEqual(retrieve_calls[0][1], bytes.fromhex("80E2910009BF2B06A004800200BA"))

    def test_retrieve_notification_request_encodes_high_bit_sequence_as_positive_integer(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(b""),
        )

        payload = orchestrator._build_retrieve_notification_request_payload(188)

        self.assertEqual(payload, bytes.fromhex("BF2B06A004800200BC"))

    def test_notification_sync_recovers_from_6e00_via_fresh_logical_channel(self):
        # Regression for the EnableProfile → notification-read cascade:
        # ETSI TS 102 221 §11.1.17 + SGP.22 §5.7.12. BF28 *and* BF2B both
        # hit 6E00 because the supplementary CH was dropped during the
        # profile state change, so the ES10b session is the suspect rather
        # than the card's function set. Only that combination licenses the
        # orchestrator to reset the transport, reopen ISD-R on a fresh
        # logical channel via MANAGE CHANNEL OPEN, replay the StoreData
        # with the matching CLA, then close the channel.
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()
        original_send = apdu_channel.send
        fallback_log = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"
        list_attempts = {"count": 0}
        retrieve_attempts = {"count": 0}
        reset_calls = {"count": 0}

        def send_with_recovery(apdu: bytes, log_name: str) -> bytes:
            if log_name == "DOWNLOAD: ListNotifications":
                apdu_channel.send_calls.append((log_name, apdu))
                list_attempts["count"] += 1
                raise IOError("APDU Failed: 6E00")
            if log_name.startswith(fallback_log) is False:
                return original_send(apdu, log_name)
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == fallback_log:
                retrieve_attempts["count"] += 1
                raise IOError("APDU Failed: 6E00")
            if log_name.endswith("[OPEN LOGICAL CHANNEL]"):
                return b"\x01\x90\x00"
            if log_name.endswith("[CH1]"):
                return bytes.fromhex("BF2B02A000")
            return b""

        def fake_reset() -> bool:
            reset_calls["count"] += 1
            return True

        apdu_channel.send = send_with_recovery
        apdu_channel.reset = fake_reset

        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertEqual(list_attempts["count"], 1)
        # One probe on the live channel, then the ladder's own first send.
        self.assertEqual(retrieve_attempts["count"], 2)
        # 6E00 is the card answering, so the ladder rebuilds the channel
        # without power-cycling it.
        self.assertEqual(reset_calls["count"], 0)
        self.assertEqual(orchestrator._es10b_logical_channel, 0)
        self.assertEqual(provider.handle_notification_calls, [])
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "DOWNLOAD: ListNotifications",
                fallback_log,
                fallback_log,
                f"{fallback_log} [OPEN LOGICAL CHANNEL]",
                f"{fallback_log} [SELECT ISD-R CH1]",
                f"{fallback_log} [TERMINAL CAPABILITY]",
                f"{fallback_log} [STATUS CH0]",
                f"{fallback_log} [CH1]",
                f"{fallback_log} [CLOSE LOGICAL CHANNEL 1]",
            ],
        )
        self.assertIs(orchestrator._last_notification_sync_succeeded, True)
        # BF2B only answered after the session was rebuilt, which says
        # nothing about whether the card implements BF28.
        self.assertFalse(orchestrator._es10b_list_notifications_unsupported)

    def test_notification_sync_primes_active_logical_channel_before_opening_new_one(self):
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()
        fallback_log = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"
        list_attempts = {"count": 0}
        reset_calls = {"count": 0}

        def send_with_active_channel_recovery(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == "DOWNLOAD: ListNotifications":
                list_attempts["count"] += 1
                raise IOError("APDU Failed: 6985")
            if log_name == fallback_log:
                raise IOError("APDU Failed: 6985")
            if log_name.endswith("[OPEN LOGICAL CHANNEL]"):
                raise AssertionError("active channel recovery should run before opening a new channel")
            if log_name == f"{fallback_log} [ACTIVE CH1]":
                return bytes.fromhex("BF2B02A000")
            return b""

        def fake_reset() -> bool:
            reset_calls["count"] += 1
            return True

        apdu_channel.send = send_with_active_channel_recovery
        apdu_channel.reset = fake_reset
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        orchestrator._es10b_logical_channel = 1

        orchestrator._sync_pending_notifications()

        self.assertEqual(list_attempts["count"], 1)
        self.assertEqual(reset_calls["count"], 0)
        self.assertEqual(orchestrator._es10b_logical_channel, 1)
        self.assertEqual(provider.handle_notification_calls, [])
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            [
                "DOWNLOAD: ListNotifications",
                fallback_log,
                fallback_log,
                f"{fallback_log} [TERMINAL CAPABILITY]",
                f"{fallback_log} [STATUS CH0]",
                f"{fallback_log} [ACTIVE CH1]",
            ],
        )
        self.assertEqual(apdu_channel.send_calls[-1][1][:2], bytes.fromhex("81E2"))
        self.assertIs(orchestrator._last_notification_sync_succeeded, True)

    def test_notification_sync_falls_through_to_bf2b_without_touching_the_session(self):
        # An SGP.32 ISD-R exposes RetrieveNotificationsList and no
        # ListNotification at all, so BF28 draws 6985 while ES10b is
        # healthy. That is a function-set fact, not a broken session: the
        # read must fall straight through to BF2B on the same channel,
        # without replaying TERMINAL PROFILE, opening a channel, or
        # cold-resetting the card in the middle of an eIM poll.
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()
        fallback_log = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"
        reset_calls = {"count": 0}

        def send_with_bf28_unsupported(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == "DOWNLOAD: ListNotifications":
                raise IOError("APDU Failed: 6985")
            if log_name == fallback_log:
                return bytes.fromhex("BF2B02A000")
            return b""

        apdu_channel.send = send_with_bf28_unsupported
        apdu_channel.reset = lambda: reset_calls.__setitem__("count", reset_calls["count"] + 1) or True
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        orchestrator._es10b_logical_channel = 1

        orchestrator._sync_pending_notifications()

        self.assertEqual(reset_calls["count"], 0)
        self.assertEqual(orchestrator._es10b_logical_channel, 1)
        self.assertEqual(
            [name for name, _ in apdu_channel.send_calls],
            ["DOWNLOAD: ListNotifications", fallback_log],
        )
        self.assertTrue(orchestrator._es10b_list_notifications_unsupported)
        self.assertIs(orchestrator._last_notification_sync_succeeded, True)

        # The latch holds for the rest of the session: no second BF28.
        apdu_channel.send_calls.clear()
        orchestrator._sync_pending_notifications()
        self.assertEqual([name for name, _ in apdu_channel.send_calls], [fallback_log])

    def test_notification_sync_marks_failure_when_bf2b_reports_a_result_error(self):
        # SGP.22 §5.6.4: a queue that could not be read must never be
        # reported as a drained one, or the console's post-command
        # auto-clear deletes notifications that were never forwarded.
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()
        fallback_log = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"

        def send_with_bf2b_result_error(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == "DOWNLOAD: ListNotifications":
                raise IOError("APDU Failed: 6985")
            if log_name == fallback_log:
                return bytes.fromhex("BF2B0381017F")
            return b""

        apdu_channel.send = send_with_bf2b_result_error
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertIs(orchestrator._last_notification_sync_succeeded, False)

    def test_notification_sync_marks_failure_when_bf2b_body_is_unwalkable(self):
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()
        fallback_log = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"

        def send_with_unknown_bf2b_shape(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == "DOWNLOAD: ListNotifications":
                raise IOError("APDU Failed: 6985")
            if log_name == fallback_log:
                return bytes.fromhex("BF2B03A10100")
            return b""

        apdu_channel.send = send_with_unknown_bf2b_shape
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertIs(orchestrator._last_notification_sync_succeeded, False)

    def test_repackage_accepts_the_application_60_notification_list_tag(self):
        # SGP.22 §5.7.12 notificationList is reachable under the
        # application-class 60 encoding as well as A0; the repackager must
        # harvest both so a card using it is not read as an empty queue.
        metadata = wrap_tlv("BF2F", wrap_tlv("80", bytes([0x00, 0x6A])))
        pending = wrap_tlv("BF37", metadata)
        bf2b_response = wrap_tlv("BF2B", wrap_tlv("60", pending))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(b""),
        )

        repackaged = orchestrator._repackage_retrieve_notifications_as_metadata_list(bf2b_response)

        self.assertEqual(repackaged, wrap_tlv("BF28", wrap_tlv("A0", metadata)))

    def test_active_channel_recovery_failure_preserves_error_context(self):
        cfg = FakeCfg()
        apdu_channel = FakeApduChannel()

        def send_with_exhausted_recovery(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            if log_name == "DOWNLOAD: ListNotifications":
                raise IOError("APDU Failed: 6985")
            if log_name == "DOWNLOAD: ListNotifications [ACTIVE CH1]":
                raise IOError("APDU Failed: 6985 active")
            if log_name == "DOWNLOAD: ListNotifications [OPEN LOGICAL CHANNEL]":
                return b"\x01"
            if log_name == "DOWNLOAD: ListNotifications [CH1]":
                raise IOError("APDU Failed: 6985 logical")
            if log_name == "DOWNLOAD: ListNotifications [STK MODE BASIC]":
                raise IOError("APDU Failed: 6985 stk")
            return b""

        apdu_channel.send = send_with_exhausted_recovery
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(b""),
        )
        orchestrator._es10b_logical_channel = 1

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._send_es10b_store_data(
                bytes.fromhex("BF2800"),
                "DOWNLOAD: ListNotifications",
                allow_stk_retry=True,
            )

        error_text = str(raised.exception)
        self.assertIn("active channel retry failed: APDU Failed: 6985 active", error_text)
        self.assertIn("logical channel retry failed: APDU Failed: 6985 logical", error_text)
        self.assertIn("STK mode retry failed: APDU Failed: 6985 stk", error_text)

    def test_notification_sync_marks_failure_when_recovery_exhausted(self):
        # When base channel, MANAGE CHANNEL recovery, and STK mode all
        # fail, _last_notification_sync_succeeded must be False so the
        # console layer suppresses the post-command auto-clear and
        # leaves on-card notifications queued for the next attempt
        # (SGP.22 §5.6.4).
        cfg = FakeCfg()
        provider = FakeProvider(b"")
        apdu_channel = FakeApduChannel()

        def always_fail(apdu: bytes, log_name: str) -> bytes:
            apdu_channel.send_calls.append((log_name, apdu))
            raise IOError("APDU Failed: 6985")

        apdu_channel.send = always_fail
        apdu_channel.reset = lambda: True

        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator._sync_pending_notifications()

        self.assertIs(orchestrator._last_notification_sync_succeeded, False)
        self.assertEqual(provider.handle_notification_calls, [])

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
                        wrap_tlv("87", bytes.fromhex("0780")),
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
        self.assertIn("eimRetrieveHttps", entries[0]["supported_protocol"])
        self.assertEqual(entries[0]["euicc_ci_pkid"], "01020304")
        self.assertEqual(entries[0]["indirect_profile_download"], "Present")
        self.assertEqual(
            entries[0]["trusted_tls_public_key_data"],
            wrap_tlv("30", tls_key_material),
        )

    def test_decode_eim_configuration_entries_does_not_pin_tls_from_certificate_a6(self):
        # SGP.32 v1.3 trustedPublicKeyDataTls [6] carries either an SPKI
        # (trustedEimPkTls) or a Certificate (trustedCertificateTls) that may
        # be the CA's rather than the eIM's, so only the SPKI form pins TLS.
        certificate_der = build_self_signed_cert().dump()
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
        self.assertEqual(entries[0]["trusted_tls_public_key_data"], b"")

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
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator.state.card_challenge = bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)
        expected_body = orchestrator._build_get_eim_package_tlv(request.eid)

        self.assertEqual(request.eid, "89049032000000000000000000000101")
        self.assertEqual(request.raw_body, expected_body)
        self.assertEqual(request.euicc_challenge, "")
        self.assertFalse(any(call[0] == "EIM: GetEuiccChallenge" for call in apdu_channel.send_calls))
        self.assertTrue(
            any(call[0] == "EIM: RESELECT ISD-R" for call in apdu_channel.send_calls),
            "ISD-R must be reselected after reading EID from ECASD.",
        )

    def test_build_eim_poll_request_variant_one_omits_challenge(self):
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
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(EIM_REQUEST_VARIANT=1),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator.state.card_challenge = bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(request.raw_body, orchestrator._build_get_eim_package_tlv(request.eid))
        self.assertEqual(request.euicc_challenge, "")
        self.assertFalse(any(call[0] == "EIM: GetEuiccChallenge" for call in apdu_channel.send_calls))

    def test_build_eim_poll_request_uses_fqdn_eim_id_when_fqdn_field_absent(self):
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.test"))
        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    b"".join(
                        [
                            wrap_tlv("80", b"eim1.example.test"),
                            wrap_tlv("82", b"\x02"),
                        ]
                    ),
                ),
            ),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        orchestrator.cache_eim_poll_metadata(
            eid="89049032000000000000000000000101",
            euicc_configured_data=configured_data,
            eim_configuration_data=eim_configuration,
            euicc_info1=wrap_tlv("BF20", b"\x82\x03\x02\x05\x00"),
            euicc_info2=wrap_tlv("BF22", b"\x81\x03\x02\x03\x01"),
        )

        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        self.assertEqual(request.eim_fqdn, "eim1.example.test")
        self.assertEqual(request.eim_id, "eim1.example.test")
        self.assertEqual(request.eim_id_type, "eimIdTypeFqdn (2)")

    @staticmethod
    def _eim_configuration_blob(*eim_ids: str) -> bytes:
        rows = b"".join(
            wrap_tlv(
                "30",
                wrap_tlv("80", eim_id.encode("utf-8"))
                + wrap_tlv("81", eim_id.encode("utf-8"))
                + wrap_tlv("82", b"\x01"),
            )
            for eim_id in eim_ids
        )
        return wrap_tlv("BF55", wrap_tlv("A0", rows))

    def _orchestrator_with_stubbed_bf55(self, card_blob: bytes, cached_blob: bytes):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        orchestrator.cache_eim_poll_metadata(
            eid="89049032000000000000000000000101",
            euicc_configured_data=wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.test")),
            eim_configuration_data=cached_blob,
            euicc_info1=wrap_tlv("BF20", b"\x82\x03\x02\x05\x00"),
            euicc_info2=wrap_tlv("BF22", b"\x81\x03\x02\x03\x01"),
        )
        reads: list[bytes] = []

        def fake_retrieve(payload: bytes, log_name: str) -> bytes:
            reads.append(bytes(payload))
            if bytes(payload) == bytes.fromhex("BF5500"):
                return card_blob
            return b""

        orchestrator._retrieve_es10b_data = fake_retrieve
        return orchestrator, reads

    def test_entry_index_sweep_and_entry_lookup_share_one_bf55_read(self):
        # An eIM the init-banner snapshot never saw used to resolve to an
        # in-range index and then fail the per-entry lookup against the
        # stale cache.
        card_blob = self._eim_configuration_blob("eim1.example.test", "eim2.example.test")
        cached_blob = self._eim_configuration_blob("eim1.example.test")
        orchestrator, _ = self._orchestrator_with_stubbed_bf55(card_blob, cached_blob)

        indices = orchestrator._resolve_eim_poll_entry_indices(None)

        self.assertEqual(indices, [0, 1])
        request = orchestrator._build_eim_poll_request(matching_id="", entry_index=1)
        self.assertEqual(request.eim_fqdn, "eim2.example.test")

    @staticmethod
    def _signed_eco_package(command: bytes) -> bytes:
        return wrap_tlv(
            "BF51",
            wrap_tlv(
                "30",
                wrap_tlv("80", b"eim1.example.test") + wrap_tlv("A1", command),
            )
            + wrap_tlv("5F37", b"\xAA" * 64),
        )

    def test_add_eim_drops_the_cached_entry_list_without_a_card_read(self):
        card_blob = self._eim_configuration_blob("eim1.example.test", "eim2.example.test")
        cached_blob = self._eim_configuration_blob("eim1.example.test")
        orchestrator, reads = self._orchestrator_with_stubbed_bf55(card_blob, cached_blob)
        add_eim = wrap_tlv("A8", wrap_tlv("80", b"eim2.example.test"))

        orchestrator._invalidate_eim_configuration_after_eco(self._signed_eco_package(add_eim))

        self.assertEqual(reads, [])
        self.assertEqual(orchestrator._cached_eim_poll_metadata["eim_configuration_data"], b"")
        request = orchestrator._build_eim_poll_request(matching_id="", entry_index=1)
        self.assertEqual(request.eim_fqdn, "eim2.example.test")

    def test_list_eim_leaves_the_cached_entry_list_alone(self):
        card_blob = self._eim_configuration_blob("eim1.example.test", "eim2.example.test")
        cached_blob = self._eim_configuration_blob("eim1.example.test")
        orchestrator, reads = self._orchestrator_with_stubbed_bf55(card_blob, cached_blob)

        orchestrator._invalidate_eim_configuration_after_eco(
            self._signed_eco_package(wrap_tlv("AB", b""))
        )

        self.assertEqual(reads, [])
        self.assertEqual(
            orchestrator._cached_eim_poll_metadata["eim_configuration_data"],
            cached_blob,
        )

    def test_run_eim_poll_skips_an_entry_a_delete_eim_removed_during_the_sweep(self):
        # The first eIM deletes the second one; its BF55 index no longer
        # exists, and an index lookup reported "out of range" as a failure.
        both = self._eim_configuration_blob("eim1.example.test", "eim2.example.test")
        after_delete = self._eim_configuration_blob("eim1.example.test")
        orchestrator, _reads = self._orchestrator_with_stubbed_bf55(both, both)
        delete_eim = self._signed_eco_package(wrap_tlv("A9", wrap_tlv("80", b"eim2.example.test")))
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[delete_eim.hex().upper()],
                    polling_complete=False,
                ),
                EimPollResponse(transaction_id="tx-2", polling_complete=True, eim_result_code=1),
            ],
        )
        orchestrator.profile_provider = provider
        orchestrator._phase_connect = lambda: None
        orchestrator._sync_pending_notifications = lambda *args, **kwargs: None
        card = {"bf55": both}
        orchestrator._retrieve_es10b_data = lambda payload, log_name: (
            card["bf55"] if bytes(payload) == bytes.fromhex("BF5500") else b""
        )

        def relay_delete_eim(package_bytes, poll_round, package_index):
            card["bf55"] = after_delete
            orchestrator._invalidate_eim_configuration_after_eco(package_bytes)
            return wrap_tlv("BF51", wrap_tlv("A0", wrap_tlv("30", wrap_tlv("83", b"\x22"))))

        orchestrator._relay_eim_package_to_card = relay_delete_eim

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            orchestrator.run_eim_poll(matching_id="")

        rendered = output.getvalue()
        self.assertEqual(
            [call.eim_fqdn for call in provider.poll_eim_calls],
            ["eim1.example.test", "eim1.example.test"],
        )
        self.assertIn("eimId eim2.example.test is no longer in the card's eIM configuration", rendered)
        self.assertIn("1 entry(s) left the card's eIM configuration during the sweep", rendered)
        self.assertIn("config_index=1 eimId=eim2.example.test: removed by an eCO, not polled", rendered)
        self.assertNotIn("out of range", rendered)
        self.assertNotIn("[!] eIM entry failed", rendered)

    def test_provide_eim_package_result_removes_what_the_eim_acknowledged(self):
        acknowledgements = base64.b64encode(bytes.fromhex("BF5306800121800122")).decode("ascii")
        for answer in (
            {"packageFormat": "eimAcknowledgements", "eimAcknowledgements": acknowledgements},
            {"provideEimPackageResultResponse": {"eimAcknowledgements": acknowledgements}},
        ):
            with self.subTest(answer=answer):
                provider = FakeProvider(bpp_bytes=b"")
                provider.provide_eim_package_result = lambda request_obj, answer=answer: answer
                apdu_channel = FakeApduChannel()
                orchestrator = SGP22Orchestrator(
                    cfg=FakeCfg(),
                    apdu_channel=apdu_channel,
                    profile_provider=provider,
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    orchestrator._provide_eim_package_result(self._minimal_eim_poll_request())

                removals = [apdu for log_name, apdu in apdu_channel.send_calls if "RemoveNotificationFromList" in log_name]
                self.assertEqual(len(removals), 2)
                self.assertIn(bytes.fromhex("BF3003800121"), removals[0])
                self.assertIn(bytes.fromhex("BF3003800122"), removals[1])

    def test_provide_eim_package_result_removes_nothing_without_a_decodable_acknowledgement(self):
        for answer in (
            {"packageFormat": "emptyResponse"},
            {"eimAcknowledgements": base64.b64encode(bytes.fromhex("BF5305800121")).decode("ascii")},
            {"eimAcknowledgements": "not base64!"},
        ):
            with self.subTest(answer=answer):
                provider = FakeProvider(bpp_bytes=b"")
                provider.provide_eim_package_result = lambda request_obj, answer=answer: answer
                apdu_channel = FakeApduChannel()
                orchestrator = SGP22Orchestrator(
                    cfg=FakeCfg(),
                    apdu_channel=apdu_channel,
                    profile_provider=provider,
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    orchestrator._provide_eim_package_result(self._minimal_eim_poll_request())

                self.assertEqual(
                    [log_name for log_name, _apdu in apdu_channel.send_calls if "RemoveNotificationFromList" in log_name],
                    [],
                )

    @staticmethod
    def _profile_installation_result(seq_number: int) -> bytes:
        """ProfileInstallationResult (SGP.22 v3.1 page 439) whose NotificationMetadata carries ``seq_number``."""
        result_data = wrap_tlv(
            "BF27",
            wrap_tlv("80", b"\x10" * 8)
            + wrap_tlv(
                "BF2F",
                wrap_tlv("80", bytes([seq_number]))
                + wrap_tlv("81", b"\x07\x80")
                + wrap_tlv("0C", b"rsp.example.com"),
            )
            + wrap_tlv("06", bytes.fromhex("2B0601040183A40F0004"))
            + wrap_tlv(
                "A2",
                wrap_tlv(
                    "A0",
                    wrap_tlv("4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                    + wrap_tlv("04", bytes.fromhex("3007A0053003800100")),
                ),
            ),
        )
        return wrap_tlv("BF37", result_data + wrap_tlv("5F37", b"\x22" * 64))

    def _run_eim_triggered_download_round(self, handle_notification):
        """One eIM poll round whose ProfileDownloadTrigger installs a profile (PIR seqNumber 0x21) on CH1.

        run_flow is real down to its phases; the install phase hands the
        card's ProfileInstallationResult to the notification sync the way
        _phase_install_package does.
        """
        seq_number = 0x21
        installation_result = self._profile_installation_result(seq_number)
        trigger = wrap_tlv(
            "BF54",
            wrap_tlv("A0", wrap_tlv("80", b"1$rsp.example.com$MATCH-54"))
            + wrap_tlv("82", b"\x01\x02\x03\x04"),
        )
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    transaction_id="tx-1",
                    euicc_package_list=[trigger.hex().upper()],
                    polling_complete=False,
                ),
                EimPollResponse(transaction_id="tx-2", polling_complete=True, eim_result_code=1),
            ],
        )
        provider.handle_notification = handle_notification
        apdu_channel = NotificationQueueApduChannel()
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=apdu_channel, profile_provider=provider)
        # The poll's _phase_connect has opened CH1 and selected ISD-R on it.
        orchestrator._es10b_logical_channel = 1
        orchestrator._phase_connect_complete = True
        orchestrator._phase_load_credentials = lambda: None
        orchestrator._phase_authentication_seed = lambda **kwargs: {}
        orchestrator._phase_authenticate_server = lambda auth_seed, matching_id="": None
        orchestrator._phase_prepare_download = lambda smdp_address=None: None
        orchestrator._phase_get_bound_profile_package = lambda smdp_address=None: True

        def install(progress_bar=None):
            # The last LoadBoundProfilePackage block answers the PIR, which
            # the eUICC also keeps in its Pending Notifications List.
            apdu_channel.pending[seq_number] = installation_result
            orchestrator.state.load_bpp_response = installation_result
            orchestrator._sync_pending_notifications(installation_result)
            return True

        orchestrator._phase_install_package = install
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            orchestrator._run_single_eim_poll_round(self._minimal_eim_poll_request())
            orchestrator._sync_pending_notifications()
        expected_body = wrap_tlv(
            "BF3D",
            wrap_tlv(
                "BF50",
                wrap_tlv("5A", bytes.fromhex("89049032123451234512345678901235"))
                + wrap_tlv("BF54", wrap_tlv("82", b"\x01\x02\x03\x04") + installation_result),
            ),
        )
        return orchestrator, apdu_channel, provider, output.getvalue(), expected_body

    def test_eim_triggered_download_reports_its_result_by_esipa_handle_notification(self):
        # SGP.32 v1.3 §3.2.3.1 step 13. The download used to close the poll's
        # CH1 on its way out, and the result went by ProvideEimPackageResult,
        # whose acknowledgement then drew 6D00 on the basic channel.
        def delivered(request_obj):
            return {}

        orchestrator, apdu_channel, provider, rendered, expected_body = self._run_eim_triggered_download_round(delivered)

        self.assertEqual(provider.provide_eim_package_result_calls, [])
        self.assertEqual([call.raw_body for call in provider.handle_notification_esipa_calls], [expected_body])
        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(orchestrator._es10b_logical_channel, 1)
        self.assertFalse(any("CLOSE LOGICAL CHANNEL" in name for name, _apdu in apdu_channel.send_calls))
        removals = [apdu for name, apdu in apdu_channel.send_calls if "RemoveNotificationFromList" in name]
        self.assertEqual(removals, [bytes.fromhex("81E2910006BF3003800121")])
        list_reads = [apdu for name, apdu in apdu_channel.send_calls if name == "DOWNLOAD: ListNotifications"]
        self.assertEqual(list_reads, [bytes.fromhex("81E2910003BF2800")] * 2)
        self.assertEqual(apdu_channel.pending, {})
        self.assertIn("removed seq=33 from the eUICC (ok(0))", rendered)
        self.assertIn(
            "Sending ProfileDownloadTriggerResult to the eIM (ESipa.HandleNotification) for package 1 in poll round 1.",
            rendered,
        )
        self.assertNotIn("eIM acknowledged", rendered)
        self.assertNotIn("failed", rendered)

    def test_installation_result_the_smdp_did_not_take_stays_on_the_card(self):
        # Only the SM-DP+'s acknowledgement deletes the PIR (SGP.32 v1.3 §3.7
        # step 3); the eIM gets the result by HandleNotification all the same.
        def unreachable(request_obj):
            raise RuntimeError("ES9+ HandleNotification: connection refused")

        orchestrator, apdu_channel, provider, rendered, expected_body = self._run_eim_triggered_download_round(unreachable)

        self.assertEqual([call.raw_body for call in provider.handle_notification_esipa_calls], [expected_body])
        self.assertEqual(
            [name for name, _apdu in apdu_channel.send_calls if "RemoveNotificationFromList" in name],
            [],
        )
        self.assertEqual(list(apdu_channel.pending), [0x21])
        # The closing sync tried the SM-DP+ again and reports the entry as unforwarded.
        self.assertIn("DOWNLOAD: RetrieveNotification [33]", [name for name, _apdu in apdu_channel.send_calls])
        self.assertIs(orchestrator._last_notification_sync_succeeded, False)

    def test_triggered_download_without_an_installation_result_reports_a_download_error(self):
        # SGP.32 v1.3 §2.11.2.3: no PIR from this download, so profileDownloadError,
        # never a PIR an earlier download left in the session state.
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=FakeProvider(bpp_bytes=b""))
        orchestrator.state.load_bpp_response = self._profile_installation_result(0x20)
        orchestrator.run_flow = lambda matching_id="", smdp_address="": None
        trigger = wrap_tlv(
            "BF54",
            wrap_tlv("A0", wrap_tlv("80", b"1$rsp.example.com$MATCH-55"))
            + wrap_tlv("82", b"\x05\x06"),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            response = orchestrator._relay_eim_package_to_card(trigger, poll_round=1, package_index=1)

        self.assertEqual(response, bytes.fromhex("BF540982020506300380017F"))

    def test_malformed_download_trigger_answers_invalid_package_format(self):
        # SGP.32 v1.3 §3.2.3.1 steps 3 and 4. The answer keeps the eIM's
        # transaction id and goes by ProvideEimPackageResult (§3.1.1.1 step 6).
        transaction_id = b"\x11\x22"
        for label, download_data in (
            ("activation code with AC_Format 2", wrap_tlv("A0", wrap_tlv("80", b"2$rsp.example.com$MATCH-1"))),
            ("contactDefaultSmdp without a default SM-DP+", wrap_tlv("A0", wrap_tlv("81", b""))),
            ("no profileDownloadData", b""),
        ):
            with self.subTest(trigger=label):
                orchestrator = SGP22Orchestrator(
                    cfg=FakeCfg(),
                    apdu_channel=FakeApduChannel(),
                    profile_provider=FakeProvider(bpp_bytes=b""),
                )
                orchestrator.run_flow = mock.Mock(side_effect=AssertionError("no download for a malformed trigger"))
                trigger = wrap_tlv("BF54", download_data + wrap_tlv("82", transaction_id))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    response = orchestrator._relay_eim_package_to_card(trigger, poll_round=1, package_index=1)
                    result = orchestrator._build_provide_eim_package_result_tlv(
                        response,
                        eid="89049032123451234512345678901235",
                        package_bytes=trigger,
                    )

                self.assertEqual(response, bytes.fromhex("A00780021122020101"))
                self.assertEqual(
                    result,
                    wrap_tlv("BF50", wrap_tlv("5A", bytes.fromhex("89049032123451234512345678901235")) + response),
                )
                self.assertIn("invalidPackageFormat(1)", output.getvalue())
                self.assertNotIn("not a valid SGP.32 EimPackageResult", output.getvalue())

    def test_eim_package_result_response_error_shape_is_checked(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        for valid in ("A003020101", "A00780021122020101"):
            with self.subTest(valid=valid):
                self.assertTrue(orchestrator._is_eim_package_result_response_error(bytes.fromhex(valid)))
        for invalid in (
            "",
            "A0",
            "A000",
            "A005020101",
            "A003020101FF",
            "A003040101",
            "3003020101",
            "A006020101020101",
            "A0028000",
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(orchestrator._is_eim_package_result_response_error(bytes.fromhex(invalid)))

    def test_top_level_run_flow_closes_the_channel_it_opened(self):
        cfg = FakeCfg()
        cfg.ES10B_USE_LOGICAL_CHANNEL = True
        apdu_channel = NotificationQueueApduChannel()
        orchestrator = SGP22Orchestrator(cfg=cfg, apdu_channel=apdu_channel, profile_provider=FakeProvider(bpp_bytes=b""))
        orchestrator._phase_load_credentials = lambda: None
        orchestrator._phase_authentication_seed = lambda **kwargs: {}
        orchestrator._phase_authenticate_server = lambda auth_seed, matching_id="": None
        orchestrator._phase_prepare_download = lambda smdp_address=None: None
        orchestrator._phase_get_bound_profile_package = lambda smdp_address=None: False
        orchestrator._phase_install_package = lambda progress_bar=None: False

        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator.run_flow(matching_id="MATCH-1", smdp_address="rsp.example.com")

        self.assertEqual(orchestrator._es10b_logical_channel, 0)
        self.assertIn(
            ("FLOW: CLOSE LOGICAL CHANNEL 1", bytes.fromhex("0070800100")),
            apdu_channel.send_calls,
        )

    def test_decode_notification_sent_status_refuses_malformed_answers(self):
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

        self.assertEqual(orchestrator._decode_notification_sent_status(bytes.fromhex("BF3003800100")), 0)
        self.assertEqual(orchestrator._decode_notification_sent_status(bytes.fromhex("BF3003800101")), 1)
        self.assertEqual(orchestrator._decode_notification_sent_status(bytes.fromhex("BF300380017F")), 127)
        for answer in (
            b"",
            b"\xBF",
            bytes.fromhex("BF30"),
            bytes.fromhex("BF3000"),
            bytes.fromhex("BF3005800100"),
            bytes.fromhex("BF30038005"),
            bytes.fromhex("BF30028000"),
            bytes.fromhex("3003800100"),
            None,
        ):
            with self.subTest(answer=answer):
                self.assertIsNone(orchestrator._decode_notification_sent_status(answer))

    def test_remove_notification_reports_the_delete_notification_status(self):
        for answer, expected_status, expected_text in (
            (bytes.fromhex("BF3003800100"), 0, "removed seq=7 from the eUICC (ok(0))"),
            (bytes.fromhex("BF3003800101"), 1, "seq=7 was already gone from the eUICC (nothingToDelete(1))"),
            (bytes.fromhex("BF300380017F"), 127, "removeNotificationFromList failed for seq=7 (undefinedError(127))"),
            (b"", None, "removeNotificationFromList for seq=7 answered without a deleteNotificationStatus (no data)"),
        ):
            with self.subTest(answer=answer):
                orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)
                orchestrator._send_es10b_store_data = lambda payload, log_name, allow_stk_retry=False, answer=answer: answer
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    status = orchestrator._remove_notification_from_list(7)

                self.assertEqual(status, expected_status)
                self.assertIn(expected_text, output.getvalue())

    @staticmethod
    def _minimal_eim_poll_request() -> EimPollRequest:
        return EimPollRequest(
            eim_fqdn="eim1.example.test",
            eim_id="eim1.example.test",
            eim_id_type="2",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            eid="89049032123451234512345678901235",
            raw_body=bytes.fromhex("BF5000"),
        )

    def test_build_eim_poll_request_omits_challenge_for_vendor_quirk_endpoint(self):
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
        apdu_channel = FakeApduChannel(
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        orchestrator._phase_connect()
        orchestrator.state.card_challenge = bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        request = orchestrator._build_eim_poll_request(matching_id="MATCH-1", entry_index=0)

        # A vendor-quirk endpoint gets notifyStateChange and stateChangeCause
        # in the initial GetEimPackage (SGP.32 v1.3 GetEimPackageRequest
        # [0] NULL / [1] StateChangeCause) but never an eUICC challenge.
        self.assertEqual(
            request.raw_body,
            orchestrator._build_get_eim_package_tlv(
                request.eid,
                notify_state_change=True,
                state_change_cause=3,
            ),
        )
        self.assertEqual(request.euicc_challenge, "")
        self.assertFalse(any(call[0] == "EIM: GetEuiccChallenge" for call in apdu_channel.send_calls))

    def test_build_get_eim_package_tlv_supports_notify_and_rplmn(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        payload = orchestrator._build_get_eim_package_tlv(
            "89049032000000000000000000000101",
            notify_state_change=True,
            # Test PLMN MCC=001, MNC=01 (3GPP TS 31.124 v18.7 §27.22.2A) → BCD 00 F1 10.
            rplmn_bytes=bytes.fromhex("00F110"),
        )

        self.assertEqual(
            payload,
            bytes.fromhex(
                "BF4F195A1089049032000000000000000000000101"
                "8000"
                "820300F110"
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
            eid="89049032000000000000000000000101",
        )

        self.assertEqual(
            payload,
            bytes.fromhex("BF50185A1089049032000000000000000000000101BF5103800101"),
        )

    def test_relay_answers_unknown_package_when_card_declines_it(self):
        # SGP.32 v1.3 §6.3.2.7: eimPackageResultResponseError [0] carrying
        # unknownPackage(2), sent with the EID so the eIM can place it.
        package = bytes.fromhex("CA0401020304")
        apdu_channel = DecliningRelayApduChannel(
            declined_tag=b"\xCA",
            declined_error=IOError("APDU Failed: 6A80"),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)
        payload = orchestrator._build_provide_eim_package_result_tlv(
            response,
            eid=TEST_EID,
            package_bytes=package,
        )

        self.assertEqual(response, bytes.fromhex("A003020102"))
        self.assertEqual(payload, bytes.fromhex("BF50175A10" + TEST_EID + "A003020102"))
        relay_apdus = [apdu for name, apdu in apdu_channel.send_calls if name.startswith("EIM: RelayPackage")]
        self.assertEqual(relay_apdus, [bytes([0x80, 0xE2, 0x91, 0x00, len(package)]) + package])

    def test_relay_passes_on_card_answer_to_unknown_package_under_its_tag(self):
        package = bytes.fromhex("CA0401020304")
        answer = bytes.fromhex("CA0100")
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(eim_package_response=answer),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)
        payload = orchestrator._build_provide_eim_package_result_tlv(
            response,
            eid=TEST_EID,
            package_bytes=package,
        )

        self.assertEqual(response, answer)
        self.assertEqual(payload, bytes.fromhex("BF50155A10" + TEST_EID + "CA0100"))

    def test_relay_answers_unknown_package_when_card_returns_nothing(self):
        package = bytes.fromhex("CA0401020304")
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(eim_package_response=b""),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertEqual(response, bytes.fromhex("A003020102"))

    def test_relay_leaves_unknown_package_unanswered_when_the_link_fails(self):
        # No status word means the card never saw the package; the poll
        # entry fails and the next DOWNLOAD fetches it again.
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=DecliningRelayApduChannel(
                declined_tag=b"\xCA",
                declined_error=IOError("PC/SC transmit failed: card removed"),
            ),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(IOError):
                orchestrator._relay_eim_package_to_card(
                    bytes.fromhex("CA0401020304"),
                    poll_round=1,
                    package_index=1,
                )

    def test_build_provide_eim_package_result_refuses_other_answers(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        invalid_package_format = bytes.fromhex("BF50175A10" + TEST_EID + "A003020101")
        cases = (
            # An answer under a foreign tag is no result for the package.
            ("foreign tag", bytes.fromhex("BF3700"), bytes.fromhex("CA0401020304")),
            ("trailing octets", bytes.fromhex("CA0100FF"), bytes.fromhex("CA0401020304")),
            ("truncated answer", bytes.fromhex("CA05"), bytes.fromhex("CA0401020304")),
            # The error alternative passes only as the answer to a package
            # outside SGP.32, never for one the IPA handles itself.
            ("error for a known package", bytes.fromhex("A003020102"), wrap_tlv("BF51", wrap_tlv("30", b""))),
            ("error without its package", bytes.fromhex("A003020102"), b""),
        )
        for label, answer, package in cases:
            with self.subTest(label):
                with contextlib.redirect_stdout(io.StringIO()):
                    payload = orchestrator._build_provide_eim_package_result_tlv(
                        answer,
                        eid=TEST_EID,
                        package_bytes=package,
                    )

                self.assertEqual(payload, invalid_package_format)

    def test_run_eim_poll_answers_unknown_package_then_reaches_the_queued_one(self):
        # A package left without a result stays pending ahead of the rest of
        # the eIM's queue; the unknownPackage(2) answer lets the eIM manage
        # it (SGP.32 v1.3 §5.14.6) and the next poll delivers the package
        # queued behind it.
        configured_data = wrap_tlv("BF3C", wrap_tlv("80", b"rsp.example.com"))
        eim_configuration = wrap_tlv(
            "BF55",
            wrap_tlv(
                "A0",
                wrap_tlv(
                    "30",
                    wrap_tlv("80", b"manager-1")
                    + wrap_tlv("81", b"eim.example.com")
                    + wrap_tlv("82", b"\x01"),
                ),
            ),
        )
        unknown_package = bytes.fromhex("CA0401020304")
        queued_package = wrap_tlv(
            "BF51",
            wrap_tlv(
                "30",
                wrap_tlv("80", b"manager-1")
                + wrap_tlv("5A", bytes.fromhex(TEST_EID))
                + wrap_tlv("81", b"\x01")
                + wrap_tlv("A0", wrap_tlv("BF2D", b"")),
            )
            + wrap_tlv("5F37", b"\x33" * 64),
        )
        package_result = _euicc_package_result_entry(1)
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_responses=[
                EimPollResponse(
                    euicc_package_list=[base64.b64encode(unknown_package).decode("ascii")],
                    polling_complete=False,
                ),
                EimPollResponse(
                    euicc_package_list=[base64.b64encode(queued_package).decode("ascii")],
                    polling_complete=False,
                ),
                EimPollResponse(polling_complete=True, eim_result_code=1),
            ],
        )
        apdu_channel = DecliningRelayApduChannel(
            declined_tag=b"\xCA",
            declined_error=IOError("APDU Failed: 6A80"),
            eim_configuration_response=eim_configuration,
            configured_data_response=configured_data,
            eid_response=wrap_tlv("5A", bytes.fromhex(TEST_EID)),
            eim_package_response=package_result,
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator.run_eim_poll()

        relayed = [apdu[5:] for name, apdu in apdu_channel.send_calls if name.startswith("EIM: RelayPackage")]
        self.assertEqual(relayed, [unknown_package, queued_package])
        provide_bodies = [call.raw_body for call in provider.provide_eim_package_result_calls]
        self.assertEqual(
            provide_bodies,
            [
                bytes.fromhex("BF50175A10" + TEST_EID + "A003020102"),
                wrap_tlv("BF50", wrap_tlv("5A", bytes.fromhex(TEST_EID)) + package_result),
            ],
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
                            wrap_tlv("87", bytes.fromhex("0780")),
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
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
            eim_package_response=bytes.fromhex("BF3700"),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )

        orchestrator.run_eim_poll(matching_id="MATCH-1")

        # The package result is provided once, then the eIM is polled again
        # until it reports noEimPackageAvailable(1).
        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(len(provider.provide_eim_package_result_calls), 1)
        first_request = provider.poll_eim_calls[0]
        self.assertEqual(first_request.eim_fqdn, "eim.example.com")
        self.assertEqual(first_request.eim_id, "manager-1")
        self.assertEqual(first_request.matching_id, "MATCH-1")
        self.assertEqual(first_request.association_token, "3735928559")
        self.assertEqual(first_request.euicc_configured_data, base64.b64encode(configured_data).decode("utf-8"))
        self.assertEqual(first_request.eim_configuration_data, base64.b64encode(eim_configuration).decode("utf-8"))
        self.assertEqual(first_request.euicc_package_result, "")
        self.assertEqual(first_request.euicc_challenge, "")
        self.assertFalse(any(call[0] == "EIM: GetEuiccChallenge" for call in apdu_channel.send_calls))
        self.assertEqual(first_request.trusted_tls_public_key_data, wrap_tlv("30", tls_key_material))
        self.assertEqual(
            first_request.raw_body,
            orchestrator._build_get_eim_package_tlv(first_request.eid),
        )

        provide_request = provider.provide_eim_package_result_calls[0]
        self.assertEqual(provide_request.euicc_package_result, "")
        self.assertEqual(
            provide_request.raw_body,
            bytes.fromhex("BF50175A1089049032000000000000000000000101A003020101"),
        )

        relay_calls = [call for call in apdu_channel.send_calls if call[0].startswith("EIM: RelayPackage")]
        self.assertEqual(len(relay_calls), 1)
        self.assertEqual(
            relay_calls[0][1],
            bytes([0x80, 0xE2, 0x91, 0x00, len(card_package)]) + card_package,
        )

    def test_poll_eim_timeout_probes_one_variant_then_raises(self):
        provider = FakeProvider(
            bpp_bytes=b"",
            eim_poll_errors=[TimeoutError("The read operation timed out")],
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
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
            eid="89049032000000000000000000000101",
            euicc_challenge="stale-eim-challenge",
            raw_body=bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
        )

        with self.assertRaises(RuntimeError) as raised:
            orchestrator._poll_eim(request)

        # A timed-out GetEimPackage is retried once with the next request
        # variant before the failure surfaces; neither attempt carries the
        # stale eUICC challenge.
        self.assertIn("Provider getEimPackage failed", str(raised.exception))
        self.assertEqual(len(provider.poll_eim_calls), 2)
        self.assertEqual(provider.poll_eim_calls[0].raw_body, request.raw_body)
        self.assertNotEqual(provider.poll_eim_calls[1].raw_body, request.raw_body)
        self.assertEqual(provider.poll_eim_calls[0].euicc_challenge, "")
        self.assertEqual(provider.poll_eim_calls[1].euicc_challenge, "")

    def test_build_get_eim_package_variant_requests_includes_alternatives(self):
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        # eim1.example.com does not match the FakeCfg vendor-quirk suffix, so
        # no stateChangeCause variant is offered; a quirk endpoint adds one.
        request = EimPollRequest(
            eim_fqdn="eim1.example.com",
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
            eid="89049032000000000000000000000101",
            euicc_challenge="",
            raw_body=bytes.fromhex(
                "BF4F195A1089049032000000000000000000000101"
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
            euicc_info2=base64.b64encode(bytes.fromhex("BF2208810302600116840100")).decode("utf-8"),
            eid="89049032000000000000000000000101",
            euicc_challenge="",
            raw_body=bytes.fromhex(
                "BF4F195A1089049032000000000000000000000101"
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
            euicc_info2=base64.b64encode(bytes.fromhex("BF2208810302600116840100")).decode("utf-8"),
            eid="89049032000000000000000000000101",
            euicc_challenge="",
            raw_body=bytes.fromhex(
                "BF4F1C5A1089049032000000000000000000000101"
                "80008101038203260116"
            ),
        )

        response = orchestrator._get_eim_package(request)

        self.assertEqual(response.eim_result_code, 1)
        self.assertEqual(len(provider.poll_eim_calls), 2)

    def test_run_eim_poll_reports_explicit_undefined_error_127_without_raising(self):
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
        orchestrator._resolve_eim_poll_entry_indices = lambda entry_index=None: [0]
        # eim1.example.com is not a vendor-quirk endpoint, so the 127 probe
        # tries exactly one request variant after the initial poll.
        orchestrator._build_eim_poll_request = lambda matching_id="", entry_index=0, expected_eim_id="": EimPollRequest(
            eim_fqdn="eim1.example.com",
            eim_id="manager-1",
            eim_id_type="1",
            counter_value="0",
            association_token="",
            supported_protocol="3",
            euicc_ci_pkid="",
            indirect_profile_download="0",
            euicc_configured_data="",
            eim_configuration_data="",
            eid="89049032000000000000000000000101",
            raw_body=bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
        )

        # A failed entry is reported and the sweep finishes, so the command
        # flow around it (notification sync, auto-clear) can still run.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            orchestrator.run_eim_poll(matching_id="MATCH-1")

        rendered = output.getvalue()
        self.assertIn("[!] eIM entry failed", rendered)
        self.assertIn("undefinedError(127)", rendered)
        self.assertEqual(len(provider.poll_eim_calls), 2)

    def test_relay_profile_download_trigger_runs_profile_download_flow(self):
        provider = FakeProvider(bpp_bytes=b"")
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=provider,
        )
        captured = {}

        def fake_run_flow(matching_id: str = "", smdp_address: str = ""):
            captured["matching_id"] = matching_id
            captured["smdp_address"] = smdp_address
            orchestrator.state.load_bpp_response = bytes.fromhex("BF3700")

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

    def test_relay_profile_download_trigger_gets_challenge_via_smdp_flow(self):
        cfg = FakeCfg()
        cfg.CAPABILITIES = {
            "gsmSupportedRelease": b"\x99\x00\x00",
            "utranSupportedRelease": b"\x99\x00\x00",
            "eutranEpcSupportedRelease": b"\x99\x00\x00",
        }
        apdu_channel = FakeApduChannel()
        provider = FakeProvider(bpp_bytes=b"")
        orchestrator = SGP22Orchestrator(
            cfg=cfg,
            apdu_channel=apdu_channel,
            profile_provider=provider,
        )
        self._seed_local_credentials(orchestrator)
        package = wrap_tlv(
            "BF54",
            wrap_tlv("82", b"\x01\x02\x03\x04")
            + wrap_tlv("30", wrap_tlv("80", b"LPA:1$rsp.example.com$MATCH-54")),
        )

        orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        call_names = [name for name, _ in apdu_channel.send_calls]
        self.assertIn("HANDSHAKE: GetEuiccChallenge", call_names)
        self.assertFalse(any(name == "EIM: GetEuiccChallenge" for name in call_names))
        self.assertEqual(provider.base_url_calls, ["https://rsp.example.com"])

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

    def test_relay_package_data_request_builds_local_bf52_response(self):
        configured_data = wrap_tlv(
            "BF3C",
            b"".join(
                [
                    wrap_tlv("80", b"rsp.example.com"),
                    wrap_tlv("81", b"root-smds.example.com"),
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
                        wrap_tlv("81", bytes.fromhex("0640")),
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
            "PackageDataResponse CHOICE packageData requires [0] (0xA0) tag",
        )
        self.assertIn(notification_item, response)
        self.assertIn(wrap_tlv("81", b"rsp.example.com"), response)
        self.assertIn(wrap_tlv("A2", b""), response)
        self.assertIn(bytes.fromhex("BF2000"), response)
        self.assertIn(euicc_info2, response)
        self.assertIn(wrap_tlv("83", b"root-smds.example.com"), response)
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
        self.assertEqual(package_result_calls[0][1], bytes.fromhex("80E2910007BF2B04A0028200"))

    def test_relay_package_data_request_uses_requesting_eim_association_token(self):
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
                                    wrap_tlv("81", b"eim1.example.test"),
                                    wrap_tlv("82", b"\x01"),
                                    wrap_tlv("84", b"\x01"),
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
                                    wrap_tlv("81", b"eim2.example.test"),
                                    wrap_tlv("82", b"\x01"),
                                    wrap_tlv("84", b"\x02"),
                                ]
                            ),
                        ),
                    ),
                ]
            ),
        )
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(eim_configuration_response=eim_configuration),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        inner_request = wrap_tlv("BF52", wrap_tlv("5C", bytes.fromhex("84")))
        signed_request = wrap_tlv(
            "30",
            b"".join(
                [
                    wrap_tlv("80", b"manager-2"),
                    wrap_tlv("5A", bytes.fromhex("89049032123456789012345678901234")),
                    wrap_tlv("81", b"\x35"),
                    wrap_tlv("82", b"\x00\x00\x00\x00\x00\x00\x04\xA3"),
                    wrap_tlv("A0", inner_request),
                ]
            ),
        )
        package = wrap_tlv("BF52", signed_request + wrap_tlv("5F37", b"\xCC" * 64))

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertTrue(response.startswith(bytes.fromhex("BF52")))
        self.assertIn(bytes.fromhex("840102"), response)
        self.assertNotIn(bytes.fromhex("840101"), response)

    def test_relay_package_data_request_returns_empty_a2_when_card_returns_other_choice(self):
        configured_data = wrap_tlv(
            "BF3C",
            b"".join(
                [
                    wrap_tlv("80", b"rsp.example.com"),
                    wrap_tlv("81", b"root-smds.example.com"),
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
            "PackageDataResponse CHOICE packageData requires [0] (0xA0) tag",
        )
        self.assertIn(wrap_tlv("81", b"rsp.example.com"), response)
        self.assertIn(wrap_tlv("A2", b""), response)
        self.assertIn(bytes.fromhex("A808800202C481020780"), response)
        self.assertIn(bytes.fromhex("870800000000000004A4"), response)

    def test_relay_package_data_request_filters_package_results_by_sequence_number(self):
        wanted = _euicc_package_result_entry(2)
        other = _euicc_package_result_entry(3)
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(
                euicc_package_result_list_response=wrap_tlv("BF2B", wrap_tlv("A2", wanted + other)),
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

        self.assertIn(wrap_tlv("A2", wanted), response)
        self.assertNotIn(other, response)
        package_result_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if "RetrieveEuiccPackageResults" in call[0]
        ]
        self.assertEqual(len(package_result_calls), 1)
        # ES10b has no sequence-filtered euiccPackageResults variant, so the
        # IPA always asks for the whole list and filters it itself.
        self.assertEqual(package_result_calls[0][1], bytes.fromhex("80E2910007BF2B04A0028200"))

    def test_relay_package_data_request_selects_notifications_by_management_operation(self):
        notification_item = wrap_tlv("A0", wrap_tlv("BF2F", wrap_tlv("80", b"\x02")))
        orchestrator = SGP22Orchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(
                notification_retrieve_response=wrap_tlv("BF2B", notification_item),
            ),
            profile_provider=FakeProvider(bpp_bytes=b""),
        )
        package = wrap_tlv(
            "BF52",
            wrap_tlv("5C", bytes.fromhex("A0"))
            + wrap_tlv("A1", wrap_tlv("81", bytes.fromhex("0640")))
            + wrap_tlv("83", bytes.fromhex("00000000000004A6")),
        )

        response = orchestrator._relay_eim_package_to_card(package, poll_round=1, package_index=1)

        self.assertIn(notification_item, response)
        notification_calls = [
            call
            for call in orchestrator.apdu_channel.send_calls
            if "RetrieveNotificationsList" in call[0]
        ]
        self.assertEqual(len(notification_calls), 1)
        self.assertEqual(notification_calls[0][1], bytes.fromhex("80E2910009BF2B06A00481020640"))

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
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
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
            eid_response=wrap_tlv("5A", bytes.fromhex("89049032000000000000000000000101")),
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
