# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import base64
import contextlib
import io
import os
import unittest
import importlib.util
import sys
import json
import datetime
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ES9_CLIENT_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "live" / "es9_client.py"
MODELS_PATH = Path(__file__).resolve().parent.parent / "SCP11" / "live" / "models.py"

models_spec = importlib.util.spec_from_file_location("scp11_models_module", MODELS_PATH)
models_module = importlib.util.module_from_spec(models_spec)
assert models_spec is not None
assert models_spec.loader is not None
sys.modules[models_spec.name] = models_module
sys.modules["models"] = models_module
models_spec.loader.exec_module(models_module)

es9_spec = importlib.util.spec_from_file_location("scp11_es9_client_module", ES9_CLIENT_PATH)
es9_module = importlib.util.module_from_spec(es9_spec)
assert es9_spec is not None
assert es9_spec.loader is not None
sys.modules[es9_spec.name] = es9_module
es9_spec.loader.exec_module(es9_module)

Es9LikeClient = es9_module.Es9LikeClient
EIM_TRANSPORT_MODE_REST_RESOURCE = models_module.EIM_TRANSPORT_MODE_REST_RESOURCE
EimPollRequest = models_module.EimPollRequest


class RecordingEs9Client(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.post_calls = []
        self.next_response = {}

    def _post_json_to_base_url(
        self,
        base_url: str,
        path: str,
        body: dict,
        protocol_header: str = "gsma/rsp/v2.2.0",
        pinned_tls_public_key_data: bytes = b"",
        use_configured_ca_bundle: bool = True,
        tls_log_label: str = "ES9",
        user_agent: str = "gsma-rsp-lpad",
    ) -> dict:
        self.post_calls.append(
            {
                "base_url": base_url,
                "path": path,
                "body": body,
                "protocol_header": protocol_header,
                "pinned_tls_public_key_data": pinned_tls_public_key_data,
                "use_configured_ca_bundle": use_configured_ca_bundle,
                "tls_log_label": tls_log_label,
                "user_agent": user_agent,
            }
        )
        return self.next_response


class _DummyResponseHandle:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._payload


class RecordingEimBinaryClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.open_contexts = []
        self.open_pinned_spki_args = []
        self._verified_context = object()
        self._bundle_context = object()
        self._pinned_context = object()
        self._response_payload = b"{}"
        self._initial_error = None
        self._resolved_bundle = ""
        self.open_errors = []
        self.pinned_context_calls = []

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
        if len(self.open_errors) > 0:
            raise self.open_errors.pop(0)
        if len(self.open_contexts) == 1 and self._initial_error is not None:
            raise self._initial_error
        return _DummyResponseHandle(self._response_payload)

    def _resolve_dynamic_ca_bundle_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str,
        initial_error: urllib.error.URLError,
    ) -> str:
        return self._resolved_bundle

    def _create_default_context_with_bundle(self, bundle_path: str):
        return self._bundle_context

    def _build_pinned_tls_context(self, endpoint: str, pinned_tls_public_key_data: bytes):
        self.pinned_context_calls.append((endpoint, pinned_tls_public_key_data))
        return self._pinned_context


class RecordingDynamicDiscoveryClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain_der = []
        self._bundle_verifies = True
        self.bundle_verify_calls = []

    def _fetch_server_certificate_chain_der(self, hostname: str, port: int) -> list[bytes]:
        return list(self.chain_der)

    def _bundle_verifies_tls_handshake(
        self,
        endpoint: str,
        bundle_path: str,
        log_label: str = "ES9",
    ) -> bool:
        self.bundle_verify_calls.append((endpoint, bundle_path, log_label))
        return self._bundle_verifies


class _DummyHttpResponse:
    def __init__(self, payload: bytes, status: int = 200, reason: str = "OK"):
        self._payload = payload
        self.status = status
        self.reason = reason
        self.headers = {}
        self.closed = False

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        self.closed = True


class _FakeHttpConnection:
    def __init__(self):
        self.calls = []
        self.response = _DummyHttpResponse(b"{}")
        self.connect_error = None
        self.send_error = None
        self.response_error = None
        self.closed = False
        self.sock = None

    def connect(self):
        self.calls.append(("connect",))
        if self.connect_error is not None:
            raise self.connect_error

    def request(self, method: str, path: str, body: bytes = b"", headers: dict | None = None):
        self.calls.append(("request", method, path, body, headers or {}))
        if self.send_error is not None:
            raise self.send_error

    def getresponse(self):
        self.calls.append(("getresponse",))
        if self.response_error is not None:
            raise self.response_error
        return self.response

    def close(self):
        self.closed = True


class RecordingHttpStageClient(Es9LikeClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection = _FakeHttpConnection()
        self.logged_failures = []

    def _create_http_connection(self, parsed_endpoint, ssl_context, timeout_seconds: int | None = None):
        return self.connection

    def _log_http_stage_failure(
        self,
        label: str,
        endpoint: str,
        stage: str,
        started_at: float,
        error: Exception,
    ) -> None:
        self.logged_failures.append((label, endpoint, stage, type(error).__name__, str(error)))


class _FakeTlsSocket:
    def __init__(self, certificate_der: bytes):
        self._certificate_der = bytes(certificate_der)

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        if binary_form:
            return self._certificate_der
        return None


def build_test_ca_and_leaf(hostname: str) -> tuple[bytes, bytes]:
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "EE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM Test"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Dynamic TLS Root"),
        ]
    )
    ca_cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            crypto_x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "EE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM Test"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    leaf_cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            crypto_x509.SubjectAlternativeName([crypto_x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(
            crypto_x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf_cert.public_bytes(serialization.Encoding.DER),
        ca_cert.public_bytes(serialization.Encoding.DER),
    )


class TrustPathBundleFlagClient(RecordingEimBinaryClient):
    """Records the CA-anchor preference each eIM TLS context is built with."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_configured_ca_bundle_flags = []

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ):
        self.use_configured_ca_bundle_flags.append(use_configured_ca_bundle)
        return super()._build_ssl_context_for_endpoint(
            endpoint,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
            use_configured_ca_bundle=use_configured_ca_bundle,
            log_label=log_label,
        )


class Es9LikeClientEimTests(unittest.TestCase):
    def test_dump_eim_response_for_debug_defaults_to_eim_local_runtime_dir(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        raw = bytes.fromhex("BF4F03020101")

        with tempfile.TemporaryDirectory() as temp_root:
            previous_runtime_root = os.environ.get("YGGDRASIM_RUNTIME_ROOT")
            previous_debug_dir = os.environ.get("EIM_DEBUG_DIR")
            try:
                os.environ["YGGDRASIM_RUNTIME_ROOT"] = temp_root
                os.environ.pop("EIM_DEBUG_DIR", None)
                client._dump_eim_response_for_debug(raw)
                dump_dir = Path(temp_root) / "SCP11" / "eim_local"
                hex_path = dump_dir / "eim_last_response_hex.txt"
                bin_path = dump_dir / "eim_last_response.bin"
                self.assertTrue(hex_path.exists())
                self.assertTrue(bin_path.exists())
                self.assertEqual(bin_path.read_bytes(), raw)
                self.assertIn("len=6", hex_path.read_text(encoding="utf-8"))
            finally:
                if previous_runtime_root is None:
                    os.environ.pop("YGGDRASIM_RUNTIME_ROOT", None)
                else:
                    os.environ["YGGDRASIM_RUNTIME_ROOT"] = previous_runtime_root
                if previous_debug_dir is None:
                    os.environ.pop("EIM_DEBUG_DIR", None)
                else:
                    os.environ["EIM_DEBUG_DIR"] = previous_debug_dir

    def test_open_http_response_logs_request_send_and_header_wait_stages(self):
        client = RecordingHttpStageClient(base_url="https://rsp.example.com")
        request = urllib.request.Request(
            "https://rsp.example.com/gsma/rsp2/asn1?query=1",
            data=b"\x01\x02",
            method="POST",
            headers={"Content-Type": "application/octet-stream", "X-Test": "yes"},
        )

        with client._open_http_response(request, ssl_context=None, endpoint=request.full_url, label="HTTP") as response:
            self.assertEqual(response.read(), b"{}")

        self.assertEqual(
            client.connection.calls,
            [
                ("connect",),
                (
                    "request",
                    "POST",
                    "/gsma/rsp2/asn1?query=1",
                    b"\x01\x02",
                    {"Content-type": "application/octet-stream", "X-test": "yes"},
                ),
                ("getresponse",),
            ],
        )
        self.assertEqual(client.logged_failures, [])
        self.assertTrue(client.connection.closed)
        self.assertTrue(client.connection.response.closed)

    def test_open_http_response_classifies_response_header_timeout(self):
        client = RecordingHttpStageClient(base_url="https://rsp.example.com")
        client.connection.response_error = TimeoutError("The read operation timed out")
        request = urllib.request.Request(
            "https://rsp.example.com/gsma/rsp2/asn1",
            data=b"\x01\x02",
            method="POST",
        )

        with self.assertRaises(TimeoutError):
            client._open_http_response(request, ssl_context=None, endpoint=request.full_url, label="HTTP")

        self.assertEqual(len(client.logged_failures), 1)
        self.assertEqual(client.logged_failures[0][2], "response-headers")
        self.assertTrue(client.connection.closed)

    def test_open_http_response_classifies_request_send_timeout(self):
        client = RecordingHttpStageClient(base_url="https://rsp.example.com")
        client.connection.send_error = TimeoutError("The write operation timed out")
        request = urllib.request.Request(
            "https://rsp.example.com/gsma/rsp2/asn1",
            data=b"\x01\x02",
            method="POST",
        )

        with self.assertRaises(TimeoutError):
            client._open_http_response(request, ssl_context=None, endpoint=request.full_url, label="HTTP")

        self.assertEqual(len(client.logged_failures), 1)
        self.assertEqual(client.logged_failures[0][2], "request-send")
        self.assertTrue(client.connection.closed)

    def test_open_http_response_raises_http_error_for_error_status(self):
        client = RecordingHttpStageClient(base_url="https://rsp.example.com")
        client.connection.response = _DummyHttpResponse(
            b'{"status":500,"error":"Internal Server Error"}',
            status=500,
            reason="Internal Server Error",
        )
        request = urllib.request.Request(
            "https://rsp.example.com/gsma/rsp2/asn1",
            data=b"\x01\x02",
            method="POST",
        )

        with self.assertRaises(urllib.error.HTTPError) as raised:
            client._open_http_response(request, ssl_context=None, endpoint=request.full_url, label="HTTP")

        self.assertEqual(raised.exception.code, 500)
        self.assertEqual(raised.exception.read(), b'{"status":500,"error":"Internal Server Error"}')
        self.assertEqual(client.logged_failures, [])
        self.assertTrue(client.connection.closed)
        self.assertTrue(client.connection.response.closed)

    def test_poll_eim_uses_configured_direct_transport_path(self):
        client = RecordingEs9Client(
            base_url="https://rsp.example.com",
            eim_base_url="https://polling.example.net",
            eim_http_path="custom/esipa/request",
            eim_http_protocol="gsma/rsp/v9.9.9",
        )
        client.next_response = {
            "transactionId": "tx-1",
            "euiccPackageList": ["QUJD"],
            "pollingComplete": False,
            "retryAfterSeconds": 12,
        }

        response = client.poll_eim(
            EimPollRequest(
                eim_fqdn="eim.example.com",
                eim_id="1.2.3",
                eim_id_type="1",
                counter_value="2",
                association_token="AA",
                supported_protocol="3",
                euicc_ci_pkid="BB",
                indirect_profile_download="0",
                euicc_configured_data="cfg",
                eim_configuration_data="eimCfg",
                trusted_tls_public_key_data=b"\x01\x02",
            )
        )

        self.assertEqual(response.transaction_id, "tx-1")
        self.assertEqual(response.euicc_package_list, ["QUJD"])
        self.assertFalse(response.polling_complete)
        self.assertEqual(response.retry_after_seconds, 12)
        self.assertEqual(len(client.post_calls), 1)
        self.assertEqual(client.post_calls[0]["base_url"], "https://polling.example.net")
        self.assertEqual(client.post_calls[0]["path"], "/custom/esipa/request")
        self.assertEqual(client.post_calls[0]["protocol_header"], "gsma/rsp/v9.9.9")
        self.assertEqual(client.post_calls[0]["pinned_tls_public_key_data"], b"\x01\x02")

    def test_poll_eim_accepts_vendor_style_response_fields(self):
        client = RecordingEs9Client(
            base_url="https://rsp.example.com",
            eim_base_url="https://eim1.esim.example.test",
        )
        client.next_response = {
            "eimTransactionId": "eim-tx-1",
            "requestPackageJson": "QUJDRA==",
            "retryCounter": 4,
        }

        response = client.poll_eim(
            EimPollRequest(
                eim_fqdn="eim.example.com",
                eim_id="1.2.3",
                eim_id_type="1",
                counter_value="2",
                association_token="AA",
                supported_protocol="3",
                euicc_ci_pkid="BB",
                indirect_profile_download="0",
                euicc_configured_data="cfg",
                eim_configuration_data="eimCfg",
            )
        )

        self.assertEqual(response.transaction_id, "eim-tx-1")
        self.assertEqual(response.euicc_package_list, ["QUJDRA=="])
        self.assertEqual(response.retry_after_seconds, 4)
        self.assertEqual(client.post_calls[0]["path"], "/gsma/rsp2/asn1")
        self.assertEqual(client.post_calls[0]["protocol_header"], "gsma/rsp/v1.3.0")
        self.assertEqual(client.post_calls[0]["user_agent"], "gsma-rsp-ipad")

    def test_get_eim_package_exposes_no_package_result_code(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        client.next_response = {
            "eimTransactionId": "eim-tx-2",
            "eimResultCode": 1,
            "pollingComplete": True,
        }

        response = client.get_eim_package(
            EimPollRequest(
                eim_fqdn="eim.example.com",
                eim_id="1.2.3",
                eim_id_type="1",
                counter_value="2",
                association_token="AA",
                supported_protocol="3",
                euicc_ci_pkid="BB",
                indirect_profile_download="0",
                euicc_configured_data="cfg",
                eim_configuration_data="eimCfg",
            )
        )

        self.assertEqual(response.transaction_id, "eim-tx-2")
        self.assertEqual(response.euicc_package_list, [])
        self.assertTrue(response.polling_complete)
        self.assertEqual(response.eim_result_code, 1)

    def test_parse_eim_binary_response_extracts_bf51_package(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        raw = bytes.fromhex(
            "BF4F8188BF518184303F8019312E332E362E312E342E312E35333737352E312E352E312E31"
            "5A10890490320000000000000000000001018101318208000000000000049BA003BF2D005F37"
            "40CBE8797590F764F1E50E00C2AA7FE42934914775E22DFC6C2FA657B92A144F6F5CECA6AC39"
            "A7106CB0C79B8FC1567FB27C6BA15EEA4A646515A200C3931C3A2C"
        )

        decoded = client._parse_eim_binary_response(raw)
        expected_package = base64.b64encode(raw[4:]).decode("ascii")

        self.assertEqual(
            decoded["euiccPackageList"],
            [
                expected_package
            ],
        )
        self.assertFalse(decoded["pollingComplete"])
        self.assertIsNone(decoded["eimResultCode"])

    def test_parse_eim_binary_response_extracts_bf52_and_bf54_packages(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        bf52 = bytes.fromhex("BF5203800001")
        bf54 = bytes.fromhex("BF5403800102")
        raw = bf52 + bf54

        decoded = client._parse_eim_binary_response(raw)

        self.assertEqual(
            decoded["euiccPackageList"],
            [
                base64.b64encode(bf52).decode("ascii"),
                base64.b64encode(bf54).decode("ascii"),
            ],
        )
        self.assertFalse(decoded["pollingComplete"])
        self.assertIsNone(decoded["eimResultCode"])

    def test_parse_eim_binary_response_accepts_bf50_acknowledgement(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        raw = bytes.fromhex("BF5006BF5303800164")

        decoded = client._parse_eim_binary_response(raw)

        self.assertEqual(decoded["euiccPackageList"], [])
        self.assertTrue(decoded["pollingComplete"])
        self.assertEqual(decoded["packageFormat"], "eimAcknowledgements")
        self.assertIsNone(decoded["eimResultCode"])
        self.assertEqual(
            decoded["eimAcknowledgements"],
            base64.b64encode(bytes.fromhex("BF5303800164")).decode("ascii"),
        )

    def test_parse_eim_binary_response_keeps_every_acknowledged_sequence_number(self):
        from SCP03.logic.sgp32_decode import decode_eim_acknowledgements

        client = RecordingEs9Client(base_url="https://rsp.example.com")

        for raw in (bytes.fromhex("BF5009BF5306800121800122"), bytes.fromhex("BF5306800121800122")):
            with self.subTest(raw=raw.hex().upper()):
                decoded = client._parse_eim_binary_response(raw)

                acknowledged = base64.b64decode(decoded["eimAcknowledgements"])
                self.assertEqual(decode_eim_acknowledgements(acknowledged), [33, 34])

    def test_parse_eim_binary_response_maps_no_package_result(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        raw = bytes.fromhex("BF4F03020101")

        decoded = client._parse_eim_binary_response(raw)

        self.assertEqual(decoded["euiccPackageList"], [])
        self.assertTrue(decoded["pollingComplete"])
        self.assertEqual(decoded["eimResultCode"], 1)

    def test_parse_eim_binary_response_hands_on_alternative_outside_sgp32(self):
        # SGP.32 v1.3 §6.3.2.6 defines 'BF51', 'BF52', 'BF54' and the
        # eimPackageError INTEGER. Any other alternative is still a package
        # the eIM waits on, so it reaches the IPA instead of ending the poll.
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        alternative = bytes.fromhex("CA0401020304")
        raw = bytes.fromhex("BF4F06") + alternative

        decoded = client._parse_eim_binary_response(raw)

        self.assertEqual(
            decoded["euiccPackageList"],
            [base64.b64encode(alternative).decode("ascii")],
        )
        self.assertFalse(decoded["pollingComplete"])
        self.assertIsNone(decoded["eimResultCode"])

    def test_parse_eim_binary_response_ignores_unframed_alternative(self):
        client = RecordingEs9Client(base_url="https://rsp.example.com")
        for raw_hex in (
            "BF4F00",  # no alternative at all
            "BF4F01CA",  # a lone tag octet
            "BF4F02DF81",  # a multi-octet tag cut short
            "BF4F02CA05",  # a length that claims more than is there
            "BF4F05CA010000FF",  # trailing octets after the alternative
        ):
            with self.subTest(raw_hex=raw_hex):
                decoded = client._parse_eim_binary_response(bytes.fromhex(raw_hex))

                self.assertEqual(decoded["euiccPackageList"], [])
                self.assertTrue(decoded["pollingComplete"])

    def test_poll_eim_rest_resource_mode_requires_explicit_mapping(self):
        client = RecordingEs9Client(
            base_url="https://rsp.example.com",
            eim_transport_mode=EIM_TRANSPORT_MODE_REST_RESOURCE,
            eim_rest_create_path="/edr/create",
            eim_rest_lookup_path_template="/edr/lookup/{resource_id}",
        )

        with self.assertRaises(NotImplementedError) as raised:
            client.poll_eim(
                EimPollRequest(
                    eim_fqdn="eim.example.com",
                    eim_id="1.2.3",
                    eim_id_type="1",
                    counter_value="2",
                    association_token="AA",
                    supported_protocol="3",
                    euicc_ci_pkid="BB",
                    indirect_profile_download="0",
                    euicc_configured_data="cfg",
                    eim_configuration_data="eimCfg",
                )
            )

        self.assertIn("vendor-specific resource contract mapping", str(raised.exception))

    def test_post_eim_binary_uses_direct_pinned_path_when_key_available(self):
        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client._response_payload = b'{"euiccPackageList":["QUJD"]}'

        response = client._post_eim_binary(
            "https://polling.example.net",
            bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
            b"\x01\x02",
        )

        self.assertEqual(response, {"euiccPackageList": ["QUJD"]})
        self.assertEqual(len(client.open_contexts), 1)
        self.assertEqual(
            client.open_pinned_spki_args,
            [b"\x01\x02"],
        )
        self.assertEqual(client.pinned_context_calls, [])

    def test_handle_notification_esipa_posts_bf3d_over_the_asn1_binding(self):
        # SGP.32 v1.3 section 6.1.1: every ESipa call is one EsipaMessageFromIpaToEim
        # posted to gsma/rsp2/asn1. HandleNotification is a Notification function,
        # so the eIM answers 204 with an empty body (SGP.22 v3.1 section 6.3).
        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client._response_payload = b""
        posted = []
        open_response = client._open_http_response

        def record(request, ssl_context, endpoint, label, timeout_seconds=None, pinned_tls_spki=None):
            posted.append((endpoint, request.data, request.get_header("Content-type")))
            return open_response(
                request,
                ssl_context,
                endpoint,
                label,
                timeout_seconds=timeout_seconds,
                pinned_tls_spki=pinned_tls_spki,
            )

        client._open_http_response = record
        body = bytes.fromhex("BF3D0BBF5008BF5405300380017F")

        response = client.handle_notification_esipa(
            EimPollRequest(
                eim_fqdn="eim.example.com",
                eim_id="1.2.3",
                eim_id_type="1",
                counter_value="2",
                association_token="",
                supported_protocol="3",
                euicc_ci_pkid="",
                indirect_profile_download="0",
                euicc_configured_data="",
                eim_configuration_data="",
                raw_body=body,
            )
        )

        self.assertEqual(response, {})
        self.assertEqual(posted, [("https://eim.example.com/gsma/rsp2/asn1", body, "application/x-gsma-rsp-asn1")])

    def test_post_eim_binary_pinned_path_reraises_original_exception(self):
        # The pinned branch used to wrap any failure in
        # ``IOError("Provider getEimPackage failed: ...")`` which produced
        # the prefix twice in operator-facing output because the
        # orchestrator layer already adds the canonical
        # ``Provider getEimPackage failed: ...`` wrap. The client now
        # re-raises the underlying exception unchanged and lets the
        # orchestrator supply the single prefix.
        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client.open_errors = [
            TimeoutError("The read operation timed out"),
        ]

        with self.assertRaises(TimeoutError) as raised:
            client._post_eim_binary(
                "https://polling.example.net",
                bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
                b"\x01\x02",
            )

        self.assertIn("timed out", str(raised.exception).lower())
        self.assertNotIn("Provider getEimPackage failed", str(raised.exception))
        self.assertEqual(len(client.open_contexts), 1)
        self.assertEqual(
            client.open_pinned_spki_args,
            [b"\x01\x02"],
        )

    def test_post_eim_binary_no_pinned_key_uses_ca_cascade(self):
        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client._response_payload = b'{"euiccPackageList":["QUJD"]}'

        response = client._post_eim_binary(
            "https://polling.example.net",
            bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
            b"",
        )

        self.assertEqual(response, {"euiccPackageList": ["QUJD"]})
        self.assertEqual(len(client.open_contexts), 1)
        self.assertIs(client.open_contexts[0], client._verified_context)
        self.assertEqual(
            client.open_pinned_spki_args,
            [None],
        )

    def test_missing_configured_ca_bundle_is_refused_not_silently_skipped(self):
        """A configured anchor that has gone missing must not be substituted.

        The path used to fall through to the per-host entry or the system
        store, so the operator kept believing traffic was pinned to their
        bundle. The provider chain check already refuses the same path.
        """
        client = Es9LikeClient(base_url="https://rsp.example.com")
        client._ca_bundle_path = "/nonexistent/yggdrasim-test-ca.pem"

        with self.assertRaises(RuntimeError) as caught:
            client._preferred_ca_bundle_for_endpoint(
                "https://eim1.esim.example.test/gsma/rsp2/asn1"
            )

        self.assertIn("/nonexistent/yggdrasim-test-ca.pem", str(caught.exception))
        self.assertIn("SET-ES9-CA", str(caught.exception))

    def test_missing_configured_ca_bundle_is_ignored_when_not_requested(self):
        # The eIM and ES9 sites both ask for the configured anchor now, but
        # the parameter still exists; a caller opting out must not trip the
        # refusal on a path it never intended to use.
        client = Es9LikeClient(base_url="https://rsp.example.com")
        client._ca_bundle_path = "/nonexistent/yggdrasim-test-ca.pem"
        client._dynamic_ca_lookup = {}

        self.assertEqual(
            client._preferred_ca_bundle_for_endpoint(
                "https://eim1.esim.example.test/gsma/rsp2/asn1",
                use_configured_ca_bundle=False,
            ),
            "",
        )

    def test_poll_eim_offers_the_configured_ca_anchor_to_the_eim_endpoint(self):
        # SET-ES9-CA / ES9_CA_BUNDLE_PATH is the documented fix for an
        # untrusted eIM FQDN, not only an untrusted SM-DP+ one, so the
        # configured anchor has to reach the eIM context.
        client = RecordingEs9Client(
            base_url="https://rsp.example.com",
            eim_base_url="https://eim1.esim.example.test",
        )
        client.next_response = {"eimTransactionId": "eim-tx-1"}

        client.poll_eim(
            EimPollRequest(
                eim_fqdn="eim1.esim.example.test",
                eim_id="1.2.3",
                eim_id_type="1",
                counter_value="2",
                association_token="AA",
                supported_protocol="3",
                euicc_ci_pkid="BB",
                indirect_profile_download="0",
                euicc_configured_data="cfg",
                eim_configuration_data="eimCfg",
            )
        )

        self.assertTrue(client.post_calls[0]["use_configured_ca_bundle"])

    def test_post_eim_binary_trust_path_offers_the_configured_ca_anchor(self):
        # The live client already reads it this way; this pins the relay
        # client to the same one so the two cannot drift apart again.
        client = TrustPathBundleFlagClient(base_url="https://rsp.example.com")

        client._post_eim_binary(
            "https://polling.example.net",
            bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
            b"",
        )

        self.assertEqual(client.use_configured_ca_bundle_flags, [True])

    def test_post_eim_binary_pin_mismatch_falls_back_to_trust_path(self):
        # An eIM that rotates its TLS leaf invalidates the BF55 pin without
        # becoming unreachable, so the poll retries over the CA-verified
        # path rather than failing the whole sweep.
        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client._response_payload = b'{"euiccPackageList":["QUJD"]}'
        client.open_errors = [
            es9_module.PinnedTlsMismatchError(
                "Pinned TLS public key mismatch for eIM endpoint "
                "https://polling.example.net/gsma/rsp2/asn1."
            ),
        ]

        response = client._post_eim_binary(
            "https://polling.example.net",
            bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
            b"\x01\x02",
        )

        self.assertEqual(response, {"euiccPackageList": ["QUJD"]})
        self.assertEqual(len(client.open_contexts), 2)
        self.assertIs(client.open_contexts[1], client._verified_context)
        self.assertEqual(
            client.open_pinned_spki_args,
            [b"\x01\x02", None],
        )

    def test_post_eim_binary_pin_mismatch_raises_when_pinning_required(self):
        from SCP11.shared import tls_helpers

        client = RecordingEimBinaryClient(base_url="https://rsp.example.com")
        client.open_errors = [
            es9_module.PinnedTlsMismatchError(
                "Pinned TLS public key mismatch for eIM endpoint "
                "https://polling.example.net/gsma/rsp2/asn1."
            ),
        ]

        with mock.patch.dict(
            os.environ,
            {tls_helpers.REQUIRE_PINNED_TLS_ENV: "1"},
            clear=False,
        ):
            with self.assertRaises(es9_module.PinnedTlsMismatchError):
                client._post_eim_binary(
                    "https://polling.example.net",
                    bytes.fromhex("BF4F125A1089049032000000000000000000000101"),
                    b"\x01\x02",
                )

        self.assertEqual(len(client.open_contexts), 1)

    def test_dynamic_tls_discovery_persists_presented_chain_bundle(self):
        hostname = "new-eim.example.test"
        leaf_der, ca_der = build_test_ca_and_leaf(hostname)
        client = RecordingDynamicDiscoveryClient(base_url=f"https://{hostname}")
        client.chain_der = [leaf_der, ca_der]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            module_dir = temp_root / "SCP11"
            dynamic_ca_dir = module_dir / "dynamic_ca"
            module_dir.mkdir()
            dynamic_ca_dir.mkdir()
            lookup_path = module_dir / "es9_ca_lookup.json"
            lookup_path.write_text("{}\n", encoding="utf-8")

            client._workspace_root = str(temp_root)
            client._module_dir = str(module_dir)
            client._es9_ca_lookup_path = str(lookup_path)
            client._dynamic_ca_lookup = {}

            original_verify = es9_module.verify_certificate_against_ca_bundle

            expected_subject = crypto_x509.load_der_x509_certificate(ca_der).subject.rfc4514_string()

            def fake_verify(certificate_der: bytes, bundle_path: str) -> str:
                # The bundle is PEM, so the issuer subject is inside the
                # encoded body and not in the surrounding text. Matching the
                # subject as a substring never held; the caller used to
                # swallow the resulting error and take the bundle anyway.
                bundle_bytes = Path(bundle_path).read_bytes()
                self.assertIn(b"BEGIN CERTIFICATE", bundle_bytes)
                self.assertIn(
                    ca_der,
                    [
                        certificate.public_bytes(serialization.Encoding.DER)
                        for certificate in crypto_x509.load_pem_x509_certificates(bundle_bytes)
                    ],
                )
                return expected_subject

            es9_module.verify_certificate_against_ca_bundle = fake_verify
            try:
                resolved_bundle = client._resolve_dynamic_ca_bundle_for_endpoint(
                    endpoint=f"https://{hostname}/gsma/rsp2/asn1",
                    trust_hint_ci_pkid="",
                    initial_error=urllib.error.URLError("certificate verify failed"),
                )
            finally:
                es9_module.verify_certificate_against_ca_bundle = original_verify

            self.assertTrue(resolved_bundle.endswith("_auto_ca_bundle.pem"))
            self.assertTrue(Path(resolved_bundle).exists())

            saved_lookup = json.loads(lookup_path.read_text(encoding="utf-8"))
            self.assertIn(hostname, saved_lookup)
            self.assertEqual(
                saved_lookup[hostname]["selected_ca_bundle"],
                str(Path(resolved_bundle).relative_to(temp_root)),
            )
            self.assertEqual(len(saved_lookup[hostname]["selected_ca_chain"]), 1)
            self.assertTrue(saved_lookup[hostname]["selected_ca_chain"][0].endswith(".pem"))
            self.assertIn("Auto-resolved by trusting the live TLS chain", saved_lookup[hostname]["notes"][0])

    def test_dynamic_tls_discovery_skips_presented_chain_rejected_by_openssl(self):
        hostname = "new-eim.example.test"
        leaf_der, ca_der = build_test_ca_and_leaf(hostname)
        client = RecordingDynamicDiscoveryClient(base_url=f"https://{hostname}")
        client.chain_der = [leaf_der, ca_der]
        client._bundle_verifies = False

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            module_dir = temp_root / "SCP11"
            dynamic_ca_dir = module_dir / "dynamic_ca"
            module_dir.mkdir()
            dynamic_ca_dir.mkdir()
            lookup_path = module_dir / "es9_ca_lookup.json"
            lookup_path.write_text("{}\n", encoding="utf-8")

            client._workspace_root = str(temp_root)
            client._module_dir = str(module_dir)
            client._es9_ca_lookup_path = str(lookup_path)
            client._dynamic_ca_lookup = {}

            original_verify = es9_module.verify_certificate_against_ca_bundle

            def fake_verify(certificate_der: bytes, bundle_path: str) -> str:
                return "CN=Dynamic TLS Root,O=YggdraSIM Test,C=XX"

            es9_module.verify_certificate_against_ca_bundle = fake_verify
            try:
                resolved_bundle = client._resolve_dynamic_ca_bundle_for_endpoint(
                    endpoint=f"https://{hostname}/gsma/rsp2/asn1",
                    trust_hint_ci_pkid="",
                    initial_error=urllib.error.URLError("certificate verify failed"),
                )
            finally:
                es9_module.verify_certificate_against_ca_bundle = original_verify

            self.assertEqual(resolved_bundle, "")
            saved_lookup = json.loads(lookup_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_lookup, {})
            # The presented chain bundle is probed once and, after its
            # rejection, the leaf-only bundle once; neither is persisted.
            self.assertEqual(len(client.bundle_verify_calls), 2)


class Es9LikeClientTransportLogGatingTests(unittest.TestCase):
    """
    Regression coverage for the debug-mode gating applied to the ES9
    HTTP/TLS transport traces. When the global debug flag is off the
    operator surface must stay quiet; when it is on the full trace
    returns without any code change.
    """

    def setUp(self) -> None:
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        self._env_key = GLOBAL_DEBUG_ENV
        self._previous_value = os.environ.get(self._env_key, "")

    def tearDown(self) -> None:
        os.environ[self._env_key] = self._previous_value

    def _run_open_http_response(self) -> str:
        import io as _io
        import contextlib

        client = RecordingHttpStageClient(base_url="https://rsp.example.com")
        request = urllib.request.Request("https://rsp.example.com/gsma/rsp2/es9plus/handleNotification")
        buffer = _io.StringIO()
        with contextlib.redirect_stdout(buffer):
            handle = client._open_http_response(
                request,
                None,
                request.full_url,
                label="ES9",
            )
            try:
                handle.__exit__(None, None, None)
            except Exception:
                pass
        return buffer.getvalue()

    def test_http_transport_traces_are_hidden_when_debug_off(self) -> None:
        from yggdrasim_common.process_debug import set_global_debug

        set_global_debug(False)
        captured = self._run_open_http_response()
        self.assertNotIn("transport: connect/TLS completed in", captured)
        self.assertNotIn("transport: request sent in", captured)
        self.assertNotIn("transport: response headers received in", captured)

    def test_http_transport_traces_surface_when_debug_on(self) -> None:
        from yggdrasim_common.process_debug import set_global_debug

        set_global_debug(True)
        try:
            captured = self._run_open_http_response()
        finally:
            set_global_debug(False)
        self.assertIn("transport: connect/TLS completed in", captured)
        self.assertIn("transport: request sent in", captured)
        self.assertIn("transport: response headers received in", captured)

    def test_pinned_tls_spki_mismatch_aborts_regardless_of_debug(self) -> None:
        """A pin mismatch closes the connection and raises, in either debug mode.

        The pinned context is built with ``CERT_NONE``, so this layer never
        sends the body: continuing would put it on an unverified channel.
        Rebuilding over a CA-verified path is the caller's job. Debug only
        controls logging, never whether the transfer proceeds.
        """
        from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

        for debug_value in ("0", "1"):
            with self.subTest(debug=debug_value):
                client = RecordingHttpStageClient(base_url="https://rsp.example.com")
                leaf_der, _ = build_test_ca_and_leaf("rsp.example.com")
                client.connection.sock = _FakeTlsSocket(leaf_der)
                request = urllib.request.Request("https://rsp.example.com/gsma/rsp2/asn1")
                buffer = io.StringIO()

                with mock.patch.dict(os.environ, {GLOBAL_DEBUG_ENV: debug_value}, clear=False):
                    with contextlib.redirect_stdout(buffer):
                        with self.assertRaises(OSError) as caught:
                            with client._open_http_response(
                                request,
                                None,
                                request.full_url,
                                label="eIM",
                                pinned_tls_spki=b"\x01",
                            ):
                                pass

                self.assertIn("Pinned TLS public key mismatch", str(caught.exception))
                self.assertTrue(client.connection.closed)
                self.assertNotIn(("request",), client.connection.calls)


if __name__ == "__main__":
    unittest.main()
