import datetime
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.live.console import SCP11Console as LiveConsole
from SCP11.test.console import SCP11Console as Scp11TestConsole
from SCP11.test.es9_client import Es9LikeClient
from SCP11.test.orchestrator import SGP22Orchestrator


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


def wrap_tlv(tag_hex: str, value: bytes) -> bytes:
    tag_bytes = bytes.fromhex(tag_hex)
    return tag_bytes + encode_der_length(len(value)) + value


def build_self_signed_cert_der() -> bytes:
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Test eIM"),
        ]
    )
    certificate = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class DummyCfg:
    pass


class PollDummyCfg:
    RSP_SERVER_URL = "smdp.example.test"
    ES9_BASE_URL = "https://rsp.example.test"
    ES9_VERIFY_TLS = True
    ES9_CA_BUNDLE_PATH = ""


class PollDummyApduChannel:
    def send(self, apdu: bytes, log_name: str) -> bytes:
        return b""


class PollDummyClient:
    def __init__(self):
        self.cfg = PollDummyCfg()
        self.apdu_channel = PollDummyApduChannel()
        self.orchestrator = types.SimpleNamespace(
            run_eim_status_watchdog=lambda **kwargs: setattr(self, "last_poll_kwargs", kwargs)
        )


class RecordingEimClient(Es9LikeClient):
    def __init__(self, ca_bundle_path: str):
        super().__init__(
            base_url="https://rsp.example.com",
            eim_base_url="https://eim1.esim.tst.1ot.mobi",
            ca_bundle_path=ca_bundle_path,
        )
        self.use_configured_ca_bundle_flags = []

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ):
        self.use_configured_ca_bundle_flags.append(use_configured_ca_bundle)
        return None

    def _open_http_response(
        self,
        request,
        ssl_context,
        endpoint: str,
        label: str,
        timeout_seconds=None,
        pinned_tls_spki=None,
    ):
        class _Response:
            status = 200

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, exc_type, exc, tb):
                return False

        return _Response()

    def _read_http_response_bytes(self, response, endpoint: str, label: str) -> bytes:
        return b'{"euiccPackageList":[],"pollingComplete":true,"eimResultCode":1}'


class TestSplitPinningTests(unittest.TestCase):
    def _run_console_poll(self, console_type, argument: str):
        client = PollDummyClient()
        console = console_type(client)

        keep_running = console._cmd_eim_poll(argument)

        self.assertTrue(keep_running)
        return console, client

    def test_test_orchestrator_initializes_eim_poll_debug_flag(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)

        self.assertIs(orchestrator._eim_poll_debug_enabled, False)

    def test_test_console_poll_command_metadata_matches_live_console(self):
        live_console, _ = self._run_console_poll(LiveConsole, "")
        test_console, _ = self._run_console_poll(Scp11TestConsole, "")

        self.assertEqual(
            test_console._commands["POLL"].usage,
            live_console._commands["POLL"].usage,
        )
        self.assertEqual(
            test_console._commands["POLL"].visible_in_help,
            live_console._commands["POLL"].visible_in_help,
        )

    def test_test_console_poll_parser_matches_live_console(self):
        for argument in ["", "3", "3 15 --debug", "2 -t 20s -s 5"]:
            live_console, live_client = self._run_console_poll(LiveConsole, argument)
            test_console, test_client = self._run_console_poll(Scp11TestConsole, argument)

            self.assertIsNotNone(live_console)
            self.assertIsNotNone(test_console)
            self.assertEqual(test_client.last_poll_kwargs, live_client.last_poll_kwargs)

    def test_console_poll_uses_global_debug_when_enabled(self):
        with mock.patch.dict(os.environ, {"YGGDRASIM_GLOBAL_DEBUG": "1"}, clear=False):
            _, live_client = self._run_console_poll(LiveConsole, "")
            _, test_client = self._run_console_poll(Scp11TestConsole, "")

        self.assertTrue(bool(live_client.last_poll_kwargs["debug"]))
        self.assertTrue(bool(test_client.last_poll_kwargs["debug"]))

    def test_test_console_rejects_same_invalid_poll_tokens_as_live_console(self):
        live_client = PollDummyClient()
        live_console = LiveConsole(live_client)
        test_client = PollDummyClient()
        test_console = Scp11TestConsole(test_client)

        self.assertTrue(live_console._cmd_eim_poll("legacy-mode"))
        self.assertTrue(test_console._cmd_eim_poll("legacy-mode"))
        self.assertFalse(hasattr(live_client, "last_poll_kwargs"))
        self.assertFalse(hasattr(test_client, "last_poll_kwargs"))

    def test_certificate_form_a6_does_not_become_direct_tls_pin(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)
        certificate_der = build_self_signed_cert_der()

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A1", certificate_der)
        )

        self.assertEqual(extracted, b"")

    def test_direct_spki_form_a6_still_extracts_pin(self):
        orchestrator = SGP22Orchestrator(cfg=DummyCfg(), apdu_channel=None, profile_provider=None)
        tls_key_material = bytes.fromhex(
            "301306072A8648CE3D020106082A8648CE3D03010703420004" + "22" * 64
        )

        extracted = orchestrator._extract_direct_tls_subject_public_key_info(
            wrap_tlv("A0", tls_key_material)
        )

        self.assertEqual(extracted, wrap_tlv("30", tls_key_material))

    def test_test_eim_binary_uses_configured_ca_bundle_when_not_pinning(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_path = Path(temp_dir) / "test-ca.pem"
            bundle_path.write_text("dummy\n", encoding="utf-8")
            client = RecordingEimClient(str(bundle_path))

            client._post_eim_binary(
                "https://eim1.esim.tst.1ot.mobi",
                bytes.fromhex("BF4F125A1089049032118427504800000000006079"),
                b"",
            )

        self.assertEqual(client.use_configured_ca_bundle_flags, [True])


if __name__ == "__main__":
    unittest.main()
