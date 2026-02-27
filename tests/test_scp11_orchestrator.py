import datetime
import unittest
from dataclasses import dataclass

from asn1crypto import core, x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.asn1_registry import ASN1Registry
from SCP11.orchestrator import SGP22Orchestrator


def encode_der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x81, value])
    return bytes([0x82, (value >> 8) & 0xFF, value & 0xFF])


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
    def __init__(self):
        self.chunked_calls = []
        self.auth_response = self._build_auth_response()

    def send(self, apdu: bytes, log_name: str) -> bytes:
        if "GetEuiccInfo1" in log_name:
            return bytes.fromhex("BF2000")
        if "GetEuiccChallenge" in log_name:
            return bytes.fromhex("AA55AA55AA55AA55AA55AA55AA55AA55")
        return b""

    def send_chunked(self, cla, ins, p1, p2_start, payload, log_name, chunk_size=250):
        self.chunked_calls.append((log_name, payload))
        if "AuthenticateServer" in log_name:
            return self.auth_response
        return b"\xBF\x21\x00"

    def _build_auth_response(self) -> bytes:
        cert = build_self_signed_cert()
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
    BACKEND_MODE: str = "remote_dp"


class OrchestratorFlowTests(unittest.TestCase):
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

        orchestrator._phase_connect()
        orchestrator._phase_authentication_seed(matching_id="", smdp_address=cfg.RSP_SERVER_URL)
        auth_seed = orchestrator._build_local_auth_seed(smdp_address=cfg.RSP_SERVER_URL)
        orchestrator._phase_authenticate_server(auth_seed, matching_id="")
        orchestrator._phase_prepare_download(smdp_address=cfg.RSP_SERVER_URL)

        self.assertTrue(len(orchestrator.state.euicc_signature1) == 64)
        self.assertTrue(len(orchestrator.state.prepare_download_response_b64) > 0)


if __name__ == "__main__":
    unittest.main()
