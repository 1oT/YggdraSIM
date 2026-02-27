import base64
import binascii
from typing import Any, Optional

from asn1crypto import core, x509

try:
    from .asn1_registry import ASN1Registry
    from .crypto_engine import CryptoEngine
    from .models import (
        AuthenticateClientRequest,
        BACKEND_MODE_LOCAL_SGP26,
        GetBoundProfilePackageRequest,
        InitiateAuthenticationRequest,
        SCP11SessionState,
    )
    from .payload_builder import PayloadBuilder
except ImportError:
    from asn1_registry import ASN1Registry
    from crypto_engine import CryptoEngine
    from models import (
        AuthenticateClientRequest,
        BACKEND_MODE_LOCAL_SGP26,
        GetBoundProfilePackageRequest,
        InitiateAuthenticationRequest,
        SCP11SessionState,
    )
    from payload_builder import PayloadBuilder


class SGP22Orchestrator:
    """Phase-based SCP11/SGP.22 orchestration with pluggable transport/provider."""

    def __init__(self, cfg: Any, apdu_channel: Any, profile_provider: Optional[Any] = None):
        self.cfg = cfg
        self.apdu_channel = apdu_channel
        self.profile_provider = profile_provider
        self.state = SCP11SessionState()
        self.cert_auth = None
        self.key_auth = None
        self.cert_pb = None
        self.key_pb = None
        self._local_credentials_loaded = False

    def run_flow(self, matching_id: str = "", smdp_address: Optional[str] = None) -> None:
        effective_smdp_address = smdp_address
        if effective_smdp_address is None:
            effective_smdp_address = self.cfg.RSP_SERVER_URL

        print("--- IOT / SGP.22 TOOL - RELAY READY ---")
        self._phase_connect()
        self._phase_load_credentials()
        auth_seed = self._phase_authentication_seed(
            matching_id=matching_id,
            smdp_address=effective_smdp_address,
        )
        self._phase_authenticate_server(auth_seed, matching_id=matching_id)
        self._phase_prepare_download(smdp_address=effective_smdp_address)
        self._phase_get_bound_profile_package(smdp_address=effective_smdp_address)
        self._phase_install_package()
        print("\n[SUCCESS] Sequence Completed.")

    def _phase_connect(self) -> None:
        print("\n[*] Phase: Connect")
        try:
            self.apdu_channel.send(bytes.fromhex("80AA000007A9058303170000"), "INIT: TERMINAL CAPABILITY")
        except IOError:
            pass

        select_apdu = b"\x00\xA4\x04\x00" + bytes([len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
        self.apdu_channel.send(select_apdu, "INIT: SELECT ISD-R")

    def _phase_load_credentials(self) -> None:
        print("\n[*] Phase: Load Credentials")
        if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
            self._ensure_local_credentials_loaded()
            print("[+] Local DP credentials loaded for SGP.26 simulation.")
            return

        if self._local_fallback_enabled():
            try:
                self._ensure_local_credentials_loaded()
                print("[+] Remote DP mode with local fallback enabled (credentials loaded).")
            except Exception as error:
                print(f"[*] Remote DP mode; local fallback unavailable ({error}).")
            return

        print("[*] Remote DP mode. Using provider-managed credentials only.")

    def _phase_authentication_seed(self, matching_id: str, smdp_address: str) -> dict:
        print("\n[*] Phase: Authentication Seed")
        euicc_info1 = self.apdu_channel.send(b"\x80\xE2\x91\x00\x03\xBF\x20\x00", "HANDSHAKE: GetEuiccInfo1")
        challenge_response = self.apdu_channel.send(
            b"\x80\xE2\x91\x00\x03\xBF\x2E\x00",
            "HANDSHAKE: GetEuiccChallenge",
        )
        self.state.card_challenge = challenge_response[-16:]
        print(f"[+] Card Challenge: {self.state.card_challenge.hex().upper()}")

        auth_seed = self._initiate_authentication_with_provider(
            euicc_info1,
            smdp_address=smdp_address,
        )
        auth_seed["matching_id"] = matching_id
        return auth_seed

    def _initiate_authentication_with_provider(self, euicc_info1: bytes, smdp_address: str) -> dict:
        can_use_provider = self.profile_provider is not None
        if can_use_provider is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("No profile provider configured and local fallback is disabled.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        request_obj = InitiateAuthenticationRequest(
            euicc_challenge=self._b64encode(self.state.card_challenge),
            euicc_info1=self._b64encode(euicc_info1),
            smdp_address=smdp_address,
        )
        try:
            response = self.profile_provider.initiate_authentication(request_obj)
        except NotImplementedError:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider initiateAuthentication not implemented and local fallback is disabled.")
            print("[*] Provider initiateAuthentication not implemented, using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)
        except Exception as error:
            if self._local_fallback_enabled() is False:
                raise RuntimeError(f"Provider initiateAuthentication failed: {error}")
            print(f"[*] Provider initiateAuthentication failed ({error}), using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        server_signed1_bytes = self._decode_string_payload(response.server_signed1)
        server_signature1 = self._decode_string_payload(response.server_signature1)
        server_certificate_bytes = self._decode_string_payload(response.server_certificate)
        ci_pk_id = self._decode_string_payload(response.euicc_ci_pkid_to_be_used)
        transaction_id = self._decode_string_payload(response.transaction_id)

        has_required_fields = True
        if len(server_signed1_bytes) == 0:
            has_required_fields = False
        if len(server_signature1) == 0:
            has_required_fields = False
        if len(server_certificate_bytes) == 0:
            has_required_fields = False
        if len(transaction_id) == 0:
            has_required_fields = False

        if has_required_fields is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider initiateAuthentication response incomplete.")
            print("[*] Provider initiateAuthentication response incomplete, using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        self.state.transaction_id = transaction_id
        server_signed1 = ASN1Registry.ServerSigned1.load(server_signed1_bytes)
        server_certificate = x509.Certificate.load(server_certificate_bytes)
        return {
            "server_signed1": server_signed1,
            "server_signature1": server_signature1,
            "server_certificate": server_certificate,
            "root_ci_id": ci_pk_id,
        }

    def _build_local_auth_seed(self, smdp_address: str) -> dict:
        self._ensure_local_credentials_loaded()
        signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(
            self.state.card_challenge,
            smdp_address,
        )
        self.state.transaction_id = transaction_id
        self.state.server_challenge = server_challenge
        signature = CryptoEngine.sign_asn1(signed1, self.key_auth)
        return {
            "server_signed1": signed1,
            "server_signature1": signature,
            "server_certificate": self.cert_auth,
            "root_ci_id": self.cfg.ROOT_CI_ID,
        }

    def _phase_authenticate_server(self, auth_seed: dict, matching_id: str) -> None:
        print("\n[*] Phase: Authenticate Server with eUICC")
        ctx_params = {
            "matchingId": matching_id,
            "deviceInfo": {
                "tac": self.cfg.TAC,
                "deviceCapabilities": self.cfg.CAPABILITIES,
            },
        }
        payload = PayloadBuilder.build_auth_server(
            signed1=auth_seed["server_signed1"],
            signature=auth_seed["server_signature1"],
            cert=auth_seed["server_certificate"],
            ctx_params=ctx_params,
            root_ci_id=auth_seed["root_ci_id"],
        )
        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "AUTH: AuthenticateServer",
        )
        self._parse_authenticate_server_response(response)
        self.state.authenticate_server_response_b64 = self._b64encode(response)

    def _parse_authenticate_server_response(self, data: bytes) -> None:
        print("\n[*] Parsing Auth Response...")
        if data[:2] != b"\xBF\x38":
            raise ValueError("Invalid Response Tag (Expected BF38)")

        offset = 2
        length_byte = data[offset]
        if length_byte < 0x80:
            content_start = offset + 1
        elif length_byte == 0x81:
            content_start = offset + 2
        elif length_byte == 0x82:
            content_start = offset + 3
        else:
            raise ValueError("Invalid DER length encoding")

        response_content = data[content_start:]
        choice_kind, choice_payload = self._unwrap_authenticate_server_choice(response_content)
        if choice_kind == "error":
            error_detail = self._decode_authenticate_server_error_constructed(choice_payload)
            if len(error_detail) > 0:
                raise PermissionError(f"Server Auth Refused by Card. {error_detail}")
            raise PermissionError("Server Auth Refused by Card (error response)")
        if choice_kind == "ok":
            response_content = choice_payload

        try:
            response_object = ASN1Registry.AuthenticateServerResponse.load(response_content)
        except Exception as error:
            error_detail = self._decode_authenticate_server_error_constructed(response_content)
            if len(error_detail) > 0:
                raise PermissionError(f"Server Auth Refused by Card. {error_detail}") from error
            preview = response_content.hex().upper()
            if len(preview) > 120:
                preview = preview[:120] + "..."
            raise ValueError(
                f"Could not parse AuthenticateServer response ({error}). Raw={preview}"
            ) from error

        if response_object.name == "authenticateResponseError":
            raise PermissionError(f"Server Auth Refused by Card. Code: {response_object.native}")

        ok_data = response_object.chosen
        self.state.euicc_signature1 = ok_data["euiccSignature1"].native
        preview = self.state.euicc_signature1.hex()[:32]
        print(f"[+] Captured euiccSignature1: {preview}...")

    def _unwrap_authenticate_server_choice(self, payload: bytes) -> tuple:
        if len(payload) < 2:
            return "", payload

        first = payload[0]
        # Common explicit wrappers seen from cards:
        # 0xA0 / 0xA1 (context-specific constructed)
        # 0x60 / 0x61 (application constructed)
        if first not in [0xA0, 0xA1, 0x60, 0x61]:
            return "", payload

        length, len_size = self._decode_length(payload, 1)
        if len_size == 0:
            return "", payload
        value_start = 1 + len_size
        value_end = value_start + length
        if value_end > len(payload):
            return "", payload
        inner = payload[value_start:value_end]

        if first in [0xA1, 0x61]:
            return "error", inner
        return "ok", inner

    def _decode_authenticate_server_error_constructed(self, payload: bytes) -> str:
        details = self._collect_small_integer_tlvs(payload)
        if len(details) == 0:
            return "AuthenticateResponseError (constructed) received."
        return "AuthenticateResponseError (constructed) " + ", ".join(details)

    def _collect_small_integer_tlvs(self, data: bytes) -> list:
        details = []
        index = 0
        while index < len(data):
            tag = data[index]
            index += 1
            length, len_size = self._decode_length(data, index)
            if len_size == 0:
                break
            index += len_size
            end = index + length
            if end > len(data):
                break
            value = data[index:end]
            index = end

            if len(value) == 0:
                continue
            if len(value) > 4:
                continue
            int_value = int.from_bytes(value, "big", signed=False)
            details.append(f"tag 0x{tag:02X}=0x{int_value:X}")
        return details

    def _decode_length(self, data: bytes, offset: int) -> tuple:
        if offset >= len(data):
            return 0, 0
        first = data[offset]
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        if count == 0:
            return 0, 0
        end = offset + 1 + count
        if end > len(data):
            return 0, 0
        length = int.from_bytes(data[offset + 1:end], "big")
        return length, 1 + count

    def _phase_prepare_download(self, smdp_address: str) -> None:
        print("\n[*] Phase: Prepare Download")
        remote_payload = self._get_prepare_download_payload_from_provider(smdp_address=smdp_address)
        if remote_payload is None:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient did not return usable payload and local fallback is disabled.")
            self._ensure_local_credentials_loaded()
            payload = PayloadBuilder.build_prepare_download(
                self.state.transaction_id,
                self.state.euicc_signature1,
                self.cert_pb,
                self.key_pb,
            )
        else:
            payload = remote_payload

        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "DOWNLOAD: PrepareDownload",
        )
        self.state.prepare_download_response_b64 = self._b64encode(response)
        print(f"[+] PrepareDownload Response: {response.hex()[:60]}...")

    def _get_prepare_download_payload_from_provider(self, smdp_address: str) -> Optional[bytes]:
        if self.profile_provider is None:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("No profile provider configured for authenticateClient.")
            return None

        authenticate_request = AuthenticateClientRequest(
            transaction_id=self._encode_transaction_id(self.state.transaction_id),
            authenticate_server_response=self.state.authenticate_server_response_b64,
            smdp_address=smdp_address,
        )
        try:
            authenticate_response = self.profile_provider.authenticate_client(authenticate_request)
        except NotImplementedError:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient not implemented and local fallback is disabled.")
            if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
                print("[*] Local SGP.26 authenticateClient not available yet, fallback to local signing.")
            return None
        except Exception as error:
            if self._local_fallback_enabled() is False:
                raise RuntimeError(f"Provider authenticateClient failed: {error}")
            print(f"[*] Provider authenticateClient failed ({error}), fallback to local signing.")
            return None

        smdp_signed2_raw = self._decode_string_payload(authenticate_response.smdp_signed2)
        smdp_signature2_raw = self._decode_string_payload(authenticate_response.smdp_signature2)
        smdp_certificate_raw = self._decode_string_payload(authenticate_response.smdp_certificate)

        has_remote_payload = True
        if len(smdp_signed2_raw) == 0:
            has_remote_payload = False
        if len(smdp_signature2_raw) == 0:
            has_remote_payload = False
        if len(smdp_certificate_raw) == 0:
            has_remote_payload = False

        if has_remote_payload is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient returned incomplete payload.")
            return None

        try:
            smdp_signed2 = ASN1Registry.SmdpSigned2.load(smdp_signed2_raw)
            smdp_certificate = x509.Certificate.load(smdp_certificate_raw)
        except Exception as error:
            if self._local_fallback_enabled() is False:
                raise RuntimeError(f"Provider authenticateClient payload parse failed: {error}")
            print(f"[*] Provider authenticateClient payload parse failed ({error}), fallback to local signing.")
            return None

        request = ASN1Registry.PrepareDownloadRequest(
            {
                "smdpSigned2": smdp_signed2,
                "smdpSignature2": core.OctetString(smdp_signature2_raw),
                "smdpCertificate": smdp_certificate,
            }
        )
        return request.dump()

    def _phase_get_bound_profile_package(self, smdp_address: str) -> None:
        print("\n[*] Phase: Get Bound Profile Package")
        if self.profile_provider is None:
            print("[*] No provider configured, skipping BPP retrieval.")
            return

        request = GetBoundProfilePackageRequest(
            transaction_id=self._encode_transaction_id(self.state.transaction_id),
            prepare_download_response=self.state.prepare_download_response_b64,
            smdp_address=smdp_address,
        )
        try:
            response = self.profile_provider.get_bound_profile_package(request)
        except NotImplementedError:
            print("[*] Provider getBoundProfilePackage not implemented yet.")
            return
        except Exception as error:
            print(f"[*] Provider getBoundProfilePackage failed: {error}")
            return

        self.state.bpp_b64 = response.bound_profile_package
        if len(self.state.bpp_b64) > 0:
            print("[+] Bound Profile Package was received.")
        else:
            print("[*] Bound Profile Package is empty.")

    def _phase_install_package(self) -> None:
        print("\n[*] Phase: Install Package")
        if len(self.state.bpp_b64) == 0:
            print("[*] Installation phase scaffold complete. No BPP available yet.")
            return
        print("[*] BPP install APDU sequence is scaffolded and pending implementation.")

    def _encode_transaction_id(self, transaction_id: bytes) -> str:
        if len(transaction_id) == 0:
            return ""
        return self._b64encode(transaction_id)

    def _decode_string_payload(self, value: str) -> bytes:
        text = str(value).strip()
        if len(text) == 0:
            return b""

        if self._is_hex(text):
            return bytes.fromhex(text)

        try:
            return base64.b64decode(text.encode("utf-8"), validate=True)
        except binascii.Error:
            return text.encode("utf-8")

    def _b64encode(self, raw_value: bytes) -> str:
        if len(raw_value) == 0:
            return ""
        return base64.b64encode(raw_value).decode("utf-8")

    def _is_hex(self, value: str) -> bool:
        if len(value) % 2 != 0:
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return True

    def _local_fallback_enabled(self) -> bool:
        if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
            return True
        return bool(getattr(self.cfg, "REMOTE_DP_ALLOW_LOCAL_FALLBACK", False))

    def _ensure_local_credentials_loaded(self) -> None:
        if self._local_credentials_loaded:
            return
        self.cert_auth, self.key_auth = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_AUTH,
            self.cfg.KEY_PATH_AUTH,
        )
        self.cert_pb, self.key_pb = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_PB,
            self.cfg.KEY_PATH_PB,
        )
        self._local_credentials_loaded = True
