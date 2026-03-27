# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

import base64
import io
import http.client
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from yggdrasim_common.runtime_paths import ensure_runtime_dir, ensure_seeded_runtime_file, runtime_path
from SCP11.shared.gsma_error_codes import describe_sgp32_eim_package_error

try:
    from .models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        CancelSessionRequest,
        EIM_TRANSPORT_MODE_ESIPA,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )
except ImportError:
    from models import (
        AuthenticateClientRequest,
        AuthenticateClientResponse,
        CancelSessionRequest,
        EIM_TRANSPORT_MODE_ESIPA,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        GetBoundProfilePackageResponse,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        InitiateAuthenticationResponse,
    )
try:
    from .pysim_support import verify_certificate_against_ca_bundle
except ImportError:
    try:
        from pysim_support import verify_certificate_against_ca_bundle
    except ImportError:
        verify_certificate_against_ca_bundle = None


class _ManagedHttpResponse:
    def __init__(self, connection, response):
        self._connection = connection
        self._response = response

    @property
    def status(self):
        return getattr(self._response, "status", None)

    def read(self) -> bytes:
        return self._response.read()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            close_response = getattr(self._response, "close", None)
            if callable(close_response):
                close_response()
        finally:
            close_connection = getattr(self._connection, "close", None)
            if callable(close_connection):
                close_connection()
        return False


class Es9LikeClient:
    """Typed ES9-like HTTP client boundary used by SCP11 orchestration."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 15,
        verify_tls: bool = True,
        ca_bundle_path: str = "",
        eim_base_url: str = "",
        eim_timeout_seconds: int | None = None,
        eim_transport_mode: str = EIM_TRANSPORT_MODE_ESIPA,
        eim_http_path: str = "/gsma/rsp2/asn1",
        eim_http_protocol: str = "gsma/rsp/v2.1.0",
    ):
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        if isinstance(eim_timeout_seconds, int) and eim_timeout_seconds > 0:
            self._eim_timeout_seconds = eim_timeout_seconds
        else:
            self._eim_timeout_seconds = timeout_seconds
        self._verify_tls = verify_tls
        self._ca_bundle_path = ca_bundle_path.strip()
        ensure_runtime_dir("SCP11", "live")
        ensure_runtime_dir("SCP11", "live", "dynamic_ca")
        ensure_seeded_runtime_file("SCP11", "live", "es9_ca_lookup.json")
        self._module_dir = runtime_path("SCP11", "live")
        self._workspace_root = runtime_path()
        self._es9_ca_lookup_path = os.path.join(self._module_dir, "es9_ca_lookup.json")
        self._dynamic_ca_lookup = self._load_es9_ca_lookup()
        self._eim_base_url = eim_base_url.strip()
        self._eim_transport_mode = eim_transport_mode.strip()
        if self._eim_transport_mode != EIM_TRANSPORT_MODE_ESIPA:
            raise ValueError(
                "Live eIM transport only supports direct ASN.1 ESIPA mode."
            )
        self._eim_http_path = eim_http_path.strip()
        self._eim_http_protocol = eim_http_protocol.strip()

    def get_base_url(self) -> str:
        return self._base_url

    def set_base_url(self, base_url: str) -> None:
        normalized = base_url.strip().rstrip("/")
        if len(normalized) == 0:
            raise ValueError("ES9 base URL cannot be empty")
        self._base_url = normalized

    def get_verify_tls(self) -> bool:
        return self._verify_tls

    def set_verify_tls(self, enabled: bool) -> None:
        self._verify_tls = bool(enabled)

    def get_ca_bundle_path(self) -> str:
        return self._ca_bundle_path

    def set_ca_bundle_path(self, path: str) -> None:
        normalized = path.strip()
        if len(normalized) == 0:
            self._ca_bundle_path = ""
            return
        if os.path.exists(normalized) is False:
            raise ValueError(f"ES9 CA bundle does not exist: {normalized}")
        self._ca_bundle_path = normalized

    def resolve_provider_certificate_validation_bundle(
        self,
        certificate_der: bytes,
        trust_hint_ci_pkid: str = "",
    ) -> str:
        if verify_certificate_against_ca_bundle is None:
            return ""
        if len(certificate_der) == 0:
            return ""
        endpoint = self._base_url
        preferred_bundle = self._preferred_ca_bundle_for_endpoint(endpoint, trust_hint_ci_pkid)
        if len(preferred_bundle) > 0:
            try:
                verify_certificate_against_ca_bundle(certificate_der, preferred_bundle)
                return preferred_bundle
            except Exception:
                pass

        hostname, _ = self._endpoint_hostname_and_port(endpoint)
        if len(hostname) == 0:
            return ""

        lookup_entry = self._dynamic_ca_lookup.get(hostname)
        if isinstance(lookup_entry, dict):
            cached_bundle = self._resolve_lookup_bundle_path(
                str(lookup_entry.get("provider_validation_bundle", "")).strip()
            )
            if len(cached_bundle) > 0:
                try:
                    verify_certificate_against_ca_bundle(certificate_der, cached_bundle)
                    return cached_bundle
                except Exception:
                    pass

        dynamic_bundle = self._build_dynamic_validation_bundle(
            certificate_der,
            hostname=hostname,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )
        if len(dynamic_bundle) == 0:
            return ""
        verify_certificate_against_ca_bundle(certificate_der, dynamic_bundle)
        return dynamic_bundle

    def initiate_authentication(self, request_obj: InitiateAuthenticationRequest) -> InitiateAuthenticationResponse:
        payload = {
            "euiccChallenge": request_obj.euicc_challenge,
            "euiccInfo1": request_obj.euicc_info1,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json(
            "/gsma/rsp2/es9plus/initiateAuthentication",
            payload,
            trust_hint_ci_pkid=request_obj.euicc_ci_pkid_hint,
        )
        return InitiateAuthenticationResponse(
            transaction_id=self._string_field(response, "transactionId"),
            server_signed1=self._string_field(response, "serverSigned1"),
            server_signature1=self._string_field(response, "serverSignature1"),
            server_certificate=self._string_field(response, "serverCertificate"),
            euicc_ci_pkid_to_be_used=self._string_field(response, "euiccCiPKIdToBeUsed"),
        )

    def authenticate_client(self, request_obj: AuthenticateClientRequest) -> AuthenticateClientResponse:
        payload = {
            "transactionId": request_obj.transaction_id,
            "authenticateServerResponse": request_obj.authenticate_server_response,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json("/gsma/rsp2/es9plus/authenticateClient", payload)
        return AuthenticateClientResponse(
            transaction_id=self._string_field(response, "transactionID", request_obj.transaction_id),
            profile_metadata=response.get("profileMetadata"),
            smdp_signed2=self._string_field(response, "smdpSigned2"),
            smdp_signature2=self._string_field(response, "smdpSignature2"),
            smdp_certificate=self._string_field(response, "smdpCertificate"),
        )

    def get_bound_profile_package(
        self, request_obj: GetBoundProfilePackageRequest
    ) -> GetBoundProfilePackageResponse:
        payload = {
            "transactionId": request_obj.transaction_id,
            "prepareDownloadResponse": request_obj.prepare_download_response,
            "smdpAddress": request_obj.smdp_address,
        }
        response = self._post_json("/gsma/rsp2/es9plus/getBoundProfilePackage", payload)
        bpp = self._string_field(response, "boundProfilePackage")
        return GetBoundProfilePackageResponse(bound_profile_package=bpp)

    def cancel_session(self, request_obj: CancelSessionRequest) -> dict:
        payload = {
            "transactionId": request_obj.transaction_id,
            "cancelSessionResponse": request_obj.cancel_session_response,
        }
        return self._post_json("/gsma/rsp2/es9plus/cancelSession", payload)

    def handle_notification(self, request_obj: HandleNotificationRequest) -> dict:
        payload = {
            "pendingNotification": request_obj.pending_notification,
        }
        return self._post_json("/gsma/rsp2/es9plus/handleNotification", payload)

    def get_eim_package(self, request_obj: EimPollRequest) -> EimPollResponse:
        response = self._dispatch_eim_request(request_obj)
        return self._decode_eim_poll_response(response)

    def provide_eim_package_result(self, request_obj: EimPollRequest) -> dict:
        return self._dispatch_eim_request(request_obj)

    def poll_eim(self, request_obj: EimPollRequest) -> EimPollResponse:
        response = self._dispatch_eim_request(request_obj)
        return self._decode_eim_poll_response(response)

    def _dispatch_eim_request(self, request_obj: EimPollRequest) -> dict:
        base_url = self._resolve_eim_base_url(request_obj.eim_fqdn)
        if request_obj.raw_body is None or len(request_obj.raw_body) == 0:
            raise ValueError("Live eIM requests require a binary ASN.1 request body.")
        return self._post_eim_binary(
            base_url,
            request_obj.raw_body,
            request_obj.trusted_tls_public_key_data,
        )

    def _decode_eim_poll_response(self, response: dict) -> EimPollResponse:
        package_list = self._list_of_strings_field(
            response,
            "euiccPackageList",
            "packages",
            "packageList",
            "requestPackageJson",
        )
        if len(package_list) == 0:
            for wrapper in ("body", "data", "getEimPackageResponse", "getEimPackageOk"):
                if isinstance(response.get(wrapper), dict):
                    package_list = self._list_of_strings_field(
                        response[wrapper],
                        "euiccPackageList",
                        "packages",
                        "packageList",
                        "requestPackageJson",
                    )
                    if len(package_list) > 0:
                        break
        if len(package_list) == 0:
            package_value = self._first_string_field(
                response,
                "euiccPackage",
                "packageData",
                "euiccPackageRequest",
                "requestPackageJson",
            )
            if len(package_value) > 0:
                package_list = [package_value]
        return EimPollResponse(
            transaction_id=self._first_string_field(response, "transactionId", "transactionID", "eimTransactionId"),
            euicc_package_list=package_list,
            package_format=self._first_string_field(response, "packageFormat", "euiccPackageFormat"),
            polling_complete=self._bool_field(response, "pollingComplete", default=True),
            retry_after_seconds=self._int_field(response, "retryAfterSeconds", default=self._int_field(response, "retryCounter", default=0)),
            eim_result_code=self._eim_result_code_field(response),
        )

    def _poll_eim_json(self, base_url: str, request_obj: EimPollRequest) -> dict:
        raise ValueError("Live eIM polling only supports binary ASN.1 requests.")

    def _build_eim_json_payload(self, request_obj: EimPollRequest) -> dict:
        payload = {
            "eimFqdn": request_obj.eim_fqdn,
            "eimId": request_obj.eim_id,
            "eimIdType": request_obj.eim_id_type,
            "counterValue": request_obj.counter_value,
            "associationToken": request_obj.association_token,
            "supportedProtocol": request_obj.supported_protocol,
            "euiccCiPKId": request_obj.euicc_ci_pkid,
            "indirectProfileDownload": request_obj.indirect_profile_download,
            "euiccConfiguredData": request_obj.euicc_configured_data,
            "eimConfigurationData": request_obj.eim_configuration_data,
            "euiccInfo1": request_obj.euicc_info1,
            "euiccInfo2": request_obj.euicc_info2,
            "eid": request_obj.eid,
            "matchingId": request_obj.matching_id,
            "euiccPackageResult": request_obj.euicc_package_result,
        }
        if len(request_obj.transaction_id) > 0:
            payload["transactionId"] = request_obj.transaction_id
        if len(request_obj.euicc_challenge) > 0:
            payload["euiccChallenge"] = request_obj.euicc_challenge
        return payload

    def _post_eim_binary(
        self,
        base_url: str,
        body: bytes,
        pinned_tls_public_key_data: bytes,
    ) -> dict:
        path = self._normalized_eim_http_path()
        endpoint = base_url.rstrip("/") + path
        body_hex = body.hex().upper()
        if len(body) <= 64:
            print(f"[*] eIM request: POST {endpoint} body_len={len(body)} hex={body_hex}")
        else:
            print(f"[*] eIM request: POST {endpoint} body_len={len(body)} first={body[:min(32, len(body))].hex().upper()}")
        headers = {
            "Content-Type": "application/x-gsma-rsp-asn1",
            "Accept": "application/json, application/x-gsma-rsp-asn1",
        }
        if len(self._eim_http_protocol.strip()) > 0:
            headers["X-Admin-Protocol"] = self._eim_http_protocol
        request = urllib.request.Request(endpoint, data=body, method="POST", headers=headers)
        use_pinned_first = (
            endpoint.lower().startswith("https://")
            and len(pinned_tls_public_key_data) > 0
        )
        if use_pinned_first:
            print(
                "[*] eIM transport: pinned TLS public key available from BF55 "
                "metadata; using direct pinned path."
            )
            pinned_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            pinned_ctx.check_hostname = False
            pinned_ctx.verify_mode = ssl.CERT_NONE
            try:
                response_handle = self._open_http_response(
                    request,
                    pinned_ctx,
                    endpoint,
                    label="eIM",
                    timeout_seconds=self._eim_timeout_seconds,
                    pinned_tls_spki=pinned_tls_public_key_data,
                )
                with response_handle as resp:
                    raw = self._read_http_response_bytes(
                        resp,
                        endpoint,
                        label="eIM",
                    )
            except Exception as pinned_error:
                raise IOError(
                    f"Provider getEimPackage failed: {pinned_error}"
                ) from pinned_error
        else:
            ssl_context = self._build_ssl_context_for_endpoint(
                endpoint,
                use_configured_ca_bundle=False,
                log_label="eIM",
            )
            if len(pinned_tls_public_key_data) == 0:
                print(
                    "[*] eIM transport: no pinned TLS public key available "
                    "from BF55 metadata."
                )
            try:
                response_handle = self._open_http_response(
                    request,
                    ssl_context,
                    endpoint,
                    label="eIM",
                    timeout_seconds=self._eim_timeout_seconds,
                )
                with response_handle as resp:
                    raw = self._read_http_response_bytes(
                        resp,
                        endpoint,
                        label="eIM",
                    )
            except Exception as error:
                raise IOError(
                    f"ES9 request failed for {endpoint}: {error}"
                ) from error
        if len(raw) == 0:
            return {}
        is_json = raw.lstrip().startswith(b"{")
        print(f"[*] eIM response: len={len(raw)} format={'JSON' if is_json else 'binary'} "
              f"first={raw[:min(64, len(raw))].hex().upper()}")
        if is_json:
            decoded = json.loads(raw.decode("utf-8"))
            pkg_key = "euiccPackageList" if "euiccPackageList" in decoded else "packages" if "packages" in decoded else None
            pkg_count = len(decoded.get(pkg_key or "", [])) if pkg_key else 0
            print(f"[*] eIM JSON keys={list(decoded.keys())} package_key={pkg_key} package_count={pkg_count}")
            if pkg_count == 0:
                self._dump_eim_response_for_debug(raw)
        else:
            try:
                decoded = json.loads(raw.decode("utf-8"))
                print(f"[*] eIM parsed as JSON (fallback) keys={list(decoded.keys())}")
            except (ValueError, UnicodeDecodeError):
                decoded = self._parse_eim_binary_response(raw)
                pkg_count = len(decoded.get("euiccPackageList", []))
                rc = decoded.get("eimResultCode")
                rc_str = ""
                if rc is not None:
                    rc_name = self._eim_package_error_name(rc)
                    rc_str = f" eimPackageError={rc_name}"
                print(f"[*] eIM binary parsed: packages={pkg_count} "
                      f"pollingComplete={decoded.get('pollingComplete')}{rc_str}")
                if pkg_count == 0:
                    self._dump_eim_response_for_debug(raw)
        self._raise_for_execution_status(decoded, endpoint)
        return decoded

    def _dump_eim_response_for_debug(self, raw: bytes) -> None:
        try:
            debug_dir_override = str(os.environ.get("EIM_DEBUG_DIR", "")).strip()
            if len(debug_dir_override) > 0:
                debug_dir = os.path.abspath(os.path.expanduser(debug_dir_override))
                os.makedirs(debug_dir, exist_ok=True)
            else:
                debug_dir = ensure_runtime_dir("SCP11", "eim_local")
            hex_path = os.path.join(debug_dir, "eim_last_response_hex.txt")
            bin_path = os.path.join(debug_dir, "eim_last_response.bin")
            with open(hex_path, "w") as f:
                f.write(f"len={len(raw)}\n")
                f.write(raw.hex().upper())
            with open(bin_path, "wb") as f:
                f.write(raw)
            print(f"[*] eIM response dumped (packages=0): {hex_path} {bin_path}")
        except Exception as err:
            print(f"[*] eIM debug dump failed: {err}")

    def _read_tlv_at(self, data: bytes, offset: int):
        if offset >= len(data) or offset + 2 > len(data):
            return None, offset
        tag_start = offset
        offset += 1
        if data[tag_start] & 0x1F == 0x1F:
            while offset < len(data):
                offset += 1
                if data[offset - 1] & 0x80 == 0:
                    break
            else:
                return None, offset
        tag_bytes = data[tag_start:offset]
        if offset >= len(data):
            return None, offset
        length_byte = data[offset]
        offset += 1
        if length_byte & 0x80:
            num_len = length_byte & 0x7F
            if num_len > 2 or offset + num_len > len(data):
                return None, offset
            length = 0
            for _ in range(num_len):
                length = (length << 8) | data[offset]
                offset += 1
        else:
            length = length_byte
        value_start = offset
        value_end = value_start + length
        if value_end > len(data):
            return None, offset
        value = data[value_start:value_end]
        return (tag_bytes, value, value_end), value_end

    def _eim_package_error_name(self, code: int) -> str:
        """Map GetEimPackageResponse eimPackageError INTEGER to name (SGP.32)."""
        return describe_sgp32_eim_package_error(int(code))

    def _parse_eim_binary_response(self, raw: bytes) -> dict:
        """Parse eIM binary (ASN.1/BER-TLV) response; extract packages, pollingComplete, eimResultCode."""
        out = {
            "transactionId": "",
            "euiccPackageList": [],
            "pollingComplete": True,
            "packageFormat": "",
            "eimResultCode": None,
        }
        if len(raw) == 0:
            return out
        packages = []
        idx = 0
        while idx < len(raw):
            start_idx = idx
            tlv, next_idx = self._read_tlv_at(raw, idx)
            if tlv is None:
                break
            tag_bytes, value, _ = tlv
            idx = next_idx
            raw_tlv = raw[start_idx:next_idx]
            if len(tag_bytes) == 0:
                continue
            tag_first = tag_bytes[0]
            if (
                len(tag_bytes) >= 2
                and tag_bytes[0] == 0xBF
                and tag_bytes[1] == 0x4F
                and len(value) == 3
                and value[0:1] == b"\x02"
                and value[1] == 1
            ):
                result_code = value[2]
                if out.get("eimResultCode") is None:
                    out["eimResultCode"] = result_code
                if result_code == 0x7F or result_code == 0:
                    out["pollingComplete"] = True
                continue
            if tag_first == 0x0F and len(value) == 3 and value[0:1] == b"\x02" and value[1] == 1:
                result_code = value[2]
                if out.get("eimResultCode") is None:
                    out["eimResultCode"] = result_code
                if result_code == 0x7F or result_code == 0:
                    out["pollingComplete"] = True
                continue
            if tag_bytes in (b"\xBF\x51", b"\xBF\x52", b"\xBF\x54") and len(raw_tlv) > 0:
                try:
                    packages.append(base64.b64encode(raw_tlv).decode("ascii"))
                    out["pollingComplete"] = False
                except Exception:
                    pass
                continue
            if tag_bytes == b"\xBF\x50":
                out["pollingComplete"] = True
                if len(value) >= 3 and value.startswith(b"\xBF\x53"):
                    out["packageFormat"] = "eimAcknowledgements"
                    continue
                if len(value) == 2 and value == b"\x30\x00":
                    out["packageFormat"] = "emptyResponse"
                    continue
                if len(value) == 3 and value[0:1] == b"\x02" and value[1] == 1:
                    out["packageFormat"] = "provideEimPackageResultError"
                    continue
            if tag_bytes == b"\xBF\x53":
                out["pollingComplete"] = True
                out["packageFormat"] = "eimAcknowledgements"
                continue
            if tag_first == 0x04 and len(value) > 0:
                try:
                    packages.append(base64.b64encode(value).decode("ascii"))
                except Exception:
                    pass
                continue
            if tag_first == 0x0C and len(value) > 0:
                try:
                    s = value.decode("ascii", errors="ignore").strip()
                    if len(s) >= 16 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in s):
                        packages.append(s)
                except Exception:
                    pass
                continue
            constructed = (tag_first & 0x20) != 0
            if (
                constructed
                or tag_first in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0x81, 0x82, 0x83, 0x84, 0xBF)
                or (len(tag_bytes) > 1 and tag_bytes[0] == 0xBF)
            ):
                inner = self._parse_eim_binary_response(value)
                if inner.get("euiccPackageList"):
                    packages.extend(inner["euiccPackageList"])
                if inner.get("transactionId"):
                    out["transactionId"] = inner["transactionId"]
                if "pollingComplete" in inner:
                    out["pollingComplete"] = inner["pollingComplete"]
                if out.get("eimResultCode") is None and inner.get("eimResultCode") is not None:
                    out["eimResultCode"] = inner["eimResultCode"]
        if packages:
            out["euiccPackageList"] = packages
        return out

    def _post_json(
        self,
        path: str,
        body: dict,
        protocol_header: str = "gsma/rsp/v2.2.0",
        trust_hint_ci_pkid: str = "",
    ) -> dict:
        return self._post_json_to_base_url(
            self._base_url,
            path,
            body,
            protocol_header=protocol_header,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )

    def _post_json_to_base_url(
        self,
        base_url: str,
        path: str,
        body: dict,
        protocol_header: str = "gsma/rsp/v2.2.0",
        pinned_tls_public_key_data: bytes = b"",
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        tls_log_label: str = "ES9",
    ) -> dict:
        endpoint = base_url.rstrip("/") + path
        payload = json.dumps(body).encode("utf-8")
        print(
            f"[*] ES9 request: POST {endpoint} json_len={len(payload)} "
            f"keys={list(body.keys())}"
        )
        request = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers=self._build_json_headers(protocol_header),
        )

        ssl_context = None
        if endpoint.lower().startswith("https://"):
            ssl_context = self._build_ssl_context_for_endpoint(
                endpoint,
                trust_hint_ci_pkid=trust_hint_ci_pkid,
                use_configured_ca_bundle=use_configured_ca_bundle,
                log_label=tls_log_label,
            )

        try:
            raw_response = self._open_json_request(request, ssl_context)
        except Exception as error:
            resolved_bundle = self._resolve_dynamic_ca_bundle_for_endpoint(
                endpoint,
                trust_hint_ci_pkid=trust_hint_ci_pkid,
                initial_error=error,
            )
            if len(resolved_bundle) > 0:
                retry_context = self._create_default_context_with_bundle(resolved_bundle)
                try:
                    raw_response = self._open_json_request(request, retry_context)
                except Exception as retry_error:
                    raise IOError(f"ES9 request failed for {endpoint}: {retry_error}") from retry_error
            elif self._should_retry_with_pinned_tls(error, endpoint, pinned_tls_public_key_data):
                print("[*] ES9 transport: retrying with dynamically trusted pinned TLS certificate from card metadata.")
                retry_context = self._build_pinned_tls_context(endpoint, pinned_tls_public_key_data)
                try:
                    raw_response = self._open_json_request(request, retry_context)
                except Exception as retry_error:
                    raise IOError(f"ES9 request failed for {endpoint}: {retry_error}") from retry_error
            else:
                raise IOError(f"ES9 request failed for {endpoint}: {error}") from error

        if len(raw_response.strip()) == 0:
            return {}

        try:
            decoded = json.loads(raw_response)
        except json.JSONDecodeError:
            json_start = raw_response.find("{")
            if json_start == -1:
                raise IOError(f"ES9 response was not JSON: {raw_response}")
            trimmed = raw_response[json_start:]
            decoded = json.loads(trimmed)

        print(f"[*] ES9 JSON response keys={list(decoded.keys())}")
        self._raise_for_execution_status(decoded, endpoint)
        return decoded

    def _build_json_headers(self, protocol_header: str) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if len(protocol_header.strip()) > 0:
            headers["X-Admin-Protocol"] = protocol_header
        return headers

    def _open_json_request(self, request: urllib.request.Request, ssl_context: ssl.SSLContext | None) -> str:
        endpoint = request.full_url
        response_handle = self._open_http_response(
            request,
            ssl_context,
            endpoint,
            label="HTTP",
        )
        with response_handle as response:
            raw = self._read_http_response_bytes(
                response,
                endpoint,
                label="HTTP",
            )
        return raw.decode("utf-8")

    def _open_http_response(
        self,
        request: urllib.request.Request,
        ssl_context: ssl.SSLContext | None,
        endpoint: str,
        label: str,
        timeout_seconds: int | None = None,
        pinned_tls_spki: bytes | None = None,
    ):
        parsed = urlparse(endpoint)
        connection = self._create_http_connection(
            parsed,
            ssl_context,
            timeout_seconds=timeout_seconds,
        )
        request_path = self._request_target_path(parsed)
        connect_started_at = time.monotonic()
        try:
            connection.connect()
        except Exception as error:
            self._log_http_stage_failure(
                label=label,
                endpoint=endpoint,
                stage="connect/tls",
                started_at=connect_started_at,
                error=error,
            )
            close_connection = getattr(connection, "close", None)
            if callable(close_connection):
                close_connection()
            raise
        connect_elapsed_ms = int((time.monotonic() - connect_started_at) * 1000)
        print(f"[*] {label} transport: connect/TLS completed in {connect_elapsed_ms} ms.")

        if pinned_tls_spki is not None and len(pinned_tls_spki) > 0:
            tls_sock = getattr(connection, "sock", None)
            if tls_sock is not None and hasattr(tls_sock, "getpeercert"):
                peer_der = tls_sock.getpeercert(binary_form=True)
                if peer_der is None:
                    close_fn = getattr(connection, "close", None)
                    if callable(close_fn):
                        close_fn()
                    raise IOError(
                        "eIM TLS endpoint presented no certificate for "
                        f"pinned key verification: {endpoint}"
                    )
                peer_certificate = crypto_x509.load_der_x509_certificate(peer_der)
                presented_spki = peer_certificate.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if presented_spki != pinned_tls_spki:
                    close_fn = getattr(connection, "close", None)
                    if callable(close_fn):
                        close_fn()
                    raise IOError(
                        "Pinned TLS public key mismatch on live eIM connection."
                    )
                print(
                    f"[*] {label} transport: pinned TLS SPKI verified "
                    f"on live connection."
                )

        send_started_at = time.monotonic()
        request_body = request.data
        if isinstance(request_body, bytes) is False:
            request_body = b"" if request_body is None else bytes(request_body)
        try:
            request_headers = {}
            for header_name, header_value in request.header_items():
                request_headers[header_name] = header_value
            connection.request(
                request.get_method(),
                request_path,
                body=request_body,
                headers=request_headers,
            )
        except Exception as error:
            self._log_http_stage_failure(
                label=label,
                endpoint=endpoint,
                stage="request-send",
                started_at=send_started_at,
                error=error,
            )
            close_connection = getattr(connection, "close", None)
            if callable(close_connection):
                close_connection()
            raise
        send_elapsed_ms = int((time.monotonic() - send_started_at) * 1000)
        print(
            f"[*] {label} transport: request sent in {send_elapsed_ms} ms "
            f"(bytes={len(request_body)})."
        )

        header_started_at = time.monotonic()
        try:
            response = connection.getresponse()
        except Exception as error:
            self._log_http_stage_failure(
                label=label,
                endpoint=endpoint,
                stage="response-headers",
                started_at=header_started_at,
                error=error,
            )
            close_connection = getattr(connection, "close", None)
            if callable(close_connection):
                close_connection()
            raise
        header_elapsed_ms = int((time.monotonic() - header_started_at) * 1000)
        status = getattr(response, "status", None)
        if status is None:
            print(f"[*] {label} transport: response headers received in {header_elapsed_ms} ms.")
        else:
            print(f"[*] {label} transport: response headers received in {header_elapsed_ms} ms (status={status}).")
        if isinstance(status, int) and status >= 400:
            error_body_started_at = time.monotonic()
            try:
                error_body = response.read()
            except Exception as error:
                self._log_http_stage_failure(
                    label=label,
                    endpoint=endpoint,
                    stage="response-body-read",
                    started_at=error_body_started_at,
                    error=error,
                )
                close_response = getattr(response, "close", None)
                if callable(close_response):
                    close_response()
                close_connection = getattr(connection, "close", None)
                if callable(close_connection):
                    close_connection()
                raise
            error_body_elapsed_ms = int((time.monotonic() - error_body_started_at) * 1000)
            print(
                f"[*] {label} transport: error response body read in "
                f"{error_body_elapsed_ms} ms (bytes={len(error_body)})."
            )
            close_response = getattr(response, "close", None)
            if callable(close_response):
                close_response()
            close_connection = getattr(connection, "close", None)
            if callable(close_connection):
                close_connection()
            raise urllib.error.HTTPError(
                endpoint,
                status,
                str(getattr(response, "reason", f"HTTP status {status}")),
                getattr(response, "headers", None),
                io.BytesIO(error_body),
            )
        return _ManagedHttpResponse(connection, response)

    def _create_http_connection(
        self,
        parsed_endpoint,
        ssl_context: ssl.SSLContext | None,
        timeout_seconds: int | None = None,
    ):
        hostname = parsed_endpoint.hostname or ""
        port = parsed_endpoint.port
        scheme = parsed_endpoint.scheme.lower()
        effective_timeout = self._timeout_seconds
        if isinstance(timeout_seconds, int) and timeout_seconds > 0:
            effective_timeout = timeout_seconds
        if scheme == "https":
            if port is None:
                port = 443
            return http.client.HTTPSConnection(
                hostname,
                port=port,
                timeout=effective_timeout,
                context=ssl_context,
            )
        if scheme == "http":
            if port is None:
                port = 80
            return http.client.HTTPConnection(
                hostname,
                port=port,
                timeout=effective_timeout,
            )
        raise ValueError(f"Unsupported URL scheme for HTTP request: {parsed_endpoint.scheme}")

    def _request_target_path(self, parsed_endpoint) -> str:
        request_path = parsed_endpoint.path or "/"
        if len(parsed_endpoint.query) > 0:
            request_path += f"?{parsed_endpoint.query}"
        return request_path

    def _read_http_response_bytes(
        self,
        response,
        endpoint: str,
        label: str,
    ) -> bytes:
        started_at = time.monotonic()
        try:
            raw = response.read()
        except Exception as error:
            self._log_http_stage_failure(
                label=label,
                endpoint=endpoint,
                stage="response-body-read",
                started_at=started_at,
                error=error,
            )
            raise
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        print(f"[*] {label} transport: response body read in {elapsed_ms} ms (bytes={len(raw)}).")
        return raw

    def _log_http_stage_failure(
        self,
        label: str,
        endpoint: str,
        stage: str,
        started_at: float,
        error: Exception,
    ) -> None:
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        detail = self._describe_http_failure_stage(stage, error)
        print(f"[!] {label} transport: failure during {detail} after {elapsed_ms} ms for {endpoint}: {error}")

    def _describe_http_failure_stage(self, stage: str, error: Exception) -> str:
        reason = getattr(error, "reason", error)
        if stage == "response-body-read":
            if isinstance(reason, (TimeoutError, socket.timeout)):
                return "response body read timeout"
            return "response body read"
        if stage == "response-headers":
            if isinstance(reason, (TimeoutError, socket.timeout)):
                return "response header wait timeout"
            return "response headers"
        if stage == "request-send":
            if isinstance(reason, (TimeoutError, socket.timeout)):
                return "request write timeout"
            return "request send"
        if stage == "connect/tls":
            if isinstance(reason, socket.gaierror):
                return "DNS resolution"
            if isinstance(reason, ssl.SSLError):
                return "TLS handshake/verification"
            if isinstance(reason, ConnectionRefusedError):
                return "TCP connect"
            if isinstance(reason, (TimeoutError, socket.timeout)):
                return "connect/TLS timeout"
            return "connect/TLS"
        if isinstance(reason, socket.gaierror):
            return "DNS resolution"
        if isinstance(reason, ssl.SSLError):
            return "TLS handshake/verification"
        if isinstance(reason, ConnectionRefusedError):
            return "TCP connect"
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return "connect/TLS/header wait timeout"
        return "connect/TLS/response headers"

    def _raise_for_execution_status(self, response: dict, endpoint: str) -> None:
        header = response.get("header")
        if isinstance(header, dict) is False:
            return

        execution = header.get("functionExecutionStatus")
        if isinstance(execution, dict) is False:
            return

        status = str(execution.get("status", "")).strip()
        if len(status) == 0:
            return
        if status.lower() == "executed-success":
            return
        if status.lower() == "success":
            return

        detail = execution.get("statusCodeData")
        if isinstance(detail, dict):
            subject_code = self._string_field(detail, "subjectCode")
            reason_code = self._string_field(detail, "reasonCode")
            message = self._string_field(detail, "message")
            fragments = []
            if len(subject_code) > 0:
                fragments.append(f"subjectCode={subject_code}")
            if len(reason_code) > 0:
                fragments.append(f"reasonCode={reason_code}")
            if len(message) > 0:
                fragments.append(message)
            if len(fragments) > 0:
                raise IOError(f"ES9 operation failed for {endpoint}: {status} ({', '.join(fragments)})")

        raise IOError(f"ES9 operation failed for {endpoint}: {status}")

    def _string_field(self, payload: dict, key: str, default: str = "") -> str:
        value = payload.get(key, default)
        if value is None:
            return default
        if isinstance(value, str):
            return value
        return str(value)

    def _first_string_field(self, payload: dict, *keys: str) -> str:
        for key in keys:
            value = self._string_field(payload, key)
            if len(value) > 0:
                return value
        return ""

    def _list_of_strings_field(self, payload: dict, *keys: str) -> list:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                out = []
                for item in value:
                    if item is None:
                        continue
                    text = str(item).strip()
                    if len(text) == 0:
                        continue
                    out.append(text)
                if len(out) > 0:
                    return out
        return []

    def _bool_field(self, payload: dict, key: str, default: bool = False) -> bool:
        value = payload.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ["true", "1", "yes"]:
                return True
            if normalized in ["false", "0", "no"]:
                return False
        return bool(value)

    def _int_field(self, payload: dict, key: str, default: int = 0) -> int:
        value = payload.get(key, default)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                return default
        return default

    def _eim_result_code_field(self, payload: dict):
        direct_code = payload.get("eimResultCode")
        if isinstance(direct_code, int):
            return direct_code
        if isinstance(direct_code, str):
            try:
                return int(direct_code.strip())
            except ValueError:
                pass
        for wrapper in ("body", "data", "getEimPackageResponse", "getEimPackageOk"):
            wrapped = payload.get(wrapper)
            if isinstance(wrapped, dict) is False:
                continue
            wrapped_code = self._eim_result_code_field(wrapped)
            if wrapped_code is not None:
                return wrapped_code
        return None

    def _normalize_poll_base_url(self, eim_fqdn: str) -> str:
        normalized = str(eim_fqdn).strip()
        if len(normalized) == 0:
            raise ValueError("eIM FQDN is empty")
        if normalized.startswith("http://") or normalized.startswith("https://"):
            return normalized.rstrip("/")
        return "https://" + normalized.rstrip("/")

    def _resolve_eim_base_url(self, eim_fqdn: str) -> str:
        configured = self._eim_base_url.strip()
        if len(configured) > 0:
            return self._normalize_poll_base_url(configured)
        return self._normalize_poll_base_url(eim_fqdn)

    def _normalized_eim_http_path(self) -> str:
        path = self._eim_http_path.strip()
        if len(path) == 0:
            raise ValueError("EIM_HTTP_PATH is empty.")
        if path.startswith("/") is False:
            path = "/" + path
        return path

    def _load_es9_ca_lookup(self) -> dict:
        if os.path.exists(self._es9_ca_lookup_path) is False:
            return {}
        try:
            with open(self._es9_ca_lookup_path, "r", encoding="utf-8") as lookup_file:
                decoded = json.load(lookup_file)
        except Exception:
            return {}
        if isinstance(decoded, dict) is False:
            return {}
        return decoded

    def _write_es9_ca_lookup(self) -> None:
        with open(self._es9_ca_lookup_path, "w", encoding="utf-8") as lookup_file:
            json.dump(self._dynamic_ca_lookup, lookup_file, indent=2, sort_keys=True)
            lookup_file.write("\n")

    def _endpoint_hostname_and_port(self, endpoint: str) -> tuple[str, int]:
        parsed = urlparse(endpoint)
        hostname = parsed.hostname or ""
        port = parsed.port or 443
        return hostname.strip().lower(), port

    def _build_ssl_context_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
        log_label: str = "ES9",
    ) -> ssl.SSLContext | None:
        if endpoint.lower().startswith("https://") is False:
            return None
        if self._verify_tls is False:
            return ssl._create_unverified_context()
        preferred_bundle = self._preferred_ca_bundle_for_endpoint(
            endpoint,
            trust_hint_ci_pkid,
            use_configured_ca_bundle=use_configured_ca_bundle,
        )
        if len(preferred_bundle) > 0:
            print(f"[*] {log_label} TLS trust bundle selected: {preferred_bundle}")
            return self._create_default_context_with_bundle(preferred_bundle)
        return ssl.create_default_context()

    def _preferred_ca_bundle_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str = "",
        use_configured_ca_bundle: bool = True,
    ) -> str:
        configured = self._ca_bundle_path.strip()
        if use_configured_ca_bundle and len(configured) > 0 and os.path.exists(configured):
            return configured
        hostname, _ = self._endpoint_hostname_and_port(endpoint)
        if len(hostname) == 0:
            return ""
        entry = self._dynamic_ca_lookup.get(hostname)
        if isinstance(entry, dict):
            resolved = self._resolve_lookup_bundle_path(str(entry.get("selected_ca_bundle", "")).strip())
            if len(resolved) > 0:
                return resolved
        normalized_hint = trust_hint_ci_pkid.strip().upper()
        if len(normalized_hint) == 0:
            return ""
        for lookup_entry in self._dynamic_ca_lookup.values():
            if isinstance(lookup_entry, dict) is False:
                continue
            if str(lookup_entry.get("euicc_ci_pkid_hint", "")).strip().upper() != normalized_hint:
                continue
            resolved = self._resolve_lookup_bundle_path(str(lookup_entry.get("selected_ca_bundle", "")).strip())
            if len(resolved) > 0:
                return resolved
        return ""

    def _resolve_dynamic_ca_bundle_for_endpoint(
        self,
        endpoint: str,
        trust_hint_ci_pkid: str,
        initial_error: Exception,
    ) -> str:
        if self._verify_tls is False:
            return ""
        if self._is_tls_verification_error(initial_error) is False:
            return ""
        if verify_certificate_against_ca_bundle is None:
            return ""
        hostname, port = self._endpoint_hostname_and_port(endpoint)
        if len(hostname) == 0:
            return ""
        try:
            chain_der = self._fetch_server_certificate_chain_der(hostname, port)
            if len(chain_der) == 0:
                return ""
            leaf_der = chain_der[0]
            leaf_certificate = crypto_x509.load_der_x509_certificate(leaf_der)
        except Exception as error:
            print(f"[*] ES9 dynamic TLS discovery failed to fetch server certificate: {error}")
            return ""
        candidates = self._candidate_ca_bundle_paths(trust_hint_ci_pkid)
        for candidate_path in candidates:
            try:
                matched_subject = verify_certificate_against_ca_bundle(leaf_der, candidate_path)
            except Exception:
                continue
            if self._bundle_verifies_tls_handshake(endpoint, candidate_path, log_label="ES9") is False:
                continue
            self._remember_dynamic_ca_bundle(
                hostname=hostname,
                candidate_path=candidate_path,
                leaf_certificate=leaf_certificate,
                matched_subject=matched_subject,
                trust_hint_ci_pkid=trust_hint_ci_pkid,
            )
            print(f"[+] ES9 dynamic TLS trust resolved for {hostname}: {candidate_path}")
            return candidate_path
        presented_chain_bundle, presented_chain_paths = self._persist_presented_chain_bundle(
            hostname=hostname,
            chain_der=chain_der,
            leaf_certificate=leaf_certificate,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )
        if len(presented_chain_bundle) > 0:
            try:
                matched_subject = verify_certificate_against_ca_bundle(leaf_der, presented_chain_bundle)
            except Exception:
                matched_subject = ""
            if self._bundle_verifies_tls_handshake(endpoint, presented_chain_bundle, log_label="ES9") is False:
                return ""
            self._remember_dynamic_ca_bundle(
                hostname=hostname,
                candidate_path=presented_chain_bundle,
                leaf_certificate=leaf_certificate,
                matched_subject=matched_subject,
                trust_hint_ci_pkid=trust_hint_ci_pkid,
                chain_paths=presented_chain_paths,
                note=(
                    "Auto-resolved by trusting the live TLS chain presented by the endpoint "
                    "and persisting it as a reusable local CA bundle."
                ),
            )
            print(f"[+] ES9 dynamic TLS trust persisted from live chain for {hostname}: {presented_chain_bundle}")
            return presented_chain_bundle
        print(
            "[*] ES9 dynamic TLS discovery could not find a matching local CA bundle "
            f"for {hostname} (hint={trust_hint_ci_pkid or 'none'})."
        )
        return ""

    def _candidate_ca_bundle_paths(self, trust_hint_ci_pkid: str) -> list[str]:
        normalized_hint = trust_hint_ci_pkid.strip().upper()
        scored_candidates = []
        seen_paths = set()

        def add_candidate(path: str) -> None:
            normalized_path = self._resolve_lookup_bundle_path(path)
            if len(normalized_path) == 0:
                return
            if normalized_path in seen_paths:
                return
            certificate_info = self._load_pem_certificate_info(normalized_path)
            if certificate_info is None:
                return
            priority = 100
            if certificate_info["is_ca"]:
                priority -= 20
            if "CI" in os.path.basename(normalized_path).upper():
                priority -= 10
            if len(normalized_hint) > 0 and certificate_info["subject_key_identifier"] == normalized_hint:
                priority -= 80
            scored_candidates.append((priority, normalized_path))
            seen_paths.add(normalized_path)

        if len(self._ca_bundle_path.strip()) > 0:
            add_candidate(self._ca_bundle_path)

        for lookup_entry in self._dynamic_ca_lookup.values():
            if isinstance(lookup_entry, dict) is False:
                continue
            add_candidate(str(lookup_entry.get("selected_ca_bundle", "")).strip())

        for current_root, dir_names, file_names in os.walk(self._workspace_root):
            dir_names[:] = [
                name for name in dir_names
                if name not in {".git", ".venv", "__pycache__", "node_modules"}
            ]
            for file_name in file_names:
                if file_name.lower().endswith(".pem") is False:
                    continue
                upper_name = file_name.upper()
                if upper_name.startswith("SK_") or upper_name.startswith("PK_"):
                    continue
                if "CERT" not in upper_name and "CA" not in upper_name:
                    continue
                add_candidate(os.path.join(current_root, file_name))

        scored_candidates.sort(key=lambda item: (item[0], item[1]))
        return [path for _, path in scored_candidates]

    def _build_dynamic_validation_bundle(
        self,
        certificate_der: bytes,
        hostname: str,
        trust_hint_ci_pkid: str,
    ) -> str:
        try:
            leaf_certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        except Exception:
            return ""

        chain_infos = self._build_candidate_certificate_chain(
            leaf_certificate,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )
        if len(chain_infos) == 0:
            print(
                "[*] ES9 provider certificate validation could not locate a local "
                f"intermediate/root chain for {hostname}."
            )
            return ""

        bundle_path = self._write_dynamic_validation_bundle(
            leaf_certificate,
            chain_infos,
            hostname=hostname,
        )
        if len(bundle_path) == 0:
            return ""
        self._remember_provider_validation_bundle(
            hostname=hostname,
            bundle_path=bundle_path,
            chain_infos=chain_infos,
            leaf_certificate=leaf_certificate,
            trust_hint_ci_pkid=trust_hint_ci_pkid,
        )
        print(f"[+] ES9 provider certificate validation bundle resolved for {hostname}: {bundle_path}")
        return bundle_path

    def _build_candidate_certificate_chain(
        self,
        leaf_certificate: crypto_x509.Certificate,
        trust_hint_ci_pkid: str,
    ) -> list[dict]:
        candidates = self._candidate_certificate_infos(trust_hint_ci_pkid)
        normalized_hint = trust_hint_ci_pkid.strip().upper()
        chain = []
        seen_paths = set()
        current_authority_key_id = self._certificate_authority_key_identifier(leaf_certificate)
        depth = 0

        while len(current_authority_key_id) > 0 and depth < 6:
            matches = []
            for candidate in candidates:
                if candidate["subject_key_identifier"] != current_authority_key_id:
                    continue
                score = 100
                if candidate["is_ca"]:
                    score -= 20
                if candidate["self_signed"]:
                    score += 5
                if len(normalized_hint) > 0 and candidate["subject_key_identifier"] == normalized_hint:
                    score -= 40
                matches.append((score, candidate))
            if len(matches) == 0:
                break
            matches.sort(key=lambda item: (item[0], item[1]["path"]))
            next_candidate = matches[0][1]
            if next_candidate["path"] in seen_paths:
                break
            chain.append(next_candidate)
            seen_paths.add(next_candidate["path"])
            if next_candidate["self_signed"]:
                break
            next_authority_key_id = next_candidate["authority_key_identifier"]
            if len(next_authority_key_id) == 0:
                break
            if next_authority_key_id == next_candidate["subject_key_identifier"]:
                break
            current_authority_key_id = next_authority_key_id
            depth += 1

        return chain

    def _candidate_certificate_infos(self, trust_hint_ci_pkid: str) -> list[dict]:
        candidate_paths = self._candidate_ca_bundle_paths(trust_hint_ci_pkid)
        infos = []
        seen_paths = set()
        for candidate_path in candidate_paths:
            certificate_info = self._load_pem_certificate_info(candidate_path)
            if certificate_info is None:
                continue
            if candidate_path in seen_paths:
                continue
            infos.append(certificate_info)
            seen_paths.add(candidate_path)
        return infos

    def _write_dynamic_validation_bundle(
        self,
        leaf_certificate: crypto_x509.Certificate,
        chain_infos: list[dict],
        hostname: str,
    ) -> str:
        fingerprint = leaf_certificate.fingerprint(hashes.SHA256()).hex().upper()
        target_dir = os.path.join(self._module_dir, "dynamic_ca")
        os.makedirs(target_dir, exist_ok=True)
        safe_hostname = hostname.replace(".", "_")
        bundle_path = os.path.join(target_dir, f"{safe_hostname}_{fingerprint[:16]}.pem")
        seen_pem_blobs = set()
        with open(bundle_path, "wb") as bundle_file:
            for chain_info in chain_infos:
                pem_data = chain_info["pem_data"]
                if pem_data in seen_pem_blobs:
                    continue
                bundle_file.write(pem_data)
                if pem_data.endswith(b"\n") is False:
                    bundle_file.write(b"\n")
                seen_pem_blobs.add(pem_data)
        return bundle_path

    def _load_pem_certificate_info(self, path: str) -> dict | None:
        try:
            with open(path, "rb") as pem_file:
                pem_data = pem_file.read()
            certificate = crypto_x509.load_pem_x509_certificate(pem_data)
        except Exception:
            return None

        try:
            ski_extension = certificate.extensions.get_extension_for_class(crypto_x509.SubjectKeyIdentifier)
            subject_key_identifier = ski_extension.value.digest.hex().upper()
        except crypto_x509.ExtensionNotFound:
            subject_key_identifier = ""

        try:
            basic_constraints = certificate.extensions.get_extension_for_class(crypto_x509.BasicConstraints)
            is_ca = bool(basic_constraints.value.ca)
        except crypto_x509.ExtensionNotFound:
            is_ca = False

        authority_key_identifier = self._certificate_authority_key_identifier(certificate)
        subject_name = certificate.subject.rfc4514_string()
        issuer_name = certificate.issuer.rfc4514_string()

        return {
            "path": path,
            "certificate": certificate,
            "pem_data": pem_data,
            "subject_key_identifier": subject_key_identifier,
            "authority_key_identifier": authority_key_identifier,
            "is_ca": is_ca,
            "subject_name": subject_name,
            "issuer_name": issuer_name,
            "self_signed": subject_name == issuer_name,
        }

    def _resolve_lookup_bundle_path(self, path: str) -> str:
        normalized = path.strip()
        if len(normalized) == 0:
            return ""
        if os.path.isabs(normalized):
            return normalized if os.path.exists(normalized) else ""
        workspace_candidate = os.path.join(self._workspace_root, normalized)
        if os.path.exists(workspace_candidate):
            return workspace_candidate
        module_candidate = os.path.join(self._module_dir, normalized)
        if os.path.exists(module_candidate):
            return module_candidate
        return ""

    def _create_default_context_with_bundle(self, bundle_path: str) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=bundle_path)
        if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        return context

    def _bundle_verifies_tls_handshake(
        self,
        endpoint: str,
        bundle_path: str,
        log_label: str = "ES9",
    ) -> bool:
        hostname, port = self._endpoint_hostname_and_port(endpoint)
        if len(hostname) == 0:
            return False
        try:
            context = self._create_default_context_with_bundle(bundle_path)
            with socket.create_connection((hostname, port), timeout=self._timeout_seconds) as connection:
                with context.wrap_socket(connection, server_hostname=hostname):
                    return True
        except Exception as error:
            print(
                f"[*] {log_label} dynamic TLS bundle rejected by OpenSSL for "
                f"{hostname}: {error}"
            )
            return False

    def _remember_dynamic_ca_bundle(
        self,
        hostname: str,
        candidate_path: str,
        leaf_certificate: crypto_x509.Certificate,
        matched_subject: str,
        trust_hint_ci_pkid: str,
        chain_paths: list[str] | None = None,
        note: str = "",
    ) -> None:
        relative_candidate = os.path.relpath(candidate_path, self._workspace_root)
        note_text = note.strip()
        if len(note_text) == 0:
            note_text = "Auto-resolved by verifying the live SM-DP+ TLS leaf certificate against locally available PEM certificates."
        entry = {
            "selected_ca_bundle": relative_candidate,
            "subject": matched_subject,
            "issuer": leaf_certificate.issuer.rfc4514_string(),
            "leaf_subject": leaf_certificate.subject.rfc4514_string(),
            "sha256_fingerprint": leaf_certificate.fingerprint(hashes.SHA256()).hex().upper(),
            "euicc_ci_pkid_hint": trust_hint_ci_pkid.strip().upper(),
            "notes": [
                note_text,
            ],
        }
        if isinstance(chain_paths, list) and len(chain_paths) > 0:
            entry["selected_ca_chain"] = [
                os.path.relpath(chain_path, self._workspace_root) for chain_path in chain_paths
            ]
        self._dynamic_ca_lookup[hostname] = entry
        self._write_es9_ca_lookup()

    def _remember_provider_validation_bundle(
        self,
        hostname: str,
        bundle_path: str,
        chain_infos: list[dict],
        leaf_certificate: crypto_x509.Certificate,
        trust_hint_ci_pkid: str,
    ) -> None:
        existing_entry = self._dynamic_ca_lookup.get(hostname)
        if isinstance(existing_entry, dict) is False:
            existing_entry = {}
        existing_entry["provider_validation_bundle"] = os.path.relpath(bundle_path, self._workspace_root)
        existing_entry["provider_validation_chain"] = [
            os.path.relpath(chain_info["path"], self._workspace_root) for chain_info in chain_infos
        ]
        existing_entry["provider_validation_leaf_subject"] = leaf_certificate.subject.rfc4514_string()
        existing_entry["provider_validation_leaf_issuer"] = leaf_certificate.issuer.rfc4514_string()
        existing_entry["provider_validation_leaf_fingerprint"] = (
            leaf_certificate.fingerprint(hashes.SHA256()).hex().upper()
        )
        if len(trust_hint_ci_pkid.strip()) > 0:
            existing_entry["euicc_ci_pkid_hint"] = trust_hint_ci_pkid.strip().upper()
        notes = existing_entry.get("notes", [])
        if isinstance(notes, list) is False:
            notes = []
        dynamic_note = (
            "Provider certificate validation bundle is auto-built from locally available PEM certificates "
            "using AKI/SKI chain matching."
        )
        if dynamic_note not in notes:
            notes.append(dynamic_note)
        existing_entry["notes"] = notes
        self._dynamic_ca_lookup[hostname] = existing_entry
        self._write_es9_ca_lookup()

    def _certificate_authority_key_identifier(self, certificate: crypto_x509.Certificate) -> str:
        try:
            authority_extension = certificate.extensions.get_extension_for_class(
                crypto_x509.AuthorityKeyIdentifier
            )
        except crypto_x509.ExtensionNotFound:
            return ""
        key_identifier = authority_extension.value.key_identifier
        if key_identifier is None:
            return ""
        return bytes(key_identifier).hex().upper()

    def _is_tls_verification_error(self, error: Exception) -> bool:
        reason = getattr(error, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return True
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        return "certificate verify failed" in str(error).lower()

    def _should_retry_with_pinned_tls(
        self,
        error: Exception,
        endpoint: str,
        pinned_tls_public_key_data: bytes,
    ) -> bool:
        if endpoint.lower().startswith("https://") is False:
            return False
        if self._verify_tls is False:
            return False
        if len(pinned_tls_public_key_data) == 0:
            return False
        reason = getattr(error, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return True
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        error_text = str(error).lower()
        if "certificate verify failed" in error_text:
            return True
        return False

    def _build_pinned_tls_context(
        self,
        endpoint: str,
        pinned_tls_public_key_data: bytes,
    ) -> ssl.SSLContext:
        parsed = urlparse(endpoint)
        hostname = parsed.hostname
        port = parsed.port
        if hostname is None or len(hostname.strip()) == 0:
            raise IOError(f"Cannot validate pinned TLS public key without hostname: {endpoint}")
        if port is None:
            port = 443

        cert_der = self._fetch_server_certificate_der(hostname, port)
        certificate = crypto_x509.load_der_x509_certificate(cert_der)
        presented_spki = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if presented_spki != pinned_tls_public_key_data:
            raise IOError("Pinned TLS public key mismatch for eIM endpoint.")
        if self._certificate_matches_hostname(certificate, hostname) is False:
            raise IOError(f"eIM TLS certificate does not match hostname {hostname}.")

        context = ssl.create_default_context()
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        context.load_verify_locations(cadata=certificate_pem)
        if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        return context

    def _fetch_server_certificate_der(self, hostname: str, port: int) -> bytes:
        chain_der = self._fetch_server_certificate_chain_der(hostname, port)
        if len(chain_der) == 0:
            return b""
        return chain_der[0]

    def _fetch_server_certificate_chain_der(self, hostname: str, port: int) -> list[bytes]:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=self._timeout_seconds) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                get_chain = getattr(tls_socket, "get_unverified_chain", None)
                if callable(get_chain):
                    try:
                        chain = get_chain()
                    except Exception:
                        chain = []
                    normalized_chain = self._normalize_certificate_chain(chain)
                    if len(normalized_chain) > 0:
                        return normalized_chain
                leaf_der = tls_socket.getpeercert(binary_form=True)
                if isinstance(leaf_der, bytes) and len(leaf_der) > 0:
                    return [leaf_der]
                return []

    def _normalize_certificate_chain(self, chain: object) -> list[bytes]:
        if isinstance(chain, (list, tuple)) is False:
            return []
        normalized = []
        seen = set()
        for item in chain:
            if isinstance(item, bytes):
                cert_der = item
            else:
                public_bytes = getattr(item, "public_bytes", None)
                if callable(public_bytes) is False:
                    continue
                try:
                    cert_der = public_bytes()
                except TypeError:
                    try:
                        cert_der = public_bytes(serialization.Encoding.DER)
                    except Exception:
                        continue
                except Exception:
                    continue
            if isinstance(cert_der, bytes) is False or len(cert_der) == 0:
                continue
            fingerprint = hashes.Hash(hashes.SHA256())
            fingerprint.update(cert_der)
            digest = fingerprint.finalize()
            if digest in seen:
                continue
            seen.add(digest)
            normalized.append(cert_der)
        return normalized

    def _persist_presented_chain_bundle(
        self,
        hostname: str,
        chain_der: list[bytes],
        leaf_certificate: crypto_x509.Certificate,
        trust_hint_ci_pkid: str,
    ) -> tuple[str, list[str]]:
        if len(chain_der) <= 1:
            return "", []
        target_dir = os.path.join(self._module_dir, "dynamic_ca")
        os.makedirs(target_dir, exist_ok=True)
        safe_hostname = hostname.replace(".", "_")
        fingerprint = leaf_certificate.fingerprint(hashes.SHA256()).hex().upper()
        bundle_path = os.path.join(target_dir, f"{safe_hostname}_{fingerprint[:16]}_auto_ca_bundle.pem")
        seen_pem_blobs = set()
        chain_to_persist = chain_der[1:]
        written_chain_paths = []
        with open(bundle_path, "wb") as bundle_file:
            for cert_index, cert_der in enumerate(chain_to_persist, start=1):
                try:
                    certificate = crypto_x509.load_der_x509_certificate(cert_der)
                except Exception:
                    continue
                pem_data = certificate.public_bytes(serialization.Encoding.PEM)
                if pem_data in seen_pem_blobs:
                    continue
                cert_fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
                cert_role = "ca"
                if certificate.subject == certificate.issuer:
                    cert_role = "root"
                cert_path = os.path.join(
                    target_dir,
                    f"{safe_hostname}_{cert_role}_{cert_fingerprint[:16]}.pem",
                )
                with open(cert_path, "wb") as cert_file:
                    cert_file.write(pem_data)
                    if pem_data.endswith(b"\n") is False:
                        cert_file.write(b"\n")
                bundle_file.write(pem_data)
                if pem_data.endswith(b"\n") is False:
                    bundle_file.write(b"\n")
                seen_pem_blobs.add(pem_data)
                written_chain_paths.append(cert_path)
        if os.path.exists(bundle_path) is False:
            return "", []
        if os.path.getsize(bundle_path) == 0:
            return "", []
        return bundle_path, written_chain_paths

    def _certificate_matches_hostname(self, certificate: crypto_x509.Certificate, hostname: str) -> bool:
        try:
            san_extension = certificate.extensions.get_extension_for_class(crypto_x509.SubjectAlternativeName)
            dns_names = san_extension.value.get_values_for_type(crypto_x509.DNSName)
        except crypto_x509.ExtensionNotFound:
            dns_names = []

        for dns_name in dns_names:
            if self._hostname_matches_pattern(hostname, dns_name):
                return True

        if len(dns_names) > 0:
            return False

        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for common_name in common_names:
            if self._hostname_matches_pattern(hostname, common_name.value):
                return True
        return False

    def _hostname_matches_pattern(self, hostname: str, pattern: str) -> bool:
        normalized_host = hostname.strip().lower()
        normalized_pattern = pattern.strip().lower()
        if normalized_host == normalized_pattern:
            return True
        if normalized_pattern.startswith("*.") is False:
            return False
        suffix = normalized_pattern[1:]
        if normalized_host.endswith(suffix) is False:
            return False
        host_labels = normalized_host.split(".")
        pattern_labels = normalized_pattern.split(".")
        return len(host_labels) == len(pattern_labels)
