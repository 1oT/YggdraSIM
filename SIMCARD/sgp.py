from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.x509.oid import ExtensionOID, NameOID

from SIMCARD.bsp import BspCryptoError, BspInstance
from SIMCARD.euicc_store import sync_euicc_store
from SIMCARD.etsi_fs import next_generated_profile_aid, rebuild_runtime_filesystem
from SIMCARD.profile_store import sync_profiles_to_store
from SIMCARD.saip_profile import decode_profile_image
from SIMCARD.sgp32_packages import (
    EuiccPackageDecodeError,
    decode_euicc_package_request,
    encode_der_integer,
    encode_euicc_package_error_signed,
    encode_euicc_package_error_unsigned,
    encode_euicc_package_result_signed,
    verify_eim_signature,
)
from SIMCARD.state import (
    SimCardState,
    SimEimEntry,
    SimEuiccPackageResultEntry,
    SimNotificationEntry,
    SimProfileEntry,
    SimSgpSession,
)
from SIMCARD.utils import (
    decode_bcd_digits,
    encode_iccid_ef,
    find_first_tlv,
    read_tlv,
    read_tlv_header,
    tlv,
)
from yggdrasim_common.card_backend import get_sim_eim_identity_path
from yggdrasim_common.inventory_crypto import read_secret_file_bytes
from yggdrasim_common.runtime_paths import ensure_seeded_workspace_file, runtime_root


DEFAULT_SIM_EIM_IDENTITY: dict[str, str] = {
    "eim_id": "2.25.311782205282738360923618091971140414400",
    "eim_id_type": "oid",
    "eim_fqdn": "yggdrasim.eim.test.1ot.com",
    "eim_endpoint": "https://yggdrasim.eim.test.1ot.com/gsma/rsp2/asn1",
    "euicc_ci_pk_id": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
    "eim_public_key_cert_path": "",
    "trusted_tls_cert_path": "",
}


class BppDuplicateIccidError(ValueError):
    pass


class BppIccidMismatchError(ValueError):
    pass


class SgpLogic:
    NOTIF_INSTALL = 0x01
    NOTIF_ENABLE = 0x02
    NOTIF_DISABLE = 0x03
    NOTIF_DELETE = 0x04

    BPP_COMMAND_IDS = {
        "bf23": 1,
        "a0": 2,
        "a1": 3,
        "a2": 4,
        "a3": 5,
    }

    def __init__(self, state: SimCardState, sim_eim_identity_path: str = "") -> None:
        self.state = state
        self._sim_eim_identity_path_override = str(sim_eim_identity_path or "").strip()
        self._ci_certificate_der = b""
        self._ci_private_key = None
        self._eum_private_key = self._load_builtin_ec_private_key(
            self._interop_asset_path(
                "SCP11",
                "SGP.26_test_Certs",
                "Valid Test Cases",
                "Variant O",
                "EUM",
                "SK_EUM_SIG_NIST.pem",
            )
        )
        self._euicc_private_key = self._load_builtin_ec_private_key(
            self._interop_asset_path(
                "SCP11",
                "SGP.26_test_Certs",
                "Valid Test Cases",
                "Variant O",
                "eUICC",
                "SK_EUICC_SIG_NIST.pem",
            )
        ) or ec.generate_private_key(ec.SECP256R1())
        self._load_builtin_interop_material()
        self._ensure_metadata_defaults()

    def reset(self) -> None:
        self.state.sgp_session = SimSgpSession()

    def handle_store_data(self, payload: bytes) -> tuple[bytes, int, int]:
        normalized = bytes(payload or b"")
        if normalized == bytes.fromhex("BF2000"):
            return self._build_euicc_info1_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF2200"):
            return self._build_euicc_info2_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF2D00"):
            return self._build_profiles_info_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF2E00"):
            challenge = self._issue_card_challenge()
            return tlv("BF2E", tlv("80", challenge)), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF28")):
            return self._build_notification_list_response(normalized), 0x90, 0x00
        if normalized == bytes.fromhex("BF2B028200"):
            return self._build_euicc_package_result_list_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF2B00"):
            return self._build_notification_retrieve_all_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF3C00"):
            return self._build_configured_data_response(), 0x90, 0x00
        if normalized == bytes.fromhex("BF4300"):
            return self._build_rat_response(), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF55")):
            return self._build_eim_configuration_response(normalized), 0x90, 0x00
        if normalized == bytes.fromhex("BF5600"):
            return self._build_certs_response(), 0x90, 0x00
        if normalized in (bytes.fromhex("BF3E00"), bytes.fromhex("BF3E035C015A")):
            return tlv("BF3E", tlv("5A", bytes.fromhex(self.state.eid))), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF31")):
            return self._handle_profile_state_change(normalized, "enabled", self.NOTIF_ENABLE, "BF31")
        if normalized.startswith(bytes.fromhex("BF32")):
            return self._handle_profile_state_change(normalized, "disabled", self.NOTIF_DISABLE, "BF32")
        if normalized.startswith(bytes.fromhex("BF33")):
            return self._handle_profile_delete(normalized)
        if normalized.startswith(bytes.fromhex("BF57")):
            return self._handle_add_eim(normalized, "BF57")
        if normalized.startswith(bytes.fromhex("BF58")):
            # SGP.32 v1.2 §5.9.16 ProfileRollbackRequest is also tagged
            # BF58, with body ``01 01 NN`` (a primitive BOOLEAN). The
            # legacy UpdateEim path uses a constructed ``A0 30 ...``
            # body. Sniff the inner first TLV to route correctly.
            if self._is_profile_rollback_request(normalized):
                return self._handle_profile_rollback(normalized)
            return self._handle_add_eim(normalized, "BF58")
        if normalized.startswith(bytes.fromhex("BF59")):
            # SGP.32 v1.2 §5.9.17 ConfigureImmediateProfileEnabling shares
            # the BF59 tag with the legacy "delete eIM" surface used by
            # the simulator's eim_local fixtures. Both carry context [0]
            # tags but differ structurally: ConfigureImmediateProfileEnabling
            # uses NULL/[1] OID/[2] UTF8String, the legacy path always
            # uses a non-empty UTF-8 eIM identifier in [0]. Sniff the
            # body to pick the correct lane.
            if self._is_configure_immediate_enable_request(normalized):
                return self._handle_configure_immediate_profile_enabling(normalized)
            return self._handle_delete_eim(normalized)
        if normalized.startswith(bytes.fromhex("BF5A")):
            return self._handle_immediate_enable(normalized)
        if normalized.startswith(bytes.fromhex("BF5B")):
            return self._handle_enable_emergency_profile(normalized)
        if normalized.startswith(bytes.fromhex("BF5C")):
            return self._handle_disable_emergency_profile(normalized)
        if normalized.startswith(bytes.fromhex("BF5D")):
            return self._handle_execute_fallback_mechanism(normalized)
        if normalized.startswith(bytes.fromhex("BF5E")):
            return self._handle_return_from_fallback(normalized)
        if normalized.startswith(bytes.fromhex("BF5F")):
            return self._handle_get_connectivity_parameters(normalized)
        if normalized.startswith(bytes.fromhex("BF65")):
            return self._handle_set_default_dp_address_es10b(normalized)
        if normalized.startswith(bytes.fromhex("BF34")):
            return self._handle_es10c_memory_reset(normalized)
        if normalized.startswith(bytes.fromhex("BF64")):
            return self._handle_euicc_memory_reset(normalized)
        if normalized.startswith(bytes.fromhex("BF30")):
            return self._remove_notification_from_list(normalized), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF35")):
            return self._handle_load_crl(normalized)
        if normalized.startswith(bytes.fromhex("BF51")):
            return self._handle_load_euicc_package(normalized)
        if normalized.startswith(bytes.fromhex("BF41")):
            reason_code = 0
            reason_raw = find_first_tlv(normalized, "81")
            if len(reason_raw) > 0:
                try:
                    _, reason_value, _, _ = read_tlv(reason_raw, 0)
                except Exception:
                    reason_value = b""
                if len(reason_value) > 0:
                    reason_code = int.from_bytes(reason_value, "big", signed=False)
            self.reset()
            return self._cancel_session_response_error(reason_code), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF2B")):
            return self._build_notification_retrieve_response(normalized), 0x90, 0x00
        if normalized.startswith(bytes.fromhex("BF38")):
            return self._handle_authenticate_server(normalized)
        if normalized.startswith(bytes.fromhex("BF21")):
            return self._handle_prepare_download(normalized)
        if normalized.startswith(bytes.fromhex("BF36")):
            return self._handle_bpp_bootstrap(normalized)
        if normalized.startswith(bytes.fromhex("BF25")):
            return self._handle_standalone_store_metadata(normalized)
        if normalized.startswith(bytes.fromhex("BF2A")):
            return self._handle_standalone_update_metadata(normalized)
        if normalized.startswith(bytes.fromhex("BF29")):
            return self._handle_set_nickname(normalized)
        if normalized.startswith(bytes.fromhex("BF3F")):
            return self._handle_set_default_dp_address(normalized)
        if len(normalized) > 0 and normalized[0] in (0x86, 0x87, 0x88, 0xA0, 0xA1, 0xA2, 0xA3):
            return self._handle_bpp_segment(normalized)
        return b"", 0x6A, 0x80

    def _handle_profile_state_change(
        self,
        payload: bytes,
        new_state: str,
        operation: int,
        response_tag: str,
    ) -> tuple[bytes, int, int]:
        profile = self._resolve_profile_reference(payload)
        if profile is None:
            return tlv(response_tag, tlv("80", b"\x01")), 0x90, 0x00
        if new_state == "enabled":
            for current in self.state.profiles:
                if current is profile:
                    current.state = "enabled"
                elif current.state == "enabled":
                    current.state = "disabled"
            self.state.active_profile_aid = profile.aid
        else:
            profile.state = new_state
            if self.state.active_profile_aid.upper() == profile.aid.upper():
                self.state.active_profile_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=operation, profile=profile)
        return tlv(response_tag, tlv("80", b"\x00")), 0x90, 0x00

    def _handle_profile_delete(self, payload: bytes) -> tuple[bytes, int, int]:
        profile = self._resolve_profile_reference(payload)
        if profile is None:
            return tlv("BF33", tlv("80", b"\x01")), 0x90, 0x00
        self._enqueue_notification(operation=self.NOTIF_DELETE, profile=profile)
        if self.state.active_profile_aid.upper() == profile.aid.upper():
            self.state.active_profile_aid = ""
        self.state.profiles = [
            current for current in self.state.profiles if current.aid.upper() != profile.aid.upper()
        ]
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        return tlv("BF33", tlv("80", b"\x00")), 0x90, 0x00

    def _handle_add_eim(self, payload: bytes, response_tag: str) -> tuple[bytes, int, int]:
        entries = self._parse_add_eim_entries(payload)
        if len(entries) == 0:
            return tlv(response_tag, tlv("80", b"\x01")), 0x90, 0x00
        self._upsert_eim_entries(entries)
        self._ensure_metadata_defaults()
        self._sync_euicc_store()
        return tlv(response_tag, b""), 0x90, 0x00

    def _handle_delete_eim(self, payload: bytes) -> tuple[bytes, int, int]:
        eim_id_raw = find_first_tlv(payload, "80")
        if len(eim_id_raw) == 0:
            return tlv("BF59", tlv("80", b"\x01")), 0x90, 0x00
        _, eim_id_value, _, _ = read_tlv(eim_id_raw, 0)
        target = self._decode_text_field(eim_id_value)
        if len(target) == 0:
            return tlv("BF59", tlv("80", b"\x01")), 0x90, 0x00
        normalized_target = self._normalize_eim_identifier(target)
        retained = [
            entry
            for entry in self.state.eim_entries
            if self._normalize_eim_identifier(entry.eim_id) != normalized_target
        ]
        if len(retained) == len(self.state.eim_entries):
            return tlv("BF59", tlv("80", b"\x01")), 0x90, 0x00
        self.state.eim_entries = retained
        self._sync_euicc_store()
        return tlv("BF59", b""), 0x90, 0x00

    @staticmethod
    def _is_configure_immediate_enable_request(payload: bytes) -> bool:
        # SGP.32 v1.2 §5.9.17 ConfigureImmediateProfileEnablingRequest body:
        #   [0] NULL OPTIONAL, [1] OBJECT IDENTIFIER OPTIONAL,
        #   [2] UTF8String OPTIONAL.
        # The legacy delete-eIM path always carries a non-empty UTF-8
        # eIM identifier under [0]. Positive ID rule: any of an empty
        # [0] (NULL), or a [1]/[2] field present, or empty body, is the
        # spec request.
        try:
            _outer_tag, outer_value, _raw, _next = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return False
        if len(outer_value) == 0:
            return True
        offset = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value, _raw_inner, next_offset = read_tlv(outer_value, offset)
            except ValueError:
                return False
            if tag_bytes == b"\x80" and len(value) == 0:
                return True
            if tag_bytes in (b"\x81", b"\x82"):
                return True
            offset = next_offset
        return False

    def _handle_configure_immediate_profile_enabling(
        self, payload: bytes
    ) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.17 ConfigureImmediateProfileEnablingResponse ::=
        # [89] SEQUENCE { configImmediateEnableResult [0] INTEGER {
        #   ok(0), insufficientMemory(1), associatedEimAlreadyExists(2),
        #   undefinedError(127) } } -- Tag 'BF59'
        if len(self.state.eim_entries) > 0:
            return (
                tlv("BF59", tlv(b"\x80", encode_der_integer(2))),
                0x90,
                0x00,
            )
        try:
            _outer_tag, outer_value, _raw, _next = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return (
                tlv("BF59", tlv(b"\x80", encode_der_integer(127))),
                0x90,
                0x00,
            )
        flag_present = False
        new_oid: str | None = None
        new_address: str | None = None
        offset = 0
        while offset < len(outer_value):
            try:
                tag_bytes, value, _raw_inner, next_offset = read_tlv(outer_value, offset)
            except ValueError:
                return (
                    tlv("BF59", tlv(b"\x80", encode_der_integer(127))),
                    0x90,
                    0x00,
                )
            if tag_bytes == b"\x80":
                flag_present = True
            elif tag_bytes == b"\x81":
                new_oid = self._format_oid(value)
            elif tag_bytes == b"\x82":
                try:
                    new_address = bytes(value).decode("utf-8", "strict").strip()
                except UnicodeDecodeError:
                    return (
                        tlv("BF59", tlv(b"\x80", encode_der_integer(127))),
                        0x90,
                        0x00,
                    )
            offset = next_offset
        self.state.immediate_enable_flag = bool(flag_present)
        if new_oid is not None:
            self.state.immediate_enable_smdp_oid = new_oid
        if new_address is not None:
            self.state.immediate_enable_smdp_address = new_address
        self._sync_euicc_store()
        return (
            tlv("BF59", tlv(b"\x80", encode_der_integer(0))),
            0x90,
            0x00,
        )

    def _handle_immediate_enable(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.15 ImmediateEnableRequest ::= [90] SEQUENCE {
        #   refreshFlag BOOLEAN } -- Tag 'BF5A'
        # Response: [90] SEQUENCE { immediateEnableResult [0] INTEGER {
        #   ok(0), immediateEnableNotAvailable(1), noSessionContext(4),
        #   catBusy(5), undefinedError(127) } }
        # The simulator does not strictly enforce "previous ES10 was
        # LoadBoundProfilePackage"; instead it requires
        # ``immediate_enable_flag`` to be set (which the spec mandates
        # as a precondition of granting immediate enabling) and a
        # disabled candidate Profile to enable.
        if self.state.immediate_enable_flag is False:
            return (
                tlv("BF5A", tlv(b"\x80", encode_der_integer(1))),
                0x90,
                0x00,
            )
        candidate = next(
            (entry for entry in reversed(self.state.profiles) if entry.state == "disabled"),
            None,
        )
        if candidate is None:
            return (
                tlv("BF5A", tlv(b"\x80", encode_der_integer(4))),
                0x90,
                0x00,
            )
        previous_enabled = next(
            (entry for entry in self.state.profiles if entry.state == "enabled"),
            None,
        )
        if previous_enabled is not None:
            previous_enabled.state = "disabled"
            previous_enabled.rollback_armed = False
            self._enqueue_notification(
                operation=self.NOTIF_DISABLE,
                profile=previous_enabled,
            )
        candidate.state = "enabled"
        candidate.rollback_armed = False
        self.state.active_profile_aid = str(candidate.aid or "")
        self.state.previous_enabled_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(
            operation=self.NOTIF_ENABLE,
            profile=candidate,
        )
        return (
            tlv("BF5A", tlv(b"\x80", encode_der_integer(0))),
            0x90,
            0x00,
        )

    @staticmethod
    def _is_profile_rollback_request(payload: bytes) -> bool:
        # BF58 ProfileRollbackRequest body: SEQUENCE { refreshFlag BOOLEAN }.
        # Single primitive BOOLEAN (tag 01). The legacy UpdateEim wrapper
        # always carries a constructed body so the discriminator is the
        # very first inner TLV tag.
        try:
            _outer_tag, outer_value, _raw, _next = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return False
        if len(outer_value) == 0:
            return False
        try:
            inner_tag, _value, _raw_inner, _next_inner = read_tlv(outer_value, 0)
        except ValueError:
            return False
        return inner_tag == b"\x01"

    def _handle_profile_rollback(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 §5.9.16 ProfileRollbackResponse ::= [88] SEQUENCE { -- BF58
        #     cmdResult INTEGER {ok(0), rollbackNotAllowed(1), catBusy(5),
        #                        commandError(7), undefinedError(127)},
        #     eUICCPackageResult [81] EuiccPackageResult OPTIONAL  -- BF51
        # }
        # AUTOMATIC TAGS keeps the cmdResult INTEGER as primitive 0x80
        # because all SEQUENCE fields are unambiguously tagged.
        candidate = next(
            (entry for entry in self.state.profiles if entry.rollback_armed is True),
            None,
        )
        previous_aid = str(self.state.previous_enabled_aid or "").strip()
        previous_profile = self._lookup_profile_by_aid(previous_aid)
        if candidate is None or previous_profile is None:
            return (
                tlv("BF58", tlv(b"\x80", encode_der_integer(1))),  # rollbackNotAllowed
                0x90,
                0x00,
            )
        candidate.state = "disabled"
        candidate.rollback_armed = False
        previous_profile.state = "enabled"
        self.state.active_profile_aid = str(previous_profile.aid or "")
        self.state.previous_enabled_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=self.NOTIF_DISABLE, profile=candidate)
        self._enqueue_notification(operation=self.NOTIF_ENABLE, profile=previous_profile)
        return (
            tlv("BF58", tlv(b"\x80", encode_der_integer(0))),
            0x90,
            0x00,
        )

    def _handle_execute_fallback_mechanism(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 §5.9.20 ExecuteFallbackMechanismResponse ::= [93] SEQUENCE { -- BF5D
        #     executeFallbackMechanismResult [0] INTEGER { ok(0),
        #         profileNotInDisabledState(2), catBusy(5),
        #         fallbackNotAvailable(6), commandError(7),
        #         ecallActive(104), undefinedError(127) }
        # }
        if bool(self.state.euicc_info.iot_specific_info.fallback_supported) is False:
            return (
                tlv("BF5D", tlv(b"\x80", encode_der_integer(7))),
                0x90,
                0x00,
            )
        fallback_profile = next(
            (entry for entry in self.state.profiles if entry.fallback_attribute is True),
            None,
        )
        currently_enabled = next(
            (entry for entry in self.state.profiles if entry.state == "enabled"),
            None,
        )
        if currently_enabled is None:
            return (
                tlv("BF5D", tlv(b"\x80", encode_der_integer(7))),
                0x90,
                0x00,
            )
        if fallback_profile is None:
            return (
                tlv("BF5D", tlv(b"\x80", encode_der_integer(6))),  # fallbackNotAvailable
                0x90,
                0x00,
            )
        if fallback_profile.state != "disabled":
            return (
                tlv("BF5D", tlv(b"\x80", encode_der_integer(2))),  # profileNotInDisabledState
                0x90,
                0x00,
            )
        currently_enabled.state = "disabled"
        fallback_profile.state = "enabled"
        self.state.active_profile_aid = str(fallback_profile.aid or "")
        # Per §5.9.20: any granted rollback authorisation is reset.
        for entry in self.state.profiles:
            entry.rollback_armed = False
        self.state.previous_enabled_aid = str(currently_enabled.aid or "")
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=self.NOTIF_DISABLE, profile=currently_enabled)
        self._enqueue_notification(operation=self.NOTIF_ENABLE, profile=fallback_profile)
        return (
            tlv("BF5D", tlv(b"\x80", encode_der_integer(0))),
            0x90,
            0x00,
        )

    def _handle_return_from_fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 §5.9.21 ReturnFromFallbackResponse ::= [94] SEQUENCE { -- BF5E
        #     returnFromFallbackResult [0] INTEGER { ok(0),
        #         fallbackNotAvailable(6), commandError(7),
        #         ecallActive(104), undefinedError(127) }
        # }
        currently_enabled = next(
            (entry for entry in self.state.profiles if entry.state == "enabled"),
            None,
        )
        if currently_enabled is None or currently_enabled.fallback_attribute is False:
            return (
                tlv("BF5E", tlv(b"\x80", encode_der_integer(6))),  # fallbackNotAvailable
                0x90,
                0x00,
            )
        previous_aid = str(self.state.previous_enabled_aid or "").strip()
        previous_profile = self._lookup_profile_by_aid(previous_aid)
        if previous_profile is None:
            return (
                tlv("BF5E", tlv(b"\x80", encode_der_integer(7))),  # commandError
                0x90,
                0x00,
            )
        currently_enabled.state = "disabled"
        previous_profile.state = "enabled"
        self.state.active_profile_aid = str(previous_profile.aid or "")
        self.state.previous_enabled_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=self.NOTIF_DISABLE, profile=currently_enabled)
        self._enqueue_notification(operation=self.NOTIF_ENABLE, profile=previous_profile)
        return (
            tlv("BF5E", tlv(b"\x80", encode_der_integer(0))),
            0x90,
            0x00,
        )

    def _lookup_profile_by_aid(self, aid: str):
        target = str(aid or "").strip().upper()
        if len(target) == 0:
            return None
        for entry in self.state.profiles:
            if str(entry.aid or "").upper() == target:
                return entry
        return None

    @staticmethod
    def _decode_refresh_flag(payload: bytes) -> bool | None:
        # SGP.32 v1.2 §5.9.22 / §5.9.23 Request body is the single
        # primitive ASN.1 BOOLEAN ``refreshFlag`` (tag ``01``). Returns
        # None for malformed payloads so the caller can map to
        # ``undefinedError(127)``.
        try:
            _outer_tag, outer_value, _raw, _next = read_tlv(bytes(payload or b""), 0)
        except ValueError:
            return None
        if len(outer_value) == 0:
            return False
        try:
            inner_tag, inner_value, _raw_inner, _next_inner = read_tlv(outer_value, 0)
        except ValueError:
            return None
        if inner_tag != b"\x01" or len(inner_value) != 1:
            return None
        return inner_value[0] != 0x00

    def _handle_enable_emergency_profile(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.22 EnableEmergencyProfile -- Tag 'BF5B'.
        # Response: [91] SEQUENCE { enableEmergencyProfileResult [0] INTEGER {
        #   ok(0), profileNotInDisabledState(2), catBusy(5),
        #   ecallNotAvailable(8), undefinedError(127) } }
        if bool(self.state.euicc_info.iot_specific_info.ecall_supported) is False:
            return tlv("BF5B", tlv(b"\x80", encode_der_integer(8))), 0x90, 0x00
        emergency_profile = next(
            (entry for entry in self.state.profiles if entry.ecall_indication is True),
            None,
        )
        if emergency_profile is None:
            return tlv("BF5B", tlv(b"\x80", encode_der_integer(8))), 0x90, 0x00
        if self._decode_refresh_flag(payload) is None:
            return tlv("BF5B", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        if emergency_profile.state != "disabled":
            return tlv("BF5B", tlv(b"\x80", encode_der_integer(2))), 0x90, 0x00
        currently_enabled = next(
            (entry for entry in self.state.profiles if entry.state == "enabled"),
            None,
        )
        if currently_enabled is not None:
            currently_enabled.state = "disabled"
            currently_enabled.rollback_armed = False
        emergency_profile.state = "enabled"
        emergency_profile.rollback_armed = False
        self.state.emergency_profile_active = True
        self.state.emergency_pre_aid = (
            str(currently_enabled.aid or "").upper() if currently_enabled is not None else ""
        )
        self.state.active_profile_aid = str(emergency_profile.aid or "")
        self.state.previous_enabled_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._sync_euicc_store()
        # Per §5.9.22: Upon enabling the Emergency Profile, the eUICC
        # SHALL NOT generate any Notifications. We therefore skip
        # ``_enqueue_notification`` here.
        return tlv("BF5B", tlv(b"\x80", encode_der_integer(0))), 0x90, 0x00

    def _handle_disable_emergency_profile(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.23 DisableEmergencyProfile -- Tag 'BF5C'.
        # Response: [92] SEQUENCE { disableEmergencyProfileResult [0] INTEGER {
        #   ok(0), profileNotInEnabledState(2), catBusy(5),
        #   undefinedError(127) } }
        # Note: the spec uses ``ecallNotAvailable(8)`` only for
        # EnableEmergencyProfile; for the disable side, §5.9.23 lists
        # ok / profileNotInEnabledState / catBusy / undefinedError.
        if bool(self.state.euicc_info.iot_specific_info.ecall_supported) is False:
            return tlv("BF5C", tlv(b"\x80", encode_der_integer(2))), 0x90, 0x00
        emergency_profile = next(
            (entry for entry in self.state.profiles if entry.ecall_indication is True),
            None,
        )
        if emergency_profile is None or emergency_profile.state != "enabled":
            return tlv("BF5C", tlv(b"\x80", encode_der_integer(2))), 0x90, 0x00
        if self._decode_refresh_flag(payload) is None:
            return tlv("BF5C", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        emergency_profile.state = "disabled"
        emergency_profile.rollback_armed = False
        previous_aid = str(self.state.emergency_pre_aid or "").strip().upper()
        previous_profile = self._lookup_profile_by_aid(previous_aid)
        if previous_profile is not None:
            previous_profile.state = "enabled"
            self.state.active_profile_aid = str(previous_profile.aid or "")
        else:
            self.state.active_profile_aid = ""
        self.state.emergency_profile_active = False
        self.state.emergency_pre_aid = ""
        self.state.previous_enabled_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._sync_euicc_store()
        # Per §5.9.23: the eUICC MAY generate notifications according
        # to the disabled / enabled Profile metadata. Existing fixtures
        # exercise the default ``notificationConfigurationInfo`` path.
        self._enqueue_notification(operation=self.NOTIF_DISABLE, profile=emergency_profile)
        if previous_profile is not None:
            self._enqueue_notification(operation=self.NOTIF_ENABLE, profile=previous_profile)
        return tlv("BF5C", tlv(b"\x80", encode_der_integer(0))), 0x90, 0x00

    def _handle_get_connectivity_parameters(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.24 GetConnectivityParameters -- Tag 'BF5F'.
        # Request: [95] SEQUENCE { } (empty body, ``BF5F00``).
        # Response: [95] CHOICE {
        #     connectivityParameters ConnectivityParameters,
        #     connectivityParametersError ConnectivityParametersError
        # } where ConnectivityParameters ::= SEQUENCE {
        #     httpParams [1] OCTET STRING OPTIONAL  -- also used for CoAP
        # } and ConnectivityParametersError ::= INTEGER {
        #     parametersNotAvailable(1), undefinedError(127) }.
        # AUTOMATIC TAGS: SEQUENCE keeps OPTIONAL field with explicit
        # context tag ``81``. The CHOICE branches inherit the same
        # implicit tagging pattern; we use ``80`` for the error INTEGER.
        _ = payload  # request carries no useful operands
        active = self._lookup_profile_by_aid(self.state.active_profile_aid)
        params_http = bytes(active.connectivity_params_http or b"") if active is not None else b""
        if len(params_http) == 0:
            return (
                tlv("BF5F", tlv(b"\x80", encode_der_integer(1))),
                0x90,
                0x00,
            )
        return (
            tlv("BF5F", tlv(b"\x81", params_http)),
            0x90,
            0x00,
        )

    def _handle_set_default_dp_address_es10b(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.25 SetDefaultDpAddress (ES10b) -- Tag 'BF65'.
        # Mirrors SGP.22 v3 §5.7.4 ES10a.SetDefaultDpAddress (BF3F) with
        # the same UTF8String operand under primitive context tag 80;
        # the eUICC MUST honour either tag and update the same persisted
        # default SM-DP+ address. Response shape [101] SEQUENCE {
        #     setDefaultDpAddressResult [0] INTEGER {
        #         ok(0), undefinedError(127) } }.
        try:
            _root_tag, root_value, _, _ = read_tlv(payload, 0)
        except Exception:
            return tlv("BF65", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        address_raw = find_first_tlv(root_value, "80")
        normalized_address = ""
        if len(address_raw) > 0:
            try:
                _, address_value, _, _ = read_tlv(address_raw, 0)
                normalized_address = address_value.decode("utf-8", "ignore").strip()
            except Exception:
                return tlv("BF65", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        if len(normalized_address) > 128:
            return tlv("BF65", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        self.state.default_dp_address = normalized_address
        self._sync_euicc_store()
        return tlv("BF65", tlv(b"\x80", encode_der_integer(0))), 0x90, 0x00

    def _handle_standalone_store_metadata(self, payload: bytes) -> tuple[bytes, int, int]:
        try:
            metadata = self._parse_store_metadata_request(payload)
        except Exception:
            return tlv("BF25", tlv("80", b"\x01")), 0x90, 0x00
        session = self.state.sgp_session
        session.bpp_store_metadata = dict(metadata)
        target_iccid = str(metadata.get("iccid", "")).strip()
        if len(target_iccid) > 0:
            self._apply_metadata_to_profile(metadata, match_iccid=target_iccid)
            self._sync_profile_store()
        return tlv("BF25", tlv("80", b"\x00")), 0x90, 0x00

    def _handle_standalone_update_metadata(self, payload: bytes) -> tuple[bytes, int, int]:
        try:
            _root_tag, root_value, _, _ = read_tlv(payload, 0)
        except Exception:
            return tlv("BF2A", tlv("80", b"\x01")), 0x90, 0x00
        rewrapped = tlv("BF25", root_value)
        try:
            metadata = self._parse_store_metadata_request(rewrapped)
        except Exception:
            metadata = {}
        target_iccid = str(metadata.get("iccid", "")).strip()
        if len(target_iccid) > 0:
            self._apply_metadata_to_profile(metadata, match_iccid=target_iccid)
            self._sync_profile_store()
        return tlv("BF2A", tlv("80", b"\x00")), 0x90, 0x00

    def _handle_set_nickname(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.22 §5.7.19 ES10c.SetNickname. BF29 root carries 5A ICCID and
        # 90 profileNickname. Result BF29 / 80 / (00 ok, 01 iccidNotFound,
        # 7F malformed).
        try:
            _root_tag, root_value, _, _ = read_tlv(payload, 0)
            iccid_raw = find_first_tlv(root_value, "5A")
            nickname_raw = find_first_tlv(root_value, "90")
        except Exception:
            return tlv("BF29", tlv("80", b"\x7F")), 0x90, 0x00

        if len(iccid_raw) == 0:
            return tlv("BF29", tlv("80", b"\x7F")), 0x90, 0x00
        try:
            _, iccid_value, _, _ = read_tlv(iccid_raw, 0)
            nickname_value = b""
            if len(nickname_raw) > 0:
                _, nickname_value, _, _ = read_tlv(nickname_raw, 0)
        except Exception:
            return tlv("BF29", tlv("80", b"\x7F")), 0x90, 0x00
        target_iccid = decode_bcd_digits(iccid_value)

        matched_profile = None
        for profile in self.state.profiles:
            if str(profile.iccid or "").strip() == target_iccid:
                matched_profile = profile
                break
        if matched_profile is None:
            return tlv("BF29", tlv("80", b"\x01")), 0x90, 0x00

        try:
            matched_profile.nickname = nickname_value.decode("utf-8", "ignore").strip()
        except Exception:
            matched_profile.nickname = ""
        self._sync_profile_store()
        return tlv("BF29", tlv("80", b"\x00")), 0x90, 0x00

    def _handle_set_default_dp_address(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.22 §5.7.21 ES10b.SetDefaultDpAddress. BF3F carries a
        # defaultDpAddress (80 utf8string). Result BF3F / 80 / (00 ok,
        # 01 invalid SM-DP+ address). An empty UTF8String resets the
        # default per the spec.
        try:
            _root_tag, root_value, _, _ = read_tlv(payload, 0)
        except Exception:
            return tlv("BF3F", tlv("80", b"\x01")), 0x90, 0x00

        address_raw = find_first_tlv(root_value, "80")
        if len(address_raw) == 0:
            return tlv("BF3F", tlv("80", b"\x01")), 0x90, 0x00
        _, address_value, _, _ = read_tlv(address_raw, 0)
        try:
            normalized_address = address_value.decode("utf-8", "ignore").strip()
        except Exception:
            return tlv("BF3F", tlv("80", b"\x01")), 0x90, 0x00
        if len(normalized_address) > 128:
            return tlv("BF3F", tlv("80", b"\x01")), 0x90, 0x00
        self.state.default_dp_address = normalized_address
        self._sync_euicc_store()
        return tlv("BF3F", tlv("80", b"\x00")), 0x90, 0x00

    def _apply_metadata_to_profile(self, metadata: dict, *, match_iccid: str) -> None:
        normalized_target = str(match_iccid or "").strip()
        if len(normalized_target) == 0:
            return
        for profile in self.state.profiles:
            if str(profile.iccid or "").strip() != normalized_target:
                continue
            service_provider = str(metadata.get("service_provider", "")).strip()
            profile_name = str(metadata.get("profile_name", "")).strip()
            profile_class = str(metadata.get("profile_class", "")).strip().lower()
            notification_address = str(metadata.get("notification_address", "")).strip()
            if len(service_provider) > 0:
                profile.service_provider = service_provider
            if len(profile_name) > 0:
                profile.profile_name = profile_name
            if len(profile_class) > 0:
                profile.profile_class = profile_class
            if len(notification_address) > 0:
                profile.notification_address = notification_address
            break

    def _handle_euicc_memory_reset(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.32 v1.2 §5.9.5 EuiccMemoryResetRequest ::= [100] SEQUENCE
        #   resetOptions [2] BIT STRING { deleteOperationalProfiles(0),
        #     deleteFieldLoadedTestProfiles(1), resetDefaultSmdpAddress(2),
        #     deletePreLoadedTestProfiles(3), deleteProvisioningProfiles(4),
        #     resetEimConfigData(5), resetImmediateEnableConfig(6) }
        # The simulator response keeps the legacy "BF64 00" empty form
        # for backwards compatibility with the existing eim-local
        # regression suite; the side-effects on state are the spec-
        # mandated work that this function actually performs.
        bits = self._decode_reset_options(payload)
        self._apply_memory_reset_bits(bits)
        return tlv("BF64", b""), 0x90, 0x00

    def _handle_load_crl(self, payload: bytes) -> tuple[bytes, int, int]:
        """SGP.22 v3 §5.7.13 ES10b.LoadCRL handler.

        Request: ``BF35`` SEQUENCE { ``A0`` Crl OCTET STRING ... }.
        Response: ``BF35`` SEQUENCE { ``80`` LoadCRLResponseOk |
        ``81`` LoadCRLResponseError }.

        The simulator records the CRL DER bytes in ``state.loaded_crls``
        for introspection but does not enforce revocation today. The
        eUICC therefore always replies ``ok(0)`` provided the request
        carries a non-empty inner CRL TLV; an empty body returns
        ``invalidSignature(2)`` to keep the bouncer behaviour honest.
        """

        crl_blob = bytes(payload[2:] if len(payload) > 2 else b"")
        # Strip the outer length byte chain to reach the inner value.
        inner_value = b""
        try:
            _outer_tag, outer_value, _outer_raw, _outer_next = read_tlv(payload, 0)
            inner_value = bytes(outer_value)
        except (ValueError, IndexError):
            pass
        if len(inner_value) == 0:
            error_response = tlv("BF35", tlv(b"\x81", encode_der_integer(2)))
            return error_response, 0x90, 0x00
        self.state.loaded_crls.append(inner_value)
        ok_response = tlv("BF35", tlv(b"\x80", encode_der_integer(0)))
        return ok_response, 0x90, 0x00

    def _handle_es10c_memory_reset(self, payload: bytes) -> tuple[bytes, int, int]:
        # SGP.22 v3 §5.7.19 ES10c.eUICCMemoryReset ::= [52] SEQUENCE { -- BF34
        #   resetOptions [2] BIT STRING { deleteOperationalProfiles(0),
        #     deleteFieldLoadedTestProfiles(1), resetDefaultSmdpAddress(2),
        #     deletePreLoadedTestProfiles(3), deleteProvisioningProfiles(4) }
        # }
        # Response: [52] SEQUENCE { resetResult [0] INTEGER { ok(0),
        #   nothingToDelete(1), catBusy(5), undefinedError(127) } }
        # AUTOMATIC TAGS encodes the single field as primitive [0]
        # context tag, hence ``80 01 RR``.
        bits = self._decode_reset_options(payload)
        if len(bits) == 0:
            return tlv("BF34", tlv(b"\x80", encode_der_integer(127))), 0x90, 0x00
        deleted_any = self._apply_memory_reset_bits(bits)
        result = 0 if deleted_any is True else 1
        return tlv("BF34", tlv(b"\x80", encode_der_integer(result))), 0x90, 0x00

    def _decode_reset_options(self, payload: bytes) -> set[int]:
        options_raw = find_first_tlv(payload, "82")
        if len(options_raw) == 0:
            return set()
        try:
            _tag, options_value, _raw, _next = read_tlv(options_raw, 0)
        except ValueError:
            return set()
        return set(self._decode_named_bit_string(options_value))

    def _apply_memory_reset_bits(self, bits: set[int]) -> bool:
        deleted_any = False
        state_changed = False
        if 0 in bits or 1 in bits or 3 in bits or 4 in bits:
            classes_to_drop: set[str] = set()
            if 0 in bits:
                classes_to_drop.add("operational")
            if 1 in bits or 3 in bits:
                classes_to_drop.add("test")
            if 4 in bits:
                classes_to_drop.add("provisioning")
            retained: list[SimProfileEntry] = []
            removed: list[SimProfileEntry] = []
            for profile in self.state.profiles:
                profile_class = str(profile.profile_class or "").strip().lower()
                if profile_class in classes_to_drop:
                    removed.append(profile)
                    continue
                retained.append(profile)
            if len(removed) > 0:
                deleted_any = True
                state_changed = True
                self.state.profiles = retained
                surviving_aids = {entry.aid for entry in retained}
                if self.state.active_profile_aid not in surviving_aids:
                    self.state.active_profile_aid = ""
                if self.state.previous_enabled_aid not in surviving_aids:
                    self.state.previous_enabled_aid = ""
                for profile in removed:
                    self._enqueue_notification(
                        operation=self.NOTIF_DELETE,
                        profile=profile,
                    )
                rebuild_runtime_filesystem(self.state)
                self._sync_profile_store()
        if 2 in bits:
            self.state.default_dp_address = ""
            state_changed = True
        if 5 in bits:
            had_entries = len(self.state.eim_entries) > 0
            self.state.eim_entries = self._default_eim_entries()
            self._ensure_metadata_defaults()
            state_changed = True
            if had_entries is True:
                deleted_any = True
        if 6 in bits:
            had_immediate = (
                self.state.immediate_enable_flag is True
                or len(self.state.immediate_enable_smdp_oid) > 0
                or len(self.state.immediate_enable_smdp_address) > 0
            )
            self.state.immediate_enable_flag = False
            self.state.immediate_enable_smdp_oid = ""
            self.state.immediate_enable_smdp_address = ""
            if had_immediate is True:
                deleted_any = True
                state_changed = True
        if state_changed is True:
            self._sync_euicc_store()
        return deleted_any

    def _parse_add_eim_entries(self, payload: bytes) -> list[SimEimEntry]:
        try:
            _, root_value, _, _ = read_tlv(payload, 0)
        except Exception:
            return []
        rows: list[SimEimEntry] = []
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, field_value, _, next_offset = read_tlv(root_value, offset)
            except Exception:
                return rows
            if tag_bytes == b"\xA0":
                row_offset = 0
                while row_offset < len(field_value):
                    try:
                        row_tag, row_value, _, next_row_offset = read_tlv(field_value, row_offset)
                    except Exception:
                        break
                    if row_tag == b"\x30":
                        entry = self._parse_eim_configuration_row(row_value)
                        if entry is not None:
                            rows.append(entry)
                    row_offset = next_row_offset
            offset = next_offset
        if len(rows) > 0:
            return rows
        legacy_entry = self._parse_legacy_add_eim_entry(root_value)
        if legacy_entry is None:
            return []
        return [legacy_entry]

    def _parse_eim_configuration_row(self, row_value: bytes) -> SimEimEntry | None:
        entry = SimEimEntry(
            eim_id="",
            supported_protocol_bits=[],
            indirect_profile_download=False,
        )
        offset = 0
        while offset < len(row_value):
            try:
                tag_bytes, field_value, _, next_offset = read_tlv(row_value, offset)
            except Exception:
                return None
            if tag_bytes == b"\x80":
                entry.eim_id = self._decode_text_field(field_value)
            elif tag_bytes == b"\x81":
                entry.eim_fqdn = self._decode_text_field(field_value)
            elif tag_bytes == b"\x82":
                entry.eim_id_type = self._decode_uint(field_value, default=1)
            elif tag_bytes == b"\x83":
                entry.counter_value = self._decode_uint(field_value, default=1)
            elif tag_bytes == b"\x84":
                entry.association_token = self._decode_uint(field_value, default=1)
            elif tag_bytes == b"\x87":
                entry.supported_protocol_bits = self._decode_named_bit_string(field_value)
            elif tag_bytes == b"\x88":
                entry.euicc_ci_pkid = bytes(field_value)
            elif tag_bytes == b"\x89":
                entry.indirect_profile_download = True
            elif tag_bytes == b"\xA5":
                entry.eim_public_key_data = bytes(field_value)
            elif tag_bytes == b"\xA6":
                entry.trusted_tls_public_key_data = bytes(field_value)
            offset = next_offset
        if len(entry.eim_id) == 0:
            return None
        if len(entry.euicc_ci_pkid) == 0:
            entry.euicc_ci_pkid = bytes(self.state.root_ci_pkid)
        return entry

    def _parse_legacy_add_eim_entry(self, root_value: bytes) -> SimEimEntry | None:
        cert_bytes = b""
        endpoint = ""
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, field_value, _, next_offset = read_tlv(root_value, offset)
            except Exception:
                return None
            if tag_bytes == b"\x80":
                cert_bytes = bytes(field_value)
            elif tag_bytes == b"\x81":
                endpoint = self._decode_text_field(field_value)
            offset = next_offset
        if len(cert_bytes) == 0 and len(endpoint) == 0:
            return None
        host = self._extract_endpoint_host(endpoint)
        eim_id = host
        eim_id_type = 2
        if len(eim_id) == 0:
            eim_id = f"legacy-eim-{hashlib.sha1(cert_bytes).hexdigest()[:16]}"
            eim_id_type = 3
        wrapped_certificate = tlv("A1", cert_bytes) if len(cert_bytes) > 0 else b""
        return SimEimEntry(
            eim_id=eim_id,
            eim_fqdn=host,
            eim_id_type=eim_id_type,
            counter_value=1,
            association_token=16,
            supported_protocol_bits=[0, 2],
            euicc_ci_pkid=bytes(self.state.root_ci_pkid),
            indirect_profile_download=True,
            eim_public_key_data=wrapped_certificate,
            trusted_tls_public_key_data=wrapped_certificate,
        )

    def _upsert_eim_entries(self, new_entries: list[SimEimEntry]) -> None:
        index_by_id = {
            self._normalize_eim_identifier(entry.eim_id): index
            for index, entry in enumerate(self.state.eim_entries)
            if len(self._normalize_eim_identifier(entry.eim_id)) > 0
        }
        for entry in new_entries:
            normalized_id = self._normalize_eim_identifier(entry.eim_id)
            if len(normalized_id) == 0:
                continue
            current_index = index_by_id.get(normalized_id)
            if current_index is None:
                index_by_id[normalized_id] = len(self.state.eim_entries)
                self.state.eim_entries.append(entry)
                continue
            self.state.eim_entries[current_index] = entry

    def _sync_euicc_store(self) -> None:
        try:
            sync_euicc_store(self.state)
        except Exception:
            return

    def _default_eim_entries(self) -> list[SimEimEntry]:
        identity = self._load_sim_eim_identity()
        eim_id = str(identity.get("eim_id", "")).strip() or DEFAULT_SIM_EIM_IDENTITY["eim_id"]
        eim_fqdn = str(identity.get("eim_fqdn", "")).strip()
        if len(eim_fqdn) == 0:
            eim_fqdn = self._extract_endpoint_host(str(identity.get("eim_endpoint", "")).strip())
        if len(eim_fqdn) == 0:
            eim_fqdn = DEFAULT_SIM_EIM_IDENTITY["eim_fqdn"]
        euicc_ci_pkid = bytes(self.state.root_ci_pkid)
        normalized_ci_pkid = str(identity.get("euicc_ci_pk_id", "")).strip().replace(" ", "").replace(":", "")
        if len(normalized_ci_pkid) > 0 and len(normalized_ci_pkid) % 2 == 0:
            try:
                euicc_ci_pkid = bytes.fromhex(normalized_ci_pkid)
            except ValueError:
                euicc_ci_pkid = bytes(self.state.root_ci_pkid)
        return [
            SimEimEntry(
                eim_id=eim_id,
                eim_fqdn=eim_fqdn,
                eim_id_type=self._resolve_default_eim_id_type(identity.get("eim_id_type", "")),
                counter_value=1,
                association_token=16,
                supported_protocol_bits=[0, 2],
                euicc_ci_pkid=euicc_ci_pkid,
                indirect_profile_download=True,
                eim_public_key_data=self._load_sim_eim_certificate_der(
                    identity,
                    "eim_public_key_cert_path",
                ),
                trusted_tls_public_key_data=self._load_sim_eim_certificate_der(
                    identity,
                    "trusted_tls_cert_path",
                ),
            )
        ]

    def _load_sim_eim_identity(self) -> dict[str, str]:
        identity = dict(DEFAULT_SIM_EIM_IDENTITY)
        identity_path = self._sim_eim_identity_path()
        if identity_path.is_file() is False:
            return identity
        try:
            payload = json.loads(identity_path.read_text(encoding="utf-8"))
        except Exception:
            return identity
        if isinstance(payload, dict) is False:
            return identity
        for key in identity.keys():
            value = payload.get(key)
            if isinstance(value, str):
                cleaned = value.strip()
                if len(cleaned) > 0:
                    identity[key] = cleaned
        return identity

    @staticmethod
    def _resolve_default_eim_id_type(value: Any) -> int:
        normalized = str(value or "").strip().casefold()
        if normalized in ("", "1", "oid", "eimidtypeoid"):
            return 1
        if normalized in ("2", "fqdn", "dns", "domain", "eimidtypefqdn"):
            return 2
        if normalized in ("3", "proprietary", "eimidtypeproprietary"):
            return 3
        return 1

    def _load_sim_eim_certificate_der(self, identity: dict[str, str], field_name: str) -> bytes:
        candidate = str(identity.get(field_name, "")).strip()
        if len(candidate) == 0:
            return b""
        identity_path = self._sim_eim_identity_path()
        candidate_path = Path(candidate)
        candidate_paths: list[Path] = []
        if candidate_path.is_absolute():
            candidate_paths.append(candidate_path)
        else:
            runtime_dir = Path(runtime_root())
            candidate_paths.extend(
                [
                    runtime_dir / candidate,
                    identity_path.parent / candidate,
                    identity_path.parent / "certs" / "eim" / candidate,
                ]
            )
        seen: set[str] = set()
        for resolved in candidate_paths:
            resolved_key = str(resolved)
            if resolved_key in seen:
                continue
            seen.add(resolved_key)
            try:
                certificate_bytes = read_secret_file_bytes(
                    resolved,
                    protect_plaintext_on_read=True,
                )
            except Exception:
                continue
            normalized = self._normalize_certificate_der(certificate_bytes)
            if len(normalized) > 0:
                return normalized
        return b""

    @staticmethod
    def _normalize_certificate_der(value: bytes) -> bytes:
        raw = bytes(value or b"")
        if len(raw) == 0:
            return b""
        try:
            certificate = crypto_x509.load_der_x509_certificate(raw)
            return certificate.public_bytes(serialization.Encoding.DER)
        except Exception:
            pass
        try:
            certificate = crypto_x509.load_pem_x509_certificate(raw)
            return certificate.public_bytes(serialization.Encoding.DER)
        except Exception:
            return b""

    def _sim_eim_identity_path(self) -> Path:
        configured_path = str(self._sim_eim_identity_path_override or "").strip()
        if len(configured_path) == 0:
            try:
                configured_path = get_sim_eim_identity_path()
            except Exception:
                configured_path = ""
        if len(configured_path) == 0:
            try:
                seeded = ensure_seeded_workspace_file(
                    ("SIMCARD", "eim_identity_template.json"),
                    "SIMCARD",
                    "eim_identity.json",
                )
            except Exception:
                return Path(runtime_root()) / "Workspace" / "SIMCARD" / "eim_identity.json"
            return Path(seeded)
        return Path(configured_path)

    def _is_builtin_default_eim_entry(self, entry: SimEimEntry) -> bool:
        normalized_protocols = sorted({int(bit) for bit in list(entry.supported_protocol_bits or [])})
        return (
            self._normalize_eim_identifier(entry.eim_id)
            == self._normalize_eim_identifier(DEFAULT_SIM_EIM_IDENTITY["eim_id"])
            and str(entry.eim_fqdn or "").strip().casefold()
            == str(DEFAULT_SIM_EIM_IDENTITY["eim_fqdn"]).strip().casefold()
            and int(entry.eim_id_type or 0) == 1
            and int(entry.counter_value or 0) == 1
            and int(entry.association_token or 0) == 16
            and normalized_protocols == [0, 2]
            and bool(entry.indirect_profile_download)
            and bytes(entry.euicc_ci_pkid or b"") == bytes(self.state.root_ci_pkid)
        )

    @staticmethod
    def _normalize_eim_identifier(value: str) -> str:
        return str(value or "").strip().casefold()

    @staticmethod
    def _decode_text_field(value: bytes) -> str:
        raw = bytes(value or b"")
        if len(raw) == 0:
            return ""
        try:
            return raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return raw.hex().upper()

    @staticmethod
    def _decode_uint(value: bytes, default: int = 0) -> int:
        raw = bytes(value or b"")
        if len(raw) == 0:
            return int(default)
        return int.from_bytes(raw, "big", signed=False)

    @staticmethod
    def _decode_named_bit_string(value: bytes) -> list[int]:
        raw = bytes(value or b"")
        if len(raw) <= 1:
            return []
        unused_bits = min(7, max(0, int(raw[0])))
        payload = raw[1:]
        total_bits = max(0, (len(payload) * 8) - unused_bits)
        enabled_bits: list[int] = []
        for bit_index in range(total_bits):
            byte_index = bit_index // 8
            bit_offset = bit_index % 8
            if payload[byte_index] & (1 << (7 - bit_offset)):
                enabled_bits.append(bit_index)
        return enabled_bits

    @staticmethod
    def _extract_endpoint_host(endpoint: str) -> str:
        text = str(endpoint or "").strip()
        if len(text) == 0:
            return ""
        candidate = text if "://" in text else f"https://{text}"
        try:
            parsed = urlparse(candidate)
        except Exception:
            return text.split("/", 1)[0].split(":", 1)[0].strip().lower()
        host = str(parsed.hostname or "").strip().lower()
        if len(host) > 0:
            return host
        return text.split("/", 1)[0].split(":", 1)[0].strip().lower()

    def _resolve_profile_reference(self, payload: bytes) -> SimProfileEntry | None:
        aid_raw = find_first_tlv(payload, "4F")
        if len(aid_raw) > 0:
            _, aid_value, _, _ = read_tlv(aid_raw, 0)
            aid_hex = aid_value.hex().upper()
            for profile in self.state.profiles:
                if profile.aid.upper() == aid_hex:
                    return profile
        iccid_raw = find_first_tlv(payload, "5A")
        if len(iccid_raw) > 0:
            _, iccid_value, _, _ = read_tlv(iccid_raw, 0)
            iccid_digits = decode_bcd_digits(iccid_value)
            for profile in self.state.profiles:
                if profile.iccid == iccid_digits:
                    return profile
        return None

    def _build_profiles_info_response(self) -> bytes:
        entries = b"".join(self._encode_profile_entry(profile) for profile in self.state.profiles)
        return tlv("BF2D", tlv("A0", tlv("30", entries)))

    def _encode_profile_entry(self, profile: SimProfileEntry) -> bytes:
        state_byte = b"\x01" if str(profile.state).strip().lower() == "enabled" else b"\x00"
        profile_class = str(profile.profile_class).strip().lower()
        class_byte = b"\x02"
        if profile_class in ("provisioning", "prov"):
            class_byte = b"\x01"
        elif profile_class == "test":
            class_byte = b"\x00"
        nickname = str(profile.nickname or "").strip() or f"ICCID-{profile.iccid[-4:]}"
        provider = str(profile.service_provider or "").strip() or "YggdraSIM"
        profile_name = str(profile.profile_name or "").strip() or nickname
        body = b"".join(
            [
                tlv("5A", encode_iccid_ef(profile.iccid)),
                tlv("4F", bytes.fromhex(profile.aid)),
                tlv("9F70", state_byte),
                tlv("90", nickname.encode("utf-8")),
                tlv("91", provider.encode("utf-8")),
                tlv("92", profile_name.encode("utf-8")),
                tlv("95", class_byte),
            ]
        )
        return tlv("E3", body)

    def _issue_card_challenge(self) -> bytes:
        challenge = hashlib.sha256(
            bytes.fromhex(self.state.eid)
            + len(self.state.apdu_history).to_bytes(4, "big", signed=False)
        ).digest()[:16]
        self.state.sgp_session.card_challenge = challenge
        return challenge

    def _build_euicc_info1_response(self) -> bytes:
        self._ensure_metadata_defaults()
        pkids = self._configured_ci_pkids()
        value = tlv("82", bytes(self.state.euicc_info.info1_svn))
        if len(pkids) > 0:
            value += tlv("A9", b"".join(tlv("04", pkid) for pkid in pkids))
            value += tlv("AA", b"".join(tlv("04", pkid) for pkid in pkids))
        return tlv("BF20", value)

    def _build_euicc_info2_response(self) -> bytes:
        self._ensure_metadata_defaults()
        info = self.state.euicc_info
        pkids = self._configured_ci_pkids()
        ext_card_resources = tlv("81", self._encode_uint(self._dynamic_installed_apps_count()))
        ext_card_resources += tlv("82", self._encode_uint(self._dynamic_free_nvm()))
        ext_card_resources += tlv("83", self._encode_uint(self._dynamic_free_ram()))

        iot_specific_info = b"".join(
            tlv("04", bytes(version))
            for version in info.iot_specific_info.iot_versions
            if len(bytes(version)) > 0
        )
        if len(iot_specific_info) > 0:
            iot_specific_info = tlv("A0", iot_specific_info)
        if info.iot_specific_info.ecall_supported:
            iot_specific_info += tlv("81", b"")
        if info.iot_specific_info.fallback_supported:
            iot_specific_info += tlv("82", b"")

        value = tlv("81", bytes(info.profile_version))
        value += tlv("82", bytes(info.svn))
        value += tlv("83", bytes(info.firmware_version))
        value += tlv("84", ext_card_resources)
        value += tlv("85", self._encode_named_bit_string(info.uicc_capability_bits))
        value += tlv("86", bytes(info.ts102241_version))
        value += tlv("87", bytes(info.globalplatform_version))
        value += tlv("88", self._encode_named_bit_string(info.rsp_capability_bits))
        value += tlv("A9", b"".join(tlv("04", pkid) for pkid in pkids))
        value += tlv("AA", b"".join(tlv("04", pkid) for pkid in pkids))
        value += tlv("8B", bytes([int(info.euicc_category) & 0xFF]))
        value += tlv("99", self._encode_named_bit_string(info.forbidden_profile_policy_bits))
        value += tlv("04", bytes(info.pp_version))
        value += tlv("0C", str(info.sas_accreditation_number).encode("utf-8"))
        if len(info.additional_pp_versions) > 0:
            value += tlv("AF", b"".join(tlv("04", bytes(version)) for version in info.additional_pp_versions))
        value += tlv("90", bytes([int(info.ipa_mode) & 0xFF]))
        value += tlv("B4", iot_specific_info)
        return tlv("BF22", value)

    def _build_configured_data_response(self) -> bytes:
        self._ensure_metadata_defaults()
        configured = self.state.configured_data
        body = [tlv("80", self.state.default_dp_address.encode("utf-8"))]
        root_smds_address = str(configured.root_smds_address or "").strip()
        if len(root_smds_address) > 0:
            body.append(tlv("81", root_smds_address.encode("utf-8")))
        additional_root_smds = [
            str(address).strip()
            for address in configured.additional_root_smds_addresses
            if len(str(address).strip()) > 0
        ]
        if len(additional_root_smds) > 0:
            body.append(
                tlv(
                    "A2",
                    b"".join(tlv("82", address.encode("utf-8")) for address in additional_root_smds),
                )
            )
        for pkid in self._configured_ci_pkids():
            body.append(tlv("83", pkid))
        ci_list = self._dedupe_byte_values(getattr(configured, "ci_list", []))
        if len(ci_list) > 0:
            body.append(tlv("A4", b"".join(tlv("84", item) for item in ci_list)))
        return tlv("BF3C", b"".join(body))

    def _build_rat_response(self) -> bytes:
        # SGP.22 §5.7.16 ES10c.GetRAT returns a RulesAuthorisationTable
        # (SEQUENCE OF ProfilePolicyAuthorisationRule). An eUICC with no
        # configured PPR rules MUST still emit a well-formed empty SEQUENCE.
        # The simulated card currently ships with no PPRs, so the response
        # is a BF43 container holding one empty SEQUENCE (30 00).
        return tlv("BF43", bytes.fromhex("3000"))

    def _build_certs_response(self) -> bytes:
        self._ensure_metadata_defaults()
        body = b""
        if len(bytes(self.state.eum_certificate_der or b"")) > 0:
            body += tlv("A0", tlv("A5", bytes(self.state.eum_certificate_der)))
        euicc_certificate_der = self._current_euicc_certificate_der()
        if len(euicc_certificate_der) > 0:
            body += tlv("A1", tlv("A6", euicc_certificate_der))
        return tlv("BF56", body)

    def _build_eim_configuration_response(self, request: bytes = b"") -> bytes:
        # SGP.32 v1.2 §5.9.18 GetEimConfigurationDataRequest body carries
        # an optional ``searchCriteria CHOICE { eimId [0] UTF8String }``.
        # When provided, only the matching entry is returned.
        self._ensure_metadata_defaults()
        target_eim_id = ""
        if len(request) > 0:
            try:
                _outer_tag, outer_value, _raw, _next = read_tlv(bytes(request), 0)
            except ValueError:
                outer_value = b""
            if len(outer_value) > 0:
                try:
                    inner_tag, inner_value, _raw_inner, _next_inner = read_tlv(outer_value, 0)
                except ValueError:
                    inner_tag = b""
                    inner_value = b""
                if inner_tag == b"\x80" and len(inner_value) > 0:
                    target_eim_id = self._normalize_eim_identifier(
                        self._decode_text_field(inner_value)
                    )
        entries = b""
        for entry in self.state.eim_entries:
            if len(target_eim_id) > 0:
                if self._normalize_eim_identifier(entry.eim_id) != target_eim_id:
                    continue
            body = tlv("80", str(entry.eim_id).encode("utf-8"))
            if len(str(entry.eim_fqdn or "").strip()) > 0:
                body += tlv("81", str(entry.eim_fqdn).encode("utf-8"))
            body += tlv("82", self._encode_uint(entry.eim_id_type))
            body += tlv("83", self._encode_uint(entry.counter_value))
            body += tlv("84", self._encode_uint(entry.association_token))
            body += tlv("87", self._encode_named_bit_string(entry.supported_protocol_bits))
            body += tlv("88", bytes(entry.euicc_ci_pkid))
            if entry.indirect_profile_download:
                body += tlv("89", b"")
            if len(bytes(entry.eim_public_key_data or b"")) > 0:
                body += tlv("A5", bytes(entry.eim_public_key_data))
            if len(bytes(entry.trusted_tls_public_key_data or b"")) > 0:
                body += tlv("A6", bytes(entry.trusted_tls_public_key_data))
            entries += tlv("A0", tlv("30", body))
        return tlv("BF55", entries)

    def _ensure_metadata_defaults(self) -> None:
        configured = self.state.configured_data
        configured.allowed_ci_pkids = self._dedupe_byte_values(
            [bytes(self.state.root_ci_pkid)] + list(getattr(configured, "allowed_ci_pkids", []))
        )
        if len(configured.ci_list) == 0:
            configured.ci_list = [bytes(pkid) for pkid in configured.allowed_ci_pkids]
        else:
            configured.ci_list = self._dedupe_byte_values(getattr(configured, "ci_list", []))

        managed_default_entries = self._default_eim_entries()
        if len(self.state.eim_entries) == 1 and len(managed_default_entries) == 1:
            if self._is_builtin_default_eim_entry(self.state.eim_entries[0]):
                self.state.eim_entries = managed_default_entries

        self._ensure_default_certificate_chain()

        for index, entry in enumerate(self.state.eim_entries, start=1):
            entry.euicc_ci_pkid = bytes(entry.euicc_ci_pkid or b"") or bytes(self.state.root_ci_pkid)
            if len(bytes(entry.eim_public_key_data or b"")) == 0:
                entry.eim_public_key_data = self._build_named_certificate(
                    f"Simulated eIM Signer {index}"
                )
            if len(bytes(entry.trusted_tls_public_key_data or b"")) == 0:
                entry.trusted_tls_public_key_data = self._build_named_certificate(
                    f"Simulated eIM TLS {index}"
                )

    def _configured_ci_pkids(self) -> list[bytes]:
        configured = self.state.configured_data
        values = [bytes(self.state.root_ci_pkid)] + list(getattr(configured, "allowed_ci_pkids", []))
        return self._dedupe_byte_values(values)

    @staticmethod
    def _dedupe_byte_values(values: list[bytes]) -> list[bytes]:
        unique: list[bytes] = []
        seen: set[str] = set()
        for value in values:
            raw = bytes(value or b"")
            if len(raw) == 0:
                continue
            fingerprint = raw.hex().upper()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            unique.append(raw)
        return unique

    @staticmethod
    def _encode_uint(value: int) -> bytes:
        normalized = max(0, int(value))
        length = max(1, (normalized.bit_length() + 7) // 8)
        return normalized.to_bytes(length, "big", signed=False)

    @staticmethod
    def _encode_named_bit_string(bits: list[int]) -> bytes:
        normalized = sorted({int(bit) for bit in bits if int(bit) >= 0})
        if len(normalized) == 0:
            return b"\x00"
        highest = normalized[-1]
        payload = bytearray((highest // 8) + 1)
        for bit in normalized:
            byte_index = bit // 8
            bit_offset = bit % 8
            payload[byte_index] |= 1 << (7 - bit_offset)
        total_bits = len(payload) * 8
        unused_bits = total_bits - (highest + 1)
        return bytes([unused_bits]) + bytes(payload)

    def _active_profile(self) -> SimProfileEntry | None:
        active_aid = str(self.state.active_profile_aid or "").strip().upper()
        if len(active_aid) > 0:
            for profile in self.state.profiles:
                if profile.aid.upper() == active_aid:
                    return profile
        for profile in self.state.profiles:
            if str(profile.state).strip().lower() == "enabled":
                return profile
        return None

    def _dynamic_installed_apps_count(self) -> int:
        base_count = max(0, int(self.state.euicc_info.ext_card_resources.system_apps_count))
        total = base_count + len(self.state.profiles)
        active_profile = self._active_profile()
        if active_profile is None or active_profile.profile_image is None:
            return total
        paths = {tuple(node.path) for node in active_profile.profile_image.nodes}
        if ("MF", "ADF.USIM") in paths:
            total += 1
        if ("MF", "ADF.ISIM") in paths:
            total += 1
        return total

    def _dynamic_profile_storage_bytes(self) -> int:
        total = 0
        for profile in self.state.profiles:
            if len(bytes(profile.upp_bytes or b"")) > 0:
                total += len(bytes(profile.upp_bytes))
                continue
            image = profile.profile_image
            if image is None:
                continue
            for node in image.nodes:
                total += len(bytes(node.data or b""))
                total += sum(len(bytes(record or b"")) for record in node.records)
        return total

    def _dynamic_free_nvm(self) -> int:
        baseline = max(0, int(self.state.euicc_info.ext_card_resources.free_nvm))
        used = self._dynamic_profile_storage_bytes() + (len(self.state.profiles) * 256)
        return max(0, baseline - used)

    def _dynamic_free_ram(self) -> int:
        baseline = max(0, int(self.state.euicc_info.ext_card_resources.free_ram))
        used = (len(self.state.notifications) * 96) + (len(self.state.profiles) * 32)
        if self.state.sgp_session.session_open:
            used += 128
        return max(0, baseline - used)

    def _build_named_certificate(self, common_name: str) -> bytes:
        return self._build_self_signed_certificate(common_name=common_name)

    def _interop_asset_path(self, *parts: str) -> Path:
        if len(parts) > 0 and parts[0] == "SCP11":
            target_path = ensure_seeded_workspace_file(tuple(parts), "SCP11", *parts[1:])
            return Path(target_path)
        return Path(__file__).resolve().parents[1].joinpath(*parts)

    def _load_builtin_interop_material(self) -> None:
        certificate_der = self._load_builtin_pem_certificate_der(
            self._interop_asset_path("SCP11", "ES9_TEST_CI_CA.pem")
        )
        private_key = self._load_builtin_ec_private_key(
            self._interop_asset_path(
                "SCP11",
                "SGP.26_test_Certs",
                "Valid Test Cases",
                "Variant O",
                "CI",
                "SK_CI_SIG_NIST.pem",
            )
        )
        if len(certificate_der) == 0 or private_key is None:
            return
        try:
            certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        except Exception:
            return
        configured_root_ci = bytes(self.state.root_ci_pkid or b"")
        certificate_ski = self._certificate_subject_key_identifier(certificate)
        if len(configured_root_ci) > 0 and certificate_ski != configured_root_ci:
            return
        self._ci_certificate_der = certificate_der
        self._ci_private_key = private_key

    def _load_builtin_pem_certificate_der(self, path: Path) -> bytes:
        try:
            certificate = crypto_x509.load_pem_x509_certificate(
                read_secret_file_bytes(path, protect_plaintext_on_read=False)
            )
        except Exception:
            return b""
        return certificate.public_bytes(serialization.Encoding.DER)

    def _load_builtin_ec_private_key(self, path: Path) -> ec.EllipticCurvePrivateKey | None:
        try:
            loaded = serialization.load_pem_private_key(
                read_secret_file_bytes(path, protect_plaintext_on_read=False),
                password=None,
            )
        except Exception:
            return None
        if isinstance(loaded, ec.EllipticCurvePrivateKey) is False:
            return None
        return loaded

    @staticmethod
    def _certificate_subject_key_identifier(certificate: crypto_x509.Certificate) -> bytes:
        try:
            extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except Exception:
            return b""
        key_identifier = getattr(extension.value, "digest", None)
        if isinstance(key_identifier, bytes):
            return bytes(key_identifier)
        return b""

    @staticmethod
    def _authority_key_identifier_from_certificate(
        certificate: crypto_x509.Certificate,
    ) -> crypto_x509.AuthorityKeyIdentifier:
        try:
            ski = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            return crypto_x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except Exception:
            return crypto_x509.AuthorityKeyIdentifier.from_issuer_public_key(certificate.public_key())

    @staticmethod
    def _default_certificate_validity_window() -> tuple[datetime.datetime, datetime.datetime]:
        return (
            datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
            datetime.datetime(2039, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc),
        )

    def _ensure_default_certificate_chain(self) -> None:
        if len(bytes(self.state.eum_certificate_der or b"")) == 0:
            generated_eum = self._build_default_eum_certificate()
            if len(generated_eum) > 0:
                self.state.eum_certificate_der = generated_eum
            else:
                self.state.eum_certificate_der = self._build_named_certificate("Simulated EUM")
        if len(bytes(self.state.euicc_certificate_der or b"")) == 0:
            generated_euicc = self._build_default_euicc_certificate()
            if len(generated_euicc) > 0:
                self.state.euicc_certificate_der = generated_euicc
            else:
                self.state.euicc_certificate_der = self._build_self_signed_certificate(
                    common_name="Simulated eUICC",
                    private_key=self._euicc_private_key,
                )

    def _build_default_eum_certificate(self) -> bytes:
        if self._ci_private_key is None or self._eum_private_key is None:
            return b""
        if len(self._ci_certificate_der) == 0:
            return b""
        try:
            root_certificate = crypto_x509.load_der_x509_certificate(self._ci_certificate_der)
        except Exception:
            return b""
        eid_prefix = str(self.state.eid or "").strip().upper()[:8]
        if len(eid_prefix) != 8:
            return b""
        not_before, not_after = self._default_certificate_validity_window()
        subject = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, "EUM Test"),
            ]
        )
        builder = (
            crypto_x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_certificate.subject)
            .public_key(self._eum_private_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                self._authority_key_identifier_from_certificate(root_certificate),
                critical=False,
            )
            .add_extension(
                crypto_x509.SubjectKeyIdentifier.from_public_key(self._eum_private_key.public_key()),
                critical=False,
            )
            .add_extension(
                crypto_x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                crypto_x509.CertificatePolicies(
                    [
                        crypto_x509.PolicyInformation(
                            crypto_x509.ObjectIdentifier("2.23.146.1.2.1.2"),
                            None,
                        )
                    ]
                ),
                critical=True,
            )
            .add_extension(
                crypto_x509.NameConstraints(
                    permitted_subtrees=[
                        crypto_x509.DirectoryName(
                            crypto_x509.Name(
                                [
                                    crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
                                    crypto_x509.NameAttribute(NameOID.SERIAL_NUMBER, eid_prefix),
                                ]
                            )
                        )
                    ],
                    excluded_subtrees=None,
                ),
                critical=True,
            )
            .add_extension(
                crypto_x509.SubjectAlternativeName(
                    [crypto_x509.RegisteredID(crypto_x509.ObjectIdentifier("2.999.5"))]
                ),
                critical=False,
            )
        )
        certificate = builder.sign(self._ci_private_key, hashes.SHA256())
        return certificate.public_bytes(serialization.Encoding.DER)

    def _build_default_euicc_certificate(self) -> bytes:
        if self._eum_private_key is None:
            return b""
        eum_certificate_der = bytes(self.state.eum_certificate_der or b"")
        if len(eum_certificate_der) == 0:
            eum_certificate_der = self._build_default_eum_certificate()
            if len(eum_certificate_der) == 0:
                return b""
            self.state.eum_certificate_der = eum_certificate_der
        try:
            eum_certificate = crypto_x509.load_der_x509_certificate(eum_certificate_der)
        except Exception:
            return b""
        eid_text = str(self.state.eid or "").strip().upper()
        if len(eid_text) == 0:
            return b""
        not_before, not_after = self._default_certificate_validity_window()
        subject = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RSP Test EUM"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Test eUICC"),
                crypto_x509.NameAttribute(NameOID.SERIAL_NUMBER, eid_text),
            ]
        )
        builder = (
            crypto_x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(eum_certificate.subject)
            .public_key(self._euicc_private_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                self._authority_key_identifier_from_certificate(eum_certificate),
                critical=False,
            )
            .add_extension(
                crypto_x509.SubjectKeyIdentifier.from_public_key(self._euicc_private_key.public_key()),
                critical=False,
            )
            .add_extension(
                crypto_x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(crypto_x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                crypto_x509.CertificatePolicies(
                    [
                        crypto_x509.PolicyInformation(
                            crypto_x509.ObjectIdentifier("2.23.146.1.2.1.1"),
                            None,
                        )
                    ]
                ),
                critical=True,
            )
        )
        certificate = builder.sign(self._eum_private_key, hashes.SHA256())
        return certificate.public_bytes(serialization.Encoding.DER)

    def _sync_profile_store(self) -> None:
        store_path = str(self.state.profile_store_path or "").strip()
        if len(store_path) == 0:
            return
        try:
            sync_profiles_to_store(store_path, self.state.profiles)
        except Exception:
            return

    def _current_eum_certificate_der(self) -> bytes:
        raw = bytes(self.state.eum_certificate_der or b"")
        if len(raw) > 0:
            return raw
        generated = self._build_default_eum_certificate()
        if len(generated) == 0:
            generated = self._build_named_certificate("Simulated EUM")
        self.state.eum_certificate_der = generated
        return generated

    def _current_euicc_certificate_der(self) -> bytes:
        raw = bytes(self.state.euicc_certificate_der or b"")
        if len(raw) > 0:
            return raw
        generated = self._build_default_euicc_certificate()
        if len(generated) == 0:
            generated = self._build_self_signed_certificate(
                common_name="Simulated eUICC",
                private_key=self._euicc_private_key,
            )
        self.state.euicc_certificate_der = generated
        return generated

    def _handle_authenticate_server(self, payload: bytes) -> tuple[bytes, int, int]:
        parsed = self._parse_authenticate_server_request(payload)
        if parsed is None:
            return self._authenticate_error(0x07), 0x90, 0x00

        card_challenge = bytes(self.state.sgp_session.card_challenge)
        if len(card_challenge) == 0 or parsed["euicc_challenge"] != card_challenge:
            return self._authenticate_error(0x01), 0x90, 0x00
        validation_error = self._validate_authenticate_server_request(parsed)
        if validation_error is not None:
            return self._authenticate_error(validation_error), 0x90, 0x00

        self.state.sgp_session = SimSgpSession(
            card_challenge=card_challenge,
            transaction_id=parsed["transaction_id"],
            server_address=parsed["server_address"],
            server_challenge=parsed["server_challenge"],
            authenticate_server_request=bytes(payload),
            smdp_certificate=bytes(parsed["server_certificate_der"]),
            session_open=True,
        )
        euicc_signed1 = self._build_euicc_signed1(
            parsed["transaction_id"],
            parsed["server_address"],
            parsed["server_challenge"],
            parsed["ctx_params_raw"],
        )
        euicc_signature1 = self._raw_ecdsa_signature(self._euicc_private_key, euicc_signed1)
        self.state.sgp_session.euicc_signed1 = euicc_signed1
        self.state.sgp_session.euicc_signature1 = euicc_signature1

        response_ok = (
            euicc_signed1
            + tlv("5F37", euicc_signature1)
            + self._current_euicc_certificate_der()
            + self._current_eum_certificate_der()
        )
        response = tlv("BF38", tlv("A0", response_ok))
        self.state.sgp_session.authenticate_server_response = response
        return response, 0x90, 0x00

    def _handle_prepare_download(self, payload: bytes) -> tuple[bytes, int, int]:
        parsed = self._parse_prepare_download_request(payload)
        session = self.state.sgp_session
        if parsed is None:
            return self._prepare_download_error(0x07), 0x90, 0x00
        if session.session_open is False:
            return self._prepare_download_error(0x04), 0x90, 0x00
        if parsed["transaction_id"] != session.transaction_id:
            return self._prepare_download_error(0x05), 0x90, 0x00
        validation_error = self._validate_prepare_download_request(parsed, session)
        if validation_error is not None:
            return self._prepare_download_error(validation_error), 0x90, 0x00

        euicc_ot_private_key = ec.generate_private_key(ec.SECP256R1())
        euicc_otpk = euicc_ot_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        euicc_signed2_inner = tlv("80", session.transaction_id) + tlv("5F49", euicc_otpk)
        euicc_signed2 = tlv("30", euicc_signed2_inner)
        euicc_signature2 = self._raw_ecdsa_signature(
            self._euicc_private_key,
            euicc_signed2 + tlv("5F37", bytes(parsed["smdp_signature"])),
        )
        response = tlv("BF21", tlv("A0", euicc_signed2 + tlv("5F37", euicc_signature2)))

        session.prepare_download_request = bytes(payload)
        session.prepare_download_response = response
        session.prepare_download_done = True
        session.euicc_signed2 = euicc_signed2
        session.euicc_signature2 = euicc_signature2
        session.euicc_otpk = euicc_otpk
        session.euicc_ot_private_key = euicc_ot_private_key
        session.smdp_certificate = bytes(parsed["smdp_certificate_der"])
        return response, 0x90, 0x00

    def _handle_bpp_bootstrap(self, payload: bytes) -> tuple[bytes, int, int]:
        session = self.state.sgp_session
        session.install_command_id = self.BPP_COMMAND_IDS["bf23"]
        if session.prepare_download_done is False:
            return self._install_failure("bf23", 1), 0x90, 0x00

        bf23_raw = self._extract_bf23_bootstrap(payload)
        if len(bf23_raw) == 0:
            return self._install_failure("bf23", 7), 0x90, 0x00
        bf23_info = self._parse_bf23(bf23_raw)
        if bf23_info is None:
            return self._install_failure("bf23", 7), 0x90, 0x00
        if bf23_info["transaction_id"] != session.transaction_id:
            return self._install_failure("bf23", 13), 0x90, 0x00
        if bf23_info["remote_op_id"] != 1:
            return self._install_failure("bf23", 7), 0x90, 0x00
        key_type = bytes(bf23_info["control_ref_template"].get("keyType", b""))
        key_len = bytes(bf23_info["control_ref_template"].get("keyLen", b""))
        host_id = bytes(bf23_info["control_ref_template"].get("hostId", b""))
        smdp_otpk = bytes(bf23_info["smdp_otpk"])
        smdp_sign = bytes(bf23_info["smdp_sign"])
        if key_type != b"\x88" or key_len != b"\x10":
            return self._install_failure("bf23", 7), 0x90, 0x00
        if len(host_id) == 0 or len(host_id) > 16:
            return self._install_failure("bf23", 7), 0x90, 0x00
        if len(smdp_otpk) == 0 or len(smdp_sign) != 64:
            return self._install_failure("bf23", 7), 0x90, 0x00
        if self._verify_bf23_signature(bf23_info, session) is False:
            return self._install_failure("bf23", 8), 0x90, 0x00

        try:
            smdp_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                session.euicc_ot_private_key.curve,
                smdp_otpk,
            )
            shared_secret = session.euicc_ot_private_key.exchange(ec.ECDH(), smdp_public_key)
            session.bpp_bsp = BspInstance.from_kdf(
                shared_secret=shared_secret,
                key_type=key_type[0],
                key_length=key_len[0],
                host_id=host_id,
                eid=bytes.fromhex(self.state.eid),
            )
        except Exception:
            return self._install_failure("bf23", 8), 0x90, 0x00

        session.pending_bpp_segments = [bytes(payload)]
        session.bpp_section = ""
        session.bpp_section_remaining = -1
        session.bpp_configure_isdp_request = b""
        session.bpp_store_metadata_request = b""
        session.bpp_store_metadata = {}
        session.bpp_replace_session_keys_request = b""
        session.bpp_unprotected_profile = b""
        return b"", 0x90, 0x00

    def _extract_bf23_bootstrap(self, payload: bytes) -> bytes:
        raw = bytes(payload or b"")
        if len(raw) == 0:
            return b""
        try:
            nested = find_first_tlv(raw, "BF23")
            if len(nested) > 0:
                return nested
        except Exception:
            pass
        try:
            tag, _, header_length, _ = read_tlv_header(raw, 0)
        except Exception:
            return b""
        if tag != bytes.fromhex("BF36"):
            return b""
        truncated_value = raw[header_length:]
        try:
            child_tag, _, child_raw, _ = read_tlv(truncated_value, 0)
        except Exception:
            return b""
        if child_tag != bytes.fromhex("BF23"):
            return b""
        return child_raw

    def _handle_bpp_segment(self, payload: bytes) -> tuple[bytes, int, int]:
        session = self.state.sgp_session
        if session.prepare_download_done is False or session.bpp_bsp is None:
            return self._install_failure("bf23", 1), 0x90, 0x00
        session.pending_bpp_segments.append(bytes(payload))

        kind, section, members, declared_length = self._classify_bpp_segment(payload)
        if kind == "header":
            session.bpp_section = section
            session.bpp_section_remaining = declared_length
            session.install_command_id = self.BPP_COMMAND_IDS.get(section, session.install_command_id)
            return b"", 0x90, 0x00
        if kind == "container":
            session.bpp_section = section
            session.bpp_section_remaining = declared_length
            return self._process_bpp_members(section, members)
        if kind == "member":
            return self._process_bpp_members(section, members)
        return self._install_failure(session.bpp_section or "a3", 7), 0x90, 0x00

    def _classify_bpp_segment(self, payload: bytes) -> tuple[str, str, list[bytes], int]:
        raw = bytes(payload)
        try:
            tag, value, _, end = read_tlv(raw, 0)
            if end == len(raw):
                if tag in (b"\xA0", b"\xA1", b"\xA2", b"\xA3"):
                    return "container", self._section_from_container_tag(tag), self._split_tlv_sequence(value), len(value)
                if tag in (b"\x86", b"\x87", b"\x88"):
                    return "member", self._section_from_member_tag(tag), [raw], len(raw)
        except Exception:
            pass

        try:
            tag, length, header_length, _ = read_tlv_header(raw, 0)
            if tag in (b"\xA1", b"\xA2", b"\xA3") and header_length == len(raw):
                return "header", self._section_from_container_tag(tag), [], int(length)
        except Exception:
            pass
        return "", "", [], 0

    def _process_bpp_members(self, section: str, members: list[bytes]) -> tuple[bytes, int, int]:
        session = self.state.sgp_session
        command_id = self.BPP_COMMAND_IDS.get(section, session.install_command_id or self.BPP_COMMAND_IDS["a3"])
        session.install_command_id = command_id
        if len(members) == 0:
            return b"", 0x90, 0x00

        try:
            if section == "a0":
                plaintext = session.bpp_bsp.demac_and_decrypt(members)
                self._validate_configure_isdp_request(plaintext)
                session.bpp_configure_isdp_request = plaintext
                self._consume_bpp_section_bytes(members)
                return b"", 0x90, 0x00
            if section == "a1":
                plaintext = session.bpp_bsp.demac_only(members)
                session.bpp_store_metadata_request = plaintext
                session.bpp_store_metadata = self._parse_store_metadata_request(plaintext)
                self._consume_bpp_section_bytes(members)
                return b"", 0x90, 0x00
            if section == "a2":
                plaintext = session.bpp_bsp.demac_and_decrypt(members)
                session.bpp_replace_session_keys_request = plaintext
                replacement = self._parse_replace_session_keys_request(plaintext)
                session.bpp_bsp = BspInstance(
                    replacement["ppkEnc"],
                    replacement["ppkCmac"],
                    replacement["initialMacChainingValue"],
                )
                self._consume_bpp_section_bytes(members)
                return b"", 0x90, 0x00
            if section == "a3":
                plaintext = session.bpp_bsp.demac_and_decrypt(members)
                session.bpp_unprotected_profile += plaintext
                self._consume_bpp_section_bytes(members)
                if self._is_final_a3_chunk(plaintext):
                    profile = self._create_installed_profile_from_bpp()
                    notification = self._enqueue_notification(operation=self.NOTIF_INSTALL, profile=profile)
                    return self._profile_installation_result(
                        success=True,
                        result_code=command_id,
                        result_detail=0,
                        aid=bytes.fromhex(profile.aid),
                        seq_number=notification.seq_number,
                        operation=self.NOTIF_INSTALL,
                        iccid=profile.iccid,
                        notification_address=notification.address,
                    ), 0x90, 0x00
                return b"", 0x90, 0x00
        except BppDuplicateIccidError:
            return self._install_failure(section, 9), 0x90, 0x00
        except BppIccidMismatchError:
            return self._install_failure(section, 13), 0x90, 0x00
        except BspCryptoError:
            return self._install_failure(section, 8), 0x90, 0x00
        except ValueError:
            return self._install_failure(section, 7), 0x90, 0x00
        except Exception:
            return self._install_failure(section, 8), 0x90, 0x00
        return self._install_failure(section, 7), 0x90, 0x00

    def _consume_bpp_section_bytes(self, members: list[bytes]) -> None:
        session = self.state.sgp_session
        if session.bpp_section_remaining < 0:
            return
        session.bpp_section_remaining -= sum(len(member) for member in members)
        if session.bpp_section_remaining < 0:
            session.bpp_section_remaining = 0

    def _is_final_a3_chunk(self, plaintext: bytes) -> bool:
        session = self.state.sgp_session
        if session.bpp_section == "a3" and session.bpp_section_remaining == 0:
            return True
        if session.bpp_section == "a3" and session.bpp_section_remaining > 0:
            return False
        max_payload_size = int(getattr(session.bpp_bsp, "max_payload_size", 0) or 0)
        if session.bpp_section_remaining < 0 and max_payload_size > 0 and len(plaintext) < max_payload_size:
            return True
        return False

    def _build_notification_list_response(self, payload: bytes = b"") -> bytes:
        filter_mask = self._extract_notification_filter(payload)
        selected: list[bytes] = []
        for notification in self.state.notifications:
            op_bits = int(notification.operation or 0)
            if filter_mask is not None and (op_bits & filter_mask) == 0:
                continue
            selected.append(
                self._notification_metadata_tlv(
                    seq_number=notification.seq_number,
                    operation=op_bits,
                    iccid=notification.iccid,
                    notification_address=notification.address,
                )
            )
        if len(selected) == 0:
            return tlv("BF28", tlv("A0", b""))
        return tlv("BF28", tlv("A0", b"".join(selected)))

    @staticmethod
    def _extract_notification_filter(payload: bytes) -> int | None:
        body = bytes(payload or b"")
        if len(body) == 0 or body.startswith(bytes.fromhex("BF28")) is False:
            return None
        try:
            _, inner, _, _ = read_tlv(body, 0)
        except ValueError:
            return None
        tlv_81 = find_first_tlv(inner, "81")
        if len(tlv_81) == 0:
            return None
        try:
            _, filter_value, _, _ = read_tlv(tlv_81, 0)
        except ValueError:
            return None
        if len(filter_value) == 0:
            return None
        return int.from_bytes(filter_value, "big", signed=False)

    def _build_notification_retrieve_all_response(self) -> bytes:
        if len(self.state.notifications) == 0:
            return tlv("BF2B", b"")
        return tlv(
            "BF2B",
            tlv("A0", b"".join(notification.payload for notification in self.state.notifications)),
        )

    def _build_notification_retrieve_response(self, payload: bytes) -> bytes:
        seq_number = self._extract_notification_seq(payload)
        if seq_number is None:
            return tlv("BF2B", b"")
        for notification in self.state.notifications:
            if notification.seq_number == seq_number:
                return tlv("BF2B", tlv("A0", notification.payload))
        # SGP.32 §5.9.11: searchCriteria.seqNumber may also resolve a
        # stored eUICC Package Result. Fall through to the result list
        # so the IPA receives the matching ``A2`` body if it exists.
        for entry in self.state.euicc_package_results:
            if entry.seq_number == seq_number:
                return tlv("BF2B", tlv("A2", bytes(entry.payload)))
        return tlv("BF2B", b"")

    def _build_euicc_package_result_list_response(self) -> bytes:
        if len(self.state.euicc_package_results) == 0:
            return tlv("BF2B", b"")
        # SGP.32 §2.11.2 EuiccPackageResultList = SEQUENCE OF
        # EuiccPackageResult. Each stored payload already includes the
        # signed body wrapped in the ``A0`` (euiccPackageResultSigned)
        # alternative, so a simple concatenation under ``A2`` is the
        # correct list shape.
        body = b"".join(bytes(entry.payload) for entry in self.state.euicc_package_results)
        return tlv("BF2B", tlv("A2", body))

    # ------------------------------------------------------------------
    # SGP.32 §5.9.1 ES10b.LoadEuiccPackage / §2.11.1.1 EuiccPackageRequest
    # ------------------------------------------------------------------

    def _handle_load_euicc_package(self, payload: bytes) -> tuple[bytes, int, int]:
        """Verify and execute an ``EuiccPackageRequest`` (BF51).

        Verification ladder per SGP.32 v1.2 §5.9.1:

        1. Look up the targeted eIM by ``eimId``. Unknown eIM →
           ``euiccPackageErrorUnsigned``.
        2. Verify the ``5F37`` ECDSA r||s over
           ``euiccPackageSigned || associationToken``. Bad signature →
           ``euiccPackageErrorUnsigned``.
        3. Verify ``eidValue`` matches the eUICC's own EID. Mismatch →
           ``euiccPackageErrorSigned`` with ``invalidEid(3)``.
        4. Verify ``counterValue`` is strictly greater than the stored
           per-eIM counter and not above ``0x7FFFFF``. Replay or overflow
           → ``euiccPackageErrorSigned`` with ``replayError(4)`` or
           ``counterValueOutOfRange(6)``.
        5. Execute the inner ``psmoList`` / ``ecoList`` sequentially,
           emitting one ``EuiccResultData`` per element. Errors abort the
           remainder with ``processingTerminated``.
        6. Sign the result, persist into ``state.euicc_package_results``,
           and advance the per-eIM counter and the global notification /
           result sequence number.
        """

        try:
            envelope = decode_euicc_package_request(payload)
        except EuiccPackageDecodeError:
            # Malformed packages cannot identify the eIM. The IPA gets a
            # plain unsigned error result with no eimId so it can drop
            # the package without retrying.
            return (
                encode_euicc_package_error_unsigned(eim_id=""),
                0x90,
                0x00,
            )

        eim_entry = self._find_eim_entry(envelope.eim_id)
        if eim_entry is None or len(eim_entry.eim_public_key_data or b"") == 0:
            return (
                encode_euicc_package_error_unsigned(
                    eim_id=envelope.eim_id,
                    eim_transaction_id=envelope.eim_transaction_id,
                ),
                0x90,
                0x00,
            )

        association_token = max(0, int(eim_entry.association_token or 0))
        token_for_signature = association_token if association_token > 0 else 0
        signature_ok = verify_eim_signature(
            public_key_payload=bytes(eim_entry.eim_public_key_data),
            signed_blob=envelope.signed_blob,
            signature_rs=envelope.eim_signature,
            association_token=token_for_signature,
        )
        if signature_ok is False:
            include_token = association_token if association_token > 0 else None
            return (
                encode_euicc_package_error_unsigned(
                    eim_id=envelope.eim_id,
                    eim_transaction_id=envelope.eim_transaction_id,
                    association_token=include_token,
                ),
                0x90,
                0x00,
            )

        own_eid_bytes = self._eid_bytes()
        if len(envelope.eid_value) != 16 or envelope.eid_value != own_eid_bytes:
            return (
                self._sign_package_error(
                    envelope=envelope,
                    error_code=3,
                    association_token=token_for_signature,
                ),
                0x90,
                0x00,
            )

        if envelope.counter_value > 0x7FFFFF:
            return (
                self._sign_package_error(
                    envelope=envelope,
                    error_code=6,
                    association_token=token_for_signature,
                ),
                0x90,
                0x00,
            )
        if envelope.counter_value <= int(eim_entry.counter_value or 0):
            return (
                self._sign_package_error(
                    envelope=envelope,
                    error_code=4,
                    association_token=token_for_signature,
                ),
                0x90,
                0x00,
            )

        result_items = self._execute_euicc_package(envelope)
        seq_number = self._allocate_package_result_seq_number()
        outer_tlv, payload_tlv = encode_euicc_package_result_signed(
            eim_id=envelope.eim_id,
            counter_value=envelope.counter_value,
            seq_number=seq_number,
            euicc_results=result_items,
            eim_transaction_id=envelope.eim_transaction_id,
            private_key=self._euicc_private_key,
            association_token=token_for_signature,
        )

        eim_entry.counter_value = int(envelope.counter_value)
        self.state.euicc_package_results.append(
            SimEuiccPackageResultEntry(
                seq_number=seq_number,
                eim_id=envelope.eim_id,
                counter_value=int(envelope.counter_value),
                eim_transaction_id=bytes(envelope.eim_transaction_id),
                payload=bytes(payload_tlv),
            )
        )
        self._sync_euicc_store()
        return outer_tlv, 0x90, 0x00

    def _sign_package_error(
        self,
        *,
        envelope,
        error_code: int,
        association_token: int,
    ) -> bytes:
        return encode_euicc_package_error_signed(
            eim_id=envelope.eim_id,
            counter_value=envelope.counter_value,
            error_code=error_code,
            eim_transaction_id=envelope.eim_transaction_id,
            private_key=self._euicc_private_key,
            association_token=association_token,
        )

    def _allocate_package_result_seq_number(self) -> int:
        seq_number = int(self.state.next_notification_seq or 1)
        if seq_number < 1:
            seq_number = 1
        self.state.next_notification_seq = seq_number + 1
        return seq_number

    def _eid_bytes(self) -> bytes:
        eid_text = str(self.state.eid or "").strip().upper()
        try:
            raw = bytes.fromhex(eid_text)
        except ValueError:
            raw = b""
        return raw

    def _find_eim_entry(self, eim_id: str) -> SimEimEntry | None:
        normalized = self._normalize_eim_identifier(eim_id)
        if len(normalized) == 0:
            return None
        for entry in self.state.eim_entries:
            if self._normalize_eim_identifier(entry.eim_id) == normalized:
                return entry
        return None

    def _execute_euicc_package(self, envelope) -> list[bytes]:
        """Run ``Psmo`` / ``Eco`` items sequentially per §5.9.1.

        On the first per-element failure the eUICC stops processing and
        appends a final ``processingTerminated`` ``EuiccResultData`` so
        the eIM can correlate. Each element-level helper returns the
        already-encoded ``EuiccResultData`` TLV (e.g. ``83 01 00`` for
        an ``ok`` enable).

        The package-level constraints from §2.11.1.1 are enforced before
        execution begins:

        - ``At most one enable command SHALL occur in an eUICC Package.``
        - ``At most one disable command SHALL occur in an eUICC Package.``
        - ``A listProfileInfo command SHALL NOT occur after an enable,
          disable or delete command.`` Violation -> the matching
          ``listProfileInfoResult`` element is emitted with
          ``profileChangeOngoing(11)`` and the package is aborted with
          ``processingTerminated``.
        """

        results: list[bytes] = []
        items: list[tuple[str, bytes]] = []
        if envelope.has_psmo_list:
            for raw in envelope.psmo_items:
                items.append(("psmo", raw))
        else:
            for raw in envelope.eco_items:
                items.append(("eco", raw))

        if envelope.has_psmo_list:
            constraint_result = self._psmo_package_constraint_violation(items)
            if constraint_result is not None:
                violation_tlv, abort = constraint_result
                if violation_tlv is not None:
                    results.append(violation_tlv)
                if abort is True:
                    results.append(self._processing_terminated(2))
                    return results

        enable_or_disable_or_delete_seen = False
        for kind, raw in items:
            if kind == "psmo":
                tag_bytes = self._peek_psmo_tag(raw)
                if (
                    tag_bytes == bytes.fromhex("BF2D")
                    and enable_or_disable_or_delete_seen is True
                ):
                    # listProfileInfoResult [45] BF2D with
                    # ProfileInfoListError ::= INTEGER {profileChangeOngoing(11)}.
                    # The listProfileInfoError alternative is encoded as a
                    # primitive INTEGER (no inner context tag).
                    results.append(
                        tlv(
                            bytes.fromhex("BF2D"),
                            tlv(b"\x02", encode_der_integer(11)),
                        )
                    )
                    results.append(self._processing_terminated(2))
                    return results
                if tag_bytes in (b"\xA3", b"\xA4", b"\xA5"):
                    enable_or_disable_or_delete_seen = True
            try:
                if kind == "psmo":
                    result_tlv = self._execute_psmo(raw)
                else:
                    result_tlv = self._execute_eco(raw)
            except Exception:
                # SGP.32 §5.9.1: when execution of a PSMO/eCO fails the
                # eUICC SHALL terminate processing of the remainder and
                # emit a final ``processingTerminated`` element. The
                # 2 ``unknownOrDamagedCommand`` value matches the spec
                # description for malformed inner data.
                results.append(self._processing_terminated(2))
                return results
            results.append(result_tlv)
        return results

    @staticmethod
    def _peek_psmo_tag(raw: bytes) -> bytes:
        try:
            tag_bytes, _value, _raw_tlv, _next = read_tlv(bytes(raw or b""), 0)
        except ValueError:
            return b""
        return tag_bytes

    def _psmo_package_constraint_violation(
        self,
        items: list[tuple[str, bytes]],
    ) -> tuple[bytes | None, bool] | None:
        """Return ``(violation_tlv, abort)`` if the PSMO list breaks the
        ``at most one enable`` / ``at most one disable`` rule. ``abort``
        signals that processing must terminate without running the rest
        of the package.
        """

        enable_count = 0
        disable_count = 0
        for kind, raw in items:
            if kind != "psmo":
                continue
            tag_bytes = self._peek_psmo_tag(raw)
            if tag_bytes == b"\xA3":
                enable_count += 1
            elif tag_bytes == b"\xA4":
                disable_count += 1
        if enable_count > 1:
            # commandError(7) is the closest defined value for an
            # over-count enable in EnableProfileResult.
            return (tlv(b"\x83", encode_der_integer(127)), True)
        if disable_count > 1:
            return (tlv(b"\x84", encode_der_integer(127)), True)
        return None

    @staticmethod
    def _processing_terminated(code: int) -> bytes:
        # processingTerminated INTEGER (CHOICE alternative without an
        # explicit context tag). Per §2.11.2.1 the documented values are
        # 1 resultSizeOverflow, 2 unknownOrDamagedCommand, 3 interruption,
        # 127 undefinedError. Encoded as a primitive INTEGER (tag 02).
        return tlv(b"\x02", encode_der_integer(int(code) & 0xFF))

    # -- PSMO ----------------------------------------------------------

    def _execute_psmo(self, raw: bytes) -> bytes:
        try:
            tag_bytes, body, _raw_tlv, _next = read_tlv(raw, 0)
        except ValueError:
            return self._processing_terminated(2)

        if tag_bytes == b"\xA3":
            return self._psmo_enable(body)
        if tag_bytes == b"\xA4":
            return self._psmo_disable(body)
        if tag_bytes == b"\xA5":
            return self._psmo_delete(body)
        if tag_bytes == bytes.fromhex("BF2D"):
            return tlv(
                bytes.fromhex("BF2D"),
                tlv("A0", b""),
            ) if len(self.state.profiles) == 0 else self._psmo_list_profile_info()
        if tag_bytes == b"\xA6":
            return tlv(b"\xA6", b"")
        if tag_bytes == b"\xA7":
            return self._psmo_configure_immediate_enable(body)
        if tag_bytes == b"\xA8":
            return self._psmo_set_fallback_attribute(body)
        if tag_bytes == b"\xA9":
            return self._psmo_unset_fallback_attribute()
        if tag_bytes == bytes.fromhex("BF65"):
            return self._psmo_set_default_dp_address(body)
        return self._processing_terminated(2)

    def _psmo_enable(self, body: bytes) -> bytes:
        profile = self._resolve_profile_reference(body)
        if profile is None:
            return tlv(b"\x83", encode_der_integer(1))  # iccidOrAidNotFound
        # SGP.32 §2.11.1.1: enable SEQUENCE { iccid, rollbackFlag NULL OPTIONAL }.
        # The rollbackFlag is a primitive NULL with the auto-tag [1] -> 0x81.
        rollback_requested = self._enable_rollback_requested(body)
        if str(profile.state).strip().lower() != "disabled":
            # SGP.32 EnableProfileResult code 2 covers "profileNotInDisabledState".
            # The simulator treats already-enabled profiles as a no-op success
            # because real cards seen in the field also report ok(0) for the
            # idempotent case; tighten with caution if a strict-mode test
            # demands the spec-literal rejection.
            if str(profile.state).strip().lower() != "enabled":
                return tlv(b"\x83", encode_der_integer(2))
            return tlv(b"\x83", encode_der_integer(0))
        previous_enabled_aid = ""
        for current in self.state.profiles:
            if current is profile:
                current.state = "enabled"
            elif current.state == "enabled":
                if len(previous_enabled_aid) == 0:
                    previous_enabled_aid = str(current.aid or "")
                current.state = "disabled"
            current.rollback_armed = False
        if rollback_requested is True:
            profile.rollback_armed = True
            self.state.previous_enabled_aid = previous_enabled_aid
        else:
            self.state.previous_enabled_aid = ""
        self.state.active_profile_aid = profile.aid
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=self.NOTIF_ENABLE, profile=profile)
        return tlv(b"\x83", encode_der_integer(0))

    @staticmethod
    def _enable_rollback_requested(body: bytes) -> bool:
        offset = 0
        while offset < len(body):
            try:
                tag_bytes, _value, _raw, next_offset = read_tlv(bytes(body), offset)
            except ValueError:
                return False
            if tag_bytes == b"\x81":
                return True
            offset = next_offset
        return False

    def _psmo_disable(self, body: bytes) -> bytes:
        profile = self._resolve_profile_reference(body)
        if profile is None:
            return tlv(b"\x84", encode_der_integer(1))
        if str(profile.state).strip().lower() != "enabled":
            return tlv(b"\x84", encode_der_integer(2))
        profile.state = "disabled"
        if self.state.active_profile_aid.upper() == profile.aid.upper():
            self.state.active_profile_aid = ""
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        self._enqueue_notification(operation=self.NOTIF_DISABLE, profile=profile)
        return tlv(b"\x84", encode_der_integer(0))

    def _psmo_delete(self, body: bytes) -> bytes:
        profile = self._resolve_profile_reference(body)
        if profile is None:
            return tlv(b"\x85", encode_der_integer(1))
        if str(profile.state).strip().lower() not in ("disabled", "deleted"):
            return tlv(b"\x85", encode_der_integer(2))
        self._enqueue_notification(operation=self.NOTIF_DELETE, profile=profile)
        if self.state.active_profile_aid.upper() == profile.aid.upper():
            self.state.active_profile_aid = ""
        self.state.profiles = [
            current for current in self.state.profiles if current.aid.upper() != profile.aid.upper()
        ]
        rebuild_runtime_filesystem(self.state)
        self._sync_profile_store()
        return tlv(b"\x85", encode_der_integer(0))

    def _psmo_list_profile_info(self) -> bytes:
        # Reuse the existing ES10b.GetProfilesInfo response body. The
        # outer tag (BF2D) already matches the listProfileInfoResult
        # alternative in EuiccResultData.
        return self._build_profiles_info_response()

    def _psmo_configure_immediate_enable(self, body: bytes) -> bytes:
        # SGP.32 §2.11.1.1 configureImmediateEnable [7] SEQUENCE {
        #     immediateEnableFlag [0] NULL OPTIONAL,
        #     defaultSmdpOid [1] OBJECT IDENTIFIER OPTIONAL,
        #     defaultSmdpAddress [2] UTF8String OPTIONAL
        # }
        # ConfigureImmediateEnableResult is INTEGER tagged [7] -> primitive 0x87.
        new_flag: bool | None = None
        new_oid: str | None = None
        new_address: str | None = None
        offset = 0
        while offset < len(body):
            try:
                tag_bytes, value, _raw, next_offset = read_tlv(bytes(body), offset)
            except ValueError:
                return tlv(b"\x87", encode_der_integer(7))  # commandError
            if tag_bytes == b"\x80":
                new_flag = True
            elif tag_bytes == b"\x81":
                new_oid = self._format_oid(value)
            elif tag_bytes == b"\x82":
                try:
                    new_address = bytes(value).decode("utf-8", "strict").strip()
                except UnicodeDecodeError:
                    return tlv(b"\x87", encode_der_integer(7))
            offset = next_offset
        if new_flag is True:
            self.state.immediate_enable_flag = True
        else:
            self.state.immediate_enable_flag = False
        if new_oid is not None:
            self.state.immediate_enable_smdp_oid = new_oid
        if new_address is not None:
            self.state.immediate_enable_smdp_address = new_address
        self._sync_euicc_store()
        return tlv(b"\x87", encode_der_integer(0))

    @staticmethod
    def _format_oid(payload: bytes) -> str:
        raw = bytes(payload or b"")
        if len(raw) == 0:
            return ""
        first = raw[0]
        components: list[int] = [first // 40, first % 40]
        index = 1
        while index < len(raw):
            value = 0
            while index < len(raw):
                byte = raw[index]
                value = (value << 7) | (byte & 0x7F)
                index += 1
                if byte & 0x80 == 0:
                    break
            components.append(value)
        return ".".join(str(component) for component in components)

    def _psmo_set_fallback_attribute(self, body: bytes) -> bytes:
        # SetFallbackAttributeResult ::= INTEGER {
        #     ok(0), iccidOrAidNotFound(1), fallbackNotAllowed(2),
        #     fallbackProfileEnabled(3), undefinedError(127) }
        if bool(self.state.euicc_info.iot_specific_info.fallback_supported) is False:
            return tlv(b"\x8D", encode_der_integer(2))  # fallbackNotAllowed
        profile = self._resolve_profile_reference(body)
        if profile is None:
            return tlv(b"\x8D", encode_der_integer(1))
        if any(
            entry.fallback_attribute is True and entry.state == "enabled"
            for entry in self.state.profiles
        ):
            return tlv(b"\x8D", encode_der_integer(3))  # fallbackProfileEnabled
        for entry in self.state.profiles:
            entry.fallback_attribute = False
        profile.fallback_attribute = True
        self._sync_profile_store()
        return tlv(b"\x8D", encode_der_integer(0))

    def _psmo_unset_fallback_attribute(self) -> bytes:
        # UnsetFallbackAttributeResult ::= INTEGER {
        #     ok(0), noFallbackAttribute(2), fallbackProfileEnabled(3),
        #     commandError(7), undefinedError(127) }
        marked = [entry for entry in self.state.profiles if entry.fallback_attribute is True]
        if len(marked) == 0:
            return tlv(b"\x8E", encode_der_integer(2))  # noFallbackAttribute
        if any(entry.state == "enabled" for entry in marked):
            return tlv(b"\x8E", encode_der_integer(3))  # fallbackProfileEnabled
        for entry in marked:
            entry.fallback_attribute = False
        self._sync_profile_store()
        return tlv(b"\x8E", encode_der_integer(0))

    def _psmo_set_default_dp_address(self, body: bytes) -> bytes:
        address_raw = find_first_tlv(body, "80")
        if len(address_raw) == 0:
            return tlv(bytes.fromhex("BF65"), tlv("80", encode_der_integer(1)))
        try:
            _tag, address_value, _raw, _next = read_tlv(address_raw, 0)
        except ValueError:
            return tlv(bytes.fromhex("BF65"), tlv("80", encode_der_integer(1)))
        try:
            address_text = bytes(address_value).decode("utf-8", "strict").strip()
        except UnicodeDecodeError:
            return tlv(bytes.fromhex("BF65"), tlv("80", encode_der_integer(1)))
        if len(address_text) > 128:
            return tlv(bytes.fromhex("BF65"), tlv("80", encode_der_integer(1)))
        self.state.default_dp_address = address_text
        self._sync_euicc_store()
        return tlv(bytes.fromhex("BF65"), tlv("80", encode_der_integer(0)))

    # -- eCO -----------------------------------------------------------

    def _execute_eco(self, raw: bytes) -> bytes:
        try:
            tag_bytes, body, _raw_tlv, _next = read_tlv(raw, 0)
        except ValueError:
            return self._processing_terminated(2)

        if tag_bytes == b"\xA8":
            return self._eco_add_eim(body)
        if tag_bytes == b"\xA9":
            return self._eco_delete_eim(body)
        if tag_bytes == b"\xAA":
            return self._eco_update_eim(body)
        if tag_bytes == b"\xAB":
            return self._eco_list_eim()
        return self._processing_terminated(2)

    def _eco_add_eim(self, body: bytes) -> bytes:
        wrapped = tlv("BF57", tlv("A0", tlv("30", body)))
        entries = self._parse_add_eim_entries(wrapped)
        if len(entries) == 0:
            return tlv(b"\xA8", tlv(b"\x02", encode_der_integer(7)))
        new_entry = entries[0]
        association_request = self._extract_association_token_request(body)
        if association_request is not None and association_request < 0:
            allocated = self._allocate_association_token()
            new_entry.association_token = allocated
        existing = self._find_eim_entry(new_entry.eim_id)
        if existing is not None:
            return tlv(b"\xA8", tlv(b"\x02", encode_der_integer(2)))  # associatedEimAlreadyExists
        self._upsert_eim_entries([new_entry])
        self._ensure_metadata_defaults()
        self._sync_euicc_store()
        if new_entry.association_token > 0:
            return tlv(
                b"\xA8",
                tlv(b"\x84", encode_der_integer(int(new_entry.association_token))),
            )
        return tlv(b"\xA8", tlv(b"\x02", encode_der_integer(0)))

    def _eco_delete_eim(self, body: bytes) -> bytes:
        # SGP.32 §2.11.2.1 EuiccResultData ::= CHOICE {
        #     ..., deleteEimResult [9] DeleteEimResult, ... }
        # DeleteEimResult ::= INTEGER {...}. AUTOMATIC TAGS keeps the
        # natural primitive form for INTEGER, so the alternative is
        # encoded as the *primitive* context-specific tag 0x89, NOT the
        # constructed 0xA9 used by the eCO command-side tag of the
        # same number.
        eim_id_raw = find_first_tlv(body, "80")
        if len(eim_id_raw) == 0:
            return tlv(b"\x89", encode_der_integer(7))
        try:
            _tag, eim_id_value, _raw, _next = read_tlv(eim_id_raw, 0)
        except ValueError:
            return tlv(b"\x89", encode_der_integer(7))
        target = self._decode_text_field(eim_id_value)
        if len(target) == 0:
            return tlv(b"\x89", encode_der_integer(7))
        normalized_target = self._normalize_eim_identifier(target)
        retained = [
            entry
            for entry in self.state.eim_entries
            if self._normalize_eim_identifier(entry.eim_id) != normalized_target
        ]
        if len(retained) == len(self.state.eim_entries):
            return tlv(b"\x89", encode_der_integer(1))  # eimNotFound
        self.state.eim_entries = retained
        self._sync_euicc_store()
        if len(self.state.eim_entries) == 0:
            return tlv(b"\x89", encode_der_integer(2))  # lastEimDeleted
        return tlv(b"\x89", encode_der_integer(0))

    def _eco_update_eim(self, body: bytes) -> bytes:
        # SGP.32 §2.11.2.1 EuiccResultData updateEimResult [10] UpdateEimResult.
        # UpdateEimResult ::= INTEGER, so AUTOMATIC TAGS yields the
        # primitive context tag 0x8A. The constructed 0xAA seen on the
        # eCO command side is unrelated.
        wrapped = tlv("BF58", tlv("A0", tlv("30", body)))
        entries = self._parse_add_eim_entries(wrapped)
        if len(entries) == 0:
            return tlv(b"\x8A", encode_der_integer(7))
        update = entries[0]
        existing = self._find_eim_entry(update.eim_id)
        if existing is None:
            return tlv(b"\x8A", encode_der_integer(1))  # eimNotFound
        if int(update.counter_value or 0) < int(existing.counter_value or 0) and len(update.eim_public_key_data or b"") == 0:
            return tlv(b"\x8A", encode_der_integer(6))  # counterValueOutOfRange
        self._upsert_eim_entries([update])
        self._sync_euicc_store()
        return tlv(b"\x8A", encode_der_integer(0))

    def _eco_list_eim(self) -> bytes:
        eim_id_list = b""
        for entry in self.state.eim_entries:
            row = tlv(b"\x80", str(entry.eim_id or "").encode("utf-8"))
            if int(entry.eim_id_type or 0) > 0:
                row += tlv(b"\x82", encode_der_integer(int(entry.eim_id_type)))
            eim_id_list += tlv(b"\x30", row)
        return tlv(b"\xAB", tlv(b"\x30", eim_id_list))

    def _extract_association_token_request(self, body: bytes) -> int | None:
        token_raw = find_first_tlv(body, "84")
        if len(token_raw) == 0:
            return None
        try:
            _tag, value, _raw, _next = read_tlv(token_raw, 0)
        except ValueError:
            return None
        if len(value) == 0:
            return 0
        return int.from_bytes(value, "big", signed=True)

    def _allocate_association_token(self) -> int:
        next_token = int(self.state.association_token_counter or 0) + 1
        self.state.association_token_counter = next_token
        return next_token



    def _remove_notification_from_list(self, payload: bytes) -> bytes:
        seq_number = self._extract_notification_seq(payload)
        if seq_number is None:
            return tlv("BF30", b"")
        before_notifications = len(self.state.notifications)
        self.state.notifications = [
            notification for notification in self.state.notifications if notification.seq_number != seq_number
        ]
        before_results = len(self.state.euicc_package_results)
        self.state.euicc_package_results = [
            entry for entry in self.state.euicc_package_results if entry.seq_number != seq_number
        ]
        if (
            len(self.state.notifications) != before_notifications
            or len(self.state.euicc_package_results) != before_results
        ):
            self._sync_euicc_store()
        return tlv("BF30", b"")

    def _extract_notification_seq(self, payload: bytes) -> int | None:
        seq_raw = find_first_tlv(payload, "80")
        if len(seq_raw) == 0:
            return None
        _, seq_value, _, _ = read_tlv(seq_raw, 0)
        if len(seq_value) == 0:
            return None
        return int.from_bytes(seq_value, "big", signed=False)

    def _default_notification_address(self) -> str:
        session_address = str(self.state.sgp_session.server_address or "").strip()
        if len(session_address) > 0:
            return session_address
        return str(self.state.default_dp_address or "").strip()

    def _notification_metadata_tlv(
        self,
        *,
        seq_number: int,
        operation: int,
        iccid: str = "",
        notification_address: str = "",
    ) -> bytes:
        profile_iccid = iccid or self.state.iccid
        profile_notification_address = (
            str(notification_address or "").strip() or self._default_notification_address()
        )
        return tlv(
            "BF2F",
            tlv("80", self._encode_notification_seq(seq_number))
            + tlv("81", bytes([operation & 0xFF]))
            + tlv("0C", profile_notification_address.encode("utf-8"))
            + tlv("5A", encode_iccid_ef(profile_iccid)),
        )

    def _enqueue_notification(self, operation: int, profile: SimProfileEntry) -> SimNotificationEntry:
        seq_number = int(self.state.next_notification_seq)
        self.state.next_notification_seq += 1
        notification_address = (
            str(profile.notification_address or "").strip() or self._default_notification_address()
        )
        payload = self._profile_installation_result(
            success=True,
            result_code=0,
            result_detail=0,
            aid=bytes.fromhex(profile.aid),
            seq_number=seq_number,
            operation=operation,
            iccid=profile.iccid,
            notification_address=notification_address,
        )
        self.state.notifications.append(
            SimNotificationEntry(
                seq_number=seq_number,
                operation=operation,
                address=notification_address,
                iccid=profile.iccid,
                aid=profile.aid,
                payload=payload,
            )
        )
        return self.state.notifications[-1]

    def _profile_installation_result(
        self,
        *,
        success: bool,
        result_code: int,
        result_detail: int,
        aid: bytes = b"",
        seq_number: int | None = None,
        operation: int = 0,
        iccid: str = "",
        notification_address: str = "",
    ) -> bytes:
        session = self.state.sgp_session
        metadata = b""
        if seq_number is not None:
            metadata = self._notification_metadata_tlv(
                seq_number=seq_number,
                operation=operation,
                iccid=iccid,
                notification_address=notification_address,
            )
        final_tag = "A0" if success else "A1"
        final_result = tlv(
            final_tag,
            tlv("80", bytes([result_code & 0xFF]))
            + tlv("81", bytes([result_detail & 0xFF]))
            + (tlv("4F", aid) if len(aid) > 0 else b""),
        )
        inner = (
            tlv("80", bytes(session.transaction_id))
            + metadata
            + tlv("06", bytes.fromhex("88370A"))
            + tlv("A2", final_result)
            + tlv("5F37", self._signature_blob(b"PIR", bytes(session.transaction_id), aid))
        )
        return tlv("BF37", tlv("BF27", inner))

    @staticmethod
    def _encode_notification_seq(seq_number: int) -> bytes:
        if seq_number <= 0xFF:
            return seq_number.to_bytes(1, "big")
        if seq_number <= 0xFFFF:
            return seq_number.to_bytes(2, "big")
        return seq_number.to_bytes(4, "big")

    def _authenticate_error(self, error_code: int) -> bytes:
        return tlv("BF38", tlv("A1", tlv("80", bytes([error_code & 0xFF]))))

    def _prepare_download_error(self, error_code: int) -> bytes:
        return tlv("BF21", tlv("A1", tlv("80", bytes([error_code & 0xFF]))))

    def _install_failure(self, command: str, detail: int) -> bytes:
        result_code = self.BPP_COMMAND_IDS.get(str(command), self.state.sgp_session.install_command_id or 1)
        return self._profile_installation_result(success=False, result_code=result_code, result_detail=detail)

    @staticmethod
    def _cancel_session_response_error(reason_code: int) -> bytes:
        return tlv("BF41", tlv("81", bytes([reason_code & 0xFF])))

    def _parse_authenticate_server_request(self, payload: bytes) -> dict[str, bytes | str] | None:
        try:
            root_tag, root_value, _, _ = read_tlv(payload, 0)
            if root_tag != bytes.fromhex("BF38"):
                return None
            first_tag, first_value, first_raw, offset = read_tlv(root_value, 0)
            if first_tag != b"\x30":
                return None
            transaction_id = b""
            euicc_challenge = b""
            server_address = ""
            server_challenge = b""
            inner_offset = 0
            while inner_offset < len(first_value):
                field_tag, field_value, _, next_offset = read_tlv(first_value, inner_offset)
                if field_tag == b"\x80":
                    transaction_id = field_value
                elif field_tag == b"\x81":
                    euicc_challenge = field_value
                elif field_tag == b"\x83":
                    server_address = field_value.decode("utf-8", "ignore")
                elif field_tag == b"\x84":
                    server_challenge = field_value
                inner_offset = next_offset
            ctx_params_raw = b""
            server_signature = b""
            root_ci_id = b""
            server_certificate_der = b""
            while offset < len(root_value):
                field_tag, field_value, field_raw, next_offset = read_tlv(root_value, offset)
                if field_tag == bytes.fromhex("5F37"):
                    server_signature = field_value
                elif field_tag == b"\x04":
                    root_ci_id = field_value
                elif field_tag == b"\x30" and len(server_certificate_der) == 0:
                    server_certificate_der = field_raw
                else:
                    ctx_params_raw = field_raw
                offset = next_offset
            if len(transaction_id) == 0 or len(euicc_challenge) == 0:
                return None
            return {
                "transaction_id": transaction_id,
                "euicc_challenge": euicc_challenge,
                "server_address": server_address,
                "server_challenge": server_challenge,
                "ctx_params_raw": ctx_params_raw,
                "server_signed1_raw": first_raw,
                "server_signature": server_signature,
                "root_ci_id": root_ci_id,
                "server_certificate_der": server_certificate_der,
            }
        except Exception:
            return None

    def _validate_authenticate_server_request(self, parsed: dict[str, bytes | str]) -> int | None:
        certificate_der = bytes(parsed.get("server_certificate_der", b""))
        if len(certificate_der) == 0:
            return 0x02
        raw_signature = bytes(parsed.get("server_signature", b""))
        if len(raw_signature) != 64:
            return 0x03
        try:
            certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        except Exception:
            return 0x02

        root_ci_id = bytes(parsed.get("root_ci_id", b""))
        configured_ci_pkids = self._configured_ci_pkids()
        if len(root_ci_id) > 0 and root_ci_id not in configured_ci_pkids:
            return 0x02
        authority_key_id = self._certificate_authority_key_identifier(certificate)
        if len(root_ci_id) > 0 and len(authority_key_id) > 0 and authority_key_id != root_ci_id:
            return 0x02
        if len(root_ci_id) == 0 and len(authority_key_id) > 0 and authority_key_id not in configured_ci_pkids:
            return 0x02

        der_signature = asym_utils.encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big", signed=False),
            int.from_bytes(raw_signature[32:], "big", signed=False),
        )
        try:
            certificate.public_key().verify(
                der_signature,
                bytes(parsed.get("server_signed1_raw", b"")),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:
            return 0x03
        return None

    @staticmethod
    def _certificate_authority_key_identifier(certificate: crypto_x509.Certificate) -> bytes:
        try:
            extension = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except Exception:
            return b""
        key_identifier = getattr(extension.value, "key_identifier", None)
        if isinstance(key_identifier, bytes):
            return bytes(key_identifier)
        return b""

    @staticmethod
    def _certificate_name_text(name: Any) -> str:
        try:
            return str(name.rfc4514_string() or "").strip()
        except Exception:
            return ""

    @staticmethod
    def _certificate_name_identity(name: Any, fields: tuple[Any, ...]) -> tuple[tuple[str, str], ...]:
        rows: list[tuple[str, str]] = []
        try:
            for oid in fields:
                values = [str(attribute.value).strip() for attribute in name.get_attributes_for_oid(oid)]
                for value in values:
                    if len(value) > 0:
                        rows.append((oid.dotted_string, value))
        except Exception:
            return ()
        return tuple(rows)

    def _parse_prepare_download_request(self, payload: bytes) -> dict[str, bytes] | None:
        try:
            root_tag, root_value, _, _ = read_tlv(payload, 0)
            if root_tag != bytes.fromhex("BF21"):
                return None
            transaction_id = b""
            smdp_signed2_raw = b""
            smdp_signature = b""
            smdp_certificate_der = b""
            sequence_count = 0
            offset = 0
            while offset < len(root_value):
                field_tag, field_value, field_raw, next_offset = read_tlv(root_value, offset)
                if field_tag == b"\x30":
                    sequence_count += 1
                    if sequence_count == 1:
                        smdp_signed2_raw = field_raw
                        inner_offset = 0
                        while inner_offset < len(field_value):
                            inner_tag, inner_value, _, inner_next = read_tlv(field_value, inner_offset)
                            if inner_tag == b"\x80":
                                transaction_id = inner_value
                            inner_offset = inner_next
                    elif sequence_count == 2 and len(smdp_certificate_der) == 0:
                        smdp_certificate_der = field_raw
                elif field_tag == bytes.fromhex("5F37"):
                    smdp_signature = field_value
                offset = next_offset
            if len(transaction_id) == 0:
                return None
            return {
                "transaction_id": transaction_id,
                "smdp_signed2_raw": smdp_signed2_raw,
                "smdp_signature": smdp_signature,
                "smdp_certificate_der": smdp_certificate_der,
            }
        except Exception:
            return None

    def _validate_prepare_download_request(
        self,
        parsed: dict[str, bytes],
        session: SimSgpSession,
    ) -> int | None:
        certificate_der = bytes(parsed.get("smdp_certificate_der", b""))
        if len(certificate_der) == 0:
            return 0x01

        raw_signature = bytes(parsed.get("smdp_signature", b""))
        if len(raw_signature) != 64:
            return 0x02
        smdp_signed2_raw = bytes(parsed.get("smdp_signed2_raw", b""))
        if len(smdp_signed2_raw) == 0:
            return 0x02
        euicc_signature1 = bytes(session.euicc_signature1 or b"")
        if len(euicc_signature1) != 64:
            return 0x02

        try:
            certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        except Exception:
            return 0x01
        if self._prepare_download_certificate_continuation_valid(certificate_der, certificate, session) is False:
            return 0x01
        public_key = certificate.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey) is False:
            return 0x03
        curve_name = str(getattr(getattr(public_key, "curve", None), "name", "") or "").lower()
        if curve_name not in ("secp256r1", "prime256v1"):
            return 0x03

        signed_data = smdp_signed2_raw + tlv("5F37", euicc_signature1)
        der_signature = asym_utils.encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big", signed=False),
            int.from_bytes(raw_signature[32:], "big", signed=False),
        )
        try:
            public_key.verify(der_signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return 0x02
        return None

    def _prepare_download_certificate_continuation_valid(
        self,
        certificate_der: bytes,
        certificate: crypto_x509.Certificate,
        session: SimSgpSession,
    ) -> bool:
        previous_der = bytes(session.smdp_certificate or b"")
        if len(previous_der) == 0:
            return True
        if certificate_der == previous_der:
            return True
        try:
            previous_certificate = crypto_x509.load_der_x509_certificate(previous_der)
        except Exception:
            return False
        current_aki = self._certificate_authority_key_identifier(certificate)
        previous_aki = self._certificate_authority_key_identifier(previous_certificate)
        if len(current_aki) == 0 or len(previous_aki) == 0:
            return False
        if current_aki != previous_aki:
            return False
        current_subject = self._certificate_name_text(certificate.subject)
        previous_subject = self._certificate_name_text(previous_certificate.subject)
        current_issuer = self._certificate_name_text(certificate.issuer)
        previous_issuer = self._certificate_name_text(previous_certificate.issuer)
        if len(current_issuer) == 0 or current_issuer != previous_issuer:
            return False
        if len(current_subject) > 0 and current_subject == previous_subject:
            return True
        stable_identity_fields = (
            NameOID.COUNTRY_NAME,
            NameOID.ORGANIZATION_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
        )
        current_identity = self._certificate_name_identity(certificate.subject, stable_identity_fields)
        previous_identity = self._certificate_name_identity(previous_certificate.subject, stable_identity_fields)
        if len(current_identity) == 0 or current_identity != previous_identity:
            return False
        return True

    def _build_euicc_signed1(
        self,
        transaction_id: bytes,
        server_address: str,
        server_challenge: bytes,
        ctx_params_raw: bytes,
    ) -> bytes:
        if len(ctx_params_raw) == 0:
            ctx_params_raw = tlv("A0", tlv("A1", tlv("04", b"YGGDRA")))
        value = (
            tlv("80", bytes(transaction_id))
            + tlv("83", server_address.encode("utf-8"))
            + tlv("84", bytes(server_challenge))
            + self._build_euicc_info2_response()
            + bytes(ctx_params_raw)
        )
        return tlv("30", value)

    def _section_from_container_tag(self, tag: bytes) -> str:
        mapping = {
            b"\xA0": "a0",
            b"\xA1": "a1",
            b"\xA2": "a2",
            b"\xA3": "a3",
        }
        return mapping.get(bytes(tag), "")

    def _section_from_member_tag(self, tag: bytes) -> str:
        session = self.state.sgp_session
        if tag == b"\x88":
            return "a1"
        if tag == b"\x86":
            return "a3"
        if tag == b"\x87":
            if session.bpp_section in ("a0", "a2"):
                return session.bpp_section
            if len(session.bpp_store_metadata_request) > 0:
                return "a2"
            return "a0"
        return ""

    def _split_tlv_sequence(self, value: bytes) -> list[bytes]:
        members: list[bytes] = []
        offset = 0
        while offset < len(value):
            _, _, raw_tlv, next_offset = read_tlv(value, offset)
            members.append(raw_tlv)
            offset = next_offset
        return members

    def _validate_configure_isdp_request(self, plaintext: bytes) -> None:
        tag, _, _, end = read_tlv(plaintext, 0)
        if tag != bytes.fromhex("BF24") or end != len(plaintext):
            raise ValueError("Expected BF24 ConfigureISDPRequest.")

    def _parse_store_metadata_request(self, plaintext: bytes) -> dict[str, Any]:
        root_tag, root_value, _, end = read_tlv(plaintext, 0)
        if root_tag != bytes.fromhex("BF25") or end != len(plaintext):
            raise ValueError("Expected BF25 StoreMetadataRequest.")
        result: dict[str, Any] = {
            "iccid": "",
            "service_provider": "",
            "profile_name": "",
            "profile_class": "operational",
            "notification_address": self._default_notification_address(),
        }
        offset = 0
        while offset < len(root_value):
            field_tag, field_value, _, next_offset = read_tlv(root_value, offset)
            if field_tag == b"\x5A":
                result["iccid"] = decode_bcd_digits(field_value)
            elif field_tag == b"\x91":
                result["service_provider"] = field_value.decode("utf-8", "ignore")
            elif field_tag == b"\x92":
                result["profile_name"] = field_value.decode("utf-8", "ignore")
            elif field_tag == b"\x95":
                class_map = {0: "test", 1: "provisioning", 2: "operational"}
                result["profile_class"] = class_map.get(int.from_bytes(field_value, "big", signed=False), "operational")
            elif field_tag == bytes.fromhex("B6"):
                notification_address = self._parse_notification_configuration_info(field_value)
                if len(notification_address) > 0:
                    result["notification_address"] = notification_address
            offset = next_offset
        if len(result["profile_name"]) == 0 and len(result["service_provider"]) > 0:
            result["profile_name"] = result["service_provider"]
        if len(result["iccid"]) == 0:
            raise ValueError("StoreMetadataRequest did not contain ICCID.")
        return result

    def _parse_notification_configuration_info(self, value: bytes) -> str:
        notification_address = ""
        for raw_entry in self._split_tlv_sequence(value):
            entry_tag, entry_value, _, _ = read_tlv(raw_entry, 0)
            if entry_tag != b"\x30":
                continue
            offset = 0
            while offset < len(entry_value):
                field_tag, field_value, _, next_offset = read_tlv(entry_value, offset)
                if field_tag == b"\x0C":
                    notification_address = field_value.decode("utf-8", "ignore")
                offset = next_offset
        return notification_address

    def _parse_replace_session_keys_request(self, plaintext: bytes) -> dict[str, bytes]:
        root_tag, root_value, _, end = read_tlv(plaintext, 0)
        if root_tag != bytes.fromhex("BF26") or end != len(plaintext):
            raise ValueError("Expected BF26 ReplaceSessionKeysRequest.")
        fields: list[bytes] = []
        tagged_fields: dict[bytes, bytes] = {}
        offset = 0
        while offset < len(root_value):
            field_tag, field_value, _, next_offset = read_tlv(root_value, offset)
            if field_tag == b"\x04":
                fields.append(field_value)
            elif field_tag in (b"\x80", b"\x81", b"\x82"):
                tagged_fields[field_tag] = field_value
            else:
                raise ValueError("ReplaceSessionKeysRequest contained unexpected tag.")
            offset = next_offset
        if len(tagged_fields) > 0:
            if set(tagged_fields.keys()) != {b"\x80", b"\x81", b"\x82"}:
                raise ValueError("ReplaceSessionKeysRequest must contain 80/81/82 fields.")
            return {
                "initialMacChainingValue": tagged_fields[b"\x80"],
                "ppkEnc": tagged_fields[b"\x81"],
                "ppkCmac": tagged_fields[b"\x82"],
            }
        if len(fields) != 3:
            raise ValueError("ReplaceSessionKeysRequest must contain exactly three OCTET STRING fields.")
        return {
            "initialMacChainingValue": fields[0],
            "ppkEnc": fields[1],
            "ppkCmac": fields[2],
        }

    def _create_installed_profile_from_bpp(self) -> SimProfileEntry:
        session = self.state.sgp_session
        metadata = dict(session.bpp_store_metadata)
        if len(metadata) == 0:
            raise ValueError("StoreMetadataRequest was not decrypted before A3.")

        profile_name = str(metadata.get("profile_name", "")).strip() or f"Installed Profile {len(self.state.profiles) + 1}"
        service_provider = str(metadata.get("service_provider", "")).strip() or "YggdraSIM Lab"
        profile_class = str(metadata.get("profile_class", "operational")).strip().lower() or "operational"
        notification_address = (
            str(metadata.get("notification_address", "")).strip() or self._default_notification_address()
        )
        requested_iccid = str(metadata.get("iccid", "")).strip()
        profile_image = decode_profile_image(
            session.bpp_unprotected_profile,
            default_iccid=requested_iccid,
            default_name=profile_name,
        )
        decoded_iccid = ""
        if profile_image is not None:
            decoded_iccid = str(profile_image.iccid or "").strip()
        if len(requested_iccid) > 0 and len(decoded_iccid) > 0 and requested_iccid != decoded_iccid:
            raise BppIccidMismatchError("StoreMetadata ICCID did not match decoded profile ICCID.")
        effective_iccid = requested_iccid or decoded_iccid or self._next_generated_iccid()
        if any(profile.iccid == effective_iccid for profile in self.state.profiles):
            raise BppDuplicateIccidError("Profile ICCID already exists on simulated eUICC.")
        aid = self._next_generated_profile_aid()
        if profile_image is not None:
            profile_image.iccid = effective_iccid
            profile_image.profile_name = str(profile_image.profile_name or "").strip() or profile_name
            self._upsert_profile_image_iccid(profile_image, effective_iccid)
        profile_imsi = ""
        profile_impi = ""
        if profile_image is not None:
            profile_imsi = str(profile_image.imsi or "").strip()
            profile_impi = str(profile_image.impi or "").strip()

        profile_auth_config = None
        if profile_image is not None:
            carried_config = getattr(profile_image, "auth_config", None)
            if carried_config is not None:
                profile_auth_config = carried_config

        profile = SimProfileEntry(
            aid=aid,
            iccid=effective_iccid,
            state="disabled",
            profile_class=profile_class,
            nickname=profile_name,
            service_provider=service_provider,
            profile_name=profile_name,
            imsi=profile_imsi,
            impi=profile_impi,
            notification_address=notification_address,
            upp_bytes=bytes(session.bpp_unprotected_profile),
            profile_image=profile_image,
            profile_source="upp",
            auth_config=profile_auth_config,
        )
        self.state.profiles.append(profile)
        self._sync_profile_store()
        return profile

    def _upsert_profile_image_iccid(self, profile_image, iccid: str) -> None:
        iccid_node = self._find_profile_image_node(profile_image, ("MF", "EF.ICCID"))
        if iccid_node is None:
            profile_image.nodes.append(
                self._make_profile_image_node(
                    path=("MF", "EF.ICCID"),
                    name="EF.ICCID",
                    kind="ef",
                    fid="2FE2",
                    structure="transparent",
                    data=encode_iccid_ef(iccid),
                    sfi=0x02,
                )
            )
            return
        iccid_node.data = encode_iccid_ef(iccid)
        iccid_node.records = []

    @staticmethod
    def _find_profile_image_node(profile_image, path: tuple[str, ...]):
        if profile_image is None:
            return None
        for node in getattr(profile_image, "nodes", []):
            if getattr(node, "path", ()) == path:
                return node
        return None

    @staticmethod
    def _make_profile_image_node(
        *,
        path: tuple[str, ...],
        name: str,
        kind: str,
        fid: str = "",
        structure: str = "transparent",
        data: bytes = b"",
        sfi: int | None = None,
    ):
        from SIMCARD.state import SimProfileFsNode

        return SimProfileFsNode(
            path=path,
            name=name,
            kind=kind,
            fid=fid,
            structure=structure,
            data=data,
            sfi=sfi,
        )

    def _next_generated_profile_aid(self) -> str:
        return next_generated_profile_aid(self.state.profiles)

    def _next_generated_iccid(self) -> str:
        used = {profile.iccid for profile in self.state.profiles}
        suffix = len(self.state.profiles) + 11
        while True:
            candidate = f"894611111111111111{suffix:02d}"
            if candidate not in used:
                return candidate
            suffix += 1

    def _parse_bf23(self, raw_tlv: bytes) -> dict[str, Any] | None:
        try:
            tag, value, _, _ = read_tlv(raw_tlv, 0)
            if tag != bytes.fromhex("BF23"):
                return None
            result: dict[str, Any] = {
                "remote_op_id": 0,
                "transaction_id": b"",
                "control_ref_template": {"keyType": b"", "keyLen": b"", "hostId": b""},
                "smdp_otpk": b"",
                "smdp_sign": b"",
                "remote_op_id_raw": b"",
                "transaction_id_raw": b"",
                "control_ref_template_raw": b"",
                "smdp_otpk_raw": b"",
            }
            offset = 0
            while offset < len(value):
                field_tag, field_value, field_raw, next_offset = read_tlv(value, offset)
                if field_tag == b"\x82":
                    result["remote_op_id"] = int.from_bytes(field_value, "big", signed=False)
                    result["remote_op_id_raw"] = field_raw
                elif field_tag == b"\x80":
                    result["transaction_id"] = field_value
                    result["transaction_id_raw"] = field_raw
                elif field_tag == b"\xA6":
                    result["control_ref_template_raw"] = field_raw
                    result["control_ref_template"] = self._parse_control_ref_template(field_value)
                elif field_tag == bytes.fromhex("5F49"):
                    result["smdp_otpk"] = field_value
                    result["smdp_otpk_raw"] = field_raw
                elif field_tag == bytes.fromhex("5F37"):
                    result["smdp_sign"] = field_value
                offset = next_offset
            return result
        except Exception:
            return None

    def _parse_control_ref_template(self, value: bytes) -> dict[str, bytes]:
        result = {"keyType": b"", "keyLen": b"", "hostId": b""}
        offset = 0
        while offset < len(value):
            field_tag, field_value, _, next_offset = read_tlv(value, offset)
            if field_tag == b"\x80":
                result["keyType"] = field_value
            elif field_tag == b"\x81":
                result["keyLen"] = field_value
            elif field_tag == b"\x84":
                result["hostId"] = field_value
            offset = next_offset
        return result

    def _verify_bf23_signature(self, bf23_info: dict[str, Any], session: SimSgpSession) -> bool:
        certificate_der = bytes(session.smdp_certificate or b"")
        if len(certificate_der) == 0:
            return False
        raw_signature = bytes(bf23_info.get("smdp_sign", b""))
        if len(raw_signature) != 64:
            return False
        signed_data = (
            bytes(bf23_info.get("remote_op_id_raw", b""))
            + bytes(bf23_info.get("transaction_id_raw", b""))
            + bytes(bf23_info.get("control_ref_template_raw", b""))
            + bytes(bf23_info.get("smdp_otpk_raw", b""))
            + tlv("5F49", bytes(session.euicc_otpk))
        )
        certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key()
        der_signature = asym_utils.encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big", signed=False),
            int.from_bytes(raw_signature[32:], "big", signed=False),
        )
        try:
            public_key.verify(der_signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return False
        return True

    def _raw_ecdsa_signature(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        payload: bytes,
    ) -> bytes:
        signature_der = private_key.sign(bytes(payload), ec.ECDSA(hashes.SHA256()))
        r_value, s_value = asym_utils.decode_dss_signature(signature_der)
        return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")

    def _signature_blob(self, *parts: bytes) -> bytes:
        digest = hashlib.sha256(b"".join(bytes(part or b"") for part in parts)).digest()
        return digest + digest

    def _build_self_signed_certificate(
        self,
        *,
        common_name: str = "Simulated eUICC",
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> bytes:
        key = private_key or ec.generate_private_key(ec.SECP256R1())
        name = crypto_x509.Name(
            [
                crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
                crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YggdraSIM"),
                crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            crypto_x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.DER)
