# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 local-access session: drives a full SGP.26 local-delivery exchange without network dependencies."""
import hashlib
import os
import re
import sys
import threading
import time
import types
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID
from yggdrasim_common.euicc_issuer import infer_ecasd_issuer_identity
from yggdrasim_common.progress import progress_session
from yggdrasim_common.runtime_paths import ensure_seeded_workspace_file, remap_legacy_workspace_relative, runtime_root

try:
    from ..pysim_path import describe_pysim_resolution, ensure_repo_pysim_on_path
    from ..shared.profile_targeting import resolve_profile_target_identifier
except ImportError:
    from SCP11.pysim_path import describe_pysim_resolution, ensure_repo_pysim_on_path
    from SCP11.shared.profile_targeting import resolve_profile_target_identifier

ensure_repo_pysim_on_path()

_MODULE_NOT_PRESENT = object()
_SMARTCARD_STUB_MODULES = [
    "smartcard",
    "smartcard.util",
    "smartcard.CardConnection",
    "smartcard.System",
]
_SMPP_STUB_MODULES = [
    "smpp",
    "smpp.pdu",
    "smpp.pdu.pdu_types",
    "smpp.pdu.operations",
]


def _install_minimal_smartcard_stubs() -> None:
    try:
        from smartcard.util import toBytes as _smartcard_to_bytes  # type: ignore
    except Exception:
        _smartcard_to_bytes = None
    if callable(_smartcard_to_bytes):
        return

    def _to_bytes(value: Any) -> list[int]:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return [int(item) & 0xFF for item in bytes(value)]
        if isinstance(value, str):
            cleaned = str(value).strip().replace(" ", "").replace(":", "")
            if len(cleaned) == 0:
                return []
            if len(cleaned) % 2 != 0:
                raise ValueError("Hex string must contain an even number of digits.")
            return [int(cleaned[index : index + 2], 16) for index in range(0, len(cleaned), 2)]
        if isinstance(value, (list, tuple)):
            return [int(item) & 0xFF for item in value]
        return [int(item) & 0xFF for item in bytes(value)]

    smartcard_module = sys.modules.get("smartcard")
    if smartcard_module is None:
        smartcard_module = types.ModuleType("smartcard")
        sys.modules["smartcard"] = smartcard_module

    util_module = types.ModuleType("smartcard.util")
    util_module.toBytes = _to_bytes
    sys.modules["smartcard.util"] = util_module
    setattr(smartcard_module, "util", util_module)

    card_connection_module = types.ModuleType("smartcard.CardConnection")

    class _CardConnection:
        T0_protocol = 1
        T1_protocol = 2
        RAW_protocol = 4

    card_connection_module.CardConnection = _CardConnection
    sys.modules["smartcard.CardConnection"] = card_connection_module
    setattr(smartcard_module, "CardConnection", card_connection_module)

    system_module = types.ModuleType("smartcard.System")
    system_module.readers = lambda: []
    sys.modules["smartcard.System"] = system_module
    setattr(smartcard_module, "System", system_module)


def _install_minimal_smpp_stubs() -> None:
    try:
        from smpp.pdu import pdu_types as _pdu_types  # type: ignore
        from smpp.pdu import operations as _operations  # type: ignore
    except Exception:
        _pdu_types = None
        _operations = None
    if _pdu_types is not None and _operations is not None:
        return

    class _Placeholder:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs

    smpp_module = sys.modules.get("smpp")
    if smpp_module is None:
        smpp_module = types.ModuleType("smpp")
        sys.modules["smpp"] = smpp_module

    pdu_module = types.ModuleType("smpp.pdu")
    pdu_types_module = types.ModuleType("smpp.pdu.pdu_types")
    operations_module = types.ModuleType("smpp.pdu.operations")

    pdu_types_module.DataCoding = _Placeholder
    pdu_types_module.PDU = _Placeholder
    operations_module.DeliverSM = _Placeholder
    operations_module.SubmitSM = _Placeholder

    pdu_module.pdu_types = pdu_types_module
    pdu_module.operations = operations_module

    sys.modules["smpp.pdu"] = pdu_module
    sys.modules["smpp.pdu.pdu_types"] = pdu_types_module
    sys.modules["smpp.pdu.operations"] = operations_module
    setattr(smpp_module, "pdu", pdu_module)


def _snapshot_modules(module_names: list[str]) -> dict[str, Any]:
    return {name: sys.modules.get(name, _MODULE_NOT_PRESENT) for name in module_names}


def _restore_module_snapshot(snapshot: dict[str, Any]) -> None:
    for name, module in snapshot.items():
        if module is _MODULE_NOT_PRESENT:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def _smartcard_support_available() -> bool:
    try:
        from smartcard.util import toBytes as _smartcard_to_bytes  # type: ignore
    except Exception:
        return False
    return callable(_smartcard_to_bytes)


def _smpp_support_available() -> bool:
    try:
        from smpp.pdu import pdu_types as _pdu_types  # type: ignore
        from smpp.pdu import operations as _operations  # type: ignore
    except Exception:
        return False
    return hasattr(_pdu_types, "DataCoding") and hasattr(_operations, "SubmitSM")


@contextmanager
def _temporary_session_bound_dependency_stubs():
    snapshot: dict[str, Any] = {}
    if _smartcard_support_available() is False:
        snapshot.update(_snapshot_modules(_SMARTCARD_STUB_MODULES))
        _install_minimal_smartcard_stubs()
    if _smpp_support_available() is False:
        snapshot.update(_snapshot_modules(_SMPP_STUB_MODULES))
        _install_minimal_smpp_stubs()
    try:
        yield
    finally:
        _restore_module_snapshot(snapshot)


_SAIP_DECODE_TIMEOUT_ENV = "YGGDRASIM_SCP11_SAIP_DECODE_TIMEOUT_SECONDS"
# pySim's SAIP ASN.1 decoder can loop on production-sized UPPs; keep the
# default budget short so the operator console never wedges, and fall back
# to header-TLV identity extraction when the decoder punts. Set
# ``YGGDRASIM_SCP11_SAIP_DECODE_TIMEOUT_SECONDS`` to a larger value when a
# specific workflow genuinely needs the full decode to finish.
_SAIP_DECODE_DEFAULT_TIMEOUT = 8.0
# pySim's SAIP decoder holds the GIL for the entire walk, so even a
# time-bounded daemon thread can pin a CPU and starve later decode calls
# within the same process. Full-decode is therefore opt-in: the default
# console path sticks to the header-TLV fallback (which gives us iccid
# and profile name) and only exercises pySim when the operator explicitly
# asks for it via ``YGGDRASIM_SCP11_ALLOW_FULL_SAIP_DECODE``.
_SAIP_DECODE_ALLOW_FULL_ENV = "YGGDRASIM_SCP11_ALLOW_FULL_SAIP_DECODE"


def _resolve_saip_decode_timeout_seconds() -> float:
    raw_value = str(os .environ .get (_SAIP_DECODE_TIMEOUT_ENV ,"")or "").strip ()
    if len (raw_value )==0 :
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    try :
        parsed =float (raw_value )
    except ValueError :
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    if parsed <=0.0 :
        return _SAIP_DECODE_DEFAULT_TIMEOUT
    return parsed


def _full_saip_decode_enabled() -> bool:
    raw_value = str(os.environ.get(_SAIP_DECODE_ALLOW_FULL_ENV, "") or "").strip().lower()
    return raw_value in {"1", "true", "yes", "on"}


def _run_with_timeout(callable_, args, *, timeout_seconds: float):
    """Execute ``callable_(*args)`` under a soft deadline.

    Returns the callable's result, or ``None`` on timeout / exception. The
    returned ``None`` is treated by the caller as a "decoder punted" signal
    — the header-TLV path still supplies identity fields, so downstream
    callers degrade gracefully instead of wedging the whole console.
    Background threads are daemonised; if the decoder genuinely loops, the
    worker is left pinned but the main thread continues and the process
    will eventually be reaped by the launcher.
    """
    result_slot : list [Any ]=[None ]
    exc_slot : list [BaseException | None ]=[None ]

    def _worker ()->None :
        try :
            result_slot [0 ]=callable_ (*args )
        except BaseException as error :
            exc_slot [0 ]=error

    worker =threading .Thread (target =_worker ,daemon =True )
    worker .start ()
    worker .join (timeout =max (0.5 ,float (timeout_seconds )))
    if worker .is_alive ():
        return None
    if exc_slot [0 ] is not None :
        return None
    return result_slot [0 ]


BspInstance = None
BoundProfilePackage = None
gen_replace_session_keys = None
ProfileMetadata = None
ProtectedProfilePackage = None
UnprotectedProfilePackage = None
pysim_saip = None
PySimRspSessionState = None
CertAndPrivkey = None
PYSIM_SESSION_BOUND_IMPORT_ERROR = ""


def _describe_pysim_session_bound_support() -> str:
    detail = str(PYSIM_SESSION_BOUND_IMPORT_ERROR).strip()
    summary = describe_pysim_resolution()
    if len(detail) == 0:
        return summary
    return summary + " Session-bound import error: " + detail + "."


def _ensure_pysim_session_bound_support() -> None:
    global BspInstance
    global BoundProfilePackage
    global gen_replace_session_keys
    global ProfileMetadata
    global ProtectedProfilePackage
    global UnprotectedProfilePackage
    global pysim_saip
    global PySimRspSessionState
    global CertAndPrivkey
    global PYSIM_SESSION_BOUND_IMPORT_ERROR

    if all(
        component is not None
        for component in (
            BspInstance,
            BoundProfilePackage,
            gen_replace_session_keys,
            ProfileMetadata,
            ProtectedProfilePackage,
            UnprotectedProfilePackage,
            pysim_saip,
            PySimRspSessionState,
            CertAndPrivkey,
        )
    ):
        return

    with _temporary_session_bound_dependency_stubs():
        try:
            from pySim.esim.es8p import (
                BspInstance as _BspInstance,
                BoundProfilePackage as _BoundProfilePackage,
                ProfileMetadata as _ProfileMetadata,
                ProtectedProfilePackage as _ProtectedProfilePackage,
                UnprotectedProfilePackage as _UnprotectedProfilePackage,
                gen_replace_session_keys as _gen_replace_session_keys,
            )
            from pySim.esim import saip as _pysim_saip
            from pySim.esim.rsp import RspSessionState as _PySimRspSessionState
            from pySim.esim.x509_cert import CertAndPrivkey as _CertAndPrivkey
        except Exception as error:
            PYSIM_SESSION_BOUND_IMPORT_ERROR = f"{type(error).__name__}: {error}"
            return

    BspInstance = _BspInstance
    BoundProfilePackage = _BoundProfilePackage
    gen_replace_session_keys = _gen_replace_session_keys
    ProfileMetadata = _ProfileMetadata
    ProtectedProfilePackage = _ProtectedProfilePackage
    UnprotectedProfilePackage = _UnprotectedProfilePackage
    pysim_saip = _pysim_saip
    PySimRspSessionState = _PySimRspSessionState
    CertAndPrivkey = _CertAndPrivkey
    PYSIM_SESSION_BOUND_IMPORT_ERROR = ""

try:
    from ..shared.crypto_engine import CryptoEngine
    from ..shared.device_inventory_support import EidInventoryNamespace
    from ..shared.payload_builder import PayloadBuilder
    from ..shared.pysim_support import (
        decode_list_notification_response,
        decode_pending_notification,
        decode_retrieve_notifications_list_response,
        decode_authenticate_server_response,
        decode_prepare_download_response,
        encode_cancel_session_request,
        encode_notification_sent_request,
        extract_euicc_signed1,
    )
    from ..shared.transport import PcscApduChannel
    from .cert_store import LocalSgp26CertStore, SmdpCertificateRecord
    from .config import LocalAccessConfig
    from .metadata_codec import (
        collect_enabled_custom_metadata_tags,
        encode_store_metadata_request_from_file,
        encode_update_metadata_request_from_file,
        load_metadata_json_document,
    )
    from ..shared.gsma_error_codes import (
        describe_sgp22_download_error,
        describe_sgp22_profile_installation_reason,
    )
except ImportError:
    from SCP11.shared.crypto_engine import CryptoEngine
    from SCP11.shared.device_inventory_support import EidInventoryNamespace
    from SCP11.shared.payload_builder import PayloadBuilder
    from SCP11.shared.pysim_support import (
        decode_list_notification_response,
        decode_pending_notification,
        decode_retrieve_notifications_list_response,
        decode_authenticate_server_response,
        decode_prepare_download_response,
        encode_cancel_session_request,
        encode_notification_sent_request,
        extract_euicc_signed1,
    )
    from SCP11.shared.transport import PcscApduChannel
    from SCP11.local_access.cert_store import LocalSgp26CertStore, SmdpCertificateRecord
    from SCP11.local_access.config import LocalAccessConfig
    from SCP11.local_access.metadata_codec import (
        collect_enabled_custom_metadata_tags,
        encode_store_metadata_request_from_file,
        encode_update_metadata_request_from_file,
        load_metadata_json_document,
    )
    from SCP11.shared.gsma_error_codes import (
        describe_sgp22_download_error,
        describe_sgp22_profile_installation_reason,
    )

@dataclass
class LocalSessionState:
    isdr_selected: bool = False
    session_open: bool = False
    select_response: bytes = b""
    euicc_info1: bytes = b""
    card_challenge: bytes = b""
    configured_data: bytes = b""
    transaction_id: bytes = b""
    server_challenge: bytes = b""
    authenticate_server_request: bytes = b""
    authenticate_server_response: bytes = b""
    euicc_signed1: bytes = b""
    euicc_signature1: bytes = b""
    cancel_session_response: bytes = b""
    prepare_download_response: bytes = b""
    last_load_bpp_response: bytes = b""
    load_notifications_synced: bool = False
    allowed_ci_pkids: list[str] = field(default_factory=list)
    selected_ci_pkid: str = ""
    selected_auth_certificate_path: str = ""
    selected_pb_certificate_path: str = ""
    selected_auth_private_key_path: str = ""
    selected_pb_private_key_path: str = ""
    selected_auth_certificate_reason: str = ""
    selected_pb_certificate_reason: str = ""
    selected_local_smdp_address: str = ""
    profile_override_path: str = ""
    resolved_profile_path: str = ""
    metadata_override_path: str = ""
    resolved_metadata_path: str = ""
    bpp_command_descriptions: list[str] = field(default_factory=list)
    upp_protected_command_descriptions: list[str] = field(default_factory=list)
    last_bpp_layout_lines: list[str] = field(default_factory=list)
    last_bpp_crypto_debug_lines: list[str] = field(default_factory=list)
    last_pre_bsp_payload_bin_path: str = ""
    last_pre_bsp_payload_hex_path: str = ""
    last_bsp_s_enc_hex: str = ""
    last_bsp_s_mac_hex: str = ""
    last_bsp_mac_chain_hex: str = ""
    last_bsp_block_nr: int = 0
    last_bsp_aid_hex: str = ""
    last_bsp_protocol: str = ""


@dataclass
class OpenSessionResult:
    transaction_id: bytes
    card_challenge: bytes
    server_challenge: bytes
    euicc_signed1: bytes
    euicc_signature1: bytes
    authenticate_server_response: bytes


@dataclass
class ProfileMetadataView:
    iccid: str
    aid: str
    state: str
    profile_class: str
    nickname: str = ""
    service_provider: str = ""
    profile_name: str = ""
    profile_policy_rules_hex: str = ""


class LocalIsdrSession:
    """Local SCP11 handshake and session closure against ISD-R."""

    CANCEL_SESSION_REASON_END_USER_REJECTION = 0
    CANCEL_SESSION_REASON_POSTPONED = 1
    CANCEL_SESSION_REASON_TIMEOUT = 2
    CANCEL_SESSION_REASON_PPR_NOT_ALLOWED = 3
    TAG_ENABLE_PROFILE = bytes.fromhex("BF31")
    TAG_DISABLE_PROFILE = bytes.fromhex("BF32")
    TAG_DELETE_PROFILE = bytes.fromhex("BF33")
    TAG_STORE_METADATA = bytes.fromhex("BF25")
    TAG_UPDATE_METADATA = bytes.fromhex("BF2A")
    TAG_ICCID = b"\x5A"
    TAG_AID = b"\x4F"
    TAG_CTX_0 = b"\xA0"
    TAG_RESULT = b"\x80"

    def __init__(self, cfg: Optional[LocalAccessConfig] = None, apdu_channel: Optional[Any] = None):
        self.cfg = cfg or LocalAccessConfig()
        self.apdu_channel = apdu_channel or PcscApduChannel(reader_index=self.cfg.READER_INDEX)
        set_raw_logging = getattr(self.apdu_channel, "set_raw_apdu_logging", None)
        if callable(set_raw_logging):
            set_raw_logging(False)
        self.state = LocalSessionState()
        self.current_eid = ""
        self._inventory = EidInventoryNamespace("scp11_local_access")
        self._cert_store = LocalSgp26CertStore(
            valid_cert_root=self.cfg.SGP26_VALID_CERT_DIR,
            prefer_curve=self.cfg.CERT_CURVE_PREFERENCE,
            override_cert_root=self.cfg.CERTS_DIR,
            default_server_address=self.cfg.SERVER_ADDRESS,
            default_root_ci_id=self.cfg.ROOT_CI_ID.hex().upper(),
        )
        self._cert_auth = None
        self._key_auth = None
        self._cert_pb = None
        self._key_pb = None
        self._workspace_root = self._detect_workspace_root()
        self._workspace_root_entries = self._list_workspace_root_entries(self._workspace_root)

    @staticmethod
    def _describe_exception_chain(error: BaseException) -> str:
        parts: list[str] = []
        current: BaseException | None = error
        while current is not None:
            text = str(current).strip() or current.__class__.__name__
            if len(parts) == 0 or parts[-1] != text:
                parts.append(text)
            next_error = getattr(current, "__cause__", None)
            if isinstance(next_error, BaseException):
                current = next_error
                continue
            break
        return " | ".join(parts)

    def select_isdr(self) -> bytes:
        """SELECT the ISD-R application on the active card channel."""
        aid = bytes(self.cfg.AID_ISD_R)
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
        response = self.apdu_channel.send(apdu, "LOCAL: Select ISD-R")
        self.state.isdr_selected = True
        self.state.select_response = response
        return response

    def get_euicc_info1(self) -> bytes:
        """Send ES10b.GetEUICCInfo and return the raw EUICCInfo1 bytes."""
        response = self.apdu_channel.send(
            b"\x80\xE2\x91\x00\x03\xBF\x20\x00",
            "LOCAL: GetEuiccInfo1",
        )
        self.state.euicc_info1 = response
        return response

    def get_euicc_challenge(self) -> bytes:
        """Send ES10b.GetEUICCChallenge and return the 16-byte eUICC challenge."""
        response = self.apdu_channel.send(
            b"\x80\xE2\x91\x00\x03\xBF\x2E\x00",
            "LOCAL: GetEuiccChallenge",
        )
        if len(response) < 16:
            raise ValueError("GetEuiccChallenge response is shorter than 16 bytes.")
        self.state.card_challenge = response[-16:]
        return self.state.card_challenge

    def get_euicc_configured_data(self) -> bytes:
        """Send ES10b.GetEUICCConfiguredData and return the response bytes."""
        response = self.apdu_channel.send(
            b"\x80\xE2\x91\x00\x03\xBF\x3C\x00",
            "LOCAL: GetEuiccConfiguredData",
        )
        self.state.configured_data = response
        self.state.allowed_ci_pkids = self._extract_allowed_ci_pkids(response)
        return response

    def get_euicc_info2(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF2200"), "LOCAL: GetEuiccInfo2")

    def get_profiles_info(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF2D00"), "LOCAL: GetProfilesInfo")

    def get_rat(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF4300"), "LOCAL: GetRAT")

    def get_notifications_list(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF2B00"), "LOCAL: RetrieveNotificationsList")

    def get_eim_configuration_data(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF5500"), "LOCAL: GetEimConfigurationData")

    def get_certs(self) -> bytes:
        return self._send_retrieve_store_data(bytes.fromhex("BF5600"), "LOCAL: GetCerts")

    def get_eid(self) -> str:
        if self.state.isdr_selected is False:
            self.select_isdr()
        eid = self._read_card_eid()
        self._bind_inventory_for_eid(eid)
        return eid

    def discover_card(self) -> dict[str, Any]:
        """Run the live-style local discovery snapshot in one ISD-R context."""
        self.reset_state()
        self.select_isdr()
        profiles_raw = self.get_profiles_info()
        configured_raw = self.get_euicc_configured_data()
        eid_value = self.get_eid()
        issuer_identity = infer_ecasd_issuer_identity("")
        try:
            issuer_identity = self._read_card_ecasd_issuer_identity()
        except Exception:
            issuer_identity = infer_ecasd_issuer_identity("")
        profiles: list[ProfileMetadataView] = []
        profiles_decode_error = ""
        try:
            profiles = self.decode_profile_metadata_rows(profiles_raw)
        except Exception as error:
            profiles_decode_error = self._describe_exception_chain(error)

        configured_decoded: dict[str, Any] = {
            "default_smdp": "",
            "root_smds_primary": "",
            "root_smds_additional": [],
            "allowed_ci_pkid": [],
        }
        configured_decode_error = ""
        try:
            configured_decoded = self.decode_euicc_configured_data(configured_raw)
        except Exception as error:
            configured_decode_error = self._describe_exception_chain(error)

        snapshot = {
            "eid": eid_value,
            "issuer_number": str(issuer_identity.get("issuer_number", "")).strip(),
            "issuer_name": str(issuer_identity.get("issuer_name", "")).strip(),
            "profiles_raw": profiles_raw,
            "profiles": profiles,
            "configured_raw": configured_raw,
            "configured_decoded": configured_decoded,
            "euicc_info1": self.get_euicc_info1(),
            "euicc_info2": self.get_euicc_info2(),
            "rat": self.get_rat(),
            "notifications": self.get_notifications_list(),
            "eim_configuration": self.get_eim_configuration_data(),
            "certs": self.get_certs(),
        }
        if len(profiles_decode_error) > 0:
            snapshot["profiles_decode_error"] = profiles_decode_error
        if len(configured_decode_error) > 0:
            snapshot["configured_decode_error"] = configured_decode_error
        return snapshot

    def collect_quick_overview(self) -> dict[str, Any]:
        """Lightweight ``INFO``/``SCAN`` snapshot — header data only.

        Mirrors :meth:`discover_card` but skips the heavy ES10 reads
        (``GetRAT``, ``RetrieveNotificationsList``, ``GetCerts``) so the
        operator can refresh the header card after a profile change
        without paying the round-trip cost of the full SGP.32
        consolidated retrieval. Returns the same dict shape used by
        :func:`SCP11.shared.discovery_snapshot.render_card_overview_snapshot`
        so the renderer can be shared across all four shells.
        """
        self.reset_state()
        self.select_isdr()
        profiles_raw = self.get_profiles_info()
        configured_raw = self.get_euicc_configured_data()
        eid_value = self.get_eid()
        try:
            issuer_identity = self._read_card_ecasd_issuer_identity()
        except Exception:
            issuer_identity = infer_ecasd_issuer_identity("")

        profiles: list[ProfileMetadataView] = []
        profiles_decode_error = ""
        try:
            profiles = self.decode_profile_metadata_rows(profiles_raw)
        except Exception as error:
            profiles_decode_error = self._describe_exception_chain(error)

        configured_decoded: dict[str, Any] = {
            "default_smdp": "",
            "root_smds_primary": "",
            "root_smds_additional": [],
            "allowed_ci_pkid": [],
        }
        configured_decode_error = ""
        try:
            configured_decoded = self.decode_euicc_configured_data(configured_raw)
        except Exception as error:
            configured_decode_error = self._describe_exception_chain(error)

        # ``GetEimConfigurationData`` is cheap and central to the eIM
        # entries on the header card, so we keep it. ``GetCerts`` and
        # ``GetRAT`` stay out of the quick path.
        try:
            eim_configuration = self.get_eim_configuration_data()
        except Exception:
            eim_configuration = b""

        snapshot: dict[str, Any] = {
            "eid": eid_value,
            "issuer_number": str(issuer_identity.get("issuer_number", "")).strip(),
            "issuer_name": str(issuer_identity.get("issuer_name", "")).strip(),
            "profiles_raw": profiles_raw,
            "profiles": profiles,
            "configured_raw": configured_raw,
            "configured_decoded": configured_decoded,
            "eim_configuration": eim_configuration,
        }
        if len(profiles_decode_error) > 0:
            snapshot["profiles_decode_error"] = profiles_decode_error
        if len(configured_decode_error) > 0:
            snapshot["configured_decode_error"] = configured_decode_error
        return snapshot

    def collect_profile_metadata(self) -> list[ProfileMetadataView]:
        """Collect and return profile metadata rows for the currently enabled profile."""
        self.reset_state()
        self.select_isdr()
        raw_profiles = self.get_profiles_info()
        try:
            return self.decode_profile_metadata_rows(raw_profiles)
        except Exception as error:
            detail = self._describe_exception_chain(error)
            raise ValueError(f"Profile metadata decode failed: {detail}") from error

    def resolve_profile_target(self, identifier: str) -> Optional[tuple[bytes, str]]:
        return self._resolve_profile_target(identifier)

    def decode_profile_metadata_rows(self, raw_data: bytes) -> list[ProfileMetadataView]:
        """Decode raw profile metadata bytes into a list of human-readable (key, value) pairs."""
        rows: list[ProfileMetadataView] = []
        index = 0
        while index < len(raw_data):
            if raw_data[index] != 0xE3:
                index += 1
                continue

            length, length_size = self._decode_der_length(raw_data, index + 1)
            if length_size == 0:
                break

            value_start = index + 1 + length_size
            value_end = value_start + length
            if value_end > len(raw_data):
                break

            blob = raw_data[value_start:value_end]
            parsed = self._parse_tlv_simple(blob)
            row = self._profile_metadata_from_parsed(parsed)
            if row is not None:
                rows.append(row)
            index = value_end
        return rows

    def decode_euicc_configured_data(self, raw_data: bytes) -> dict[str, Any]:
        """Decode configured-data bytes returned by GET DATA 0x5C0A into a structured dict (SGP.22 §2.6.4)."""
        result: dict[str, Any] = {
            "default_smdp": "",
            "root_smds_primary": "",
            "root_smds_additional": [],
            "allowed_ci_pkid": [],
        }
        if len(raw_data) == 0:
            return result

        parsed = self._parse_tlv_simple(raw_data)
        root_value = b""
        if 0xBF3C in parsed:
            bf3c_value = parsed[0xBF3C]
            if isinstance(bf3c_value, list):
                if len(bf3c_value) > 0 and isinstance(bf3c_value[0], bytes):
                    root_value = bf3c_value[0]
            elif isinstance(bf3c_value, bytes):
                root_value = bf3c_value
        else:
            root_value = raw_data

        inner = self._parse_tlv_simple(root_value)

        default_values = self._extract_text_values(inner, 0x80)
        if len(default_values) > 0:
            result["default_smdp"] = default_values[0]

        primary_smds_values = self._extract_text_values(inner, 0x81)
        if len(primary_smds_values) > 0:
            result["root_smds_primary"] = primary_smds_values[0]

        additional_smds_values: list[str] = []
        additional_smds_values.extend(self._extract_text_values(inner, 0x82))
        additional_smds_values.extend(self._extract_nested_additional_smds(inner))
        result["root_smds_additional"] = self._dedupe_preserving_order(additional_smds_values)

        pkid_values = self._extract_text_values(inner, 0x83)
        result["allowed_ci_pkid"] = self._dedupe_preserving_order(pkid_values)
        return result

    def _build_store_data_apdu(self, payload: bytes) -> bytes:
        payload_len = len(payload)
        if payload_len <= 0xFF:
            return bytes([0x80, 0xE2, 0x91, 0x00, payload_len]) + payload
        if payload_len <= 0xFFFF:
            length_hi = (payload_len >> 8) & 0xFF
            length_lo = payload_len & 0xFF
            return bytes([0x80, 0xE2, 0x91, 0x00, 0x00, length_hi, length_lo]) + payload
        raise ValueError("StoreData payload exceeds APDU extended-length limit.")

    def _send_retrieve_store_data(self, payload: bytes, log_name: str) -> bytes:
        send_chunked = getattr(self.apdu_channel, "send_chunked", None)
        if len(payload) > 0xFF and callable(send_chunked):
            chunk_size = int(getattr(self.cfg, "CHUNK_SIZE", 250) or 250)
            if chunk_size <= 0:
                chunk_size = 250
            if chunk_size > 250:
                chunk_size = 250
            return send_chunked(
                0x80,
                0xE2,
                0x91,
                0x00,
                payload,
                log_name,
                chunk_size=chunk_size,
            )
        apdu = self._build_store_data_apdu(payload)
        return self.apdu_channel.send(apdu, log_name)

    def enable_profile(self, identifier: str) -> bytes:
        return self._run_profile_state_command(identifier, self.TAG_ENABLE_PROFILE, "EnableProfile")

    def disable_profile(self, identifier: str) -> bytes:
        return self._run_profile_state_command(identifier, self.TAG_DISABLE_PROFILE, "DisableProfile")

    def delete_profile(self, identifier: str) -> bytes:
        return self._run_profile_state_command(identifier, self.TAG_DELETE_PROFILE, "DeleteProfile")

    def store_metadata(self, metadata_path: str = "") -> bytes:
        """Persist the supplied metadata dict to the session metadata store."""
        encoded_metadata = self.encode_metadata_asn1(override_path=metadata_path)
        return self._run_metadata_command(
            encoded_metadata,
            self.TAG_STORE_METADATA,
            "StoreMetadata",
        )

    def update_metadata(self, metadata_path: str = "") -> bytes:
        """Update fields in the stored metadata dict without replacing it wholesale."""
        encoded_metadata = self.encode_update_metadata_asn1(override_path=metadata_path)
        return self._run_metadata_command(
            encoded_metadata,
            self.TAG_UPDATE_METADATA,
            "UpdateMetadata",
        )

    def store_metadata_custom(self, custom_tag_hex: str, metadata_path: str = "") -> bytes:
        custom_tag = self._parse_tag_hex(custom_tag_hex)
        custom_payload = self._build_custom_metadata_payload(custom_tag, metadata_path=metadata_path)
        action_label = f"StoreMetadataCustom[{custom_tag.hex().upper()}]"
        return self._run_metadata_command(custom_payload, custom_tag, action_label)

    def store_metadata_custom_all(self, metadata_path: str = "") -> list[tuple[str, bytes]]:
        """Write all custom metadata tags from *payload* into the metadata store."""
        custom_entries = self.load_enabled_custom_metadata_entries(override_path=metadata_path)
        if len(custom_entries) == 0:
            raise ValueError(
                "No enabled custom metadata tags found. "
                "Set custom.<group>.<tag>.include=true in metadata JSON."
            )
        responses: list[tuple[str, bytes]] = []
        for entry in custom_entries:
            tag_hex = str(entry.get("tag_hex", "")).upper()
            value_hex = str(entry.get("value_hex", "")).upper()
            if len(tag_hex) == 0:
                continue
            payload = self._wrap_tlv(bytes.fromhex(tag_hex), bytes.fromhex(value_hex))
            action_label = f"StoreMetadataCustom[{tag_hex}]"
            response = self._run_metadata_command(payload, bytes.fromhex(tag_hex), action_label)
            responses.append((tag_hex, response))
        return responses

    def _run_profile_state_command(self, identifier: str, command_tag: bytes, action_label: str) -> bytes:
        resolved = self._resolve_profile_target(identifier)
        if resolved is None:
            raise ValueError(f"{action_label} requires <iccid-or-aid-or-alias>.")

        target_tag, target_value_hex = resolved
        target_type = "ICCID"
        if target_tag == self.TAG_AID:
            target_type = "AID"
        self.reset_state()
        self.select_isdr()
        payload = self._build_profile_state_payload(command_tag, target_tag, target_value_hex)
        response = self._send_personalization_store_data(payload, f"LOCAL: {action_label}")

        result_code = self._extract_profile_state_result_code(response, command_tag)
        if result_code is not None and result_code != 0:
            error_text = self._profile_state_error_name(result_code)
            raise RuntimeError(
                f"{action_label} failed for {target_type}={target_value_hex}: "
                f"code=0x{result_code:02X} ({error_text})."
            )

        try:
            self._sync_pending_notifications(response)
        except Exception:
            pass

        return response

    def _resolve_profile_target(self, identifier: str) -> Optional[tuple[bytes, str]]:
        return resolve_profile_target_identifier(
            identifier,
            tag_aid=self.TAG_AID,
            tag_iccid=self.TAG_ICCID,
            resolve_aid_from_alias=self._resolve_aid_from_alias,
            is_hex=self._is_valid_hex,
            extract_decimal_iccid=self._extract_decimal_iccid,
            encode_iccid_for_command=self._encode_iccid_for_command,
            fetch_profiles=self.collect_profile_metadata,
        )

    def _resolve_aid_from_alias(self, alias: str) -> Optional[str]:
        registry_path = ensure_seeded_workspace_file(("SCP03", "aid.txt"), "SCP03", "aid.txt")
        if os.path.isfile(registry_path) is False:
            return None

        try:
            with open(registry_path, "r", encoding="utf-8") as aid_file:
                for line in aid_file:
                    clean_line = line.split("#", 1)[0].strip()
                    if len(clean_line) == 0:
                        continue
                    if ":" not in clean_line:
                        continue
                    left, right = clean_line.split(":", 1)
                    alias_value = left.strip().upper()
                    aid_hex = right.strip().upper()
                    if alias_value != alias:
                        continue
                    if self._is_valid_hex(aid_hex) is False:
                        return None
                    return aid_hex
        except Exception:
            return None

        return None

    def _profile_metadata_from_parsed(self, parsed: Dict[int, Any]) -> Optional[ProfileMetadataView]:
        iccid_bytes = self._get_tag(parsed, 0x5A)
        if not isinstance(iccid_bytes, bytes):
            return None

        iccid = self._swap_nibbles(iccid_bytes.hex().upper())

        aid = ""
        aid_bytes = self._get_tag(parsed, 0x4F) or self._get_tag(parsed, 0xA0)
        if isinstance(aid_bytes, bytes):
            aid = aid_bytes.hex().upper()

        state = "DISABLED"
        state_bytes = self._get_tag(parsed, 0x9F70)
        if isinstance(state_bytes, bytes):
            state_value = int.from_bytes(state_bytes, "big")
            if state_value == 1:
                state = "ENABLED"

        profile_class = "OPER"
        class_bytes = self._get_tag(parsed, 0x95)
        if isinstance(class_bytes, bytes):
            class_value = int.from_bytes(class_bytes, "big")
            class_map = {0: "TEST", 1: "PROV", 2: "OPER"}
            profile_class = class_map.get(class_value, "OPER")

        nickname = self._decode_optional_text(self._get_tag(parsed, 0x90))
        service_provider = self._decode_optional_text(self._get_tag(parsed, 0x91))
        profile_name = self._decode_optional_text(self._get_tag(parsed, 0x92))

        ppr_hex = ""
        ppr_bytes = self._get_tag(parsed, 0x99)
        if isinstance(ppr_bytes, bytes):
            ppr_hex = ppr_bytes.hex().upper()

        return ProfileMetadataView(
            iccid=iccid,
            aid=aid,
            state=state,
            profile_class=profile_class,
            nickname=nickname,
            service_provider=service_provider,
            profile_name=profile_name,
            profile_policy_rules_hex=ppr_hex,
        )

    def _extract_nested_additional_smds(self, parsed_tlv: Dict[int, Any]) -> List[str]:
        output: List[str] = []
        if 0xA2 not in parsed_tlv:
            return output

        values = parsed_tlv[0xA2]
        blobs: List[bytes] = []
        if isinstance(values, list):
            for item in values:
                if isinstance(item, bytes):
                    blobs.append(item)
        elif isinstance(values, bytes):
            blobs.append(values)

        for blob in blobs:
            nested = self._parse_tlv_simple(blob)
            nested_values = self._extract_text_values(nested, 0x82)
            if len(nested_values) > 0:
                output.extend(nested_values)
            else:
                output.append(self._decode_text_or_hex(blob))
        return output

    def _extract_text_values(self, parsed_tlv: Dict[int, Any], tag: int) -> List[str]:
        if tag not in parsed_tlv:
            return []

        raw_values = parsed_tlv[tag]
        normalized: List[bytes] = []
        if isinstance(raw_values, list):
            for item in raw_values:
                if isinstance(item, bytes):
                    normalized.append(item)
        elif isinstance(raw_values, bytes):
            normalized.append(raw_values)

        output: List[str] = []
        for value in normalized:
            output.append(self._decode_text_or_hex(value))
        return output

    @staticmethod
    def _dedupe_preserving_order(values: List[str]) -> List[str]:
        seen: Dict[str, bool] = {}
        output: List[str] = []
        for value in values:
            if value in seen:
                continue
            seen[value] = True
            output.append(value)
        return output

    def _get_tag(self, parsed: Dict[int, Any], tag: int, default: Any = None) -> Any:
        if tag not in parsed:
            return default
        value = parsed[tag]
        if isinstance(value, list):
            if len(value) == 0:
                return default
            return value[0]
        return value

    def _parse_tlv_simple(self, data: bytes) -> Dict[int, Any]:
        parsed: Dict[int, Any] = {}
        index = 0
        while index < len(data):
            try:
                tag_bytes, value, _, next_offset = self._read_tlv(data, index)
            except Exception:
                break
            tag = int.from_bytes(tag_bytes, "big")
            index = next_offset

            if tag in parsed:
                existing = parsed[tag]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    parsed[tag] = [existing, value]
            else:
                parsed[tag] = value

        return parsed

    @staticmethod
    def _swap_nibbles(text: str) -> str:
        output = []
        index = 0
        while index < len(text):
            if index + 1 < len(text):
                output.append(text[index + 1] + text[index])
            else:
                output.append(text[index])
            index += 2
        return "".join(output).replace("F", "")

    def _decode_optional_text(self, value: Any) -> str:
        if not isinstance(value, bytes):
            return ""
        decoded = self._decode_text_or_hex(value)
        if len(decoded) == 0:
            return ""
        return decoded

    @staticmethod
    def _is_valid_hex(value: str) -> bool:
        if len(value) == 0:
            return False
        if len(value) % 2 != 0:
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return True

    @staticmethod
    def _extract_decimal_iccid(value: str) -> Optional[str]:
        digits = ""
        for char in value:
            if char.isdigit() is False:
                return None
            digits += char
        if len(digits) < 18:
            return None
        return digits

    @staticmethod
    def _encode_iccid_for_command(iccid_digits: str) -> str:
        padded = iccid_digits
        if len(padded) % 2 != 0:
            padded += "F"
        out = ""
        index = 0
        while index < len(padded):
            first = padded[index]
            second = padded[index + 1]
            out += second + first
            index += 2
        return out

    def _build_profile_state_payload(self, command_tag: bytes, target_tag: bytes, value_hex: str) -> bytes:
        value_bytes = bytes.fromhex(value_hex)
        id_tlv = self._wrap_tlv(target_tag, value_bytes)
        if command_tag == self.TAG_DELETE_PROFILE:
            return self._wrap_tlv(command_tag, id_tlv)
        ctx_tlv = self._wrap_tlv(self.TAG_CTX_0, id_tlv)
        refresh_required_tlv = self._wrap_tlv(b"\x81", b"\x00")
        return self._wrap_tlv(command_tag, ctx_tlv + refresh_required_tlv)

    def _run_metadata_command(self, payload: bytes, command_tag: bytes, action_label: str) -> bytes:
        if len(payload) == 0:
            raise ValueError(f"{action_label} payload is empty.")
        self.reset_state()
        self.select_isdr()
        response = self._send_personalization_store_data(payload, f"LOCAL: {action_label}")
        result_code = self._extract_profile_state_result_code(response, command_tag)
        if result_code is not None and result_code != 0:
            error_text = self._profile_state_error_name(result_code)
            raise RuntimeError(
                f"{action_label} failed: code=0x{result_code:02X} ({error_text})."
            )
        return response

    def _build_custom_metadata_payload(self, custom_tag: bytes, metadata_path: str = "") -> bytes:
        custom_entries = self.load_enabled_custom_metadata_entries(override_path=metadata_path)
        custom_tag_hex = custom_tag.hex().upper()
        for entry in custom_entries:
            entry_tag_hex = str(entry.get("tag_hex", "")).upper()
            if entry_tag_hex != custom_tag_hex:
                continue
            value_hex = str(entry.get("value_hex", "")).upper()
            return self._wrap_tlv(custom_tag, bytes.fromhex(value_hex))

        # Backward-compatible fallback: when no custom section row is enabled for this
        # tag, re-tag the generated StoreMetadataRequest (BF25) payload.
        encoded_metadata = self.encode_metadata_asn1(override_path=metadata_path)
        return self._retag_tlv(encoded_metadata, custom_tag)

    def _extract_profile_state_result_code(self, response: bytes, command_tag: bytes) -> Optional[int]:
        if len(response) == 0:
            return None
        try:
            root_tag, root_value, _, _ = self._read_tlv(response, 0)
        except Exception:
            return None

        if root_tag == command_tag:
            return self._extract_result_code_from_tlv_value(root_value)

        if root_tag == self.TAG_RESULT:
            return int.from_bytes(root_value, "big", signed=False)

        return self._extract_result_code_from_tlv_value(response)

    def _extract_result_code_from_tlv_value(self, value: bytes) -> Optional[int]:
        offset = 0
        while offset < len(value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                return None
            if field_tag == self.TAG_RESULT:
                return int.from_bytes(field_value, "big", signed=False)
            offset = next_offset
        return None

    @staticmethod
    def _profile_state_error_name(result_code: int) -> str:
        error_map = {
            1: "Profile Not Found",
            2: "Already in requested state",
            3: "Invalid input parameter",
            7: "Command structure error",
            127: "Undefined error",
        }
        return error_map.get(result_code, "Unknown error")

    @staticmethod
    def _parse_tag_hex(value: str) -> bytes:
        compact = str(value).strip().replace(" ", "").upper()
        if len(compact) == 0:
            raise ValueError("Custom tag must not be empty.")
        if len(compact) % 2 != 0:
            raise ValueError("Custom tag must have even-length hexadecimal encoding.")
        try:
            tag_bytes = bytes.fromhex(compact)
        except ValueError as error:
            raise ValueError(f"Invalid custom tag hex: {value}") from error
        if len(tag_bytes) == 0:
            raise ValueError("Custom tag must not be empty.")
        return tag_bytes

    def _retag_tlv(self, encoded_tlv: bytes, new_tag: bytes) -> bytes:
        current_tag, current_value, _raw, next_offset = self._read_tlv(encoded_tlv, 0)
        if next_offset != len(encoded_tlv):
            raise ValueError(
                f"Cannot re-tag TLV: payload contains trailing bytes after {current_tag.hex().upper()}."
            )
        return self._wrap_tlv(new_tag, current_value)

    def open_session(self, transaction_id_override: Optional[bytes] = None) -> OpenSessionResult:
        """Open an ES10b or ES9+ session to the eUICC or SM-DP+ and return the session handle."""
        self.select_isdr()
        self.get_euicc_info1()
        self.get_euicc_configured_data()
        self.get_euicc_challenge()
        self._ensure_local_material_loaded()

        if self.cfg.USE_EUICC_DEFAULT_DP_ADDRESS:
            default_dp = self._extract_default_dp_address(self.state.configured_data)
            server_address = (default_dp or "").strip() or self.cfg.SERVER_ADDRESS
        else:
            server_address = self.cfg.SERVER_ADDRESS

        server_signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(
            self.state.card_challenge,
            server_address,
            transaction_id=transaction_id_override,
        )
        server_signature1 = CryptoEngine.sign_asn1(server_signed1, self._key_auth)

        ctx_params = {
            "deviceInfo": {
                "tac": self.cfg.TAC,
                "deviceCapabilities": self.cfg.CAPABILITIES,
            }
        }

        payload = PayloadBuilder.build_auth_server(
            signed1=server_signed1,
            signature=server_signature1,
            cert=self._cert_auth,
            ctx_params=ctx_params,
            root_ci_id=self._selected_root_ci_id(),
        )
        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "LOCAL: AuthenticateServer",
            chunk_size=self.cfg.CHUNK_SIZE,
        )
        parsed = self._parse_authenticate_server_response(response)

        self.state.transaction_id = transaction_id
        self.state.server_challenge = server_challenge
        self.state.authenticate_server_request = payload
        self.state.authenticate_server_response = response
        self.state.euicc_signed1 = parsed.euicc_signed1
        self.state.euicc_signature1 = parsed.euicc_signature1
        self.state.session_open = True

        return OpenSessionResult(
            transaction_id=self.state.transaction_id,
            card_challenge=self.state.card_challenge,
            server_challenge=self.state.server_challenge,
            euicc_signed1=self.state.euicc_signed1,
            euicc_signature1=self.state.euicc_signature1,
            authenticate_server_response=self.state.authenticate_server_response,
        )

    def cancel_session(self, reason: int = CANCEL_SESSION_REASON_END_USER_REJECTION) -> bytes:
        """Cancel the current provisioning session and release associated resources."""
        if len(self.state.transaction_id) == 0:
            raise RuntimeError("No active local SCP11 session is available to cancel.")

        payload = encode_cancel_session_request(self.state.transaction_id, int(reason))
        if len(payload) == 0:
            payload = self._wrap_tlv(
                bytes.fromhex("BF41"),
                self._wrap_tlv(b"\x80", self.state.transaction_id)
                + self._wrap_tlv(b"\x81", bytes([int(reason) & 0xFF])),
            )

        apdu = self._build_store_data_apdu(payload)
        response = self.apdu_channel.send(apdu, "LOCAL: CancelSession")
        self.state.cancel_session_response = response
        self.state.session_open = False
        return response

    def close_session(self, reason: int = CANCEL_SESSION_REASON_END_USER_REJECTION) -> bytes:
        if len(self.state.transaction_id) == 0:
            return b""
        return self.cancel_session(reason=reason)

    def prepare_download(self) -> bytes:
        """Issue ES9+.PrepareDownload and return the decoded server response."""
        if self.state.session_open is False:
            raise RuntimeError("No active local SCP11 session. Run OPEN first.")
        if len(self.state.euicc_signature1) == 0:
            raise RuntimeError("Missing euiccSignature1 from AuthenticateServer response.")
        self._ensure_local_material_loaded()
        if self._cert_pb is None or self._key_pb is None:
            raise RuntimeError("DPpb credential required for PrepareDownload.")

        payload = PayloadBuilder.build_prepare_download(
            self.state.transaction_id,
            self.state.euicc_signature1,
            self._cert_pb,
            self._key_pb,
        )
        if len(payload) == 0:
            raise RuntimeError("PrepareDownload payload build failed.")

        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "DOWNLOAD: PrepareDownload",
            chunk_size=self.cfg.CHUNK_SIZE,
        )
        self._parse_prepare_download_response(response)
        self.state.prepare_download_response = response
        return response

    def _parse_prepare_download_response(self, data: bytes) -> None:
        if len(data) < 3 or data[:2] != bytes.fromhex("BF21"):
            return
        try:
            decoded = decode_prepare_download_response(data)
        except Exception:
            decoded = None
        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "downloadResponseError":
                error_code = getattr(choice_value, "downloadErrorCode", None)
                if error_code is None and isinstance(choice_value, dict):
                    error_code = choice_value.get("downloadErrorCode")
                if error_code is not None:
                    detail = describe_sgp22_download_error(int(error_code))
                    msg = f"PrepareDownload refused by card: {detail}"
                    if error_code == 5:
                        msg += (
                            " The local package must carry the same transactionId as the live "
                            "AuthenticateServer and PrepareDownload session. Use a full BPP with "
                            "BF23 tag 0x80, or enable local session-bound BPP generation under "
                            "local_access so BF23 is rebuilt from the active session."
                        )
                    raise PermissionError(msg)
                raise PermissionError("PrepareDownload refused by card (error response).")
        root_tag, root_value, _, _ = self._read_tlv(data, 0)
        if root_tag != bytes.fromhex("BF21"):
            return
        if len(root_value) == 0:
            return
        choice_tag, _, _, _ = self._read_tlv(root_value, 0)
        if choice_tag in (b"\xA1", b"\x61"):
            raise PermissionError("PrepareDownload refused by card (error choice).")

    def run_load_profile_chain(self, profile_path: str = "") -> bytes:
        """
        Run the full load-profile flow: open session, PrepareDownload, LoadBoundProfilePackage,
        then close session. Same pattern as relay — each command opens, does work, closes.
        Transaction ID and card expectations: we use the transaction ID from the BPP file
        (BF23) so that AuthenticateServer, PrepareDownload and the loaded BPP all match;
        otherwise the card will reject the load.
        """
        # Each LOAD-PROFILE attempt must start from a fresh SCP11 session context.
        # Reusing a previous PrepareDownload response mixes old transaction/session
        # material with the new AuthenticateServer exchange and leads to
        # invalidTransactionId on retries inside the same shell session.
        self.reset_state()
        resolved = self.resolve_profile_path(override_path=profile_path)
        if len(resolved) == 0:
            raise FileNotFoundError(
                "No profile file resolved. Set PROFILE or place one file in profile directory."
            )
        with open(resolved, "rb") as fh:
            bpp_bytes = fh.read()
        if len(bpp_bytes) == 0:
            raise ValueError("Profile file is empty.")
        bpp_bytes = self._decode_profile_bytes(bpp_bytes)
        self.state.upp_protected_command_descriptions = []
        self.state.last_bpp_layout_lines = []
        self.state.last_bpp_crypto_debug_lines = []
        self.state.last_load_bpp_response = b""
        self.state.load_notifications_synced = False
        transaction_id_override = (
            self._extract_transaction_id_from_bpp(bpp_bytes)
            if self.cfg.USE_BPP_TRANSACTION_ID
            else None
        )
        defer_bind = False
        build_session_bound_bpp = False
        if self.cfg.USE_BPP_TRANSACTION_ID and (
            transaction_id_override is None or len(transaction_id_override) == 0
        ):
            if self.cfg.GENERATE_SESSION_BOUND_BPP:
                build_session_bound_bpp = True
            elif self.cfg.WRAP_SEGMENT_IN_BOOTSTRAP:
                defer_bind = True
            else:
                raise ValueError(
                    "BPP file has no transaction ID (expected BF36/BF23 or BF23 with tag 0x80). "
                    "Provide a session-bound local package source and metadata, enable "
                    "GENERATE_SESSION_BOUND_BPP, or set WRAP_SEGMENT_IN_BOOTSTRAP=True "
                    "to use the legacy synthetic wrapper."
                )
        # Four-phase pre-install pipeline (open → prepare → bind/wrap →
        # describe) plus an install phase whose step count is
        # discovered from the BPP. ``_load_profile_from_bytes``
        # expands the total to cover every per-segment store-data plus
        # one trailing "sync notifications" step so the sticky footer
        # stays in motion throughout the whole install rather than
        # sitting at 100 % during LoadBoundProfilePackage.
        with progress_session("Local load profile", total=4) as bar:
            bar.advance("open session")
            try:
                self.open_session(
                    transaction_id_override=None if (defer_bind or build_session_bound_bpp) else transaction_id_override
                )
                bar.advance("prepare download")
                if len(self.state.prepare_download_response) == 0:
                    self.prepare_download()
                bar.advance("bind / wrap bpp")
                if build_session_bound_bpp:
                    bpp_bytes = self._build_session_bound_profile_package(bpp_bytes)
                elif defer_bind:
                    bpp_bytes, _ = self._wrap_segment_in_bootstrap(
                        bpp_bytes,
                        transaction_id=self.state.transaction_id,
                    )
                bar.advance("describe bpp layout")
                self.state.last_bpp_layout_lines = self._describe_bpp_layout(bpp_bytes)
                return self._load_profile_from_bytes(bpp_bytes, progress_bar=bar)
            finally:
                if self.state.session_open:
                    try:
                        if self.state.load_notifications_synced is False:
                            self._sync_pending_notifications(self.state.last_load_bpp_response)
                    except Exception:
                        pass
                    self.close_session()

    def _extract_transaction_id_from_bpp(self, bpp_bytes: bytes) -> Optional[bytes]:
        """Extract transactionId (tag 0x80) from BF23 so session can use it.
        Tries standard BPP (BF36 then BF23) first; then scans for BF23 anywhere (e.g. segment)."""
        if len(bpp_bytes) < 4:
            return None
        bf23_tag = bytes.fromhex("BF23")
        try:
            root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        except ValueError:
            root_tag = None
            root_value = b""
        if root_tag == bytes.fromhex("BF36") and len(root_value) >= 2:
            try:
                child_tag, bf23_value, _, _ = self._read_tlv(root_value, 0)
            except ValueError:
                bf23_value = b""
            if child_tag == bf23_tag and len(bf23_value) > 0:
                found = self._transaction_id_from_bf23_value(bf23_value)
                if found is not None:
                    return found
        idx = 0
        while idx < len(bpp_bytes) - 2:
            if bpp_bytes[idx : idx + 2] == bf23_tag:
                try:
                    _, bf23_value, _, _ = self._read_tlv(bpp_bytes, idx)
                except ValueError:
                    idx += 1
                    continue
                found = self._transaction_id_from_bf23_value(bf23_value)
                if found is not None:
                    return found
            idx += 1
        return None

    def _transaction_id_from_bf23_value(self, bf23_value: bytes) -> Optional[bytes]:
        """Return transactionId (tag 0x80) from BF23 value, or None."""
        offset = 0
        while offset < len(bf23_value):
            try:
                tag_bytes, value, _, next_offset = self._read_tlv(bf23_value, offset)
            except ValueError:
                break
            if tag_bytes == b"\x80" and len(value) > 0:
                return value
            offset = next_offset
        return None

    def _wrap_segment_in_bootstrap(
        self, segment_bytes: bytes, transaction_id: Optional[bytes] = None
    ) -> tuple[bytes, bytes]:
        """Wrap segment-only content in a minimal BPP (BF36 + BF23).
        If transaction_id is given (e.g. from session), use it; else generate one.
        Returns (full_bpp_bytes, transaction_id)."""
        if transaction_id is None or len(transaction_id) == 0:
            transaction_id = os.urandom(16)
        else:
            transaction_id = bytes(transaction_id)[:16]
            if len(transaction_id) < 16:
                transaction_id = transaction_id + b"\x00" * (16 - len(transaction_id))
        bf23_value = self._wrap_tlv(b"\x80", transaction_id)
        bf23_tlv = self._wrap_tlv(bytes.fromhex("BF23"), bf23_value)
        bf36_value = bf23_tlv + segment_bytes
        bpp_bytes = self._wrap_tlv(bytes.fromhex("BF36"), bf36_value)
        return bpp_bytes, transaction_id

    def _build_session_bound_profile_package(self, upp_bytes: bytes) -> bytes:
        with _temporary_session_bound_dependency_stubs():
            _ensure_pysim_session_bound_support()
            if BoundProfilePackage is None or UnprotectedProfilePackage is None:
                raise RuntimeError(
                    "pySim session-bound BPP generation is unavailable in this environment. "
                    + _describe_pysim_session_bound_support()
                    + " Install `pySim` into the active interpreter (pip install pySim), "
                    + "clone the upstream tree at `<YggdraSIM>/pysim/` "
                    + "(git clone https://gitlab.com/osmocom/pysim.git pysim), "
                    + "or supply a pre-built BF36 Bound Profile Package as the profile input."
                )
            if len(upp_bytes) == 0:
                raise ValueError("Local profile payload is empty.")
            if self._cert_pb is None or self._key_pb is None:
                raise RuntimeError("DPpb credential required for local session-bound BPP generation.")

            prepare_download = self._decode_prepare_download_response_ok(self.state.prepare_download_response)
            euicc_otpk = bytes(prepare_download.get("euiccOtpk", b""))
            transaction_id = bytes(prepare_download.get("transactionId", b"")) or bytes(self.state.transaction_id)

            if len(transaction_id) == 0:
                raise RuntimeError("PrepareDownload did not yield a transactionId for local BPP generation.")
            if len(euicc_otpk) == 0:
                raise RuntimeError("PrepareDownload did not yield euiccOtpk for local BPP generation.")

            self._persist_pre_bsp_payload_debug(upp_bytes)
            profile_metadata = self._build_pysim_profile_metadata(upp_bytes)
            rsp_session = self._build_local_rsp_session(
                transaction_id=transaction_id,
                euicc_otpk=euicc_otpk,
                profile_metadata=profile_metadata,
            )
            a3_plaintext_chunk_size = self._resolve_a3_plaintext_chunk_size()
            use_ppk_replace_session_keys = self._should_use_ppk_replace_session_keys_experiment(
                a3_plaintext_chunk_size
            )
            self.state.upp_protected_command_descriptions = self._describe_upp_protected_command_sequence(
                upp_bytes,
                chunk_size=a3_plaintext_chunk_size,
            )
            self.state.last_bpp_crypto_debug_lines = self._describe_bpp_crypto_debug(
                upp_bytes,
                rsp_session,
                profile_metadata,
                a3_plaintext_chunk_size=a3_plaintext_chunk_size,
                use_ppk_replace_session_keys=use_ppk_replace_session_keys,
            )
            dp_pb = self._build_pysim_dp_pb_pair()
            if a3_plaintext_chunk_size > 0:
                bpp_bytes = self._encode_bound_profile_package_with_custom_a3_chunk_size(
                    upp_bytes,
                    rsp_session,
                    profile_metadata,
                    dp_pb,
                    a3_plaintext_chunk_size,
                )
                self._update_bpp_structure_debug(bpp_bytes)
                return bpp_bytes
            try:
                upp = UnprotectedProfilePackage.from_der(bytes(upp_bytes), metadata=profile_metadata)
            except Exception as error:
                detail = self._describe_exception_chain(error)
                raise ValueError(
                    f"Profile decode failed while building the local session-bound BPP: {detail}"
                ) from error
            if use_ppk_replace_session_keys:
                ppk_enc = bytes(getattr(self.cfg, "BPP_PPK_ENC", b""))
                ppk_mac = bytes(getattr(self.cfg, "BPP_PPK_MAC", b""))
                if len(ppk_enc) != 16 or len(ppk_mac) != 16:
                    raise ValueError("BPP_PPK_ENC and BPP_PPK_MAC must both be 16 bytes.")
                ppk_bsp = BspInstance(ppk_enc, ppk_mac, bytes(16))
                ppp = ProtectedProfilePackage.from_upp(upp, ppk_bsp)
                bpp_bytes = BoundProfilePackage.from_ppp(ppp).encode(rsp_session, dp_pb)
            else:
                bpp_bytes = BoundProfilePackage.from_upp(upp).encode(rsp_session, dp_pb)
            self._update_bpp_structure_debug(bpp_bytes)
            return bpp_bytes

    def _persist_pre_bsp_payload_debug(self, upp_bytes: bytes) -> None:
        self.state.last_pre_bsp_payload_bin_path = ""
        self.state.last_pre_bsp_payload_hex_path = ""
        debug_dir = str(getattr(self.cfg, "DEBUG_DIR", "")).strip()
        if len(debug_dir) == 0:
            return
        try:
            os.makedirs(debug_dir, exist_ok=True)
            bin_path = os.path.join(debug_dir, "_debug_pre_bsp_payload.bin")
            hex_path = os.path.join(debug_dir, "_debug_pre_bsp_payload.txt")
            with open(bin_path, "wb") as fh:
                fh.write(bytes(upp_bytes))
            with open(hex_path, "w", encoding="ascii") as fh:
                fh.write(bytes(upp_bytes).hex().upper())
                fh.write("\n")
        except Exception:
            return
        self.state.last_pre_bsp_payload_bin_path = os.path.abspath(bin_path)
        self.state.last_pre_bsp_payload_hex_path = os.path.abspath(hex_path)

    def _resolve_a3_plaintext_chunk_size(self) -> int:
        configured = int(getattr(self.cfg, "BPP_A3_PLAINTEXT_CHUNK_SIZE", 0) or 0)
        if configured <= 0:
            return 0
        default_chunk_size = self._upp_protected_chunk_size()
        if configured > default_chunk_size:
            return default_chunk_size
        return configured

    def _should_use_ppk_replace_session_keys_experiment(self, a3_plaintext_chunk_size: int) -> bool:
        if bool(getattr(self.cfg, "BPP_USE_PPK_REPLACE_SESSION_KEYS", False)) is False:
            return False
        if a3_plaintext_chunk_size > 0:
            return False
        if ProtectedProfilePackage is None:
            return False
        return True

    def _bpp_initial_block_nr(self) -> int:
        value = int(getattr(self.cfg, "BPP_INITIAL_BLOCK_NR", 1000))
        if value < 1:
            raise ValueError("BPP_INITIAL_BLOCK_NR must be a positive integer.")
        return value

    def _build_session_bsp(self, rsp_session: Any):
        _ensure_pysim_session_bound_support()
        if BspInstance is None:
            raise RuntimeError("pySim eSIM BSP support is unavailable.")
        if not isinstance(getattr(rsp_session, "eid", None), str) or len(rsp_session.eid) == 0:
            raise RuntimeError("RspSessionState EID is missing for BSP construction.")
        bsp = BspInstance.from_kdf(
            bytes(rsp_session.shared_secret),
            0x88,
            16,
            bytes(rsp_session.host_id),
            bytes.fromhex(rsp_session.eid),
        )
        bsp.c_algo.block_nr = self._bpp_initial_block_nr()
        self._snapshot_session_bsp(bsp)
        return bsp

    def _snapshot_session_bsp(self, bsp: Any) -> None:
        """Store BSP key material on the session for keybag export.

        Called whenever `_build_session_bsp` constructs a fresh BSP
        instance; the shell's `EXPORT-KEYBAG` command reads these
        fields to avoid re-running the full SCP11 handshake solely to
        dump the derived keys.
        """
        c_algo = getattr(bsp, "c_algo", None)
        m_algo = getattr(bsp, "m_algo", None)
        if c_algo is None or m_algo is None:
            return
        s_enc_bytes = bytes(getattr(c_algo, "s_enc", b"") or b"")
        s_mac_bytes = bytes(getattr(m_algo, "s_mac", b"") or b"")
        if len(s_enc_bytes) == 0 or len(s_mac_bytes) == 0:
            return
        mac_chain_bytes = bytes(getattr(m_algo, "mac_chain", b"\x00" * 16) or b"\x00" * 16)
        block_nr = int(getattr(c_algo, "block_nr", 0) or 0)
        self.state.last_bsp_s_enc_hex = s_enc_bytes.hex().upper()
        self.state.last_bsp_s_mac_hex = s_mac_bytes.hex().upper()
        self.state.last_bsp_mac_chain_hex = mac_chain_bytes.hex().upper()
        self.state.last_bsp_block_nr = block_nr
        self.state.last_bsp_protocol = "scp11c"
        self.state.last_bsp_aid_hex = bytes(self.cfg.AID_ISD_R or b"").hex().upper()

    @staticmethod
    def _advance_session_bsp_to_a3_prelude(session_bsp: Any, profile_metadata: Any) -> bytes:
        _ensure_pysim_session_bound_support()
        try:
            from pySim.esim import rsp as pysim_rsp
        except Exception as error:
            raise RuntimeError("pySim RSP ASN.1 helpers are unavailable.") from error
        configure_isdp = pysim_rsp.asn1.encode("ConfigureISDPRequest", {})
        store_metadata = profile_metadata.gen_store_metadata_request()
        session_bsp.encrypt_and_mac(0x87, configure_isdp)
        session_bsp.mac_only(0x88, store_metadata)
        return bytes(session_bsp.m_algo.mac_chain)

    @staticmethod
    def _advance_session_bsp_through_a2(
        session_bsp: Any, ppk_enc: bytes, ppk_mac: bytes, initial_mcv: bytes
    ) -> None:
        _ensure_pysim_session_bound_support()
        if gen_replace_session_keys is None:
            raise RuntimeError("pySim gen_replace_session_keys is unavailable.")
        rsk_bin = gen_replace_session_keys(ppk_enc, ppk_mac, initial_mcv)
        session_bsp.encrypt_and_mac(0x87, rsk_bin)

    def _describe_upp_protected_command_sequence(
        self,
        profile_bytes: bytes,
        chunk_size: Optional[int] = None,
    ) -> list[str]:
        if chunk_size is None or chunk_size <= 0:
            try:
                chunk_size = self._upp_protected_chunk_size()
            except Exception:
                return []
        if chunk_size <= 0 or len(profile_bytes) == 0:
            return []

        element_ranges = self._describe_upp_element_ranges(profile_bytes)
        descriptions: list[str] = []
        start = 0
        chunk_index = 1
        while start < len(profile_bytes):
            end = min(start + chunk_size, len(profile_bytes))
            overlaps = []
            for element_start, element_end, label in element_ranges:
                if element_end <= start or element_start >= end:
                    continue
                overlaps.append(label)
            overlap_text = ", ".join(overlaps)
            summary = f"plaintext[{start}:{end}]"
            if len(overlap_text) > 0:
                summary += f" overlaps {overlap_text}"
            descriptions.append(summary)
            start = end
            chunk_index += 1
        return descriptions

    @staticmethod
    def _upp_protected_chunk_size() -> int:
        _ensure_pysim_session_bound_support()
        if BspInstance is None:
            raise RuntimeError("pySim eSIM support is unavailable.")
        return int(BspInstance(b"\x00" * 16, b"\x11" * 16, b"\x22" * 16).max_payload_size)

    def _describe_upp_element_ranges(self, profile_bytes: bytes) -> list[tuple[int, int, str]]:
        raw_elements: list[tuple[int, int, bytes, bytes]] = []
        offset = 0
        while offset < len(profile_bytes):
            try:
                tag_bytes, _value, raw_tlv, next_offset = self._read_tlv(profile_bytes, offset)
            except Exception:
                break
            raw_elements.append((offset, next_offset, tag_bytes, raw_tlv))
            offset = next_offset

        labels = self._describe_upp_element_labels(bytes(profile_bytes), raw_elements)

        ranges: list[tuple[int, int, str]] = []
        for index, (start_offset, next_offset, tag_bytes, _raw_tlv) in enumerate(raw_elements):
            label = f"TLV[{index + 1}] {tag_bytes.hex().upper()}"
            if index < len(labels) and len(labels[index]) > 0:
                label += f" {labels[index]}"
            ranges.append((start_offset, next_offset, label))
        return ranges

    def _describe_upp_element_labels(
        self,
        profile_bytes: bytes,
        raw_elements: list[tuple[int, int, bytes, bytes]],
    ) -> list[str]:
        labels = ["" for _ in raw_elements]
        _ensure_pysim_session_bound_support()
        if pysim_saip is None:
            return labels

        # pySim's SAIP decoder can loop on production-sized UPPs and it holds
        # the GIL during the walk, so a background thread does not reliably
        # reclaim CPU. The full decode is therefore gated behind an opt-in
        # env flag; the default label path keeps the console responsive by
        # relying on whatever the per-element decode below can recover.
        timeout_seconds = _resolve_saip_decode_timeout_seconds()

        if _full_saip_decode_enabled():
            def _decode_profile_element_sequence(raw: bytes) -> list[Any]:
                return list(pysim_saip.ProfileElementSequence.from_der(raw))

            pes = _run_with_timeout(
                _decode_profile_element_sequence,
                (bytes(profile_bytes),),
                timeout_seconds=timeout_seconds,
            )
            if not isinstance(pes, list):
                pes = []
            for index, pe in enumerate(pes[: len(labels)]):
                labels[index] = self._format_profile_element_label(pe)

        profile_element_cls = getattr(pysim_saip, "ProfileElement", None)
        if profile_element_cls is None:
            return labels

        # Per-element decoding is the second chance to label TLVs that the
        # whole-sequence decode could not place. Each individual decode is
        # timeout-guarded *and* the whole loop shares a single wall-clock
        # budget so a profile that slowly bleeds the decoder (a handful of
        # seconds per element) cannot stall the operator console. The
        # budget is intentionally generous enough for mocked test doubles
        # to label a dozen or so elements without tripping it.
        per_element_timeout = max(0.5, timeout_seconds / 4.0)
        total_budget_seconds = max(1.0, timeout_seconds / 2.0)
        loop_deadline = time.monotonic() + total_budget_seconds
        for index, (_start, _end, _tag_bytes, raw_tlv) in enumerate(raw_elements):
            if len(labels[index]) > 0:
                continue
            if time.monotonic() >= loop_deadline:
                break
            pe = _run_with_timeout(
                profile_element_cls.from_der,
                (raw_tlv,),
                timeout_seconds=per_element_timeout,
            )
            if pe is None:
                continue
            labels[index] = self._format_profile_element_label(pe)
        return labels

    @staticmethod
    def _format_profile_element_label(pe: Any) -> str:
        pe_type = str(getattr(pe, "type", "") or "").strip()
        header_name = str(getattr(pe, "header_name", "") or "").strip()
        template_id = str(getattr(pe, "templateID", "") or "").strip()
        label = pe_type or header_name or "profileElement"
        if len(template_id) > 0:
            label += f" ({template_id})"
        return label

    def _describe_bpp_crypto_debug(
        self,
        profile_bytes: bytes,
        rsp_session: Any,
        profile_metadata: Any,
        a3_plaintext_chunk_size: int = 0,
        use_ppk_replace_session_keys: bool = False,
    ) -> list[str]:
        _ensure_pysim_session_bound_support()
        if BspInstance is None:
            return []
        if rsp_session is None:
            return []
        shared_secret = getattr(rsp_session, "shared_secret", None)
        host_id = getattr(rsp_session, "host_id", None)
        eid = getattr(rsp_session, "eid", None)
        if not isinstance(shared_secret, bytes) or len(shared_secret) == 0:
            return []
        if not isinstance(host_id, bytes) or len(host_id) == 0:
            return []
        if not isinstance(eid, str) or len(eid) == 0:
            return []

        try:
            from pySim.esim import rsp as pysim_rsp
        except Exception:
            return []

        try:
            session_bsp = self._build_session_bsp(rsp_session)
            configure_isdp = pysim_rsp.asn1.encode("ConfigureISDPRequest", {})
            store_metadata = profile_metadata.gen_store_metadata_request()
        except Exception:
            return []

        lines: list[str] = []
        lines.append(
            "BSP keys "
            f"s_enc={session_bsp.c_algo.s_enc.hex().upper()} "
            f"s_mac={session_bsp.m_algo.s_mac.hex().upper()} "
            f"initial_mcv={session_bsp.m_algo.mac_chain.hex().upper()}"
        )
        if len(self.state.last_pre_bsp_payload_bin_path) > 0:
            lines.append(
                "Pre-BSP payload "
                f"bin={self.state.last_pre_bsp_payload_bin_path} "
                f"hex={self.state.last_pre_bsp_payload_hex_path} "
                f"sha256={hashlib.sha256(profile_bytes).hexdigest().upper()}"
            )

        session_bsp.encrypt_and_mac(0x87, configure_isdp)
        session_bsp.mac_only(0x88, store_metadata)
        active_bsp = session_bsp
        prelude_prefix = "A3 prelude"
        if use_ppk_replace_session_keys:
            try:
                ppk_enc = bytes(getattr(self.cfg, "BPP_PPK_ENC", b""))
                ppk_mac = bytes(getattr(self.cfg, "BPP_PPK_MAC", b""))
                if len(ppk_enc) != 16 or len(ppk_mac) != 16:
                    raise ValueError("BPP_PPK_ENC and BPP_PPK_MAC must both be 16 bytes.")
                ppk_initial_mcv = bytes(16)
                self._advance_session_bsp_through_a2(session_bsp, ppk_enc, ppk_mac, ppk_initial_mcv)
                active_bsp = BspInstance(ppk_enc, ppk_mac, ppk_initial_mcv)
                active_bsp.c_algo.block_nr = int(session_bsp.c_algo.block_nr)
            except Exception:
                active_bsp = session_bsp
                use_ppk_replace_session_keys = False
            else:
                lines.append(
                    "A2 replaceSessionKeys "
                    f"ppk_enc={active_bsp.c_algo.s_enc.hex().upper()} "
                    f"ppk_mac={active_bsp.m_algo.s_mac.hex().upper()} "
                    f"initial_mcv={active_bsp.m_algo.mac_chain.hex().upper()}"
                )
                prelude_prefix = "A3 prelude ppk"
        lines.append(
            f"{prelude_prefix} "
            f"chunk_size={int(a3_plaintext_chunk_size or active_bsp.max_payload_size)} "
            f"block_nr={int(active_bsp.c_algo.block_nr)} "
            f"mac_chain={active_bsp.m_algo.mac_chain.hex().upper()}"
        )

        chunk_size = int(a3_plaintext_chunk_size or active_bsp.max_payload_size)
        descriptions = self._describe_upp_protected_command_sequence(
            profile_bytes,
            chunk_size=chunk_size,
        )
        start = 0
        member_index = 1
        while start < len(profile_bytes):
            end = min(start + chunk_size, len(profile_bytes))
            plaintext = bytes(profile_bytes[start:end])
            block_nr_before = int(active_bsp.c_algo.block_nr)
            mac_chain_before = active_bsp.m_algo.mac_chain.hex().upper()
            protected_member = active_bsp.encrypt_and_mac_one(0x86, plaintext)
            block_nr_after = int(active_bsp.c_algo.block_nr)
            mac_chain_after = active_bsp.m_algo.mac_chain.hex().upper()

            try:
                member_tag, member_value, _, _ = self._read_tlv(protected_member, 0)
                member_tag_text = member_tag.hex().upper()
                member_value_length = len(member_value)
            except Exception:
                member_tag_text = "?"
                member_value_length = 0

            line = (
                f"A3[{member_index}] "
                f"plain={len(plaintext)} "
                f"plain_sha256={hashlib.sha256(plaintext).hexdigest().upper()} "
                f"protected={len(protected_member)} "
                f"protected_tag={member_tag_text} "
                f"protected_value={member_value_length} "
                f"block_nr={block_nr_before}->{block_nr_after} "
                f"mac_chain={mac_chain_before}->{mac_chain_after}"
            )
            if member_index - 1 < len(descriptions):
                line += f" {descriptions[member_index - 1]}"
            lines.append(line)
            start = end
            member_index += 1
        return lines

    def _encode_bound_profile_package_with_custom_a3_chunk_size(
        self,
        upp_bytes: bytes,
        rsp_session: Any,
        profile_metadata: Any,
        dp_pb: Any,
        a3_plaintext_chunk_size: int,
    ) -> bytes:
        _ensure_pysim_session_bound_support()
        try:
            import pySim.esim.es8p as pysim_es8p
            from pySim.esim import rsp as pysim_rsp
        except Exception as error:
            raise RuntimeError(
                "pySim helpers required for custom A3 chunk generation are unavailable."
            ) from error

        if not isinstance(getattr(rsp_session, "eid", None), str) or len(rsp_session.eid) == 0:
            raise RuntimeError("RspSessionState EID is missing for custom A3 chunk generation.")

        bsp = self._build_session_bsp(rsp_session)
        if a3_plaintext_chunk_size > int(bsp.max_payload_size):
            a3_plaintext_chunk_size = int(bsp.max_payload_size)

        def encode_seq(tag: int, sequence: list[bytes]) -> bytes:
            """Encode a value as a DER SEQUENCE by wrapping it with tag 0x30."""
            payload = b"".join(sequence)
            return (
                pysim_es8p.bertlv_encode_tag(tag)
                + pysim_es8p.bertlv_encode_len(len(payload))
                + payload
            )

        iscr = pysim_es8p.gen_initialiseSecureChannel(
            rsp_session.transactionId,
            rsp_session.host_id,
            rsp_session.smdp_otpk,
            rsp_session.euicc_otpk,
            dp_pb,
        )
        configure_isdp = pysim_rsp.asn1.encode("ConfigureISDPRequest", {})
        store_metadata = profile_metadata.gen_store_metadata_request()

        bpp_sequence = pysim_rsp.asn1.encode("InitialiseSecureChannelRequest", iscr)
        bpp_sequence += encode_seq(0xA0, bsp.encrypt_and_mac(0x87, configure_isdp))
        bpp_sequence += encode_seq(0xA1, bsp.mac_only(0x88, store_metadata))

        protected_profile_members: list[bytes] = []
        start = 0
        while start < len(upp_bytes):
            end = min(start + a3_plaintext_chunk_size, len(upp_bytes))
            protected_profile_members.append(
                bsp.encrypt_and_mac_one(0x86, bytes(upp_bytes[start:end]))
            )
            start = end

        bpp_sequence += encode_seq(0xA3, protected_profile_members)
        return self._wrap_tlv(bytes.fromhex("BF36"), bpp_sequence)

    def _build_local_rsp_session(
        self,
        transaction_id: bytes,
        euicc_otpk: bytes,
        profile_metadata: Any,
    ):
        _ensure_pysim_session_bound_support()
        if PySimRspSessionState is None:
            raise RuntimeError("pySim RspSessionState is unavailable in this environment.")
        host_id = bytes(self.cfg.BPP_HOST_ID)
        if len(host_id) == 0:
            raise ValueError("BPP_HOST_ID must not be empty.")
        eid = self._read_card_eid()
        if len(eid) == 0:
            raise RuntimeError("Could not read card EID for local session-bound BPP generation.")

        rsp_session = PySimRspSessionState(
            transaction_id.hex().upper(),
            bytes(self.state.server_challenge),
            self._selected_root_ci_id(),
        )
        rsp_session.eid = eid
        rsp_session.profileMetadata = profile_metadata
        rsp_session.euicc_otpk = bytes(euicc_otpk)
        rsp_session.host_id = host_id
        rsp_session.smdp_ot = ec.generate_private_key(self._key_pb.curve)
        rsp_session.smdp_otpk = rsp_session.smdp_ot.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        euicc_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            rsp_session.smdp_ot.curve,
            rsp_session.euicc_otpk,
        )
        rsp_session.shared_secret = rsp_session.smdp_ot.exchange(ec.ECDH(), euicc_public_key)
        return rsp_session

    def _build_pysim_dp_pb_pair(self):
        _ensure_pysim_session_bound_support()
        if CertAndPrivkey is None:
            raise RuntimeError("pySim certificate wrapper is unavailable in this environment.")
        if self._cert_pb is None or self._key_pb is None:
            raise RuntimeError("DPpb credential is not loaded.")
        certificate = crypto_x509.load_der_x509_certificate(self._cert_pb)
        return CertAndPrivkey(cert=certificate, priv_key=self._key_pb)

    def _build_pysim_profile_metadata(self, profile_bytes: bytes):
        _ensure_pysim_session_bound_support()
        if ProfileMetadata is None:
            raise RuntimeError("pySim profile metadata builder is unavailable in this environment.")
        metadata = self._build_effective_metadata_document(profile_bytes)
        profile = metadata.get("profile", {})
        operator = metadata.get("operator", {})
        notifications = metadata.get("notification_events", {})

        iccid = self._normalize_hex_string(profile.get("iccid"))
        if len(iccid) == 0:
            raise ValueError("Metadata field profile.iccid must not be empty for local BPP generation.")
        if len(iccid) % 2 != 0:
            iccid += "F"

        # PE-Header stores the ICCID in straight BCD (high nibble first).
        # StoreMetadataRequest Iccid is defined as "ICCID as coded in EFiccid"
        # (SGP.22 rsp.asn, tag 5A), which is TS 102.221 BCD with swapped
        # nibbles (low nibble first).  Mirror what osmo-smdpp / pySim does:
        #   iccid_bin = h2b(swap_nibbles(iccid_str))
        iccid_bin = self._swap_bcd_nibbles(bytes.fromhex(iccid))

        spn = str(operator.get("name", "")).strip()
        if len(spn) == 0:
            raise ValueError("Metadata field operator.name must not be empty for local BPP generation.")

        profile_name = str(profile.get("name", "")).strip() or str(profile.get("profile_type", "")).strip()
        if len(profile_name) == 0:
            raise ValueError(
                "Metadata field profile.name or profile.profile_type must not be empty for local BPP generation."
            )

        profile_metadata = ProfileMetadata(
            iccid_bin=iccid_bin,
            spn=spn,
            profile_name=profile_name,
        )
        notification_address = str(notifications.get("address", "")).strip()
        if len(notification_address) == 0:
            notification_address = self._extract_default_dp_address(self.state.configured_data) or self.cfg.SERVER_ADDRESS
        for event_name in [
            "install",
            "enable",
            "disable",
            "delete",
            "rpm_enable",
            "rpm_disable",
            "rpm_delete",
            "load_rpm_package_result",
        ]:
            if bool(notifications.get(event_name, False)):
                profile_metadata.add_notification(event_name, notification_address)
        return profile_metadata

    def _build_effective_metadata_document(self, profile_bytes: bytes) -> dict[str, Any]:
        derived = self._derive_metadata_document_from_profile(profile_bytes)
        override = self._load_optional_metadata_document()
        return self._merge_metadata_documents(derived, override)

    def _load_optional_metadata_document(self) -> dict[str, Any]:
        override_path = str(self.state.metadata_override_path).strip()
        if len(override_path) > 0:
            return self.load_metadata_document()
        metadata_entries = self._metadata_dir_entries()
        if len(metadata_entries) == 0:
            return {}
        return self._sanitize_default_metadata_override(self.load_metadata_document())

    @staticmethod
    def _sanitize_default_metadata_override(document: dict[str, Any]) -> dict[str, Any]:
        sanitized = LocalIsdrSession._merge_metadata_documents({}, document)
        profile = sanitized.get("profile")
        if isinstance(profile, dict):
            profile.pop("name", None)
            profile.pop("profile_type", None)
            profile.pop("iccid", None)
        operator = sanitized.get("operator")
        if isinstance(operator, dict):
            operator.pop("name", None)
        return sanitized

    def _derive_metadata_document_from_profile(self, profile_bytes: bytes) -> dict[str, Any]:
        _ensure_pysim_session_bound_support()
        profile_name = "Local profile"
        profile_iccid = ""
        # Some UPPs trip full pySim SAIP decoding on later PEs. The header is
        # still the first TLV and already carries the identity fields we need.
        header_profile_name, header_profile_iccid = self._extract_profile_identity_from_header_tlv(profile_bytes)
        if len(header_profile_name) > 0:
            profile_name = header_profile_name
        if len(header_profile_iccid) > 0:
            profile_iccid = header_profile_iccid
        if pysim_saip is not None and _full_saip_decode_enabled():
            # pySim's SAIP ASN.1 decoder has historically looped on certain
            # non-canonical UPP packings; cap the decode at a short budget so
            # the operator console never wedges and the header-TLV identity
            # path still populates the metadata stub. Full-decode is opt-in
            # because the decoder holds the GIL and can starve later callers
            # even when a daemon-thread timeout fires.
            timeout_seconds = _resolve_saip_decode_timeout_seconds()
            pes = _run_with_timeout(
                pysim_saip.ProfileElementSequence.from_der,
                (bytes(profile_bytes),),
                timeout_seconds=timeout_seconds,
            )
            if pes is not None:
                try:
                    header = pes.get_pe_for_type("header")
                    if header is not None and isinstance(header.decoded, dict):
                        decoded_header = header.decoded
                        profile_type = decoded_header.get("profileType", "")
                        if isinstance(profile_type, (bytes, bytearray, memoryview)):
                            decoded_profile_name = self._decode_text_or_hex(bytes(profile_type)).strip()
                        else:
                            decoded_profile_name = str(profile_type or "").strip()
                        profile_name = decoded_profile_name or profile_name
                        iccid_value = decoded_header.get("iccid", b"")
                        if isinstance(iccid_value, (bytes, bytearray, memoryview)) and len(iccid_value) > 0:
                            profile_iccid = self._decode_bcd_digits(bytes(iccid_value))
                except Exception:
                    pass
        return {
            "profile": {
                "name": profile_name,
                "profile_type": profile_name,
                "profile_class": "OPERATIONAL",
                "iccid": profile_iccid,
                "icon": {
                    "type": "NONE",
                    "data_hex": "",
                },
            },
            "operator": {
                "name": profile_name,
                "mcc": "",
                "mnc": "",
                "gid1": "",
                "gid2": "",
            },
            "notification_events": {
                "install": False,
                "enable": True,
                "disable": True,
                "delete": True,
                "rpm_enable": False,
                "rpm_disable": False,
                "rpm_delete": False,
                "load_rpm_package_result": False,
                "address": "",
            },
            "policy_rules": {
                "update_control_forbidden": False,
                "disable_not_allowed": False,
                "delete_not_allowed": False,
            },
        }

    def _extract_profile_identity_from_header_tlv(self, profile_bytes: bytes) -> tuple[str, str]:
        profile_name = ""
        profile_iccid = ""
        try:
            tag_bytes, value, _, _ = self._read_tlv(profile_bytes, 0)
        except Exception:
            return profile_name, profile_iccid
        if tag_bytes != b"\xA0":
            return profile_name, profile_iccid

        offset = 0
        while offset < len(value):
            try:
                child_tag, child_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                break
            if child_tag == b"\x82" and len(profile_name) == 0:
                profile_name = self._decode_text_or_hex(child_value).strip()
            elif child_tag == b"\x83" and len(profile_iccid) == 0:
                profile_iccid = self._decode_bcd_digits(child_value)
            offset = next_offset
        return profile_name, profile_iccid

    @staticmethod
    def _merge_metadata_documents(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        if len(override) == 0:
            return dict(base)
        merged = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = LocalIsdrSession._merge_metadata_documents(merged[key], value)
            else:
                merged[key] = value
        return merged

    @staticmethod
    def _normalize_hex_string(value: Any) -> str:
        text = str(value or "").strip().upper()
        return text.replace(" ", "").replace(":", "").replace("-", "")

    def _read_card_eid(self) -> str:
        aid_ecasd = bytes.fromhex("A0000005591010FFFFFFFF8900000200")
        select_ecasd = bytes([0x00, 0xA4, 0x04, 0x00, len(aid_ecasd)]) + aid_ecasd
        original_selected = self.state.isdr_selected
        try:
            self.apdu_channel.send(select_ecasd, "LOCAL: Select ECASD")
            response = self.apdu_channel.send(bytes.fromhex("80CA005A00"), "LOCAL: GetEID")
        finally:
            if original_selected:
                try:
                    self.select_isdr()
                except Exception:
                    pass
        tag, value, _, _ = self._read_tlv(response, 0)
        if tag != b"\x5A":
            raise ValueError(f"GetEID returned unexpected tag {tag.hex().upper()}.")
        return self._decode_bcd_digits(value)

    def _read_card_ecasd_issuer_identity(self) -> dict[str, str]:
        aid_ecasd = bytes.fromhex("A0000005591010FFFFFFFF8900000200")
        select_ecasd = bytes([0x00, 0xA4, 0x04, 0x00, len(aid_ecasd)]) + aid_ecasd
        original_selected = self.state.isdr_selected
        try:
            self.apdu_channel.send(select_ecasd, "LOCAL: Select ECASD")
            response = self.apdu_channel.send(bytes.fromhex("80CA004200"), "LOCAL: GetIssuerIdentificationNumber")
        finally:
            if original_selected:
                try:
                    self.select_isdr()
                except Exception:
                    pass
        tag, value, _, _ = self._read_tlv(response, 0)
        if tag != b"\x42":
            raise ValueError(
                f"GetIssuerIdentificationNumber returned unexpected tag {tag.hex().upper()}."
            )
        issuer_number = self._decode_bcd_digits(value)
        return infer_ecasd_issuer_identity(issuer_number)

    def _load_profile_from_bytes(
        self,
        bpp_bytes: bytes,
        *,
        progress_bar: Any = None,
    ) -> bytes:
        """
        Run the ES10b LoadBoundProfilePackage loop and the trailing
        notification sync.

        When ``progress_bar`` is an active ``ProgressSession``, the
        caller's total is extended to cover every per-segment
        store-data round plus one final "sync notifications" slot, so
        the footer keeps moving throughout the install instead of
        parking at 100 % while the card chews through the segments.
        """
        if self.state.session_open is False:
            raise RuntimeError("No active local SCP11 session.")
        if len(self.state.prepare_download_response) == 0:
            raise RuntimeError("PrepareDownload not yet done.")
        if len(bpp_bytes) == 0:
            raise ValueError("BPP is empty.")
        self.state.last_bpp_layout_lines = self._describe_bpp_layout(bpp_bytes)
        self._update_bpp_structure_debug(bpp_bytes)
        self.state.bpp_command_descriptions = self._describe_bpp_command_id_sequence(bpp_bytes)
        segments = self._segment_bound_profile_package(bpp_bytes)
        segment_count = len(segments)
        self._progress_expand_for_install(progress_bar, segment_count)
        last_response = b""
        for index, segment in enumerate(segments, start=1):
            self._progress_advance(
                progress_bar,
                f"load segment {index}/{segment_count}",
            )
            last_response = self._send_personalization_store_data(
                segment,
                f"DOWNLOAD: LoadBoundProfilePackage [{index}/{segment_count}]",
            )
            self.state.last_load_bpp_response = last_response
            if self._is_terminal_profile_installation_result(last_response):
                self._progress_coast_remaining_segments(
                    progress_bar,
                    skipped_count=segment_count - index,
                )
                break
        self._progress_advance(progress_bar, "sync notifications")
        self._sync_pending_notifications(last_response)
        self.state.load_notifications_synced = True
        if self._is_failed_profile_installation_result(last_response):
            failure_summary = self._summarize_profile_installation_result(last_response)
            if len(failure_summary) == 0:
                failure_summary = "ProfileInstallationResult reported failure."
            indented_failure_summary = self._indent_text_block(failure_summary, prefix="  ")
            raise RuntimeError(
                f"\n{'=' * 64}\n"
                f"  LOAD-PROFILE FAILED\n"
                f"{indented_failure_summary}\n"
                f"{'=' * 64}"
            )
        return last_response

    @staticmethod
    def _progress_expand_for_install(progress_bar: Any, segment_count: int) -> None:
        """
        Grow the sticky-footer total so the install phase can advance
        once per segment plus one final "sync notifications" step.
        The total is set to ``already_completed + segment_count + 1``
        so the per-segment loop and the trailing sync land at exactly
        100 %.
        """
        if progress_bar is None:
            return
        try:
            completed_so_far = int(getattr(progress_bar, "completed", 0) or 0)
        except Exception:
            completed_so_far = 0
        normalized_segment_count = max(0, int(segment_count))
        new_total = completed_so_far + normalized_segment_count + 1
        try:
            progress_bar.set_total(new_total)
        except Exception:
            pass

    @staticmethod
    def _progress_advance(progress_bar: Any, label: str) -> None:
        if progress_bar is None:
            return
        try:
            progress_bar.advance(label)
        except Exception:
            pass

    @staticmethod
    def _progress_coast_remaining_segments(
        progress_bar: Any, skipped_count: int,
    ) -> None:
        """
        When a terminal ProfileInstallationResult short-circuits the
        loop, fast-forward the bar across the segments we will not be
        sending so the final "sync notifications" advance still lands
        at 100 %.
        """
        if progress_bar is None:
            return
        if skipped_count <= 0:
            return
        try:
            progress_bar.advance("install short-circuit", count=int(skipped_count))
        except Exception:
            pass

    def _sync_pending_notifications(self, initial_response: bytes = b"") -> None:
        seq_numbers: list[int] = []
        inline_notification, inline_seq_number = self._extract_inline_pending_notification(initial_response)
        if len(inline_notification) > 0 and isinstance(inline_seq_number, int):
            seq_numbers.append(inline_seq_number)

        try:
            response = self.apdu_channel.send(
                bytes([0x80, 0xE2, 0x91, 0x00, 0x03]) + bytes.fromhex("BF2800"),
                "LOCAL: ListNotifications",
            )
        except Exception:
            response = b""

        for entry in self._extract_notification_metadata_entries(response):
            seq_number = entry.get("seqNumber")
            if isinstance(seq_number, int) and seq_number not in seq_numbers:
                seq_numbers.append(seq_number)

        for seq_number in seq_numbers:
            self._retrieve_pending_notification(seq_number)
            self._remove_notification_from_list(seq_number)

    def _extract_inline_pending_notification(self, raw_response: bytes) -> tuple[bytes, Optional[int]]:
        if len(raw_response) == 0:
            return b"", None
        try:
            root_tag, _, _, _ = self._read_tlv(raw_response, 0)
        except Exception:
            return b"", None
        if root_tag != bytes.fromhex("BF37"):
            return b"", None
        bf2f_raw = self._find_first_tlv_in_value(raw_response, bytes.fromhex("BF2F"))
        if len(bf2f_raw) == 0:
            return raw_response, None
        return raw_response, self._extract_notification_sequence_from_metadata(bf2f_raw)

    def _extract_notification_metadata_entries(self, raw_response: bytes) -> list[dict[str, Optional[int]]]:
        entries: list[dict[str, Optional[int]]] = []
        if len(raw_response) == 0:
            return entries
        try:
            decoded = decode_list_notification_response(raw_response)
        except Exception:
            decoded = None
        if isinstance(decoded, tuple) is True and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "notificationMetadataList" and isinstance(choice_value, list):
                for entry in choice_value:
                    if isinstance(entry, dict) is False:
                        continue
                    seq_number = entry.get("seqNumber")
                    entries.append(
                        {
                            "seqNumber": int(seq_number) if isinstance(seq_number, int) else None,
                        }
                    )
                return entries
        # pySim decoder returned nothing usable — fall back to manual BER-TLV
        # parsing so that notifications queued on the eUICC are never missed.
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        except Exception:
            return entries
        bf28_tag = bytes.fromhex("BF28")
        bf2b_tag = bytes.fromhex("BF2B")
        if root_tag not in (bf28_tag, bf2b_tag):
            return entries
        bf2f_tag = bytes.fromhex("BF2F")
        seq_tag = bytes.fromhex("80")
        list_value = root_value
        try:
            choice_tag, choice_value, _, _ = self._read_tlv(list_value, 0)
        except Exception:
            return entries
        if choice_tag in (b"\xA0", b"\x60"):
            list_value = choice_value
        inner_offset = 0
        while inner_offset < len(list_value):
            try:
                entry_tag, entry_value, _, next_offset = self._read_tlv(list_value, inner_offset)
            except Exception:
                break
            bf2f_raw = b""
            if entry_tag == bf2f_tag:
                bf2f_raw = list_value[inner_offset:next_offset]
            else:
                bf2f_raw = self._find_first_tlv_in_value(entry_value, bf2f_tag)
            if len(bf2f_raw) > 0:
                seq_raw = self._find_first_tlv_in_value(bf2f_raw, seq_tag)
                seq_number = None
                if len(seq_raw) > 0:
                    try:
                        _, seq_value, _, _ = self._read_tlv(seq_raw, 0)
                        seq_number = int.from_bytes(seq_value, "big")
                    except Exception:
                        pass
                entries.append(
                    {
                        "seqNumber": seq_number,
                    }
                )
            inner_offset = next_offset
        return entries

    def _retrieve_pending_notification(self, seq_number: int) -> bytes:
        payload = self._build_retrieve_notification_request_payload(seq_number)
        try:
            response = self.apdu_channel.send(
                self._build_store_data_apdu(payload),
                f"LOCAL: RetrieveNotification [{seq_number}]",
            )
        except Exception:
            return b""
        return self._extract_pending_notification_payload(response)

    def _build_retrieve_notification_request_payload(self, seq_number: int) -> bytes:
        seq_bytes = self._encode_notification_sequence(seq_number)
        return self._wrap_tlv(
            bytes.fromhex("BF2B"),
            self._wrap_tlv(b"\xA0", self._wrap_tlv(b"\x80", seq_bytes)),
        )

    def _extract_pending_notification_payload(self, raw_response: bytes) -> bytes:
        if len(raw_response) == 0:
            return b""
        try:
            decoded = decode_retrieve_notifications_list_response(raw_response)
        except Exception:
            decoded = None
        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, _choice_value = decoded
            if choice_name == "notificationList":
                try:
                    root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
                    if root_tag != bytes.fromhex("BF2B"):
                        return b""
                    choice_tag, choice_bytes, _, _ = self._read_tlv(root_value, 0)
                    if choice_tag not in [b"\xA0", b"\x60"]:
                        return b""
                    pending_tag, _, pending_raw, _ = self._read_tlv(choice_bytes, 0)
                    if pending_tag in [b"\x30", bytes.fromhex("BF37")]:
                        decode_pending_notification(pending_raw)
                        return pending_raw
                except Exception:
                    return b""
        return b""

    def _remove_notification_from_list(self, seq_number: Optional[int]) -> None:
        if isinstance(seq_number, int) is False:
            return
        try:
            payload = encode_notification_sent_request(seq_number)
        except Exception:
            payload = b""
        if len(payload) == 0:
            payload = self._wrap_tlv(bytes.fromhex("BF30"), self._wrap_tlv(b"\x80", self._encode_notification_sequence(seq_number)))
        try:
            self.apdu_channel.send(
                self._build_store_data_apdu(payload),
                f"LOCAL: RemoveNotificationFromList [{seq_number}]",
            )
        except Exception:
            return

    def _extract_notification_sequence_from_metadata(self, raw_metadata: bytes) -> Optional[int]:
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_metadata, 0)
        except Exception:
            return None
        if root_tag != bytes.fromhex("BF2F"):
            return None
        offset = 0
        while offset < len(root_value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                return None
            if field_tag == b"\x80" and len(field_value) > 0:
                return int.from_bytes(field_value, "big", signed=False)
            offset = next_offset
        return None

    def _find_first_tlv_in_value(self, value: bytes, target_tag: bytes) -> bytes:
        offset = 0
        while offset < len(value):
            try:
                tag_bytes, child_value, raw_tlv, next_offset = self._read_tlv(value, offset)
            except Exception:
                return b""
            if tag_bytes == target_tag:
                return raw_tlv
            if self._is_constructed_tag(tag_bytes):
                nested = self._find_first_tlv_in_value(child_value, target_tag)
                if len(nested) > 0:
                    return nested
            offset = next_offset
        return b""

    @staticmethod
    def _encode_notification_sequence(seq_number: int) -> bytes:
        if seq_number <= 0xFF:
            return seq_number.to_bytes(1, "big")
        if seq_number <= 0xFFFF:
            return seq_number.to_bytes(2, "big")
        return seq_number.to_bytes(4, "big")

    def _describe_bpp_command_sequence(self, bpp_bytes: bytes) -> list[str]:
        descriptions: list[str] = []
        root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        if root_tag != bytes.fromhex("BF36"):
            return descriptions
        child_offset = 0
        while child_offset < len(root_value):
            child_tag, child_value, _, next_offset = self._read_tlv(root_value, child_offset)
            if child_tag == bytes.fromhex("BF23"):
                descriptions.append("BF23.InitialiseSecureChannelRequest")
            elif child_tag in (b"\xA0", b"\xA1", b"\xA2"):
                members = self._extract_sequence_members(child_value)
                for member_index, _member in enumerate(members, start=1):
                    if child_tag == b"\xA0":
                        descriptions.append(f"A0.ConfigureISDPRequest[{member_index}]")
                    elif child_tag == b"\xA1":
                        descriptions.append(f"A1.StoreMetadataRequest[{member_index}]")
                    elif child_tag == b"\xA2":
                        descriptions.append(f"A2.ReplaceSessionKeys[{member_index}]")
            elif child_tag == b"\xA3":
                members = self._extract_sequence_members(child_value)
                for member_index, _member in enumerate(members, start=1):
                    base = f"A3.ProtectedProfilePackageCommand[{member_index}]"
                    protected_index = member_index - 1
                    if protected_index < len(self.state.upp_protected_command_descriptions):
                        base += f" {self.state.upp_protected_command_descriptions[protected_index]}"
                    descriptions.append(base)
            child_offset = next_offset
        return descriptions

    def _describe_bpp_command_id_sequence(self, bpp_bytes: bytes) -> list[str]:
        descriptions: list[str] = []
        root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        if root_tag != bytes.fromhex("BF36"):
            return descriptions
        child_offset = 0
        while child_offset < len(root_value):
            child_tag, _child_value, _child_raw, next_offset = self._read_tlv(root_value, child_offset)
            if child_tag == bytes.fromhex("BF23"):
                descriptions.append("BF23.InitialiseSecureChannelRequest")
            elif child_tag == b"\xA0":
                descriptions.append("A0.ConfigureISDPRequest")
            elif child_tag == b"\xA1":
                descriptions.append("A1.StoreMetadataRequest")
            elif child_tag == b"\xA2":
                descriptions.append("A2.ReplaceSessionKeys")
            elif child_tag == b"\xA3":
                descriptions.append("A3.ProtectedProfilePackageCommand")
            child_offset = next_offset
        return descriptions

    def _describe_bpp_layout(self, bpp_bytes: bytes) -> list[str]:
        lines: list[str] = []
        if len(bpp_bytes) == 0:
            return lines
        try:
            root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        except Exception:
            return lines
        if root_tag != bytes.fromhex("BF36"):
            lines.append(f"Non-BF36 payload: total={len(bpp_bytes)}")
            return lines

        lines.append(f"BF36 total={len(bpp_bytes)} value={len(root_value)}")
        child_offset = 0
        while child_offset < len(root_value):
            try:
                child_tag, child_value, child_raw, next_offset = self._read_tlv(root_value, child_offset)
            except Exception:
                break

            if child_tag == bytes.fromhex("BF23"):
                transaction_id = self._transaction_id_from_bf23_value(child_value)
                line = f"BF23 total={len(child_raw)} value={len(child_value)}"
                if transaction_id is not None and len(transaction_id) > 0:
                    line += f" transactionId={transaction_id.hex().upper()}"
                lines.append(line)
            elif child_tag in (b"\xA0", b"\xA1", b"\xA2", b"\xA3"):
                child_name = child_tag.hex().upper()
                try:
                    members = self._extract_sequence_members(child_value)
                except Exception:
                    lines.append(
                        f"{child_name} total={len(child_raw)} value={len(child_value)} "
                        "members=unparsed"
                    )
                    child_offset = next_offset
                    continue
                member_lengths = ", ".join(str(len(member)) for member in members)
                lines.append(
                    f"{child_name} total={len(child_raw)} value={len(child_value)} "
                    f"members={len(members)} memberLengths=[{member_lengths}]"
                )
                for member_index, member in enumerate(members, start=1):
                    member_line = f"{child_name}[{member_index}] len={len(member)}"
                    if child_tag == b"\xA3":
                        protected_index = member_index - 1
                        if protected_index < len(self.state.upp_protected_command_descriptions):
                            member_line += (
                                " "
                                + self.state.upp_protected_command_descriptions[protected_index]
                            )
                    lines.append(member_line)
            else:
                lines.append(f"{child_tag.hex().upper()} total={len(child_raw)} value={len(child_value)}")
            child_offset = next_offset
        return lines

    @staticmethod
    def _split_overlap_labels(overlap_text: str) -> list[str]:
        labels: list[str] = []
        for raw_label in str(overlap_text or "").split(","):
            label = str(raw_label).strip()
            if len(label) == 0:
                continue
            if label == "...":
                continue
            labels.append(label)
        return labels

    def _parse_a3_layout_members(self) -> list[dict[str, Any]]:
        members: list[dict[str, Any]] = []
        pattern = re.compile(
            r"^A3\[(?P<index>\d+)\] len=(?P<length>\d+) "
            r"plaintext\[(?P<start>\d+):(?P<end>\d+)\]"
            r"(?: overlaps (?P<overlap>.*))?$"
        )
        for line in self.state.last_bpp_layout_lines:
            match = pattern.match(str(line))
            if match is None:
                continue
            members.append(
                {
                    "index": int(match.group("index")),
                    "length": int(match.group("length")),
                    "start": int(match.group("start")),
                    "end": int(match.group("end")),
                    "overlap": str(match.group("overlap") or "").strip(),
                }
            )
        return members

    @staticmethod
    def _a3_member_block_window(member_index: int, protected_length: int, apdu_chunk_size: int = 120) -> str:
        if apdu_chunk_size <= 0:
            return f"{member_index}.0"
        if protected_length <= 0:
            return f"{member_index}.0"
        block_count = (protected_length + apdu_chunk_size - 1) // apdu_chunk_size
        return f"{member_index}.0 -> {member_index}.{block_count - 1}"

    def _describe_a3_failure_focus_parts(self) -> list[str]:
        members = self._parse_a3_layout_members()
        if len(members) == 0:
            return []

        terminal_label = ""
        for member in reversed(members):
            labels = self._split_overlap_labels(str(member.get("overlap", "")))
            if len(labels) == 0:
                continue
            terminal_label = labels[-1]
            break
        if len(terminal_label) == 0:
            return []

        candidates: list[dict[str, Any]] = []
        for member in members:
            labels = self._split_overlap_labels(str(member.get("overlap", "")))
            if terminal_label not in labels:
                continue
            candidate = dict(member)
            candidate["labels"] = labels
            candidates.append(candidate)
        if len(candidates) == 0:
            return []

        likely = candidates[0]
        for member in candidates:
            labels = member.get("labels", [])
            if isinstance(labels, list) and len(labels) > 1:
                likely = member
                break

        likely_index = int(likely.get("index", 0))
        likely_length = int(likely.get("length", 0))
        likely_start = int(likely.get("start", 0))
        likely_end = int(likely.get("end", 0))
        likely_overlap = str(likely.get("overlap", "")).strip()
        parts = [f"likelyProtectedChunk=A3[{likely_index}]"]
        parts.append(f"  blocks={self._a3_member_block_window(likely_index, likely_length)}")
        parts.append(f"  plaintext[{likely_start}:{likely_end}]")
        if len(likely_overlap) > 0:
            parts.append("  overlaps:")
            for label in self._split_overlap_labels(likely_overlap):
                parts.append(f"    {label}")

        tail = candidates[-1]
        tail_index = int(tail.get("index", 0))
        if tail_index != likely_index:
            tail_length = int(tail.get("length", 0))
            tail_start = int(tail.get("start", 0))
            tail_end = int(tail.get("end", 0))
            tail_overlap = str(tail.get("overlap", "")).strip()
            continuation = f"terminalChunkContinuation=A3[{tail_index}]"
            parts.append(continuation)
            parts.append(f"  blocks={self._a3_member_block_window(tail_index, tail_length)}")
            parts.append(f"  plaintext[{tail_start}:{tail_end}]")
            if len(tail_overlap) > 0:
                parts.append("  overlaps:")
                for label in self._split_overlap_labels(tail_overlap):
                    parts.append(f"    {label}")
        return parts

    def _update_bpp_structure_debug(self, bpp_bytes: bytes) -> None:
        has_replace_session_keys = self._bpp_contains_sequence_tag(bpp_bytes, b"\xA2")
        structure_line = (
            "BPP structure "
            f"replaceSessionKeys={'present' if has_replace_session_keys else 'absent'}"
        )
        existing_lines = [
            line
            for line in self.state.last_bpp_crypto_debug_lines
            if line.startswith("BPP structure ") is False
        ]
        self.state.last_bpp_crypto_debug_lines = [structure_line] + existing_lines

    def _bpp_contains_sequence_tag(self, bpp_bytes: bytes, sequence_tag: bytes) -> bool:
        if len(bpp_bytes) == 0:
            return False
        try:
            root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        except Exception:
            return False
        if root_tag != bytes.fromhex("BF36"):
            return False
        child_offset = 0
        while child_offset < len(root_value):
            try:
                child_tag, _child_value, _child_raw, next_offset = self._read_tlv(root_value, child_offset)
            except Exception:
                return False
            if child_tag == sequence_tag:
                return True
            child_offset = next_offset
        return False

    def load_profile(self, profile_path: str = "") -> bytes:
        """Load a compiled profile to the eUICC via ES10b.LoadBoundProfilePackage (SGP.22 §5.7.20)."""
        if self.state.session_open is False:
            raise RuntimeError("No active local SCP11 session.")
        if len(self.state.prepare_download_response) == 0:
            raise RuntimeError("PrepareDownload not yet done.")
        resolved = self.resolve_profile_path(override_path=profile_path)
        if len(resolved) == 0:
            raise FileNotFoundError(
                "No profile file resolved. Set PROFILE or place one file in profile directory."
            )
        with open(resolved, "rb") as fh:
            bpp_bytes = fh.read()
        if len(bpp_bytes) == 0:
            raise ValueError("Profile file is empty.")
        bpp_bytes = self._decode_profile_bytes(bpp_bytes)
        return self._load_profile_from_bytes(bpp_bytes)

    def _decode_profile_bytes(self, data: bytes) -> bytes:
        """If data looks like ASCII hex (e.g. from a .txt profile), decode to binary."""
        if len(data) < 4 or len(data) % 2 != 0:
            return data
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            return data
        if len(text) % 2 != 0:
            return data
        allowed = set("0123456789ABCDEFabcdef \t\n\r")
        if not all(c in allowed for c in text):
            return data
        hex_str = "".join(text.split())
        if len(hex_str) == 0:
            return data
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return data

    def _inventory_payload(self) -> dict[str, Any]:
        return {
            "selected_ci_pkid": self.state.selected_ci_pkid,
            "selected_auth_certificate_path": self.state.selected_auth_certificate_path,
            "selected_pb_certificate_path": self.state.selected_pb_certificate_path,
            "selected_auth_private_key_path": self.state.selected_auth_private_key_path,
            "selected_pb_private_key_path": self.state.selected_pb_private_key_path,
            "selected_auth_certificate_reason": self.state.selected_auth_certificate_reason,
            "selected_pb_certificate_reason": self.state.selected_pb_certificate_reason,
            "selected_local_smdp_address": self.state.selected_local_smdp_address,
            "profile_override_path": self.state.profile_override_path,
            "metadata_override_path": self.state.metadata_override_path,
        }

    def _restore_inventory_override_path(self, stored_path: Any, *, base_dir: str) -> str:
        normalized_path = str(stored_path or "").strip()
        if len(normalized_path) == 0:
            return ""
        resolved_path = self._normalize_user_path(normalized_path, base_dir=base_dir)
        if os.path.isfile(resolved_path) is False:
            return ""
        return resolved_path

    def _apply_inventory_profile(self, payload: dict[str, Any]) -> None:
        self.state.selected_ci_pkid = str(payload.get("selected_ci_pkid", self.state.selected_ci_pkid)).strip().upper()
        self.state.selected_auth_certificate_path = str(
            payload.get("selected_auth_certificate_path", self.state.selected_auth_certificate_path)
        ).strip()
        self.state.selected_pb_certificate_path = str(
            payload.get("selected_pb_certificate_path", self.state.selected_pb_certificate_path)
        ).strip()
        self.state.selected_auth_private_key_path = str(
            payload.get("selected_auth_private_key_path", self.state.selected_auth_private_key_path)
        ).strip()
        self.state.selected_pb_private_key_path = str(
            payload.get("selected_pb_private_key_path", self.state.selected_pb_private_key_path)
        ).strip()
        self.state.selected_auth_certificate_reason = str(
            payload.get("selected_auth_certificate_reason", self.state.selected_auth_certificate_reason)
        ).strip()
        self.state.selected_pb_certificate_reason = str(
            payload.get("selected_pb_certificate_reason", self.state.selected_pb_certificate_reason)
        ).strip()
        self.state.selected_local_smdp_address = str(
            payload.get("selected_local_smdp_address", self.state.selected_local_smdp_address)
        ).strip()

        profile_override_path = self._restore_inventory_override_path(
            payload.get("profile_override_path", self.state.profile_override_path),
            base_dir=str(self.cfg.PROFILE_DIR),
        )
        if len(profile_override_path) > 0:
            self.state.profile_override_path = profile_override_path
            self.state.resolved_profile_path = profile_override_path

        metadata_override_path = self._restore_inventory_override_path(
            payload.get("metadata_override_path", self.state.metadata_override_path),
            base_dir=str(self.cfg.METADATA_DIR),
        )
        if len(metadata_override_path) > 0:
            self.state.metadata_override_path = metadata_override_path
            self.state.resolved_metadata_path = metadata_override_path

    def _persist_inventory_profile(self) -> None:
        if len(self.current_eid) == 0:
            return
        self._inventory.replace(self.current_eid, self._inventory_payload())

    def _bind_inventory_for_eid(self, eid: str) -> None:
        normalized_eid = self._inventory.normalize_eid(eid)
        if len(normalized_eid) == 0:
            return
        if self.current_eid != normalized_eid:
            self._cert_auth = None
            self._key_auth = None
            self._cert_pb = None
            self._key_pb = None
            self.state.selected_ci_pkid = ""
            self.state.selected_auth_certificate_path = ""
            self.state.selected_pb_certificate_path = ""
            self.state.selected_auth_private_key_path = ""
            self.state.selected_pb_private_key_path = ""
            self.state.selected_auth_certificate_reason = ""
            self.state.selected_pb_certificate_reason = ""
            self.state.selected_local_smdp_address = ""
        self.current_eid = normalized_eid
        payload = self._inventory.load(normalized_eid)
        if len(payload) > 0:
            self._apply_inventory_profile(payload)
            return
        self._persist_inventory_profile()

    def _selection_reason(
        self,
        record: SmdpCertificateRecord,
        allowed_ci_pkids: list[str],
    ) -> str:
        normalized_allowed = [str(value).strip().upper() for value in allowed_ci_pkids if len(str(value).strip()) > 0]
        source_label = "local_override" if record.source == "local_override" else "sgp26_bundle"
        if len(normalized_allowed) > 0 and record.root_ci_ski in normalized_allowed:
            return f"{source_label}_ci_match"
        return f"{source_label}_fallback"

    def _remember_selected_smdp_record(
        self,
        role: str,
        record: SmdpCertificateRecord,
        allowed_ci_pkids: list[str],
    ) -> None:
        if role == "auth":
            self._cert_auth = record.der_bytes
            self._key_auth = record.private_key
            self.state.selected_ci_pkid = record.root_ci_ski
            self.state.selected_auth_certificate_path = record.certificate_path
            self.state.selected_auth_private_key_path = record.private_key_path
            self.state.selected_auth_certificate_reason = self._selection_reason(record, allowed_ci_pkids)
            self.state.selected_local_smdp_address = str(record.server_address or "").strip()
            return
        if role == "pb":
            self._cert_pb = record.der_bytes
            self._key_pb = record.private_key
            self.state.selected_pb_certificate_path = record.certificate_path
            self.state.selected_pb_private_key_path = record.private_key_path
            self.state.selected_pb_certificate_reason = self._selection_reason(record, allowed_ci_pkids)
            if len(self.state.selected_ci_pkid) == 0:
                self.state.selected_ci_pkid = record.root_ci_ski
            return
        raise ValueError(f"Unsupported SM-DP+ role: {role}")

    def _smdp_record_summary(
        self,
        record: SmdpCertificateRecord,
        allowed_ci_pkids: list[str],
    ) -> dict[str, Any]:
        return {
            "role": record.role,
            "source": record.source,
            "curve": record.curve,
            "certificate_path": record.certificate_path,
            "private_key_path": record.private_key_path,
            "root_ci_pkid": record.root_ci_ski,
            "aki": record.aki,
            "subject": record.subject,
            "issuer": record.issuer,
            "server_address": record.server_address,
            "selection_reason": self._selection_reason(record, allowed_ci_pkids),
        }

    def list_local_smdp_certificate_inventory(self) -> dict[str, Any]:
        """Return the sorted inventory of known local SM-DP+ certificates."""
        allowed_ci_pkids = list(self.state.allowed_ci_pkids)
        auth_records = [
            self._smdp_record_summary(record, allowed_ci_pkids)
            for record in self._cert_store.auth_records()
        ]
        pb_records = [
            self._smdp_record_summary(record, allowed_ci_pkids)
            for record in self._cert_store.pb_records()
        ]
        selected_auth = self._cert_store.resolve_auth_record(allowed_ci_pkids)
        selected_pb = self._cert_store.resolve_pb_record(allowed_ci_pkids)
        return {
            "allowed_ci_pkids": allowed_ci_pkids,
            "auth_records": auth_records,
            "pb_records": pb_records,
            "selected_auth": (
                self._smdp_record_summary(selected_auth, allowed_ci_pkids)
                if selected_auth is not None
                else None
            ),
            "selected_pb": (
                self._smdp_record_summary(selected_pb, allowed_ci_pkids)
                if selected_pb is not None
                else None
            ),
        }

    def local_smdp_reference_address(self) -> str:
        """Return the active SM-DP+ reference address for the current local session."""
        selected_address = str(self.state.selected_local_smdp_address or "").strip()
        if len(selected_address) > 0:
            return selected_address
        auth_record = self._cert_store.resolve_auth_record(self.state.allowed_ci_pkids)
        if auth_record is None:
            return ""
        candidate = str(auth_record.server_address or "").strip()
        if len(candidate) == 0:
            return ""
        return candidate

    def _prime_inventory_profile(self) -> None:
        try:
            eid = self._read_card_eid()
        except Exception:
            return
        self._bind_inventory_for_eid(eid)

    def _find_smdp_record_by_certificate_path(
        self,
        role: str,
        certificate_path: str,
        allowed_ci_pkids: list[str],
    ) -> Optional[Any]:
        normalized_path = os.path.abspath(str(certificate_path).strip())
        if len(normalized_path) == 0:
            return None
        allowed = [str(value).strip().upper() for value in allowed_ci_pkids if len(str(value).strip()) > 0]
        if role == "auth":
            records = self._cert_store.auth_records()
        else:
            records = self._cert_store.pb_records()
        for record in records:
            if os.path.abspath(record.certificate_path) != normalized_path:
                continue
            if len(allowed) > 0 and record.root_ci_ski not in allowed:
                continue
            return record
        return None

    def _load_inventory_material(self) -> None:
        auth_record = self._find_smdp_record_by_certificate_path(
            "auth",
            self.state.selected_auth_certificate_path,
            self.state.allowed_ci_pkids,
        )
        if auth_record is not None:
            self._cert_auth = auth_record.der_bytes
            self._key_auth = auth_record.private_key
            self.state.selected_ci_pkid = auth_record.root_ci_ski
            self.state.selected_auth_certificate_path = auth_record.certificate_path

        pb_record = self._find_smdp_record_by_certificate_path(
            "pb",
            self.state.selected_pb_certificate_path,
            self.state.allowed_ci_pkids,
        )
        if pb_record is not None:
            self._cert_pb = pb_record.der_bytes
            self._key_pb = pb_record.private_key
            self.state.selected_pb_certificate_path = pb_record.certificate_path
            if len(self.state.selected_ci_pkid) == 0:
                self.state.selected_ci_pkid = pb_record.root_ci_ski

    def set_profile_override_path(self, profile_path: str) -> str:
        """Set a path override for the profile binary; subsequent resolves will use this path."""
        normalized_path = str(profile_path).strip()
        if len(normalized_path) == 0:
            raise ValueError("Profile override path cannot be empty.")
        resolved_path = self.resolve_profile_path(override_path=normalized_path)
        self.state.profile_override_path = resolved_path
        self.state.resolved_profile_path = resolved_path
        self._persist_inventory_profile()
        return resolved_path

    def clear_profile_override_path(self) -> None:
        self.state.profile_override_path = ""
        self.state.resolved_profile_path = ""
        self._persist_inventory_profile()

    def _normalize_user_path(self, path_text: str, base_dir: str = "") -> str:
        candidate = os.path.expandvars(os.path.expanduser(str(path_text).strip()))
        if os.path.isabs(candidate):
            return os.path.abspath(candidate)
        candidate = remap_legacy_workspace_relative(candidate)
        repo_resolved = self._resolve_repo_relative_candidate(candidate)
        if repo_resolved is not None:
            return repo_resolved
        base = str(base_dir).strip()
        if len(base) == 0:
            return os.path.abspath(candidate)
        return os.path.abspath(os.path.join(base, candidate))

    def _resolve_repo_relative_candidate(self, candidate: str) -> Optional[str]:
        cleaned = candidate.strip()
        if len(cleaned) == 0:
            return None
        if cleaned.startswith("."):
            return None
        if len(self._workspace_root) == 0:
            return None
        resolved = os.path.abspath(os.path.join(self._workspace_root, cleaned))
        if os.path.exists(resolved):
            return resolved
        first_segment = self._first_path_segment(cleaned)
        if len(first_segment) == 0:
            return None
        if first_segment in self._workspace_root_entries:
            return resolved
        return None

    def _detect_workspace_root(self) -> str:
        configured_root = runtime_root()
        if os.path.isdir(configured_root):
            configured_entries = self._list_workspace_root_entries(configured_root)
            if "SCP11" in configured_entries:
                return configured_root
        start = os.path.dirname(os.path.abspath(__file__))
        current = start
        while True:
            marker = os.path.join(current, ".git")
            if os.path.isdir(marker):
                return current
            parent = os.path.dirname(current)
            if parent == current:
                return ""
            current = parent

    def _list_workspace_root_entries(self, workspace_root: str) -> set[str]:
        if len(workspace_root) == 0:
            return set()
        if os.path.isdir(workspace_root) is False:
            return set()
        try:
            return set(os.listdir(workspace_root))
        except Exception:
            return set()

    def _first_path_segment(self, path_text: str) -> str:
        normalized = path_text.replace("\\", "/")
        parts = normalized.split("/")
        if len(parts) == 0:
            return ""
        return parts[0].strip()

    def resolve_profile_path(self, override_path: str = "") -> str:
        """Resolve the absolute path of the profile binary, respecting any override."""
        candidate_override = str(override_path).strip()
        if len(candidate_override) == 0:
            candidate_override = str(self.state.profile_override_path).strip()

        if len(candidate_override) > 0:
            resolved_override = self._normalize_user_path(
                candidate_override,
                base_dir=str(self.cfg.PROFILE_DIR),
            )
            if os.path.isfile(resolved_override) is False:
                raise FileNotFoundError(f"Profile override file not found: {resolved_override}")
            self.state.resolved_profile_path = resolved_override
            return resolved_override

        default_entries = self._profile_dir_entries()
        if len(default_entries) == 0:
            self.state.resolved_profile_path = ""
            return ""
        if len(default_entries) > 1:
            raise ValueError(
                "Profile directory contains multiple files. "
                "Keep a single default profile file in the folder or provide an override path."
            )
        self.state.resolved_profile_path = default_entries[0]
        return default_entries[0]

    def set_metadata_override_path(self, metadata_path: str) -> str:
        """Set a path override for the metadata JSON; subsequent resolves will use this path."""
        normalized_path = str(metadata_path).strip()
        if len(normalized_path) == 0:
            raise ValueError("Metadata override path cannot be empty.")
        resolved_path = self.resolve_metadata_path(override_path=normalized_path)
        self.state.metadata_override_path = resolved_path
        self.state.resolved_metadata_path = resolved_path
        self._persist_inventory_profile()
        return resolved_path

    def clear_metadata_override_path(self) -> None:
        self.state.metadata_override_path = ""
        self.state.resolved_metadata_path = ""
        self._persist_inventory_profile()

    def resolve_metadata_path(self, override_path: str = "") -> str:
        """Resolve the absolute path of the metadata JSON, respecting any override."""
        candidate_override = str(override_path).strip()
        if len(candidate_override) == 0:
            candidate_override = str(self.state.metadata_override_path).strip()

        if len(candidate_override) > 0:
            resolved_override = self._normalize_user_path(
                candidate_override,
                base_dir=str(self.cfg.METADATA_DIR),
            )
            if os.path.isfile(resolved_override) is False:
                raise FileNotFoundError(f"Metadata override file not found: {resolved_override}")
            self.state.resolved_metadata_path = resolved_override
            return resolved_override

        default_entries = self._metadata_dir_entries()
        if len(default_entries) == 0:
            self.state.resolved_metadata_path = ""
            return ""
        if len(default_entries) > 1:
            raise ValueError(
                "Metadata directory contains multiple JSON files. "
                "Keep a single default metadata file in the folder or provide an override path."
            )
        self.state.resolved_metadata_path = default_entries[0]
        return default_entries[0]

    def load_metadata_document(self, override_path: str = "") -> dict[str, Any]:
        resolved_path = self.resolve_metadata_path(override_path=override_path)
        if len(resolved_path) == 0:
            raise FileNotFoundError("No metadata JSON file is available.")
        return load_metadata_json_document(resolved_path)

    def encode_metadata_asn1(self, override_path: str = "") -> bytes:
        resolved_path = self.resolve_metadata_path(override_path=override_path)
        if len(resolved_path) == 0:
            raise FileNotFoundError("No metadata JSON file is available.")
        return encode_store_metadata_request_from_file(resolved_path)

    def encode_update_metadata_asn1(self, override_path: str = "") -> bytes:
        resolved_path = self.resolve_metadata_path(override_path=override_path)
        if len(resolved_path) == 0:
            raise FileNotFoundError("No metadata JSON file is available.")
        return encode_update_metadata_request_from_file(resolved_path)

    def load_enabled_custom_metadata_entries(self, override_path: str = "") -> list[dict[str, Any]]:
        document = self.load_metadata_document(override_path=override_path)
        return collect_enabled_custom_metadata_tags(document)

    def lint_metadata(self, metadata_path: str = "") -> dict[str, Any]:
        """Run static lint checks on the metadata document and return a list of finding strings."""
        resolved_path = self.resolve_metadata_path(override_path=metadata_path)
        if len(resolved_path) == 0:
            raise FileNotFoundError("No metadata JSON file is available.")

        # Validate JSON decode and both ASN.1 projections.
        document = load_metadata_json_document(resolved_path)
        store_metadata_der = encode_store_metadata_request_from_file(resolved_path)
        update_metadata_der = b""
        update_error = ""
        try:
            update_metadata_der = encode_update_metadata_request_from_file(resolved_path)
        except Exception as error:
            update_error = str(error)

        custom_entries = collect_enabled_custom_metadata_tags(document)
        duplicate_tags: dict[str, list[str]] = {}
        tag_to_paths: dict[str, list[str]] = {}
        for entry in custom_entries:
            tag_hex = str(entry.get("tag_hex", "")).upper()
            path = str(entry.get("path", ""))
            if len(tag_hex) == 0:
                continue
            existing = tag_to_paths.get(tag_hex)
            if existing is None:
                tag_to_paths[tag_hex] = [path]
                continue
            existing.append(path)
        for tag_hex, paths in tag_to_paths.items():
            if len(paths) > 1:
                duplicate_tags[tag_hex] = paths

        return {
            "metadata_path": resolved_path,
            "store_metadata_len": len(store_metadata_der),
            "update_metadata_len": len(update_metadata_der),
            "update_metadata_error": update_error,
            "enabled_custom_count": len(custom_entries),
            "enabled_custom_tags": [str(entry.get("tag_hex", "")).upper() for entry in custom_entries],
            "duplicate_enabled_custom_tags": duplicate_tags,
        }

    def reset_state(self) -> None:
        """Reset the local-access session state to defaults without disconnecting from the card."""
        persistent_profile_override_path = self.state.profile_override_path
        persistent_resolved_profile_path = self.state.resolved_profile_path
        persistent_metadata_override_path = self.state.metadata_override_path
        persistent_resolved_metadata_path = self.state.resolved_metadata_path
        persistent_selected_ci_pkid = self.state.selected_ci_pkid
        persistent_selected_auth_certificate_path = self.state.selected_auth_certificate_path
        persistent_selected_pb_certificate_path = self.state.selected_pb_certificate_path
        persistent_selected_auth_private_key_path = self.state.selected_auth_private_key_path
        persistent_selected_pb_private_key_path = self.state.selected_pb_private_key_path
        persistent_selected_auth_certificate_reason = self.state.selected_auth_certificate_reason
        persistent_selected_pb_certificate_reason = self.state.selected_pb_certificate_reason
        persistent_selected_local_smdp_address = self.state.selected_local_smdp_address
        self.state = LocalSessionState()
        self.state.profile_override_path = persistent_profile_override_path
        self.state.resolved_profile_path = persistent_resolved_profile_path
        self.state.metadata_override_path = persistent_metadata_override_path
        self.state.resolved_metadata_path = persistent_resolved_metadata_path
        self.state.selected_ci_pkid = persistent_selected_ci_pkid
        self.state.selected_auth_certificate_path = persistent_selected_auth_certificate_path
        self.state.selected_pb_certificate_path = persistent_selected_pb_certificate_path
        self.state.selected_auth_private_key_path = persistent_selected_auth_private_key_path
        self.state.selected_pb_private_key_path = persistent_selected_pb_private_key_path
        self.state.selected_auth_certificate_reason = persistent_selected_auth_certificate_reason
        self.state.selected_pb_certificate_reason = persistent_selected_pb_certificate_reason
        self.state.selected_local_smdp_address = persistent_selected_local_smdp_address

    def _ensure_local_material_loaded(self) -> None:
        if self._cert_auth is not None and self._key_auth is not None:
            return

        auth_record = self._cert_store.resolve_auth_record(self.state.allowed_ci_pkids)
        pb_record = self._cert_store.resolve_pb_record(self.state.allowed_ci_pkids)
        if auth_record is not None:
            self._remember_selected_smdp_record("auth", auth_record, self.state.allowed_ci_pkids)
        if pb_record is not None:
            self._remember_selected_smdp_record("pb", pb_record, self.state.allowed_ci_pkids)

        if self._cert_auth is not None and self._key_auth is not None:
            self._persist_inventory_profile()
            return

        allowed_text = ", ".join(self.state.allowed_ci_pkids) if len(self.state.allowed_ci_pkids) > 0 else "none"
        raise FileNotFoundError(
            "No matching SGP.26 local credential set was found. "
            f"Allowed CI PKIDs from card: {allowed_text}"
        )

    def _certs_dir_contains_override_files(self) -> bool:
        certs_dir = str(self.cfg.CERTS_DIR).strip()
        if len(certs_dir) == 0:
            return False
        if os.path.isdir(certs_dir) is False:
            return False

        for entry_name in os.listdir(certs_dir):
            entry_path = os.path.join(certs_dir, entry_name)
            if os.path.isfile(entry_path) is False:
                continue
            lower_name = entry_name.lower()
            if lower_name == "readme.md":
                continue
            if lower_name.endswith((".der", ".crt", ".cer", ".pem", ".key")):
                return True
        return False

    def _profile_dir_entries(self) -> list[str]:
        profile_dir = str(self.cfg.PROFILE_DIR).strip()
        if len(profile_dir) == 0:
            return []
        if os.path.isdir(profile_dir) is False:
            return []

        entries: list[str] = []
        for entry_name in sorted(os.listdir(profile_dir)):
            entry_path = os.path.join(profile_dir, entry_name)
            if os.path.isfile(entry_path) is False:
                continue
            lower_name = entry_name.lower()
            if lower_name == "readme.md":
                continue
            if entry_name.startswith("."):
                continue
            entries.append(os.path.abspath(entry_path))
        return entries

    def _metadata_dir_entries(self) -> list[str]:
        metadata_dir = str(self.cfg.METADATA_DIR).strip()
        if len(metadata_dir) == 0:
            return []
        if os.path.isdir(metadata_dir) is False:
            return []

        entries: list[str] = []
        for entry_name in sorted(os.listdir(metadata_dir)):
            entry_path = os.path.join(metadata_dir, entry_name)
            if os.path.isfile(entry_path) is False:
                continue
            lower_name = entry_name.lower()
            if lower_name == "readme.md":
                continue
            if entry_name.startswith("."):
                continue
            if lower_name.endswith(".json") is False:
                continue
            entries.append(os.path.abspath(entry_path))
        return entries

    def _load_folder_override_material(self) -> None:
        auth_cert_exists = os.path.exists(self.cfg.CERT_PATH_AUTH)
        auth_key_exists = os.path.exists(self.cfg.KEY_PATH_AUTH)
        if auth_cert_exists is False or auth_key_exists is False:
            raise FileNotFoundError(
                "Manual certificate override is enabled because files were found in the local certs folder, "
                "but the required DPauth pair is missing. Expected files: "
                f"{self.cfg.CERT_PATH_AUTH} and {self.cfg.KEY_PATH_AUTH}"
            )

        cert_auth, key_auth = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_AUTH,
            self.cfg.KEY_PATH_AUTH,
        )
        self._cert_auth = cert_auth.dump()
        self._key_auth = key_auth
        self.state.selected_auth_certificate_path = self.cfg.CERT_PATH_AUTH

        authority_key_id = self._certificate_authority_key_identifier(self._cert_auth)
        if len(authority_key_id) > 0:
            self.state.selected_ci_pkid = authority_key_id
        else:
            self.state.selected_ci_pkid = self.cfg.ROOT_CI_ID.hex().upper()

        pb_cert_exists = os.path.exists(self.cfg.CERT_PATH_PB)
        pb_key_exists = os.path.exists(self.cfg.KEY_PATH_PB)
        if pb_cert_exists != pb_key_exists:
            raise FileNotFoundError(
                "Manual certificate override detected a partial DPpb pair. Expected both files or neither: "
                f"{self.cfg.CERT_PATH_PB} and {self.cfg.KEY_PATH_PB}"
            )
        if pb_cert_exists and pb_key_exists:
            cert_pb, key_pb = CryptoEngine.load_credentials(
                self.cfg.CERT_PATH_PB,
                self.cfg.KEY_PATH_PB,
            )
            self._cert_pb = cert_pb.dump()
            self._key_pb = key_pb
            self.state.selected_pb_certificate_path = self.cfg.CERT_PATH_PB
        self._persist_inventory_profile()

    @staticmethod
    def _certificate_authority_key_identifier(certificate_der: bytes) -> str:
        try:
            certificate = crypto_x509.load_der_x509_certificate(certificate_der)
            extension = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except Exception:
            return ""
        key_identifier = extension.value.key_identifier
        if key_identifier is None:
            return ""
        return key_identifier.hex().upper()

    def _selected_root_ci_id(self) -> bytes:
        if len(self.state.selected_ci_pkid) > 0:
            try:
                return bytes.fromhex(self.state.selected_ci_pkid)
            except ValueError:
                pass
        return self.cfg.ROOT_CI_ID

    def _extract_default_dp_address(self, configured_data: bytes) -> Optional[str]:
        """Extract defaultDpAddress (tag 0x80) from GetEuiccConfiguredData (BF3C) per SGP.22.
        Returns UTF-8 string or None if not present. Used as serverAddress so eUICC accepts session."""
        if len(configured_data) < 4:
            return None
        try:
            root_tag, root_value, _, _ = self._read_tlv(configured_data, 0)
        except ValueError:
            return None
        if root_tag != bytes.fromhex("BF3C"):
            return None
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, value, _, next_offset = self._read_tlv(root_value, offset)
            except ValueError:
                break
            if tag_bytes == b"\x80" and len(value) > 0:
                try:
                    return value.decode("utf-8").strip()
                except UnicodeDecodeError:
                    return None
            offset = next_offset
        return None

    def _extract_allowed_ci_pkids(self, response: bytes) -> list[str]:
        pkid_values: list[str] = []

        def walk(blob: bytes) -> None:
            """Walk the decoded profile tree depth-first and yield (path, node) tuples."""
            offset = 0
            while offset < len(blob):
                try:
                    tag_bytes, value, _, offset = self._read_tlv(blob, offset)
                except Exception:
                    break

                if tag_bytes == b"\x83":
                    decoded = self._decode_text_or_hex(value)
                    normalized = decoded.strip().upper()
                    if len(normalized) > 0 and normalized not in pkid_values:
                        pkid_values.append(normalized)

                if self._is_constructed_tag(tag_bytes):
                    walk(value)

        walk(response)
        return pkid_values

    @staticmethod
    def _decode_text_or_hex(value: bytes) -> str:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex().upper()
        if text.isprintable():
            return text
        return value.hex().upper()

    @staticmethod
    def _is_constructed_tag(tag_bytes: bytes) -> bool:
        if len(tag_bytes) == 0:
            return False
        return bool(tag_bytes[0] & 0x20)

    def _parse_authenticate_server_response(self, response: bytes) -> OpenSessionResult:
        if response[:2] != bytes.fromhex("BF38"):
            raise ValueError("AuthenticateServer response did not start with BF38.")

        try:
            decoded = decode_authenticate_server_response(response)
        except Exception:
            decoded = None

        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "authenticateResponseError":
                raise PermissionError(f"AuthenticateServer rejected by eUICC: {choice_value}")

        root_tag, root_value, _, _ = self._read_tlv(response, 0)
        if root_tag != bytes.fromhex("BF38"):
            raise ValueError("AuthenticateServer response root tag was not BF38.")

        choice_tag, choice_value, _, _ = self._read_tlv(root_value, 0)
        if choice_tag in (b"\xA1", b"\x61"):
            raise PermissionError("AuthenticateServer returned an error choice.")
        if choice_tag not in (b"\xA0", b"\x60"):
            raise ValueError(f"Unexpected AuthenticateServer choice tag: {choice_tag.hex().upper()}")

        first_tag, _, first_raw, offset = self._read_tlv(choice_value, 0)
        if first_tag != b"\x30":
            raise ValueError("AuthenticateServer response did not contain euiccSigned1 as the first field.")

        second_tag, second_value, _, _ = self._read_tlv(choice_value, offset)
        if second_tag != bytes.fromhex("5F37"):
            raise ValueError("AuthenticateServer response did not contain euiccSignature1 as the second field.")

        try:
            euicc_signed1 = extract_euicc_signed1(response)
        except Exception:
            euicc_signed1 = b""
        if len(euicc_signed1) == 0:
            euicc_signed1 = first_raw

        return OpenSessionResult(
            transaction_id=self.state.transaction_id,
            card_challenge=self.state.card_challenge,
            server_challenge=self.state.server_challenge,
            euicc_signed1=euicc_signed1,
            euicc_signature1=second_value,
            authenticate_server_response=response,
        )

    def _decode_prepare_download_response_ok(self, raw_response: bytes) -> dict[str, bytes]:
        result = {
            "transactionId": b"",
            "euiccOtpk": b"",
            "euiccOtpkRaw": b"",
        }
        if len(raw_response) == 0:
            return result

        try:
            decoded = decode_prepare_download_response(raw_response)
        except Exception:
            decoded = None

        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "downloadResponseOk" and isinstance(choice_value, dict):
                euicc_signed2 = choice_value.get("euiccSigned2", {})
                if isinstance(euicc_signed2, dict):
                    result["transactionId"] = bytes(euicc_signed2.get("transactionId", b""))
                    result["euiccOtpk"] = bytes(euicc_signed2.get("euiccOtpk", b""))

        root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        if root_tag != bytes.fromhex("BF21") or len(root_value) == 0:
            return result

        choice_tag, choice_value, _, _ = self._read_tlv(root_value, 0)
        if choice_tag not in (b"\xA0", b"\x60"):
            return result

        first_tag, first_value, _, first_end = self._read_tlv(choice_value, 0)
        if first_tag != b"\x30":
            return result

        euicc_signed2_value = b""
        nested_tag, nested_value, _, _ = self._read_tlv(first_value, 0)
        if nested_tag == b"\x30":
            euicc_signed2_value = nested_value
        elif first_end == len(choice_value):
            euicc_signed2_value = first_value
        else:
            euicc_signed2_value = first_value

        inner_offset = 0
        while inner_offset < len(euicc_signed2_value):
            field_tag, field_value, field_raw, next_offset = self._read_tlv(
                euicc_signed2_value,
                inner_offset,
            )
            if field_tag == b"\x80":
                result["transactionId"] = field_value
            elif field_tag == bytes.fromhex("5F49"):
                result["euiccOtpk"] = field_value
                result["euiccOtpkRaw"] = field_raw
            inner_offset = next_offset
        return result

    @staticmethod
    def _read_tlv(data: bytes, offset: int):
        if offset >= len(data):
            raise ValueError("TLV offset out of range.")

        tag_start = offset
        offset += 1
        if data[tag_start] & 0x1F == 0x1F:
            while offset < len(data):
                current = data[offset]
                offset += 1
                if current & 0x80 == 0:
                    break
            else:
                raise ValueError("Truncated multi-byte tag.")

        tag_bytes = data[tag_start:offset]
        length, length_size = LocalIsdrSession._decode_der_length(data, offset)
        if length_size == 0:
            raise ValueError("Invalid TLV length.")

        value_start = offset + length_size
        value_end = value_start + length
        if value_end > len(data):
            raise ValueError("TLV value overruns input.")

        raw_tlv = data[tag_start:value_end]
        return tag_bytes, data[value_start:value_end], raw_tlv, value_end

    @staticmethod
    def _decode_der_length(data: bytes, offset: int):
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
        return int.from_bytes(data[offset + 1:end], "big"), 1 + count

    @staticmethod
    def _encode_der_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError("DER length exceeds supported encoding.")

    @staticmethod
    def _wrap_tlv(tag_bytes: bytes, value: bytes) -> bytes:
        return bytes(tag_bytes) + LocalIsdrSession._encode_der_length(len(value)) + bytes(value)

    @staticmethod
    def _decode_bcd_digits(value: bytes) -> str:
        digits = ""
        for byte in value:
            high = (byte >> 4) & 0x0F
            low = byte & 0x0F
            for nibble in [high, low]:
                if nibble == 0x0F:
                    continue
                digits += str(nibble)
        return digits

    @staticmethod
    def _swap_bcd_nibbles(value: bytes) -> bytes:
        """Swap high/low nibbles in each byte.

        Converts between PE-Header straight BCD and TS 102.221 EF_ICCID
        coding.  Equivalent to osmocom ``h2b(swap_nibbles(b2h(value)))``.
        """
        return bytes(((b & 0x0F) << 4) | ((b >> 4) & 0x0F) for b in value)

    def _is_terminal_profile_installation_result(self, raw_response: bytes) -> bool:
        details = self._decode_profile_installation_result(raw_response)
        return len(details) > 0

    def _is_failed_profile_installation_result(self, raw_response: bytes) -> bool:
        details = self._decode_profile_installation_result(raw_response)
        if len(details) == 0:
            return False
        return details.get("finalResultTag") == b"\xA1"

    def _summarize_profile_installation_result(self, raw_response: bytes) -> str:
        details = self._decode_profile_installation_result(raw_response)
        if len(details) == 0:
            return ""

        result_detail = details.get("resultDetail")
        reason_name = ""
        if isinstance(result_detail, int):
            reason_name = self._describe_profile_installation_error_reason(result_detail)

        headline = ""
        if isinstance(result_detail, int) and len(reason_name) > 0:
            headline = f"[ERROR {result_detail}] {reason_name}"
        elif isinstance(result_detail, int):
            headline = f"[ERROR {result_detail}]"

        lines = []
        if len(headline) > 0:
            lines.append(headline)
        if isinstance(result_detail, int):
            lines.append(f"errorReason={result_detail}")
        result_code = details.get("resultCode")
        if isinstance(result_code, int):
            cmd_desc = self._describe_bpp_command_id(result_code)
            lines.append(f"bppCommandId={result_code}")
            if len(cmd_desc) > 0:
                lines.append(f"command={cmd_desc}")
                if cmd_desc == "A3.ProtectedProfilePackageCommand":
                    lines.extend(self._describe_a3_failure_focus_parts())
        iccid = details.get("iccid")
        if isinstance(iccid, str) and len(iccid) > 0:
            lines.append(f"iccid={iccid}")
        aid = details.get("aid")
        if isinstance(aid, bytes) and len(aid) > 0:
            lines.append(f"aid={aid.hex().upper()}")
        sima_response = details.get("simaResponse")
        if isinstance(sima_response, bytes) and len(sima_response) > 0:
            lines.append(f"simaResponse={sima_response.hex().upper()}")
        smdp_oid = details.get("smdpOid")
        if isinstance(smdp_oid, str) and len(smdp_oid) > 0:
            lines.append(f"smdpOid={smdp_oid}")
        notification_address = details.get("notificationAddress")
        if isinstance(notification_address, str) and len(notification_address) > 0:
            lines.append(f"notificationAddress={notification_address}")
        return "\n".join(lines)

    @staticmethod
    def _indent_text_block(text: str, prefix: str = "  ") -> str:
        lines = str(text).splitlines()
        if len(lines) == 0:
            return prefix.rstrip()
        return "\n".join(f"{prefix}{line}" if len(line) > 0 else prefix.rstrip() for line in lines)

    # SGP.22 v3.0 §5.5.4 / §5.5.5: bppCommandId is a 1-based index into the
    # canonical BoundProfilePackage command sequence. When the observed BPP
    # layout in self.state.bpp_command_descriptions is shorter than the
    # failing command (typical when the BPP was segmented upstream or
    # supplied as a stub in unit tests), fall back to this canonical table
    # so the failure summary still identifies which step aborted.
    _SGP22_BPP_COMMAND_ID_TABLE = (
        "BF23.InitialiseSecureChannelRequest",
        "A0.ConfigureISDPRequest",
        "A1.StoreMetadataRequest",
        "A2.ReplaceSessionKeys",
        "A3.ProtectedProfilePackageCommand",
    )

    def _describe_bpp_command_id(self, command_id: int) -> str:
        if command_id <= 0:
            return ""
        index = command_id - 1
        observed = self.state.bpp_command_descriptions
        if index < len(observed):
            return observed[index]
        if index < len(self._SGP22_BPP_COMMAND_ID_TABLE):
            return self._SGP22_BPP_COMMAND_ID_TABLE[index]
        return ""

    @staticmethod
    def _describe_profile_installation_error_reason(error_reason: int) -> str:
        return describe_sgp22_profile_installation_reason(int(error_reason))

    def _decode_profile_installation_result(self, raw_response: bytes) -> dict:
        if len(raw_response) == 0:
            return {}
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        except Exception:
            return {}
        if root_tag != bytes.fromhex("BF37"):
            return {}
        try:
            inner_tag, inner_value, _, _ = self._read_tlv(root_value, 0)
        except Exception:
            return {}
        if inner_tag != bytes.fromhex("BF27"):
            return {}
        details = {
            "transactionId": b"",
            "seqNumber": None,
            "profileManagementOperation": None,
            "notificationAddress": "",
            "iccid": "",
            "smdpOid": "",
            "aid": b"",
            "simaResponse": b"",
            "euiccSignPIR": b"",
            "finalResultTag": b"",
            "resultCode": None,
            "resultDetail": None,
        }
        offset = 0
        while offset < len(inner_value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(inner_value, offset)
            except Exception:
                break
            if field_tag == b"\x80":
                details["transactionId"] = field_value
            elif field_tag == bytes.fromhex("BF2F"):
                details.update(self._decode_notification_metadata_fields(field_value))
            elif field_tag == b"\x06":
                details["smdpOid"] = self._decode_oid(field_value)
            elif field_tag == b"\xA2":
                self._decode_profile_installation_final_result(field_value, details)
            elif field_tag == bytes.fromhex("5F37"):
                details["euiccSignPIR"] = field_value
            offset = next_offset
        return details

    def _decode_profile_installation_final_result(self, value: bytes, details: dict) -> None:
        offset = 0
        while offset < len(value):
            try:
                result_tag, result_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                return
            if result_tag in [b"\xA0", b"\xA1"]:
                details["finalResultTag"] = result_tag
                inner_offset = 0
                while inner_offset < len(result_value):
                    try:
                        field_tag, field_value, _, inner_next_offset = self._read_tlv(result_value, inner_offset)
                    except Exception:
                        return
                    if field_tag == b"\x80":
                        details["resultCode"] = int.from_bytes(field_value, "big", signed=False)
                    elif field_tag == b"\x81":
                        details["resultDetail"] = int.from_bytes(field_value, "big", signed=False)
                    elif field_tag == b"\x4F":
                        details["aid"] = field_value
                    elif field_tag == b"\x04":
                        details["simaResponse"] = field_value
                    inner_offset = inner_next_offset
            offset = next_offset

    def _decode_notification_metadata_fields(self, value: bytes) -> dict:
        details = {
            "seqNumber": None,
            "profileManagementOperation": None,
            "notificationAddress": "",
            "iccid": "",
        }
        offset = 0
        while offset < len(value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                return details
            if field_tag == b"\x80":
                details["seqNumber"] = int.from_bytes(field_value, "big", signed=False)
            elif field_tag == b"\x81":
                details["profileManagementOperation"] = int.from_bytes(field_value, "big", signed=False)
            elif field_tag == b"\x0C":
                details["notificationAddress"] = field_value.decode("utf-8", "ignore")
            elif field_tag == b"\x5A":
                details["iccid"] = self._decode_bcd_digits(field_value)
            offset = next_offset
        return details

    @staticmethod
    def _decode_oid(value: bytes) -> str:
        if len(value) == 0:
            return ""
        first = value[0]
        parts = [str(first // 40), str(first % 40)]
        current = 0
        for byte in value[1:]:
            current = (current << 7) | (byte & 0x7F)
            if byte & 0x80:
                continue
            parts.append(str(current))
            current = 0
        if current != 0:
            parts.append(str(current))
        return ".".join(parts)

    def _segment_bound_profile_package(self, bpp_bytes: bytes) -> list[bytes]:
        # Keep the A0 configureISDPRequest wrapped and emit A1/A2/A3
        # container headers as their own StoreData chains, matching
        # SGP.22 Annex M "ES10b.LoadBoundProfilePackage". Without this
        # framing a compliant eUICC can misinterpret the first bare 86
        # as a terminal loadProfileElements result.
        if len(bpp_bytes) == 0:
            raise ValueError("Bound Profile Package is empty.")
        root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        if root_tag != bytes.fromhex("BF36"):
            raise ValueError(f"Unexpected BPP root tag: {root_tag.hex().upper()}")
        segments: list[bytes] = []
        child_offset = 0
        first_child = True
        while child_offset < len(root_value):
            child_tag, child_value, child_raw, next_offset = self._read_tlv(root_value, child_offset)
            if first_child and child_tag != bytes.fromhex("BF23"):
                raise ValueError(f"Expected BF23 as first BPP child, got {child_tag.hex().upper()}")
            if child_tag == bytes.fromhex("BF23"):
                bootstrap_end = next_offset + (len(bpp_bytes) - len(root_value))
                segments.append(bpp_bytes[:bootstrap_end])
            elif child_tag == b"\xA0":
                segments.append(child_raw)
            elif child_tag in (b"\xA1", b"\xA2", b"\xA3"):
                segments.append(self._encode_tlv_header(child_tag, len(child_value)))
                if len(child_value) > 0:
                    segments.extend(self._extract_sequence_members(child_value))
            else:
                raise ValueError(f"Unexpected BPP child tag: {child_tag.hex().upper()}")
            child_offset = next_offset
            first_child = False
        if len(segments) == 0:
            raise ValueError("BPP did not contain any loadable segments.")
        return segments

    def _encode_tlv_header(self, tag_bytes: bytes, value_length: int) -> bytes:
        return bytes(tag_bytes) + self._encode_der_length(value_length)

    def _extract_sequence_members(self, value: bytes) -> list[bytes]:
        members: list[bytes] = []
        offset = 0
        while offset < len(value):
            _, _, raw_tlv, next_offset = self._read_tlv(value, offset)
            members.append(raw_tlv)
            offset = next_offset
        return members

    def _send_personalization_store_data(self, payload: bytes, log_name: str, chunk_size: int = 255) -> bytes:
        total = len(payload)
        offset = 0
        block = 0
        response = b""
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            p1 = 0x11
            if is_last_chunk:
                p1 = 0x91
            apdu = bytes([0x80, 0xE2, p1, block & 0xFF, len(chunk)]) + chunk
            response = self.apdu_channel.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1
        return response
