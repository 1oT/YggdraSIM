import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from yggdrasim_common.inventory_crypto import read_secret_file_bytes
from yggdrasim_common.progress import progress_session
from yggdrasim_common.runtime_paths import ensure_seeded_workspace_file, runtime_root

try:
    from SCP11.local_access.session import LocalIsdrSession
except ImportError:
    from ..local_access.session import LocalIsdrSession

try:
    from SCP11.eim_packages import parse_eim_package
except ImportError:
    from ..eim_packages import parse_eim_package

from .config import EimLocalConfig
from .eim_cert_store import EimCertificateRecord, EimCertificateStore
from .eim_package_codec import (
    encode_additional_tlvs,
    encode_optional_tlvs,
    lint_eim_package_document,
    load_eim_package_document,
    resolve_package_runtime_hints,
)
from .identity import load_eim_identity
from .models import EimLocalState, EimHandoverContext, ensure_handover_transaction
from .poll_audit_store import EimPollAuditStore
from .response_logger import EimResponseLogger
from .runtime_state import EimRuntimeStateStore
from SCP11.shared.gsma_error_codes import (
    describe_sgp22_profile_state_result,
    describe_sgp32_eim_package_result_error,
    describe_sgp32_profile_download_error_reason,
    resolve_sgp22_profile_state_result_code,
    resolve_sgp32_eim_package_result_error_code,
    resolve_sgp32_profile_download_error_reason_code,
)


class EimLocalSession(LocalIsdrSession):
    """Isolated local SCP11 session with eIM/IPAd/IPAe additions."""

    EIM_ID_TYPE_CODE_MAP: dict[str, int] = {
        "1": 1,
        "oid": 1,
        "eimidtypeoid": 1,
        "eimidtypeoid(1)": 1,
        "2": 2,
        "fqdn": 2,
        "eimidtypefqdn": 2,
        "eimidtypefqdn(2)": 2,
        "3": 3,
        "proprietary": 3,
        "eimidtypeproprietary": 3,
        "eimidtypeproprietary(3)": 3,
    }
    EIM_SUPPORTED_PROTOCOL_FLAGS: tuple[str, ...] = (
        "eimRetrieveHttps",
        "eimRetrieveCoaps",
        "eimInjectHttps",
        "eimInjectCoaps",
        "eimProprietary",
    )
    EUICC_MEMORY_RESET_OPTION_FIELDS: tuple[tuple[str, str], ...] = (
        ("delete_operational_profiles", "deleteOperationalProfiles"),
        ("delete_field_loaded_test_profiles", "deleteFieldLoadedTestProfiles"),
        ("reset_default_smdp_address", "resetDefaultSmdpAddress"),
        ("delete_preloaded_test_profiles", "deletePreLoadedTestProfiles"),
        ("delete_provisioning_profiles", "deleteProvisioningProfiles"),
        ("reset_eim_config_data", "resetEimConfigData"),
        ("reset_immediate_enable_config", "resetImmediateEnableConfig"),
    )

    def __init__(self, cfg: Optional[EimLocalConfig] = None, apdu_channel: Optional[Any] = None):
        local_cfg = cfg if cfg is not None else EimLocalConfig()
        super().__init__(cfg=local_cfg, apdu_channel=apdu_channel)
        self.cfg: EimLocalConfig = local_cfg
        self.eim_identity = load_eim_identity(self.cfg.EIM_IDENTITY_FILE)
        self.eim_state = EimLocalState(
            current_bip_endpoint="",
        )
        self.runtime_state = EimRuntimeStateStore(self.cfg.EIM_RUNTIME_STATE_FILE)
        self.response_logger = EimResponseLogger(self.cfg.EIM_RESPONSE_LOG_FILE)
        self.poll_audit_store = EimPollAuditStore(self.cfg.EIM_POLL_AUDIT_DB_FILE)
        self._workspace_root = self._detect_workspace_root()
        self._workspace_root_entries = self._list_workspace_root_entries(self._workspace_root)
        identity_cert_path = ""
        if len(self._effective_eim_public_key_cert_path()) > 0:
            identity_cert_path = self._normalize_user_path(
                self._effective_eim_public_key_cert_path(),
                base_dir=self.cfg.EIM_CERTS_DIR,
            )
        self._eim_cert_store = EimCertificateStore(
            local_cert_root=self.cfg.EIM_CERTS_DIR,
            sgp26_valid_cert_root=self.cfg.SGP26_VALID_CERT_DIR,
            prefer_curve=self.cfg.CERT_CURVE_PREFERENCE,
            identity_default_cert_path=identity_cert_path,
            identity_default_ci_pkid=self._effective_euicc_ci_pk_id(),
        )
        self.eim_state.current_bip_endpoint = self._effective_eim_endpoint()

    def reset_state(self) -> None:
        super().reset_state()
        self.eim_state.handover = EimHandoverContext()
        self._activate_runtime_bip_role("eim", reason="reset")
        self.eim_state.last_intercepted_target = ""
        self.eim_state.last_intercept_reason = ""
        self.reset_hotfolder_poll_session()

    def _normalize_user_path(self, path_text: str, base_dir: str = "") -> str:
        candidate = os.path.expandvars(os.path.expanduser(str(path_text).strip()))
        if os.path.isabs(candidate):
            return os.path.abspath(candidate)
        repo_resolved = self._resolve_repo_relative_candidate(candidate)
        if repo_resolved is not None:
            return repo_resolved
        return super()._normalize_user_path(candidate, base_dir=base_dir)

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

    def set_eim_package_override_path(self, package_path: str) -> str:
        resolved = self._normalize_user_path(package_path, base_dir=self.cfg.EIM_PACKAGES_DIR)
        self.eim_state.eim_package_override_path = resolved
        return resolved

    def clear_eim_package_override_path(self) -> None:
        self.eim_state.eim_package_override_path = ""

    def set_hotfolder_override_path(self, hotfolder_path: str) -> str:
        resolved = self._normalize_user_path(hotfolder_path, base_dir=self.cfg.EIM_HOTFOLDER_DIR)
        self.eim_state.hotfolder_override_path = resolved
        return resolved

    def clear_hotfolder_override_path(self) -> None:
        self.eim_state.hotfolder_override_path = ""

    def list_profile_aliases(self) -> list[dict[str, str]]:
        registry_path = ensure_seeded_workspace_file(("SCP03", "aid.txt"), "SCP03", "aid.txt")
        if os.path.isfile(registry_path) is False:
            return []
        rows: list[dict[str, str]] = []
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
                    if len(alias_value) == 0 or len(aid_hex) == 0:
                        continue
                    rows.append(
                        {
                            "alias": alias_value,
                            "aid": aid_hex,
                        }
                    )
        except Exception:
            return []
        return rows

    def resolve_hotfolder_path(self, override_path: str = "") -> str:
        target = override_path
        if len(target) == 0:
            target = self.eim_state.hotfolder_override_path
        if len(target) == 0:
            target = self.cfg.EIM_HOTFOLDER_DIR
        resolved = self._normalize_user_path(target, base_dir=self.cfg.EIM_HOTFOLDER_DIR)
        if os.path.isdir(resolved) is False:
            raise NotADirectoryError(f"Hotfolder directory does not exist: {resolved}")
        return resolved

    @staticmethod
    def _boolish_flag(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "y", "on"):
            return True
        if text in ("0", "false", "no", "n", "off"):
            return False
        return default

    def _euicc_memory_reset_request(self, package_document: dict[str, Any]) -> dict[str, Any]:
        sgp22 = package_document.get("sgp22", {})
        if isinstance(sgp22, dict) is False:
            return {}
        request = sgp22.get("euicc_memory_reset_request", {})
        if isinstance(request, dict):
            return request
        return {}

    def _euicc_memory_reset_options(self, package_document: dict[str, Any]) -> dict[str, bool]:
        request = self._euicc_memory_reset_request(package_document)
        option_source = request.get("options", {})
        if isinstance(option_source, dict) is False or len(option_source) == 0:
            option_source = request
        normalized: dict[str, bool] = {}
        for snake_name, camel_name in self.EUICC_MEMORY_RESET_OPTION_FIELDS:
            value = False
            if isinstance(option_source, dict):
                if snake_name in option_source:
                    value = self._boolish_flag(option_source.get(snake_name), False)
                elif camel_name in option_source:
                    value = self._boolish_flag(option_source.get(camel_name), False)
            normalized[snake_name] = value
        return normalized

    def _encode_euicc_memory_reset_options(self, options: dict[str, bool]) -> bytes:
        last_enabled_index = -1
        normalized_flags: list[bool] = []
        for index, (snake_name, _) in enumerate(self.EUICC_MEMORY_RESET_OPTION_FIELDS):
            enabled = bool(options.get(snake_name, False))
            normalized_flags.append(enabled)
            if enabled:
                last_enabled_index = index
        if last_enabled_index < 0:
            return b"\x00"
        bit_count = last_enabled_index + 1
        unused_bits = (8 - (bit_count % 8)) % 8
        data = bytearray([unused_bits])
        data.extend(b"\x00" * ((bit_count + 7) // 8))
        for index in range(bit_count):
            if normalized_flags[index] is False:
                continue
            byte_index = 1 + (index // 8)
            bit_mask = 0x80 >> (index % 8)
            data[byte_index] |= bit_mask
        return bytes(data)

    def _build_euicc_memory_reset_payload(self, package_document: dict[str, Any]) -> bytes:
        options = self._euicc_memory_reset_options(package_document)
        encoded_options = self._encode_euicc_memory_reset_options(options)
        return self._wrap_tlv(bytes.fromhex("BF64"), self._wrap_tlv(b"\x82", encoded_options))

    def get_eim_configuration_data(self) -> bytes:
        self.reset_state()
        self.select_isdr()
        response = self._send_retrieve_store_data(bytes.fromhex("BF5500"), "EIM-LOCAL: GetEimConfigurationData")
        self._sync_pending_notifications(response)
        self._append_response_log_event(
            action="get_eim_configuration_data",
            package_path="",
            package_type="bf55",
            transaction_id_hex="",
            matching_id="",
            success=True,
            result_len=len(response),
            response_preview_hex=self._response_preview_hex(response),
            details={},
        )
        return response

    def delete_eim(self, eim_id: str) -> bytes:
        target = str(eim_id).strip()
        if len(target) == 0:
            raise ValueError("DeleteEim requires eim_id.")
        payload = self._wrap_tlv(b"\x80", target.encode("utf-8"))
        command_payload = self._wrap_tlv(bytes.fromhex("BF59"), payload)
        self.reset_state()
        self.select_isdr()
        response = self._send_retrieve_store_data(command_payload, "EIM-LOCAL: DeleteEim")
        self._sync_pending_notifications(response)
        self._append_response_log_event(
            action="delete_eim",
            package_path="",
            package_type="bf59",
            transaction_id_hex="",
            matching_id=target,
            success=True,
            result_len=len(response),
            response_preview_hex=self._response_preview_hex(response),
            details={"eim_id": target},
        )
        return response

    def euicc_memory_reset(self, package_path: str = "") -> bytes:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        package_document = self.load_eim_package_document(override_path=resolved_path)
        command_payload = self._build_euicc_memory_reset_payload(package_document)
        options = self._euicc_memory_reset_options(package_document)
        self._remember_selected_eim_certificate("", "", [], "")
        self.reset_state()
        self.select_isdr()
        response = self._send_retrieve_store_data(
            command_payload,
            "EIM-LOCAL: eUICCMemoryReset",
        )
        self._sync_pending_notifications(response)
        self.runtime_state.record_operation("euicc_memory_reset", transaction_id_hex="", matching_id="")
        self._append_response_log_event(
            action="euicc_memory_reset",
            package_path=resolved_path,
            package_type="euicc_memory_reset",
            transaction_id_hex="",
            matching_id="",
            success=True,
            result_len=len(response),
            response_preview_hex=self._response_preview_hex(response),
            details={
                "command_payload_hex": command_payload.hex().upper(),
                "options": options,
            },
        )
        return response

    def resolve_eim_package_path(self, override_path: str = "") -> str:
        target = override_path
        if len(target) == 0:
            target = self.eim_state.eim_package_override_path
        if len(target) > 0:
            return self._normalize_user_path(target, base_dir=self.cfg.EIM_PACKAGES_DIR)
        return self._normalize_user_path(
            self.cfg.EIM_DEFAULT_PACKAGE_FILE,
            base_dir=self.cfg.EIM_PACKAGES_DIR,
        )

    def load_eim_package_document(self, override_path: str = "") -> dict[str, Any]:
        package_path = self.resolve_eim_package_path(override_path=override_path)
        return load_eim_package_document(package_path)

    def lint_eim_package(self, package_path: str = "", strict_executable: bool = False) -> dict[str, Any]:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        document = load_eim_package_document(resolved_path)
        report = lint_eim_package_document(document)
        if strict_executable:
            package_type = str(document.get("package_type", "")).strip().lower()
            coverage = self.execution_coverage_matrix().get(package_type, {})
            mode = str(coverage.get("mode", "")).strip().lower()
            if mode == "model_only" and self._is_model_only_allowed(document) is False:
                errors = report.get("errors", [])
                if isinstance(errors, list) is False:
                    errors = []
                errors.append(
                    "strict_executable mode: package_type is model_only and "
                    "runtime.allow_model_only/runtime.mock_mode is not enabled."
                )
                report["errors"] = errors
                report["ok"] = False
            report["strict_executable"] = True
        report["package_path"] = resolved_path
        return report

    def list_eim_package_files(self, package_dir: str = "") -> list[str]:
        target_dir = package_dir.strip()
        if len(target_dir) == 0:
            target_dir = self.cfg.EIM_PACKAGES_DIR
        resolved_dir = self._normalize_user_path(target_dir, base_dir=self.cfg.EIM_PACKAGES_DIR)
        if os.path.isdir(resolved_dir) is False:
            raise NotADirectoryError(f"Package directory does not exist: {resolved_dir}")
        package_files: list[str] = []
        for name in sorted(os.listdir(resolved_dir)):
            full_path = os.path.join(resolved_dir, name)
            if os.path.isdir(full_path):
                continue
            if name.lower().endswith(".json") is False:
                continue
            package_files.append(full_path)
        return package_files

    def _sort_poll_queue_files(self, package_files: list[str]) -> list[str]:
        scored_rows: list[tuple[int, int, str]] = []
        for index, path in enumerate(package_files):
            order_value = self._resolve_hotfolder_order_value(path)
            scored_rows.append((order_value, index, path))
        scored_rows.sort(key=lambda row: (row[0], row[1], row[2]))
        return [row[2] for row in scored_rows]

    def _poll_fixture_directories(self) -> list[tuple[str, str]]:
        return [
            ("fixture.eim_to_esim", self.cfg.EIM_POLL_EIM_TO_ESIM_DIR),
            ("fixture.esim_to_eim", self.cfg.EIM_POLL_ESIM_TO_EIM_DIR),
        ]

    def _exclude_campaign_seen_package_files(
        self,
        package_files: list[str],
        exclude_package_paths: Optional[set[str]] = None,
    ) -> list[str]:
        if exclude_package_paths is None or len(exclude_package_paths) == 0:
            return list(package_files)
        normalized_excludes = {
            os.path.abspath(str(path).strip())
            for path in exclude_package_paths
            if len(str(path).strip()) > 0
        }
        if len(normalized_excludes) == 0:
            return list(package_files)
        remaining: list[str] = []
        for package_path in package_files:
            if os.path.abspath(package_path) in normalized_excludes:
                continue
            remaining.append(package_path)
        return remaining

    def reset_hotfolder_poll_session(self, hotfolder_dir: str = "") -> str:
        resolved_dir = self.resolve_hotfolder_path(override_path=hotfolder_dir.strip())
        self.eim_state.hotfolder_poll_session_dir = resolved_dir
        self.eim_state.hotfolder_poll_session_issued_paths = set()
        return resolved_dir

    def _effective_hotfolder_poll_excludes(
        self,
        hotfolder_dir: str = "",
        exclude_package_paths: Optional[set[str]] = None,
    ) -> tuple[str, set[str]]:
        resolved_dir = self.resolve_hotfolder_path(override_path=hotfolder_dir.strip())
        session_dir = str(self.eim_state.hotfolder_poll_session_dir).strip()
        if len(session_dir) == 0:
            self.eim_state.hotfolder_poll_session_dir = resolved_dir
        else:
            if os.path.abspath(session_dir) != os.path.abspath(resolved_dir):
                self.reset_hotfolder_poll_session(hotfolder_dir=resolved_dir)
        excludes: set[str] = set()
        for package_path in self.eim_state.hotfolder_poll_session_issued_paths:
            normalized_path = os.path.abspath(str(package_path).strip())
            if len(normalized_path) == 0:
                continue
            excludes.add(normalized_path)
        if exclude_package_paths is not None:
            for package_path in exclude_package_paths:
                normalized_path = os.path.abspath(str(package_path).strip())
                if len(normalized_path) == 0:
                    continue
                excludes.add(normalized_path)
        return resolved_dir, excludes

    def _record_hotfolder_poll_issue(self, package_path: str, hotfolder_dir: str = "") -> None:
        resolved_dir = self.resolve_hotfolder_path(override_path=hotfolder_dir.strip())
        session_dir = str(self.eim_state.hotfolder_poll_session_dir).strip()
        if len(session_dir) == 0:
            self.eim_state.hotfolder_poll_session_dir = resolved_dir
        else:
            if os.path.abspath(session_dir) != os.path.abspath(resolved_dir):
                self.reset_hotfolder_poll_session(hotfolder_dir=resolved_dir)
        normalized_path = os.path.abspath(str(package_path).strip())
        if len(normalized_path) == 0:
            return
        self.eim_state.hotfolder_poll_session_issued_paths.add(normalized_path)

    def list_fixed_poll_fixture_package_files(self) -> list[str]:
        if bool(getattr(self.cfg, "EIM_POLL_INCLUDE_FIXED_FIXTURES", True)) is False:
            return []
        package_files: list[str] = []
        for _, target_dir in self._poll_fixture_directories():
            resolved_dir = self._normalize_user_path(target_dir, base_dir=self.cfg.EIM_PACKAGES_DIR)
            if os.path.isdir(resolved_dir) is False:
                continue
            package_files.extend(self.list_eim_package_files(package_dir=resolved_dir))
        return self._sort_poll_queue_files(package_files)

    def list_hotfolder_package_files(self, hotfolder_dir: str = "") -> list[str]:
        resolved_dir = self.resolve_hotfolder_path(override_path=hotfolder_dir.strip())
        package_files = self.list_fixed_poll_fixture_package_files()
        package_files.extend(self.list_eim_package_files(package_dir=resolved_dir))
        return self._sort_poll_queue_files(package_files)

    def list_hotfolder_preview(
        self,
        hotfolder_dir: str = "",
        exclude_package_paths: Optional[set[str]] = None,
    ) -> list[dict[str, Any]]:
        resolved_dir, effective_excludes = self._effective_hotfolder_poll_excludes(
            hotfolder_dir=hotfolder_dir,
            exclude_package_paths=exclude_package_paths,
        )
        package_files = self.list_hotfolder_package_files(hotfolder_dir=resolved_dir)
        package_files = self._exclude_campaign_seen_package_files(
            package_files,
            exclude_package_paths=effective_excludes,
        )
        rows: list[dict[str, Any]] = []
        for order_index, package_path in enumerate(package_files, start=1):
            rows.append(
                self._build_hotfolder_preview_row(
                    order_index,
                    package_path,
                    hotfolder_dir=resolved_dir,
                )
            )
        return rows

    def ipad_discover(self, package_path: str = "") -> list[tuple[str, bytes]]:
        self._activate_runtime_bip_role("eim", reason="ipad_discover")
        sequence = self.discover_card()
        self._sync_pending_notifications()
        if len(package_path.strip()) > 0:
            self.set_eim_package_override_path(package_path)
        return sequence

    def ipae_authenticate(self, matching_id: str = "") -> EimHandoverContext:
        self._activate_runtime_bip_role("eim", reason="ipae_authenticate")
        self.reset_state()
        self.select_isdr()
        self.open_session()
        self._sync_pending_notifications()
        effective_matching_id = matching_id.strip()
        if len(effective_matching_id) == 0:
            effective_matching_id = self._default_matching_id()
        self.eim_state.handover = EimHandoverContext(
            transaction_id=bytes(self.state.transaction_id),
            matching_id=effective_matching_id,
            source="IPAe-AUTHENTICATE",
        )
        return self.eim_state.handover

    def ipae_download(self, profile_path: str = "", matching_id: str = "") -> bytes:
        handover = self.eim_state.handover
        transaction_id = ensure_handover_transaction(handover)
        if len(matching_id.strip()) > 0:
            handover.matching_id = matching_id.strip()
        if len(profile_path.strip()) > 0:
            handover.profile_path = profile_path.strip()
        self._activate_runtime_bip_role("smdpp", reason="ipae_download_handover")
        try:
            response = self.run_load_profile_chain_with_transaction(
                transaction_id=transaction_id,
                profile_path=handover.profile_path or profile_path,
            )
            self._sync_pending_notifications(response)
        finally:
            self._activate_runtime_bip_role("eim", reason="ipae_download_complete")
        return response

    def run_load_profile_chain_with_transaction(self, transaction_id: bytes, profile_path: str = "") -> bytes:
        if len(transaction_id) == 0:
            raise ValueError("transaction_id must not be empty for eIM handover load.")
        source_bytes = self._read_profile_source_bytes(profile_path=profile_path)
        bpp_bytes = b""
        response = b""
        self.reset_state()
        # Four-phase pre-install pipeline (select → open → prepare →
        # build) plus an install phase whose step count is discovered
        # from the BPP. ``_load_profile_from_bytes`` expands the total
        # to cover every per-segment store-data round plus one final
        # "sync notifications" step so the sticky footer keeps moving
        # through the whole chain rather than sitting at 100 % for the
        # duration of LoadBoundProfilePackage and the trailing notify
        # sync.
        with progress_session("eIM handover load", total=4) as bar:
            try:
                bar.advance("select ISD-R")
                self.select_isdr()
                bar.advance("open session")
                self.open_session(transaction_id_override=bytes(transaction_id))
                bar.advance("prepare download")
                self.prepare_download()
                bar.advance("build bpp")
                if source_bytes.startswith(bytes.fromhex("BF36")):
                    bpp_bytes = bytes(source_bytes)
                else:
                    bpp_bytes = self._build_session_bound_profile_package(source_bytes)
                response = self._load_profile_from_bytes(bpp_bytes, progress_bar=bar)
            finally:
                try:
                    if self.state.session_open:
                        self.close_session()
                except Exception:
                    pass
            if len(response) > 0:
                self.state.load_notifications_synced = False
                self._sync_pending_notifications(response)
                self.state.load_notifications_synced = True
        return response

    def _resolve_runtime_transaction_id(self, runtime_hints: dict[str, Any]) -> bytes:
        txid_hex = str(runtime_hints.get("transaction_id_hex", "")).strip().replace(" ", "")
        if len(txid_hex) > 0 and len(txid_hex) % 2 == 0:
            try:
                return bytes.fromhex(txid_hex)
            except ValueError:
                pass
        handover_txid = bytes(self.eim_state.handover.transaction_id)
        if len(handover_txid) > 0:
            return handover_txid
        return bytes(self.state.transaction_id)

    def _resolve_runtime_matching_id(self, runtime_hints: dict[str, Any]) -> str:
        matching_id = str(runtime_hints.get("matching_id", "")).strip()
        if len(matching_id) > 0:
            return matching_id
        handover_matching = str(self.eim_state.handover.matching_id).strip()
        if len(handover_matching) > 0:
            return handover_matching
        return self._default_matching_id()

    def _resolve_runtime_smdp_address(self, runtime_hints: dict[str, Any]) -> str:
        candidate = str(runtime_hints.get("smdp_address", "")).strip()
        if len(candidate) == 0:
            hinted_endpoints = runtime_hints.get("bip_endpoints", {})
            if isinstance(hinted_endpoints, dict):
                candidate = str(hinted_endpoints.get("smdpp", "")).strip()
        if len(candidate) == 0:
            candidate = self.local_smdp_reference_address()
        if len(candidate) == 0:
            candidate = self._effective_smdp_address()
        if len(candidate) > 0:
            self.eim_state.last_intercepted_target = candidate
            self.eim_state.last_intercept_reason = "runtime handover to simulated SM-DP+"
        return candidate

    def _read_profile_source_bytes(self, profile_path: str) -> bytes:
        resolved = self.resolve_profile_path(override_path=profile_path)
        if len(resolved) == 0:
            raise FileNotFoundError("No profile file resolved for direct profile download.")
        with open(resolved, "rb") as handle:
            source_bytes = handle.read()
        if len(source_bytes) == 0:
            raise ValueError("Profile file is empty.")
        return self._decode_profile_bytes(source_bytes)

    def _eid_bcd_string_to_bytes(self, eid: str) -> bytes:
        digits = "".join(char for char in str(eid).strip() if char.isdigit())
        if len(digits) == 0:
            return b""
        if len(digits) % 2 != 0:
            digits += "F"
        try:
            return bytes.fromhex(digits)
        except ValueError:
            return b""

    def _read_card_eid_safe(self) -> str:
        try:
            return self._read_card_eid()
        except Exception:
            return ""

    def _build_euicc_package_result_tlv(
        self,
        card_response: bytes,
        transaction_id: bytes = b"",
    ) -> bytes:
        if len(card_response) == 0 and len(transaction_id) == 0:
            return b""
        if card_response.startswith(bytes.fromhex("BF51")):
            return card_response
        body = b""
        if len(transaction_id) > 0:
            body += self._wrap_tlv(b"\x80", transaction_id)
        body += card_response
        return self._wrap_tlv(bytes.fromhex("BF51"), body)

    def _build_ipa_euicc_data_response_tlv(
        self,
        card_response: bytes,
        transaction_id: bytes = b"",
    ) -> bytes:
        if len(card_response) == 0 and len(transaction_id) == 0:
            return b""
        if card_response.startswith(bytes.fromhex("BF52")):
            return card_response
        body = b""
        if len(transaction_id) > 0:
            body += self._wrap_tlv(b"\x80", transaction_id)
        body += card_response
        return self._wrap_tlv(bytes.fromhex("BF52"), body)

    def _build_profile_download_trigger_result_error(
        self,
        eim_transaction_id: bytes = b"",
        error_reason: int = 127,
    ) -> bytes:
        if error_reason < 0 or error_reason > 127:
            error_reason = 127
        reason_tlv = bytes([0x80, 0x01, error_reason & 0xFF])
        download_error_seq = self._wrap_tlv(b"\x30", reason_tlv)
        body = b""
        if len(eim_transaction_id) > 0:
            body += self._wrap_tlv(b"\x82", eim_transaction_id)
        body += download_error_seq
        return self._wrap_tlv(bytes.fromhex("BF54"), body)

    def _build_profile_download_trigger_result_tlv(
        self,
        card_response: bytes,
        eim_transaction_id: bytes = b"",
    ) -> bytes:
        if len(card_response) == 0:
            return b""
        if card_response.startswith(bytes.fromhex("BF54")):
            return card_response
        body = b""
        if len(eim_transaction_id) > 0:
            body += self._wrap_tlv(b"\x82", eim_transaction_id)
        body += card_response
        return self._wrap_tlv(bytes.fromhex("BF54"), body)

    def _build_eim_package_result_response_error_tlv(
        self,
        eid: str = "",
        error_code: int = 127,
    ) -> bytes:
        if error_code < 0 or error_code > 127:
            error_code = 127
        body = b""
        eid_bytes = self._eid_bcd_string_to_bytes(eid)
        if len(eid_bytes) == 16:
            body += self._wrap_tlv(b"\x5A", eid_bytes)
        body += bytes.fromhex(f"800530030201{error_code:02X}")
        return self._wrap_tlv(bytes.fromhex("BF50"), body)

    def _build_provide_eim_package_result_tlv(self, card_response: bytes, eid: str = "") -> bytes:
        if len(card_response) == 0:
            return b""
        body = b""
        eid_bytes = self._eid_bcd_string_to_bytes(eid)
        if len(eid_bytes) == 16:
            body += self._wrap_tlv(b"\x5A", eid_bytes)
        if (
            card_response.startswith(bytes.fromhex("BF51"))
            or card_response.startswith(bytes.fromhex("BF52"))
            or card_response.startswith(bytes.fromhex("BF54"))
        ):
            body += card_response
        else:
            body += self._build_euicc_package_result_tlv(card_response)
        return self._wrap_tlv(bytes.fromhex("BF50"), body)

    def _run_direct_profile_download_with_transaction(
        self,
        transaction_id: bytes,
        profile_path: str = "",
    ) -> tuple[bytes, bytes]:
        if len(transaction_id) == 0:
            raise ValueError("transaction_id must not be empty for direct profile download.")
        source_bytes = self._read_profile_source_bytes(profile_path=profile_path)
        bpp_bytes = b""
        response = b""
        self.reset_state()
        self._activate_runtime_bip_role("eim", reason="direct_profile_download")
        try:
            self.select_isdr()
            self.open_session(transaction_id_override=bytes(transaction_id))
            self.prepare_download()
            if source_bytes.startswith(bytes.fromhex("BF36")):
                bpp_bytes = bytes(source_bytes)
            else:
                bpp_bytes = self._build_session_bound_profile_package(source_bytes)
            response = self._load_profile_from_bytes(bpp_bytes)
        finally:
            try:
                if self.state.session_open:
                    self.close_session()
            except Exception:
                pass
        if len(response) > 0:
            self.state.load_notifications_synced = False
            self._sync_pending_notifications(response)
            self.state.load_notifications_synced = True
        return response, bpp_bytes

    def _execute_indirect_profile_download_request(
        self,
        package_document: dict[str, Any],
        runtime_hints: dict[str, Any],
    ) -> tuple[bytes, bool, dict[str, Any]]:
        txid = self._resolve_runtime_transaction_id(runtime_hints)
        matching_id = self._resolve_runtime_matching_id(runtime_hints)
        wire_payload = self._build_profile_download_trigger_request_preview(
            package_document,
            runtime_hints,
            txid,
        )
        parsed = parse_eim_package(wire_payload)
        eim_txid = bytes(parsed.eim_transaction_id) or txid
        resolved_matching_id = str(parsed.matching_id or matching_id).strip() or matching_id
        smdp_address = str(parsed.smdp_address or self._resolve_runtime_smdp_address(runtime_hints)).strip()
        profile_path = str(runtime_hints.get("profile_path", "")).strip()
        self.set_handover_transaction(eim_txid.hex().upper(), matching_id=resolved_matching_id)
        eid_value = self._read_card_eid_safe()
        details = {
            "download_mode": "indirect",
            "wire_payload_len": len(wire_payload),
            "wire_payload_preview_hex": self._response_preview_hex(wire_payload),
            "matching_id": resolved_matching_id,
            "smdp_address": smdp_address,
            "profile_path": profile_path,
        }
        try:
            response = self.ipae_download(
                profile_path=profile_path,
                matching_id=resolved_matching_id,
            )
            branch = self._build_profile_download_trigger_result_tlv(
                card_response=response,
                eim_transaction_id=eim_txid,
            )
            provide = self._build_provide_eim_package_result_tlv(branch, eid=eid_value)
            details["card_response_preview_hex"] = self._response_preview_hex(response)
            details["eim_result_preview_hex"] = self._response_preview_hex(provide)
            self.state.eim_package_response = provide
            return provide, True, details
        except Exception as error:
            branch = self._build_profile_download_trigger_result_error(
                eim_transaction_id=eim_txid,
                error_reason=127,
            )
            provide = self._build_provide_eim_package_result_tlv(branch, eid=eid_value)
            details["card_flow_error"] = f"{type(error).__name__}: {error}"
            details["eim_result_preview_hex"] = self._response_preview_hex(provide)
            self.state.eim_package_response = provide
            return provide, False, details

    def _execute_direct_bound_profile_package_request(
        self,
        runtime_hints: dict[str, Any],
    ) -> tuple[bytes, bool, dict[str, Any]]:
        txid = self._resolve_runtime_transaction_id(runtime_hints)
        if len(txid) == 0:
            raise ValueError("Direct profile download requires a transaction_id_hex or active handover transaction.")
        profile_path = str(runtime_hints.get("profile_path", "")).strip()
        matching_id = self._resolve_runtime_matching_id(runtime_hints)
        eid_value = self._read_card_eid_safe()
        details = {
            "download_mode": "direct",
            "matching_id": matching_id,
            "profile_path": profile_path,
        }
        try:
            response, bpp_bytes = self._run_direct_profile_download_with_transaction(
                transaction_id=txid,
                profile_path=profile_path,
            )
            euicc_result = self._build_euicc_package_result_tlv(response, transaction_id=txid)
            provide = self._build_provide_eim_package_result_tlv(euicc_result, eid=eid_value)
            details["bound_profile_package_len"] = len(bpp_bytes)
            details["bound_profile_package_preview_hex"] = self._response_preview_hex(bpp_bytes)
            details["card_response_preview_hex"] = self._response_preview_hex(response)
            details["eim_result_preview_hex"] = self._response_preview_hex(provide)
            self.state.eim_package_response = provide
            return provide, True, details
        except Exception as error:
            provide = self._build_eim_package_result_response_error_tlv(eid=eid_value, error_code=127)
            details["card_flow_error"] = f"{type(error).__name__}: {error}"
            details["eim_result_preview_hex"] = self._response_preview_hex(provide)
            self.state.eim_package_response = provide
            return provide, False, details

    def set_bip_role(self, role: str) -> str:
        raise RuntimeError(
            "Manual BIP role selection is disabled. "
            "Routing is hardcoded and managed by active runtime flow."
        )

    def handover_bip_to_smdpp(self) -> str:
        raise RuntimeError(
            "Manual BIP handover is disabled. "
            "Routing is hardcoded and managed by active runtime flow."
        )

    def handover_bip_to_eim(self) -> str:
        raise RuntimeError(
            "Manual BIP handover is disabled. "
            "Routing is hardcoded and managed by active runtime flow."
        )

    def enforce_notification_hygiene(self, max_pending: Optional[int] = None) -> int:
        self._sync_pending_notifications()
        response = self._send_retrieve_store_data(bytes.fromhex("BF2B00"), "EIM-LOCAL: RetrieveNotificationsList")
        pending_rows = self._extract_notification_metadata_entries(response)
        pending_count = len(pending_rows)
        allowed = self.cfg.EIM_NOTIFICATION_MAX_PENDING
        if max_pending is not None:
            allowed = max_pending
        if pending_count > allowed:
            raise RuntimeError(
                "Notification hygiene failed: pending="
                f"{pending_count}, allowed={allowed}. Drain notifications before continuing."
            )
        return pending_count

    def add_initial_eim(
        self,
        cert_path: str = "",
        package_path: str = "",
        source_mode: str = "package",
    ) -> bytes:
        return self._run_add_eim_command(
            tag_hex=self.cfg.EIM_ADD_INITIAL_TAG_HEX,
            action_label="AddInitialEim",
            cert_path=cert_path,
            package_path=package_path,
            source_mode=source_mode,
        )

    def add_eim(
        self,
        cert_path: str = "",
        package_path: str = "",
        source_mode: str = "package",
    ) -> bytes:
        return self._run_add_eim_command(
            tag_hex=self.cfg.EIM_ADD_TAG_HEX,
            action_label="AddEim",
            cert_path=cert_path,
            package_path=package_path,
            source_mode=source_mode,
        )

    def _run_add_eim_command(
        self,
        tag_hex: str,
        action_label: str,
        cert_path: str = "",
        package_path: str = "",
        source_mode: str = "package",
    ) -> bytes:
        self._activate_runtime_bip_role("eim", reason=action_label)
        normalized_source = source_mode.strip().lower()
        try:
            if normalized_source in ("isdr", "handshake"):
                return self._run_add_eim_from_isdr_handshake(
                    tag_hex=tag_hex,
                    action_label=action_label,
                    cert_path=cert_path,
                )
            if normalized_source in (
                "local",
                "local_auth",
                "package_isdr",
                "package-isdr",
                "isdr_package",
                "isdr-package",
                "session",
            ):
                return self._run_add_eim_from_package_with_local_session(
                    tag_hex=tag_hex,
                    action_label=action_label,
                    cert_path=cert_path,
                    package_path=package_path,
                )
            if normalized_source in ("package", "pkg", "json"):
                return self._run_add_eim_from_package(
                    tag_hex=tag_hex,
                    action_label=action_label,
                    cert_path=cert_path,
                    package_path=package_path,
                )
            raise ValueError("source_mode must be one of: package, isdr, package_isdr.")
        except Exception as error:
            self._append_response_log_event(
                action=action_label,
                package_path=package_path,
                package_type="",
                transaction_id_hex="",
                matching_id="",
                success=False,
                result_len=-1,
                response_preview_hex="",
                details={
                    "mode": normalized_source,
                    "cert_path": cert_path,
                },
                error=error,
            )
            raise

    def _run_add_eim_from_package(
        self,
        tag_hex: str,
        action_label: str,
        cert_path: str = "",
        package_path: str = "",
    ) -> bytes:
        package_document = self.load_eim_package_document(override_path=package_path)
        counter_assignments = self._apply_runtime_counters(package_document)
        runtime_hints = resolve_package_runtime_hints(package_document)
        command_payload, command_mode = self._build_add_eim_command_payload(
            package_document=package_document,
            tag_hex=tag_hex,
            cert_override_path=cert_path,
        )
        matching_id = str(runtime_hints.get("matching_id", "")).strip()

        self.reset_state()
        self.select_isdr()
        response = self._send_retrieve_store_data(
            command_payload,
            f"EIM-LOCAL: {action_label}",
        )
        self._sync_pending_notifications(response)
        self.enforce_notification_hygiene()
        self._commit_counter_assignments(counter_assignments)
        self.runtime_state.record_operation(
            action_label,
            transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
            matching_id=matching_id,
        )
        self._append_response_log_event(
            action=action_label,
            package_path=package_path,
            package_type=str(package_document.get("package_type", "")),
            transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
            matching_id=matching_id,
            success=True,
            result_len=len(response),
            response_preview_hex=self._response_preview_hex(response),
            details={
                "mode": command_mode,
                "cert_path": self.eim_state.selected_eim_certificate_path.strip(),
                "cert_reason": self.eim_state.selected_eim_certificate_reason.strip(),
                "cert_root_ci_pkids": list(self.eim_state.selected_eim_certificate_ci_pkids),
                "wire_payload_len": len(command_payload),
                "wire_payload_preview_hex": self._response_preview_hex(command_payload),
            },
        )
        return response

    def _run_add_eim_from_package_with_local_session(
        self,
        tag_hex: str,
        action_label: str,
        cert_path: str = "",
        package_path: str = "",
    ) -> bytes:
        package_document = self.load_eim_package_document(override_path=package_path)
        counter_assignments = self._apply_runtime_counters(package_document)
        runtime_hints = resolve_package_runtime_hints(package_document)
        command_payload, command_mode = self._build_add_eim_command_payload(
            package_document=package_document,
            tag_hex=tag_hex,
            cert_override_path=cert_path,
        )
        matching_id = str(runtime_hints.get("matching_id", "")).strip()

        self.reset_state()
        self.select_isdr()
        self.open_session()
        response = b""
        try:
            response = self._send_retrieve_store_data(
                command_payload,
                f"EIM-LOCAL: {action_label} [LOCAL-AUTH]",
            )
            self._sync_pending_notifications(response)
            self.enforce_notification_hygiene()
            self._commit_counter_assignments(counter_assignments)
            self.runtime_state.record_operation(
                action_label,
                transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                matching_id=matching_id,
            )
            self._append_response_log_event(
                action=action_label,
                package_path=package_path,
                package_type=str(package_document.get("package_type", "")),
                transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                matching_id=matching_id,
                success=True,
                result_len=len(response),
                response_preview_hex=self._response_preview_hex(response),
                details={
                    "mode": f"{command_mode}_isdr",
                    "transport": "local_auth",
                    "cert_path": self.eim_state.selected_eim_certificate_path.strip(),
                    "cert_reason": self.eim_state.selected_eim_certificate_reason.strip(),
                    "cert_root_ci_pkids": list(self.eim_state.selected_eim_certificate_ci_pkids),
                    "wire_payload_len": len(command_payload),
                    "wire_payload_preview_hex": self._response_preview_hex(command_payload),
                },
            )
        finally:
            if self.state.session_open:
                self.close_session()
        return response

    def _run_add_eim_from_isdr_handshake(
        self,
        tag_hex: str,
        action_label: str,
        cert_path: str = "",
    ) -> bytes:
        cert_file = cert_path.strip()
        resolved_cert, _, _, _ = self._resolve_signing_certificate_candidate(
            requested_path=cert_file,
            preferred_ci_pkids=[self._effective_euicc_ci_pk_id()],
            allow_auto_select=self._is_auto_selectable_signing_cert_path(cert_file),
        )
        cert_bytes, resolved_cert = self._load_certificate_bytes(resolved_cert)
        if len(cert_bytes) == 0:
            raise RuntimeError(f"{action_label} certificate file is empty: {resolved_cert}")

        matching_id = self.eim_state.handover.matching_id.strip()
        if len(matching_id) == 0:
            matching_id = self._default_matching_id()
        endpoint = self.cfg.EIM_BIP_ENDPOINT

        payload = b""
        payload += self._wrap_tlv(b"\x80", cert_bytes)
        payload += self._wrap_tlv(b"\x81", endpoint.encode("utf-8"))
        if len(matching_id) > 0:
            payload += self._wrap_tlv(b"\x82", matching_id.encode("utf-8"))
        command_tag = bytes.fromhex(tag_hex)
        command_payload = self._wrap_tlv(command_tag, payload)

        self.reset_state()
        self.select_isdr()
        self.open_session()
        response = b""
        try:
            response = self._send_retrieve_store_data(
                command_payload,
                f"EIM-LOCAL: {action_label} [ISDR-HANDSHAKE]",
            )
            self._sync_pending_notifications(response)
            self.enforce_notification_hygiene()
            self.runtime_state.record_operation(
                f"{action_label}_isdr",
                transaction_id_hex="",
                matching_id=matching_id,
            )
            self._append_response_log_event(
                action=action_label,
                package_path="",
                package_type=f"{action_label.lower()}_isdr",
                transaction_id_hex="",
                matching_id=matching_id,
                success=True,
                result_len=len(response),
                response_preview_hex=self._response_preview_hex(response),
                details={
                    "mode": "isdr",
                    "cert_path": resolved_cert,
                    "cert_reason": self.eim_state.selected_eim_certificate_reason.strip(),
                    "cert_root_ci_pkids": list(self.eim_state.selected_eim_certificate_ci_pkids),
                },
            )
        finally:
            if self.state.session_open:
                self.close_session()
        return response

    def _build_add_eim_command_payload(
        self,
        package_document: dict[str, Any],
        tag_hex: str,
        cert_override_path: str = "",
    ) -> tuple[bytes, str]:
        request_section = self._resolve_add_eim_request_section(package_document)
        if request_section is not None:
            return (
                self._build_add_eim_sgp32_command_payload(
                    package_document=package_document,
                    request_section=request_section,
                    default_tag_hex=tag_hex,
                    cert_override_path=cert_override_path,
                ),
                "package_sgp32",
            )
        return (
            self._build_add_eim_legacy_command_payload(
                package_document=package_document,
                tag_hex=tag_hex,
                cert_override_path=cert_override_path,
            ),
            "package_bridge",
        )

    def _resolve_add_eim_request_section(self, package_document: dict[str, Any]) -> Optional[dict[str, Any]]:
        package_type = str(package_document.get("package_type", "")).strip().lower()
        sgp32 = package_document.get("sgp32", {})
        if isinstance(sgp32, dict) is False:
            return None
        if package_type in ("add_initial_eim", "addinitialeim"):
            request = sgp32.get("add_initial_eim_request", {})
            if isinstance(request, dict):
                return request
            return None
        if package_type in ("add_eim", "addeim"):
            request = sgp32.get("add_eim_request", {})
            if isinstance(request, dict):
                return request
            return None
        return None

    def _build_add_eim_sgp32_command_payload(
        self,
        package_document: dict[str, Any],
        request_section: dict[str, Any],
        default_tag_hex: str,
        cert_override_path: str = "",
    ) -> bytes:
        if bool(request_section.get("include", True)) is False:
            raise ValueError("add-eim request section must have include=true.")
        rows = request_section.get("eim_configuration_data_list", [])
        if isinstance(rows, list) is False or len(rows) == 0:
            raise ValueError("eim_configuration_data_list must contain at least one entry.")
        encoded_rows: list[bytes] = []
        remaining_override = cert_override_path.strip()
        for row in rows:
            if isinstance(row, dict) is False:
                continue
            if bool(row.get("include", True)) is False:
                continue
            encoded_rows.append(
                self._wrap_tlv(
                    b"\x30",
                    self._encode_eim_configuration_row(
                        row,
                        cert_override_path=remaining_override,
                    ),
                )
            )
            remaining_override = ""
        if len(encoded_rows) == 0:
            raise ValueError("No enabled eim_configuration_data_list rows were found.")
        tag_value = str(default_tag_hex).strip().upper()
        request_command_tag = str(request_section.get("command_tag_hex", "")).strip().upper()
        if len(request_command_tag) > 0:
            tag_value = request_command_tag
        payload = self._wrap_tlv(b"\xA0", b"".join(encoded_rows))
        return self._wrap_tlv(bytes.fromhex(tag_value), payload)

    def _build_add_eim_legacy_command_payload(
        self,
        package_document: dict[str, Any],
        tag_hex: str,
        cert_override_path: str = "",
    ) -> bytes:
        runtime_hints = resolve_package_runtime_hints(package_document)
        cert_file = cert_override_path.strip()
        if len(cert_file) == 0:
            cert_file = str(runtime_hints.get("cert_der_path", "")).strip()
        if len(cert_file) == 0:
            cert_file = self._effective_eim_public_key_cert_path()
        if len(cert_file) == 0:
            raise ValueError("Legacy add-eim bridge requires cert_path or cert_der_path.")
        resolved_cert, _, _, _ = self._resolve_signing_certificate_candidate(
            requested_path=cert_file,
            preferred_ci_pkids=[self._effective_euicc_ci_pk_id()],
            allow_auto_select=self._is_auto_selectable_signing_cert_path(cert_file)
            and len(cert_override_path.strip()) == 0,
        )
        cert_bytes, _ = self._load_certificate_bytes(resolved_cert)
        payload = b""
        if bool(package_document.get("include_cert_tag", True)):
            payload += self._wrap_tlv(b"\x80", cert_bytes)
        endpoint = self._resolve_package_endpoint(package_document)
        if bool(package_document.get("include_endpoint_tag", True)) and len(endpoint) > 0:
            payload += self._wrap_tlv(b"\x81", endpoint.encode("utf-8"))
        matching_id = str(runtime_hints.get("matching_id", "")).strip()
        if bool(package_document.get("include_matching_id_tag", True)) and len(matching_id) > 0:
            payload += self._wrap_tlv(b"\x82", matching_id.encode("utf-8"))
        for extra_tag, extra_value in encode_additional_tlvs(package_document):
            payload += self._wrap_tlv(extra_tag, extra_value)
        for extra_tag, extra_value in encode_optional_tlvs(package_document):
            payload += self._wrap_tlv(extra_tag, extra_value)
        return self._wrap_tlv(bytes.fromhex(tag_hex), payload)

    def _encode_eim_configuration_row(
        self,
        row: dict[str, Any],
        cert_override_path: str = "",
    ) -> bytes:
        payload = b""
        preferred_ci_pkids: list[str] = []
        eim_id = self._field_mapping(row.get("eim_id"))
        if bool(eim_id.get("include", True)):
            value = str(eim_id.get("value", "")).strip()
            if len(value) == 0:
                value = self._effective_eim_id()
            if len(value) == 0:
                raise ValueError("eim_id.value must be non-empty.")
            payload += self._wrap_tlv(b"\x80", value.encode("utf-8"))
        eim_fqdn = self._field_mapping(row.get("eim_fqdn"))
        if bool(eim_fqdn.get("include", False)):
            value = str(eim_fqdn.get("value", "")).strip()
            if len(value) == 0:
                value = self._effective_eim_fqdn()
            if len(value) == 0:
                raise ValueError("eim_fqdn.value must be non-empty when include=true.")
            payload += self._wrap_tlv(b"\x81", value.encode("utf-8"))
        eim_id_type = self._field_mapping(row.get("eim_id_type"))
        if bool(eim_id_type.get("include", False)):
            eim_id_type_value = eim_id_type.get("value")
            if len(str(eim_id_type_value or "").strip()) == 0:
                eim_id_type_value = self._effective_eim_id_type()
            payload += self._wrap_tlv(
                b"\x82",
                self._encode_minimal_unsigned_integer(
                    self._resolve_eim_id_type_code(eim_id_type_value)
                ),
            )
        counter_value = self._field_mapping(row.get("counter_value"))
        if bool(counter_value.get("include", True)):
            payload += self._wrap_tlv(
                b"\x83",
                self._encode_minimal_unsigned_integer(
                    self._coerce_integer(counter_value.get("value"), "counter_value.value")
                ),
            )
        association_token = self._field_mapping(row.get("association_token"))
        if bool(association_token.get("include", False)):
            payload += self._wrap_tlv(
                b"\x84",
                self._encode_association_token(
                    association_token.get("value")
                ),
            )
        euicc_ci_pk_id = self._field_mapping(row.get("euicc_ci_pk_id"))
        euicc_ci_pk_value = ""
        if bool(euicc_ci_pk_id.get("include", False)):
            euicc_ci_pk_value = str(euicc_ci_pk_id.get("value_hex", "")).strip()
            if len(euicc_ci_pk_value) == 0:
                euicc_ci_pk_value = self._effective_euicc_ci_pk_id()
            normalized_ci_pkid = self._normalize_ci_pkid(euicc_ci_pk_value)
            if len(normalized_ci_pkid) > 0:
                preferred_ci_pkids.append(normalized_ci_pkid)
        eim_public_key_data = self._field_mapping(row.get("eim_public_key_data"))
        if bool(eim_public_key_data.get("include", True)):
            payload += self._wrap_tlv(
                b"\xA5",
                self._encode_subject_public_key_choice(
                    field=eim_public_key_data,
                    certificate_path_key="eim_certificate_der_path",
                    certificate_hex_key="eim_certificate_der_hex",
                    public_key_hex_key="eim_public_key_spki_hex",
                    cert_override_path=cert_override_path,
                    default_certificate_path=self._effective_eim_public_key_cert_path(),
                    preferred_ci_pkids=preferred_ci_pkids,
                    allow_auto_select=True,
                ),
            )
        trusted_tls = self._field_mapping(row.get("trusted_public_key_data_tls"))
        if bool(trusted_tls.get("include", False)):
            payload += self._wrap_tlv(
                b"\xA6",
                self._encode_subject_public_key_choice(
                    field=trusted_tls,
                    certificate_path_key="trusted_certificate_der_path",
                    certificate_hex_key="trusted_certificate_der_hex",
                    public_key_hex_key="trusted_eim_pk_tls_spki_hex",
                    default_certificate_path=self._effective_trusted_tls_cert_path(),
                    preferred_ci_pkids=[],
                    allow_auto_select=False,
                ),
            )
        supported_protocol = self._field_mapping(row.get("eim_supported_protocol"))
        if bool(supported_protocol.get("include", False)):
            payload += self._wrap_tlv(
                b"\x87",
                self._encode_eim_supported_protocol_value(supported_protocol),
            )
        if bool(euicc_ci_pk_id.get("include", False)):
            payload += self._wrap_tlv(
                b"\x88",
                self._decode_hex_field(
                    euicc_ci_pk_value,
                    "euicc_ci_pk_id.value_hex",
                ),
            )
        indirect_profile_download = self._field_mapping(row.get("indirect_profile_download"))
        if bool(indirect_profile_download.get("include", False)):
            payload += self._wrap_tlv(b"\x89", b"")
        return payload

    @staticmethod
    def _field_mapping(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    def _encode_subject_public_key_choice(
        self,
        *,
        field: dict[str, Any],
        certificate_path_key: str,
        certificate_hex_key: str,
        public_key_hex_key: str,
        cert_override_path: str = "",
        default_certificate_path: str = "",
        preferred_ci_pkids: Optional[list[str]] = None,
        allow_auto_select: bool = False,
    ) -> bytes:
        choice = str(field.get("choice", "")).strip().lower()
        if choice in (
            "eim_public_key",
            "public_key",
            "spki",
            "trusted_eim_pk_tls",
            "trusted_public_key_tls",
        ):
            return self._wrap_tlv(
                b"\xA0",
                self._decode_hex_field(
                    field.get(public_key_hex_key),
                    public_key_hex_key,
                ),
            )
        if choice in (
            "eim_certificate",
            "certificate",
            "trusted_certificate_tls",
            "trusted_certificate",
        ):
            cert_bytes = self._load_certificate_bytes_from_field(
                field=field,
                path_key=certificate_path_key,
                hex_key=certificate_hex_key,
                cert_override_path=cert_override_path,
                default_path=default_certificate_path,
                preferred_ci_pkids=preferred_ci_pkids or [],
                allow_auto_select=allow_auto_select,
            )
            return self._wrap_tlv(b"\xA1", cert_bytes)
        raise ValueError(
            "Unsupported subject public key choice: "
            f"{choice or '(empty)'}"
        )

    def _load_certificate_bytes_from_field(
        self,
        *,
        field: dict[str, Any],
        path_key: str,
        hex_key: str,
        cert_override_path: str = "",
        default_path: str = "",
        preferred_ci_pkids: list[str],
        allow_auto_select: bool = False,
    ) -> bytes:
        override_path = cert_override_path.strip()
        if len(override_path) > 0:
            if allow_auto_select:
                resolved_path, _, _, _ = self._resolve_signing_certificate_candidate(
                    requested_path=override_path,
                    preferred_ci_pkids=preferred_ci_pkids,
                    allow_auto_select=False,
                )
                cert_bytes, _ = self._load_certificate_bytes(resolved_path)
                return cert_bytes
            cert_bytes, _ = self._load_certificate_bytes(override_path)
            return cert_bytes
        value_hex = str(field.get(hex_key, "")).strip().replace(" ", "")
        if len(value_hex) > 0:
            return self._decode_hex_field(value_hex, hex_key)
        path_value = str(field.get(path_key, "")).strip()
        if len(path_value) == 0:
            path_value = default_path.strip()
        if len(path_value) == 0:
            raise ValueError(f"{path_key} or {hex_key} must be set.")
        if allow_auto_select:
            resolved_path, _, _, _ = self._resolve_signing_certificate_candidate(
                requested_path=path_value,
                preferred_ci_pkids=preferred_ci_pkids,
                allow_auto_select=self._is_auto_selectable_signing_cert_path(path_value),
            )
            cert_bytes, _ = self._load_certificate_bytes(resolved_path)
            return cert_bytes
        cert_bytes, _ = self._load_certificate_bytes(path_value)
        return cert_bytes

    def _load_certificate_bytes(self, path_text: str) -> tuple[bytes, str]:
        resolved_path = self._normalize_user_path(path_text, base_dir=self.cfg.EIM_CERTS_DIR)
        raw_bytes = read_secret_file_bytes(
            resolved_path,
            protect_plaintext_on_read=True,
        )
        if len(raw_bytes) == 0:
            raise RuntimeError(f"Certificate file is empty: {resolved_path}")
        stripped = raw_bytes.lstrip()
        if stripped.startswith(b"-----BEGIN CERTIFICATE-----"):
            begin_marker = b"-----BEGIN CERTIFICATE-----"
            end_marker = b"-----END CERTIFICATE-----"
            start = stripped.find(begin_marker)
            end = stripped.find(end_marker, start)
            if start < 0 or end < 0:
                raise ValueError(f"Invalid PEM certificate file: {resolved_path}")
            pem_bytes = stripped[start : end + len(end_marker)] + b"\n"
            certificate = crypto_x509.load_pem_x509_certificate(pem_bytes)
            raw_bytes = certificate.public_bytes(serialization.Encoding.DER)
        return raw_bytes, resolved_path

    def _normalize_ci_pkid(self, value: Any) -> str:
        text = str(value or "").strip().replace(" ", "").upper()
        if len(text) == 0:
            return ""
        if len(text) % 2 != 0:
            return ""
        try:
            bytes.fromhex(text)
        except ValueError:
            return ""
        return text

    def _normalize_ci_pkid_list(self, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            clean = self._normalize_ci_pkid(value)
            if len(clean) == 0:
                continue
            if clean in normalized:
                continue
            normalized.append(clean)
        return normalized

    def _card_allowed_ci_pkids_for_eim_cert_selection(self) -> list[str]:
        cached = self._normalize_ci_pkid_list(list(self.state.allowed_ci_pkids))
        if len(cached) > 0:
            return cached
        if self.apdu_channel is None:
            return []
        try:
            if self.state.isdr_selected is False:
                self.select_isdr()
            self.get_euicc_configured_data()
        except Exception:
            return self._normalize_ci_pkid_list(list(self.state.allowed_ci_pkids))
        return self._normalize_ci_pkid_list(list(self.state.allowed_ci_pkids))

    def _is_auto_selectable_signing_cert_path(self, path_text: str) -> bool:
        candidate = str(path_text or "").strip()
        if len(candidate) == 0:
            return True
        identity_path = self._effective_eim_public_key_cert_path()
        if len(identity_path) == 0:
            return False
        try:
            normalized_candidate = self._normalize_user_path(candidate, base_dir=self.cfg.EIM_CERTS_DIR)
            normalized_identity = self._normalize_user_path(identity_path, base_dir=self.cfg.EIM_CERTS_DIR)
        except Exception:
            return False
        return normalized_candidate == normalized_identity

    def _remember_selected_eim_certificate(
        self,
        path: str,
        reason: str = "",
        root_ci_pkids: Optional[list[str]] = None,
        private_key_path: str = "",
    ) -> None:
        self.eim_state.selected_eim_certificate_path = str(path or "").strip()
        self.eim_state.selected_eim_certificate_reason = str(reason or "").strip()
        self.eim_state.selected_eim_certificate_ci_pkids = list(root_ci_pkids or [])
        self.eim_state.selected_eim_private_key_path = str(private_key_path or "").strip()

    def _preferred_ci_pkids_from_package_path(self, package_path: str = "") -> list[str]:
        candidate = str(package_path or "").strip()
        default_ci = self._normalize_ci_pkid(self._effective_euicc_ci_pk_id())
        if len(candidate) == 0:
            if len(default_ci) == 0:
                return []
            return [default_ci]
        try:
            resolved_path = self.resolve_eim_package_path(override_path=candidate)
            package_document = self.load_eim_package_document(override_path=resolved_path)
        except Exception:
            if len(default_ci) == 0:
                return []
            return [default_ci]
        request_section = self._resolve_add_eim_request_section(package_document)
        if request_section is None:
            if len(default_ci) == 0:
                return []
            return [default_ci]
        values: list[str] = []
        rows = request_section.get("eim_configuration_data_list", [])
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) is False:
                    continue
                if bool(row.get("include", True)) is False:
                    continue
                field = self._field_mapping(row.get("euicc_ci_pk_id"))
                if bool(field.get("include", False)) is False:
                    continue
                candidate_ci = str(field.get("value_hex", "")).strip()
                if len(candidate_ci) == 0:
                    candidate_ci = self._effective_euicc_ci_pk_id()
                normalized = self._normalize_ci_pkid(candidate_ci)
                if len(normalized) == 0:
                    continue
                if normalized in values:
                    continue
                values.append(normalized)
        if len(values) == 0 and len(default_ci) > 0:
            values.append(default_ci)
        return values

    def _signing_certificate_selection_reason(
        self,
        record: EimCertificateRecord,
        allowed_ci_pkids: list[str],
        preferred_ci_pkids: list[str],
        fallback_path: str,
    ) -> str:
        record_ci_pkids = set(record.root_ci_pkids)
        allowed = set(self._normalize_ci_pkid_list(allowed_ci_pkids))
        preferred = set(self._normalize_ci_pkid_list(preferred_ci_pkids))
        if len(record_ci_pkids.intersection(allowed)) > 0 and len(record_ci_pkids.intersection(preferred)) > 0:
            return "card_ci_and_preferred_ci_match"
        if len(record_ci_pkids.intersection(allowed)) > 0:
            return "card_allowed_ci_match"
        if len(record_ci_pkids.intersection(preferred)) > 0:
            return "preferred_ci_match"
        normalized_path = self._normalize_user_path(record.certificate_path, base_dir=self.cfg.EIM_CERTS_DIR)
        identity_path = self._effective_eim_public_key_cert_path()
        if len(identity_path) > 0:
            normalized_identity = self._normalize_user_path(identity_path, base_dir=self.cfg.EIM_CERTS_DIR)
            if normalized_path == normalized_identity:
                return "identity_default_fallback"
        if len(fallback_path) > 0:
            normalized_fallback = self._normalize_user_path(fallback_path, base_dir=self.cfg.EIM_CERTS_DIR)
            if normalized_path == normalized_fallback:
                return "requested_path_fallback"
        return "inventory_fallback"

    def _resolve_signing_certificate_candidate(
        self,
        *,
        requested_path: str = "",
        preferred_ci_pkids: Optional[list[str]] = None,
        allow_auto_select: bool = False,
        update_state: bool = True,
    ) -> tuple[str, str, list[str], str]:
        requested = str(requested_path or "").strip()
        fallback_path = requested
        if len(fallback_path) == 0:
            fallback_path = self._effective_eim_public_key_cert_path()
        if len(fallback_path) == 0:
            raise ValueError("No eIM signing certificate path is configured.")
        if allow_auto_select is False and len(requested) > 0:
            resolved = self._normalize_user_path(requested, base_dir=self.cfg.EIM_CERTS_DIR)
            record = self._eim_cert_store.record_for_path(resolved)
            reason = "explicit_override"
            root_ci_pkids = list(record.root_ci_pkids) if record is not None else []
            private_key_path = record.private_key_path if record is not None else ""
            if update_state:
                self._remember_selected_eim_certificate(
                    resolved,
                    reason=reason,
                    root_ci_pkids=root_ci_pkids,
                    private_key_path=private_key_path,
                )
            return resolved, reason, root_ci_pkids, private_key_path
        allowed_ci_pkids = self._card_allowed_ci_pkids_for_eim_cert_selection() if allow_auto_select else []
        preferred = self._normalize_ci_pkid_list(list(preferred_ci_pkids or []))
        if len(preferred) == 0:
            default_ci = self._normalize_ci_pkid(self._effective_euicc_ci_pk_id())
            if len(default_ci) > 0:
                preferred.append(default_ci)
        record = None
        if allow_auto_select:
            record = self._eim_cert_store.resolve_signing_record(
                allowed_ci_pkids=allowed_ci_pkids,
                preferred_ci_pkids=preferred,
                fallback_path=fallback_path,
            )
        if record is None:
            resolved = self._normalize_user_path(fallback_path, base_dir=self.cfg.EIM_CERTS_DIR)
            record = self._eim_cert_store.record_for_path(resolved)
            reason = "identity_default" if len(requested) == 0 else "requested_path"
            root_ci_pkids = list(record.root_ci_pkids) if record is not None else []
            private_key_path = record.private_key_path if record is not None else ""
            if update_state:
                self._remember_selected_eim_certificate(
                    resolved,
                    reason=reason,
                    root_ci_pkids=root_ci_pkids,
                    private_key_path=private_key_path,
                )
            return resolved, reason, root_ci_pkids, private_key_path
        reason = self._signing_certificate_selection_reason(
            record,
            allowed_ci_pkids=allowed_ci_pkids,
            preferred_ci_pkids=preferred,
            fallback_path=fallback_path,
        )
        if update_state:
            self._remember_selected_eim_certificate(
                record.certificate_path,
                reason=reason,
                root_ci_pkids=list(record.root_ci_pkids),
                private_key_path=record.private_key_path,
            )
        return record.certificate_path, reason, list(record.root_ci_pkids), record.private_key_path

    @classmethod
    def _resolve_eim_id_type_code(cls, value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("eim_id_type.value must not be a boolean.")
        if isinstance(value, int):
            if value in (1, 2, 3):
                return value
            raise ValueError(f"Unsupported eim_id_type integer: {value}")
        normalized = str(value).strip().lower()
        compact = normalized.replace("_", "").replace("-", "")
        resolved = cls.EIM_ID_TYPE_CODE_MAP.get(compact)
        if resolved is None:
            raise ValueError(f"Unsupported eim_id_type value: {value}")
        return resolved

    @staticmethod
    def _coerce_integer(value: Any, field_name: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{field_name} must not be boolean.")
        if isinstance(value, int):
            return value
        text = str(value).strip()
        if len(text) == 0:
            raise ValueError(f"{field_name} must be non-empty.")
        try:
            return int(text, 10)
        except ValueError as error:
            raise ValueError(f"{field_name} must be a decimal integer.") from error

    @staticmethod
    def _encode_minimal_unsigned_integer(value: int) -> bytes:
        if value < 0:
            raise ValueError("Unsigned integer must be zero or positive.")
        if value == 0:
            return b"\x00"
        length = max(1, (int(value).bit_length() + 7) // 8)
        return int(value).to_bytes(length, "big")

    def _encode_association_token(self, value: Any) -> bytes:
        token_value = self._coerce_integer(value, "association_token.value")
        if token_value < 0:
            return b"\xFF"
        return self._encode_minimal_unsigned_integer(token_value)

    @staticmethod
    def _decode_hex_field(value: Any, field_name: str) -> bytes:
        text = str(value or "").strip().replace(" ", "")
        if len(text) == 0:
            raise ValueError(f"{field_name} must be non-empty hex.")
        try:
            return bytes.fromhex(text)
        except ValueError as error:
            raise ValueError(f"{field_name} must be valid even-length hex.") from error

    @classmethod
    def _encode_eim_supported_protocol_value(cls, field: dict[str, Any]) -> bytes:
        highest_set_bit = -1
        payload = bytearray(1)
        for bit_index, flag_name in enumerate(cls.EIM_SUPPORTED_PROTOCOL_FLAGS):
            if bool(field.get(flag_name, False)) is False:
                continue
            highest_set_bit = bit_index
            payload[0] |= 1 << (7 - bit_index)
        if highest_set_bit < 0:
            return bytes.fromhex("0800")
        unused_bits = 7 - highest_set_bit
        return bytes([unused_bits & 0xFF]) + bytes(payload)

    def set_handover_transaction(self, transaction_id_hex: str, matching_id: str = "") -> EimHandoverContext:
        raw_hex = transaction_id_hex.strip().replace(" ", "")
        if len(raw_hex) == 0:
            raise ValueError("transaction_id_hex must be non-empty.")
        transaction_id = bytes.fromhex(raw_hex)
        self.eim_state.handover = EimHandoverContext(
            transaction_id=transaction_id,
            matching_id=matching_id.strip(),
            source="manual",
        )
        return self.eim_state.handover

    def handover_context(self) -> dict[str, Any]:
        return self.eim_state.handover.as_json_dict()

    def pending_operations(self) -> list[dict[str, str]]:
        rows = self.eim_state.pending_operations
        return [dict(row) for row in rows]

    def runtime_state_summary(self) -> dict[str, Any]:
        payload = self.runtime_state.to_dict()
        payload["state_file"] = self.cfg.EIM_RUNTIME_STATE_FILE
        payload["response_log_file"] = self.cfg.EIM_RESPONSE_LOG_FILE
        payload["poll_audit_db_file"] = self.cfg.EIM_POLL_AUDIT_DB_FILE
        return payload

    def identity_summary(self) -> dict[str, str]:
        payload = dict(self.eim_identity)
        payload["identity_file"] = self.cfg.EIM_IDENTITY_FILE
        return payload

    def selected_eim_certificate_summary(self) -> dict[str, Any]:
        return {
            "path": self.eim_state.selected_eim_certificate_path.strip(),
            "reason": self.eim_state.selected_eim_certificate_reason.strip(),
            "root_ci_pkids": list(self.eim_state.selected_eim_certificate_ci_pkids),
            "private_key_path": self.eim_state.selected_eim_private_key_path.strip(),
        }

    def preview_eim_signing_certificate(
        self,
        package_path: str = "",
        cert_path: str = "",
    ) -> dict[str, Any]:
        preferred_ci_pkids = self._preferred_ci_pkids_from_package_path(package_path)
        allow_auto_select = len(str(cert_path or "").strip()) == 0
        resolved_path, reason, root_ci_pkids, private_key_path = self._resolve_signing_certificate_candidate(
            requested_path=cert_path,
            preferred_ci_pkids=preferred_ci_pkids,
            allow_auto_select=allow_auto_select,
            update_state=False,
        )
        return {
            "path": resolved_path,
            "reason": reason,
            "root_ci_pkids": list(root_ci_pkids),
            "private_key_path": private_key_path,
            "card_allowed_ci_pkids": self._card_allowed_ci_pkids_for_eim_cert_selection(),
            "preferred_ci_pkids": preferred_ci_pkids,
        }

    def list_eim_certificate_inventory(
        self,
        package_path: str = "",
        cert_path: str = "",
    ) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for record in self._eim_cert_store.signing_records():
            rows.append(
                {
                    "path": record.certificate_path,
                    "private_key_path": record.private_key_path,
                    "subject": record.subject,
                    "issuer": record.issuer,
                    "subject_cn": record.subject_cn,
                    "curve": record.curve,
                    "root_ci_pkids": list(record.root_ci_pkids),
                    "source": record.source,
                }
            )
        return {
            "card_allowed_ci_pkids": self._card_allowed_ci_pkids_for_eim_cert_selection(),
            "selected": self.preview_eim_signing_certificate(
                package_path=package_path,
                cert_path=cert_path,
            ),
            "count": len(rows),
            "rows": rows,
        }

    def response_log_path(self) -> str:
        return self.cfg.EIM_RESPONSE_LOG_FILE

    def poll_audit_db_path(self) -> str:
        return self.cfg.EIM_POLL_AUDIT_DB_FILE

    def read_response_log(self, limit: int = 25) -> list[dict[str, Any]]:
        path = self.response_log_path()
        if os.path.isfile(path) is False:
            return []
        max_rows = int(limit)
        if max_rows <= 0:
            max_rows = 1
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except Exception:
            return []
        rows: list[dict[str, Any]] = []
        for raw in lines[-max_rows:]:
            text = str(raw).strip()
            if len(text) == 0:
                continue
            try:
                payload = json.loads(text)
            except Exception:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows

    def clear_response_log(self) -> int:
        path = self.response_log_path()
        if os.path.isfile(path) is False:
            return 0
        try:
            with open(path, "r", encoding="utf-8") as handle:
                count = len(handle.read().splitlines())
        except Exception:
            count = 0
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("")
        return count

    def read_poll_audit_rows(
        self,
        limit: int = 25,
        *,
        eid: str = "",
        flow: str = "",
        package_type: str = "",
    ) -> list[dict[str, Any]]:
        return self.poll_audit_store.list_events(
            limit=limit,
            eid=eid,
            flow=flow,
            package_type=package_type,
        )

    def clear_poll_audit_rows(self) -> int:
        return self.poll_audit_store.clear()

    def filter_response_log(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        needle = str(query).strip().upper()
        if len(needle) == 0:
            return self.read_response_log(limit=limit)
        rows = self.read_response_log(limit=max(int(limit) * 4, int(limit)))
        filtered: list[dict[str, Any]] = []
        for row in rows:
            txid = str(row.get("transaction_id_hex", "")).strip().upper()
            mid = str(row.get("matching_id", "")).strip().upper()
            pkg = str(row.get("package_path", "")).strip().upper()
            action = str(row.get("action", "")).strip().upper()
            if needle in txid or needle in mid or needle in pkg or needle in action:
                filtered.append(row)
        if len(filtered) > limit:
            return filtered[-limit:]
        return filtered

    def set_error_code_in_package(
        self,
        family: str,
        code_value: Any,
        package_path: str = "",
    ) -> dict[str, Any]:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        document = load_eim_package_document(resolved_path)
        normalized_family = str(family).strip().lower().replace("-", "_").replace(".", "_")
        updated_paths: list[str] = []
        resolved_code = 127
        resolved_name = "undefinedError(127)"

        if normalized_family in (
            "sgp32_eim_package_result_error",
            "eim_package_result_error",
            "eim_package_error_result",
            "provide_eim_package_result_error",
            "epr_error",
        ):
            resolved_code = resolve_sgp32_eim_package_result_error_code(code_value)
            resolved_name = describe_sgp32_eim_package_result_error(resolved_code)
            self._set_document_value(
                document,
                ["sgp32", "provide_eim_package_result", "result_choice"],
                "eim_package_result_response_error",
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "provide_eim_package_result", "eim_package_result_response_error", "include"],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "provide_eim_package_result", "eim_package_result_response_error", "error_code"],
                resolved_name,
                updated_paths,
            )
        elif normalized_family in (
            "sgp32_profile_download_error_reason",
            "profile_download_error_reason",
            "profile_download_error",
            "pdt_error_reason",
        ):
            resolved_code = resolve_sgp32_profile_download_error_reason_code(code_value)
            resolved_name = describe_sgp32_profile_download_error_reason(resolved_code)
            self._set_document_value(
                document,
                ["sgp32", "provide_eim_package_result", "result_choice"],
                "profile_download_trigger_result",
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "provide_eim_package_result", "profile_download_trigger_result", "include"],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                [
                    "sgp32",
                    "provide_eim_package_result",
                    "profile_download_trigger_result",
                    "profile_download_error",
                    "include",
                ],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                [
                    "sgp32",
                    "provide_eim_package_result",
                    "profile_download_trigger_result",
                    "profile_download_error",
                    "value",
                ],
                resolved_name,
                updated_paths,
            )
        elif normalized_family in (
            "sgp22_profile_state_result",
            "profile_state_result",
            "result_code",
            "profile_result_code",
        ):
            resolved_code = resolve_sgp22_profile_state_result_code(code_value)
            resolved_name = describe_sgp22_profile_state_result(resolved_code)
            self._set_document_value(
                document,
                ["sgp32", "profile_download_trigger_result", "result_code", "include"],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "profile_download_trigger_result", "result_code", "value"],
                resolved_name,
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "eim_package_result", "choice"],
                "profile_download_trigger_result",
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "eim_package_result", "profile_download_trigger_result", "include"],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "eim_package_result", "profile_download_trigger_result", "result_code", "include"],
                True,
                updated_paths,
            )
            self._set_document_value(
                document,
                ["sgp32", "eim_package_result", "profile_download_trigger_result", "result_code", "value"],
                resolved_name,
                updated_paths,
            )
        else:
            raise ValueError(
                "Unsupported family. Use one of: "
                "sgp32_eim_package_result_error, "
                "sgp32_profile_download_error_reason, "
                "sgp22_profile_state_result."
            )

        self._save_package_document(resolved_path, document)
        self._append_response_log_event(
            action="error_code_set",
            package_path=resolved_path,
            package_type=str(document.get("package_type", "")).strip().lower(),
            transaction_id_hex="",
            matching_id="",
            success=True,
            result_len=len(updated_paths),
            response_preview_hex="",
            details={
                "family": normalized_family,
                "resolved_code": int(resolved_code),
                "resolved_name": resolved_name,
                "updated_paths": list(updated_paths),
            },
        )
        return {
            "package_path": resolved_path,
            "family": normalized_family,
            "resolved_code": int(resolved_code),
            "resolved_name": resolved_name,
            "updated_paths": updated_paths,
        }

    def _set_document_value(
        self,
        document: dict[str, Any],
        path_tokens: list[str],
        value: Any,
        updated_paths: list[str],
    ) -> None:
        node: Any = document
        if len(path_tokens) == 0:
            return
        for token in path_tokens[:-1]:
            if isinstance(node, dict) is False:
                return
            existing = node.get(token)
            if isinstance(existing, dict) is False:
                existing = {}
                node[token] = existing
            node = existing
        if isinstance(node, dict) is False:
            return
        leaf = path_tokens[-1]
        node[leaf] = value
        updated_paths.append(".".join(path_tokens))

    def _save_package_document(self, path: str, document: dict[str, Any]) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=True)
            handle.write("\n")

    def _response_preview_hex(self, payload: bytes, max_chars: int = 160) -> str:
        if isinstance(payload, (bytes, bytearray)) is False:
            return ""
        if len(payload) == 0:
            return ""
        text = bytes(payload).hex().upper()
        if len(text) <= max_chars:
            return text
        return f"{text[:max_chars]}..."

    def _current_eid_hint(self, explicit_eid: str = "") -> str:
        eid_value = str(explicit_eid or "").strip()
        if len(eid_value) > 0:
            return eid_value
        current_eid = str(getattr(self, "current_eid", "") or "").strip()
        if len(current_eid) > 0:
            return current_eid
        if self.apdu_channel is None:
            return ""
        if bool(getattr(self.state, "isdr_selected", False)) is False:
            return ""
        try:
            return self.get_eid()
        except Exception:
            return ""

    @staticmethod
    def _normalize_flow_value(flow: str) -> str:
        normalized = str(flow or "").strip().lower()
        normalized = normalized.replace("-", "_")
        normalized = normalized.replace(" ", "_")
        while "__" in normalized:
            normalized = normalized.replace("__", "_")
        return normalized.strip("_")

    def _default_flow_for_event(
        self,
        *,
        action: str,
        package_type: str,
        details: Optional[dict[str, Any]] = None,
    ) -> str:
        normalized_action = str(action or "").strip().lower()
        normalized_package_type = str(package_type or "").strip().lower()
        details_payload = details if isinstance(details, dict) else {}
        transport = str(details_payload.get("transport", "") or "").strip().lower()
        execution_path = str(details_payload.get("execution_path", "") or "").strip().lower()
        if normalized_action in ("poll_cycle", "hotfolder_fetch"):
            return "hotfolder_poll"
        if normalized_action.startswith("localized_"):
            return "localized_poll"
        if transport in ("local_auth", "direct_card", "isdr_store_data"):
            return "direct_auth"
        if normalized_action in (
            "get_eim_configuration_data",
            "delete_eim",
            "euicc_memory_reset",
            "addinitialeim",
            "addeim",
        ):
            return "direct_auth"
        if normalized_package_type in (
            "add_initial_eim",
            "add_eim",
            "euicc_memory_reset",
        ):
            return "direct_auth"
        if normalized_package_type in ("ipad_discover", "ipad", "get_eim_package"):
            return "ipad_direct"
        if normalized_package_type in (
            "ipae_authenticate",
            "ipae_auth",
            "ipae_handover",
            "ipae_download",
        ):
            return "ipae_direct"
        if execution_path == "indirect_profile_download":
            return "profile_download_trigger"
        if execution_path == "direct_profile_download":
            return "direct_profile_download"
        if execution_path == "pending_operation_register":
            return "model_only"
        return "runtime"

    def record_poll_audit_event(
        self,
        *,
        action: str,
        package_path: str = "",
        package_type: str = "",
        transaction_id_hex: str = "",
        matching_id: str = "",
        success: bool,
        result_len: int = 0,
        response_preview_hex: str = "",
        details: Optional[dict[str, Any]] = None,
        error: Optional[Exception] = None,
        flow: str = "",
        flow_run_id: str = "",
        eid: str = "",
    ) -> None:
        self._append_response_log_event(
            action=action,
            package_path=package_path,
            package_type=package_type,
            transaction_id_hex=transaction_id_hex,
            matching_id=matching_id,
            success=success,
            result_len=result_len,
            response_preview_hex=response_preview_hex,
            details=details,
            error=error,
            flow=flow,
            flow_run_id=flow_run_id,
            eid=eid,
        )

    def _append_response_log_event(
        self,
        *,
        action: str,
        package_path: str = "",
        package_type: str = "",
        transaction_id_hex: str = "",
        matching_id: str = "",
        success: bool,
        result_len: int = 0,
        response_preview_hex: str = "",
        details: Optional[dict[str, Any]] = None,
        error: Optional[Exception] = None,
        flow: str = "",
        flow_run_id: str = "",
        eid: str = "",
    ) -> None:
        details_payload = details if isinstance(details, dict) else {}
        normalized_flow = self._normalize_flow_value(flow)
        if len(normalized_flow) == 0:
            normalized_flow = self._default_flow_for_event(
                action=action,
                package_type=package_type,
                details=details_payload,
            )
        logged_at_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        event: dict[str, Any] = {
            "logged_at_utc": logged_at_utc,
            "action": str(action).strip(),
            "package_path": str(package_path).strip(),
            "package_type": str(package_type).strip().lower(),
            "transaction_id_hex": str(transaction_id_hex).strip().upper(),
            "matching_id": str(matching_id).strip(),
            "success": bool(success),
            "result_len": int(result_len),
            "response_preview_hex": str(response_preview_hex).strip().upper(),
            "session_transaction_id_hex": bytes(self.state.transaction_id).hex().upper(),
            "flow": normalized_flow,
            "flow_run_id": str(flow_run_id).strip(),
            "eid": self._current_eid_hint(eid),
        }
        if len(str(details_payload.get("transport", "") or "").strip()) > 0:
            event["transport"] = str(details_payload.get("transport", "")).strip()
        if len(str(details_payload.get("execution_path", "") or "").strip()) > 0:
            event["execution_path"] = str(details_payload.get("execution_path", "")).strip()
        if len(str(details_payload.get("eim_result_code", "") or "").strip()) > 0:
            event["eim_result_code"] = str(details_payload.get("eim_result_code", "")).strip()
        if len(str(details_payload.get("eim_result_name", "") or "").strip()) > 0:
            event["eim_result_name"] = str(details_payload.get("eim_result_name", "")).strip()
        if len(details_payload) > 0:
            event["details"] = dict(details_payload)
        if error is not None:
            event["error_type"] = type(error).__name__
            event["error_message"] = str(error)
        try:
            self.response_logger.append_event(event)
        except Exception:
            pass
        try:
            self.poll_audit_store.append_event(event)
        except Exception:
            pass

    def get_counter_value(self, eim_id: str = "") -> tuple[str, int]:
        target_id = str(eim_id).strip()
        if len(target_id) == 0:
            target_id = self._effective_eim_id()
        next_value = self.runtime_state.get_next_counter(target_id, default_value=1)
        return target_id, next_value

    def set_counter_value(self, eim_id: str, next_value: int) -> tuple[str, int]:
        target_id = str(eim_id).strip()
        if len(target_id) == 0:
            target_id = self._effective_eim_id()
        stored = self.runtime_state.set_next_counter(target_id, int(next_value))
        self.runtime_state.record_operation(
            "counter_override",
            transaction_id_hex="",
            matching_id=target_id,
        )
        return target_id, stored

    def acknowledge_eim_operations(
        self,
        transaction_id_hex: str = "",
        matching_id: str = "",
        strict_io: bool = False,
    ) -> int:
        txid = transaction_id_hex.strip().upper()
        mid = matching_id.strip()
        try:
            self._sync_pending_notifications()
            self.enforce_notification_hygiene()
        except Exception:
            if strict_io:
                raise
        closed = self._close_pending_operations(txid, mid)
        self.runtime_state.record_operation("eim_acknowledge", txid, mid)
        self._append_response_log_event(
            action="eim_acknowledge",
            package_path="",
            package_type="eim_acknowledgements",
            transaction_id_hex=txid,
            matching_id=mid,
            success=True,
            result_len=closed,
            response_preview_hex="",
            details={
                "closed_operations": closed,
                "strict_io": bool(strict_io),
            },
        )
        return closed

    def execution_coverage_matrix(self) -> dict[str, dict[str, str]]:
        return {
            "add_initial_eim": {"mode": "executable", "execution_path": "add_initial_eim"},
            "addinitialeim": {"mode": "executable", "execution_path": "add_initial_eim"},
            "add_eim": {"mode": "executable", "execution_path": "add_eim"},
            "addeim": {"mode": "executable", "execution_path": "add_eim"},
            "euicc_memory_reset": {"mode": "executable", "execution_path": "euicc_memory_reset"},
            "ipad_discover": {"mode": "executable", "execution_path": "ipad_discover"},
            "ipad": {"mode": "executable", "execution_path": "ipad_discover"},
            "get_eim_package": {"mode": "executable", "execution_path": "get_eim_package_discover"},
            "ipae_authenticate": {"mode": "executable", "execution_path": "ipae_authenticate"},
            "ipae_auth": {"mode": "executable", "execution_path": "ipae_authenticate"},
            "ipae_handover": {"mode": "executable", "execution_path": "ipae_download"},
            "ipae_download": {"mode": "executable", "execution_path": "ipae_download"},
            "provide_eim_package_result": {"mode": "executable", "execution_path": "provide_eim_package_result_preview"},
            "bound_profile_package": {"mode": "executable", "execution_path": "direct_profile_download"},
            "direct_profile_download": {"mode": "executable", "execution_path": "direct_profile_download"},
            "eim_acknowledgements": {"mode": "executable", "execution_path": "acknowledge_pending"},
            "eim_package_result": {"mode": "executable", "execution_path": "result_acknowledge"},
            "euicc_package_result": {"mode": "executable", "execution_path": "result_acknowledge"},
            "ipa_euicc_data_response": {"mode": "executable", "execution_path": "result_acknowledge"},
            "profile_download_trigger_result": {"mode": "executable", "execution_path": "result_acknowledge"},
            "eim_package_request": {"mode": "model_only", "execution_path": "pending_operation_register"},
            "euicc_package_request_eim_configuration_data": {"mode": "model_only", "execution_path": "pending_operation_register"},
            "euicc_package_request_ecos": {"mode": "model_only", "execution_path": "pending_operation_register"},
            "euicc_package_request_psmos": {"mode": "model_only", "execution_path": "pending_operation_register"},
            "ipa_euicc_data_request": {"mode": "model_only", "execution_path": "pending_operation_register"},
            "profile_download_trigger_request": {"mode": "executable", "execution_path": "indirect_profile_download"},
        }

    def execution_plan_for_package(self, package_path: str = "") -> dict[str, Any]:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        package_document = self.load_eim_package_document(override_path=resolved_path)
        package_type = str(package_document.get("package_type", "")).strip().lower()
        coverage = self.execution_coverage_matrix().get(package_type, {})
        runtime_hints = resolve_package_runtime_hints(package_document)
        mode = str(coverage.get("mode", "unsupported")).strip().lower()
        if mode == "unsupported":
            raise ValueError(f"Unsupported package_type in {resolved_path}: {package_type or '(missing)'}")
        if mode == "model_only" and self._is_model_only_allowed(package_document) is False:
            raise ValueError(
                "Unsupported executable branch for package_type "
                f"'{package_type}'. This type is model_only. "
                "Set runtime.allow_model_only=true in package JSON to run mock registration mode."
            )
        return {
            "package_path": resolved_path,
            "package_type": package_type,
            "mode": mode,
            "execution_path": str(coverage.get("execution_path", "")).strip(),
            "transaction_id_hex": str(runtime_hints.get("transaction_id_hex", "")).strip().upper(),
            "matching_id": str(runtime_hints.get("matching_id", "")).strip(),
        }

    def _wire_preview_transaction_id(
        self,
        runtime_hints: dict[str, Any],
    ) -> tuple[str, bytes]:
        txid_hex = str(runtime_hints.get("transaction_id_hex", "")).strip().replace(" ", "").upper()
        txid = b""
        if len(txid_hex) > 0 and len(txid_hex) % 2 == 0:
            try:
                txid = bytes.fromhex(txid_hex)
            except ValueError:
                txid = b""
        return txid_hex, txid

    def _build_profile_download_trigger_request_preview(
        self,
        package_document: dict[str, Any],
        runtime_hints: dict[str, Any],
        txid: bytes,
    ) -> bytes:
        sgp32 = package_document.get("sgp32", {})
        trigger_request: dict[str, Any] = {}
        if isinstance(sgp32, dict):
            direct = sgp32.get("profile_download_trigger_request", {})
            if isinstance(direct, dict):
                trigger_request = direct
            wrapper = sgp32.get("eim_package_request", {})
            if isinstance(wrapper, dict):
                choice = str(wrapper.get("choice", "")).strip().lower()
                if choice == "profile_download_trigger_request":
                    nested = wrapper.get("profile_download_trigger_request", {})
                    if isinstance(nested, dict):
                        trigger_request = nested

        if len(txid) == 0:
            txid_field = trigger_request.get("transaction_id", {})
            if isinstance(txid_field, dict) and bool(txid_field.get("include", False)):
                txid_hex = str(txid_field.get("value_hex", "")).strip().replace(" ", "").upper()
                if len(txid_hex) > 0 and len(txid_hex) % 2 == 0:
                    try:
                        txid = bytes.fromhex(txid_hex)
                    except ValueError:
                        txid = b""

        matching_id = str(runtime_hints.get("matching_id", "")).strip()
        matching_field = trigger_request.get("matching_id", {})
        if isinstance(matching_field, dict) and bool(matching_field.get("include", False)):
            candidate = str(matching_field.get("value", "")).strip()
            if len(candidate) > 0:
                matching_id = candidate
        if len(matching_id) == 0:
            matching_id = self._default_matching_id()

        smdp_address = self._resolve_runtime_smdp_address(runtime_hints)
        activation_code = f"1${smdp_address}${matching_id}"
        inner = b""
        if len(txid) > 0:
            inner += self._wrap_tlv(b"\x82", txid)
        inner += self._wrap_tlv(b"\x80", activation_code.encode("utf-8"))
        return self._wrap_tlv(bytes.fromhex("BF54"), inner)

    def build_wire_payload_preview(self, package_document: dict[str, Any]) -> bytes:
        package_type = str(package_document.get("package_type", "")).strip().lower()
        runtime_hints = resolve_package_runtime_hints(package_document)
        txid_hex, txid = self._wire_preview_transaction_id(runtime_hints)
        if package_type in ("add_initial_eim", "addinitialeim"):
            command_payload, _ = self._build_add_eim_command_payload(
                package_document=package_document,
                tag_hex=self.cfg.EIM_ADD_INITIAL_TAG_HEX,
            )
            return command_payload
        if package_type in ("add_eim", "addeim"):
            command_payload, _ = self._build_add_eim_command_payload(
                package_document=package_document,
                tag_hex=self.cfg.EIM_ADD_TAG_HEX,
            )
            return command_payload
        if package_type == "euicc_memory_reset":
            return self._build_euicc_memory_reset_payload(package_document)
        if package_type in ("profile_download_trigger_request",):
            return self._build_profile_download_trigger_request_preview(
                package_document,
                runtime_hints,
                txid,
            )
        if package_type in ("bound_profile_package", "direct_profile_download"):
            profile_path = str(runtime_hints.get("profile_path", "")).strip()
            if len(profile_path) == 0:
                return b""
            try:
                source_bytes = self._read_profile_source_bytes(profile_path=profile_path)
            except Exception:
                return b""
            if source_bytes.startswith(bytes.fromhex("BF36")):
                return bytes(source_bytes)
            return b""
        if package_type in ("eim_package_request",):
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                request = sgp32.get("eim_package_request", {})
                if isinstance(request, dict):
                    choice = str(request.get("choice", "")).strip().lower()
                    if choice == "profile_download_trigger_request":
                        return self._build_profile_download_trigger_request_preview(
                            package_document,
                            runtime_hints,
                            txid,
                        )
        if package_type in ("euicc_package_result",):
            payload = b""
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                result = sgp32.get("euicc_package_result", {})
                if isinstance(result, dict):
                    payload_field = result.get("result_payload", {})
                    if isinstance(payload_field, dict) and bool(payload_field.get("include", False)):
                        payload_hex = str(payload_field.get("value_hex", "")).strip().replace(" ", "")
                        if len(payload_hex) > 0 and len(payload_hex) % 2 == 0:
                            try:
                                payload = bytes.fromhex(payload_hex)
                            except ValueError:
                                payload = b""
            return self._build_euicc_package_result_tlv(payload, transaction_id=txid)
        if package_type in ("ipa_euicc_data_response",):
            payload = b""
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                result = sgp32.get("ipa_euicc_data_response", {})
                if isinstance(result, dict):
                    payload_field = result.get("response_payload", {})
                    if isinstance(payload_field, dict) and bool(payload_field.get("include", False)):
                        payload_hex = str(payload_field.get("value_hex", "")).strip().replace(" ", "")
                        if len(payload_hex) > 0 and len(payload_hex) % 2 == 0:
                            try:
                                payload = bytes.fromhex(payload_hex)
                            except ValueError:
                                payload = b""
            return self._build_ipa_euicc_data_response_tlv(payload, transaction_id=txid)
        if package_type in ("profile_download_trigger_result",):
            inner = b""
            if len(txid) > 0:
                inner += self._wrap_tlv(b"\x80", txid)
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                pd = sgp32.get("profile_download_trigger_result", {})
                if isinstance(pd, dict):
                    result_code = pd.get("result_code", {})
                    if isinstance(result_code, dict) and bool(result_code.get("include", False)):
                        resolved = resolve_sgp22_profile_state_result_code(result_code.get("value"), default_code=127)
                        inner += self._wrap_tlv(b"\x81", bytes([resolved & 0xFF]))
            return self._wrap_tlv(bytes.fromhex("BF54"), inner)
        if package_type in ("eim_package_result",):
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                family = sgp32.get("eim_package_result", {})
                if isinstance(family, dict):
                    choice = str(family.get("choice", "")).strip().lower()
                    if choice == "euicc_package_result":
                        synthetic = {
                            "package_type": "euicc_package_result",
                            "runtime": {"transaction_id_hex": txid_hex},
                        }
                        return self.build_wire_payload_preview(synthetic)
                    if choice == "ipa_euicc_data_response":
                        synthetic = {
                            "package_type": "ipa_euicc_data_response",
                            "runtime": {"transaction_id_hex": txid_hex},
                        }
                        return self.build_wire_payload_preview(synthetic)
                    if choice == "profile_download_trigger_result":
                        synthetic = {
                            "package_type": "profile_download_trigger_result",
                            "runtime": {"transaction_id_hex": txid_hex},
                            "sgp32": {
                                "profile_download_trigger_result": family.get("profile_download_trigger_result", {}),
                            },
                        }
                        return self.build_wire_payload_preview(synthetic)
            return self._wrap_tlv(bytes.fromhex("BF50"), b"")
        if package_type in ("provide_eim_package_result",):
            sgp32 = package_document.get("sgp32", {})
            if isinstance(sgp32, dict):
                provide = sgp32.get("provide_eim_package_result", {})
                if isinstance(provide, dict):
                    choice = str(provide.get("result_choice", "")).strip().lower()
                    eid_value = ""
                    eid_field = provide.get("eid_value", {})
                    if isinstance(eid_field, dict) and bool(eid_field.get("include", False)):
                        eid_hex = str(eid_field.get("value_hex", "")).strip().replace(" ", "")
                        if len(eid_hex) > 0 and len(eid_hex) % 2 == 0:
                            try:
                                eid_value = self._decode_bcd_digits(bytes.fromhex(eid_hex))
                            except ValueError:
                                eid_value = ""
                    if choice == "euicc_package_result":
                        inner_txid = txid
                        euicc_section = provide.get("euicc_package_result", {})
                        if isinstance(euicc_section, dict):
                            payload_hex = str(euicc_section.get("value_hex", "")).strip().replace(" ", "")
                            payload = b""
                            if len(payload_hex) > 0 and len(payload_hex) % 2 == 0:
                                try:
                                    payload = bytes.fromhex(payload_hex)
                                except ValueError:
                                    payload = b""
                            branch = self._build_euicc_package_result_tlv(payload, transaction_id=inner_txid)
                            return self._build_provide_eim_package_result_tlv(branch, eid=eid_value)
                    if choice == "ipa_euicc_data_response":
                        inner_txid = txid
                        ipa_section = provide.get("ipa_euicc_data_response", {})
                        if isinstance(ipa_section, dict):
                            payload_hex = str(ipa_section.get("value_hex", "")).strip().replace(" ", "")
                            payload = b""
                            if len(payload_hex) > 0 and len(payload_hex) % 2 == 0:
                                try:
                                    payload = bytes.fromhex(payload_hex)
                                except ValueError:
                                    payload = b""
                            branch = self._build_ipa_euicc_data_response_tlv(payload, transaction_id=inner_txid)
                            return self._build_provide_eim_package_result_tlv(branch, eid=eid_value)
                    if choice == "profile_download_trigger_result":
                        inner_txid = str(
                            provide.get("profile_download_trigger_result", {}).get("transaction_id_hex", txid_hex)
                        ).strip().replace(" ", "")
                        synthetic = {
                            "package_type": "profile_download_trigger_result",
                            "runtime": {"transaction_id_hex": inner_txid},
                            "sgp32": {
                                "profile_download_trigger_result": provide.get("profile_download_trigger_result", {}),
                            },
                        }
                        branch = self.build_wire_payload_preview(synthetic)
                        return self._build_provide_eim_package_result_tlv(branch, eid=eid_value)
                    if choice == "eim_package_result_response_error":
                        error_code = provide.get("eim_package_result_response_error", {}).get("error_code", 127)
                        resolved = resolve_sgp32_eim_package_result_error_code(error_code, default_code=127)
                        return self._build_eim_package_result_response_error_tlv(
                            eid=eid_value,
                            error_code=resolved,
                        )
            return self._wrap_tlv(bytes.fromhex("BF50"), b"")
        return b""

    def _is_model_only_allowed(self, package_document: dict[str, Any]) -> bool:
        runtime = package_document.get("runtime", {})
        if isinstance(runtime, dict) is False:
            return False
        if bool(runtime.get("allow_model_only", False)):
            return True
        if bool(runtime.get("mock_mode", False)):
            return True
        return False

    def load_eim_package_to_isdr(self, package_path: str = "", cert_path: str = "") -> dict[str, Any]:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        package_document = self.load_eim_package_document(override_path=resolved_path)
        package_type = str(package_document.get("package_type", "")).strip().lower()
        response = b""
        result_len = 0
        execution_path = ""
        transport = "direct_card"
        supported_card_facing_types = (
            "add_initial_eim",
            "addinitialeim",
            "add_eim",
            "addeim",
            "euicc_memory_reset",
            "profile_download_trigger_request",
            "bound_profile_package",
            "direct_profile_download",
        )
        if package_type not in supported_card_facing_types:
            raise ValueError(
                "LOAD-EIM-PACKAGE only supports card-facing package types: "
                "add_initial_eim, add_eim, euicc_memory_reset, "
                "profile_download_trigger_request, bound_profile_package, "
                "direct_profile_download."
            )
        if package_type in ("add_initial_eim", "addinitialeim"):
            response = self.add_initial_eim(
                cert_path=cert_path,
                package_path=resolved_path,
                source_mode="package_isdr",
            )
            result_len = len(response)
            execution_path = "add_initial_eim_package_isdr"
            transport = "local_auth"
        elif package_type in ("add_eim", "addeim"):
            response = self.add_eim(
                cert_path=cert_path,
                package_path=resolved_path,
                source_mode="package_isdr",
            )
            result_len = len(response)
            execution_path = "add_eim_package_isdr"
            transport = "local_auth"
        elif package_type == "euicc_memory_reset":
            response = self.euicc_memory_reset(package_path=resolved_path)
            result_len = len(response)
            execution_path = "euicc_memory_reset"
            transport = "isdr_store_data"
        else:
            _, _, result_len = self.issue_eim_package_file(resolved_path)
            response = bytes(getattr(self.state, "eim_package_response", b""))
            execution_path = str(
                self.execution_coverage_matrix().get(package_type, {}).get(
                    "execution_path",
                    "issue_eim_package_file",
                )
            )
            transport = "local_auth"
        return {
            "package_path": resolved_path,
            "package_type": package_type,
            "result_len": int(result_len),
            "response": bytes(response),
            "execution_path": execution_path,
            "transport": transport,
            "response_preview_hex": self._response_preview_hex(response),
            "selected_cert_path": self.eim_state.selected_eim_certificate_path.strip(),
            "selected_cert_reason": self.eim_state.selected_eim_certificate_reason.strip(),
            "selected_cert_root_ci_pkids": list(self.eim_state.selected_eim_certificate_ci_pkids),
        }

    def issue_eim_package_file(self, package_path: str = "") -> tuple[str, str, int]:
        resolved_path = self.resolve_eim_package_path(override_path=package_path)
        package_document = self.load_eim_package_document(override_path=resolved_path)
        runtime_hints = resolve_package_runtime_hints(package_document)
        package_type = str(package_document.get("package_type", "")).strip().lower()
        coverage = self.execution_coverage_matrix().get(package_type, {})
        mode = str(coverage.get("mode", "")).strip().lower()
        if mode == "model_only" and self._is_model_only_allowed(package_document) is False:
            raise ValueError(
                "Unsupported executable branch for package_type "
                f"'{package_type}'. This type is model_only. "
                "Set runtime.allow_model_only=true in package JSON to run mock registration mode."
            )
        txid = str(runtime_hints.get("transaction_id_hex", "")).strip().upper()
        matching_id = str(runtime_hints.get("matching_id", "")).strip()
        response_preview = ""
        details: dict[str, Any] = {}
        result_len = 0
        try:
            if package_type in ("add_initial_eim", "addinitialeim"):
                response = self.add_initial_eim(package_path=resolved_path)
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "add_initial_eim"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in ("add_eim", "addeim"):
                response = self.add_eim(package_path=resolved_path)
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "add_eim"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type == "euicc_memory_reset":
                response = self.euicc_memory_reset(package_path=resolved_path)
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "euicc_memory_reset"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in ("profile_download_trigger_request",):
                if self.apdu_channel is None or self._is_model_only_allowed(package_document):
                    self._register_pending_operation(package_type, runtime_hints)
                    self.runtime_state.record_operation(
                        package_type,
                        transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                        matching_id=str(runtime_hints.get("matching_id", "")),
                    )
                    details["execution_path"] = "pending_operation_register"
                    details["execution_mode"] = "model_only"
                    details["pending_operations"] = len(self.eim_state.pending_operations)
                    self._append_response_log_event(
                        action="issue_package",
                        package_path=resolved_path,
                        package_type=package_type,
                        transaction_id_hex=txid,
                        matching_id=matching_id,
                        success=True,
                        result_len=0,
                        response_preview_hex="",
                        details=details,
                    )
                    return resolved_path, package_type, 0
                response, success, exec_details = self._execute_indirect_profile_download_request(
                    package_document=package_document,
                    runtime_hints=runtime_hints,
                )
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "indirect_profile_download"
                details.update(exec_details)
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=success,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in ("bound_profile_package", "direct_profile_download"):
                if self.apdu_channel is None or self._is_model_only_allowed(package_document):
                    self._register_pending_operation(package_type, runtime_hints)
                    self.runtime_state.record_operation(
                        package_type,
                        transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                        matching_id=str(runtime_hints.get("matching_id", "")),
                    )
                    details["execution_path"] = "pending_operation_register"
                    details["execution_mode"] = "model_only"
                    details["pending_operations"] = len(self.eim_state.pending_operations)
                    self._append_response_log_event(
                        action="issue_package",
                        package_path=resolved_path,
                        package_type=package_type,
                        transaction_id_hex=txid,
                        matching_id=matching_id,
                        success=True,
                        result_len=0,
                        response_preview_hex="",
                        details=details,
                    )
                    return resolved_path, package_type, 0
                response, success, exec_details = self._execute_direct_bound_profile_package_request(
                    runtime_hints=runtime_hints,
                )
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "direct_profile_download"
                details.update(exec_details)
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=success,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in (
                "eim_package_request",
                "euicc_package_request_eim_configuration_data",
                "euicc_package_request_ecos",
                "euicc_package_request_psmos",
                "ipa_euicc_data_request",
            ):
                counter_assignments = self._apply_runtime_counters(package_document)
                self._register_pending_operation(package_type, runtime_hints)
                self._commit_counter_assignments(counter_assignments)
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                details["execution_path"] = "pending_operation_register"
                details["execution_mode"] = "model_only"
                details["pending_operations"] = len(self.eim_state.pending_operations)
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=0,
                    response_preview_hex="",
                    details=details,
                )
                return resolved_path, package_type, 0
            if package_type in ("eim_acknowledgements",):
                closed = self._close_pending_from_hints(runtime_hints)
                self.acknowledge_eim_operations(
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                    strict_io=False,
                )
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                details["execution_path"] = "acknowledge_pending"
                details["closed_operations"] = int(closed)
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=closed,
                    response_preview_hex="",
                    details=details,
                )
                return resolved_path, package_type, closed
            if package_type in ("ipad_discover", "ipad"):
                self.ipad_discover(package_path=resolved_path)
                details["execution_path"] = "ipad_discover"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=0,
                    response_preview_hex="",
                    details=details,
                )
                return resolved_path, package_type, 0
            if package_type in ("get_eim_package",):
                self.ipad_discover(package_path=resolved_path)
                details["execution_path"] = "get_eim_package_discover"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=0,
                    response_preview_hex="",
                    details=details,
                )
                return resolved_path, package_type, 0
            if package_type in ("ipae_authenticate", "ipae_auth"):
                self.ipae_authenticate(matching_id=str(runtime_hints.get("matching_id", "")))
                result_len = len(self.state.transaction_id)
                details["execution_path"] = "ipae_authenticate"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=bytes(self.state.transaction_id).hex().upper() or txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex="",
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in ("ipae_handover", "ipae_download"):
                transaction_id_hex = str(runtime_hints.get("transaction_id_hex", "")).strip()
                if len(transaction_id_hex) > 0:
                    self.set_handover_transaction(
                        transaction_id_hex,
                        matching_id=str(runtime_hints.get("matching_id", "")),
                    )
                response = self.ipae_download(
                    profile_path=str(runtime_hints.get("profile_path", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                result_len = len(response)
                response_preview = self._response_preview_hex(response)
                details["execution_path"] = "ipae_download"
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in ("provide_eim_package_result",):
                wire_payload = self.build_wire_payload_preview(package_document)
                closed = self._close_pending_from_hints(runtime_hints)
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                self.state.eim_package_response = wire_payload
                result_len = len(wire_payload)
                response_preview = self._response_preview_hex(wire_payload)
                details["execution_path"] = "provide_eim_package_result_preview"
                details["wire_payload_len"] = len(wire_payload)
                details["wire_payload_preview_hex"] = self._response_preview_hex(wire_payload)
                details["closed_operations"] = int(closed)
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=result_len,
                    response_preview_hex=response_preview,
                    details=details,
                )
                return resolved_path, package_type, result_len
            if package_type in (
                "eim_package_result",
                "euicc_package_result",
                "ipa_euicc_data_response",
                "profile_download_trigger_result",
            ):
                wire_payload = self.build_wire_payload_preview(package_document)
                closed = self._close_pending_from_hints(runtime_hints)
                self.acknowledge_eim_operations(
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                    strict_io=False,
                )
                self.runtime_state.record_operation(
                    package_type,
                    transaction_id_hex=str(runtime_hints.get("transaction_id_hex", "")),
                    matching_id=str(runtime_hints.get("matching_id", "")),
                )
                details["execution_path"] = "result_acknowledge_wire_preview"
                details["wire_payload_len"] = len(wire_payload)
                details["closed_operations"] = int(closed)
                self._append_response_log_event(
                    action="issue_package",
                    package_path=resolved_path,
                    package_type=package_type,
                    transaction_id_hex=txid,
                    matching_id=matching_id,
                    success=True,
                    result_len=len(wire_payload),
                    response_preview_hex=self._response_preview_hex(wire_payload),
                    details=details,
                )
                return resolved_path, package_type, len(wire_payload)
            raise ValueError(
                f"Unsupported package_type in {resolved_path}: {package_type or '(missing)'}"
            )
        except Exception as error:
            self._append_response_log_event(
                action="issue_package",
                package_path=resolved_path,
                package_type=package_type,
                transaction_id_hex=txid,
                matching_id=matching_id,
                success=False,
                result_len=-1,
                response_preview_hex=response_preview,
                details=details,
                error=error,
            )
            raise

    def issue_all_eim_package_files(self, package_dir: str = "") -> list[tuple[str, str, int]]:
        results: list[tuple[str, str, int]] = []
        for package_file in self.list_eim_package_files(package_dir=package_dir):
            try:
                results.append(self.issue_eim_package_file(package_file))
            except Exception as error:
                results.append((package_file, f"error:{type(error).__name__}", -1))
        return results

    def issue_hotfolder_packages(self, hotfolder_dir: str = "") -> list[tuple[str, str, int]]:
        resolved_dir = self.reset_hotfolder_poll_session(hotfolder_dir=hotfolder_dir)
        poll_meta = self.hotfolder_poll_response_meta(hotfolder_dir=resolved_dir)
        if poll_meta.get("eim_result_code") == self.cfg.EIM_NO_PACKAGE_RESULT_CODE:
            self.runtime_state.record_operation("hotfolder_empty_no_eim_package_available")
            self._append_response_log_event(
                action="hotfolder_fetch",
                package_path="",
                package_type="no_package_available",
                transaction_id_hex="",
                matching_id="",
                success=True,
                result_len=0,
                response_preview_hex=str(poll_meta.get("response_tlv_hex", "")).strip().upper(),
                details={
                    "hotfolder_dir": hotfolder_dir,
                    "eim_result_code": poll_meta.get("eim_result_code"),
                    "eim_result_name": poll_meta.get("eim_result_name"),
                },
            )
            return []
        results: list[tuple[str, str, int]] = []
        for package_file in self.list_hotfolder_package_files(hotfolder_dir=resolved_dir):
            try:
                issued = self.issue_eim_package_file(package_file)
                self._record_hotfolder_poll_issue(package_file, hotfolder_dir=resolved_dir)
                results.append(issued)
            except Exception as error:
                results.append((package_file, f"error:{type(error).__name__}", -1))
        return results

    def summarize_issue_results(self, results: list[tuple[str, str, int]]) -> dict[str, Any]:
        total = len(results)
        success = 0
        failure = 0
        by_type: dict[str, int] = {}
        for _, package_type, result_len in results:
            key = str(package_type or "").strip()
            if len(key) == 0:
                key = "(unknown)"
            by_type[key] = int(by_type.get(key, 0)) + 1
            if int(result_len) < 0 or key.startswith("error:"):
                failure += 1
            else:
                success += 1
        return {
            "total": total,
            "success": success,
            "failure": failure,
            "by_type": by_type,
        }

    def issue_next_hotfolder_package(self, hotfolder_dir: str = "") -> Optional[tuple[str, str, int]]:
        resolved_dir, effective_excludes = self._effective_hotfolder_poll_excludes(hotfolder_dir=hotfolder_dir)
        package_files = self.list_hotfolder_package_files(hotfolder_dir=resolved_dir)
        package_files = self._exclude_campaign_seen_package_files(
            package_files,
            exclude_package_paths=effective_excludes,
        )
        if len(package_files) == 0:
            return None
        next_file = package_files[0]
        issued = self.issue_eim_package_file(next_file)
        self._record_hotfolder_poll_issue(next_file, hotfolder_dir=resolved_dir)
        return issued

    def poll_hotfolder(
        self,
        cycles: int = 10,
        interval_ms: int = 1000,
        hotfolder_dir: str = "",
    ) -> list[dict[str, Any]]:
        report = self.poll_hotfolder_campaign(
            cycles=cycles,
            interval_ms=interval_ms,
            hotfolder_dir=hotfolder_dir,
            until_empty=False,
            max_cycles=None,
        )
        rows = report.get("rows", [])
        if isinstance(rows, list):
            return rows
        return []

    def poll_hotfolder_campaign(
        self,
        cycles: int = 10,
        interval_ms: int = 1000,
        hotfolder_dir: str = "",
        until_empty: bool = False,
        max_cycles: Optional[int] = None,
    ) -> dict[str, Any]:
        requested_cycles = int(cycles)
        if requested_cycles <= 0:
            requested_cycles = 1
        limit_cycles = int(max_cycles) if max_cycles is not None else requested_cycles
        if limit_cycles <= 0:
            limit_cycles = requested_cycles
        if until_empty:
            run_cycles = limit_cycles
        else:
            run_cycles = requested_cycles
        sleep_ms = int(interval_ms)
        if sleep_ms < 0:
            sleep_ms = 0
        rows: list[dict[str, Any]] = []
        resolved_dir = self.reset_hotfolder_poll_session(hotfolder_dir=hotfolder_dir)
        stop_reason = "cycles_completed"
        # Determinate bar — we know the cycle budget up front. When
        # ``until_empty`` is set the bar may finish early (early break
        # below); the sticky footer just shows the real completion
        # state whenever the caller exits the ``with`` block.
        with progress_session(
            "eIM hotfolder poll", total=run_cycles
        ) as bar:
            for index in range(run_cycles):
                cycle_no = index + 1
                meta = self.hotfolder_poll_metadata(hotfolder_dir=resolved_dir)
                package_count = int(meta.get("package_count", 0))
                bar.advance(
                    f"cycle {cycle_no}/{run_cycles} · {package_count} pending"
                )
                row: dict[str, Any] = {
                    "cycle": cycle_no,
                    "package_count": package_count,
                    "polling_complete": bool(meta.get("polling_complete", True)),
                    "eim_result_code": meta.get("eim_result_code"),
                    "eim_result_name": str(meta.get("eim_result_name", "")).strip(),
                    "issued": False,
                    "issued_file": "",
                    "issued_type": "",
                    "issued_result_len": 0,
                    "error": "",
                }
                if package_count > 0:
                    try:
                        issued = self.issue_next_hotfolder_package(hotfolder_dir=resolved_dir)
                        if issued is not None:
                            row["issued"] = True
                            row["issued_file"] = issued[0]
                            row["issued_type"] = issued[1]
                            row["issued_result_len"] = issued[2]
                        else:
                            raise ValueError("Campaign queue reported pending packages but did not expose next_file.")
                    except Exception as error:
                        row["error"] = f"{type(error).__name__}: {error}"
                rows.append(row)
                self._append_response_log_event(
                    action="poll_cycle",
                    package_path=str(row.get("issued_file", "")),
                    package_type=str(row.get("issued_type", "")),
                    transaction_id_hex="",
                    matching_id="",
                    success=len(str(row.get("error", "")).strip()) == 0,
                    result_len=int(row.get("issued_result_len", 0)),
                    response_preview_hex="",
                    details=dict(row),
                )
                if until_empty and package_count <= 0:
                    stop_reason = "queue_empty"
                    break
                if sleep_ms > 0 and cycle_no < run_cycles:
                    time.sleep(float(sleep_ms) / 1000.0)
        summary = {
            "total_cycles": len(rows),
            "issued_cycles": len([row for row in rows if bool(row.get("issued", False))]),
            "no_package_cycles": len([row for row in rows if int(row.get("package_count", 0)) <= 0]),
            "error_cycles": len([row for row in rows if len(str(row.get("error", "")).strip()) > 0]),
            "stop_reason": stop_reason,
        }
        return {
            "requested_cycles": requested_cycles,
            "executed_cycles": len(rows),
            "interval_ms": sleep_ms,
            "until_empty": bool(until_empty),
            "max_cycles": int(limit_cycles),
            "hotfolder_dir": self.resolve_hotfolder_path(override_path=hotfolder_dir.strip()),
            "summary": summary,
            "rows": rows,
        }

    def export_campaign_report(
        self,
        campaign_report: dict[str, Any],
        output_path: str = "",
    ) -> str:
        target = str(output_path).strip()
        if len(target) == 0:
            file_name = (
                "eim_poll_campaign_"
                + datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            base_dir = self._workspace_root if len(self._workspace_root) > 0 else os.getcwd()
            report_dir = os.path.join(base_dir, "reports")
            os.makedirs(report_dir, exist_ok=True)
            target = os.path.join(report_dir, file_name)
        else:
            target = self._normalize_user_path(target, base_dir=self._workspace_root or os.getcwd())
            parent = os.path.dirname(target)
            if len(parent) > 0:
                os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(campaign_report, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
        self._append_response_log_event(
            action="campaign_export",
            package_path="",
            package_type="campaign_report",
            transaction_id_hex="",
            matching_id="",
            success=True,
            result_len=len(campaign_report.get("rows", [])) if isinstance(campaign_report, dict) else 0,
            response_preview_hex="",
            details={"output_path": target},
        )
        return target

    def aggregate_campaign_reports(self, reports_dir: str = "") -> dict[str, Any]:
        target_dir = str(reports_dir).strip()
        if len(target_dir) == 0:
            base_dir = self._workspace_root if len(self._workspace_root) > 0 else os.getcwd()
            target_dir = os.path.join(base_dir, "reports")
        resolved = self._normalize_user_path(target_dir, base_dir=self._workspace_root or os.getcwd())
        if os.path.isdir(resolved) is False:
            raise NotADirectoryError(f"Reports directory does not exist: {resolved}")
        files: list[str] = []
        for name in sorted(os.listdir(resolved)):
            lowered = name.lower()
            if lowered.startswith("eim_poll_campaign_") is False:
                continue
            if lowered.endswith(".json") is False:
                continue
            files.append(os.path.join(resolved, name))
        total_campaigns = 0
        total_cycles = 0
        total_issued = 0
        total_errors = 0
        stop_reason_counts: dict[str, int] = {}
        rows: list[dict[str, Any]] = []
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            if isinstance(payload, dict) is False:
                continue
            summary = payload.get("summary", {})
            if isinstance(summary, dict) is False:
                summary = {}
            total_campaigns += 1
            total_cycles += int(payload.get("executed_cycles", 0))
            total_issued += int(summary.get("issued_cycles", 0))
            total_errors += int(summary.get("error_cycles", 0))
            stop_reason = str(summary.get("stop_reason", "")).strip() or "unknown"
            stop_reason_counts[stop_reason] = int(stop_reason_counts.get(stop_reason, 0)) + 1
            rows.append(
                {
                    "file": path,
                    "executed_cycles": int(payload.get("executed_cycles", 0)),
                    "issued_cycles": int(summary.get("issued_cycles", 0)),
                    "error_cycles": int(summary.get("error_cycles", 0)),
                    "stop_reason": stop_reason,
                }
            )
        return {
            "reports_dir": resolved,
            "campaign_count": total_campaigns,
            "total_cycles": total_cycles,
            "total_issued_cycles": total_issued,
            "total_error_cycles": total_errors,
            "stop_reason_counts": stop_reason_counts,
            "campaign_rows": rows,
        }

    def export_aggregate_campaign_report(self, aggregate_report: dict[str, Any], output_path: str = "") -> str:
        target = str(output_path).strip()
        if len(target) == 0:
            file_name = (
                "eim_poll_campaign_aggregate_"
                + datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y%m%dT%H%M%SZ")
                + ".json"
            )
            base_dir = self._workspace_root if len(self._workspace_root) > 0 else os.getcwd()
            report_dir = os.path.join(base_dir, "reports")
            os.makedirs(report_dir, exist_ok=True)
            target = os.path.join(report_dir, file_name)
        else:
            target = self._normalize_user_path(target, base_dir=self._workspace_root or os.getcwd())
            parent = os.path.dirname(target)
            if len(parent) > 0:
                os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(aggregate_report, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
        return target

    def hotfolder_poll_response_meta(
        self,
        hotfolder_dir: str = "",
        exclude_package_paths: Optional[set[str]] = None,
    ) -> dict[str, Any]:
        resolved_dir, effective_excludes = self._effective_hotfolder_poll_excludes(
            hotfolder_dir=hotfolder_dir,
            exclude_package_paths=exclude_package_paths,
        )
        package_files = self.list_hotfolder_package_files(hotfolder_dir=resolved_dir)
        package_files = self._exclude_campaign_seen_package_files(
            package_files,
            exclude_package_paths=effective_excludes,
        )
        if len(package_files) > 0:
            return {
                "package_count": len(package_files),
                "package_files": list(package_files),
                "polling_complete": False,
                "eim_result_code": None,
                "eim_result_name": "",
                "response_tlv_hex": "",
            }
        response_tlv_hex = "BF4F03020101"
        return {
            "package_count": 0,
            "package_files": [],
            "polling_complete": True,
            "eim_result_code": int(self.cfg.EIM_NO_PACKAGE_RESULT_CODE),
            "eim_result_name": "noEimPackageAvailable",
            "response_tlv_hex": response_tlv_hex,
        }

    def hotfolder_poll_metadata(
        self,
        hotfolder_dir: str = "",
        exclude_package_paths: Optional[set[str]] = None,
    ) -> dict[str, Any]:
        resolved_dir, effective_excludes = self._effective_hotfolder_poll_excludes(
            hotfolder_dir=hotfolder_dir,
            exclude_package_paths=exclude_package_paths,
        )
        queue_preview = self.list_hotfolder_preview(
            hotfolder_dir=resolved_dir,
            exclude_package_paths=effective_excludes,
        )
        response_meta = self.hotfolder_poll_response_meta(
            hotfolder_dir=resolved_dir,
            exclude_package_paths=effective_excludes,
        )
        next_file = ""
        if len(queue_preview) > 0:
            next_file = str(queue_preview[0].get("path", "")).strip()
        return {
            "hotfolder_dir": resolved_dir,
            "polling_complete": bool(response_meta.get("polling_complete", True)),
            "eim_result_code": response_meta.get("eim_result_code"),
            "eim_result_name": str(response_meta.get("eim_result_name", "")).strip(),
            "response_tlv_hex": str(response_meta.get("response_tlv_hex", "")).strip().upper(),
            "package_count": int(response_meta.get("package_count", 0)),
            "next_file": next_file,
            "queue_preview": queue_preview,
        }

    def _resolve_package_endpoint(self, package_document: dict[str, Any]) -> str:
        runtime_hints = resolve_package_runtime_hints(package_document)
        candidate = ""
        hinted_endpoint = str(runtime_hints.get("bip_endpoint", "")).strip()
        if len(hinted_endpoint) > 0:
            candidate = hinted_endpoint
        hinted_endpoints = runtime_hints.get("bip_endpoints", {})
        if len(candidate) == 0 and isinstance(hinted_endpoints, dict):
            active = str(hinted_endpoints.get(self.eim_state.current_bip_role, "")).strip()
            if len(active) > 0:
                candidate = active
        if len(candidate) == 0:
            if self.eim_state.current_bip_role == "smdpp":
                candidate = self._effective_smdpp_endpoint()
            else:
                candidate = self._effective_eim_endpoint()
        if len(candidate) > 0:
            self.eim_state.last_intercepted_target = candidate
            self.eim_state.last_intercept_reason = (
                f"runtime intercept while role={self.eim_state.current_bip_role}"
            )
        return candidate

    def _activate_runtime_bip_role(self, role: str, reason: str = "") -> str:
        normalized = role.strip().lower()
        if normalized not in ("eim", "smdpp"):
            raise ValueError("BIP role must be either 'eim' or 'smdpp'.")
        if normalized == "eim":
            endpoint = self._effective_eim_endpoint()
        else:
            endpoint = self._effective_smdpp_endpoint()
        self.eim_state.current_bip_role = normalized
        self.eim_state.current_bip_endpoint = endpoint
        if len(reason.strip()) > 0:
            self.eim_state.last_intercept_reason = f"role switch by {reason.strip()}"
        return endpoint

    def _apply_runtime_counters(self, package_document: dict[str, Any]) -> list[tuple[str, int]]:
        assignments: list[tuple[str, int]] = []
        for row in self._iter_eim_configuration_rows(package_document):
            include_row = bool(row.get("include", True))
            if include_row is False:
                continue
            eim_id_field = row.get("eim_id", {})
            eim_id = ""
            if isinstance(eim_id_field, dict):
                eim_id = str(eim_id_field.get("value", "")).strip()
            if len(eim_id) == 0:
                eim_id = self._effective_eim_id()
            counter_field = row.get("counter_value", {})
            if isinstance(counter_field, dict) is False:
                continue
            include_counter = bool(counter_field.get("include", True))
            if include_counter is False:
                continue
            raw_counter_value = counter_field.get("value")
            counter_value_unspecified = raw_counter_value is None
            if isinstance(raw_counter_value, str) and len(raw_counter_value.strip()) == 0:
                counter_value_unspecified = True
            if counter_value_unspecified:
                counter_value = self.runtime_state.get_next_counter(eim_id, default_value=1)
                counter_field["value"] = counter_value
            else:
                counter_value = self._coerce_integer(raw_counter_value, "counter_value.value")
                if counter_value < 0:
                    counter_value = self.runtime_state.get_next_counter(eim_id, default_value=1)
                    counter_field["value"] = counter_value
            assignments.append((eim_id, counter_value))
        return assignments

    def _commit_counter_assignments(self, assignments: list[tuple[str, int]]) -> None:
        for eim_id, counter_value in assignments:
            self.runtime_state.mark_counter_used(eim_id, counter_value)

    def _iter_eim_configuration_rows(self, package_document: dict[str, Any]) -> list[dict[str, Any]]:
        sgp32 = package_document.get("sgp32", {})
        if isinstance(sgp32, dict) is False:
            return []
        rows: list[dict[str, Any]] = []
        add_initial = sgp32.get("add_initial_eim_request", {})
        if isinstance(add_initial, dict):
            values = add_initial.get("eim_configuration_data_list", [])
            if isinstance(values, list):
                rows.extend([row for row in values if isinstance(row, dict)])
        add_eim = sgp32.get("add_eim_request", {})
        if isinstance(add_eim, dict):
            values = add_eim.get("eim_configuration_data_list", [])
            if isinstance(values, list):
                rows.extend([row for row in values if isinstance(row, dict)])
        euicc_package_request = sgp32.get("euicc_package_request", {})
        if isinstance(euicc_package_request, dict):
            eim_cfg = euicc_package_request.get("eim_configuration_data", {})
            if isinstance(eim_cfg, dict):
                values = eim_cfg.get("rows", [])
                if isinstance(values, list):
                    rows.extend([row for row in values if isinstance(row, dict)])
        return rows

    def _as_positive_int(self, value: Any) -> int:
        if isinstance(value, int):
            if value > 0:
                return value
            return 0
        if isinstance(value, str):
            text = value.strip()
            if len(text) == 0:
                return 0
            try:
                parsed = int(text, 10)
            except ValueError:
                return 0
            if parsed > 0:
                return parsed
            return 0
        return 0

    def _resolve_hotfolder_order_value(self, package_path: str) -> int:
        try:
            document = load_eim_package_document(package_path)
        except Exception:
            return 2**63 - 1
        runtime = document.get("runtime", {})
        if isinstance(runtime, dict):
            explicit_id = self._as_positive_int(runtime.get("queue_id"))
            if explicit_id > 0:
                return explicit_id
        explicit_id = self._as_positive_int(document.get("queue_id"))
        if explicit_id > 0:
            return explicit_id
        runtime_hints = resolve_package_runtime_hints(document)
        txid_hex = str(runtime_hints.get("transaction_id_hex", "")).strip().replace(" ", "")
        if len(txid_hex) > 0 and len(txid_hex) % 2 == 0:
            try:
                return int(txid_hex, 16)
            except ValueError:
                pass
        name = os.path.basename(package_path)
        prefix = ""
        for char in name:
            if char.isdigit():
                prefix += char
                continue
            break
        if len(prefix) > 0:
            try:
                return int(prefix, 10)
            except ValueError:
                pass
        return 2**63 - 1

    def _poll_session_source(self, package_path: str, hotfolder_dir: str = "") -> str:
        target_path = os.path.abspath(package_path)
        source_dirs: list[tuple[str, str]] = []
        if len(hotfolder_dir.strip()) > 0:
            source_dirs.append(("hotfolder", hotfolder_dir.strip()))
        for label, target_dir in self._poll_fixture_directories():
            source_dirs.append((label, target_dir))
        for label, target_dir in source_dirs:
            candidate_dir = str(target_dir).strip()
            if len(candidate_dir) == 0:
                continue
            resolved_dir = self._normalize_user_path(candidate_dir, base_dir=self.cfg.EIM_PACKAGES_DIR)
            if os.path.isdir(resolved_dir) is False:
                continue
            try:
                if os.path.commonpath([target_path, resolved_dir]) == resolved_dir:
                    return label
            except ValueError:
                continue
        return "package"

    def _build_hotfolder_preview_row(
        self,
        order_index: int,
        package_path: str,
        hotfolder_dir: str = "",
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "order": int(order_index),
            "path": package_path,
            "session_source": self._poll_session_source(package_path, hotfolder_dir=hotfolder_dir),
            "package_type": "",
            "queue_order": 2**63 - 1,
            "queue_source": "fallback",
            "queue_id": None,
            "transaction_id_hex": "",
            "matching_id": "",
            "error": "",
        }
        try:
            document = load_eim_package_document(package_path)
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"
            return row
        runtime_hints = resolve_package_runtime_hints(document)
        row["package_type"] = str(document.get("package_type", "")).strip().lower()
        row["transaction_id_hex"] = str(runtime_hints.get("transaction_id_hex", "")).strip().upper()
        row["matching_id"] = str(runtime_hints.get("matching_id", "")).strip()
        queue_order, queue_source, queue_id = self._resolve_hotfolder_order_with_source(document, package_path)
        row["queue_order"] = queue_order
        row["queue_source"] = queue_source
        row["queue_id"] = queue_id
        return row

    def _resolve_hotfolder_order_with_source(
        self,
        document: dict[str, Any],
        package_path: str,
    ) -> tuple[int, str, Optional[int]]:
        runtime = document.get("runtime", {})
        if isinstance(runtime, dict):
            explicit_id = self._as_positive_int(runtime.get("queue_id"))
            if explicit_id > 0:
                return explicit_id, "runtime.queue_id", explicit_id
        explicit_id = self._as_positive_int(document.get("queue_id"))
        if explicit_id > 0:
            return explicit_id, "queue_id", explicit_id
        runtime_hints = resolve_package_runtime_hints(document)
        txid_hex = str(runtime_hints.get("transaction_id_hex", "")).strip().replace(" ", "")
        if len(txid_hex) > 0 and len(txid_hex) % 2 == 0:
            try:
                return int(txid_hex, 16), "runtime.transaction_id_hex", None
            except ValueError:
                pass
        name = os.path.basename(package_path)
        prefix = ""
        for char in name:
            if char.isdigit():
                prefix += char
                continue
            break
        if len(prefix) > 0:
            try:
                return int(prefix, 10), "filename_prefix", None
            except ValueError:
                pass
        return 2**63 - 1, "fallback", None

    def _effective_eim_id(self) -> str:
        identity_id = str(self.eim_identity.get("eim_id", "")).strip()
        if len(identity_id) > 0:
            return identity_id
        return self.cfg.EIM_ID

    def _effective_eim_fqdn(self) -> str:
        fqdn = str(self.eim_identity.get("eim_fqdn", "")).strip()
        if len(fqdn) > 0:
            return fqdn
        return ""

    def _effective_eim_id_type(self) -> str:
        value = str(self.eim_identity.get("eim_id_type", "")).strip()
        if len(value) > 0:
            return value
        return "oid"

    def _effective_eim_endpoint(self) -> str:
        endpoint = str(self.eim_identity.get("eim_endpoint", "")).strip()
        if len(endpoint) > 0:
            return endpoint
        return str(self.cfg.EIM_BIP_ENDPOINT).strip()

    def _effective_smdpp_endpoint(self) -> str:
        endpoint = str(self.eim_identity.get("smdpp_endpoint", "")).strip()
        if len(endpoint) > 0:
            return endpoint
        return str(self.cfg.SMDPP_BIP_ENDPOINT).strip()

    def _effective_smdp_address(self) -> str:
        smdp_address = str(self.eim_identity.get("smdp_address", "")).strip()
        if len(smdp_address) > 0:
            return smdp_address
        return self._effective_smdpp_endpoint()

    def _effective_eim_public_key_cert_path(self) -> str:
        return str(self.eim_identity.get("eim_public_key_cert_path", "")).strip()

    def _effective_trusted_tls_cert_path(self) -> str:
        return str(self.eim_identity.get("trusted_tls_cert_path", "")).strip()

    def _effective_euicc_ci_pk_id(self) -> str:
        value = str(self.eim_identity.get("euicc_ci_pk_id", "")).strip()
        if len(value) > 0:
            return value
        return bytes(self.cfg.ROOT_CI_ID).hex().upper()

    def _default_matching_id(self) -> str:
        matching = str(self.eim_identity.get("default_matching_id", "")).strip()
        if len(matching) > 0:
            return matching
        return self._effective_eim_id()

    def _register_pending_operation(self, package_type: str, runtime_hints: dict[str, Any]) -> None:
        row = {
            "package_type": package_type.strip().lower(),
            "transaction_id_hex": str(runtime_hints.get("transaction_id_hex", "")).strip().upper(),
            "matching_id": str(runtime_hints.get("matching_id", "")).strip(),
        }
        self.eim_state.pending_operations.append(row)

    def _close_pending_from_hints(self, runtime_hints: dict[str, Any]) -> int:
        txid = str(runtime_hints.get("transaction_id_hex", "")).strip().upper()
        mid = str(runtime_hints.get("matching_id", "")).strip()
        return self._close_pending_operations(txid, mid)

    def _close_pending_operations(self, txid_hex: str = "", matching_id: str = "") -> int:
        txid = txid_hex.strip().upper()
        mid = matching_id.strip()
        rows = self.eim_state.pending_operations
        if len(rows) == 0:
            return 0
        kept: list[dict[str, str]] = []
        closed = 0
        for row in rows:
            row_txid = str(row.get("transaction_id_hex", "")).strip().upper()
            row_mid = str(row.get("matching_id", "")).strip()
            match_txid = True
            if len(txid) > 0:
                match_txid = row_txid == txid
            match_mid = True
            if len(mid) > 0:
                match_mid = row_mid == mid
            if match_txid and match_mid:
                closed += 1
                continue
            kept.append(row)
        if len(txid) == 0 and len(mid) == 0:
            closed = len(rows)
            kept = []
        self.eim_state.pending_operations = kept
        return closed
