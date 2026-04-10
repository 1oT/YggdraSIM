import os
from dataclasses import dataclass, field

from yggdrasim_common.runtime_paths import (
    ensure_runtime_dir,
    ensure_seeded_workspace_file,
    ensure_seeded_workspace_tree,
    ensure_workspace_dir,
    workspace_path,
)

try:
    from SCP11.local_access.config import LocalAccessConfig
except ImportError:
    from ..local_access.config import LocalAccessConfig


def _module_dir() -> str:
    return workspace_path("LocalEIM")


def _certs_dir() -> str:
    return os.path.join(_module_dir(), "certs")


def _profile_dir() -> str:
    return os.path.join(_module_dir(), "profile")


def _metadata_dir() -> str:
    return os.path.join(_profile_dir(), "metadata")


def _debug_dir() -> str:
    return os.path.join(_module_dir(), "debug")


def _eim_packages_dir() -> str:
    return os.path.join(_module_dir(), "eim_packages")


def _eim_certs_dir() -> str:
    return os.path.join(_certs_dir(), "eim")


def _eim_package_templates_dir() -> str:
    return os.path.join(_eim_packages_dir(), "templates")


def _eim_hotfolder_dir() -> str:
    return os.path.join(_eim_packages_dir(), "hotfolder")


def _eim_poll_fixtures_dir() -> str:
    return os.path.join(_eim_packages_dir(), "fixtures")


def _eim_poll_eim_to_esim_dir() -> str:
    return os.path.join(_eim_poll_fixtures_dir(), "eim_to_esim")


def _eim_poll_esim_to_eim_dir() -> str:
    return os.path.join(_eim_poll_fixtures_dir(), "esim_to_eim")


def _eim_runtime_state_file() -> str:
    return os.path.join(_module_dir(), "eim_runtime_state.json")


def _eim_identity_file() -> str:
    return os.path.join(_module_dir(), "eim_identity.json")


def _eim_response_log_file() -> str:
    return os.path.join(_module_dir(), "eim_response_log.jsonl")


def _eim_poll_audit_db_file() -> str:
    return os.path.join(_module_dir(), "eim_poll_audit.sqlite3")


@dataclass(frozen=True)
class EimLocalConfig(LocalAccessConfig):
    """Configuration for isolated eIM-enabled local SCP11 experimentation."""

    CERTS_DIR: str = field(default_factory=_certs_dir)
    PROFILE_DIR: str = field(default_factory=_profile_dir)
    METADATA_DIR: str = field(default_factory=_metadata_dir)
    DEBUG_DIR: str = field(default_factory=_debug_dir)

    EIM_PACKAGES_DIR: str = field(default_factory=_eim_packages_dir)
    EIM_PACKAGE_TEMPLATES_DIR: str = field(default_factory=_eim_package_templates_dir)
    EIM_HOTFOLDER_DIR: str = field(default_factory=_eim_hotfolder_dir)
    EIM_POLL_FIXTURES_DIR: str = field(default_factory=_eim_poll_fixtures_dir)
    EIM_POLL_EIM_TO_ESIM_DIR: str = field(default_factory=_eim_poll_eim_to_esim_dir)
    EIM_POLL_ESIM_TO_EIM_DIR: str = field(default_factory=_eim_poll_esim_to_eim_dir)
    EIM_CERTS_DIR: str = field(default_factory=_eim_certs_dir)
    EIM_RUNTIME_STATE_FILE: str = field(default_factory=_eim_runtime_state_file)
    EIM_RESPONSE_LOG_FILE: str = field(default_factory=_eim_response_log_file)
    EIM_POLL_AUDIT_DB_FILE: str = field(default_factory=_eim_poll_audit_db_file)
    EIM_IDENTITY_FILE: str = field(default_factory=_eim_identity_file)
    EIM_DEFAULT_PACKAGE_FILE: str = "default_eim_package.json"
    EIM_ADD_INITIAL_TAG_HEX: str = "BF57"
    EIM_ADD_TAG_HEX: str = "BF58"
    EIM_ID: str = "2.25.311782205282738360923618091971140414400"
    EIM_NOTIFICATION_MAX_PENDING: int = 0
    EIM_NO_PACKAGE_RESULT_CODE: int = 1
    EIM_POLL_INCLUDE_FIXED_FIXTURES: bool = True

    EIM_BIP_ENDPOINT: str = "https://yggdrasim.eim.test.1ot.com/gsma/rsp2/asn1"
    SMDPP_BIP_ENDPOINT: str = "https://yggdrasim.smdpp.test.1ot.com/gsma/rsp2/es9plus"
    POLL_BRIDGE_BIND_HOST: str = "127.0.0.1"
    POLL_BRIDGE_DNS_PORT: int = 15353
    POLL_BRIDGE_EIM_TLS_PORT: int = 18443
    POLL_BRIDGE_SMDP_TLS_PORT: int = 19443

    def __post_init__(self) -> None:
        super().__post_init__()
        ensure_runtime_dir("SCP11", "eim_local")
        ensure_workspace_dir("LocalEIM", "debug")
        ensure_seeded_workspace_tree(("SCP11", "eim_local", "certs"), "LocalEIM", "certs")
        ensure_seeded_workspace_tree(("SCP11", "eim_local", "profile"), "LocalEIM", "profile")
        ensure_seeded_workspace_tree(("SCP11", "eim_local", "eim_packages"), "LocalEIM", "eim_packages")
        ensure_seeded_workspace_file(("SCP11", "eim_local", "eim_identity.json"), "LocalEIM", "eim_identity.json")
