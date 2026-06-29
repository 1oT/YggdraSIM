# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 local-access configuration: resolves cert, profile, and metadata paths for the local-access session."""
import os
from dataclasses import dataclass, field

from yggdrasim_common.runtime_paths import (
    ensure_runtime_dir,
    ensure_seeded_workspace_tree,
    ensure_workspace_dir,
    workspace_path,
)


def _module_dir() -> str:
    return workspace_path("LocalSMDPP")


def _certs_dir() -> str:
    return os.path.join(_module_dir(), "certs")


def _profile_dir() -> str:
    return os.path.join(_module_dir(), "profile")


def _debug_dir() -> str:
    return os.path.join(_module_dir(), "debug")


def _metadata_dir() -> str:
    return os.path.join(_profile_dir(), "metadata")


def _sgp26_valid_cert_dir() -> str:
    return workspace_path("SCP11", "SGP.26_test_Certs", "Valid Test Cases")


@dataclass(frozen=True)
class LocalAccessConfig:
    """Configuration for local SCP11 access against ISD-R."""

    CERTS_DIR: str = field(default_factory=_certs_dir)
    PROFILE_DIR: str = field(default_factory=_profile_dir)
    DEBUG_DIR: str = field(default_factory=_debug_dir)
    METADATA_DIR: str = field(default_factory=_metadata_dir)
    SGP26_VALID_CERT_DIR: str = field(default_factory=_sgp26_valid_cert_dir)
    CERT_CURVE_PREFERENCE: str = "NIST"
    CERT_PATH_AUTH: str = field(
        default_factory=lambda: os.path.join(_certs_dir(), "CERT.DPauth.ECDSA.der")
    )
    KEY_PATH_AUTH: str = field(
        default_factory=lambda: os.path.join(_certs_dir(), "SK.DPauth.ECDSA.pem")
    )
    CERT_PATH_PB: str = field(
        default_factory=lambda: os.path.join(_certs_dir(), "CERT.DPpb.ECDSA.der")
    )
    KEY_PATH_PB: str = field(
        default_factory=lambda: os.path.join(_certs_dir(), "SK.DPpb.ECDSA.pem")
    )

    READER_INDEX: int = 0
    SERVER_ADDRESS: str = "local.isdr"
    # If True, use the eUICC default SM-DP+ address from GetEuiccConfiguredData (tag 0x80)
    # as serverAddress in AuthenticateServer so the card accepts the session (avoids
    # downloadErrorCode=5 on some eUICCs that require serverAddress to match).
    USE_EUICC_DEFAULT_DP_ADDRESS: bool = True
    AID_ISD_R: bytes = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
    ROOT_CI_ID: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    TAC: bytes = bytes.fromhex("01020304")
    CHUNK_SIZE: int = 250

    # If True, use the transaction ID from the BPP file so PrepareDownload and
    # LoadBoundProfilePackage share the same ID (required; else downloadErrorCode=5
    # invalidTransactionId). If False, use a fresh ID — card returns invalidTransactionId(5).
    USE_BPP_TRANSACTION_ID: bool = True

    # If True and the profile file has no transaction ID (segment-only), bind during session:
    # open session using the card challenge as transaction ID, then wrap the segment in a
    # minimal BPP (BF36/BF23) with that same ID so the card accepts it. If False, require
    # a full BPP and raise a clear error when the file has no transaction ID.
    WRAP_SEGMENT_IN_BOOTSTRAP: bool = True
    # If True and the profile input has no BF23 transaction ID, build a session-bound BPP
    # locally after PrepareDownload using pySim's RspSessionState/BoundProfilePackage flow.
    # This keeps local_access self-contained and avoids using any remote SM-DP+ session state.
    GENERATE_SESSION_BOUND_BPP: bool = True
    # Host ID used inside the locally generated InitialiseSecureChannelRequest (BF23).
    BPP_HOST_ID: bytes = b"mahlzeit"
    # Local default BSP data block counter seed for generated BPP diagnostics.
    # Override this to 1 when strict spec-start reproduction is required.
    BPP_INITIAL_BLOCK_NR: int = 1000
    # Experimental local-only knob: prebuild a pySim ProtectedProfilePackage with static
    # Profile Protection Keys and let pySim emit A2.ReplaceSessionKeys before A3. This keeps
    # ASN.1 construction inside pySim while exercising the PPK-based branch explicitly.
    BPP_USE_PPK_REPLACE_SESSION_KEYS: bool = True
    # Experimental static PPK values for the local-only ReplaceSessionKeys trial path.
    BPP_PPK_ENC: bytes = bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    BPP_PPK_MAC: bytes = bytes.fromhex("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
    # Experimental local-only compatibility knob for A3.ProtectedProfilePackageCommand
    # chunking. 0 keeps pySim's default BoundProfilePackage encoding, including any
    # A2.ReplaceSessionKeys handling that pySim emits. Any positive value switches back to
    # the local manual A3 chunk builder and overrides the plaintext bytes per protected A3
    # member, capped to pySim's maximum payload size.
    BPP_A3_PLAINTEXT_CHUNK_SIZE: int = 0

    CAPABILITIES: dict = field(
        default_factory=lambda: {
            "gsmSupportedRelease": b"\x99\x00\x00",
            "utranSupportedRelease": b"\x99\x00\x00",
            "eutranEpcSupportedRelease": b"\x99\x00\x00",
        }
    )

    def credential_paths(self):
        """Return a dict of resolved local-access credential file paths."""
        return [
            ("DPauth certificate", self.CERT_PATH_AUTH),
            ("DPauth private key", self.KEY_PATH_AUTH),
            ("DPpb certificate", self.CERT_PATH_PB),
            ("DPpb private key", self.KEY_PATH_PB),
        ]

    def __post_init__(self) -> None:
        ensure_runtime_dir("SCP11", "local_access")
        ensure_workspace_dir("LocalSMDPP", "debug")
        ensure_seeded_workspace_tree(
            ("SCP11", "SGP.26_test_Certs", "Valid Test Cases"),
            "SCP11",
            "SGP.26_test_Certs",
            "Valid Test Cases",
        )
        ensure_seeded_workspace_tree(("SCP11", "local_access", "certs"), "LocalSMDPP", "certs")
        ensure_seeded_workspace_tree(("SCP11", "local_access", "profile"), "LocalSMDPP", "profile")
