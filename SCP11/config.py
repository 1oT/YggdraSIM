# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import shutil
import sys
from dataclasses import dataclass, field

try:
    from .models import BACKEND_MODE_REMOTE_DP, TRANSPORT_MODE_PCSC
except ImportError:
    from models import BACKEND_MODE_REMOTE_DP, TRANSPORT_MODE_PCSC


def _get_config_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _get_bundled_dir():
    return os.path.dirname(os.path.abspath(__file__))


@dataclass(frozen=True)
class SGPConfig:
    """Configuration constants for SCP11 relay flow and SGP.26 local mode."""

    CERT_PATH_AUTH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "CERT.DPauth.ECDSA.der")
    )
    KEY_PATH_AUTH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SK.DPauth.ECDSA.pem")
    )
    CERT_PATH_PB: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "CERT.DPpb.ECDSA.der")
    )
    KEY_PATH_PB: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SK.DPpb.ECDSA.pem")
    )

    STATIC_PPK_ENC: bytes = bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    STATIC_PPK_MAC: bytes = bytes.fromhex("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

    AID_ISD_R: bytes = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
    ROOT_CI_ID: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    RSP_SERVER_URL: str = "rsp.example.com"

    TAC: bytes = bytes.fromhex("01020304")
    CAPABILITIES: dict = field(default=None)

    READER_INDEX: int = 0
    TRANSPORT_MODE: str = TRANSPORT_MODE_PCSC
    RELAY_URL: str = "http://127.0.0.1:8080/apdu"
    RELAY_TIMEOUT_SECONDS: int = 30
    RELAY_VERIFY_TLS: bool = True
    RELAY_SESSION_ID: str = ""

    BACKEND_MODE: str = BACKEND_MODE_REMOTE_DP
    ES9_BASE_URL: str = "https://rsp.example.com"
    ES9_TIMEOUT_SECONDS: int = 30
    ES9_VERIFY_TLS: bool = True
    ES9_CA_BUNDLE_PATH: str = ""
    REMOTE_DP_ALLOW_LOCAL_FALLBACK: bool = False

    LOCAL_SGP26_TRUST_ANCHOR_PATH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SGP26_TRUST_ANCHOR.pem")
    )
    LOCAL_SGP26_INTERMEDIATE_PATHS: list = field(default_factory=list)
    LOCAL_SGP26_ISSUER_CERT_PATH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SGP26_ISSUER.pem")
    )

    def __post_init__(self):
        if self.CAPABILITIES is None:
            object.__setattr__(
                self,
                "CAPABILITIES",
                {
                    "gsmSupportedRelease": b"\x99\x00\x00",
                    "utranSupportedRelease": b"\x99\x00\x00",
                    "eutranEpcSupportedRelease": b"\x99\x00\x00",
                },
            )

        if getattr(sys, "frozen", False):
            bundled_dir = _get_bundled_dir()
            for filename in [
                "CERT.DPauth.ECDSA.der",
                "SK.DPauth.ECDSA.pem",
                "CERT.DPpb.ECDSA.der",
                "SK.DPpb.ECDSA.pem",
            ]:
                user_path = os.path.join(_get_config_dir(), filename)
                bundled_path = os.path.join(bundled_dir, filename)
                user_missing = os.path.exists(user_path) is False
                bundled_exists = os.path.exists(bundled_path)
                if user_missing and bundled_exists:
                    try:
                        shutil.copy2(bundled_path, user_path)
                    except Exception as error:
                        print(f"Warning: Could not copy default {filename} to {_get_config_dir()}: {error}")