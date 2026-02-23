# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os
import sys
import shutil
from dataclasses import dataclass, field

def _get_config_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def _get_bundled_dir():
    return os.path.dirname(os.path.abspath(__file__))

@dataclass(frozen=True)
class SGPConfig:
    """Configuration constants for SGP.26 emulation."""
    
    # Paths
    CERT_PATH_AUTH: str = field(default_factory=lambda: os.path.join(_get_config_dir(), "CERT.DPauth.ECDSA.der"))
    KEY_PATH_AUTH: str = field(default_factory=lambda: os.path.join(_get_config_dir(), "SK.DPauth.ECDSA.pem"))
    CERT_PATH_PB: str = field(default_factory=lambda: os.path.join(_get_config_dir(), "CERT.DPpb.ECDSA.der"))
    KEY_PATH_PB: str = field(default_factory=lambda: os.path.join(_get_config_dir(), "SK.DPpb.ECDSA.pem"))

    # Profile Protection Keys (Static fallback)
    STATIC_PPK_ENC: bytes = bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    STATIC_PPK_MAC: bytes = bytes.fromhex("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")

    # Identifiers
    AID_ISD_R: bytes = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
    ROOT_CI_ID: bytes = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
    RSP_SERVER_URL: str = "rsp.example.com"

    # Device Info
    TAC: bytes = bytes.fromhex("01020304")
    CAPABILITIES: dict = field(default=None)

    def __post_init__(self):
        # Initialize mutable defaults if necessary
        if self.CAPABILITIES is None:
            object.__setattr__(self, 'CAPABILITIES', {
                'gsmSupportedRelease': b'\x99\x00\x00',
                'utranSupportedRelease': b'\x99\x00\x00',
                'eutranEpcSupportedRelease': b'\x99\x00\x00'
            })
            
        # Copy bundled certs/keys to config dir if missing in frozen environment
        if getattr(sys, 'frozen', False):
            bundled_dir = _get_bundled_dir()
            for filename in ["CERT.DPauth.ECDSA.der", "SK.DPauth.ECDSA.pem", "CERT.DPpb.ECDSA.der", "SK.DPpb.ECDSA.pem"]:
                user_path = os.path.join(_get_config_dir(), filename)
                bundled_path = os.path.join(bundled_dir, filename)
                if not os.path.exists(user_path) and os.path.exists(bundled_path):
                    try:
                        shutil.copy2(bundled_path, user_path)
                    except Exception as e:
                        print(f"Warning: Could not copy default {filename} to {_get_config_dir()}: {e}")