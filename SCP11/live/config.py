# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-live configuration: loads SM-DP+ URL and certificate paths for the live physical-reader session."""
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
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

import os
from dataclasses import dataclass, field

from yggdrasim_common.runtime_paths import (
    ensure_runtime_dir,
    ensure_seeded_workspace_file,
    ensure_workspace_dir,
    workspace_path,
)

try:
    from .models import (
        BACKEND_MODE_LOCAL_SGP26,
        BACKEND_MODE_REMOTE_DP,
        EIM_TRANSPORT_MODE_ESIPA,
        TRANSPORT_MODE_PCSC,
        TRANSPORT_MODE_RELAY,
    )
except ImportError:
    from models import (
        BACKEND_MODE_LOCAL_SGP26,
        BACKEND_MODE_REMOTE_DP,
        EIM_TRANSPORT_MODE_ESIPA,
        TRANSPORT_MODE_PCSC,
        TRANSPORT_MODE_RELAY,
    )


def _get_config_dir():
    return workspace_path("SCP11", "live")


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
    ES9_TIMEOUT_SECONDS: int = 15
    ES9_VERIFY_TLS: bool = True
    ES9_CA_BUNDLE_PATH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "ES9_TEST_CI_CA.pem")
    )
    EIM_BASE_URL: str = ""
    EIM_TIMEOUT_SECONDS: int = 30
    EIM_TRANSPORT_MODE: str = EIM_TRANSPORT_MODE_ESIPA
    EIM_HTTP_PATH: str = "/gsma/rsp2/asn1"
    EIM_HTTP_PROTOCOL: str = "gsma/rsp/v2.1.0"
    EIM_EUICC_CHALLENGE_ASN1: bool = True
    REMOTE_DP_ALLOW_LOCAL_FALLBACK: bool = False
    # FQDN suffix allow-list that gates vendor-specific eIM quirks. The
    # shipped tree carries the mechanism only; operators populate the
    # targets via EIM_VENDOR_QUIRK_FQDN_SUFFIXES so production endpoint
    # names stay out of the public source. Comma- or space-separated.
    EIM_VENDOR_QUIRK_FQDN_SUFFIXES: tuple = ()
    # Prefer ES10b STORE DATA on a dedicated logical channel, matching the
    # channel layout used by commercial LPAs on physical cards.
    ES10B_USE_LOGICAL_CHANNEL: bool = True
    # Preserve top-level BPP section framing during ES10b install for physical
    # cards that reject flattened member-only A0/A1/A2/A3 payloads.
    BPP_INSTALL_USE_SECTION_FRAMING: bool = True

    LOCAL_SGP26_TRUST_ANCHOR_PATH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SGP26_TRUST_ANCHOR.pem")
    )
    LOCAL_SGP26_INTERMEDIATE_PATHS: list = field(default_factory=list)
    LOCAL_SGP26_ISSUER_CERT_PATH: str = field(
        default_factory=lambda: os.path.join(_get_config_dir(), "SGP26_ISSUER.pem")
    )

    def __post_init__(self):
        ensure_workspace_dir("SCP11", "live")
        ensure_runtime_dir("SCP11", "live", "dynamic_ca")
        ev_eim_timeout = os.environ.get("EIM_TIMEOUT_SECONDS", "").strip()
        if ev_eim_timeout != "":
            try:
                parsed_timeout = int(ev_eim_timeout, 10)
            except ValueError:
                parsed_timeout = 0
            if parsed_timeout > 0:
                object.__setattr__(self, "EIM_TIMEOUT_SECONDS", parsed_timeout)
        ev_quirk = os.environ.get("EIM_VENDOR_QUIRK_FQDN_SUFFIXES", "").strip()
        if ev_quirk != "":
            normalized_suffixes = tuple(
                suffix.lower().lstrip(".")
                for suffix in ev_quirk.replace(",", " ").split()
                if len(suffix.strip()) > 0
            )
            object.__setattr__(self, "EIM_VENDOR_QUIRK_FQDN_SUFFIXES", normalized_suffixes)
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

        for filename in [
            "CERT.DPauth.ECDSA.der",
            "SK.DPauth.ECDSA.pem",
            "CERT.DPpb.ECDSA.der",
            "SK.DPpb.ECDSA.pem",
            "ES9_TEST_CI_CA.pem",
            "SGP26_TRUST_ANCHOR.pem",
            "SGP26_ISSUER.pem",
        ]:
            try:
                ensure_seeded_workspace_file(("SCP11", "live", filename), "SCP11", "live", filename)
            except Exception as error:
                print(f"Warning: Could not copy default {filename} to {_get_config_dir()}: {error}")

    def local_credential_paths(self):
        """Return a dict of resolved certificate and key file paths for this session variant."""
        return [
            ("DPauth certificate", self.CERT_PATH_AUTH),
            ("DPauth private key", self.KEY_PATH_AUTH),
            ("DPpb certificate", self.CERT_PATH_PB),
            ("DPpb private key", self.KEY_PATH_PB),
        ]

    def collect_startup_diagnostics(self):
        """Check that all required credential files exist and return a list of diagnostic warning strings."""
        errors = []
        warnings = []

        supported_transports = [TRANSPORT_MODE_PCSC, TRANSPORT_MODE_RELAY]
        if self.TRANSPORT_MODE not in supported_transports:
            errors.append(
                f"Unsupported TRANSPORT_MODE '{self.TRANSPORT_MODE}'. Supported values: {', '.join(supported_transports)}."
            )

        supported_backends = [BACKEND_MODE_REMOTE_DP, BACKEND_MODE_LOCAL_SGP26]
        if self.BACKEND_MODE not in supported_backends:
            errors.append(
                f"Unsupported BACKEND_MODE '{self.BACKEND_MODE}'. Supported values: {', '.join(supported_backends)}."
            )

        supported_eim_transports = [EIM_TRANSPORT_MODE_ESIPA]
        if self.EIM_TRANSPORT_MODE not in supported_eim_transports:
            errors.append(
                f"Unsupported EIM_TRANSPORT_MODE '{self.EIM_TRANSPORT_MODE}'. "
                f"Supported values: {', '.join(supported_eim_transports)}."
            )

        if self.READER_INDEX < 0:
            errors.append("READER_INDEX must be zero or greater.")

        relay_url = str(self.RELAY_URL).strip()
        if self.TRANSPORT_MODE == TRANSPORT_MODE_RELAY:
            if len(relay_url) == 0:
                errors.append("RELAY_URL is empty while TRANSPORT_MODE is set to relay.")
            elif relay_url.startswith(("http://", "https://")) is False:
                errors.append("RELAY_URL must start with http:// or https://.")

        es9_url = str(self.ES9_BASE_URL).strip()
        smdp_address = str(self.RSP_SERVER_URL).strip()
        if self.BACKEND_MODE == BACKEND_MODE_REMOTE_DP:
            if len(es9_url) == 0:
                errors.append("ES9_BASE_URL is empty while BACKEND_MODE is remote_dp.")
            elif "example.com" in es9_url.lower():
                warnings.append("ES9_BASE_URL still points to an example endpoint.")

            if len(smdp_address) == 0:
                warnings.append("RSP_SERVER_URL is empty. FLOW will need an SM-DP+ address before use.")
            elif "example.com" in smdp_address.lower():
                warnings.append("RSP_SERVER_URL still points to an example endpoint.")

        require_local_credentials = self.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26 or self.REMOTE_DP_ALLOW_LOCAL_FALLBACK
        missing_local = []
        for label, path in self.local_credential_paths():
            if os.path.exists(path) is False:
                missing_local.append(f"{label}: {path}")

        if require_local_credentials and missing_local:
            if self.BACKEND_MODE == BACKEND_MODE_REMOTE_DP:
                warnings.append("Local fallback is enabled but local SCP11 credential files are missing.")
                warnings.extend(missing_local)
            else:
                errors.append("Local SGP.26 mode requires SCP11 credential files that are missing.")
                errors.extend(missing_local)

        return errors, warnings