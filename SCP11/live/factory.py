# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-live session factory: constructs the PCSC channel, provider, and crypto-engine for a live-reader session."""
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

try:
    from .es9_client import Es9LikeClient
    from .models import (
        BACKEND_MODE_LOCAL_SGP26,
        BACKEND_MODE_REMOTE_DP,
        TRANSPORT_MODE_PCSC,
    )
    from .providers import RemoteEs9Provider, Sgp26LocalProvider
    from .transport import PcscApduChannel
except ImportError:
    from es9_client import Es9LikeClient
    from models import (
        BACKEND_MODE_LOCAL_SGP26,
        BACKEND_MODE_REMOTE_DP,
        TRANSPORT_MODE_PCSC,
    )
    from providers import RemoteEs9Provider, Sgp26LocalProvider
    from transport import PcscApduChannel


def build_apdu_channel(cfg):
    """Construct and return the direct PC/SC APDU channel for this session variant."""
    if cfg.TRANSPORT_MODE == TRANSPORT_MODE_PCSC:
        try:
            return PcscApduChannel(reader_index=cfg.READER_INDEX)
        except Exception as error:
            raise RuntimeError(
                f"PC/SC transport startup failed on reader index {cfg.READER_INDEX}: {error}"
            ) from error

    raise ValueError(
        f"Unsupported transport mode: {cfg.TRANSPORT_MODE}. Supported value: {TRANSPORT_MODE_PCSC}."
    )


def build_profile_provider(cfg):
    """Construct and return the profile provider (remote ES9+, local SGP.26, or simulated) for this session variant."""
    if cfg.BACKEND_MODE == BACKEND_MODE_REMOTE_DP:
        if len(str(cfg.ES9_BASE_URL).strip()) == 0:
            raise ValueError("Remote DP mode requires ES9_BASE_URL to be configured.")
        es9_client = Es9LikeClient(
            base_url=cfg.ES9_BASE_URL,
            timeout_seconds=cfg.ES9_TIMEOUT_SECONDS,
            verify_tls=cfg.ES9_VERIFY_TLS,
            ca_bundle_path=cfg.ES9_CA_BUNDLE_PATH,
            eim_base_url=cfg.EIM_BASE_URL,
            eim_timeout_seconds=cfg.EIM_TIMEOUT_SECONDS,
            eim_transport_mode=cfg.EIM_TRANSPORT_MODE,
            eim_http_path=cfg.EIM_HTTP_PATH,
            eim_http_protocol=cfg.EIM_HTTP_PROTOCOL,
        )
        return RemoteEs9Provider(es9_client=es9_client)

    if cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
        return Sgp26LocalProvider(
            trust_anchor_path=cfg.LOCAL_SGP26_TRUST_ANCHOR_PATH,
            intermediate_paths=cfg.LOCAL_SGP26_INTERMEDIATE_PATHS,
            issuer_cert_path=cfg.LOCAL_SGP26_ISSUER_CERT_PATH,
        )

    raise ValueError(
        f"Unsupported backend mode: {cfg.BACKEND_MODE}. Supported values: {BACKEND_MODE_REMOTE_DP}, {BACKEND_MODE_LOCAL_SGP26}."
    )
