"""
Session-key bundle contract for the EUM diagnostics dissector.

An EUM / SM-DP+ operator investigating a failed download typically has
access to the session keys that the server database associates with
the failing ICCID:

* ``ShS-ENC`` -- the AES-128 shared secret used to encrypt the Bound
  Profile Package (SGP.22 §2.5.6).
* ``ShS-MAC`` -- the AES-128 shared secret used for the S-ENC/MAC
  integrity layer over the BPP segments.
* ``DEK``      -- the optional Data Encryption Key that protects PPR
  elements inside the BPP (present for some profile types).

This module defines a strongly-typed container, validates the inputs
(length / hex discipline / constant-time comparisons), and serialises
the bundle to a side-car JSON file that the Lua dissector reads via
the ``YGGDRASIM_EUM_SESSION_KEYS`` environment variable.

The container deliberately does NOT perform any decryption -- that is
the Lua dissector's job (or pySim, for the offline decode CLI). We
keep the Python side pure so it is safe to import on hosts that lack
tshark / libgcrypt / libnettle.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_LOGGER = logging.getLogger(__name__)


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

KEY_LENGTH_BYTES_ENC: int = 16
KEY_LENGTH_BYTES_MAC: int = 16
KEY_LENGTH_BYTES_DEK: int = 16

SESSION_KEYS_ENV_VAR: str = "YGGDRASIM_EUM_SESSION_KEYS"
BUNDLE_FILE_FORMAT: str = "yggdrasim-eum-session-keys/v1"


class SessionKeyError(ValueError):
    """Raised whenever the session-key inputs fail validation."""


def _normalise_hex(raw: str, *, field: str, expected_bytes: int) -> str:
    cleaned = str(raw or "").strip().replace(" ", "").replace(":", "")
    if len(cleaned) == 0:
        raise SessionKeyError(f"{field} is empty")
    if _HEX_RE.match(cleaned) is None:
        raise SessionKeyError(f"{field} is not valid hex: {raw!r}")
    if len(cleaned) != expected_bytes * 2:
        raise SessionKeyError(
            f"{field} must be {expected_bytes} bytes ({expected_bytes * 2} hex chars); "
            f"got {len(cleaned)} hex chars"
        )
    return cleaned.upper()


def _normalise_optional_hex(
    raw: str | None,
    *,
    field: str,
    expected_bytes: int,
) -> str:
    if raw is None:
        return ""
    cleaned = str(raw).strip()
    if len(cleaned) == 0:
        return ""
    return _normalise_hex(cleaned, field=field, expected_bytes=expected_bytes)


@dataclass(frozen=True)
class SessionKeyBundle:
    """Validated container for a single ES8+ session-key tuple.

    Use :meth:`from_hex` to build an instance from operator-supplied
    hex strings. The constructor parameters are the raw uppercase hex
    values so downstream code (Lua, JSON) can consume them directly.
    """

    iccid: str
    shs_enc_hex: str
    shs_mac_hex: str
    dek_hex: str = ""
    comment: str = ""

    @staticmethod
    def from_hex(
        *,
        iccid: str,
        shs_enc: str,
        shs_mac: str,
        dek: str | None = None,
        comment: str = "",
    ) -> "SessionKeyBundle":
        iccid_clean = str(iccid or "").strip().upper()
        if len(iccid_clean) == 0:
            raise SessionKeyError("iccid is empty")
        enc = _normalise_hex(shs_enc, field="shs_enc", expected_bytes=KEY_LENGTH_BYTES_ENC)
        mac = _normalise_hex(shs_mac, field="shs_mac", expected_bytes=KEY_LENGTH_BYTES_MAC)
        dek_hex = _normalise_optional_hex(dek, field="dek", expected_bytes=KEY_LENGTH_BYTES_DEK)
        return SessionKeyBundle(
            iccid=iccid_clean,
            shs_enc_hex=enc,
            shs_mac_hex=mac,
            dek_hex=dek_hex,
            comment=str(comment or ""),
        )

    def to_json_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "iccid": self.iccid,
            "shs_enc_hex": self.shs_enc_hex,
            "shs_mac_hex": self.shs_mac_hex,
        }
        if len(self.dek_hex) > 0:
            payload["dek_hex"] = self.dek_hex
        if len(self.comment) > 0:
            payload["comment"] = self.comment
        return payload

    def matches_secret(self, *, shs_enc_hex: str, shs_mac_hex: str) -> bool:
        """Constant-time equality check against another bundle's keys."""
        enc_ok = hmac.compare_digest(
            self.shs_enc_hex.upper().encode("ascii"),
            str(shs_enc_hex or "").upper().encode("ascii"),
        )
        mac_ok = hmac.compare_digest(
            self.shs_mac_hex.upper().encode("ascii"),
            str(shs_mac_hex or "").upper().encode("ascii"),
        )
        return enc_ok is True and mac_ok is True


@dataclass(frozen=True)
class SessionKeyRepository:
    """Collection of :class:`SessionKeyBundle` entries keyed by ICCID.

    The Lua dissector performs a per-BPP ICCID lookup to select the
    right keys. Serialising the repository is therefore an
    ICCID-indexed JSON object rather than a bare list -- constant-time
    lookup at dissection time matters on large PCAPs.
    """

    bundles: tuple[SessionKeyBundle, ...]

    @staticmethod
    def from_bundles(bundles: list[SessionKeyBundle]) -> "SessionKeyRepository":
        seen: dict[str, SessionKeyBundle] = {}
        for bundle in bundles:
            if bundle.iccid in seen:
                raise SessionKeyError(
                    f"duplicate iccid {bundle.iccid} in session-key repository"
                )
            seen[bundle.iccid] = bundle
        return SessionKeyRepository(tuple(bundles))

    def lookup(self, iccid: str) -> SessionKeyBundle | None:
        iccid_clean = str(iccid or "").strip().upper()
        for bundle in self.bundles:
            if bundle.iccid == iccid_clean:
                return bundle
        return None

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "format": BUNDLE_FILE_FORMAT,
            "entries": {
                bundle.iccid: bundle.to_json_dict() for bundle in self.bundles
            },
        }

    @staticmethod
    def from_json_dict(payload: dict[str, Any]) -> "SessionKeyRepository":
        if isinstance(payload, dict) is False:
            raise SessionKeyError("session-key repository JSON must be an object")
        fmt = str(payload.get("format") or "")
        if fmt != BUNDLE_FILE_FORMAT:
            raise SessionKeyError(
                f"unsupported session-key repository format: {fmt!r}; "
                f"expected {BUNDLE_FILE_FORMAT}"
            )
        entries = payload.get("entries", {})
        if isinstance(entries, dict) is False:
            raise SessionKeyError("session-key repository 'entries' must be an object")
        bundles: list[SessionKeyBundle] = []
        for raw_iccid, raw_bundle in entries.items():
            if isinstance(raw_bundle, dict) is False:
                raise SessionKeyError(
                    f"session-key bundle for {raw_iccid!r} must be an object"
                )
            bundles.append(
                SessionKeyBundle.from_hex(
                    iccid=str(raw_bundle.get("iccid") or raw_iccid),
                    shs_enc=str(raw_bundle.get("shs_enc_hex") or ""),
                    shs_mac=str(raw_bundle.get("shs_mac_hex") or ""),
                    dek=str(raw_bundle.get("dek_hex") or "") or None,
                    comment=str(raw_bundle.get("comment") or ""),
                )
            )
        return SessionKeyRepository.from_bundles(bundles)


def write_repository_atomic(
    repository: SessionKeyRepository,
    target_path: Path,
) -> Path:
    """Write the repository to ``target_path`` with 0o600 permissions.

    The write is atomic: the payload lands in a temp file next to the
    target, gets chmod 0o600 on POSIX, and is then ``os.replace`` d
    over the destination. This avoids a window where an attacker
    could race a read before the final chmod.
    """
    target_path = Path(target_path).expanduser().resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        repository.to_json_dict(),
        indent=2,
        sort_keys=True,
    ) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=".yggdrasim-eum-keys-",
        suffix=".json.tmp",
        dir=str(target_path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        if hasattr(os, "chmod"):
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, target_path)
    except Exception:
        if tmp_path.is_file() is True:
            tmp_path.unlink(missing_ok=True)
        raise
    return target_path


def _warn_if_world_readable(path: Path) -> None:
    """Surface a warning when the on-disk keys file is not operator-private.

    Session-key JSON holds plaintext AES-128 secrets. A world- or
    group-readable file on a shared host (CI runner, jump box,
    lab-share mount) is the kind of operational blunder we want to
    flag loudly. The check is best-effort: Windows reports ``0``
    permission bits through ``os.stat`` and we simply skip in that
    case.
    """
    if sys.platform.startswith("win") is True:
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    exposed_bits = mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)
    if exposed_bits == 0:
        return
    _LOGGER.warning(
        "EUM session-keys file %s has group/other-visible permissions "
        "(mode=%04o). AES-128 session secrets should be 0600.",
        path,
        stat.S_IMODE(mode),
    )


def load_repository(path: Path) -> SessionKeyRepository:
    path = Path(path).expanduser().resolve()
    _warn_if_world_readable(path)
    payload = json.loads(path.read_text("utf-8"))
    return SessionKeyRepository.from_json_dict(payload)
