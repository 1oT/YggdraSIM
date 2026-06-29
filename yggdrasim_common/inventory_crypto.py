# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Inventory crypto manager: age-based encryption/decryption for secret files stored in the device inventory."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .runtime_paths import runtime_path


_LOGGER = logging.getLogger(__name__)


class InventoryCryptoManager:
    """Config-driven envelope encryption for inventory payloads."""

    ENVELOPE_MARKER = "__ygg_inventory_encrypted__"
    FILE_ENCRYPTED_MARKER = b"-----BEGIN PGP MESSAGE-----"
    DEFAULT_CONFIG_PATH = Path(runtime_path("state", "inventory_crypto.json"))
    DEFAULT_CONFIG: dict[str, Any] = {
        "enabled": False,
        "provider": "gpg",
        "plaintext_fallback_writes": False,
        "gpg": {
            "binary": "gpg",
            "gpg_key_file": "",
            "recipients": [],
        },
    }

    def __init__(self, config_path: str | None = None):
        if config_path is None:
            self.config_path = self.DEFAULT_CONFIG_PATH
        else:
            self.config_path = Path(os.path.abspath(os.path.expanduser(str(config_path).strip())))
        self.config: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        if self.config_path.exists() is False:
            self.config_path.write_text(
                json.dumps(self.DEFAULT_CONFIG, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        payload = {}
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as decode_error:
            self._quarantine_corrupt_config(decode_error)
            payload = {}
        except OSError as io_error:
            _LOGGER.warning(
                "inventory_crypto: unable to read %s (%s); using defaults.",
                str(self.config_path),
                io_error,
            )
            payload = {}
        merged = json.loads(json.dumps(self.DEFAULT_CONFIG))
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, dict) and isinstance(merged.get(key), dict):
                    merged[key].update(value)
                    continue
                merged[key] = value
        self.config = merged

    def _quarantine_corrupt_config(self, decode_error: json.JSONDecodeError) -> None:
        """Rename corrupt inventory_crypto.json to a .corrupt.<ts> sidecar.

        Prior behaviour silently discarded the file and wrote defaults over
        the top, which could mask operator misconfiguration (unbalanced
        braces from a manual edit, disk truncation, etc). The sidecar
        lets operators recover the source material while keeping the
        process able to boot with defaults.
        """
        sidecar_path = self.config_path.with_suffix(
            self.config_path.suffix + f".corrupt.{int(time.time())}"
        )
        try:
            shutil.move(str(self.config_path), str(sidecar_path))
        except OSError as move_error:
            _LOGGER.error(
                "inventory_crypto: %s is corrupt (%s) and could not be "
                "renamed aside (%s); defaults will be written on top.",
                str(self.config_path),
                decode_error,
                move_error,
            )
            return
        _LOGGER.warning(
            "inventory_crypto: %s was unparseable (%s); moved to %s. "
            "Review or restore the file before relying on encrypted state.",
            str(self.config_path),
            decode_error,
            str(sidecar_path),
        )

    def write_encryption_enabled(self) -> bool:
        return bool(self.config.get("enabled", False))

    def plaintext_fallback_writes_allowed(self) -> bool:
        return bool(self.config.get("plaintext_fallback_writes", False))

    def blocks_plaintext_secret_writes(self) -> bool:
        if self.write_encryption_enabled() is False:
            return False
        if self.plaintext_fallback_writes_allowed():
            return False
        return self.provider_ready_for_encrypt()

    def is_encrypted_payload(self, payload: Any) -> bool:
        if isinstance(payload, dict) is False:
            return False
        return bool(payload.get(self.ENVELOPE_MARKER, False))

    def encrypt_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Encrypt *plaintext* bytes using the active KDF and cipher and return the ciphertext."""
        if self.write_encryption_enabled() is False:
            return dict(payload)
        provider = self._normalized_provider()
        plaintext = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8")
        if provider != "gpg":
            raise ValueError(f"Unsupported inventory crypto provider: {provider}")
        ciphertext_ascii = self._gpg_encrypt(plaintext)
        return {
            self.ENVELOPE_MARKER: True,
            "provider": "gpg",
            "ciphertext_ascii": ciphertext_ascii,
        }

    def decrypt_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Decrypt *ciphertext* bytes using the active KDF and cipher and return the plaintext."""
        if self.is_encrypted_payload(payload) is False:
            return dict(payload)
        provider = str(payload.get("provider", "")).strip().lower()
        if provider != "gpg":
            raise ValueError(f"Unsupported inventory crypto provider: {provider}")
        ciphertext_ascii = str(payload.get("ciphertext_ascii", ""))
        plaintext = self._gpg_decrypt(ciphertext_ascii)
        decoded = json.loads(plaintext.decode("utf-8"))
        if isinstance(decoded, dict) is False:
            raise ValueError("Decrypted inventory payload must be a JSON object.")
        return decoded

    @classmethod
    def is_encrypted_file_bytes(cls, payload: bytes | bytearray | memoryview | str) -> bool:
        if isinstance(payload, str):
            raw_bytes = payload.encode("utf-8", errors="ignore")
        else:
            raw_bytes = bytes(payload)
        return raw_bytes.lstrip().startswith(cls.FILE_ENCRYPTED_MARKER)

    def encrypt_bytes(self, plaintext: bytes | bytearray | memoryview) -> bytes:
        return self._gpg_encrypt(bytes(plaintext)).encode("utf-8")

    def decrypt_bytes(self, ciphertext: bytes | bytearray | memoryview | str) -> bytes:
        if isinstance(ciphertext, str):
            ciphertext_ascii = ciphertext
        else:
            ciphertext_ascii = bytes(ciphertext).decode("utf-8", errors="strict")
        return self._gpg_decrypt(ciphertext_ascii)

    def _normalized_provider(self) -> str:
        provider = str(self.config.get("provider", "gpg")).strip().lower()
        if len(provider) == 0:
            return "gpg"
        return provider

    def provider_ready_for_encrypt(self) -> bool:
        """Return True if the active encryption provider has all required key material."""
        provider = self._normalized_provider()
        if provider != "gpg":
            return False
        binary = self._gpg_binary()
        if shutil.which(binary) is None:
            return False
        return len(self._gpg_recipients()) > 0

    def _gpg_binary(self) -> str:
        section = self.config.get("gpg", {})
        if isinstance(section, dict):
            binary = str(section.get("binary", "gpg")).strip()
            if len(binary) > 0:
                return binary
        return "gpg"

    def _gpg_timeout_seconds(self) -> float:
        section = self.config.get("gpg", {})
        if isinstance(section, dict):
            raw_value = section.get("timeout_seconds")
            if raw_value is not None:
                try:
                    coerced = float(raw_value)
                except (TypeError, ValueError):
                    coerced = 0.0
                if coerced > 0:
                    return coerced
        return 120.0

    @staticmethod
    def _normalize_gpg_recipient_text(value: object) -> str:
        text = str(value or "").strip()
        if len(text) == 0:
            return ""
        compact = "".join(text.split())
        if len(compact) > 0 and all(ch in "0123456789abcdefABCDEF" for ch in compact):
            return compact.upper()
        return text

    def _gpg_key_file_path(self) -> Path | None:
        section = self.config.get("gpg", {})
        if isinstance(section, dict) is False:
            return None
        raw_value = str(section.get("gpg_key_file", "")).strip()
        if len(raw_value) == 0:
            return None
        candidate = Path(os.path.expanduser(raw_value))
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.config_path.parent / candidate).resolve()
        if self._path_is_inside_config_dir(resolved) is False:
            _LOGGER.warning(
                "inventory_crypto: refusing gpg_key_file %s; it resolves "
                "outside the inventory config directory %s.",
                str(resolved),
                str(self.config_path.parent),
            )
            return None
        return resolved

    def _path_is_inside_config_dir(self, candidate_path: Path) -> bool:
        """Return ``True`` when *candidate_path* resolves inside the config dir.

        The inventory crypto config lives next to other secret material, so
        the ``gpg_key_file`` field must not be used to pull recipient
        fingerprints from arbitrary filesystem locations (e.g. a
        ``../../etc/passwd`` relative escape, or an absolute path pointing
        at an attacker-controlled file). v1 treats ``config_path.parent``
        as the trust boundary and refuses anything outside it.
        """
        try:
            config_dir = self.config_path.parent.resolve()
        except OSError:
            return False
        try:
            candidate_path.resolve().relative_to(config_dir)
        except (OSError, ValueError):
            return False
        return True

    def _gpg_recipients_from_key_file(self) -> list[str]:
        key_file_path = self._gpg_key_file_path()
        if key_file_path is None:
            return []
        if key_file_path.exists() is False:
            return []
        normalized: list[str] = []
        for raw_line in key_file_path.read_text(encoding="utf-8").splitlines():
            line_text = str(raw_line).split("#", 1)[0].strip()
            recipient = self._normalize_gpg_recipient_text(line_text)
            if len(recipient) > 0:
                normalized.append(recipient)
        return normalized

    def _gpg_recipients(self) -> list[str]:
        section = self.config.get("gpg", {})
        recipients: list[object] = []
        if isinstance(section, dict):
            loaded_recipients = section.get("recipients", [])
            if isinstance(loaded_recipients, list):
                recipients = list(loaded_recipients)
        normalized: list[str] = []
        seen: set[str] = set()
        for recipient in recipients:
            text = self._normalize_gpg_recipient_text(recipient)
            if len(text) > 0 and text not in seen:
                normalized.append(text)
                seen.add(text)
        for recipient in self._gpg_recipients_from_key_file():
            if recipient not in seen:
                normalized.append(recipient)
                seen.add(recipient)
        return normalized

    def _gpg_encrypt(self, plaintext: bytes) -> str:
        binary = self._gpg_binary()
        recipients = self._gpg_recipients()
        if shutil.which(binary) is None:
            raise FileNotFoundError(f"GPG binary not found in PATH: {binary}")
        if len(recipients) == 0:
            raise ValueError("Inventory crypto is enabled, but no GPG recipients are configured.")
        command = [binary, "--batch", "--yes", "--quiet", "--armor", "--encrypt"]
        for recipient in recipients:
            command.extend(["--recipient", recipient])
        try:
            completed = subprocess.run(
                command,
                input=plaintext,
                capture_output=True,
                check=False,
                timeout=self._gpg_timeout_seconds(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "GPG inventory encryption timed out; check gpg-agent / pinentry availability."
            ) from exc
        if completed.returncode != 0:
            stderr_text = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"GPG inventory encryption failed: {stderr_text}")
        return completed.stdout.decode("utf-8", errors="strict")

    def _gpg_decrypt(self, ciphertext_ascii: str) -> bytes:
        binary = self._gpg_binary()
        if shutil.which(binary) is None:
            raise FileNotFoundError(f"GPG binary not found in PATH: {binary}")
        command = [binary, "--batch", "--yes", "--quiet", "--decrypt"]
        try:
            completed = subprocess.run(
                command,
                input=str(ciphertext_ascii).encode("utf-8"),
                capture_output=True,
                check=False,
                timeout=self._gpg_timeout_seconds(),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "GPG inventory decryption timed out; check gpg-agent / pinentry availability."
            ) from exc
        if completed.returncode != 0:
            stderr_text = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"GPG inventory decryption failed: {stderr_text}")
        return bytes(completed.stdout)


def _coerce_crypto_manager(crypto_manager: InventoryCryptoManager | None) -> InventoryCryptoManager:
    if crypto_manager is not None:
        return crypto_manager
    return InventoryCryptoManager()


def read_secret_file_bytes(
    path: str | Path,
    *,
    crypto_manager: InventoryCryptoManager | None = None,
    protect_plaintext_on_read: bool = False,
) -> bytes:
    """Read and return the raw bytes of a secret file, applying any configured decryption."""
    file_path = Path(path)
    raw_bytes = file_path.read_bytes()
    manager = _coerce_crypto_manager(crypto_manager)
    if manager.is_encrypted_file_bytes(raw_bytes):
        return manager.decrypt_bytes(raw_bytes)
    if protect_plaintext_on_read and manager.write_encryption_enabled():
        write_secret_file_bytes(file_path, raw_bytes, crypto_manager=manager)
    return raw_bytes


def write_secret_file_bytes(
    path: str | Path,
    payload: bytes | bytearray | memoryview,
    *,
    crypto_manager: InventoryCryptoManager | None = None,
) -> None:
    """Write *data* to *path* setting restrictive permissions (0o600) afterwards."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    manager = _coerce_crypto_manager(crypto_manager)
    raw_bytes = bytes(payload)
    output_bytes = raw_bytes
    if manager.write_encryption_enabled():
        output_bytes = manager.encrypt_bytes(raw_bytes)
    # Atomic replace so a crash mid-write cannot leave the secret truncated or
    # half-encrypted. The tmp sibling is pre-chmoded to 0600 on POSIX so that
    # for the plaintext-fallback case (inventory_crypto disabled, or
    # ``plaintext_fallback_writes`` enabled) the dropped file stays
    # owner-readable only; on Windows ``os.chmod`` is a no-op for 0600 which is
    # fine since the atomic replace preserves the target's existing ACL.
    tmp_path = file_path.with_suffix(file_path.suffix + f".tmp.{os.getpid()}.{int(time.time() * 1_000_000)}")
    try:
        tmp_path.write_bytes(output_bytes)
        if os.name == "posix":
            try:
                os.chmod(tmp_path, 0o600)
            except OSError as chmod_error:
                _LOGGER.warning(
                    "inventory_crypto: unable to chmod 0600 on %s (%s: %s); "
                    "atomic replace proceeds with inherited umask.",
                    str(tmp_path),
                    chmod_error.__class__.__name__,
                    chmod_error,
                )
        os.replace(tmp_path, file_path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def read_secret_json_file(
    path: str | Path,
    *,
    crypto_manager: InventoryCryptoManager | None = None,
    protect_plaintext_on_read: bool = False,
) -> Any:
    """Read and JSON-decode the contents of a secret (0o600-protected) JSON file."""
    file_path = Path(path)
    if file_path.is_file() is False:
        return None
    try:
        raw_bytes = read_secret_file_bytes(
            file_path,
            crypto_manager=crypto_manager,
            protect_plaintext_on_read=protect_plaintext_on_read,
        )
    except (RuntimeError, OSError) as decrypt_error:
        _LOGGER.warning(
            "inventory_crypto: failed to read/decrypt %s (%s: %s); treating as empty.",
            str(file_path),
            decrypt_error.__class__.__name__,
            decrypt_error,
        )
        return None
    try:
        return json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as parse_error:
        _LOGGER.warning(
            "inventory_crypto: %s did not parse as UTF-8 JSON (%s: %s); treating as empty.",
            str(file_path),
            parse_error.__class__.__name__,
            parse_error,
        )
        return None


def write_secret_json_file(
    path: str | Path,
    payload: Any,
    *,
    crypto_manager: InventoryCryptoManager | None = None,
) -> None:
    """JSON-encode *obj* and write it to *path* with restrictive permissions."""
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    write_secret_file_bytes(path, encoded, crypto_manager=crypto_manager)
