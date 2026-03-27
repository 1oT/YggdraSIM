from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .runtime_paths import runtime_path


class InventoryCryptoManager:
    """Config-driven envelope encryption for inventory payloads."""

    ENVELOPE_MARKER = "__ygg_inventory_encrypted__"
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
        except Exception:
            payload = {}
        merged = json.loads(json.dumps(self.DEFAULT_CONFIG))
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, dict) and isinstance(merged.get(key), dict):
                    merged[key].update(value)
                    continue
                merged[key] = value
        self.config = merged

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

    def _normalized_provider(self) -> str:
        provider = str(self.config.get("provider", "gpg")).strip().lower()
        if len(provider) == 0:
            return "gpg"
        return provider

    def provider_ready_for_encrypt(self) -> bool:
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
            return candidate.resolve()
        return (self.config_path.parent / candidate).resolve()

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
        completed = subprocess.run(
            command,
            input=plaintext,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            stderr_text = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"GPG inventory encryption failed: {stderr_text}")
        return completed.stdout.decode("utf-8", errors="strict")

    def _gpg_decrypt(self, ciphertext_ascii: str) -> bytes:
        binary = self._gpg_binary()
        if shutil.which(binary) is None:
            raise FileNotFoundError(f"GPG binary not found in PATH: {binary}")
        command = [binary, "--batch", "--yes", "--quiet", "--decrypt"]
        completed = subprocess.run(
            command,
            input=str(ciphertext_ascii).encode("utf-8"),
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            stderr_text = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"GPG inventory decryption failed: {stderr_text}")
        return bytes(completed.stdout)
