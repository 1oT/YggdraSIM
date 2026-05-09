# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
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
# Copyright (c) 2026 1oT OE. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Offline replay of SCP03 / SCP11c secure messaging for the HIL decode TUI.

The HIL decode TUI can display saved pcaps (see `run_live_decode_tui` with
`live_capture=False`). For ciphered SCP03 / SCP11c APDUs the on-wire bytes
are opaque unless the session keys are provided. This module loads a
side-car JSON keybag and attempts to verify / decrypt every secure-messaging
APDU so the TUI can render plaintext context lines next to the ciphered
frame.

Keybag format (version 1):

.. code-block:: json

    {
      "version": 1,
      "sessions": [
        {
          "label": "SCP03 to ISD-R",
          "protocol": "scp03",
          "match": {
            "aid": "A0000005591010FFFFFFFF8900000100",
            "card_session_index": 1,
            "first_frame": 12
          },
          "keys": {
            "s_enc":  "0F0E0D0C0B0A09080706050403020100",
            "s_mac":  "0F0E0D0C0B0A09080706050403020100",
            "s_rmac": "0F0E0D0C0B0A09080706050403020100"
          },
          "initial_state": {
            "ssc": 0,
            "chaining_value": "00000000000000000000000000000000"
          }
        }
      ]
    }

All "match" fields are optional. When no match fields are configured, the
engine applies the session to every ciphered APDU it sees (reasonable for
single-session captures). For multi-session captures the combination of
`card_session_index`, `aid`, and `first_frame` narrows the window.

The wrap / unwrap implementation mirrors `SCP03/crypto/session.Scp03Session`
verbatim (same IV construction, same SSC pre-increment, same MAC chain).
SCP11c reuses the same on-wire secure messaging, so the same engine covers
both protocols; only the keying material origin differs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from typing import Any

try:
    from cryptography.hazmat.primitives import cmac as _cmac_module
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _CRYPTO_IMPORT_ERROR = ""
except Exception as _crypto_exc:
    _cmac_module = None
    Cipher = None
    algorithms = None
    modes = None
    _CRYPTO_IMPORT_ERROR = f"{_crypto_exc}"


SECURE_MESSAGING_CLA_BIT = 0x04
SECURE_MESSAGING_CIPHER_BIT = 0x02
_SUPPORTED_PROTOCOLS = frozenset({"scp03", "scp11c"})
_DEFAULT_CHAINING_HEX = "00" * 16


@dataclass(frozen=True, slots=True)
class KeybagSession:
    """Immutable description of a single keybag entry."""

    label: str
    protocol: str
    s_enc: bytes
    s_mac: bytes
    s_rmac: bytes
    match_aid: str = ""
    match_card_session_index: int | None = None
    match_first_frame: int | None = None
    initial_ssc: int = 0
    initial_chaining_value: bytes = b"\x00" * 16


@dataclass(slots=True)
class _SessionRuntime:
    """Live counters for a single keybag session."""

    session: KeybagSession
    ssc: int = 0
    chaining_value: bytes = b"\x00" * 16
    command_count: int = 0
    response_count: int = 0
    mac_mismatch_count: int = 0


@dataclass(frozen=True, slots=True)
class UnwrapContext:
    """Per-frame context the annotator passes to the replay engine."""

    frame_number: int
    card_session_index: int
    current_aid_hex: str = ""


@dataclass(frozen=True, slots=True)
class UnwrapResult:
    """Result of a single wrap/unwrap attempt."""

    matched_label: str
    lines: tuple[str, ...]


class KeybagError(RuntimeError):
    """Raised when a keybag JSON is malformed or references an unknown key."""


def load_keybag(path: str) -> list[KeybagSession]:
    """Load and validate a keybag JSON file.

    Raises :class:`KeybagError` on malformed input. Missing file raises
    `FileNotFoundError` so the caller can distinguish "no keybag yet" from
    "keybag is broken".
    """
    normalized_path = str(path or "").strip()
    if len(normalized_path) == 0:
        raise KeybagError("Keybag path is empty.")
    expanded_path = os.path.abspath(os.path.expanduser(normalized_path))
    with open(expanded_path, "rb") as handle:
        raw_bytes = handle.read()
    try:
        document = json.loads(raw_bytes.decode("utf-8"))
    except Exception as parse_exc:
        raise KeybagError(
            f"Keybag JSON at {expanded_path} is not valid UTF-8 JSON: {parse_exc}"
        ) from parse_exc
    if isinstance(document, dict) is False:
        raise KeybagError("Keybag top-level document must be a JSON object.")
    version_value = int(document.get("version", 1) or 1)
    if version_value != 1:
        raise KeybagError(
            f"Unsupported keybag version {version_value}; this build handles version 1 only."
        )
    raw_sessions = document.get("sessions", None)
    if isinstance(raw_sessions, list) is False:
        raise KeybagError("Keybag 'sessions' must be a JSON array.")
    parsed: list[KeybagSession] = []
    for index, entry in enumerate(raw_sessions):
        if isinstance(entry, dict) is False:
            raise KeybagError(
                f"Keybag session at index {index} is not a JSON object."
            )
        parsed.append(_parse_keybag_session(entry, index))
    return parsed


def _parse_keybag_session(entry: dict[str, Any], index: int) -> KeybagSession:
    label = str(entry.get("label", "") or f"session-{index}").strip()
    protocol = str(entry.get("protocol", "scp03") or "scp03").strip().lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        raise KeybagError(
            f"Keybag session '{label}' references unsupported protocol '{protocol}'. "
            f"Supported protocols: {sorted(_SUPPORTED_PROTOCOLS)}"
        )
    keys_section = entry.get("keys", None)
    if isinstance(keys_section, dict) is False:
        raise KeybagError(f"Keybag session '{label}' is missing 'keys' object.")
    s_enc_bytes = _required_hex(keys_section, "s_enc", label)
    s_mac_bytes = _required_hex(keys_section, "s_mac", label)
    s_rmac_hex = str(keys_section.get("s_rmac", "") or "").strip()
    if len(s_rmac_hex) == 0:
        s_rmac_bytes = s_mac_bytes
    else:
        s_rmac_bytes = _parse_hex_field(s_rmac_hex, f"{label}.keys.s_rmac")
    for key_name, key_bytes in (
        ("s_enc", s_enc_bytes),
        ("s_mac", s_mac_bytes),
        ("s_rmac", s_rmac_bytes),
    ):
        if len(key_bytes) not in (16, 24, 32):
            raise KeybagError(
                f"Keybag session '{label}' key '{key_name}' must be 16, 24, or 32 bytes "
                f"of raw AES key material (got {len(key_bytes)})."
            )
    match_section = entry.get("match", {}) or {}
    if isinstance(match_section, dict) is False:
        raise KeybagError(f"Keybag session '{label}' 'match' must be an object.")
    match_aid = str(match_section.get("aid", "") or "").strip().upper().replace(" ", "")
    match_card_session_index_raw = match_section.get("card_session_index", None)
    match_card_session_index: int | None = None
    if match_card_session_index_raw is not None:
        try:
            match_card_session_index = int(match_card_session_index_raw)
        except (TypeError, ValueError):
            raise KeybagError(
                f"Keybag session '{label}' match.card_session_index must be an integer."
            )
    match_first_frame_raw = match_section.get("first_frame", None)
    match_first_frame: int | None = None
    if match_first_frame_raw is not None:
        try:
            match_first_frame = int(match_first_frame_raw)
        except (TypeError, ValueError):
            raise KeybagError(
                f"Keybag session '{label}' match.first_frame must be an integer."
            )
    initial_state = entry.get("initial_state", {}) or {}
    if isinstance(initial_state, dict) is False:
        raise KeybagError(
            f"Keybag session '{label}' 'initial_state' must be an object."
        )
    initial_ssc_value = int(initial_state.get("ssc", 0) or 0)
    initial_chaining_hex = str(
        initial_state.get("chaining_value", _DEFAULT_CHAINING_HEX)
        or _DEFAULT_CHAINING_HEX
    )
    initial_chaining_bytes = _parse_hex_field(
        initial_chaining_hex,
        f"{label}.initial_state.chaining_value",
    )
    if len(initial_chaining_bytes) != 16:
        raise KeybagError(
            f"Keybag session '{label}' initial_state.chaining_value must be 16 bytes."
        )
    return KeybagSession(
        label=label,
        protocol=protocol,
        s_enc=s_enc_bytes,
        s_mac=s_mac_bytes,
        s_rmac=s_rmac_bytes,
        match_aid=match_aid,
        match_card_session_index=match_card_session_index,
        match_first_frame=match_first_frame,
        initial_ssc=initial_ssc_value,
        initial_chaining_value=initial_chaining_bytes,
    )


def _required_hex(section: dict[str, Any], field_name: str, label: str) -> bytes:
    raw_value = section.get(field_name, None)
    if raw_value is None:
        raise KeybagError(
            f"Keybag session '{label}' is missing required key '{field_name}'."
        )
    return _parse_hex_field(
        str(raw_value or ""),
        f"{label}.keys.{field_name}",
    )


def _parse_hex_field(value_text: str, context_label: str) -> bytes:
    normalized = str(value_text or "").strip().replace(" ", "").replace(":", "")
    if len(normalized) == 0:
        raise KeybagError(f"{context_label} is empty.")
    if (len(normalized) % 2) != 0:
        raise KeybagError(
            f"{context_label} must be an even-length hex string (got {len(normalized)} chars)."
        )
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise KeybagError(f"{context_label} is not valid hex: {exc}") from exc


class ScpReplayEngine:
    """Stateful replay of SCP03 / SCP11c secure messaging.

    The engine keeps one runtime (SSC + MAC chain) per keybag session and
    advances it as ciphered APDUs are consumed in capture order. When the
    user switches the displayed pcap the engine must be rebuilt from the
    keybag so the counters restart from the JSON-provided offsets.
    """

    def __init__(self, sessions: list[KeybagSession]) -> None:
        if _cmac_module is None or Cipher is None:
            raise RuntimeError(
                f"cryptography backend is unavailable: {_CRYPTO_IMPORT_ERROR}"
            )
        self._runtimes: list[_SessionRuntime] = [
            _SessionRuntime(
                session=session,
                ssc=int(session.initial_ssc),
                chaining_value=bytes(session.initial_chaining_value),
            )
            for session in sessions
        ]

    def has_sessions(self) -> bool:
        return len(self._runtimes) > 0

    def session_labels(self) -> list[str]:
        return [runtime.session.label for runtime in self._runtimes]

    def runtime_snapshots(self) -> list[dict[str, Any]]:
        """Return a list of runtime snapshot dicts for all recorded SCP sessions."""
        snapshots: list[dict[str, Any]] = []
        for runtime in self._runtimes:
            snapshots.append(
                {
                    "label": runtime.session.label,
                    "protocol": runtime.session.protocol,
                    "ssc": int(runtime.ssc),
                    "chaining_value": runtime.chaining_value.hex().upper(),
                    "command_count": int(runtime.command_count),
                    "response_count": int(runtime.response_count),
                    "mac_mismatch_count": int(runtime.mac_mismatch_count),
                }
            )
        return snapshots

    def try_unwrap_exchange(
        self,
        command_bytes: bytes,
        response_bytes: bytes,
        *,
        context: UnwrapContext,
    ) -> UnwrapResult | None:
        """Attempt to unwrap a (command, response) pair captured from the wire.

        Returns None when no keybag session applies or when the command is
        not a secure messaging APDU (CLA bit 0x04 clear).
        """
        if len(command_bytes) < 5:
            return None
        cla_byte = int(command_bytes[0])
        if (cla_byte & SECURE_MESSAGING_CLA_BIT) == 0:
            return None
        runtime = self._select_runtime(context)
        if runtime is None:
            return None
        # Parse the secure-messaging command per SCP03 C-MAC / C-ENCRYPTION.
        command_lines, mac_ok = self._unwrap_command(runtime, command_bytes)
        # Response parsing depends on sec_level (R-MAC and R-ENCRYPTION bits).
        # We probe both candidates and fall through on MAC mismatch because
        # the on-wire frame carries no sec_level indicator.
        response_lines = self._unwrap_response(
            runtime,
            response_bytes,
            command_had_mac=mac_ok,
        )
        combined_lines = list(command_lines) + list(response_lines)
        return UnwrapResult(
            matched_label=runtime.session.label,
            lines=tuple(combined_lines),
        )

    def _select_runtime(self, context: UnwrapContext) -> _SessionRuntime | None:
        if len(self._runtimes) == 0:
            return None
        best_match: _SessionRuntime | None = None
        best_specificity = -1
        for runtime in self._runtimes:
            session = runtime.session
            specificity = 0
            if len(session.match_aid) > 0:
                context_aid = str(context.current_aid_hex or "").strip().upper().replace(" ", "")
                if context_aid != session.match_aid:
                    continue
                specificity += 2
            if session.match_card_session_index is not None:
                if int(session.match_card_session_index) != int(context.card_session_index):
                    continue
                specificity += 1
            if session.match_first_frame is not None:
                if int(context.frame_number) < int(session.match_first_frame):
                    continue
                specificity += 1
            if specificity > best_specificity:
                best_match = runtime
                best_specificity = specificity
        return best_match

    def _unwrap_command(
        self,
        runtime: _SessionRuntime,
        command_bytes: bytes,
    ) -> tuple[list[str], bool]:
        lines: list[str] = []
        if len(command_bytes) < 5:
            return lines, False
        cla_byte = int(command_bytes[0])
        ins_byte = int(command_bytes[1])
        p1_byte = int(command_bytes[2])
        p2_byte = int(command_bytes[3])
        lc_byte = int(command_bytes[4])
        header = bytes([cla_byte, ins_byte, p1_byte, p2_byte, lc_byte])
        if len(command_bytes) < 5 + lc_byte:
            return lines, False
        body = bytes(command_bytes[5 : 5 + lc_byte])
        if len(body) < 8:
            lines.append(
                f"SCP replay: {runtime.session.label}: command body too short for MAC "
                f"(lc={lc_byte} < 8)"
            )
            return lines, False
        enc_payload = body[:-8]
        observed_mac = body[-8:]
        runtime.ssc = int(runtime.ssc) + 1
        expected_full_mac = _aes_cmac(
            runtime.session.s_mac,
            runtime.chaining_value + header + enc_payload,
        )
        expected_mac = expected_full_mac[:8]
        if expected_mac != observed_mac:
            runtime.mac_mismatch_count += 1
            lines.append(
                f"SCP replay: {runtime.session.label}: C-MAC mismatch "
                f"(ssc={runtime.ssc}, expected {expected_mac.hex().upper()}, "
                f"observed {observed_mac.hex().upper()})"
            )
            return lines, False
        runtime.chaining_value = expected_full_mac
        runtime.command_count += 1
        lines.append(
            f"SCP replay: {runtime.session.label}: C-MAC ok "
            f"(ssc={runtime.ssc}, chain={runtime.chaining_value[:4].hex().upper()}...)"
        )
        cipher_bit_set = (cla_byte & SECURE_MESSAGING_CIPHER_BIT) == SECURE_MESSAGING_CIPHER_BIT
        plaintext_body: bytes = enc_payload
        if cipher_bit_set and len(enc_payload) > 0:
            plaintext_body = _scp03_decrypt_command_payload(
                runtime.session.s_enc,
                runtime.ssc,
                enc_payload,
            )
        cleartext_apdu = _build_cleartext_apdu_from_header(
            cla_byte, ins_byte, p1_byte, p2_byte, plaintext_body
        )
        lines.append(
            f"SCP replay: command plaintext {cleartext_apdu.hex().upper()}"
        )
        return lines, True

    def _unwrap_response(
        self,
        runtime: _SessionRuntime,
        response_bytes: bytes,
        *,
        command_had_mac: bool,
    ) -> list[str]:
        # Response layout when R-MAC is present: [data..., mac[8], sw1, sw2].
        # When R-MAC is absent the whole response except SW is already plaintext.
        if len(response_bytes) < 2:
            return []
        if command_had_mac is False:
            return []
        sw_bytes = response_bytes[-2:]
        body_with_mac = response_bytes[:-2]
        if len(body_with_mac) < 8:
            return []
        data_part = body_with_mac[:-8]
        observed_rmac = body_with_mac[-8:]
        expected_full_rmac = _aes_cmac(
            runtime.session.s_rmac,
            runtime.chaining_value + data_part + sw_bytes,
        )
        expected_rmac = expected_full_rmac[:8]
        if expected_rmac != observed_rmac:
            # Response has no R-MAC (sec_level bit clear) — silently skip.
            return []
        runtime.response_count += 1
        plaintext_preview = data_part[:48].hex().upper()
        if len(data_part) > 48:
            plaintext_preview = plaintext_preview + "..."
        return [
            (
                f"SCP replay: {runtime.session.label}: R-MAC ok "
                f"({len(data_part)} data bytes, sw={sw_bytes.hex().upper()})"
            ),
            f"SCP replay: response plaintext {plaintext_preview}",
        ]


def _aes_cmac(key: bytes, data: bytes) -> bytes:
    if _cmac_module is None:
        raise RuntimeError(
            f"cryptography.primitives.cmac is unavailable: {_CRYPTO_IMPORT_ERROR}"
        )
    mac = _cmac_module.CMAC(algorithms.AES(key))
    mac.update(data)
    return mac.finalize()


def _scp03_encode_counter(counter: int) -> bytes:
    return int(counter).to_bytes(16, "big")


def _scp03_decrypt_command_payload(
    s_enc: bytes,
    post_increment_ssc: int,
    enc_payload: bytes,
) -> bytes:
    # Mirror the existing SCP03 session wrap: IV is AES_ECB(S-ENC, SSC - 1).
    iv_counter = (int(post_increment_ssc) - 1).to_bytes(16, "big")
    ecb_cipher = Cipher(algorithms.AES(s_enc), modes.ECB())
    encryptor = ecb_cipher.encryptor()
    iv = encryptor.update(iv_counter) + encryptor.finalize()
    cbc_cipher = Cipher(algorithms.AES(s_enc), modes.CBC(iv))
    decryptor = cbc_cipher.decryptor()
    plaintext_padded = decryptor.update(enc_payload) + decryptor.finalize()
    return _strip_iso7816_d4_padding(plaintext_padded)


def _strip_iso7816_d4_padding(padded: bytes) -> bytes:
    if len(padded) == 0:
        return padded
    pad_index = padded.rfind(b"\x80")
    if pad_index == -1:
        return padded
    trailer = padded[pad_index + 1 :]
    if all(byte == 0 for byte in trailer):
        return padded[:pad_index]
    return padded


def _build_cleartext_apdu_from_header(
    original_cla: int,
    ins: int,
    p1: int,
    p2: int,
    body: bytes,
) -> bytes:
    # Strip secure-messaging and cipher bits so the decoded APDU matches
    # what the application layer originally issued prior to SCP wrapping.
    cla_without_sm = int(original_cla) & 0xF9
    if len(body) == 0:
        return bytes([cla_without_sm, ins, p1, p2])
    if len(body) > 0xFF:
        raise ValueError("Cleartext body longer than 255 bytes is not supported here.")
    return bytes([cla_without_sm, ins, p1, p2, len(body)]) + body


def try_autodiscover_sidecar_keybag(pcap_path: str) -> str:
    """Return the first sibling `<pcap>*.keys.json` that exists, else ""."""
    normalized = str(pcap_path or "").strip()
    if len(normalized) == 0:
        return ""
    expanded = os.path.abspath(os.path.expanduser(normalized))
    direct_candidate = expanded + ".keys.json"
    if os.path.isfile(direct_candidate):
        return direct_candidate
    stem_candidate = os.path.splitext(expanded)[0] + ".keys.json"
    if os.path.isfile(stem_candidate):
        return stem_candidate
    return ""


@dataclass(frozen=True, slots=True)
class KeybagLoadSummary:
    """Human-readable summary used by the TUI status line / console log."""

    session_count: int
    source_path: str
    error_text: str = ""
    labels: tuple[str, ...] = field(default_factory=tuple)


def load_keybag_safe(path: str) -> KeybagLoadSummary:
    """Wrapper around `load_keybag` that never raises.

    Designed for the TUI startup path where a missing or broken keybag
    should downgrade the experience to "ciphered APDUs stay wrapped" rather
    than crash the whole offline review session.
    """
    normalized_path = str(path or "").strip()
    if len(normalized_path) == 0:
        return KeybagLoadSummary(session_count=0, source_path="")
    try:
        sessions = load_keybag(normalized_path)
    except FileNotFoundError:
        return KeybagLoadSummary(
            session_count=0,
            source_path=normalized_path,
            error_text=f"Keybag file not found: {normalized_path}",
        )
    except KeybagError as exc:
        return KeybagLoadSummary(
            session_count=0,
            source_path=normalized_path,
            error_text=str(exc),
        )
    except Exception as exc:
        return KeybagLoadSummary(
            session_count=0,
            source_path=normalized_path,
            error_text=f"Unexpected keybag load error: {exc}",
        )
    return KeybagLoadSummary(
        session_count=len(sessions),
        source_path=normalized_path,
        labels=tuple(str(session.label) for session in sessions),
    )
