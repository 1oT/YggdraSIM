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

"""Structured fallback wrappers for SCP11 TLV / X.509 / ASN.1 parsing.

The three SCP11 trees historically accumulated a large number of broad
``except Exception`` sites; most were TLV-parse or certificate-decode
fallbacks that silently continue on malformed input. ``safe_parse``
centralises the pattern so every swallowed failure is tagged with a
``label`` and a bounded preview of the offending buffer, and so the
default value is explicit at the call site instead of hidden inside a
broad ``except`` block.

Typical use:

    from SCP11.shared.safe_parse import safe_parse

    def _decode_eim_euicc_challenge_binary(self, value: str) -> bytes:
        raw_value = self._decode_string_payload(value)
        if len(raw_value) == 16:
            return raw_value

        def _parse_challenge(buf: bytes) -> bytes:
            tag, inner_value, _, end_offset = self._read_tlv(buf, 0)
            if end_offset != len(buf):
                raise ValueError("trailing bytes after challenge TLV")
            if tag != b"\\x81":
                raise ValueError("unexpected outer tag")
            if len(inner_value) != 16:
                raise ValueError("challenge length != 16 bytes")
            return inner_value

        return safe_parse(
            "eim.euicc_challenge",
            raw_value,
            _parse_challenge,
            default=b"",
        )

The helper never raises. It records the failure via the module logger so
SOC / debug configurations can surface what the SCP11 stack quietly
dropped, and it supports any parser callable that takes the buffer as its
only argument.
"""

from __future__ import annotations

import logging
from typing import Callable, TypeVar

_LOGGER = logging.getLogger(__name__)

_DEFAULT_PREVIEW_BYTES = 16

T = TypeVar("T")


def _format_preview(buffer: bytes | bytearray | memoryview | None, preview_bytes: int) -> str:
    if buffer is None:
        return "<none>"
    raw = bytes(buffer)
    if len(raw) == 0:
        return "<empty>"
    head = raw[:preview_bytes]
    tail_note = ""
    if len(raw) > preview_bytes:
        tail_note = f"... (+{len(raw) - preview_bytes} more)"
    return f"{head.hex().upper()}{tail_note} (len={len(raw)})"


def safe_parse(
    label: str,
    buffer: bytes | bytearray | memoryview | None,
    parser: Callable[[bytes], T],
    *,
    default: T,
    preview_bytes: int = _DEFAULT_PREVIEW_BYTES,
    logger: logging.Logger | None = None,
) -> T:
    """Run *parser(buffer)* and return *default* on any exception.

    All exceptions are caught deliberately: SCP11 TLV / ASN.1 / X.509
    fallbacks are the site this helper exists to replace, and the caller
    has already committed to a fixed *default* for malformed input. Every
    swallowed failure is logged at ``DEBUG`` with *label*, the exception
    type and message, and a bounded hex preview of the input buffer. The
    same record is escalated to ``WARNING`` via a rate-limited rollup so
    it is visible without drowning an otherwise healthy session in noise.
    """
    active_logger = logger if logger is not None else _LOGGER
    normalized_buffer = b"" if buffer is None else bytes(buffer)
    try:
        return parser(normalized_buffer)
    except Exception as exc:  # noqa: BLE001 -- documented fallback site
        preview = _format_preview(normalized_buffer, preview_bytes)
        active_logger.debug(
            "safe_parse(%s) suppressed %s: %s [buffer=%s]",
            label,
            exc.__class__.__name__,
            exc,
            preview,
        )
        _record_rollup(active_logger, label, exc)
        return default


# --- rate-limited rollup ----------------------------------------------------
#
# The rollup keeps one ``WARNING`` per distinct (label, exception class)
# pair per process so a flood of malformed TLVs still produces one visible
# line per failure type, but does not spam the shell for every element in
# a list decode. Tests that care about structured output can query
# ``reset_safe_parse_rollup`` to start clean.

_ROLLUP: dict[tuple[str, str], int] = {}


def _record_rollup(active_logger: logging.Logger, label: str, exc: BaseException) -> None:
    key = (str(label), exc.__class__.__name__)
    previous_count = _ROLLUP.get(key, 0)
    _ROLLUP[key] = previous_count + 1
    if previous_count == 0:
        active_logger.warning(
            "safe_parse(%s) suppressed first %s occurrence: %s",
            label,
            exc.__class__.__name__,
            exc,
        )


def reset_safe_parse_rollup() -> None:
    """Clear the rate-limited rollup counters.

    Intended for tests and for shells that want to re-arm the "first
    occurrence" warning between operator commands.
    """
    _ROLLUP.clear()


def safe_parse_rollup_snapshot() -> dict[tuple[str, str], int]:
    """Return a snapshot of the current rollup counters."""
    return dict(_ROLLUP)
