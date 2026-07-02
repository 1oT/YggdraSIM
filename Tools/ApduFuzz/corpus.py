# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
APDU corpus loader.

The fuzzer replays known-good APDU sequences captured from the
YggdraSIM simulator ``ShellSessionRecorder`` (see
``yggdrasim_common.session_recording``) and mutates them before
sending the commands to a physical card. Corpora are JSON files with
the following shape (superset-friendly — unknown keys are ignored)::

    {
        "session_id": "...",
        "apdu_trace": [
            {"index": 0, "command": "00A40004023F00", "response": "9000"},
            {"index": 1, "command": "00B200010400000020", "response": "6A82"},
            ...
        ]
    }

The loader additionally accepts a bare list of hex-command strings
for ad-hoc corpora hand-written by an operator.

This module does **not** touch any live transport. It is safe to
import and test without PC/SC or a HIL bridge.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


@dataclass(frozen=True)
class CorpusEntry:
    """One command APDU + metadata drawn from a session recording."""

    index: int
    command_hex: str
    response_hex: str = ""

    def command_bytes(self) -> bytes:
        """Return the raw APDU command bytes for this corpus entry."""
        cleaned = self.command_hex.strip().replace(" ", "")
        if len(cleaned) == 0:
            return b""
        if len(cleaned) % 2 != 0:
            raise ValueError(
                f"CorpusEntry index={self.index} has odd-length command hex"
            )
        try:
            return bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError(
                f"CorpusEntry index={self.index} command hex is invalid: {error}"
            ) from error


@dataclass(frozen=True)
class Corpus:
    """Ordered collection of :class:`CorpusEntry` records."""

    source_path: Path
    session_id: str
    entries: tuple[CorpusEntry, ...]

    @property
    def command_count(self) -> int:
        return len(self.entries)


def _coerce_hex(value: object, *, index: int, field: str) -> str:
    if value is None:
        return ""
    if isinstance(value, str) is False:
        raise ValueError(
            f"CorpusEntry index={index} field={field} must be a hex string"
        )
    cleaned = value.strip().replace(" ", "")
    if len(cleaned) == 0:
        return ""
    if _HEX_RE.match(cleaned) is None:
        raise ValueError(
            f"CorpusEntry index={index} field={field} is not hex: {cleaned!r}"
        )
    return cleaned.upper()


def _parse_list_payload(items: list[object], *, source: Path) -> Corpus:
    entries: list[CorpusEntry] = []
    for raw_index, raw in enumerate(items):
        if isinstance(raw, dict) is True:
            command = _coerce_hex(raw.get("command"), index=raw_index, field="command")
            response = _coerce_hex(raw.get("response"), index=raw_index, field="response")
            index_value = raw.get("index", raw_index)
            entries.append(
                CorpusEntry(
                    index=int(index_value),
                    command_hex=command,
                    response_hex=response,
                )
            )
            continue
        if isinstance(raw, str) is True:
            entries.append(
                CorpusEntry(
                    index=raw_index,
                    command_hex=_coerce_hex(raw, index=raw_index, field="command"),
                )
            )
            continue
        raise ValueError(
            f"Corpus entry index={raw_index} has unsupported type {type(raw).__name__}"
        )
    return Corpus(
        source_path=source,
        session_id=source.stem,
        entries=tuple(entries),
    )


def _parse_recorder_payload(payload: dict[str, object], *, source: Path) -> Corpus:
    session_id = str(payload.get("session_id") or source.stem)
    raw_trace = payload.get("apdu_trace", payload.get("commands", []))
    if isinstance(raw_trace, list) is False:
        raise ValueError(
            f"{source}: corpus payload lacks 'apdu_trace' list "
            f"(got {type(raw_trace).__name__})"
        )
    corpus_from_list = _parse_list_payload(raw_trace, source=source)
    return Corpus(
        source_path=source,
        session_id=session_id,
        entries=corpus_from_list.entries,
    )


def load_corpus(path: Path) -> Corpus:
    """Parse a JSON corpus from disk.

    Accepts either:

    * A full recorder dump (``{"session_id": ..., "apdu_trace": [...]}``).
    * A bare list of ``{"command": "...", "response": "..."}`` dicts.
    * A bare list of hex-string commands.
    """
    path = Path(path).expanduser().resolve()
    if path.is_file() is False:
        raise FileNotFoundError(f"corpus file not found: {path}")
    payload = json.loads(path.read_text("utf-8"))
    if isinstance(payload, list) is True:
        return _parse_list_payload(payload, source=path)
    if isinstance(payload, dict) is True:
        return _parse_recorder_payload(payload, source=path)
    raise ValueError(
        f"{path}: corpus must be a list or an object, got {type(payload).__name__}"
    )


def filter_select_only(corpus: Corpus) -> Corpus:
    """Return a corpus with non-SELECT APDUs stripped.

    Useful when the operator wants to fuzz only the file-selection
    surface (ETSI TS 102 221 §11.1.1). Non-SELECT entries are
    identified by CLA=00, INS=A4 (or CLA&0xF0==0x00, INS=A4).
    """
    kept: list[CorpusEntry] = []
    for entry in corpus.entries:
        command_bytes = entry.command_bytes()
        if len(command_bytes) < 2:
            continue
        if command_bytes[1] != 0xA4:
            continue
        kept.append(entry)
    return Corpus(
        source_path=corpus.source_path,
        session_id=corpus.session_id,
        entries=tuple(kept),
    )
