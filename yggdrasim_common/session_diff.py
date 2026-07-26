# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Diff the APDU traces of two shell session recordings.

Answers the question a card lab asks constantly: the same script ran
against two cards, or against one card before and after a change, so where
did they stop agreeing?

Exchanges are aligned with :class:`difflib.SequenceMatcher` keyed on the
command APDU rather than by position, because a single extra exchange on
one side (a retry, an added GET RESPONSE) would otherwise make everything
after it look different.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml


SCHEMA_PREFIX = "yggdrasim_session_recording/"

#: Response payloads can carry PINs and operator secrets, so text output
#: truncates them unless the caller asks for everything.
DEFAULT_DATA_PREVIEW = 32

KIND_RESPONSE = "response"
KIND_STATUS = "status"
KIND_ONLY_LEFT = "only_in_left"
KIND_ONLY_RIGHT = "only_in_right"


class SessionDiffError(ValueError):
    """A recording could not be read or does not carry an APDU trace."""


@dataclass(frozen=True)
class Exchange:
    """One APDU exchange, normalised out of a recording's trace entry."""

    index: int
    apdu_hex: str
    data_hex: str
    status_hex: str
    ok: bool

    @property
    def key(self) -> str:
        return self.apdu_hex


@dataclass(frozen=True)
class DiffEntry:
    kind: str
    apdu_hex: str
    left_index: int | None = None
    right_index: int | None = None
    left_value: str = ""
    right_value: str = ""

    def describe(self, *, preview: int) -> str:
        where = f"L{self.left_index if self.left_index is not None else '-'}" \
                f"/R{self.right_index if self.right_index is not None else '-'}"
        apdu = _clip(self.apdu_hex, preview)
        if self.kind == KIND_ONLY_LEFT:
            return f"{where}  only in left   {apdu}"
        if self.kind == KIND_ONLY_RIGHT:
            return f"{where}  only in right  {apdu}"
        label = "status" if self.kind == KIND_STATUS else "response"
        return (
            f"{where}  {label} differs  {apdu}\n"
            f"        left : {_clip(self.left_value, preview)}\n"
            f"        right: {_clip(self.right_value, preview)}"
        )


@dataclass
class SessionDiff:
    left_path: str
    right_path: str
    left_count: int
    right_count: int
    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def identical(self) -> bool:
        return not self.entries

    @property
    def first_divergence(self) -> DiffEntry | None:
        return self.entries[0] if self.entries else None

    def counts(self) -> dict[str, int]:
        totals = {
            KIND_STATUS: 0,
            KIND_RESPONSE: 0,
            KIND_ONLY_LEFT: 0,
            KIND_ONLY_RIGHT: 0,
        }
        for entry in self.entries:
            totals[entry.kind] = totals.get(entry.kind, 0) + 1
        return totals

    def to_json(self) -> dict[str, Any]:
        return {
            "left": {"path": self.left_path, "exchanges": self.left_count},
            "right": {"path": self.right_path, "exchanges": self.right_count},
            "identical": self.identical,
            "counts": self.counts(),
            "entries": [
                {
                    "kind": entry.kind,
                    "apdu": entry.apdu_hex,
                    "left_index": entry.left_index,
                    "right_index": entry.right_index,
                    "left": entry.left_value,
                    "right": entry.right_value,
                }
                for entry in self.entries
            ],
        }


def _clip(value: str, preview: int) -> str:
    text = str(value or "")
    if preview <= 0 or len(text) <= preview:
        return text or "(empty)"
    return f"{text[:preview]}... ({len(text)} hex chars)"


def load_recording(path: str | Path) -> list[Exchange]:
    """Read a session recording and return its APDU trace."""

    resolved = Path(path).expanduser()
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise SessionDiffError(f"cannot read recording {resolved}: {exc}") from exc

    try:
        # ``safe_load`` parses JSON too, so one path covers both suffixes.
        payload = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SessionDiffError(f"{resolved} is not valid YAML or JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise SessionDiffError(f"{resolved} is not a session recording mapping")
    schema = str(payload.get("schema") or "")
    if not schema.startswith(SCHEMA_PREFIX):
        raise SessionDiffError(
            f"{resolved} is not a session recording (schema={schema or 'absent'!r})"
        )
    trace = payload.get("apdu_trace")
    if not isinstance(trace, list):
        raise SessionDiffError(f"{resolved} carries no apdu_trace list")
    return _exchanges_from_trace(trace)


def _exchanges_from_trace(trace: Iterable[Any]) -> list[Exchange]:
    exchanges: list[Exchange] = []
    for position, raw in enumerate(trace):
        if not isinstance(raw, dict):
            continue
        status = str(raw.get("status_hex") or "").upper()
        if not status:
            sw1 = raw.get("sw1")
            sw2 = raw.get("sw2")
            if isinstance(sw1, int) and isinstance(sw2, int):
                status = f"{sw1:02X}{sw2:02X}"
        exchanges.append(
            Exchange(
                index=int(raw.get("index", position) or position),
                apdu_hex=str(raw.get("apdu_hex") or "").upper(),
                data_hex=str(raw.get("response_data_hex") or "").upper(),
                status_hex=status,
                ok=bool(raw.get("ok", status in ("9000", "9100"))),
            )
        )
    return exchanges


def diff_exchanges(
    left: Sequence[Exchange],
    right: Sequence[Exchange],
    *,
    left_path: str = "left",
    right_path: str = "right",
) -> SessionDiff:
    """Align two traces on their command APDUs and report what differs."""

    result = SessionDiff(
        left_path=left_path,
        right_path=right_path,
        left_count=len(left),
        right_count=len(right),
    )
    matcher = SequenceMatcher(
        a=[item.key for item in left],
        b=[item.key for item in right],
        autojunk=False,
    )
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                result.entries.extend(
                    _compare_matched(left[i1 + offset], right[j1 + offset])
                )
            continue
        # ``replace`` is a delete plus an insert: the commands themselves
        # diverged, so there is no meaningful response comparison to make.
        for item in left[i1:i2]:
            result.entries.append(
                DiffEntry(
                    kind=KIND_ONLY_LEFT,
                    apdu_hex=item.apdu_hex,
                    left_index=item.index,
                )
            )
        for item in right[j1:j2]:
            result.entries.append(
                DiffEntry(
                    kind=KIND_ONLY_RIGHT,
                    apdu_hex=item.apdu_hex,
                    right_index=item.index,
                )
            )
    return result


def _compare_matched(left: Exchange, right: Exchange) -> list[DiffEntry]:
    entries: list[DiffEntry] = []
    if left.status_hex != right.status_hex:
        entries.append(
            DiffEntry(
                kind=KIND_STATUS,
                apdu_hex=left.apdu_hex,
                left_index=left.index,
                right_index=right.index,
                left_value=left.status_hex,
                right_value=right.status_hex,
            )
        )
    if left.data_hex != right.data_hex:
        entries.append(
            DiffEntry(
                kind=KIND_RESPONSE,
                apdu_hex=left.apdu_hex,
                left_index=left.index,
                right_index=right.index,
                left_value=left.data_hex,
                right_value=right.data_hex,
            )
        )
    return entries


def diff_recordings(left_path: str | Path, right_path: str | Path) -> SessionDiff:
    """Load two recordings and diff their APDU traces."""

    return diff_exchanges(
        load_recording(left_path),
        load_recording(right_path),
        left_path=str(left_path),
        right_path=str(right_path),
    )


def format_diff(result: SessionDiff, *, preview: int = DEFAULT_DATA_PREVIEW) -> str:
    """Render a diff as operator-readable text."""

    lines = [
        f"left : {result.left_path}  ({result.left_count} exchanges)",
        f"right: {result.right_path}  ({result.right_count} exchanges)",
    ]
    if result.identical:
        lines.append("")
        lines.append("APDU traces are identical.")
        return "\n".join(lines)

    counts = result.counts()
    lines.append("")
    lines.append(
        f"{len(result.entries)} difference(s): "
        f"{counts[KIND_STATUS]} status, {counts[KIND_RESPONSE]} response, "
        f"{counts[KIND_ONLY_LEFT]} only-left, {counts[KIND_ONLY_RIGHT]} only-right"
    )
    lines.append("")
    for entry in result.entries:
        lines.append(entry.describe(preview=preview))
    return "\n".join(lines)


def run_cli(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="yggdrasim-session-diff",
        description="Diff the APDU traces of two shell session recordings.",
    )
    parser.add_argument("left", help="baseline recording (.yaml/.yml/.json)")
    parser.add_argument("right", help="recording to compare against the baseline")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the diff as JSON instead of text",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "print untruncated response payloads. These can contain PINs and "
            "operator secrets; the default truncates them."
        ),
    )
    options = parser.parse_args(list(argv) if argv is not None else None)

    try:
        result = diff_recordings(options.left, options.right)
    except SessionDiffError as exc:
        print(f"session-diff: {exc}")
        return 2

    if options.json:
        print(json.dumps(result.to_json(), indent=2))
    else:
        preview = 0 if options.full else DEFAULT_DATA_PREVIEW
        print(format_diff(result, preview=preview))
    # Exit 1 on divergence so a shell loop can branch on it.
    return 0 if result.identical else 1


if __name__ == "__main__":
    raise SystemExit(run_cli())
