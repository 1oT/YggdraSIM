# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Deterministic APDU mutation strategies.

Each mutator is a pure function ``(bytes, random.Random) -> bytes``
that produces a single mutated command APDU from a known-good
original. Determinism (via the supplied ``Random`` instance) is a
contract — crashes must be reproducible from a seed, otherwise
vulnerability research is impossible.

Supported strategies (ETSI TS 102 221 §10.1 APDU framing):

* :func:`mutate_bit_flip`       — flip one or more random bits in the
  payload portion of the APDU (never touches the CLA/INS header so
  the card still tries to parse the command).
* :func:`mutate_length_mangle`  — corrupt the Lc / Le fields so the
  command declares a length that does not match the actual payload.
* :func:`mutate_tag_shuffle`    -- substitutes one random byte inside
  the data field. Byte-level, not TLV-aware; the TLV-aware strategies
  are the ``tlv_*`` family below.
* :func:`mutate_padding_bloat`  — appends N bytes of junk past the
  declared Lc to test if the card strictly enforces length checks.
* :func:`mutate_zero_lc`        — sets Lc to 0x00 while keeping the
  original payload (classic length-confusion surface).

The five above work on the APDU envelope. The strategies below parse
the BER-TLV grammar of the data field first, so they can violate it
deliberately rather than by chance -- the decode paths reached by a
Bound Profile Package or an SGP.32 eUICC package are structured deeply
enough that random byte edits rarely produce a parseable-but-wrong
encoding.

* :func:`mutate_tlv_length_overclaim` -- a TLV declares more body than
  the field contains.
* :func:`mutate_tlv_length_underclaim` -- a TLV declares less, leaving
  trailing bytes the parser must decide how to treat.
* :func:`mutate_tlv_truncate`   -- cuts the data at a TLV boundary so
  the last element is structurally incomplete.
* :func:`mutate_tlv_reorder`    -- swaps two sibling TLVs, exercising
  decoders that assume a fixed field order in a SEQUENCE.
* :func:`mutate_tlv_long_form_length` -- re-encodes a short-form length
  as an over-claiming long-form one.

All mutators respect the short APDU envelope (5-byte header). Extended
APDU mutation support is deferred — the simulator session recordings
we target use short APDUs exclusively.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


APDU_HEADER_BYTES: int = 5


@dataclass(frozen=True)
class MutationResult:
    """Outcome of a single mutation strategy.

    ``description`` is a short, grep-friendly tag used in crash dumps
    (e.g. ``"bit_flip@byte=7,bit=3"``). The runner writes it into the
    crash-dump filename so reproducing the failure from an operator's
    issue report is trivial.
    """

    mutated_apdu: bytes
    description: str


def _apdu_split(apdu: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a case-4 short APDU into ``(header, data, le)`` chunks."""
    if len(apdu) < APDU_HEADER_BYTES:
        return bytes(apdu), b"", b""
    header = bytes(apdu[:APDU_HEADER_BYTES])
    tail = bytes(apdu[APDU_HEADER_BYTES:])
    if len(tail) == 0:
        return header, b"", b""
    lc_value = header[4]
    if lc_value == 0:
        # Case-2: pure Le
        return header, b"", tail
    data_chunk = tail[:lc_value]
    le_chunk = tail[lc_value:]
    return header, data_chunk, le_chunk


def _reassemble(header: bytes, data: bytes, le: bytes) -> bytes:
    return bytes(header) + bytes(data) + bytes(le)


def mutate_bit_flip(apdu: bytes, rng: random.Random) -> MutationResult:
    """Return a mutated APDU with one randomly chosen bit flipped."""
    if len(apdu) <= APDU_HEADER_BYTES:
        if len(apdu) == 0:
            return MutationResult(mutated_apdu=b"", description="bit_flip@empty")
        byte_index = rng.randrange(len(apdu))
    else:
        byte_index = rng.randrange(APDU_HEADER_BYTES, len(apdu))
    bit_index = rng.randrange(8)
    mutated = bytearray(apdu)
    mutated[byte_index] ^= 1 << bit_index
    return MutationResult(
        mutated_apdu=bytes(mutated),
        description=f"bit_flip@byte={byte_index},bit={bit_index}",
    )


def mutate_length_mangle(apdu: bytes, rng: random.Random) -> MutationResult:
    """Return a mutated APDU with the Lc/Le field set to an out-of-range value."""
    if len(apdu) < APDU_HEADER_BYTES:
        return MutationResult(mutated_apdu=bytes(apdu), description="length_mangle@short")
    mutated = bytearray(apdu)
    original_lc = mutated[4]
    drift = rng.choice([-1, +1, +0x10, -0x10, 0x7F, 0xFF])
    new_value = (original_lc + drift) & 0xFF
    mutated[4] = new_value
    return MutationResult(
        mutated_apdu=bytes(mutated),
        description=f"length_mangle@lc={original_lc:02X}->drift{drift:+d}={new_value:02X}",
    )


def mutate_zero_lc(apdu: bytes, _rng: random.Random) -> MutationResult:
    """Return a mutated APDU with the Lc field set to zero."""
    if len(apdu) < APDU_HEADER_BYTES:
        return MutationResult(mutated_apdu=bytes(apdu), description="zero_lc@short")
    mutated = bytearray(apdu)
    original_lc = mutated[4]
    mutated[4] = 0x00
    return MutationResult(
        mutated_apdu=bytes(mutated),
        description=f"zero_lc@lc={original_lc:02X}->00",
    )


def mutate_tag_shuffle(apdu: bytes, rng: random.Random) -> MutationResult:
    """Return a mutated APDU with one random data-field byte substituted.

    Byte-level despite the name, which is kept because historical crash
    dumps and seeds reference it. For strategies that parse the TLV
    grammar before breaking it, see the ``tlv_*`` mutators.
    """
    header, data, le = _apdu_split(apdu)
    if len(data) == 0:
        return MutationResult(mutated_apdu=bytes(apdu), description="tag_shuffle@no_data")
    mutated_data = bytearray(data)
    target_index = rng.randrange(len(mutated_data))
    original_tag = mutated_data[target_index]
    candidate = original_tag
    for _ in range(8):
        candidate = rng.randrange(0x01, 0xFF)
        if candidate != original_tag:
            break
    mutated_data[target_index] = candidate
    return MutationResult(
        mutated_apdu=_reassemble(header, bytes(mutated_data), le),
        description=(
            f"tag_shuffle@data_byte={target_index},"
            f"tag={original_tag:02X}->{candidate:02X}"
        ),
    )


def mutate_padding_bloat(apdu: bytes, rng: random.Random) -> MutationResult:
    """Return a mutated APDU with excess padding appended to the data field."""
    pad_count = rng.randint(1, 16)
    mutated = bytearray(apdu)
    mutated.extend(rng.randrange(0, 256) for _ in range(pad_count))
    return MutationResult(
        mutated_apdu=bytes(mutated),
        description=f"padding_bloat@pad={pad_count}",
    )


@dataclass(frozen=True)
class TlvField:
    """One BER-TLV element located inside an APDU data field.

    Offsets are relative to the start of the data field, not the APDU.
    """

    tag_start: int
    value_start: int
    value_end: int
    tag: bytes
    length_octets: bytes

    @property
    def end(self) -> int:
        return self.value_end


def _read_tag(data: bytes, offset: int) -> tuple[bytes, int] | None:
    """Return (tag_bytes, next_offset) for a BER tag at ``offset``."""
    if offset >= len(data):
        return None
    first = data[offset]
    if first in (0x00, 0xFF):
        return None
    # ISO/IEC 8825-1 8.1.2.4: low tag-number form unless bits 5-1 are all set.
    if (first & 0x1F) != 0x1F:
        return bytes([first]), offset + 1
    cursor = offset + 1
    while cursor < len(data):
        current = data[cursor]
        cursor += 1
        if (current & 0x80) == 0:
            return bytes(data[offset:cursor]), cursor
    return None


def _read_length(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
    """Return (value_length, length_octets, next_offset) at ``offset``."""
    if offset >= len(data):
        return None
    first = data[offset]
    if (first & 0x80) == 0:
        return first, bytes([first]), offset + 1
    count = first & 0x7F
    if count == 0 or count > 4:
        # Indefinite length, or a long form wider than anything a short
        # APDU can carry.
        return None
    end = offset + 1 + count
    if end > len(data):
        return None
    return (
        int.from_bytes(data[offset + 1 : end], "big"),
        bytes(data[offset : end]),
        end,
    )


def parse_tlv_fields(data: bytes) -> list[TlvField]:
    """Return the top-level BER-TLV elements in ``data``.

    Parsing stops at the first element that does not decode cleanly, so a
    partially structured payload still yields the prefix that did parse.
    """
    fields: list[TlvField] = []
    cursor = 0
    while cursor < len(data):
        tag_read = _read_tag(data, cursor)
        if tag_read is None:
            break
        tag, after_tag = tag_read
        length_read = _read_length(data, after_tag)
        if length_read is None:
            break
        value_length, length_octets, value_start = length_read
        value_end = value_start + value_length
        if value_end > len(data):
            break
        fields.append(
            TlvField(
                tag_start=cursor,
                value_start=value_start,
                value_end=value_end,
                tag=tag,
                length_octets=length_octets,
            )
        )
        cursor = value_end
    return fields


def _rebuild(header: bytes, data: bytes, le: bytes) -> bytes:
    """Reassemble an APDU, keeping Lc consistent with the new data length."""
    mutated_header = bytearray(header)
    if len(mutated_header) >= APDU_HEADER_BYTES:
        mutated_header[4] = len(data) & 0xFF
    return bytes(mutated_header) + bytes(data) + bytes(le)


def _tlv_context(
    apdu: bytes,
) -> tuple[bytes, bytes, bytes, list[TlvField]] | None:
    header, data, le = _apdu_split(apdu)
    if len(data) == 0:
        return None
    fields = parse_tlv_fields(data)
    if len(fields) == 0:
        return None
    return header, data, le, fields


def mutate_tlv_length_overclaim(apdu: bytes, rng: random.Random) -> MutationResult:
    """Make one TLV declare a longer body than the field actually holds."""
    context = _tlv_context(apdu)
    if context is None:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_length_overclaim@no_tlv")
    header, data, le, fields = context
    target = rng.choice(fields)
    if len(target.length_octets) != 1 or target.length_octets[0] >= 0x7F:
        return MutationResult(
            mutated_apdu=bytes(apdu), description="tlv_length_overclaim@not_short_form"
        )
    original = target.length_octets[0]
    inflated = min(0x7F, original + rng.randint(1, 32))
    if inflated == original:
        inflated = original + 1
    mutated = bytearray(data)
    mutated[target.value_start - 1] = inflated
    return MutationResult(
        mutated_apdu=_rebuild(header, bytes(mutated), le),
        description=(
            f"tlv_length_overclaim@tag={target.tag.hex().upper()},"
            f"len={original:02X}->{inflated:02X}"
        ),
    )


def mutate_tlv_length_underclaim(apdu: bytes, rng: random.Random) -> MutationResult:
    """Make one TLV declare a shorter body, leaving trailing bytes behind."""
    context = _tlv_context(apdu)
    if context is None:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_length_underclaim@no_tlv")
    header, data, le, fields = context
    candidates = [
        field
        for field in fields
        if len(field.length_octets) == 1 and field.length_octets[0] > 0
    ]
    if len(candidates) == 0:
        return MutationResult(
            mutated_apdu=bytes(apdu), description="tlv_length_underclaim@no_candidate"
        )
    target = rng.choice(candidates)
    original = target.length_octets[0]
    reduced = rng.randrange(0, original)
    mutated = bytearray(data)
    mutated[target.value_start - 1] = reduced
    return MutationResult(
        mutated_apdu=_rebuild(header, bytes(mutated), le),
        description=(
            f"tlv_length_underclaim@tag={target.tag.hex().upper()},"
            f"len={original:02X}->{reduced:02X}"
        ),
    )


def mutate_tlv_truncate(apdu: bytes, rng: random.Random) -> MutationResult:
    """Cut the data field mid-element so the last TLV is incomplete."""
    context = _tlv_context(apdu)
    if context is None:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_truncate@no_tlv")
    header, data, le, fields = context
    target = rng.choice(fields)
    # Land inside the value so the element promises bytes that are gone.
    if target.value_end - target.value_start > 0:
        cut = rng.randrange(target.value_start, target.value_end)
    else:
        cut = target.value_start
    if cut == 0:
        cut = min(1, len(data))
    return MutationResult(
        mutated_apdu=_rebuild(header, bytes(data[:cut]), le),
        description=f"tlv_truncate@tag={target.tag.hex().upper()},cut={cut}",
    )


def mutate_tlv_reorder(apdu: bytes, rng: random.Random) -> MutationResult:
    """Swap two sibling TLVs to break assumed field order in a SEQUENCE."""
    context = _tlv_context(apdu)
    if context is None:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_reorder@no_tlv")
    header, data, le, fields = context
    if len(fields) < 2:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_reorder@single_tlv")
    first_index = rng.randrange(len(fields) - 1)
    second_index = first_index + 1
    first = fields[first_index]
    second = fields[second_index]
    reordered = (
        data[: first.tag_start]
        + data[second.tag_start : second.end]
        + data[first.tag_start : first.end]
        + data[second.end :]
    )
    return MutationResult(
        mutated_apdu=_rebuild(header, bytes(reordered), le),
        description=(
            f"tlv_reorder@{first.tag.hex().upper()}<->{second.tag.hex().upper()}"
        ),
    )


def mutate_tlv_long_form_length(apdu: bytes, rng: random.Random) -> MutationResult:
    """Re-encode a short-form length as an over-claiming long-form one."""
    context = _tlv_context(apdu)
    if context is None:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_long_form@no_tlv")
    header, data, le, fields = context
    candidates = [field for field in fields if len(field.length_octets) == 1]
    if len(candidates) == 0:
        return MutationResult(mutated_apdu=bytes(apdu), description="tlv_long_form@no_candidate")
    target = rng.choice(candidates)
    claimed = rng.randint(0x0100, 0xFFFF)
    rewritten = (
        data[: target.value_start - 1]
        + bytes([0x82])
        + claimed.to_bytes(2, "big")
        + data[target.value_start :]
    )
    return MutationResult(
        mutated_apdu=_rebuild(header, bytes(rewritten), le),
        description=(
            f"tlv_long_form@tag={target.tag.hex().upper()},claimed={claimed:04X}"
        ),
    )


MUTATORS: dict[str, Callable[[bytes, random.Random], MutationResult]] = {
    "bit_flip": mutate_bit_flip,
    "length_mangle": mutate_length_mangle,
    "zero_lc": mutate_zero_lc,
    "tag_shuffle": mutate_tag_shuffle,
    "padding_bloat": mutate_padding_bloat,
    "tlv_length_overclaim": mutate_tlv_length_overclaim,
    "tlv_length_underclaim": mutate_tlv_length_underclaim,
    "tlv_truncate": mutate_tlv_truncate,
    "tlv_reorder": mutate_tlv_reorder,
    "tlv_long_form_length": mutate_tlv_long_form_length,
}


def choose_mutator(
    rng: random.Random,
    *,
    enabled_names: tuple[str, ...] | None = None,
) -> Callable[[bytes, random.Random], MutationResult]:
    """Pick a mutator uniformly at random from the enabled set.

    ``enabled_names=None`` means "use every registered mutator", which
    is the default for CLI callers that do not restrict the strategy.
    Explicit subsets are useful for regression sweeps that want to
    isolate a single failure mode (e.g. only ``length_mangle`` to
    confirm a card still accepts case-4 length-drift APDUs after a
    firmware update).
    """
    if enabled_names is None:
        pool = list(MUTATORS.items())
    else:
        pool = [
            (name, func)
            for name, func in MUTATORS.items()
            if name in enabled_names
        ]
    if len(pool) == 0:
        raise ValueError("no mutators enabled")
    _, chosen = rng.choice(pool)
    return chosen
