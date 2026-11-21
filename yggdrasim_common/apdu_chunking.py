# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Block chaining for command APDUs whose data field exceeds 255 bytes.

A short command APDU carries at most 255 data bytes (ISO/IEC 7816-4 one-byte
Lc). STORE DATA and LOAD carry a longer payload by splitting it across a
numbered sequence of commands instead: P1.b8 announces "more blocks" (0) or
"last block" (1) and P2 carries the block number, coded sequentially from '00'
to 'FF' (GPC v2.3.1 §11.6.2.2, Tables 11-57 and 11-89).

The split is by size, not by structure. SGP.22 v3.1 §5.7.2 requires only the
more-blocks bit for the generic ES10x transport command, and §2.5.5 states the
payload is "sent in blocks of 255 bytes for the first blocks and a last block
that MAY be shorter" -- a block boundary therefore falls wherever byte 255
lands, including inside a TLV. LoadBoundProfilePackage is the one caller that
additionally aligns blocks to the BPP's own TLV boundaries (§5.7.6); it keeps
its own splitter and does not use this module.

Only STORE DATA ('E2') and LOAD ('E8') define block chaining, so
:func:`plan_oversized_command` refuses every other instruction rather than
fragmenting a command whose card-side semantics would not survive it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

__all__ = [
    "BLOCK_CHAINED_INSTRUCTIONS",
    "MAX_SHORT_APDU_DATA",
    "ChunkedApdu",
    "cla_for_logical_channel",
    "is_complete_ber_tlv",
    "logical_channel_from_cla",
    "plan_chunked_apdus",
    "plan_oversized_command",
]

#: Largest data field a one-byte Lc can announce (ISO/IEC 7816-4).
MAX_SHORT_APDU_DATA = 0xFF

#: Instructions that define a numbered block sequence in P1/P2.
#: STORE DATA is GPC v2.3.1 §11.11, LOAD is §11.6.
BLOCK_CHAINED_INSTRUCTIONS = frozenset({0xE2, 0xE8})

#: Classes GPC v2.3.1 Table 11-88 allows for STORE DATA, of which SGP.22 v3.1
#: Table 47 uses '80'-'83' and 'C0'-'CF'. A byte outside them is not a command
#: class here, which is what keeps a two-byte BER-TLV tag such as 'BFE2' from
#: being read as a header whose INS happens to be block-chained.
_BLOCK_CHAINED_CLA_RANGES = ((0x80, 0x8F), (0xC0, 0xCF), (0xE0, 0xEF))

#: ES10x transport command defaults (SGP.22 v3.1 §5.7.2, Tables 47 and 48):
#: BER-TLV command data, ISO case 4, '11' for more blocks and '91' for the last.
ES10X_P1_LAST = 0x91


@dataclass(frozen=True)
class ChunkedApdu:
    """One command APDU in a block-chained sequence."""

    index: int
    total: int
    p1: int
    p2: int
    data: bytes
    apdu: bytes

    @property
    def is_last(self) -> bool:
        return self.index + 1 == self.total

    @property
    def apdu_hex(self) -> str:
        return self.apdu.hex().upper()


def logical_channel_from_cla(cla: int) -> int:
    """Return the logical channel a CLA byte selects (TS 102 221 v18.4 §10.1.1)."""
    value = int(cla) & 0xFF
    if value & 0x40:
        return 4 + (value & 0x0F)
    return value & 0x03


def cla_for_logical_channel(channel: int, base: int = 0x80) -> int:
    """Return *base* re-encoded for *channel* (TS 102 221 v18.4 §10.1.1).

    Channels 0-3 sit in b2b1 of the base class; 4-19 use the b7 = 1 form,
    which the same clause codes as '4X'/'CX' rather than '8X'.
    """
    number = int(channel)
    if number < 0 or number > 19:
        raise ValueError(f"Logical channel {number} is outside the range 0..19.")
    root = int(base) & 0xFC
    if number <= 3:
        return root | number
    return (root & 0xB0) | 0x40 | (number - 4)


def plan_chunked_apdus(
    payload: bytes,
    *,
    cla: int = 0x80,
    ins: int = 0xE2,
    p1_last: int = ES10X_P1_LAST,
    p1_more: Optional[int] = None,
    p2_start: int = 0x00,
    chunk_size: int = MAX_SHORT_APDU_DATA,
    le: Optional[int] = None,
) -> tuple[ChunkedApdu, ...]:
    """Split *payload* into a numbered sequence of short command APDUs.

    *p1_more* defaults to *p1_last* with b8 cleared, which is how both
    Table 11-89 (STORE DATA) and Table 11-57 (LOAD) separate an intermediate
    block from the last one; the remaining P1 bits describe the data field and
    are carried unchanged. Block numbers start at *p2_start* and wrap at 'FF'
    (GPC v2.3.1 §11.6.2.2).

    *le* is appended to every block when given, and the block sequence
    deliberately differs from the single-APDU paths on it. Table 11-88 calls
    for Le '00' whenever P1.b1 is set, which is what
    ``GlobalPlatformManager.store_data`` and the STORE DATA wizard do for an
    explicitly given P1; an observed ES10x transfer instead sends P1 '91'
    with no Le at all. Omitting it is safe because SGP.22 v3.1 §5.7.2
    retrieves a response longer than the block through the '61xx' chain
    rather than through Le, so the ES10x callers here pass no *le*. Pass
    ``le=0x00`` if a card ever rejects the shorter framing.
    """
    data = bytes(payload)
    size = int(chunk_size)
    if size < 1 or size > MAX_SHORT_APDU_DATA:
        raise ValueError(
            f"Chunk size {size} is outside the short-APDU range 1..{MAX_SHORT_APDU_DATA}."
        )
    last_p1 = int(p1_last) & 0xFF
    more_p1 = last_p1 & 0x7F
    if p1_more is not None:
        more_p1 = int(p1_more) & 0xFF

    blocks = [data[start : start + size] for start in range(0, len(data), size)]
    if len(blocks) == 0:
        blocks = [b""]

    total = len(blocks)
    planned: list[ChunkedApdu] = []
    for index, block in enumerate(blocks):
        is_last = index + 1 == total
        current_p1 = last_p1 if is_last else more_p1
        current_p2 = (int(p2_start) + index) & 0xFF
        apdu = bytes([int(cla) & 0xFF, int(ins) & 0xFF, current_p1, current_p2, len(block)]) + block
        if le is not None:
            apdu += bytes([int(le) & 0xFF])
        planned.append(
            ChunkedApdu(
                index=index,
                total=total,
                p1=current_p1,
                p2=current_p2,
                data=block,
                apdu=apdu,
            )
        )
    return tuple(planned)


def is_complete_ber_tlv(data: bytes) -> bool:
    """Report whether *data* is exactly one complete BER-TLV object.

    Used to tell an ES10x command payload apart from a command APDU when an
    operator pastes one or the other on the same input line. Multi-byte tags
    and the definite long-form length of ITU-T X.690 §8.1.3 are both accepted;
    an indefinite length is not, because a card command never carries one.
    """
    raw = bytes(data)
    if len(raw) < 2:
        return False
    offset = 1
    if raw[0] & 0x1F == 0x1F:
        while offset < len(raw):
            current = raw[offset]
            offset += 1
            if current & 0x80 == 0:
                break
        else:
            return False
    if offset >= len(raw):
        return False
    length_byte = raw[offset]
    offset += 1
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4:
            return False
        if offset + count > len(raw):
            return False
        length = int.from_bytes(raw[offset : offset + count], "big")
        offset += count
    else:
        length = length_byte
    return offset + length == len(raw)


def plan_oversized_command(
    command: Sequence[int] | bytes,
    *,
    default_cla: int = 0x80,
    default_ins: int = 0xE2,
    default_p1_last: int = ES10X_P1_LAST,
    chunk_size: int = MAX_SHORT_APDU_DATA,
    le: Optional[int] = None,
) -> Optional[tuple[ChunkedApdu, ...]]:
    """Return the block sequence for an over-long input line, or None.

    Three input shapes reach an operator console and all three describe the
    same transfer:

    * a command APDU with an extended Lc, whose data field exceeds 255 bytes;
    * a four-byte header followed by more than 255 raw data bytes, which is
      what a hand-written script line looks like once the payload outgrew Lc;
    * a bare BER-TLV command payload with no header at all, wrapped here as
      STORE DATA on *default_cla*.

    None means the input needs no chunking or defines no block sequence: a
    well-formed short APDU, or any instruction outside
    :data:`BLOCK_CHAINED_INSTRUCTIONS`, which is passed through untouched so
    an extended-length command still reaches a card that declared support for
    one (TS 102 221 v18.4 §10.1.3).
    """
    raw = bytes(command)
    if len(raw) == 0:
        return None

    if len(raw) >= 5:
        cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
        body = raw[4:]
        if ins in BLOCK_CHAINED_INSTRUCTIONS and _is_block_chained_cla(cla):
            payload = _oversized_data_field(body)
            if payload is not None:
                return plan_chunked_apdus(
                    payload,
                    cla=cla,
                    ins=ins,
                    p1_last=p1,
                    p2_start=p2,
                    chunk_size=chunk_size,
                    le=le,
                )

    if len(raw) > MAX_SHORT_APDU_DATA and is_complete_ber_tlv(raw):
        return plan_chunked_apdus(
            raw,
            cla=default_cla,
            ins=default_ins,
            p1_last=default_p1_last,
            chunk_size=chunk_size,
            le=le,
        )
    return None


def _is_block_chained_cla(cla: int) -> bool:
    value = int(cla) & 0xFF
    return any(low <= value <= high for low, high in _BLOCK_CHAINED_CLA_RANGES)


def _oversized_data_field(body: bytes) -> Optional[bytes]:
    """Return the data field of an over-long command body, or None.

    *body* is everything after CLA INS P1 P2. A short Lc that accounts for the
    whole body describes a command that already fits, so it yields None.
    """
    if len(body) <= 1:
        return None
    if body[0] == 0x00 and len(body) >= 3:
        declared = int.from_bytes(body[1:3], "big")
        data = body[3 : 3 + declared]
        if declared > MAX_SHORT_APDU_DATA and len(data) == declared:
            return data
    short_lc = body[0]
    if len(body) in (1 + short_lc, 2 + short_lc) and short_lc != 0:
        return None
    if len(body) > MAX_SHORT_APDU_DATA:
        return body
    return None
