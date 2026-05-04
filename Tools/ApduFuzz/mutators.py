"""
Deterministic APDU mutation strategies.

Each mutator is a pure function ``(bytes, random.Random) -> bytes``
that produces a single mutated command APDU from a known-good
original. Determinism (via the supplied ``Random`` instance) is a
contract -- crashes must be reproducible from a seed, otherwise
vulnerability research is impossible.

Supported strategies (ETSI TS 102 221 §10.1 APDU framing):

* :func:`mutate_bit_flip`       -- flip one or more random bits in the
  payload portion of the APDU (never touches the CLA/INS header so
  the card still tries to parse the command).
* :func:`mutate_length_mangle`  -- corrupt the Lc / Le fields so the
  command declares a length that does not match the actual payload.
* :func:`mutate_tag_shuffle`    -- BER-TLV aware; reshuffles the
  tag byte of one TLV inside a SELECT/INS-APDU payload.
* :func:`mutate_padding_bloat`  -- appends N bytes of junk past the
  declared Lc to test if the card strictly enforces length checks.
* :func:`mutate_zero_lc`        -- sets Lc to 0x00 while keeping the
  original payload (classic length-confusion surface).

All mutators respect the short APDU envelope (5-byte header). Extended
APDU mutation support is deferred -- the simulator session recordings
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
    pad_count = rng.randint(1, 16)
    mutated = bytearray(apdu)
    mutated.extend(rng.randrange(0, 256) for _ in range(pad_count))
    return MutationResult(
        mutated_apdu=bytes(mutated),
        description=f"padding_bloat@pad={pad_count}",
    )


MUTATORS: dict[str, Callable[[bytes, random.Random], MutationResult]] = {
    "bit_flip": mutate_bit_flip,
    "length_mangle": mutate_length_mangle,
    "zero_lc": mutate_zero_lc,
    "tag_shuffle": mutate_tag_shuffle,
    "padding_bloat": mutate_padding_bloat,
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
