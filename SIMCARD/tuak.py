"""
TUAK algorithm implementation for the simulated USIM.

Reference
---------
- 3GPP TS 35.231: TUAK algorithm specification.
- 3GPP TS 35.232: TUAK implementers' test data (test sets).
- 3GPP TS 35.233: TUAK design conformance test data.

Notes
-----
The TUAK state layout, INSTANCE encoding, ALGONAME ("TUAK1.0"), byte reversal
and domain-separation padding ("1F ... 80") match the reference described in
TS 35.231 and the public CryptoMobile Python reference (mitshell/CryptoMobile).

All inputs are applied in "TUAK byte order" which byte-reverses each field
(TOPc, RAND, AMF, SQN, K) before it is placed into the 200-byte Keccak state.
Outputs are byte-reversed back to network order before they are returned.

Simulator Activation
--------------------
The PE-AKAParameter plumbing feeds ``algorithmID=tuak(2)`` profiles into
``SimProfileAuthConfig``. The ``INTERNAL AUTHENTICATE`` dispatch activates TUAK
when ``YGGDRASIM_ENABLE_TUAK`` is set truthy. This lets operators cross-check
the pure-Python reference against hardware and network-side AuC results before
trusting it for network authentication over the HIL bridge.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_KECCAK_ROTATION_OFFSETS = (
    ( 0, 36,  3, 41, 18),
    ( 1, 44, 10, 45,  2),
    (62,  6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39,  8, 14),
)

_LANE_MASK = 0xFFFFFFFFFFFFFFFF

_ALGONAME = b"TUAK1.0"

_PAD_START_OFFSET = 96
_PAD_END_OFFSET = 135


def _rotate_left_64(value: int, offset: int) -> int:
    offset = offset % 64
    masked = value & _LANE_MASK
    return ((masked << offset) | (masked >> (64 - offset))) & _LANE_MASK


def keccak_f_1600(state_bytes: bytes) -> bytes:
    data = bytes(state_bytes or b"")
    if len(data) != 200:
        raise ValueError("Keccak-f[1600] requires a 200-byte state.")
    lanes = [[0] * 5 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            offset = (y * 5 + x) * 8
            lanes[x][y] = int.from_bytes(data[offset:offset + 8], "little")

    for round_index in range(24):
        column = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        theta_mask = [column[(x - 1) % 5] ^ _rotate_left_64(column[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] = (lanes[x][y] ^ theta_mask[x]) & _LANE_MASK

        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                rotated[new_x][new_y] = _rotate_left_64(lanes[x][y], _KECCAK_ROTATION_OFFSETS[x][y])
        lanes = rotated

        for y in range(5):
            row = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = (row[x] ^ ((~row[(x + 1) % 5] & _LANE_MASK) & row[(x + 2) % 5])) & _LANE_MASK

        lanes[0][0] = (lanes[0][0] ^ _KECCAK_ROUND_CONSTANTS[round_index]) & _LANE_MASK

    output = bytearray(200)
    for y in range(5):
        for x in range(5):
            offset = (y * 5 + x) * 8
            output[offset:offset + 8] = lanes[x][y].to_bytes(8, "little")
    return bytes(output)


@dataclass(frozen=True)
class TuakVectors:
    mac_a: bytes
    mac_s: bytes
    res: bytes
    ck: bytes
    ik: bytes
    ak: bytes
    ak_star: bytes


def _apply_keccak_iterations(state: bytes, iterations: int) -> bytes:
    current = state
    for _ in range(max(1, int(iterations or 1))):
        current = keccak_f_1600(current)
    return current


def _build_state(
    *,
    topc: bytes,
    instance: int,
    key: bytes,
    rand: bytes = b"\x00" * 16,
    amf: bytes = b"\x00\x00",
    sqn: bytes = b"\x00" * 6,
    include_amf_sqn: bool = True,
) -> bytes:
    topc_bytes = bytes(topc or b"")
    key_bytes = bytes(key or b"")
    if len(topc_bytes) != 32:
        raise ValueError("TUAK requires a 32-byte TOP/TOPc.")
    if len(key_bytes) not in (16, 32):
        raise ValueError("TUAK requires a 128-bit or 256-bit key.")

    state = bytearray(200)
    state[0:32] = topc_bytes[::-1]
    state[32] = int(instance) & 0xFF
    state[33:40] = _ALGONAME[::-1]
    state[40:56] = bytes(rand or b"\x00" * 16)[::-1]
    if include_amf_sqn:
        state[56:58] = bytes(amf or b"\x00\x00")[::-1]
        state[58:64] = bytes(sqn or b"\x00" * 6)[::-1]
    # When AMF/SQN are not part of the inputs (f2/f3/f4/f5/f5* and TOPc), the
    # spec leaves 8 zero bytes at positions [56..63].
    if len(key_bytes) == 32:
        state[64:96] = key_bytes[::-1]
    else:
        state[64:80] = key_bytes[::-1]
    state[_PAD_START_OFFSET] = 0x1F
    state[_PAD_END_OFFSET] = 0x80
    return bytes(state)


def _validate_tuak_inputs(
    *,
    topc: bytes,
    rand: bytes | None,
    sqn: bytes | None,
    amf: bytes | None,
    key: bytes,
) -> None:
    if len(bytes(topc or b"")) != 32:
        raise ValueError("TUAK requires a 32-byte TOPc.")
    if rand is not None and len(bytes(rand)) != 16:
        raise ValueError("TUAK requires a 16-byte RAND.")
    if sqn is not None and len(bytes(sqn)) != 6:
        raise ValueError("TUAK requires a 6-byte SQN.")
    if amf is not None and len(bytes(amf)) != 2:
        raise ValueError("TUAK requires a 2-byte AMF.")
    if len(bytes(key or b"")) not in (16, 32):
        raise ValueError("TUAK key must be 128 or 256 bits.")


def derive_topc(top: bytes, key: bytes, *, number_of_keccak: int = 1) -> bytes:
    """Compute TOPc = msb256 of Keccak-f[1600]^n(TUAK_state with INSTANCE)."""
    _validate_tuak_inputs(topc=top, rand=None, sqn=None, amf=None, key=key)
    key_bytes = bytes(key or b"")
    instance = 0x00 if len(key_bytes) == 16 else 0x01
    state = _build_state(
        topc=bytes(top),
        instance=instance,
        key=key_bytes,
        include_amf_sqn=False,
    )
    state = _apply_keccak_iterations(state, number_of_keccak)
    return state[:32][::-1]


def _f1_instance(*, key_len: int, mac_len_bytes: int, star: bool) -> int:
    if mac_len_bytes == 8:
        instance = 0x08
    elif mac_len_bytes == 16:
        instance = 0x10
    elif mac_len_bytes == 32:
        instance = 0x20
    else:
        raise ValueError("MAC length must be 64, 128 or 256 bits.")
    if star:
        instance |= 0x80
    if key_len == 32:
        instance |= 0x01
    return instance


def _f2345_instance(*, key_len: int, res_len_bytes: int, ck_len_bytes: int, ik_len_bytes: int) -> int:
    if res_len_bytes == 4:
        instance = 0x40
    elif res_len_bytes == 8:
        instance = 0x48
    elif res_len_bytes == 16:
        instance = 0x50
    elif res_len_bytes == 32:
        instance = 0x60
    else:
        raise ValueError("RES length must be 32, 64, 128 or 256 bits.")
    if ck_len_bytes == 32:
        instance |= 0x04
    if ik_len_bytes == 32:
        instance |= 0x02
    if key_len == 32:
        instance |= 0x01
    return instance


def _f5star_instance(*, key_len: int) -> int:
    instance = 0xC0
    if key_len == 32:
        instance |= 0x01
    return instance


def tuak_f1(
    *,
    topc: bytes,
    rand: bytes,
    sqn: bytes,
    amf: bytes,
    key: bytes,
    number_of_keccak: int = 1,
    mac_size_bytes: int = 8,
) -> bytes:
    _validate_tuak_inputs(topc=topc, rand=rand, sqn=sqn, amf=amf, key=key)
    instance = _f1_instance(key_len=len(bytes(key)), mac_len_bytes=int(mac_size_bytes), star=False)
    state = _build_state(
        topc=bytes(topc),
        instance=instance,
        key=bytes(key),
        rand=bytes(rand),
        amf=bytes(amf),
        sqn=bytes(sqn),
        include_amf_sqn=True,
    )
    state = _apply_keccak_iterations(state, number_of_keccak)
    return state[:int(mac_size_bytes)][::-1]


def tuak_f1_star(
    *,
    topc: bytes,
    rand: bytes,
    sqn: bytes,
    amf: bytes,
    key: bytes,
    number_of_keccak: int = 1,
    mac_size_bytes: int = 8,
) -> bytes:
    _validate_tuak_inputs(topc=topc, rand=rand, sqn=sqn, amf=amf, key=key)
    instance = _f1_instance(key_len=len(bytes(key)), mac_len_bytes=int(mac_size_bytes), star=True)
    state = _build_state(
        topc=bytes(topc),
        instance=instance,
        key=bytes(key),
        rand=bytes(rand),
        amf=bytes(amf),
        sqn=bytes(sqn),
        include_amf_sqn=True,
    )
    state = _apply_keccak_iterations(state, number_of_keccak)
    return state[:int(mac_size_bytes)][::-1]


def tuak_f2345(
    *,
    topc: bytes,
    rand: bytes,
    key: bytes,
    number_of_keccak: int = 1,
    res_size_bytes: int = 8,
    ck_size_bytes: int = 16,
    ik_size_bytes: int = 16,
) -> tuple[bytes, bytes, bytes, bytes]:
    _validate_tuak_inputs(topc=topc, rand=rand, sqn=None, amf=None, key=key)
    instance = _f2345_instance(
        key_len=len(bytes(key)),
        res_len_bytes=int(res_size_bytes),
        ck_len_bytes=int(ck_size_bytes),
        ik_len_bytes=int(ik_size_bytes),
    )
    state = _build_state(
        topc=bytes(topc),
        instance=instance,
        key=bytes(key),
        rand=bytes(rand),
        include_amf_sqn=False,
    )
    state = _apply_keccak_iterations(state, number_of_keccak)
    res = state[:int(res_size_bytes)][::-1]
    ck = state[32:32 + int(ck_size_bytes)][::-1]
    ik = state[64:64 + int(ik_size_bytes)][::-1]
    ak = state[96:102][::-1]
    return res, ck, ik, ak


def tuak_f5_star(
    *,
    topc: bytes,
    rand: bytes,
    key: bytes,
    number_of_keccak: int = 1,
) -> bytes:
    _validate_tuak_inputs(topc=topc, rand=rand, sqn=None, amf=None, key=key)
    instance = _f5star_instance(key_len=len(bytes(key)))
    state = _build_state(
        topc=bytes(topc),
        instance=instance,
        key=bytes(key),
        rand=bytes(rand),
        include_amf_sqn=False,
    )
    state = _apply_keccak_iterations(state, number_of_keccak)
    return state[96:102][::-1]


def tuak_vectors(
    *,
    topc: bytes,
    rand: bytes,
    sqn: bytes,
    amf: bytes,
    key: bytes,
    number_of_keccak: int = 1,
    res_size_bytes: int = 8,
    mac_size_bytes: int = 8,
    ck_ik_size_bytes: int = 16,
) -> TuakVectors:
    _validate_tuak_inputs(topc=topc, rand=rand, sqn=sqn, amf=amf, key=key)
    mac_a = tuak_f1(
        topc=topc,
        rand=rand,
        sqn=sqn,
        amf=amf,
        key=key,
        number_of_keccak=number_of_keccak,
        mac_size_bytes=mac_size_bytes,
    )
    mac_s = tuak_f1_star(
        topc=topc,
        rand=rand,
        sqn=sqn,
        amf=amf,
        key=key,
        number_of_keccak=number_of_keccak,
        mac_size_bytes=mac_size_bytes,
    )
    res, ck, ik, ak = tuak_f2345(
        topc=topc,
        rand=rand,
        key=key,
        number_of_keccak=number_of_keccak,
        res_size_bytes=res_size_bytes,
        ck_size_bytes=ck_ik_size_bytes,
        ik_size_bytes=ck_ik_size_bytes,
    )
    ak_star = tuak_f5_star(
        topc=topc,
        rand=rand,
        key=key,
        number_of_keccak=number_of_keccak,
    )
    return TuakVectors(
        mac_a=mac_a,
        mac_s=mac_s,
        res=res,
        ck=ck,
        ik=ik,
        ak=ak,
        ak_star=ak_star,
    )


def tuak_runtime_enabled() -> bool:
    value = str(os.environ.get("YGGDRASIM_ENABLE_TUAK", "") or "").strip().lower()
    return value in ("1", "true", "yes", "on")
