# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""BSP segment size of a Bound Profile Package (SGP.22 v3.1 §2.5.3).

A segment is at most 1020 bytes with its tag, length field and MAC. An
encrypted segment therefore carries 1007 bytes of plaintext: the '80'
padding takes at least one byte of the 1008 the ciphertext may have.
"""

from __future__ import annotations

from typing import Any

from SCP11.shared.ber_tlv import read_ber_tlv

# SGP.22 v3.1 §2.5.3 Protected Profile Package: tag, length field and MAC included.
MAX_SEGMENT_SIZE = 1020
# SGP.22 v3.1 §2.5.4 Bound Profile Package: its sequences and the segment tag each holds.
_SEGMENT_SEQUENCES = {b"\xA0": b"\x87", b"\xA1": b"\x88", b"\xA2": b"\x87", b"\xA3": b"\x86"}
_BOUND_PROFILE_PACKAGE = bytes.fromhex("BF36")


class BspSegmentTooLong(RuntimeError):
    """A Bound Profile Package holds a segment above the size an eUICC has to accept."""


def encrypted_payload_limit(bsp: Any) -> int:
    """Plaintext bytes one encrypted segment of *bsp* carries."""
    declared = getattr(bsp, "max_encrypted_payload_size", None)
    if declared is not None:
        return int(declared)
    block = int(bsp.c_algo.blocksize)
    return int(bsp.max_payload_size) // block * block - 1


def install_encrypted_segment_limit(bsp_class: Any) -> bool:
    """Make a pySim ``BspInstance`` without the limit cut encrypted plaintext at 1007 bytes.

    pySim cut it at 1008, which pads to 1024 and gives a 1036-byte segment
    (``upstream_patches/osmocom-pysim-bsp-segment-size``). A pySim that
    declares ``max_encrypted_payload_size`` is left alone, so this stops
    doing anything once the pinned pySim carries the fix. Returns whether
    the class was changed; ``check_segment_sizes`` is the proof of the effect.
    """
    probe = bsp_class(bytes(16), bytes(16), bytes(16))
    if getattr(probe, "max_encrypted_payload_size", None) is not None:
        return False
    if getattr(bsp_class.encrypt_and_mac, "_yggdrasim_segment_limit", False):
        return True

    def encrypt_and_mac(self: Any, tag: int, plaintext: bytes) -> list[bytes]:
        limit = encrypted_payload_limit(self)
        remainder = bytes(plaintext)
        segments: list[bytes] = []
        while len(remainder) > 0:
            segments.append(self.encrypt_and_mac_one(tag, remainder[:limit]))
            remainder = remainder[limit:]
        return segments

    setattr(encrypt_and_mac, "_yggdrasim_segment_limit", True)
    bsp_class.encrypt_and_mac = encrypt_and_mac
    return True


def check_segment_sizes(bound_profile_package: bytes) -> int:
    """Refuse a BPP with a segment above 1020 bytes; returns the number of segments read."""
    tag, value, _raw, _next = read_ber_tlv(bytes(bound_profile_package), 0)
    if tag != _BOUND_PROFILE_PACKAGE:
        raise ValueError("Not a Bound Profile Package: the outer tag is not 'BF36'.")
    count = 0
    offset = 0
    while offset < len(value):
        sequence_tag, members, _raw, offset = read_ber_tlv(value, offset)
        segment_tag = _SEGMENT_SEQUENCES.get(sequence_tag)
        if segment_tag is None:
            continue
        inner = 0
        while inner < len(members):
            member_tag, _value, raw, inner = read_ber_tlv(members, inner)
            if member_tag != segment_tag:
                continue
            count += 1
            if len(raw) > MAX_SEGMENT_SIZE:
                raise BspSegmentTooLong(
                    f"Bound Profile Package segment {count} (tag '{member_tag.hex().upper()}' in "
                    f"'{sequence_tag.hex().upper()}') is {len(raw)} bytes; SGP.22 allows {MAX_SEGMENT_SIZE}. "
                    "The pySim in use cuts encrypted segments too long: install the pySim "
                    "pyproject.toml pins (hampushellsberg-dev/pysim)."
                )
    return count
