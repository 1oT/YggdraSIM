# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""asn1tools fixes the SAIP and card decoders depend on.

Each installer patches the imported asn1tools module only, is idempotent,
checks its own effect and changes nothing once the pinned asn1tools carries
the fix. Evidence and the upstream patch are in
``upstream_patches/eerimoq-asn1tools-oid-arc2/``.
"""

from __future__ import annotations

import importlib
from functools import wraps
from typing import Any

_OID_ARC2_MARKER = "_yggdrasim_oid_arc2_decoding"

# Rec. ITU-T X.690 (02/2021) §8.19.4: the first subidentifier is X*40 + Y,
# and arcs 0 and 1 have at most 39 sub-arcs, so every value from 80 up
# belongs to arc 2, whose second component is unbounded.
_ARC2_FIRST_SUBIDENTIFIER = 80
_ARC2_PROBE = "2.999.1"


class Asn1ObjectIdentifierDecodeMismatch(RuntimeError):
    """The OBJECT IDENTIFIER decode fix did not take on this asn1tools."""


def install_object_identifier_arc2_decoding() -> bool:
    """Decode an OBJECT IDENTIFIER under arc 2 with a second arc above 39.

    ``asn1tools.codecs.ber.decode_object_identifier`` splits the first
    subidentifier as ``value // 40, value % 40`` for every value, so
    ``2.40.1`` reads back as ``3.0.1`` and ``2.999.1`` as ``26.39.1``, while
    the encoder writes X.690's ``X*40 + Y`` correctly. The split is right
    for arcs 0 and 1 and for arc 2 up to ``2.39``; an identifier under
    ``2.40`` and above (``2.999`` is the X.660 example arc) comes back
    rewritten, which a PE-NonStandard ``issuerID`` may carry.

    The wrapper calls upstream and, for a first subidentifier from 80 up,
    replaces the first two components with ``2`` and ``value - 80``; for a
    fixed asn1tools that is what upstream returned already. The PER and OER
    codecs import the function by name and get the wrapper too. A probe
    decode of ``2.999.1`` raises :class:`Asn1ObjectIdentifierDecodeMismatch`
    when the result is still wrong.

    The fix holds in a process once a SAIP surface has installed it (the
    SAIP codec and the card engine do); the SCP11 shells compile their RSP
    schemas without it.

    Returns ``True`` when this call installed the wrapper and ``False`` when
    it was already active.
    """
    ber = importlib.import_module("asn1tools.codecs.ber")
    current = ber.decode_object_identifier
    if getattr(current, _OID_ARC2_MARKER, False):
        return False

    @wraps(current)
    def _decode_object_identifier(data: Any, offset: int, end_offset: int) -> str:
        text = current(data, offset, end_offset)
        first, _next_offset = ber.decode_object_identifier_subidentifier(data, offset)
        if first < _ARC2_FIRST_SUBIDENTIFIER:
            return text
        rest = text.split(".")[2:]
        return ".".join(["2", str(first - _ARC2_FIRST_SUBIDENTIFIER)] + rest)

    setattr(_decode_object_identifier, _OID_ARC2_MARKER, True)
    ber.decode_object_identifier = _decode_object_identifier
    for name in ("asn1tools.codecs.oer", "asn1tools.codecs.per"):
        module = importlib.import_module(name)
        if getattr(module, "decode_object_identifier", None) is current:
            module.decode_object_identifier = _decode_object_identifier

    probe = bytearray(ber.encode_object_identifier(_ARC2_PROBE))
    decoded = ber.decode_object_identifier(probe, 0, len(probe))
    if decoded != _ARC2_PROBE:
        raise Asn1ObjectIdentifierDecodeMismatch(
            f"{_ARC2_PROBE} still decodes as {decoded}; the fix in "
            "upstream_patches/eerimoq-asn1tools-oid-arc2/ no longer models this asn1tools."
        )
    return True


__all__ = [
    "Asn1ObjectIdentifierDecodeMismatch",
    "install_object_identifier_arc2_decoding",
]
