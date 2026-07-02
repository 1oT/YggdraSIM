# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SAIP placeholder transformation functions.

Covers ``SwapNibbles(NAME)`` and ``EncodeEfImsi(NAME)`` inside hex
templates with the brace and bracket placeholder styles. Both
transformations are grounded in ETSI TS 102 221 §13.2 (BCD / nibble
swap for EF.ICCID) and 3GPP TS 31.102 §4.2.2 (EF.IMSI body coding).
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_json_codec import TokenExpansionContext


class SwapNibblesTransformTests(unittest.TestCase):
    """Byte-wise nibble swap: 8949...0F → 9894...F0 (ETSI TS 102 221 §13.2 BCD)."""

    def test_bracket_form_swaps_nibbles(self) -> None:
        ctx = TokenExpansionContext(
            defs={"ICCID": {"hex": "8949001304080000016F"}},
            style="bracket",
        )
        out = ctx.expand_mixed_hex("[SwapNibbles(ICCID)]").hex().upper()
        self.assertEqual(out, "989400314080000010F6")

    def test_brace_form_swaps_nibbles(self) -> None:
        ctx = TokenExpansionContext(
            defs={"ICCID": {"hex": "8949001304080000016F"}},
            style="brace",
        )
        out = ctx.expand_mixed_hex("{SwapNibbles(ICCID)}").hex().upper()
        self.assertEqual(out, "989400314080000010F6")

    def test_transform_composes_with_literal_hex(self) -> None:
        ctx = TokenExpansionContext(
            defs={"X": {"hex": "12"}},
            style="bracket",
        )
        out = ctx.expand_mixed_hex("AB[SwapNibbles(X)]CD").hex().upper()
        self.assertEqual(out, "AB21CD")


class EncodeEfImsiTransformTests(unittest.TestCase):
    """3GPP TS 31.102 §4.2.2 EF.IMSI encoding via the ``EncodeEfImsi`` transform."""

    def test_encode_ef_imsi_ascii_15_digit(self) -> None:
        ctx = TokenExpansionContext(
            # ASCII bytes for "001010123456789" (15 digits — odd; parity nibble 0x9).
            defs={"IMSI": {"hex": "303031303130313233343536373839"}},
            style="bracket",
        )
        out = ctx.expand_mixed_hex("[EncodeEfImsi(IMSI)]").hex().upper()
        # 15-digit IMSI → length 0x08, byte 2 = (digit1<<4)|parity = 0x09,
        # remaining 14 digits → 7 nibble-swapped bytes.
        self.assertEqual(out, "080910101032547698")

    def test_encode_ef_imsi_ascii_14_digit_pads_with_f(self) -> None:
        ctx = TokenExpansionContext(
            # ASCII bytes for "00101012345678" (14 digits — even; parity nibble 0x1).
            defs={"IMSI": {"hex": "3030313031303132333435363738"}},
            style="bracket",
        )
        out = ctx.expand_mixed_hex("[EncodeEfImsi(IMSI)]").hex().upper()
        # 14-digit IMSI → byte 2 = (digit1<<4)|0x1 = 0x01, last byte gets the
        # F filler nibble in the high position after nibble swap (8F → F8).
        self.assertEqual(out, "0801101010325476F8")

    def test_encode_ef_imsi_rejects_oversized_input(self) -> None:
        ctx = TokenExpansionContext(
            defs={"IMSI": {"hex": "303132333435363738393031323334353637"}},
            style="bracket",
        )
        with self.assertRaises(ValueError):
            ctx.expand_mixed_hex("[EncodeEfImsi(IMSI)]")


class TransformedLengthCompanionTests(unittest.TestCase):
    """``[#Func(NAME)]`` emits the length of the transformed bytes."""

    def test_length_companion_tracks_encode_ef_imsi(self) -> None:
        ctx = TokenExpansionContext(
            defs={"IMSI": {"hex": "303031303130313233343536373839"}},
            style="bracket",
        )
        out = ctx.expand_mixed_hex("[#EncodeEfImsi(IMSI)][EncodeEfImsi(IMSI)]")
        # 9-byte body (length 0x08 + 8 payload octets) → companion = 0x09.
        self.assertEqual(out[0], 9)
        self.assertEqual(out[1:].hex().upper(), "080910101032547698")

    def test_unknown_transform_raises_value_error(self) -> None:
        ctx = TokenExpansionContext(
            defs={"X": {"hex": "01"}},
            style="bracket",
        )
        with self.assertRaises(ValueError):
            ctx.expand_mixed_hex("[Unknown(X)]")


if __name__ == "__main__":
    unittest.main()
