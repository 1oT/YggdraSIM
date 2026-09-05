# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Additional response data in a PoR, per ETSI TS 102 226 table 5.1.

The table orders the field as: one octet counting the commands the script
executed, then the two status octets of the last one, then its response
data. Reading the status off the tail instead only agrees when the last
command returned no data.
"""

from __future__ import annotations

import unittest

from SCP80 import transport as scp80_transport

#: A PoR for a one-command script that ended '90 00' and returned nothing.
POR_SINGLE = bytes.fromhex(
    "D02E810301130082028183050086028001"
    "8B1D410005811250F341F613"
    "027100000E0AB00001000000FFFF0000019000"
)


def _with_command_count(por: bytes, count: int) -> bytes:
    """Return the same PoR reporting a different number of commands.

    Only the count octet changes, so every length in the message stays
    valid.
    """

    patched = bytearray(por)
    patched[-3] = count
    return bytes(patched)


class PorAdditionalResponseData(unittest.TestCase):
    def _decode(self, por: bytes) -> dict:
        decoded = scp80_transport.Transport.decode_por(por, 0x9000)
        self.assertTrue(decoded["valid"], decoded.get("error"))
        return decoded

    def test_status_word_is_read_from_the_head_of_the_field(self) -> None:
        decoded = self._decode(POR_SINGLE)
        self.assertEqual(decoded["command_count"], 1)
        self.assertEqual(decoded["command_sw"], "9000")
        self.assertEqual(decoded["command_response"], "")

    def test_status_word_is_reported_for_a_multi_command_script(self) -> None:
        """The table gives the status of the last command whatever the
        count; it used to be reported only when exactly one ran."""

        for count in (2, 5, 0xFF):
            with self.subTest(commands=count):
                decoded = self._decode(_with_command_count(POR_SINGLE, count))
                self.assertEqual(decoded["command_count"], count)
                self.assertEqual(decoded["command_sw"], "9000")

    def test_an_error_status_is_reported_the_same_way(self) -> None:
        patched = bytearray(POR_SINGLE)
        patched[-2:] = bytes.fromhex("6A82")
        decoded = self._decode(bytes(patched))
        self.assertEqual(decoded["command_sw"], "6A82")


if __name__ == "__main__":
    unittest.main()
