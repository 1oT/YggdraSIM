# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""OBJECT IDENTIFIER decoding under arc 2 (``yggdrasim_common.asn1tools_compat``).

Rec. ITU-T X.690 (02/2021) §8.19.4 packs the first two components as
X*40 + Y; arcs 0 and 1 have at most 39 sub-arcs, so a first subidentifier
from 80 up is arc 2 with Y = value - 80. asn1tools decodes it as
``value // 40, value % 40`` (``upstream_patches/eerimoq-asn1tools-oid-arc2/``).
"""

from __future__ import annotations

import importlib
import inspect
import unittest

from yggdrasim_common.asn1tools_compat import install_object_identifier_arc2_decoding


def _roundtrip(oid: str) -> str:
    ber = importlib.import_module("asn1tools.codecs.ber")
    encoded = bytearray(ber.encode_object_identifier(oid))
    return ber.decode_object_identifier(encoded, 0, len(encoded))


class ObjectIdentifierArc2DecodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        install_object_identifier_arc2_decoding()

    def test_installer_is_idempotent(self) -> None:
        ber = importlib.import_module("asn1tools.codecs.ber")
        installed = ber.decode_object_identifier
        self.assertFalse(install_object_identifier_arc2_decoding())
        self.assertIs(ber.decode_object_identifier, installed)

    def test_identifiers_on_both_sides_of_the_arc_2_boundary_round_trip(self) -> None:
        for oid in ("0.4.0.127", "1.3.6.1.4.1.0", "2.23.143.1.2.1", "2.39.1", "2.40.1", "2.999.1", "2.25.1"):
            with self.subTest(oid=oid):
                self.assertEqual(_roundtrip(oid), oid)

    def test_the_per_and_oer_codecs_use_the_same_decoder(self) -> None:
        ber = importlib.import_module("asn1tools.codecs.ber")
        for name in ("asn1tools.codecs.oer", "asn1tools.codecs.per"):
            with self.subTest(module=name):
                module = importlib.import_module(name)
                self.assertIs(module.decode_object_identifier, ber.decode_object_identifier)

    def test_a_compiled_der_module_decodes_arc_2(self) -> None:
        import asn1tools

        spec = asn1tools.compile_string(
            "T DEFINITIONS ::= BEGIN O ::= OBJECT IDENTIFIER END", "der",
        )
        self.assertEqual(spec.decode("O", spec.encode("O", "2.999.1")), "2.999.1")

    def test_upstream_still_needs_the_fix(self) -> None:
        """Pin the upstream gap so the fix cannot outlive it unnoticed."""
        ber = importlib.import_module("asn1tools.codecs.ber")
        upstream = inspect.unwrap(ber.decode_object_identifier)
        encoded = bytearray(ber.encode_object_identifier("2.999.1"))
        self.assertEqual(
            upstream(encoded, 0, len(encoded)),
            "26.39.1",
            "asn1tools now decodes arc 2 itself: delete "
            "yggdrasim_common/asn1tools_compat.py::install_object_identifier_arc2_decoding "
            "and upstream_patches/eerimoq-asn1tools-oid-arc2/",
        )


if __name__ == "__main__":
    unittest.main()
