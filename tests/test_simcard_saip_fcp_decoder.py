# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for ``decode_fcp_attributes``.

The adapter routes FCP descriptor parsing through pySim's
``File.from_fileDescriptor`` so the simulator stays aligned with the
upstream SAIP toolchain. These tests pin the contract:

  * ``record_length`` / ``transparent_size`` derivations match
    TS 102 221 §11.1.1.4.3.
  * ``arr`` (securityAttributesReferenced), ``lcsi``, ``fillPattern``,
    ``repeatPattern`` and ``specialFileInformation`` are surfaced.
  * The PRIVATE 7 ``linkPath`` extension is decoded alongside, since
    pySim does not yet handle it.
  * Both dict and tuple-list FCP shapes are accepted (asn1tools
    delivers both depending on which OPTIONAL fields are present).
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_pysim_specs import FcpAttributes, decode_fcp_attributes


def _make_fcp_dict(**overrides) -> dict:
    """Build a representative ``Fcp`` dict (asn1tools-decoded shape)."""
    base = {
        "fileDescriptor": b"\x42\x21\x00\x07",
        "fileID": b"\x6f\x07",
        "lcsi": b"\x05",
    }
    base.update(overrides)
    return base


class TransparentFcpDecoderTests(unittest.TestCase):
    """Cover the ``TR`` path through ``from_fileDescriptor``."""

    def test_transparent_descriptor_yields_TR_file_type(self) -> None:
        fcp = {
            "fileDescriptor": b"\x41\x21",
            "fileID": b"\x6f\x07",
            "efFileSize": b"\x09",
            "lcsi": b"\x05",
        }

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.file_type, "TR")
        self.assertEqual(attrs.structure, "transparent")
        self.assertEqual(attrs.fid, 0x6F07)
        self.assertEqual(attrs.file_size, 9)
        self.assertEqual(attrs.transparent_size, 9)
        self.assertEqual(attrs.record_length, 0)
        self.assertEqual(attrs.lcsi, 0x05)


class LinearFixedFcpDecoderTests(unittest.TestCase):
    """Cover the ``LF`` path -- record_len + nb_rec derivation."""

    def test_linear_fixed_record_len_extracted(self) -> None:
        fcp = {
            "fileDescriptor": b"\x42\x21\x00\x37",
            "fileID": b"\x6f\x06",
            "efFileSize": b"\x04\xf1",
            "lcsi": b"\x05",
        }

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.file_type, "LF")
        self.assertEqual(attrs.structure, "linear-fixed")
        self.assertEqual(attrs.record_length, 0x37)
        self.assertEqual(attrs.fid, 0x6F06)
        # nb_rec = file_size // rec_len = 0x04F1 // 0x37 = 23 records
        self.assertEqual(attrs.nb_rec, 0x04F1 // 0x37)
        self.assertEqual(attrs.file_size, 0x04F1)

    def test_linear_fixed_without_efFileSize_leaves_file_size_unset(self) -> None:
        fcp = {
            "fileDescriptor": b"\x42\x21\x00\x10",
            "fileID": b"\x6f\x3b",
            "lcsi": b"\x05",
        }

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.file_type, "LF")
        self.assertEqual(attrs.record_length, 0x10)
        self.assertEqual(attrs.file_size, None)


class CyclicFcpDecoderTests(unittest.TestCase):
    """Cover the ``CY`` path -- bit 0x40 of fileDescriptorByte."""

    def test_cyclic_descriptor_yields_CY_file_type(self) -> None:
        fcp = {
            "fileDescriptor": b"\x46\x21\x00\x26",
            "fileID": b"\x6f\x80",
            "efFileSize": b"\x02\xf8",
            "lcsi": b"\x05",
        }

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.file_type, "CY")
        self.assertEqual(attrs.structure, "cyclic")
        self.assertEqual(attrs.record_length, 0x26)


class ArrAndLcsiTests(unittest.TestCase):
    """Pin the security-attributes and life-cycle handling."""

    def test_securityAttributesReferenced_preserved_as_bytes(self) -> None:
        fcp = _make_fcp_dict(securityAttributesReferenced=b"\x6f\x06\x02")

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.arr, b"\x6f\x06\x02")

    def test_lcsi_byte_normalized_to_int(self) -> None:
        fcp = _make_fcp_dict(lcsi=b"\x05")

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.lcsi, 0x05)

    def test_lcsi_missing_returns_None(self) -> None:
        fcp = {"fileDescriptor": b"\x42\x21\x00\x10", "fileID": b"\x6f\x06"}

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.lcsi, None)


class ProprietaryEfInfoDecoderTests(unittest.TestCase):
    """Cover ``proprietaryEFInfo`` -- fillPattern / repeatPattern / SPFI."""

    def test_fill_pattern_marks_repeat_false(self) -> None:
        fcp = _make_fcp_dict(
            proprietaryEFInfo={
                "fillPattern": b"\xff\xff\xff",
                "specialFileInformation": b"\x00",
            },
        )

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.fill_pattern, b"\xff\xff\xff")
        self.assertFalse(attrs.fill_pattern_repeat)

    def test_repeat_pattern_marks_repeat_true(self) -> None:
        fcp = _make_fcp_dict(
            proprietaryEFInfo={
                "repeatPattern": b"\xab\xcd",
                "specialFileInformation": b"\x00",
            },
        )

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.fill_pattern, b"\xab\xcd")
        self.assertTrue(attrs.fill_pattern_repeat)

    def test_specialFileInformation_high_update_bit_extracted(self) -> None:
        fcp = _make_fcp_dict(
            proprietaryEFInfo={"specialFileInformation": b"\x80"},
        )

        attrs = decode_fcp_attributes(fcp)

        self.assertTrue(attrs.high_update)
        self.assertFalse(attrs.read_and_update_when_deact)

    def test_specialFileInformation_read_update_deact_bit_extracted(self) -> None:
        fcp = _make_fcp_dict(
            proprietaryEFInfo={"specialFileInformation": b"\x40"},
        )

        attrs = decode_fcp_attributes(fcp)

        self.assertFalse(attrs.high_update)
        self.assertTrue(attrs.read_and_update_when_deact)


class LinkPathDecoderTests(unittest.TestCase):
    """Pin the PRIVATE 7 ``linkPath`` extension parser (SAIP §8.3.5)."""

    def test_two_byte_link_path_decoded(self) -> None:
        fcp = _make_fcp_dict(linkPath=b"\x7f\x20\x6f\x07")

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.link_path, ("7F20", "6F07"))

    def test_empty_link_path_returns_empty_tuple(self) -> None:
        fcp = _make_fcp_dict(linkPath=b"")

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.link_path, ())

    def test_odd_length_link_path_returns_empty_tuple(self) -> None:
        fcp = _make_fcp_dict(linkPath=b"\x7f\x20\x6f")

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.link_path, ())

    def test_missing_link_path_returns_empty_tuple(self) -> None:
        fcp = _make_fcp_dict()

        attrs = decode_fcp_attributes(fcp)

        self.assertEqual(attrs.link_path, ())


class InputCoercionTests(unittest.TestCase):
    """Both dict and tuple-list FCP shapes must decode to the same result."""

    def test_tuple_list_decodes_same_as_dict(self) -> None:
        fcp_dict = {
            "fileDescriptor": b"\x42\x21\x00\x10",
            "fileID": b"\x6f\x3b",
            "lcsi": b"\x05",
        }
        fcp_tuples = [
            ("fileDescriptor", b"\x42\x21\x00\x10"),
            ("fileID", b"\x6f\x3b"),
            ("lcsi", b"\x05"),
        ]

        from_dict = decode_fcp_attributes(fcp_dict)
        from_tuples = decode_fcp_attributes(fcp_tuples)

        self.assertEqual(from_dict, from_tuples)

    def test_none_input_returns_default_attributes(self) -> None:
        attrs = decode_fcp_attributes(None)

        self.assertIsInstance(attrs, FcpAttributes)
        self.assertEqual(attrs.file_type, "")
        self.assertEqual(attrs.structure, "")
        self.assertEqual(attrs.fid, None)
        self.assertEqual(attrs.link_path, ())

    def test_unrecognised_input_shape_returns_default_attributes(self) -> None:
        attrs = decode_fcp_attributes("not-a-dict")

        self.assertIsInstance(attrs, FcpAttributes)
        self.assertEqual(attrs.file_type, "")


class FidHexHelperTests(unittest.TestCase):
    """The ``fid_hex`` accessor must zero-pad to 4 chars."""

    def test_short_fid_padded(self) -> None:
        attrs = FcpAttributes(fid=0x07)
        self.assertEqual(attrs.fid_hex, "0007")

    def test_full_fid_uppercase(self) -> None:
        attrs = FcpAttributes(fid=0x6F07)
        self.assertEqual(attrs.fid_hex, "6F07")

    def test_no_fid_returns_empty_string(self) -> None:
        attrs = FcpAttributes(fid=None)
        self.assertEqual(attrs.fid_hex, "")


if __name__ == "__main__":
    unittest.main()
