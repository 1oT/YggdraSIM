# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Key Type coding, pinned to GlobalPlatform Card Specification 2.3.1.

SAIP defers to table 11-16 for key types, and the byte reaches the card in
the PUT KEY control reference template, so a wrong value installs a key
the card will interpret as a different algorithm. The strings that reach
the lookup are pySim's KeyType enum spellings, so the mapping is checked
against that enum rather than against a copy of the table kept here.
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_profile import _GP_KEY_TYPE_STRING_TO_BYTE, _key_type_string_to_byte

try:
    from pySim.global_platform import KeyType as _PYSIM_KEY_TYPE
except ImportError:  # pragma: no cover - exercised only without pySim
    _PYSIM_KEY_TYPE = None

#: pySim reuses one Enum for key types and for unrelated single-byte
#: codings (SD privileges, life-cycle states). Only the key types belong
#: to table 11-16.
_NOT_KEY_TYPES = frozenset({
    "isd", "app_or_ssd", "isd_and_assoc_apps",
    "loaded", "installed", "selectable", "personalized", "locked", "tag",
})


class GpKeyTypeCoding(unittest.TestCase):
    #: Values read from table 11-16 rather than from the implementation.
    SPEC_VALUES = {
        "des": 0x80,
        "tls_psk": 0x85,
        "aes": 0x88,
        "hmac_sha1": 0x90,
        "hmac_sha1_160": 0x91,
        "rsa_public_exponent_e_cleartex": 0xA0,
        "rsa_chines_remainder_dqi": 0xA8,
        "ecc_public_key": 0xB0,
        "ecc_private_key": 0xB1,
        # The field parameters run P, A, B, G, N, k. Dropping P shifts
        # every one of the others onto its neighbour's value.
        "ecc_field_parameter_p": 0xB2,
        "ecc_field_parameter_a": 0xB3,
        "ecc_field_parameter_b": 0xB4,
        "ecc_field_parameter_g": 0xB5,
        "ecc_field_parameter_n": 0xB6,
        "ecc_field_parameter_k": 0xB7,
        "ecc_key_parameters_reference": 0xF0,
    }

    def test_values_match_the_spec(self) -> None:
        for name, expected in self.SPEC_VALUES.items():
            with self.subTest(name):
                self.assertEqual(_key_type_string_to_byte(name), expected)

    def test_separators_do_not_change_the_result(self) -> None:
        """A hyphenated spelling has to resolve, not fall through to zero."""

        for name, expected in self.SPEC_VALUES.items():
            with self.subTest(name):
                self.assertEqual(
                    _key_type_string_to_byte(name.replace("_", "-")), expected
                )

    @unittest.skipIf(_PYSIM_KEY_TYPE is None, "pySim not installed")
    def test_every_pysim_key_type_resolves(self) -> None:
        """The lookup only ever sees pySim spellings, so all must resolve.

        An unrecognised name returns zero, which is indistinguishable from
        a key with no type. That is how a table keyed on spellings pySim
        never emits stayed unnoticed.
        """

        for name, value in _PYSIM_KEY_TYPE.encmapping.items():
            if name in _NOT_KEY_TYPES:
                continue
            with self.subTest(name):
                self.assertEqual(_key_type_string_to_byte(name), value)

    def test_unknown_names_still_fall_back_to_zero(self) -> None:
        self.assertEqual(_key_type_string_to_byte("no-such-key-type"), 0)
        self.assertEqual(_key_type_string_to_byte(""), 0)

    def test_no_entry_sits_outside_a_byte(self) -> None:
        for name, value in _GP_KEY_TYPE_STRING_TO_BYTE.items():
            with self.subTest(name):
                self.assertGreaterEqual(value, 0)
                self.assertLessEqual(value, 0xFF)


if __name__ == "__main__":
    unittest.main()
