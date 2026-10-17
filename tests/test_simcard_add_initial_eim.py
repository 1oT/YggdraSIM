# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10b.AddInitialEim of the simulated eUICC (SGP.32 v1.2 §5.9.4).

Pins the association token handling (signed INTEGER, -1 requests allocation), the values the
eUICC assigns to absent fields, each error code, the all-or-nothing rule and the strict mode
that drops the simulator's upsert convenience.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.utils import tlv


def _public_key_data() -> bytes:
    spki = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    # eimPublicKeyData [5] is an explicit CHOICE; eimPublicKey is its first alternative.
    return tlv("A5", tlv("A0", spki))


def _row(
    eim_id: str = "testeim1",
    *,
    counter: bytes | None = b"\x01",
    token: bytes | None = None,
    ci_pkid: bytes | None = None,
    with_key: bool = True,
) -> bytes:
    body = tlv("80", eim_id.encode("utf-8"))
    if counter is not None:
        body += tlv("83", counter)
    if token is not None:
        body += tlv("84", token)
    if with_key:
        body += _public_key_data()
    if ci_pkid is not None:
        body += tlv("88", ci_pkid)
    return tlv("30", body)


def _request(*rows: bytes) -> bytes:
    return tlv("BF57", tlv("A0", b"".join(rows)))


class AddInitialEimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.state.eim_entries = []
        self.state.association_token_counter = 0
        self.logic = SgpLogic(self.state)

    def test_minus_one_requests_a_token_that_is_returned_and_stored(self) -> None:
        response, sw1, sw2 = self.logic.handle_store_data(_request(_row(token=b"\xFF")))

        self.assertEqual((response, sw1, sw2), (tlv("BF57", tlv("A0", tlv("84", b"\x01"))), 0x90, 0x00))
        self.assertEqual(self.state.eim_entries[0].association_token, 1)
        self.assertEqual(self.state.association_token_counter, 1)

    def test_absent_fields_take_the_values_the_euicc_assigns(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(_row()))

        self.assertEqual(response, tlv("BF57", tlv("A0", tlv("05", b""))))
        entry = self.state.eim_entries[0]
        self.assertEqual(entry.eim_id_type, 3)
        self.assertEqual(entry.supported_protocol_bits, [4])
        self.assertEqual(entry.association_token, 0)
        self.assertEqual(bytes(entry.euicc_ci_pkid), bytes(self.logic._configured_ci_pkids()[0]))

    def test_counter_above_the_supported_maximum_is_out_of_range(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(_row(counter=b"\x00\x80\x00\x00")))

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x06")))
        self.assertEqual(self.state.eim_entries, [])

    def test_eim_id_longer_than_128_characters_is_a_command_error(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(_row("e" * 129)))

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x07")))

    def test_missing_counter_or_public_key_is_a_command_error(self) -> None:
        for row in (_row(counter=None), _row(with_key=False)):
            response, _, _ = self.logic.handle_store_data(_request(row))
            self.assertEqual(response, tlv("BF57", tlv("81", b"\x07")))
        self.assertEqual(self.state.eim_entries, [])

    def test_unknown_ci_pkid_is_ci_pk_unknown(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(_row(ci_pkid=b"\x42" * 20)))

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x03")))

    def test_an_invalid_row_leaves_the_configuration_untouched(self) -> None:
        response, _, _ = self.logic.handle_store_data(
            _request(_row("testeim1", token=b"\xFF"), _row("testeim2", counter=None))
        )

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x07")))
        self.assertEqual(self.state.eim_entries, [])
        self.assertEqual(self.state.association_token_counter, 0)


class StrictAddInitialEimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        self.state.eim_entries = []
        self.state.conformance_strict = True
        self.logic = SgpLogic(self.state)

    def test_second_call_finds_an_associated_eim(self) -> None:
        self.logic.handle_store_data(_request(_row("testeim1")))

        response, _, _ = self.logic.handle_store_data(_request(_row("testeim2")))

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x02")))
        self.assertEqual([entry.eim_id for entry in self.state.eim_entries], ["testeim1"])

    def test_token_other_than_minus_one_is_invalid(self) -> None:
        response, _, _ = self.logic.handle_store_data(_request(_row(token=b"\x05")))

        self.assertEqual(response, tlv("BF57", tlv("81", b"\x05")))
        self.assertEqual(self.state.eim_entries, [])


if __name__ == "__main__":
    unittest.main()
