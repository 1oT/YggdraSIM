# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The synthesised EF.ARR must answer the references its own FCPs emit."""

from __future__ import annotations

import unittest

from SIMCARD.etsi_fs import (
    CONTAINER_ARR_RECORD_INDEX,
    DEFAULT_ARR_RECORD,
    DEFAULT_ARR_RECORDS,
)
from Tools.ProfilePackage.saip_asn1_decode import (
    ARR_SCOPE_DF,
    ARR_SCOPE_EF,
    _decode_ef_arr,
)


def _rules(
    record: bytes,
    *,
    scope: str = ARR_SCOPE_EF,
) -> list[tuple[tuple[str, ...], str]]:
    decoded = _decode_ef_arr(record.hex().upper(), scope=scope)
    if not isinstance(decoded, dict):
        raise AssertionError(f"record does not decode: {record.hex().upper()}")
    return [
        (tuple(rule["accessModes"]), rule["condition"])
        for rule in decoded.get("rules", [])
    ]


# The record numbers `_build_security_attributes_referenced` derives from a
# node's write ACL, and what each one has to grant for that reference to mean
# what the FCP claims.
_EF_ADMIN = ("DEACTIVATE", "ACTIVATE", "TERMINATE", "DELETE_FILE")

_REFERENCED_RECORDS: dict[int, tuple[tuple[tuple[str, ...], str], ...]] = {
    0x01: ((("READ", "UPDATE"), "Always"), (_EF_ADMIN, "ADM1")),
    0x02: ((("READ",), "Always"), (("UPDATE",), "PIN1"), (_EF_ADMIN, "ADM1")),
    0x06: ((("READ",), "Always"), (("UPDATE",), "Never"), (_EF_ADMIN, "ADM1")),
    0x0A: ((("READ",), "Always"), (("UPDATE",) + _EF_ADMIN, "ADM1")),
}

# Record 0x0E is cited by MF/DF/ADF FCPs, so its low bits mean CREATE and
# DELETE CHILD rather than READ, UPDATE and APPEND.
_CONTAINER_RECORD_RULES = (
    (
        (
            "DELETE_CHILD",
            "CREATE_EF",
            "CREATE_DF",
            "DEACTIVATE",
            "ACTIVATE",
            "TERMINATE",
            "DELETE_FILE",
        ),
        "ADM1",
    ),
)

_ALL_EF_MODES = (
    "READ",
    "UPDATE",
    "APPEND",
    "DEACTIVATE",
    "ACTIVATE",
    "TERMINATE",
    "DELETE_FILE",
)
_ALL_DF_MODES = (
    "DELETE_CHILD",
    "CREATE_EF",
    "CREATE_DF",
    "DEACTIVATE",
    "ACTIVATE",
    "TERMINATE",
    "DELETE_FILE",
)


class DefaultArrRecordTests(unittest.TestCase):
    def test_every_record_is_well_formed_ber_tlv(self) -> None:
        for index, record in enumerate(DEFAULT_ARR_RECORDS, start=1):
            for scope in (ARR_SCOPE_EF, ARR_SCOPE_DF):
                with self.subTest(record=index, scope=scope):
                    self.assertNotEqual(_rules(record, scope=scope), [])

    def test_the_container_record_is_encoded_in_df_scope(self) -> None:
        record = DEFAULT_ARR_RECORDS[CONTAINER_ARR_RECORD_INDEX - 1]

        self.assertEqual(
            _rules(record, scope=ARR_SCOPE_DF),
            list(_CONTAINER_RECORD_RULES),
        )

    def test_the_container_record_is_not_an_ef_rule(self) -> None:
        # Read in EF scope the same byte grants READ/UPDATE/APPEND, which is
        # what the single-table encoder used to produce for a directory.
        record = DEFAULT_ARR_RECORDS[CONTAINER_ARR_RECORD_INDEX - 1]

        self.assertNotEqual(
            _rules(record, scope=ARR_SCOPE_EF),
            list(_CONTAINER_RECORD_RULES),
        )

    def test_the_table_covers_every_record_the_fcp_emitter_cites(self) -> None:
        # 0x0E is the highest reference `_build_security_attributes_referenced`
        # produces, so the file has to be at least that long.
        self.assertGreaterEqual(len(DEFAULT_ARR_RECORDS), 0x0E)

    def test_each_referenced_record_grants_what_its_reference_claims(self) -> None:
        for index, expected in _REFERENCED_RECORDS.items():
            with self.subTest(record=f"0x{index:02X}"):
                self.assertEqual(_rules(DEFAULT_ARR_RECORDS[index - 1]), list(expected))

    def test_an_uncited_record_denies_every_operation_in_either_scope(self) -> None:
        # A reference the emitter never produces must fail closed rather than
        # inherit a neighbouring record's rules, and it cannot know whether the
        # file that made the stray reference is a directory.
        cited = set(_REFERENCED_RECORDS) | {CONTAINER_ARR_RECORD_INDEX}
        for index in range(1, len(DEFAULT_ARR_RECORDS) + 1):
            if index in cited:
                continue
            record = DEFAULT_ARR_RECORDS[index - 1]
            with self.subTest(record=f"0x{index:02X}"):
                self.assertEqual(_rules(record), [(_ALL_EF_MODES, "Never")])
                self.assertEqual(
                    _rules(record, scope=ARR_SCOPE_DF),
                    [(_ALL_DF_MODES, "Never")],
                )

    def test_records_share_one_length_as_a_linear_fixed_ef_requires(self) -> None:
        self.assertEqual(len({len(record) for record in DEFAULT_ARR_RECORDS}), 1)

    def test_the_single_record_alias_stays_record_one(self) -> None:
        self.assertEqual(DEFAULT_ARR_RECORD, DEFAULT_ARR_RECORDS[0])


if __name__ == "__main__":
    unittest.main()
