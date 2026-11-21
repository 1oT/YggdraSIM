# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card-standard classification in the SCP03 ``card_info`` probe.

Background
----------
``_probe_eid_and_standard`` used to decide the card standard from
whether the EID came back: a failed ``GET DATA 5A`` on ECASD returned
early with "Legacy UICC" and the ISD-R probe never ran. Cards exist
that carry ISD-R -- an eUICC by definition -- and still answer 6A88 to
that GET DATA, because SGP.22 §5.7.20 serves the EID over ES10c on a
logical channel rather than from the basic channel. Such a card was
reported as legacy in the Command Center header.

The classification depends on which RSP applications the card exposes,
never on whether the EID could be read. These tests pin that split.
"""

from __future__ import annotations

import unittest

from yggdrasim_common.gui_server.actions.scp03 import _probe_eid_and_standard

ECASD_AID = "A0000005591010FFFFFFFF8900000200"
ISDR_AID = "A0000005591010FFFFFFFF8900000100"
TEST_EID = "89049032" + "0" * 24


class _FakeTransporter:
    """Answers SELECT-by-AID and GET DATA 5A from a declared card shape."""

    def __init__(
        self,
        *,
        ecasd: bool,
        isdr: bool,
        eid: str = "",
        raise_on_isdr: bool = False,
    ) -> None:
        self.ecasd = ecasd
        self.isdr = isdr
        self.eid = eid
        self.raise_on_isdr = raise_on_isdr
        self.sent: list[str] = []

    def transmit(self, apdu: str, silent: bool = False) -> tuple[bytes, int, int]:
        upper = str(apdu).upper()
        self.sent.append(upper)
        if ISDR_AID in upper:
            if self.raise_on_isdr:
                raise OSError("card removed")
            return (b"", 0x90, 0x00) if self.isdr else (b"", 0x6A, 0x82)
        if ECASD_AID in upper:
            return (b"", 0x90, 0x00) if self.ecasd else (b"", 0x6A, 0x82)
        if upper.startswith("80CA5A"):
            if len(self.eid) > 0:
                return bytes.fromhex("5A10" + self.eid), 0x90, 0x00
            # Card holds an EID but will not serve it from the basic channel.
            return b"", 0x6A, 0x88
        return b"", 0x90, 0x00


class CardStandardProbeTests(unittest.TestCase):
    def test_isdr_present_is_an_euicc_even_when_the_eid_is_unreadable(self) -> None:
        transporter = _FakeTransporter(ecasd=True, isdr=True)
        eid, standard = _probe_eid_and_standard(transporter)
        self.assertEqual(standard, "eUICC")
        self.assertEqual(eid, "")
        # The regression was returning before this probe ever ran.
        self.assertTrue(any(ISDR_AID in sent for sent in transporter.sent))

    def test_isdr_present_with_a_readable_eid(self) -> None:
        transporter = _FakeTransporter(ecasd=True, isdr=True, eid=TEST_EID)
        eid, standard = _probe_eid_and_standard(transporter)
        self.assertEqual(standard, "eUICC")
        self.assertEqual(eid, TEST_EID)

    def test_isdr_without_ecasd_still_classifies_as_euicc(self) -> None:
        _eid, standard = _probe_eid_and_standard(
            _FakeTransporter(ecasd=False, isdr=True)
        )
        self.assertEqual(standard, "eUICC")

    def test_ecasd_without_isdr(self) -> None:
        _eid, standard = _probe_eid_and_standard(
            _FakeTransporter(ecasd=True, isdr=False)
        )
        self.assertEqual(standard, "UICC + ECASD")

    def test_card_with_neither_application_is_legacy(self) -> None:
        _eid, standard = _probe_eid_and_standard(
            _FakeTransporter(ecasd=False, isdr=False)
        )
        self.assertEqual(standard, "Legacy UICC")

    def test_transport_failure_keeps_what_the_probes_established(self) -> None:
        """A card yanked mid-probe must not be reported as legacy."""
        _eid, standard = _probe_eid_and_standard(
            _FakeTransporter(ecasd=True, isdr=True, raise_on_isdr=True)
        )
        self.assertEqual(standard, "UICC + ECASD")


if __name__ == "__main__":
    unittest.main()
