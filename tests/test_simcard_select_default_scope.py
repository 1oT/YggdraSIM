# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 221 §8.4.2 SELECT default-scope conformance tests.

These lock the simulator's behaviour when the terminal issues
``SELECT 00 A4 00 04 02 <FID>`` (P1 = 0x00, "select by FID,
default scope"). A real UICC searches in this exact order:

1. The current DF.
2. Direct children of the current DF.
3. The parent DF (or grandparent, when the cursor is on an EF).
4. Children of the parent DF (siblings of the current DF / EF).
5. The currently selected ADF (if applicable) and its children.

The simulator must NOT perform a global tree walk: a real card
cannot ``SELECT 6F07`` from MF context. The previous behaviour
silently resolved the FID anywhere in the tree, masking host
bugs that issued out-of-scope SELECTs.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID


class SelectDefaultScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        store_root = Path(self._td.name) / "simcard"
        store_root.mkdir(parents=True, exist_ok=True)
        euicc_path = store_root / "euicc"
        euicc_path.mkdir(parents=True, exist_ok=True)
        profile_store = store_root / "profile_store"
        profile_store.mkdir(parents=True, exist_ok=True)
        self.engine = SimulatedSimCardEngine(
            euicc_store_root=str(store_root),
            profile_store_path=str(profile_store),
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select(self, p1: int, identifier: bytes) -> tuple[bytes, int, int]:
        apdu = bytes([0x00, 0xA4, p1 & 0xFF, 0x04, len(identifier)]) + identifier
        return self.engine.transmit(apdu)

    def _select_fid(self, fid: str) -> tuple[bytes, int, int]:
        return self._select(0x00, bytes.fromhex(fid))

    def _select_aid(self, aid: str) -> tuple[bytes, int, int]:
        return self._select(0x04, bytes.fromhex(aid))

    def test_imsi_is_unreachable_from_mf_context(self) -> None:
        """`SELECT 6F07` from MF must fail — EF.IMSI lives under ADF.USIM."""
        _, sw1, sw2 = self._select_fid("3F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("6F07")
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_iccid_resolves_under_mf(self) -> None:
        """`SELECT 2FE2` (EF.ICCID) is a child of MF and must resolve."""
        _, sw1, sw2 = self._select_fid("3F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("2FE2")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_imsi_resolves_after_selecting_usim_application(self) -> None:
        """After `SELECT ADF.USIM` the cursor anchors inside the USIM tree."""
        _, sw1, sw2 = self._select_aid(USIM_AID)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("6F07")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_parent_df_is_resolvable_from_ef(self) -> None:
        """ETSI TS 102 221 §8.4.2 step 3: parent DF is in scope."""
        _, sw1, sw2 = self._select_fid("3F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("2FE2")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("3F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_sibling_ef_resolves_after_selecting_an_ef(self) -> None:
        """ETSI TS 102 221 §8.4.2 step 4: siblings under the parent DF."""
        _, sw1, sw2 = self._select_fid("3F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._select_fid("2FE2")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # EF.DIR (2F00) lives under MF, so once the cursor is on EF.ICCID
        # the parent DF (MF) is the search anchor and 2F00 is a sibling.
        _, sw1, sw2 = self._select_fid("2F00")
        self.assertEqual((sw1, sw2), (0x90, 0x00))


if __name__ == "__main__":
    unittest.main()
