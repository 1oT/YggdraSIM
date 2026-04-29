"""Modem-initiated FS write persistence + ACL gating.

A live modem talks to the UICC over a basic logical channel and
issues UPDATE BINARY / UPDATE RECORD against system files such as
EF.LOCI (6F7E), EF.PSLOCI (6F73), EF.EPSLOCI (6FE3) and EF.FPLMN
(6F7B) during normal attach / camp-on. Three properties matter
for HIL-bridge fidelity:

1. The write must take effect in the live FS view immediately
   (already covered by ``etsi_fs.update_binary``).
2. The write must survive an engine restart so a power-cycled
   simulator returns the same EF body that the modem just stored.
3. Operator-provisioned files (EF.IMSI, EF.UST, EF.AD) MUST NOT
   be writable from a normal modem channel; they require an
   authenticated administrative context (SCP03 authenticated, or
   an ADM CHV verified).

These tests pin items 2 and 3 against the simulator. Item 1 is
exercised transitively by the round-trip checks.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.profile_store import (
    load_profile_image_json_file,
    sync_profiles_to_store,
)
from SIMCARD.state import (
    SimChvReference,
    SimProfileFsNode,
    SimProfileImage,
    SimProfileEntry,
)


class _ModemSession:
    """Tiny terminal-side helper to keep the APDU shape readable."""

    def __init__(self, engine: SimulatedSimCardEngine) -> None:
        self.engine = engine

    def select_aid(self, aid_hex: str) -> tuple[bytes, int, int]:
        aid = bytes.fromhex(aid_hex)
        apdu = bytes([0x00, 0xA4, 0x04, 0x04, len(aid)]) + aid
        return self.engine.transmit(apdu)

    def select_fid(self, fid_hex: str) -> tuple[bytes, int, int]:
        fid = bytes.fromhex(fid_hex)
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, len(fid)]) + fid
        return self.engine.transmit(apdu)

    def update_binary(self, payload: bytes, *, offset: int = 0) -> tuple[bytes, int, int]:
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        apdu = bytes([0x00, 0xD6, p1, p2, len(payload)]) + bytes(payload)
        return self.engine.transmit(apdu)

    def read_binary(self, length: int, *, offset: int = 0) -> tuple[bytes, int, int]:
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        apdu = bytes([0x00, 0xB0, p1, p2, length & 0xFF])
        return self.engine.transmit(apdu)


class _StoreFixture(unittest.TestCase):
    """Shared engine / temp-store setup."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._root = Path(self._td.name) / "simcard"
        self._root.mkdir(parents=True, exist_ok=True)
        self.euicc_root = self._root / "euicc"
        self.euicc_root.mkdir(parents=True, exist_ok=True)
        self.profile_store = self._root / "profile_store"
        self.profile_store.mkdir(parents=True, exist_ok=True)
        self.engine = self._build_engine()
        self.session = _ModemSession(self.engine)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _build_engine(self) -> SimulatedSimCardEngine:
        return SimulatedSimCardEngine(
            euicc_store_root=str(self._root),
            profile_store_path=str(self.profile_store),
        )

    def _select_efs(self, fid_hex: str) -> None:
        sw_aid = self.session.select_aid(USIM_AID)
        self.assertEqual(sw_aid[1:], (0x90, 0x00))
        sw_ef = self.session.select_fid(fid_hex)
        self.assertEqual(sw_ef[1:], (0x90, 0x00))


class ModemWriteHotPathTests(_StoreFixture):
    """Single-session writes land in the runtime FS view."""

    def test_update_binary_on_loci_is_visible_to_subsequent_read(self) -> None:
        self._select_efs("6F7E")
        # 11 bytes is the canonical EF.LOCI length (TS 31.102 §4.2.17).
        new_loci = bytes.fromhex("13579BDF02468ACE000000")
        self.assertEqual(len(new_loci), 11)
        sw = self.session.update_binary(new_loci)
        self.assertEqual(sw[1:], (0x90, 0x00))
        # Re-select to keep the cursor on EF.LOCI before the read.
        self._select_efs("6F7E")
        payload, sw1, sw2 = self.session.read_binary(11)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(payload[: len(new_loci)], new_loci)

    def test_update_binary_on_fplmn_is_visible_to_subsequent_read(self) -> None:
        self._select_efs("6F7B")
        # Three encoded PLMNs (12 bytes is the FPLMN list length on a USIM).
        forbidden = bytes.fromhex("21F354FFFFFFFFFFFFFFFFFF")
        sw = self.session.update_binary(forbidden)
        self.assertEqual(sw[1:], (0x90, 0x00))
        self._select_efs("6F7B")
        payload, sw1, sw2 = self.session.read_binary(len(forbidden))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(payload, forbidden)


class ModemWritePersistenceTests(_StoreFixture):
    """Modem-initiated writes survive a simulator restart."""

    def test_loci_round_trips_across_engine_restart(self) -> None:
        self._select_efs("6F7E")
        new_loci = bytes.fromhex("11223344556677889900AA")
        self.assertEqual(self.session.update_binary(new_loci)[1:], (0x90, 0x00))
        # Drop the live engine; rebuild from the on-disk profile store
        # exactly the way a power-cycle of the HIL bridge would.
        self.engine = self._build_engine()
        self.session = _ModemSession(self.engine)
        self._select_efs("6F7E")
        payload, sw1, sw2 = self.session.read_binary(len(new_loci))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(payload, new_loci)

    def test_fplmn_round_trips_across_engine_restart(self) -> None:
        self._select_efs("6F7B")
        forbidden = bytes.fromhex("01F2034F50CCFFFFFFFFFFFF")
        self.assertEqual(self.session.update_binary(forbidden)[1:], (0x90, 0x00))
        self.engine = self._build_engine()
        self.session = _ModemSession(self.engine)
        self._select_efs("6F7B")
        payload, sw1, sw2 = self.session.read_binary(len(forbidden))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(payload, forbidden)


class ModemWriteAclGatingTests(_StoreFixture):
    """Operator-provisioned files reject normal-channel writes."""

    def test_imsi_update_is_rejected_without_admin_context(self) -> None:
        self._select_efs("6F07")
        attacker = bytes.fromhex("0809001020304050607080")
        sw = self.session.update_binary(attacker)
        # 6982 -- security status not satisfied.
        self.assertEqual(sw[1:], (0x69, 0x82))

    def test_ust_update_is_rejected_without_admin_context(self) -> None:
        self._select_efs("6F38")
        sw = self.session.update_binary(b"\xFF" * 8)
        self.assertEqual(sw[1:], (0x69, 0x82))

    def test_ad_update_is_rejected_without_admin_context(self) -> None:
        self._select_efs("6FAD")
        sw = self.session.update_binary(b"\x80\x00\x00\x03")
        self.assertEqual(sw[1:], (0x69, 0x82))

    def test_imsi_update_is_accepted_after_scp03_auth(self) -> None:
        self.engine.state.scp03_session.authenticated = True
        self._select_efs("6F07")
        new_imsi_ef = bytes.fromhex("089910204060708091")
        sw = self.session.update_binary(new_imsi_ef)
        self.assertEqual(sw[1:], (0x90, 0x00))

    def test_ad_update_is_accepted_with_adm_chv_verified(self) -> None:
        # No ADM CHV in chv_references by default; install a verified one.
        self.engine.state.chv_references[0x0A] = SimChvReference(
            reference=0x0A,
            value="adm12345",
            verified=True,
            retries_remaining=10,
            retry_limit=10,
        )
        self._select_efs("6FAD")
        sw = self.session.update_binary(b"\x80\x00\x00\x03")
        self.assertEqual(sw[1:], (0x90, 0x00))


class ProfileStoreWriteAclRoundTripTests(unittest.TestCase):
    """``write_acl`` persists through the JSON image serializer."""

    def test_write_acl_round_trips_to_json_and_back(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store_path = os.path.join(td, "profile_store")
            os.makedirs(store_path, exist_ok=True)
            profile = SimProfileEntry(
                aid="A0000005591010FFFFFFFF8900001100",
                iccid="89461111111111111112",
                state="enabled",
                profile_class="test",
                imsi="001010000000001",
                profile_image=SimProfileImage(
                    iccid="89461111111111111112",
                    imsi="001010000000001",
                    nodes=[
                        SimProfileFsNode(
                            path=("MF", "ADF.USIM", "EF.IMSI"),
                            name="EF.IMSI",
                            kind="ef",
                            fid="6F07",
                            structure="transparent",
                            data=bytes.fromhex("08099900100020003040"),
                            write_acl="adm",
                        ),
                        SimProfileFsNode(
                            path=("MF", "ADF.USIM", "EF.LOCI"),
                            name="EF.LOCI",
                            kind="ef",
                            fid="6F7E",
                            structure="transparent",
                            data=b"\xFF" * 11,
                            write_acl="always",
                        ),
                    ],
                ),
            )
            sync_profiles_to_store(store_path, [profile])
            directory_name = "AID_" + profile.aid.upper()
            json_path = os.path.join(store_path, directory_name, "profile_image.json")
            self.assertTrue(os.path.isfile(json_path))
            reloaded = load_profile_image_json_file(json_path)
            self.assertIsNotNone(reloaded)
            assert reloaded is not None
            acls = {tuple(node.path): node.write_acl for node in reloaded.nodes}
            self.assertEqual(acls.get(("MF", "ADF.USIM", "EF.IMSI")), "adm")
            self.assertEqual(acls.get(("MF", "ADF.USIM", "EF.LOCI")), "always")

    def test_legacy_json_without_write_acl_defaults_to_always(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "profile_image.json")
            with open(json_path, "w", encoding="utf-8") as handle:
                handle.write(
                    """
                    {
                        "profile_name": "Legacy",
                        "iccid": "89461111111111111199",
                        "imsi": "001010000000099",
                        "impi": "",
                        "auth": null,
                        "nodes": [
                            {
                                "path": ["MF", "ADF.USIM", "EF.LOCI"],
                                "name": "EF.LOCI",
                                "kind": "ef",
                                "fid": "6F7E",
                                "aid": "",
                                "label": "",
                                "structure": "transparent",
                                "data_hex": "FFFFFFFFFFFFFFFFFFFFFF",
                                "records_hex": [],
                                "sfi": null
                            }
                        ]
                    }
                    """.strip()
                )
            reloaded = load_profile_image_json_file(json_path)
            self.assertIsNotNone(reloaded)
            assert reloaded is not None
            self.assertEqual(len(reloaded.nodes), 1)
            self.assertEqual(reloaded.nodes[0].write_acl, "always")


if __name__ == "__main__":
    unittest.main()
