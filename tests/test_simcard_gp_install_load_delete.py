"""GlobalPlatform Card Spec v2.3.1 §11 dispatch coverage.

Locks the simulator's behaviour for INSTALL / LOAD / DELETE /
PUT KEY / SET STATUS as well as the extended GET STATUS scopes
(P1 = 0x10 / 0x20 / 0x60). All command bytes route through the
SCP03 secure channel - the engine refuses these proprietary
INS values without an authenticated session.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine


class _AuthenticatedFixture(unittest.TestCase):
    """Driver that puts the simulator into an SCP03-authenticated state.

    The engine only gates GP commands on
    ``state.scp03_session.authenticated`` so the test bypasses the
    INIT UPDATE / EXTERNAL AUTH dance and flips the flag directly.
    A separate ``GpSecurityGateTests`` class verifies the gate
    itself - this fixture is exclusively about the dispatch logic.
    """

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        store_root = Path(self._td.name) / "simcard"
        store_root.mkdir(parents=True, exist_ok=True)
        (store_root / "euicc").mkdir(parents=True, exist_ok=True)
        profile_store = store_root / "profile_store"
        profile_store.mkdir(parents=True, exist_ok=True)
        self.engine = SimulatedSimCardEngine(
            euicc_store_root=str(store_root),
            profile_store_path=str(profile_store),
        )
        self.engine.state.scp03_session.authenticated = True

    def tearDown(self) -> None:
        self._td.cleanup()

    def _send(self, hex_str: str) -> tuple[bytes, int, int]:
        return self.engine.transmit(bytes.fromhex(hex_str))

    @staticmethod
    def _lv(payload: bytes) -> bytes:
        return bytes([len(payload)]) + bytes(payload)

    def _install_for_load(self, elf_aid: bytes, sd_aid: bytes) -> tuple[bytes, int, int]:
        body = (
            self._lv(elf_aid)
            + self._lv(sd_aid)
            + self._lv(b"")
            + self._lv(b"")
            + self._lv(b"")
        )
        apdu = bytes([0x80, 0xE6, 0x02, 0x00, len(body)]) + body + b"\x00"
        return self._send(apdu.hex().upper())

    def _load_block(self, block_num: int, payload: bytes, *, last: bool) -> tuple[bytes, int, int]:
        p1 = 0x80 if last else 0x00
        apdu = bytes([0x80, 0xE8, p1, block_num & 0xFF, len(payload)]) + bytes(payload) + b"\x00"
        return self._send(apdu.hex().upper())

    def _install_for_install(
        self,
        elf_aid: bytes,
        module_aid: bytes,
        app_aid: bytes,
        privileges: bytes,
        *,
        make_selectable: bool,
    ) -> tuple[bytes, int, int]:
        body = (
            self._lv(elf_aid)
            + self._lv(module_aid)
            + self._lv(app_aid)
            + self._lv(privileges)
            + self._lv(b"")
            + self._lv(b"")
        )
        sub_function = 0x0C if make_selectable else 0x04
        apdu = bytes([0x80, 0xE6, sub_function, 0x00, len(body)]) + body + b"\x00"
        return self._send(apdu.hex().upper())

    def _delete_object(self, aid: bytes, *, with_related: bool) -> tuple[bytes, int, int]:
        body = b"\x4F" + bytes([len(aid)]) + bytes(aid)
        p2 = 0x80 if with_related else 0x00
        apdu = bytes([0x80, 0xE4, 0x00, p2, len(body)]) + body + b"\x00"
        return self._send(apdu.hex().upper())


def _gp_get_status_apdu(scope: int, search_aid_hex: str = "") -> str:
    """Case 4 short APDU per GP Card Spec v2.3.1 §11.4.

    ``CLA INS P1 P2 Lc <4F-TLV(search-aid)> Le``
    """
    aid_bytes = bytes.fromhex(search_aid_hex) if len(search_aid_hex) > 0 else b""
    body = bytes([0x4F, len(aid_bytes)]) + aid_bytes
    apdu = bytes([0x80, 0xF2, scope & 0xFF, 0x00, len(body)]) + body + bytes([0x00])
    return apdu.hex().upper()


class GpGetStatusScopesTests(_AuthenticatedFixture):
    def test_isd_scope_returns_security_domains(self) -> None:
        data, sw1, sw2 = self._send(_gp_get_status_apdu(0x80))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertGreater(data.count(b"\xE3"), 0)
        self.assertIn(bytes.fromhex(self.engine.state.isdr_aid), data)

    def test_application_scope_returns_application_entries(self) -> None:
        data, sw1, sw2 = self._send(_gp_get_status_apdu(0x40))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertGreater(len(data), 0)

    def test_elf_module_combined_scopes_start_empty(self) -> None:
        for scope in (0x10, 0x20, 0x60):
            data, sw1, sw2 = self._send(_gp_get_status_apdu(scope))
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            self.assertEqual(data, b"")

    def test_unsupported_scope_returns_6a86(self) -> None:
        _, sw1, sw2 = self._send(_gp_get_status_apdu(0x99))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class GpInstallLoadFlowTests(_AuthenticatedFixture):
    ELF_AID = bytes.fromhex("A0000001515350")
    MODULE_AID = bytes.fromhex("A000000151535000")
    APP_AID = bytes.fromhex("A000000151535001")
    SD_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")

    def test_install_for_load_sets_up_pending_context(self) -> None:
        _, sw1, sw2 = self._install_for_load(self.ELF_AID, self.SD_AID)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        ctx = self.engine.state.gp_install
        self.assertEqual(ctx.pending_elf_aid, self.ELF_AID.hex().upper())
        self.assertEqual(ctx.expected_block, 0)

    def test_load_chain_promotes_elf_to_registry_with_lifecycle_loaded(self) -> None:
        self._install_for_load(self.ELF_AID, self.SD_AID)
        _, sw1, sw2 = self._load_block(0, b"\xCA\xFE\xBA\xBE", last=False)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _, sw1, sw2 = self._load_block(1, b"\x01\x02\x03\x04", last=True)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

        elf_records = [app for app in self.engine.state.gp_apps if app.kind == "elf"]
        self.assertEqual(len(elf_records), 1)
        self.assertEqual(elf_records[0].aid, self.ELF_AID.hex().upper())
        self.assertEqual(elf_records[0].lifecycle_state, 0x01)

    def test_load_without_install_for_load_returns_6985(self) -> None:
        _, sw1, sw2 = self._load_block(0, b"\xAA\xBB", last=True)
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_install_for_install_creates_application_in_selectable_state(self) -> None:
        self._install_for_load(self.ELF_AID, self.SD_AID)
        self._load_block(0, b"\xCA\xFE", last=True)
        _, sw1, sw2 = self._install_for_install(
            self.ELF_AID,
            self.MODULE_AID,
            self.APP_AID,
            b"\x80",
            make_selectable=True,
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

        applications = [
            app for app in self.engine.state.gp_apps if app.kind == "application"
        ]
        self.assertEqual(len(applications), 1)
        self.assertEqual(applications[0].lifecycle_state, 0x07)
        self.assertEqual(applications[0].privileges, b"\x80")

    def test_install_for_install_against_unknown_elf_returns_6a82(self) -> None:
        _, sw1, sw2 = self._install_for_install(
            bytes.fromhex("DEADBEEFCAFEBABE"),
            self.MODULE_AID,
            self.APP_AID,
            b"\x00",
            make_selectable=True,
        )
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_get_status_after_install_lists_application(self) -> None:
        self._install_for_load(self.ELF_AID, self.SD_AID)
        self._load_block(0, b"\x00", last=True)
        self._install_for_install(
            self.ELF_AID,
            self.MODULE_AID,
            self.APP_AID,
            b"\x80",
            make_selectable=True,
        )
        data, sw1, sw2 = self._send(_gp_get_status_apdu(0x10))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(self.ELF_AID, data)


class GpDeleteAndSetStatusTests(_AuthenticatedFixture):
    ELF_AID = bytes.fromhex("A0000001515350")
    MODULE_AID = bytes.fromhex("A000000151535000")
    APP_AID = bytes.fromhex("A000000151535001")
    SD_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")

    def _ensure_app(self) -> None:
        body = (
            bytes([len(self.ELF_AID)]) + self.ELF_AID
            + bytes([len(self.SD_AID)]) + self.SD_AID
            + b"\x00\x00\x00"
        )
        apdu = bytes([0x80, 0xE6, 0x02, 0x00, len(body)]) + body + b"\x00"
        self._send(apdu.hex().upper())
        # Tiny single-block LOAD: P1=0x80 (final), P2=0 (block 0), payload 1 byte.
        self._send("80E88000010100")
        body = (
            bytes([len(self.ELF_AID)]) + self.ELF_AID
            + bytes([len(self.MODULE_AID)]) + self.MODULE_AID
            + bytes([len(self.APP_AID)]) + self.APP_AID
            + b"\x01\x80"
            + b"\x00\x00"
        )
        apdu = bytes([0x80, 0xE6, 0x0C, 0x00, len(body)]) + body + b"\x00"
        self._send(apdu.hex().upper())

    def test_delete_application_removes_registry_entry(self) -> None:
        self._ensure_app()
        before = len([a for a in self.engine.state.gp_apps if a.kind == "application"])
        body = b"\x4F" + bytes([len(self.APP_AID)]) + self.APP_AID
        apdu = bytes([0x80, 0xE4, 0x00, 0x00, len(body)]) + body + b"\x00"
        _, sw1, sw2 = self._send(apdu.hex().upper())
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        after = len([a for a in self.engine.state.gp_apps if a.kind == "application"])
        self.assertEqual(after, before - 1)

    def test_delete_unknown_aid_returns_6a82(self) -> None:
        body = b"\x4F\x05\xDE\xAD\xBE\xEF\x00"
        apdu = bytes([0x80, 0xE4, 0x00, 0x00, len(body)]) + body + b"\x00"
        _, sw1, sw2 = self._send(apdu.hex().upper())
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_set_status_changes_application_lifecycle(self) -> None:
        self._ensure_app()
        apdu = bytes([0x80, 0xF0, 0x40, 0x83, len(self.APP_AID)]) + self.APP_AID + b"\x00"
        _, sw1, sw2 = self._send(apdu.hex().upper())
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        target = next(a for a in self.engine.state.gp_apps if a.aid == self.APP_AID.hex().upper())
        self.assertEqual(target.lifecycle_state, 0x83)

    def test_put_key_against_default_kvn_returns_6a86(self) -> None:
        # PUT KEY with KVN=0 / KeyID=0 means "next free slot" which the
        # simulator deliberately rejects (the static keys are owned by
        # Scp03CardLogic, not GpLogic).
        _, sw1, sw2 = self._send("80D80000020000 00".replace(" ", ""))
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class GpSecurityGateTests(unittest.TestCase):
    """Without an SCP03 session the engine must reject GP commands."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        store_root = Path(self._td.name) / "simcard"
        store_root.mkdir(parents=True, exist_ok=True)
        (store_root / "euicc").mkdir(parents=True, exist_ok=True)
        profile_store = store_root / "profile_store"
        profile_store.mkdir(parents=True, exist_ok=True)
        self.engine = SimulatedSimCardEngine(
            euicc_store_root=str(store_root),
            profile_store_path=str(profile_store),
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_install_without_scp03_returns_6982(self) -> None:
        for hex_apdu in (
            "80E602000400AA000000",                       # INSTALL [for load]
            "80E88000020100 00".replace(" ", ""),         # LOAD final block 0
            "80E40000054F0301AABB 00".replace(" ", ""),  # DELETE
            "80F040810403AABBCC 00".replace(" ", ""),    # SET STATUS
            "80D801000301020300",                         # PUT KEY
        ):
            _, sw1, sw2 = self.engine.transmit(bytes.fromhex(hex_apdu))
            self.assertEqual((sw1, sw2), (0x69, 0x82), msg=hex_apdu)


if __name__ == "__main__":
    unittest.main()
