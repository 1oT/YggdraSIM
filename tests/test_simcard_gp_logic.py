# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``SIMCARD.gp`` command-dispatch logic.

Covers: SimulatedSecureSession.encrypt_key_data, GpLogic.handle_load,
GpLogic.handle_delete, GpLogic.handle_put_key, GpLogic.handle_set_status.
All tests use a minimal SimCardState constructed from public fields;
no card transport or external I/O is touched.
"""

from __future__ import annotations

import unittest

from SIMCARD.gp import GP_LCS_LOADED, GpLogic, SimulatedSecureSession
from SIMCARD.state import SimCardState


def _make_state(**kw) -> SimCardState:
    defaults = dict(
        atr=bytes.fromhex("3B9F96801FC78031A073BE21136743200718000001A5"),
        eid="89049032123456789012345678901235",
        iccid="8988201234567890123",
        imsi="001010000000001",
        default_dp_address="eim.example.test",
        root_ci_pkid=b"\x00" * 20,
        isdr_aid="A0000005591010FFFFFFFF8900000100",
        ecasd_aid="A0000005591010FFFFFFFF8900000200",
        mno_sd_aid="A000000151000000",
    )
    defaults.update(kw)
    return SimCardState(**defaults)


def _make_gp() -> tuple[GpLogic, SimCardState]:
    state = _make_state()
    return GpLogic(state), state


class SimulatedSecureSessionTests(unittest.TestCase):

    def test_encrypt_key_data_passthrough(self) -> None:
        sess = SimulatedSecureSession()
        payload = b"\xDE\xAD\xBE\xEF"
        self.assertEqual(sess.encrypt_key_data(payload), payload)

    def test_encrypt_key_data_empty(self) -> None:
        sess = SimulatedSecureSession()
        self.assertEqual(sess.encrypt_key_data(b""), b"")

    def test_encrypt_key_data_returns_bytes(self) -> None:
        sess = SimulatedSecureSession()
        self.assertIsInstance(sess.encrypt_key_data(b"\x01"), bytes)


class HandlePutKeyTests(unittest.TestCase):

    def test_valid_kvn_returns_9000(self) -> None:
        gp, _ = _make_gp()
        data, sw1, sw2 = gp.handle_put_key(0x01, 0x01, b"\x00" * 10)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_response_contains_kvn(self) -> None:
        gp, _ = _make_gp()
        data, sw1, sw2 = gp.handle_put_key(0x03, 0x01, b"\x00")
        self.assertEqual(data, bytes([0x03]))

    def test_zero_kvn_zero_kid_returns_error(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_put_key(0x00, 0x00, b"")
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_returns_bytes_sw(self) -> None:
        gp, _ = _make_gp()
        result = gp.handle_put_key(0x01, 0x01, b"")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)


class HandleSetStatusTests(unittest.TestCase):

    def test_empty_data_returns_6a80(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_set_status(0x80, 0x07, b"")
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_isdr_aid_scope80_returns_9000(self) -> None:
        gp, state = _make_gp()
        isdr_bytes = bytes.fromhex(state.isdr_aid)
        _, sw1, sw2 = gp.handle_set_status(0x80, 0x07, isdr_bytes)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_ecasd_aid_scope80_returns_9000(self) -> None:
        gp, state = _make_gp()
        ecasd_bytes = bytes.fromhex(state.ecasd_aid)
        _, sw1, sw2 = gp.handle_set_status(0x80, 0x07, ecasd_bytes)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_unknown_sd_aid_returns_6a82(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_set_status(0x80, 0x07, b"\xDE\xAD")
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_application_scope_updates_lifecycle(self) -> None:
        from SIMCARD.state import SimGpAppEntry
        gp, state = _make_gp()
        app = SimGpAppEntry(aid="AABBCCDD", kind="app", lifecycle_state=0x07, privileges=b"")
        state.gp_apps.append(app)
        aid_bytes = bytes.fromhex("AABBCCDD")
        _, sw1, sw2 = gp.handle_set_status(0x40, 0x83, aid_bytes)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(state.gp_apps[0].lifecycle_state, 0x83)

    def test_unknown_application_returns_6a82(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_set_status(0x40, 0x07, b"\xDE\xAD\xBE\xEF")
        self.assertEqual((sw1, sw2), (0x6A, 0x82))


class HandleLoadTests(unittest.TestCase):

    def test_no_pending_elf_aid_returns_6985(self) -> None:
        gp, state = _make_gp()
        state.gp_install.pending_elf_aid = ""
        _, sw1, sw2 = gp.handle_load(0x00, 0x00, b"\xAA\xBB")
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_wrong_block_number_returns_6a80(self) -> None:
        gp, state = _make_gp()
        state.gp_install.pending_elf_aid = "DEADBEEF"
        state.gp_install.expected_block = 0
        # Block 1 when 0 is expected
        _, sw1, sw2 = gp.handle_load(0x00, 0x01, b"\xAA")
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_intermediate_block_accumulates(self) -> None:
        gp, state = _make_gp()
        state.gp_install.pending_elf_aid = "DEADBEEF"
        state.gp_install.expected_block = 0
        _, sw1, sw2 = gp.handle_load(0x00, 0x00, b"\x01\x02")  # P1=0 not last, P2=0
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(state.gp_install.load_buffer, b"\x01\x02")

    def test_last_block_registers_elf_app(self) -> None:
        gp, state = _make_gp()
        state.gp_install.pending_elf_aid = "DEADBEEF"
        state.gp_install.expected_block = 0
        _, sw1, sw2 = gp.handle_load(0x80, 0x00, b"\xFF")  # P1=0x80 = last block
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        aids = [a.aid for a in state.gp_apps]
        self.assertIn("DEADBEEF", aids)

    def test_last_block_clears_context(self) -> None:
        gp, state = _make_gp()
        state.gp_install.pending_elf_aid = "DEADBEEF"
        state.gp_install.expected_block = 0
        gp.handle_load(0x80, 0x00, b"\xFF")
        self.assertEqual(state.gp_install.pending_elf_aid, "")
        self.assertEqual(state.gp_install.expected_block, 0)


class HandleDeleteTests(unittest.TestCase):

    def test_bad_tag_returns_6a80(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_delete(0, 0, b"\xAA\x04\x01\x02\x03\x04")
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_truncated_aid_returns_6a80(self) -> None:
        gp, _ = _make_gp()
        # Claims 8 bytes but only 2 follow
        _, sw1, sw2 = gp.handle_delete(0, 0, bytes([0x4F, 0x08, 0x01, 0x02]))
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_unknown_aid_returns_6a82(self) -> None:
        gp, _ = _make_gp()
        _, sw1, sw2 = gp.handle_delete(0, 0, bytes([0x4F, 0x04]) + b"\xDE\xAD\xBE\xEF")
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_delete_registered_elf(self) -> None:
        from SIMCARD.state import SimGpAppEntry
        gp, state = _make_gp()
        state.gp_apps.append(
            SimGpAppEntry(aid="AABB1122", kind="elf", lifecycle_state=GP_LCS_LOADED, privileges=b"")
        )
        _, sw1, sw2 = gp.handle_delete(0, 0, bytes([0x4F, 0x04]) + bytes.fromhex("AABB1122"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertFalse(any(a.aid == "AABB1122" for a in state.gp_apps))

    def test_delete_related_cascade(self) -> None:
        from SIMCARD.state import SimGpAppEntry
        gp, state = _make_gp()
        elf_aid = "CCDD3344"
        app_aid = "AABB1122"
        state.gp_apps.append(
            SimGpAppEntry(aid=elf_aid, kind="elf", lifecycle_state=GP_LCS_LOADED, privileges=b"")
        )
        state.gp_apps.append(
            SimGpAppEntry(aid=app_aid, kind="app", lifecycle_state=0x07, privileges=b"",
                         associated_elf=elf_aid)
        )
        # P2 = 0x80 = delete-related
        _, sw1, sw2 = gp.handle_delete(0, 0x80, bytes([0x4F, 0x04]) + bytes.fromhex(elf_aid))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        remaining = [a.aid for a in state.gp_apps]
        self.assertNotIn(elf_aid, remaining)
        self.assertNotIn(app_aid, remaining)


if __name__ == "__main__":
    unittest.main()
