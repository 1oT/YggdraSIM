# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import os
import unittest

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.scp80 import Scp80Logic
from SIMCARD.utils import split_apdu_sequence


def _cryptodome_available() -> bool:
    try:
        import Crypto.Cipher.AES  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


@unittest.skipUnless(_cryptodome_available(), "requires PyCryptodome (Crypto)")
class Scp80348RoundTripTests(unittest.TestCase):
    def test_decrypt_roundtrip_matches_builder_aes(self) -> None:
        from SCP80.builder import OtaPacketBuilder
        from SCP80.config import ConfigManager
        from SCP80.crypto import CryptoEngine

        os.environ["YGGDRASIM_ALLOW_DEMO_KEYS"] = "1"
        cfg = ConfigManager()
        cfg.set("key_enc", "1122334455667788AABBCCDDEEFF0011")
        cfg.set("key_mac", "1122334455667788AABBCCDDEEFF0011")
        cfg.set("spi", "1621")
        cfg.set("kic", "22")
        cfg.set("kid", "22")
        cfg.set("tar", "B00001")
        cfg.set("cntr", "0000000312")
        inner = bytes.fromhex("00A40004023F00")
        plan = OtaPacketBuilder(cfg).build_plan(override_payload=inner.hex().upper())
        block = plan.block_0348
        k_enc = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
        k_mac = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
        plain, param, cntr = CryptoEngine.decrypt_0348_command_block(block, k_enc, k_mac)
        self.assertEqual(plain, inner)
        rapdu = bytes.fromhex("6233229000")
        rsp_body = bytes([0x00]) + rapdu
        out = CryptoEngine.build_0348_response_block(
            rsp_body,
            param_data=param,
            cntr_bytes=cntr,
            k_enc=k_enc,
            k_mac=k_mac,
        )
        self.assertGreater(len(out), 10)
        back, param_b, cntr_b = CryptoEngine.decrypt_0348_command_block(out, k_enc, k_mac)
        self.assertEqual(param_b, param)
        self.assertEqual(cntr_b, cntr)
        self.assertEqual(back, rsp_body)


@unittest.skipUnless(_cryptodome_available(), "requires PyCryptodome (Crypto)")
class Scp80EnvelopeDispatchTests(unittest.TestCase):
    def test_d1_envelope_dispatches_inner_select(self) -> None:
        from SCP80.builder import OtaPacketBuilder
        from SCP80.config import ConfigManager

        os.environ["YGGDRASIM_ALLOW_DEMO_KEYS"] = "1"
        cfg = ConfigManager()
        cfg.set("key_enc", "1122334455667788AABBCCDDEEFF0011")
        cfg.set("key_mac", "1122334455667788AABBCCDDEEFF0011")
        cfg.set("spi", "1621")
        cfg.set("kic", "22")
        cfg.set("kid", "22")
        cfg.set("tar", "B00001")
        cfg.set("cntr", "0000000315")
        inner = "00A40004023F00"
        plan = OtaPacketBuilder(cfg).build_plan(override_payload=inner)
        apdu = bytes.fromhex(plan.reader_apdus[0])
        engine = SimulatedSimCardEngine()
        engine.state.scp80_security.key_enc = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
        engine.state.scp80_security.key_mac = bytes.fromhex("1122334455667788AABBCCDDEEFF0011")
        engine.state.scp80_security.spi = "1621"
        engine.state.scp80_security.kic = "22"
        engine.state.scp80_security.kid = "22"
        engine.state.scp80_security.tar = "B00001"
        _data, sw1, sw2 = engine.transmit(apdu)
        self.assertEqual(sw1, 0x91)
        fetch = bytes([0x80, 0x12, 0x00, 0x00, sw2 & 0xFF])
        por, sw1b, sw2b = engine.transmit(fetch)
        self.assertEqual((sw1b, sw2b), (0x90, 0x00))
        self.assertGreater(len(por), 10)


class ApduSplitTests(unittest.TestCase):
    def test_split_select_then_read_binary(self) -> None:
        raw = bytes.fromhex("00A4080C022FE200B000000A")
        parts = split_apdu_sequence(raw)
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0].hex().upper(), "00A4080C022FE2")
        self.assertEqual(parts[1].hex().upper(), "00B000000A")


class Scp8061xxChainTests(unittest.TestCase):
    def test_transmit_collapses_61_with_get_response(self) -> None:
        from SIMCARD.etsi_fs import build_default_state

        seq: list[bytes] = []

        def fake_xmit(apdu: bytes) -> tuple[bytes, int, int]:
            seq.append(bytes(apdu))
            if len(seq) == 1:
                return (bytes.fromhex("DEAD"), 0x61, 0x03)
            if bytes(apdu) == bytes.fromhex("00C0000003"):
                return (bytes.fromhex("BEEF01"), 0x90, 0x00)
            return (b"", 0x6F, 0x00)

        logic = Scp80Logic(build_default_state(), fake_xmit)
        collapsed = logic._transmit_with_get_response_chain(bytes.fromhex("00B0000004"))
        self.assertEqual(collapsed, bytes.fromhex("DEADBEEF019000"))
        self.assertEqual(len(seq), 2)


def _build_concat_tpdu_for_test(fragment: bytes, ref: int, total: int, sequence: int) -> bytes:
    prefix = bytes.fromhex("4005811250F341F6222222222222222502")
    tp_ud = bytes.fromhex("050003") + bytes([ref & 0xFF, total & 0xFF, sequence & 0xFF]) + fragment
    return prefix + bytes([len(tp_ud) & 0xFF]) + tp_ud


class Scp80ConcatSmsTests(unittest.TestCase):
    def test_two_udh_segments_merge_before_decrypt(self) -> None:
        from SIMCARD.etsi_fs import build_default_state

        frag_a = bytes.fromhex("AABB")
        frag_b = bytes.fromhex("CCDD")
        tpdu_a = _build_concat_tpdu_for_test(frag_a, 9, 2, 1)
        tpdu_b = _build_concat_tpdu_for_test(frag_b, 9, 2, 2)
        logic = Scp80Logic(build_default_state(), lambda _apdu: (b"", 0x90, 0x00))
        self.assertIsNone(logic._resolve_0348_block(tpdu_a))
        merged = logic._resolve_0348_block(tpdu_b)
        self.assertEqual(merged, frag_a + frag_b)
