# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec pins for the GlobalPlatform manager, the SCP03 session and the CAP parser.

Every vector is read from GlobalPlatform Card Specification v2.3.1
(``GPC_CardSpecification_v2.3.1.49_PublicRvw``), Secure Channel Protocol '03'
Amendment D v1.1.2 and the Java Card VM Specification 3.1. All keys are
synthetic.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from SCP03.core.cap import CapFileParser
from SCP03.crypto.session import Scp03Error, Scp03Session
from SCP03.logic.gp import GlobalPlatformManager

DEK = bytes.fromhex("606162636465666768696A6B6C6D6E6F")
STATIC_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
PACKAGE_AID = bytes.fromhex("A000000151")
APPLET_AID = bytes.fromhex("A00000015101")
SD_AID = bytes.fromhex("A000000151000000")


def _manager(transmit_return=(b"", 0x90, 0x00)) -> GlobalPlatformManager:
    tp = MagicMock()
    tp.session = None
    tp.transmit.return_value = transmit_return
    mgr = GlobalPlatformManager.__new__(GlobalPlatformManager)
    mgr.tp = tp
    mgr.raw_keys = {}
    mgr.target_aid = SD_AID
    mgr.active_scp_protocol = "SCP03"
    mgr.scp03_kvn = 0x30
    mgr.scp03_keys = {"kenc": STATIC_KEY, "kmac": STATIC_KEY, "dek": DEK}
    return mgr


def _authenticated_manager() -> GlobalPlatformManager:
    mgr = _manager()
    mgr.tp.session = MagicMock()
    mgr.tp.session.is_authenticated = True
    mgr.tp.session.sec_level = 0x03
    mgr.tp.session.protocol_name = "SCP03"
    return mgr


def _sent(mgr: GlobalPlatformManager) -> list[str]:
    return [call.args[0].upper() for call in mgr.tp.transmit.call_args_list]


def _aes_cbc_zero_iv(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


class _DekSession:
    """Session stub that only wraps key material under the static DEK."""

    protocol_name = "SCP03"
    is_authenticated = True
    sec_level = 0x03

    def encrypt_key_data(self, key_bytes: bytes) -> bytes:
        return _aes_cbc_zero_iv(DEK, bytes(key_bytes))


def _component(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + len(payload).to_bytes(2, "big") + payload

# JCVM 3.1 §6.4 header_component_compact, everything ahead of AID_length:
# magic 'DECAFFED', CAP format minor then major ('02' '02'), flags, and the
# package_info minor and major version.
HEADER_PREFIX = bytes.fromhex("DECAFFED") + b"\x02\x02\x00\x00\x01"


class LifeCycleCodingTests(unittest.TestCase):
    """GPC v2.3.1 §11.1.1 Tables 11-3 to 11-6."""

    def test_executable_load_file_states_follow_table_11_3(self) -> None:
        self.assertEqual(
            GlobalPlatformManager._state_to_string(0x01, "PACKAGES"), "LOADED"
        )
        self.assertEqual(
            GlobalPlatformManager._state_to_string(0x00, "PACKAGES"),
            "LOGICALLY_DELETED",
        )

    def test_application_states_follow_tables_11_4_and_11_5(self) -> None:
        expected = {
            0x03: "INSTALLED",
            0x07: "SELECTABLE",
            0x0F: "PERSONALIZED",
            0x83: "LOCKED",
            0x8F: "LOCKED",
            0xFF: "LOCKED",
            0x17: "APP_SPECIFIC_0x17",
        }
        for state, name in expected.items():
            with self.subTest(state=state):
                self.assertEqual(
                    GlobalPlatformManager._state_to_string(state, "APPS"), name
                )
        self.assertEqual(GlobalPlatformManager._state_to_string(0x80, "APPS"), "0x80")

    def test_issuer_security_domain_uses_the_card_life_cycle(self) -> None:
        expected = {
            0x01: "OP_READY",
            0x07: "INITIALIZED",
            0x0F: "SECURED",
            0x7F: "CARD_LOCKED",
            0xFF: "TERMINATED",
        }
        for state, name in expected.items():
            with self.subTest(state=state):
                self.assertEqual(
                    GlobalPlatformManager._state_to_string(state, "SD"), name
                )

    def test_registry_entries_read_the_state_for_their_kind(self) -> None:
        elf_row = bytes.fromhex("E30B4F05A0000001519F700101")
        result = _manager((elf_row, 0x90, 0x00)).get_registry_data("PACKAGES")
        self.assertEqual(result["entries"][0]["state"], "LOADED")

        isd_row = bytes.fromhex("E3134F08A0000001510000009F70010FC5039EFE80")
        result = _manager((isd_row, 0x90, 0x00)).get_registry_data("SD")
        self.assertEqual(result["entries"][0]["state"], "SECURED")
        self.assertEqual(result["entries"][0]["extra"], "9EFE80")

    def test_executable_load_file_row_shows_its_security_domain(self) -> None:
        row = bytes.fromhex("E3154F05A0000001519F700101CC08A000000151000000")
        result = _manager((row, 0x90, 0x00)).get_registry_data("PACKAGES")
        self.assertEqual(result["entries"][0]["extra"], "A000000151000000")


class InstallDataFieldTests(unittest.TestCase):
    """GPC v2.3.1 §11.5.2.3 LV data fields and the case-4 Le of Table 11-40."""

    def test_make_selectable_matches_table_11_44(self) -> None:
        mgr = _authenticated_manager()
        mgr.install_make_selectable(APPLET_AID.hex(), "00")
        self.assertEqual(
            _sent(mgr)[-1],
            "80E608000D" + "0000" + "06" + APPLET_AID.hex().upper() + "0100" + "00" + "00" + "00",
        )

    def test_extradition_matches_table_11_45(self) -> None:
        mgr = _authenticated_manager()
        mgr.install_extradition(APPLET_AID.hex(), SD_AID.hex(), token="1122")
        body = (
            "08" + SD_AID.hex().upper()
            + "00"
            + "06" + APPLET_AID.hex().upper()
            + "00"
            + "00"
            + "021122"
        )
        self.assertEqual(_sent(mgr)[-1], "80E6100016" + body + "00")

    def test_personalization_matches_table_11_47(self) -> None:
        mgr = _authenticated_manager()
        mgr.install_personalization(APPLET_AID.hex())
        self.assertEqual(
            _sent(mgr)[-1],
            "80E620000C" + "0000" + "06" + APPLET_AID.hex().upper() + "000000" + "00",
        )

    def test_registry_update_matches_table_11_46(self) -> None:
        mgr = _authenticated_manager()
        mgr.install_registry_update(
            APPLET_AID.hex(), "80", "", sd_aid_hex=SD_AID.hex()
        )
        body = (
            "08" + SD_AID.hex().upper()
            + "00"
            + "06" + APPLET_AID.hex().upper()
            + "0180"
            + "00"
            + "00"
        )
        self.assertEqual(_sent(mgr)[-1], "80E6400015" + body + "00")

    def test_parameter_lengths_above_127_use_ber_coding(self) -> None:
        mgr = _authenticated_manager()
        params = "EF" + "81" + "80" + "CF01" + "00" + "AA" * 124
        self.assertEqual(len(params) // 2, 130)
        mgr.install_for_load(PACKAGE_AID.hex(), "", "", params, "")
        apdu = _sent(mgr)[-1]
        prefix = "05" + PACKAGE_AID.hex().upper() + "00" + "00"
        self.assertIn(prefix + "8182" + params.upper() + "00" + "00", apdu)

    def test_install_and_delete_carry_le(self) -> None:
        mgr = _authenticated_manager()
        mgr._send_install_cmd(0x02, b"\x00" * 4, "For Load")
        self.assertEqual(_sent(mgr)[-1], "80E60200040000000000")

        mgr.delete_object(APPLET_AID.hex())
        self.assertEqual(
            _sent(mgr)[-1], "80E4008008" + "4F06" + APPLET_AID.hex().upper() + "00"
        )

    def test_case_4_builder_pairs_an_extended_lc_with_a_two_byte_le(self) -> None:
        apdu = GlobalPlatformManager._build_case4_apdu(
            0x80, 0xE6, 0x40, 0x00, b"\x00" * 256
        )
        self.assertTrue(apdu.startswith("80E64000000100"))
        self.assertTrue(apdu.endswith("0000"))
        self.assertEqual(len(apdu), (4 + 3 + 256 + 2) * 2)

    def test_cap_load_sends_install_for_load_and_load_as_case_4(self) -> None:
        mgr = _authenticated_manager()
        mgr.tp.session.sec_level = 0
        header_payload = HEADER_PREFIX + bytes([len(PACKAGE_AID)]) + PACKAGE_AID
        applet_payload = bytes([1, len(APPLET_AID)]) + APPLET_AID + b"\x00\x00"
        component_blob = _component(0x01, header_payload) + _component(0x03, applet_payload)
        load_block = CapFileParser._wrap_load_file_block(component_blob)

        with tempfile.TemporaryDirectory() as temp_dir:
            ijc_path = Path(temp_dir) / "sample.ijc"
            ijc_path.write_bytes(load_block)
            mgr.install_cap_file(str(ijc_path), instantiate=False)

        calls = _sent(mgr)
        self.assertEqual(
            calls[0],
            "80E60200" + "0A" + "05" + PACKAGE_AID.hex().upper() + "00000000" + "00",
        )
        self.assertEqual(
            calls[1],
            "80E88000" + f"{len(load_block):02X}" + load_block.hex().upper() + "00",
        )


class StoreDataTests(unittest.TestCase):
    """GPC v2.3.1 §11.11.2 Tables 11-88 and 11-89."""

    def test_chunk_sequence_marks_only_the_last_block(self) -> None:
        mgr = _authenticated_manager()
        mgr.store_data("AB" * 300)
        calls = _sent(mgr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:10], "80E20000F0")
        self.assertEqual(calls[1][:10], "80E280013C")
        self.assertEqual(len(calls[0]), (5 + 240) * 2)
        self.assertEqual(len(calls[1]), (5 + 60) * 2)

    def test_manual_p1_case_4_appends_le(self) -> None:
        mgr = _authenticated_manager()
        mgr.store_data("AABB", 0x91, 0x00)
        self.assertEqual(_sent(mgr)[-1], "80E2910002AABB00")
        mgr.store_data("AABB", 0x90, 0x00)
        self.assertEqual(_sent(mgr)[-1], "80E2900002AABB")


class PutKeyTests(unittest.TestCase):
    """GPC v2.3.1 §11.8 Tables 11-65 to 11-71 and Annex B.8."""

    def _manager_with_dek(self) -> GlobalPlatformManager:
        mgr = _manager()
        mgr.tp.session = _DekSession()
        return mgr

    def test_aes_128_key_data_field(self) -> None:
        mgr = self._manager_with_dek()
        key = bytes.fromhex("505152535455565758595A5B5C5D5E5F")
        self.assertTrue(mgr.put_key(0x00, 0x01, 0x30, [key.hex()], 0x88))

        component = _aes_cbc_zero_iv(DEK, key)
        kcv = _aes_ecb(key, b"\x01" * 16)[:3]
        expected = (
            "80D80001" + "17"
            + "30"
            + "88" + "10" + component.hex().upper()
            + "03" + kcv.hex().upper()
            + "00"
        )
        self.assertEqual(_sent(mgr)[-1], expected)

    def test_aes_192_key_is_padded_and_length_prefixed(self) -> None:
        mgr = self._manager_with_dek()
        key = bytes(range(0x20, 0x38))
        self.assertTrue(mgr.put_key(0x30, 0x01, 0x31, [key.hex()], 0x88))

        component = b"\x18" + _aes_cbc_zero_iv(DEK, key + b"\x00" * 8)
        kcv = _aes_ecb(key, b"\x01" * 16)[:3]
        expected = (
            "80D83001" + "28"
            + "31"
            + "88" + "21" + component.hex().upper()
            + "03" + kcv.hex().upper()
            + "00"
        )
        self.assertEqual(_sent(mgr)[-1], expected)

    def test_multiple_keys_set_p2_b8(self) -> None:
        mgr = self._manager_with_dek()
        keys = [STATIC_KEY.hex(), DEK.hex(), bytes(range(16)).hex()]
        self.assertTrue(mgr.put_key(0x00, 0x01, 0x30, keys, 0x88))
        apdu = _sent(mgr)[-1]
        self.assertEqual(apdu[:8], "80D80081")
        # Table 11-67: the KVN then three key data fields of 22 bytes each.
        self.assertEqual(apdu[8:10], "43")

    def test_annex_b8_check_values(self) -> None:
        des_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # pragma: no cover - older cryptography
            TripleDES = algorithms.TripleDES
        des = Cipher(TripleDES(des_key), modes.ECB()).encryptor()
        self.assertEqual(
            GlobalPlatformManager._key_check_value(0x80, des_key),
            (des.update(b"\x00" * 8) + des.finalize())[:3],
        )
        self.assertEqual(
            GlobalPlatformManager._key_check_value(0x88, STATIC_KEY),
            _aes_ecb(STATIC_KEY, b"\x01" * 16)[:3],
        )
        sm4 = Cipher(algorithms.SM4(STATIC_KEY), modes.ECB()).encryptor()
        self.assertEqual(
            GlobalPlatformManager._key_check_value(0x89, STATIC_KEY),
            (sm4.update(b"\x02" * 16) + sm4.finalize())[:3],
        )
        self.assertEqual(GlobalPlatformManager._key_check_value(0xA1, STATIC_KEY), b"")

    def test_response_echo_is_checked(self) -> None:
        kcv = _aes_ecb(STATIC_KEY, b"\x01" * 16)[:3]
        mgr = self._manager_with_dek()
        mgr.tp.transmit.return_value = (b"\x30" + kcv, 0x90, 0x00)
        self.assertTrue(mgr.put_key(0x00, 0x01, 0x30, [STATIC_KEY.hex()], 0x88))

        mgr.tp.transmit.return_value = (b"\x30", 0x90, 0x00)
        self.assertTrue(mgr.put_key(0x00, 0x01, 0x30, [STATIC_KEY.hex()], 0x88))

        mgr.tp.transmit.return_value = (b"\x30\x00\x00\x00", 0x90, 0x00)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(mgr.put_key(0x00, 0x01, 0x30, [STATIC_KEY.hex()], 0x88))

    def test_key_version_ranges_are_enforced(self) -> None:
        mgr = self._manager_with_dek()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(mgr.put_key(0x00, 0x01, 0x80, [STATIC_KEY.hex()], 0x88))
            self.assertFalse(mgr.put_key(0x80, 0x01, 0x30, [STATIC_KEY.hex()], 0x88))
            self.assertFalse(mgr.put_key(0x00, 0x80, 0x30, [STATIC_KEY.hex()], 0x88))
        mgr.tp.transmit.assert_not_called()


class SecureChannelCommandTests(unittest.TestCase):
    """GP Amd D v1.1.2 Table 7-2 and GPC v2.3.1 §11.3 GET DATA."""

    def test_initialize_update_is_case_4(self) -> None:
        mgr = _manager((b"", 0x6A, 0x88))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(mgr.authenticate_scp03())
        init_updates = [apdu for apdu in _sent(mgr) if apdu.startswith("8050")]
        self.assertEqual([apdu[4:6] for apdu in init_updates], ["30", "00"])
        for apdu in init_updates:
            self.assertEqual(apdu[6:10], "0008")
            self.assertEqual(len(apdu), (5 + 8 + 1) * 2)
            self.assertTrue(apdu.endswith("00"))

    def test_get_cplc_prints_the_raw_value(self) -> None:
        cplc = bytes.fromhex("9F7F2A" + "11" * 42)
        mgr = _manager((cplc, 0x90, 0x00))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mgr.get_cplc()
        self.assertIn("42 bytes", out.getvalue())
        self.assertIn("11" * 42, out.getvalue())


class KeyInformationTemplateTests(unittest.TestCase):
    """GPC v2.3.1 §11.3.3.1.1 Table 11-28 and Table 11-16."""

    def test_table_11_16_key_type_names(self) -> None:
        mgr = _manager()
        entries = mgr._parse_key_template_entries(
            bytes.fromhex("E00C" + "C004" + "0130" + "A380" + "C004" + "0231" + "B520")
        )
        self.assertEqual(entries[0]["components"][0]["type"], "RSA private exponent")
        self.assertEqual(entries[0]["components"][0]["length"], 0x80)
        self.assertEqual(entries[1]["components"][0]["type"], "ECC parameter G")

    def test_f0_component_carries_a_parameter_reference(self) -> None:
        mgr = _manager()
        entries = mgr._parse_key_template_entries(
            bytes.fromhex("E008" + "C006" + "0130" + "B120" + "F001")
        )
        reference = entries[0]["components"][1]
        self.assertEqual(reference["type"], "ECC parameters reference")
        self.assertEqual(reference["key_parameter_reference"], "01")


class SessionSecurityLevelTests(unittest.TestCase):
    """GP Amd D v1.1.2 Table 7-6, §6.2.8 and GPC v2.3.1 Annex B.2.3."""

    def _session(self) -> Scp03Session:
        session = Scp03Session({"kenc": STATIC_KEY, "kmac": STATIC_KEY, "dek": DEK})
        session.i_parameter = 0x60
        return session

    def test_only_external_authenticate_levels_are_accepted(self) -> None:
        session = self._session()
        for level in (0x00, 0x01, 0x03, 0x11, 0x13, 0x33):
            with self.subTest(level=level):
                session.sec_level = level
                session._validate_security_level()
        for level in (0x02, 0x10, 0x12, 0x20, 0x21, 0x23, 0x30, 0x31):
            with self.subTest(level=level):
                session.sec_level = level
                with self.assertRaises(Scp03Error):
                    session._validate_security_level()

    def test_dek_wrapping_is_aes_cbc_over_whole_blocks(self) -> None:
        session = self._session()
        self.assertEqual(
            session.encrypt_key_data(STATIC_KEY), _aes_cbc_zero_iv(DEK, STATIC_KEY)
        )
        with self.assertRaises(Scp03Error):
            session.encrypt_key_data(bytes(24))

    def test_pad80_follows_annex_b_2_3(self) -> None:
        self.assertEqual(Scp03Session._pad80(b""), b"\x80" + b"\x00" * 15)
        self.assertEqual(Scp03Session._pad80(b"\x01"), b"\x01\x80" + b"\x00" * 14)
        self.assertEqual(
            Scp03Session._pad80(bytes(16)), bytes(16) + b"\x80" + b"\x00" * 15
        )

    def test_secure_messaging_cla_keeps_the_logical_channel_off_the_mac(self) -> None:
        self.assertEqual(Scp03Session._secure_messaging_cla(0x81), (0x84, 0x85))
        self.assertEqual(Scp03Session._secure_messaging_cla(0xC0), (0x84, 0xE0))
        self.assertEqual(Scp03Session._secure_messaging_cla(0xC3), (0x84, 0xE3))


class CapParserSpecTests(unittest.TestCase):
    """JCVM 3.1 §6.2 to §6.6 and GPC v2.3.1 §11.6."""

    def test_component_tags_follow_table_6_1(self) -> None:
        self.assertEqual(CapFileParser.TAG_NAMES[0x09], "RefLocation.cap")
        self.assertEqual(CapFileParser.TAG_NAMES[0x0A], "Export.cap")
        self.assertEqual(CapFileParser.TAG_NAMES[0x0B], "Descriptor.cap")
        self.assertEqual(CapFileParser.TAG_NAMES[0x0D], "StaticResources.capx")

    def test_reference_install_order_follows_section_6_3(self) -> None:
        self.assertEqual(
            CapFileParser.ORDER,
            [
                "Header.cap",
                "Directory.cap",
                "Import.cap",
                "Applet.cap",
                "Class.cap",
                "Method.cap",
                "StaticField.cap",
                "Export.cap",
                "ConstantPool.cap",
                "RefLocation.cap",
                "Descriptor.cap",
            ],
        )

    def test_extended_format_header_is_rejected(self) -> None:
        payload = b"\xDE\xCA\xFF\xED" + b"\x03\x02" + b"\x08" + b"\x00\x01" + bytes([5]) + PACKAGE_AID
        with self.assertRaisesRegex(ValueError, "ACC_EXTENDED"):
            CapFileParser._extract_pkg_aid(_component(0x01, payload))

        compact = b"\xDE\xCA\xFF\xED" + b"\x03\x02" + b"\x04" + b"\x00\x01" + bytes([5]) + PACKAGE_AID
        self.assertEqual(CapFileParser._extract_pkg_aid(_component(0x01, compact)), PACKAGE_AID)

    def test_extended_format_members_are_rejected(self) -> None:
        header_payload = HEADER_PREFIX + bytes([len(PACKAGE_AID)]) + PACKAGE_AID
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "extended.cap"
            with zipfile.ZipFile(archive, "w") as cap_zip:
                cap_zip.writestr("pkg/javacard/Header.cap", _component(0x01, header_payload))
                cap_zip.writestr("pkg/javacard/StaticResources.capx", b"\x0D\x00\x00\x00\x02\x00\x00")
            with self.assertRaisesRegex(ValueError, "capx"):
                CapFileParser.parse_with_metadata(str(archive))

    def test_load_chunks_reassemble_the_load_block(self) -> None:
        header_payload = HEADER_PREFIX + bytes([len(PACKAGE_AID)]) + PACKAGE_AID
        method_payload = bytes(range(256)) * 3
        component_blob = _component(0x01, header_payload) + _component(0x07, method_payload)
        load_block = CapFileParser._wrap_load_file_block(component_blob)
        parsed = CapFileParser._build_parse_result(
            load_block=load_block,
            component_blob=component_blob,
            pkg_aid=PACKAGE_AID,
            applet_aids=[],
            ordered_names=["Header.cap", "Method.cap"],
        )

        chunks = CapFileParser.plan_load_chunks(parsed, max_chunk_size=100)

        self.assertEqual(b"".join(chunk.payload for chunk in chunks), load_block)
        self.assertEqual(chunks[0].start_offset, 0)
        for previous, current in zip(chunks, chunks[1:]):
            self.assertEqual(previous.end_offset, current.start_offset)
        self.assertTrue(all(len(chunk.payload) <= 100 for chunk in chunks))


if __name__ == "__main__":
    unittest.main()
