from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Tools.HilBridge.scp_replay import (
    KeybagError,
    ScpReplayEngine,
    UnwrapContext,
    load_keybag,
    load_keybag_safe,
    try_autodiscover_sidecar_keybag,
)


# Fixed pair of AES-128 keys. Not meant to match any real profile -- the
# goal is to round-trip a known wrap/unwrap through the replay engine.
_S_ENC = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
_S_MAC = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
_S_RMAC = _S_MAC


def _wrap_scp03_command_with_mac_only(
    header: bytes, enc_payload: bytes, chaining_value: bytes
) -> tuple[bytes, bytes]:
    """Mirror Scp03Session.wrap_apdu for the MAC-only (sec_level 0x10) case."""
    c = cmac.CMAC(algorithms.AES(_S_MAC))
    c.update(chaining_value + header + enc_payload)
    new_chain = c.finalize()
    return new_chain, new_chain[:8]


def _encrypt_scp03_payload(payload: bytes, post_increment_ssc: int) -> bytes:
    """Wrap bytes the same way Scp03Session.wrap_apdu does for sec_level 0x02."""
    iv_counter = (int(post_increment_ssc) - 1).to_bytes(16, "big")
    ecb_cipher = Cipher(algorithms.AES(_S_ENC), modes.ECB())
    encryptor = ecb_cipher.encryptor()
    iv = encryptor.update(iv_counter) + encryptor.finalize()
    pad_len = 16 - (len(payload) % 16)
    padded = payload + b"\x80" + (b"\x00" * (pad_len - 1))
    cbc_cipher = Cipher(algorithms.AES(_S_ENC), modes.CBC(iv))
    cbc_encryptor = cbc_cipher.encryptor()
    return cbc_encryptor.update(padded) + cbc_encryptor.finalize()


class KeybagLoaderTests(unittest.TestCase):
    def _write_keybag(self, document: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".keys.json", delete=False
        )
        json.dump(document, tmp)
        tmp.close()
        return Path(tmp.name)

    def test_load_keybag_parses_valid_entry(self) -> None:
        path = self._write_keybag(
            {
                "version": 1,
                "sessions": [
                    {
                        "label": "demo",
                        "protocol": "scp03",
                        "keys": {
                            "s_enc": _S_ENC.hex(),
                            "s_mac": _S_MAC.hex(),
                        },
                    }
                ],
            }
        )
        sessions = load_keybag(str(path))
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].label, "demo")
        self.assertEqual(sessions[0].protocol, "scp03")
        self.assertEqual(sessions[0].s_enc, _S_ENC)
        self.assertEqual(sessions[0].s_mac, _S_MAC)
        # s_rmac defaults to s_mac when omitted.
        self.assertEqual(sessions[0].s_rmac, _S_MAC)

    def test_load_keybag_rejects_unsupported_protocol(self) -> None:
        path = self._write_keybag(
            {
                "version": 1,
                "sessions": [
                    {
                        "protocol": "scp80",
                        "keys": {
                            "s_enc": _S_ENC.hex(),
                            "s_mac": _S_MAC.hex(),
                        },
                    }
                ],
            }
        )
        with self.assertRaises(KeybagError):
            load_keybag(str(path))

    def test_load_keybag_rejects_short_key(self) -> None:
        path = self._write_keybag(
            {
                "version": 1,
                "sessions": [
                    {
                        "protocol": "scp03",
                        "keys": {
                            "s_enc": "00112233",
                            "s_mac": _S_MAC.hex(),
                        },
                    }
                ],
            }
        )
        with self.assertRaises(KeybagError):
            load_keybag(str(path))

    def test_load_keybag_safe_converts_missing_file_to_summary(self) -> None:
        summary = load_keybag_safe("/tmp/definitely/does/not/exist.json")
        self.assertEqual(summary.session_count, 0)
        self.assertIn("not found", summary.error_text.lower())

    def test_autodiscover_sidecar_with_suffix_appended(self) -> None:
        tmp_dir = tempfile.mkdtemp(prefix="ygg_keybag_")
        pcap_path = Path(tmp_dir) / "capture.pcap"
        pcap_path.write_bytes(b"")
        sidecar = pcap_path.with_name(pcap_path.name + ".keys.json")
        sidecar.write_text("{}")
        resolved = try_autodiscover_sidecar_keybag(str(pcap_path))
        self.assertEqual(Path(resolved), sidecar)


class ScpReplayEngineTests(unittest.TestCase):
    def _make_engine(self, **match_overrides) -> ScpReplayEngine:
        from Tools.HilBridge.scp_replay import KeybagSession

        session = KeybagSession(
            label="test-session",
            protocol="scp03",
            s_enc=_S_ENC,
            s_mac=_S_MAC,
            s_rmac=_S_RMAC,
            match_aid=match_overrides.get("match_aid", ""),
            match_card_session_index=match_overrides.get(
                "match_card_session_index", None
            ),
            match_first_frame=match_overrides.get("match_first_frame", None),
            initial_ssc=0,
            initial_chaining_value=b"\x00" * 16,
        )
        return ScpReplayEngine([session])

    def test_unwrap_mac_only_command_succeeds(self) -> None:
        engine = self._make_engine()
        # Header matches what Scp03Session.wrap_apdu emits with sec_level
        # 0x10 (MAC only): CLA bit 0x04 set, no cipher bit, lc = enc_payload + 8.
        enc_payload = bytes.fromhex("01020304050607")
        chaining = b"\x00" * 16
        header = bytes([0x84, 0xE2, 0x00, 0x00, len(enc_payload) + 8])
        _, mac_tag = _wrap_scp03_command_with_mac_only(
            header, enc_payload, chaining
        )
        command_bytes = header + enc_payload + mac_tag
        response_bytes = bytes([0x90, 0x00])
        context = UnwrapContext(frame_number=1, card_session_index=1)
        result = engine.try_unwrap_exchange(
            command_bytes,
            response_bytes,
            context=context,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.matched_label, "test-session")
        joined_lines = "\n".join(result.lines)
        self.assertIn("C-MAC ok", joined_lines)
        self.assertIn("command plaintext", joined_lines)
        snapshots = engine.runtime_snapshots()
        self.assertEqual(snapshots[0]["command_count"], 1)
        self.assertEqual(snapshots[0]["ssc"], 1)

    def test_unwrap_encrypted_command_recovers_plaintext_prefix(self) -> None:
        engine = self._make_engine()
        plaintext = bytes.fromhex("11223344")
        ssc_after = 1
        encrypted = _encrypt_scp03_payload(plaintext, ssc_after)
        chaining = b"\x00" * 16
        header = bytes([0x86, 0xD8, 0x00, 0x00, len(encrypted) + 8])
        _, mac_tag = _wrap_scp03_command_with_mac_only(
            header, encrypted, chaining
        )
        command_bytes = header + encrypted + mac_tag
        response_bytes = bytes([0x90, 0x00])
        context = UnwrapContext(frame_number=5, card_session_index=1)
        result = engine.try_unwrap_exchange(
            command_bytes,
            response_bytes,
            context=context,
        )
        self.assertIsNotNone(result)
        joined_lines = "\n".join(result.lines)
        # The recovered plaintext APDU should end with the original 4 bytes
        # of body after the stripped CLA/INS/P1/P2/Lc header.
        self.assertIn(plaintext.hex().upper(), joined_lines.upper())

    def test_unwrap_reports_mac_mismatch_without_state_corruption(self) -> None:
        engine = self._make_engine()
        # Flip one bit inside the MAC so the replay engine rejects it.
        enc_payload = bytes.fromhex("0A0B0C")
        chaining = b"\x00" * 16
        header = bytes([0x84, 0xE2, 0x00, 0x00, len(enc_payload) + 8])
        _, mac_tag = _wrap_scp03_command_with_mac_only(
            header, enc_payload, chaining
        )
        tampered_mac = bytearray(mac_tag)
        tampered_mac[0] ^= 0x01
        command_bytes = header + enc_payload + bytes(tampered_mac)
        response_bytes = bytes([0x90, 0x00])
        context = UnwrapContext(frame_number=1, card_session_index=1)
        result = engine.try_unwrap_exchange(
            command_bytes,
            response_bytes,
            context=context,
        )
        self.assertIsNotNone(result)
        joined_lines = "\n".join(result.lines)
        self.assertIn("C-MAC mismatch", joined_lines)
        snapshots = engine.runtime_snapshots()
        self.assertEqual(snapshots[0]["mac_mismatch_count"], 1)
        self.assertEqual(snapshots[0]["command_count"], 0)

    def test_plain_apdu_is_ignored(self) -> None:
        engine = self._make_engine()
        # CLA 0x80 has no secure-messaging bit set; engine must return None.
        command_bytes = bytes.fromhex("80E20000020011")
        response_bytes = bytes([0x90, 0x00])
        context = UnwrapContext(frame_number=1, card_session_index=1)
        self.assertIsNone(
            engine.try_unwrap_exchange(
                command_bytes,
                response_bytes,
                context=context,
            )
        )

    def test_match_rules_narrow_session_selection(self) -> None:
        # When the match constraint is tighter than the current frame
        # context, the engine should refuse to apply the session instead
        # of silently advancing counters.
        engine = self._make_engine(
            match_card_session_index=7,
            match_first_frame=100,
        )
        enc_payload = bytes.fromhex("AA")
        chaining = b"\x00" * 16
        header = bytes([0x84, 0xE2, 0x00, 0x00, len(enc_payload) + 8])
        _, mac_tag = _wrap_scp03_command_with_mac_only(
            header, enc_payload, chaining
        )
        command_bytes = header + enc_payload + mac_tag
        response_bytes = bytes([0x90, 0x00])
        context = UnwrapContext(frame_number=1, card_session_index=1)
        self.assertIsNone(
            engine.try_unwrap_exchange(
                command_bytes,
                response_bytes,
                context=context,
            )
        )
        snapshots = engine.runtime_snapshots()
        self.assertEqual(snapshots[0]["command_count"], 0)
        self.assertEqual(snapshots[0]["ssc"], 0)


if __name__ == "__main__":
    unittest.main()
