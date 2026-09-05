# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Secure messaging: structure without keys, plaintext with a sidecar.

Two halves, tested separately because they fail for different reasons.

Without keys the dissector still reports that a command is wrapped and
breaks out its C-MAC and ciphertext. That needs no crypto and must work
on every capture.

With keys, the plaintext comes from a sidecar built by
``Tools/ApduDissector/sidecar.py``, because Wireshark's Lua binding has
no AES, no CMAC and no hash. The sidecar is bound to its capture by
matching the on-wire ciphered command, so a sidecar from a different
capture contributes nothing rather than lying -- which is the property
these tests care about most.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    write_capture,
)

S_ENC = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
S_MAC = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
S_RMAC = bytes.fromhex("202122232425262728292A2B2C2D2E2F")


def _wrap_command(session, plaintext: bytes) -> bytes:
    """Produce a genuine SCP03-wrapped command for *plaintext*.

    Built with the engine's own primitives so the fixture cannot drift
    away from what the engine will accept when it unwraps it.
    """
    from Tools.HilBridge import scp_replay

    cla = plaintext[0] | 0x04
    header = bytes([cla, plaintext[1], plaintext[2], plaintext[3]])
    body = plaintext[5:] if len(plaintext) > 5 else b""
    # No C-DECRYPTION: the cipher bit stays clear, so the body travels
    # authenticated but in the clear and only the MAC is added.
    lc = len(body) + 8
    mac_input = session["chaining"] + header + bytes([lc]) + body
    full_mac = scp_replay._aes_cmac(S_MAC, mac_input)
    session["chaining"] = full_mac
    return header + bytes([lc]) + body + full_mac[:8]


def _keybag(path: Path) -> Path:
    document = {
        "version": 1,
        "sessions": [
            {
                "label": "SCP03 to ISD-R",
                "protocol": "scp03",
                "match": {},
                "keys": {
                    "s_enc": S_ENC.hex().upper(),
                    "s_mac": S_MAC.hex().upper(),
                    "s_rmac": S_RMAC.hex().upper(),
                },
                "initial_state": {"ssc": 0, "chaining_value": "00" * 16},
            }
        ],
    }
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    path.chmod(0o644)
    return path


class StructureWithoutKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "wrapped.pcap",
            [
                Exchange(
                    bytes.fromhex("84E2910018") + bytes(range(0x18)),
                    bytes.fromhex("9000"),
                ),
                Exchange(
                    bytes.fromhex("80E2910004") + bytes.fromhex("AABBCCDD"),
                    bytes.fromhex("9000"),
                ),
            ],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_a_wrapped_command_is_identified(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.sm.protocol"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(len(values), 1, "only the 0x84 command is wrapped")

    def test_the_mac_is_broken_out(self) -> None:
        text = decode_text(self.capture, display_filter="frame.number==1")
        self.assertIn("C-MAC", text)

    def test_an_unwrapped_command_gets_no_secure_messaging_subtree(self) -> None:
        # Asserted on the subtree's own field rather than the words
        # "Secure messaging", which also appear in the class-byte
        # breakdown of every command as "Secure messaging: None".
        rows = decode_fields(
            self.capture, ["frame.number", "yapdu.sm.protocol"]
        )
        by_frame = {row[0]: row[1] for row in rows if len(row) > 1}
        self.assertTrue(by_frame["1"])
        self.assertEqual(by_frame["2"], "")

    def test_secure_messaging_is_read_the_way_the_class_byte_defines_it(
        self,
    ) -> None:
        """The pair a test for bit 3 alone gets wrong in both directions.

        ISO/IEC 7816-4 Table 3 gives the first interindustry form four
        secure-messaging values in bits 4 and 3, so CLA '08' -- header
        not authenticated -- is secure messaging and a bit-3 test misses
        it. The further interindustry form uses a single bit instead, so
        CLA '44' is logical channel 8 with no secure messaging at all,
        and a bit-3 test carves a phantom eight-byte C-MAC off ordinary
        command data.
        """
        with tempfile.TemporaryDirectory() as directory:
            capture = write_capture(
                Path(directory) / "cla.pcap",
                [
                    Exchange(
                        bytes.fromhex("08E2910018") + bytes(range(0x18)),
                        bytes.fromhex("9000"),
                    ),
                    Exchange(
                        bytes.fromhex("44E2910018") + bytes(range(0x18)),
                        bytes.fromhex("9000"),
                    ),
                ],
            )
            rows = decode_fields(capture, ["frame.number", "yapdu.sm.protocol"])
            by_frame = {row[0]: row[1] for row in rows if len(row) > 1}
        self.assertTrue(by_frame["1"], "CLA '08' is secure messaging type '10'")
        self.assertEqual(
            by_frame["2"], "", "CLA '44' is channel 8, not secure messaging"
        )

    def test_the_sidecar_status_says_none_is_configured(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.sm.sidecar_status"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertTrue(values)
        self.assertIn("no sidecar configured", values[0])


class PlaintextFromSidecar(unittest.TestCase):
    """The end-to-end path: keybag, sidecar, decoded plaintext."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        directory = Path(cls._directory.name)

        session = {"chaining": b"\x00" * 16}
        # An ES10c GetProfilesInfo call, wrapped.
        cls.plaintext = bytes.fromhex("80E2910009") + bytes.fromhex(
            "BF2D06A0045A020102"
        )
        wrapped = _wrap_command(session, cls.plaintext)
        cls.capture = write_capture(
            directory / "scp.pcap",
            [Exchange(wrapped, bytes.fromhex("9000"))],
        )
        cls.keybag = _keybag(directory / "scp.keys.json")

        # Gate before building the sidecar, not after: build_sidecar runs
        # tshark itself, so a host without it raised TsharkMissingError out
        # of setUpClass instead of skipping the class.
        require_working_tshark(cls.capture)

        from Tools.ApduDissector.sidecar import build_sidecar

        cls.sidecar_path = directory / "scp.sidecar.json"
        cls.summary = build_sidecar(
            pcap_path=cls.capture,
            keybag_path=cls.keybag,
            output_path=cls.sidecar_path,
        )
        cls.sidecar_path.chmod(0o644)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_the_sidecar_recovered_the_exchange(self) -> None:
        self.assertEqual(self.summary.frames_wrapped, 1)
        self.assertEqual(self.summary.frames_recovered, 1)
        self.assertEqual(self.summary.mac_failures, 0)

    def test_the_recovered_plaintext_is_the_original_command(self) -> None:
        document = json.loads(self.sidecar_path.read_text(encoding="utf-8"))
        entry = document["frames"]["1"]
        self.assertEqual(
            bytes.fromhex(entry["command_plaintext"]), self.plaintext
        )
        self.assertTrue(entry["mac_ok"])

    def _decode_with_sidecar(self, sidecar: Path) -> str:
        from tests.apdu_dissector_support import DISSECTOR_PATH, run_tshark

        result = run_tshark(
            [
                "-X",
                f"lua_script:{DISSECTOR_PATH}",
                "-o",
                f"yapdu.sidecar_path:{sidecar}",
                "-r",
                str(self.capture),
                "-V",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr[:1000])
        self.assertNotIn("Lua Error", result.stderr)
        return result.stdout

    def test_the_dissector_shows_the_decrypted_command(self) -> None:
        text = self._decode_with_sidecar(self.sidecar_path)
        self.assertIn("Decrypted command APDU", text)
        self.assertIn("STORE_DATA", text)

    def test_the_decrypted_payload_is_decoded_not_just_shown(self) -> None:
        """The whole point: a ciphered ES10c call reads as an ES10c call."""
        text = self._decode_with_sidecar(self.sidecar_path)
        self.assertIn("ProfileInfoList", text)

    def test_the_keybag_session_is_named(self) -> None:
        text = self._decode_with_sidecar(self.sidecar_path)
        self.assertIn("SCP03 to ISD-R", text)

    def test_a_sidecar_from_another_capture_is_refused(self) -> None:
        """Frame numbers alone would attribute plaintext to the wrong frame.

        Lua cannot hash, so the sidecar records the ciphered command and
        the dissector compares it against the bytes in front of it.
        """
        document = json.loads(self.sidecar_path.read_text(encoding="utf-8"))
        document["frames"]["1"]["command_hex"] = "84E2910018" + "00" * 24
        foreign = Path(self._directory.name) / "foreign.sidecar.json"
        foreign.write_text(json.dumps(document), encoding="utf-8")
        foreign.chmod(0o644)

        text = self._decode_with_sidecar(foreign)
        self.assertIn("does not match", text)
        self.assertNotIn("Decrypted command APDU", text)

    def test_an_entry_with_no_command_hex_is_refused(self) -> None:
        """An unverifiable entry is the case the check exists for.

        The comparison was skipped when ``command_hex`` was absent or
        blank, which made the whole anti-cross-capture guarantee opt-in:
        a sidecar could reinstate the exact risk it was built to rule
        out simply by omitting the field.
        """
        document = json.loads(self.sidecar_path.read_text(encoding="utf-8"))
        for entry in document["frames"].values():
            entry.pop("command_hex", None)
        unverifiable = Path(self._directory.name) / "unverifiable.sidecar.json"
        unverifiable.write_text(json.dumps(document), encoding="utf-8")
        unverifiable.chmod(0o644)

        text = self._decode_with_sidecar(unverifiable)
        self.assertNotIn("Decrypted command APDU", text)

    def test_a_frames_array_is_refused_rather_than_reported_as_loaded(
        self,
    ) -> None:
        """It parses as a table and then matches nothing.

        Entries are keyed by frame number as a string, so an array is a
        silent no-op -- and the status line used to call it a successful
        load, which is the least helpful thing it could say.
        """
        array_form = Path(self._directory.name) / "array.sidecar.json"
        array_form.write_text(
            json.dumps(
                {"format": "yggdrasim-apdu-sidecar/v1", "frames": [{"a": 1}]}
            ),
            encoding="utf-8",
        )
        array_form.chmod(0o644)
        text = self._decode_with_sidecar(array_form)
        self.assertIn("JSON array", text)

    def test_a_corrupt_sidecar_degrades_to_a_status_line(self) -> None:
        broken = Path(self._directory.name) / "broken.sidecar.json"
        broken.write_text("{ this is not json", encoding="utf-8")
        broken.chmod(0o644)
        text = self._decode_with_sidecar(broken)
        self.assertIn("sidecar unreadable", text)

    def test_an_unknown_sidecar_format_is_refused(self) -> None:
        wrong = Path(self._directory.name) / "wrong.sidecar.json"
        wrong.write_text(
            json.dumps({"format": "something-else/v9", "frames": {}}),
            encoding="utf-8",
        )
        wrong.chmod(0o644)
        text = self._decode_with_sidecar(wrong)
        self.assertIn("unsupported sidecar format", text)


class SidecarBuilder(unittest.TestCase):
    """Pure Python: no tshark needed beyond reading the capture."""

    def test_the_splitter_only_claims_wrapped_commands(self) -> None:
        from Tools.ApduDissector.sidecar import split_exchange

        wrapped = bytes.fromhex("84E2910004AABBCCDD") + bytes(8) + b"\x90\x00"
        self.assertIsNotNone(split_exchange(wrapped))
        plain = bytes.fromhex("00A4000402") + bytes.fromhex("3F00") + b"\x90\x00"
        self.assertIsNone(split_exchange(plain))

    def test_short_input_is_rejected_rather_than_indexed(self) -> None:
        from Tools.ApduDissector.sidecar import split_exchange

        for payload in (b"", b"\x84", b"\x84\xE2\x91\x00", b"\x84\xE2\x91\x00\xFF"):
            with self.subTest(length=len(payload)):
                self.assertIsNone(split_exchange(payload))

    def test_a_keybag_with_no_sessions_is_an_error(self) -> None:
        from Tools.ApduDissector.sidecar import SidecarError, build_sidecar

        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.keys.json"
            empty.write_text(json.dumps({"version": 1, "sessions": []}), "utf-8")
            capture = write_capture(
                Path(directory) / "c.pcap",
                [Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("3F00"),
                          bytes.fromhex("9000"))],
            )
            with self.assertRaises(SidecarError):
                build_sidecar(
                    pcap_path=capture,
                    keybag_path=empty,
                    output_path=Path(directory) / "out.json",
                )


if __name__ == "__main__":
    unittest.main()
