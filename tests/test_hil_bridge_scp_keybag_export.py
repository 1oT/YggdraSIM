# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from Tools.HilBridge.scp_keybag_export import (
    KeybagExportEntry,
    build_keybag_document,
    entry_from_scp03_session,
    entry_from_scp11_bsp,
    write_keybag_file,
)
from Tools.HilBridge.scp_replay import KeybagError, load_keybag


_DUMMY_ENC = bytes.fromhex("0F0E0D0C0B0A09080706050403020100")
_DUMMY_MAC = bytes.fromhex("00112233445566778899AABBCCDDEEFF")


class ExportScp03EntryTests(unittest.TestCase):
    def test_entry_copies_session_keys_and_counters(self) -> None:
        session = SimpleNamespace(
            is_authenticated=True,
            s_enc=_DUMMY_ENC,
            s_mac=_DUMMY_MAC,
            s_rmac=_DUMMY_MAC,
            ssc=0,
            chaining_value=b"\x00" * 16,
        )
        entry = entry_from_scp03_session(
            session,
            label="ISD-R SCP03",
            match_card_session_index=1,
        )
        self.assertEqual(entry.protocol, "scp03")
        self.assertEqual(entry.s_enc_hex, _DUMMY_ENC.hex().upper())
        self.assertEqual(entry.s_mac_hex, _DUMMY_MAC.hex().upper())
        self.assertEqual(entry.match_card_session_index, 1)

    def test_entry_refuses_unauthenticated_session(self) -> None:
        session = SimpleNamespace(
            is_authenticated=False,
            s_enc=_DUMMY_ENC,
            s_mac=_DUMMY_MAC,
        )
        with self.assertRaises(RuntimeError):
            entry_from_scp03_session(session)


class ExportScp11EntryTests(unittest.TestCase):
    def test_entry_reads_keys_from_bsp_sub_objects(self) -> None:
        bsp_session = SimpleNamespace(
            c_algo=SimpleNamespace(s_enc=_DUMMY_ENC, block_nr=0),
            m_algo=SimpleNamespace(
                s_mac=_DUMMY_MAC,
                mac_chain=b"\x00" * 16,
            ),
        )
        entry = entry_from_scp11_bsp(
            bsp_session,
            label="eUICC BSP",
            match_aid_hex="A0000005591010FFFFFFFF8900000100",
        )
        self.assertEqual(entry.protocol, "scp11c")
        self.assertEqual(entry.match_aid_hex, "A0000005591010FFFFFFFF8900000100")
        self.assertEqual(entry.s_enc_hex, _DUMMY_ENC.hex().upper())


class KeybagRoundTripTests(unittest.TestCase):
    def test_written_keybag_reloads_through_load_keybag(self) -> None:
        entry = KeybagExportEntry(
            label="demo",
            protocol="scp03",
            s_enc_hex=_DUMMY_ENC.hex().upper(),
            s_mac_hex=_DUMMY_MAC.hex().upper(),
            s_rmac_hex=_DUMMY_MAC.hex().upper(),
            match_aid_hex="A000000151000000",
            match_card_session_index=1,
            match_first_frame=12,
            initial_ssc=0,
            initial_chaining_hex="00" * 16,
        )
        document = build_keybag_document([entry])
        self.assertEqual(document["version"], 1)
        self.assertEqual(len(document["sessions"]), 1)
        self.assertEqual(document["sessions"][0]["match"]["first_frame"], 12)
        with tempfile.TemporaryDirectory() as tmp_dir:
            keybag_path = Path(tmp_dir) / "capture.pcap.keys.json"
            written_path = write_keybag_file(str(keybag_path), [entry])
            self.assertEqual(written_path, str(keybag_path))
            parsed = load_keybag(str(keybag_path))
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].match_aid, "A000000151000000")
            self.assertEqual(parsed[0].match_first_frame, 12)
            self.assertEqual(parsed[0].s_enc, _DUMMY_ENC)

    def test_write_merges_with_existing_sessions(self) -> None:
        existing_entry = KeybagExportEntry(
            label="alpha",
            protocol="scp03",
            s_enc_hex=_DUMMY_ENC.hex().upper(),
            s_mac_hex=_DUMMY_MAC.hex().upper(),
        )
        new_entry = KeybagExportEntry(
            label="beta",
            protocol="scp11c",
            s_enc_hex=_DUMMY_ENC.hex().upper(),
            s_mac_hex=_DUMMY_MAC.hex().upper(),
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            keybag_path = Path(tmp_dir) / "session.keys.json"
            write_keybag_file(str(keybag_path), [existing_entry])
            write_keybag_file(str(keybag_path), [new_entry], merge_existing=True)
            with keybag_path.open("rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))
            self.assertEqual(
                [session["label"] for session in document["sessions"]],
                ["alpha", "beta"],
            )

    def test_broken_existing_keybag_refuses_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            keybag_path = Path(tmp_dir) / "broken.keys.json"
            keybag_path.write_text("not json at all")
            entry = KeybagExportEntry(
                label="demo",
                protocol="scp03",
                s_enc_hex=_DUMMY_ENC.hex().upper(),
                s_mac_hex=_DUMMY_MAC.hex().upper(),
            )
            with self.assertRaises(RuntimeError):
                write_keybag_file(str(keybag_path), [entry], merge_existing=True)


class KeybagValidationAfterExportTests(unittest.TestCase):
    def test_load_keybag_strict_accepts_exported_document(self) -> None:
        entry = KeybagExportEntry(
            label="demo",
            protocol="scp03",
            s_enc_hex=_DUMMY_ENC.hex().upper(),
            s_mac_hex=_DUMMY_MAC.hex().upper(),
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            keybag_path = Path(tmp_dir) / "strict.keys.json"
            write_keybag_file(str(keybag_path), [entry])
            try:
                sessions = load_keybag(str(keybag_path))
            except KeybagError as exc:
                self.fail(f"Strict loader rejected exported keybag: {exc}")
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].protocol, "scp03")


if __name__ == "__main__":
    unittest.main()
