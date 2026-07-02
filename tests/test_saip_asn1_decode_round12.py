# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Round-12 EF-decoder field-level parity tests.

Targets the byte-0 coding-indicator split-out for EF.MST and the
per-PLMN entry decomposition for EF.URSP, both anchored against
3GPP TS 31.102 v18.4.
"""
from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_ef_mst,
    _decode_ef_ursp,
    _decode_known_ef_payload,
)


class McsServiceTableTests(unittest.TestCase):
    def test_byte_0_xml_coding_and_three_active_services(self) -> None:
        # 00 = XML coding (TS 24.483); byte 1 sets services 1, 2, 3.
        decoded = _decode_ef_mst("0007")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["codingOfMcsObjects"]["hex"], "00")
        self.assertIn("XML", decoded["codingOfMcsObjects"]["name"])
        active = decoded["activeServices"]
        self.assertTrue(any("1: MCPTT UE configuration data" in row for row in active))
        self.assertTrue(any("2: MCPTT User profile data" in row for row in active))
        self.assertTrue(any("3: MCS Group configuration data" in row for row in active))

    def test_reserved_coding_byte_surfaced_with_label(self) -> None:
        decoded = _decode_ef_mst("FF00")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["codingOfMcsObjects"]["hex"], "FF")
        self.assertIn("Reserved", decoded["codingOfMcsObjects"]["name"])

    def test_no_services_when_only_coding_byte_present(self) -> None:
        decoded = _decode_ef_mst("00")
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["activeCount"], 0)


class UrspPerPlmnTests(unittest.TestCase):
    @staticmethod
    def _build_ursp(entries: list[tuple[str, bytes]]) -> str:
        """Build an EF.URSP hex payload from (PLMN-hex, rules-bytes) pairs.

        Wraps the per-PLMN concatenation in tag '80' with a BER length
        encoding picked to fit (short form when ≤127 bytes).
        """
        body = b""
        for plmn_hex, rules in entries:
            plmn_bytes = bytes.fromhex(plmn_hex)
            assert len(plmn_bytes) == 3
            length_bytes = len(rules).to_bytes(2, "big")
            body += plmn_bytes + length_bytes + rules
        if len(body) < 0x80:
            envelope = bytes([0x80, len(body)]) + body
        elif len(body) < 0x100:
            envelope = bytes([0x80, 0x81, len(body)]) + body
        else:
            envelope = bytes([0x80, 0x82, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body
        return envelope.hex().upper()

    def test_single_plmn_entry_decoded_with_rules_blob(self) -> None:
        # Test PLMN 001/01 (TS 23.003 §2.2) — encoded as 00 F1 10.
        rules = bytes.fromhex("DEADBEEF")
        payload = self._build_ursp([("00F110", rules)])
        decoded = _decode_ef_ursp(payload)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["format"], "UE Route Selection Policy")
        self.assertEqual(decoded["perPlmnEntryCount"], 1)
        entry = decoded["perPlmnEntries"][0]
        self.assertEqual(entry["plmnHex"], "00F110")
        self.assertEqual(entry["rulesLength"], 4)
        self.assertEqual(entry["rulesHex"], "DEADBEEF")

    def test_multiple_plmn_entries_walked_in_order(self) -> None:
        rules_a = bytes.fromhex("01" * 4)
        rules_b = bytes.fromhex("02" * 6)
        payload = self._build_ursp([
            ("00F110", rules_a),
            ("99F999", rules_b),
        ])
        decoded = _decode_ef_ursp(payload)
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["perPlmnEntryCount"], 2)
        self.assertEqual(decoded["perPlmnEntries"][0]["rulesLength"], 4)
        self.assertEqual(decoded["perPlmnEntries"][1]["rulesLength"], 6)

    def test_dispatcher_routes_ef_ursp_token(self) -> None:
        rules = bytes.fromhex("AA" * 8)
        payload = self._build_ursp([("00F110", rules)])
        decoded = _decode_known_ef_payload(
            ef_key="ef-ursp",
            fid=None,
            hex_clean=payload,
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["perPlmnEntryCount"], 1)
        self.assertIn("§4.4.11.12", decoded["specReference"])

    def test_truncated_per_plmn_length_returns_none(self) -> None:
        # Outer envelope claims a value length that exceeds the
        # available bytes — the decoder must reject rather than
        # silently truncate.
        self.assertIsNone(_decode_ef_ursp("8005AABBCC"))

    def test_non_envelope_payload_falls_through(self) -> None:
        # Random bytes that do not start with tag '80' must return
        # None so the dispatcher falls back to the generic walker.
        self.assertIsNone(_decode_ef_ursp("AABB"))


if __name__ == "__main__":
    unittest.main()
