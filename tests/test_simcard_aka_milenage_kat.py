"""3GPP TS 35.208 Milenage Test Set 1 known-answer tests, end-to-end.

The simulator's ``SIMCARD.auth`` Milenage primitive is already locked
against unit-level vectors in :mod:`tests.test_simcard_auth_toolkit`.
This file goes one layer up and verifies that the *full pipeline* a
real attach exercises produces the spec-mandated bytes:

1. A profile with the Test Set 1 ``(K, OPc)`` is the active profile.
2. ``ADF.USIM`` is the selected application (auth.py refuses to run
   USIM-context AKA otherwise).
3. The terminal sends ``00 88 00 81`` with a properly framed
   ``RAND || AUTN`` payload.
4. The simulator returns ``DB || RES || CK || IK || Kc`` matching
   TS 35.208 §4.3 Test Set 1 byte-for-byte.

Passing this test is the strongest single signal that a profile
downloaded from a live SM-DP+ - whose ``algoConfiguration`` carries
the operator's ``(K, OPc)`` - will satisfy a real AuC's expected
authentication vector, and therefore that the simulator can attach
through a HIL bridge to a real modem and a real network.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.auth import milenage_vectors
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimProfileAuthConfig


# 3GPP TS 35.208 §4.3 Milenage Test Set 1 - inputs.
_TS1_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_TS1_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
_TS1_RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
_TS1_SQN = bytes.fromhex("FF9BB4D0B607")
_TS1_AMF = bytes.fromhex("B9B9")

# 3GPP TS 35.208 §4.3 Milenage Test Set 1 - expected outputs.
_TS1_MAC_A = bytes.fromhex("4A9FFAC354DFAFB3")
_TS1_RES = bytes.fromhex("A54211D5E3BA50BF")
_TS1_CK = bytes.fromhex("B40BA9A3C58B2A05BBF0D987B21BF8CB")
_TS1_IK = bytes.fromhex("F769BCD7510446041276727 11C6D3441".replace(" ", ""))
_TS1_AK = bytes.fromhex("AA689C648370")


def _build_authenticate_apdu(rand: bytes, autn: bytes) -> bytes:
    """ETSI TS 102 221 §11.1.16 / TS 31.102 §7.1.2.1 USIM authenticate.

    ``CLA INS P1 P2 Lc 10 RAND[16] 10 AUTN[16] Le``
    """
    payload = bytes([0x10]) + rand + bytes([0x10]) + autn
    return bytes([0x00, 0x88, 0x00, 0x81, len(payload)]) + payload + bytes([0x00])


def _decode_aka_success_response(response: bytes) -> dict[str, bytes]:
    """Parse ``DB 08 RES 10 CK 10 IK 08 Kc``."""
    payload = bytes(response or b"")
    if len(payload) < 1 or payload[0] != 0xDB:
        raise AssertionError(f"Expected success tag 0xDB, got payload={payload.hex().upper()}")
    parsed: dict[str, bytes] = {}
    cursor = 1
    for field in ("res", "ck", "ik", "kc"):
        length = payload[cursor]
        cursor += 1
        parsed[field] = payload[cursor : cursor + length]
        cursor += length
    return parsed


class MilenagePrimitiveAgreesWithSpec(unittest.TestCase):
    """Sanity gate before the engine-level test - locks the primitive."""

    def setUp(self) -> None:
        self.vectors = milenage_vectors(_TS1_K, _TS1_OPC, _TS1_RAND, _TS1_SQN, _TS1_AMF)

    def test_mac_a_matches_ts_35208_test_set_1(self) -> None:
        self.assertEqual(self.vectors.mac_a, _TS1_MAC_A)

    def test_res_matches_ts_35208_test_set_1(self) -> None:
        self.assertEqual(self.vectors.res, _TS1_RES)

    def test_ck_matches_ts_35208_test_set_1(self) -> None:
        self.assertEqual(self.vectors.ck, _TS1_CK)

    def test_ik_matches_ts_35208_test_set_1(self) -> None:
        self.assertEqual(self.vectors.ik, _TS1_IK)

    def test_ak_matches_ts_35208_test_set_1(self) -> None:
        self.assertEqual(self.vectors.ak, _TS1_AK)


class EngineAuthenticateMatchesSpec(unittest.TestCase):
    """End-to-end: profile + SELECT ADF.USIM + AUTHENTICATE -> spec bytes."""

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

        # Pin the active profile's auth_config to TS 35.208 Test Set 1
        # values regardless of what the default ships with - this is
        # what an SM-DP+ would do when delivering a SAIP profile with
        # an operator-issued (K, OPc).
        active = self._active_profile()
        active.auth_config = SimProfileAuthConfig(
            algorithm="milenage",
            ki=_TS1_K,
            opc=_TS1_OPC,
            amf=_TS1_AMF,
            # Use SQN=0 so the simulator accepts the test vector's
            # SQN of FF9BB4D0B607 as fresh (network value > stored
            # value triggers the success path in
            # ``SIMCARD.auth._run_usim_authentication``).
            sqn=b"\x00" * 6,
        )

        # Required by ``SIMCARD.auth._selected_application_name`` -
        # USIM-context AKA only runs when ADF.USIM is current.
        select_usim = bytes([0x00, 0xA4, 0x04, 0x04, len(bytes.fromhex(USIM_AID))]) + bytes.fromhex(USIM_AID) + bytes([0x00])
        _, sw1, sw2 = self.engine.transmit(select_usim)
        self.assertEqual((sw1, sw2), (0x90, 0x00), "ADF.USIM must select cleanly before AKA.")

    def tearDown(self) -> None:
        self._td.cleanup()

    def _active_profile(self):
        # Profile activation defaults to the in-tree profile during
        # engine construction; pick whichever entry is currently
        # marked enabled.
        for profile in self.engine.state.profiles:
            if str(profile.state or "").strip().lower() == "enabled":
                return profile
        # Fall back to the AID the engine recorded as active.
        active_aid = str(self.engine.state.active_profile_aid or "").strip().upper()
        for profile in self.engine.state.profiles:
            if str(profile.aid or "").strip().upper() == active_aid:
                return profile
        raise AssertionError("Engine started without an active profile.")

    def _send_authenticate(self, rand: bytes, autn: bytes) -> tuple[bytes, int, int]:
        return self.engine.transmit(_build_authenticate_apdu(rand, autn))

    def _build_autn(self) -> bytes:
        # AUTN = (SQN xor AK) || AMF || MAC-A.
        # Per TS 33.102 Annex C, AK comes from f5(K, OPc, RAND) and is
        # invariant under SQN, so it can be derived from the primitive
        # output directly.
        primitive = milenage_vectors(_TS1_K, _TS1_OPC, _TS1_RAND, _TS1_SQN, _TS1_AMF)
        concealed_sqn = bytes(a ^ b for a, b in zip(_TS1_SQN, primitive.ak))
        return concealed_sqn + _TS1_AMF + _TS1_MAC_A

    def test_authenticate_success_response_starts_with_db_tag(self) -> None:
        autn = self._build_autn()
        data, sw1, sw2 = self._send_authenticate(_TS1_RAND, autn)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[0], 0xDB)

    def test_authenticate_returns_ts_35208_res(self) -> None:
        autn = self._build_autn()
        data, _, _ = self._send_authenticate(_TS1_RAND, autn)
        decoded = _decode_aka_success_response(data)
        self.assertEqual(decoded["res"], _TS1_RES)

    def test_authenticate_returns_ts_35208_ck(self) -> None:
        autn = self._build_autn()
        data, _, _ = self._send_authenticate(_TS1_RAND, autn)
        decoded = _decode_aka_success_response(data)
        self.assertEqual(decoded["ck"], _TS1_CK)

    def test_authenticate_returns_ts_35208_ik(self) -> None:
        autn = self._build_autn()
        data, _, _ = self._send_authenticate(_TS1_RAND, autn)
        decoded = _decode_aka_success_response(data)
        self.assertEqual(decoded["ik"], _TS1_IK)

    def test_invalid_mac_a_yields_authentication_error_9862(self) -> None:
        autn = self._build_autn()
        # Flip the last byte of MAC-A so the AUTN no longer authenticates.
        tampered = bytearray(autn)
        tampered[-1] ^= 0xFF
        _, sw1, sw2 = self._send_authenticate(_TS1_RAND, bytes(tampered))
        self.assertEqual((sw1, sw2), (0x98, 0x62))


if __name__ == "__main__":
    unittest.main()
