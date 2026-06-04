"""End-to-end modem cold-boot + USIM attach script.

This test scripts the canonical APDU sequence a real modem issues
between power-on and the first 5G AKA, against the full
``SimulatedSimCardEngine`` driven through the
``Tools.HilBridge.sim_modem.SimulatedModemCardChannel`` wrapper. The
wrapper applies T=0-style framing (``61 XX`` followed by GET RESPONSE
chaining, per-channel pending-response queue, MANAGE CHANNEL state)
so the test exercises the same byte-flow a physical modem would
generate over ISO 7816-3.

Coverage milestones (each asserted byte-exactly):

* ATR matches ``DEFAULT_SIM_ATR``.
* SELECT MF returns FCP with file-id ``3F 00``.
* EF.DIR record #1 carries the active USIM AID under tag ``61``.
* SELECT ADF.USIM by AID returns FCP for the ADF.
* TERMINAL CAPABILITY + TERMINAL PROFILE both return ``9000``.
* Default PIN1 / UPIN status probes report that no PIN entry is
  required for headless attach.
* EF.IMSI / EF.AD / EF.UST round-trip and decode to the expected
  default identity, including the 5G/SUCI service flags.
* AUTHENTICATE INS=88 P2=81 produces a TS 31.102 §7.1.2.1 ``DB``-
  tagged response containing RES, CK, IK, Kc that match an inline
  Milenage textbook recomputation.
* SELECT DF.5GS returns FCP, EF.ROUTING-INDICATOR is readable.
* GET IDENTITY P2=01 returns a TS 24.501 §9.11.3.4-shaped null-scheme
  SUCI whose MSIN matches EF.IMSI.
* After ``derive_5g_vector`` is invoked (modelling the AUSF/SEAF
  side of the 5G HE-AV), EF.5GAUTHKEYS is readable through the modem
  channel and carries the ``80 || 81`` TLV layout from
  TS 31.102 §4.4.11.5.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.auth import build_milenage_autn, milenage_vectors
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import _resolve_active_profile
from SIMCARD.suci import ProtectionScheme, decode_msin_bcd
from SIMCARD.utils import decode_imsi_ef, read_tlv
from Tools.HilBridge.sim_modem import SimulatedModemCardChannel


class _RealEnginePyscardConnection:
    """Adapter from ``SimulatedSimCardEngine`` to the pyscard-style
    surface the HIL bridge wrapper consumes.

    Exposes the engine via ``_engine`` (the wrapper reaches in for
    ``state`` / ``fs`` / ``toolkit``) and provides ``transmit``,
    ``getATR`` and ``disconnect`` matching ``smartcard.CardConnection``.
    """

    def __init__(self, engine: SimulatedSimCardEngine) -> None:
        self._engine = engine

    def disconnect(self) -> None:
        return None

    def getATR(self) -> list[int]:
        return list(self._engine.state.atr)

    def transmit(self, apdu) -> tuple[list[int], int, int]:
        response, sw1, sw2 = self._engine.transmit(bytes(apdu))
        return list(response), int(sw1), int(sw2)


class ModemColdBootAttachScriptTests(unittest.TestCase):
    """Single-test fixture orchestrating the entire boot script.

    Tests are numbered so the unittest loader runs them in the order
    a real modem would issue them. Each step builds on the file-system
    state left by the previous step (selected DF/EF, verified PIN,
    open logical channel) -- restarting the engine between steps would
    invalidate the script.
    """

    usim_aid: bytes = b""

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory()
        root = Path(cls._td.name)
        cls.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "q.py"),
            isdr_config_path=str(root / "i.json"),
            sim_eim_identity_path=str(root / "e.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "ps"),
        )
        cls.connection = _RealEnginePyscardConnection(cls.engine)
        cls.modem = SimulatedModemCardChannel(cls.connection)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.modem.disconnect()
        cls._td.cleanup()

    # -- helpers -----------------------------------------------------

    def _exchange(self, apdu_hex: str) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self.modem.transmit(bytes.fromhex(apdu_hex))
        return bytes(data), int(sw1), int(sw2)

    def _follow_get_response(
        self,
        sw1: int,
        sw2: int,
        channel: int = 0,
    ) -> tuple[bytes, int, int]:
        """Drain a ``61 XX`` chain through GET RESPONSE.

        The HIL bridge wrapper queues responses for case-4 commands
        (SELECT, INTERNAL AUTHENTICATE, ...) and signals the modem
        with ``61 XX``; the modem must reissue ``CLA C0 00 00 XX`` to
        retrieve the queued data. ``XX = 00`` advertises 256 bytes.
        """
        cla = channel & 0x03
        accumulated = b""
        while sw1 == 0x61:
            requested = sw2 & 0xFF
            if requested == 0:
                requested = 0x00  # 256 in T=0 encoding
            apdu = bytes([cla, 0xC0, 0x00, 0x00, requested])
            chunk, sw1, sw2 = self.modem.transmit(apdu)
            accumulated += bytes(chunk)
        return accumulated, int(sw1), int(sw2)

    def _select_get_fcp(self, apdu_hex: str) -> bytes:
        data, sw1, sw2 = self._exchange(apdu_hex)
        if sw1 == 0x61:
            data, sw1, sw2 = self._follow_get_response(sw1, sw2)
        self.assertEqual(
            (sw1, sw2),
            (0x90, 0x00),
            msg=f"SELECT {apdu_hex} -> {sw1:02X}{sw2:02X}",
        )
        return bytes(data)

    def _read_binary(self, le: int) -> bytes:
        data, sw1, sw2 = self._exchange(f"00B00000{le:02X}")
        self.assertEqual(
            (sw1, sw2),
            (0x90, 0x00),
            msg=f"READ BINARY Le={le:02X} -> {sw1:02X}{sw2:02X}",
        )
        return bytes(data)

    def _select_active_usim(self) -> None:
        aid = type(self).usim_aid
        self.assertGreater(len(aid), 0, "USIM AID was not extracted from EF.DIR.")
        select = bytes([0x00, 0xA4, 0x04, 0x04, len(aid)]) + bytes(aid)
        data, sw1, sw2 = self.modem.transmit(select)
        if sw1 == 0x61:
            data, sw1, sw2 = self._follow_get_response(sw1, sw2)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    # -- test sequence ----------------------------------------------

    def test_01_atr_is_default(self) -> None:
        atr = bytes(self.modem.get_atr())
        # ETSI TS 102 221 §6.1 / ISO 7816-3 §8.2 ATR. T0=0x9F declares
        # K=15 historical bytes and TD2 advertises T=15 globals, which
        # makes TCK mandatory. Historical bytes lead with 80 31 (ISO
        # 7816-4 category indicator + COMPACT-TLV) so the byte stream
        # is 22 bytes and TCK=0xA5 closes the XOR. An earlier draft
        # of this constant lost the 80 31 prefix and had no TCK at
        # all, which caused real modems to time out before issuing
        # any APDU on a fresh cold boot.
        self.assertEqual(
            atr.hex().upper(),
            "3B9F96801FC78031A073BE21136743200718000001A5",
        )

    def test_02_select_mf_returns_fcp_with_3f00(self) -> None:
        fcp = self._select_get_fcp("00A40004023F00")
        self.assertEqual(fcp[0], 0x62, msg=f"FCP outer tag = {fcp[0]:02X}")
        # Tag '83' inside FCP carries the 2-byte FID; '3F00' for MF.
        self.assertIn(b"\x83\x02\x3f\x00", fcp.lower())

    def test_03_efdir_first_record_carries_usim_aid(self) -> None:
        # SELECT EF.DIR (FID 2F00) and READ RECORD #1, Le=0x00 lets
        # the card decide the response length per ETSI TS 102 221.
        self._select_get_fcp("00A40004022F00")
        record, sw1, sw2 = self._exchange("00B2010400")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Application Template tag '61' wraps each entry.
        self.assertEqual(record[0], 0x61)
        outer_tag, outer_value, _outer_raw, _ = read_tlv(record)
        self.assertEqual(outer_tag.hex().upper(), "61")
        # Walk the inner TLVs looking for tag '4F' (Application AID).
        cursor = 0
        usim_aid: bytes = b""
        while cursor < len(outer_value):
            inner_tag, inner_value, _inner_raw, cursor = read_tlv(outer_value, cursor)
            if inner_tag.hex().upper() == "4F":
                usim_aid = bytes(inner_value)
                break
        self.assertGreater(len(usim_aid), 0, "EF.DIR record #1 missing AID tag '4F'.")
        # ETSI/3GPP USIM RID + Application code per TS 101 220 §7.2:
        #   A0 00 00 00 87  -- 3GPP RID
        #   10 02            -- USIM application code
        self.assertEqual(usim_aid[:7].hex().upper(), "A0000000871002")
        type(self).usim_aid = usim_aid

    def test_04_select_adf_usim_by_aid_returns_fcp(self) -> None:
        self._select_active_usim()

    def test_05_terminal_capability_and_profile(self) -> None:
        # TERMINAL CAPABILITY: minimal payload with mandatory tag '80'
        # (terminal-power) and a single status byte. TS 102 221 §11.1.19.
        cap_payload = bytes.fromhex("800100")
        cap_apdu = bytes([0x80, 0xAA, 0x00, 0x00, len(cap_payload)]) + cap_payload
        _, sw1, sw2 = self.modem.transmit(cap_apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

        # TERMINAL PROFILE per TS 102 223 §5.2. A non-empty bitmask
        # advertising every facility -- the simulator's bootstrap
        # logic responds to the profile being installed by enqueuing
        # proactive commands and signalling them with ``91 XX``. The
        # modem follows up with FETCH; we drain the queue here so the
        # downstream tests run against a quiescent toolkit state.
        profile_payload = bytes.fromhex("FFFFFFFFFF1F")
        profile_apdu = (
            bytes([0x80, 0x10, 0x00, 0x00, len(profile_payload)]) + profile_payload
        )
        _, sw1, sw2 = self.modem.transmit(profile_apdu)
        self.assertIn(
            sw1,
            (0x90, 0x91),
            msg=f"TERMINAL PROFILE -> {sw1:02X}{sw2:02X}",
        )

        # If the bootstrap path fired, drain the proactive queue using
        # FETCH (CLA=80 INS=12) + TERMINAL RESPONSE (CLA=80 INS=14)
        # the way a real modem would; otherwise the toolkit holds
        # ``active_proactive_command`` set and subsequent STATUS calls
        # would return ``91 XX`` instead of ``90 00``.
        while sw1 == 0x91:
            length = sw2 & 0xFF
            fetch = bytes([0x80, 0x12, 0x00, 0x00, length])
            data, fsw1, fsw2 = self.modem.transmit(fetch)
            self.assertEqual(
                (fsw1, fsw2),
                (0x90, 0x00),
                msg=f"FETCH -> {fsw1:02X}{fsw2:02X}",
            )
            self.assertGreater(len(data), 0, "FETCH returned an empty proactive command.")
            # TERMINAL RESPONSE acknowledging the proactive command.
            # We reuse the original BER-TLV header from the FETCH'd
            # command (tag 'D0' / general result '00' = command
            # performed successfully) so the toolkit treats the round
            # trip as a happy-path ack.
            tr_payload = bytes.fromhex("8103") + bytes(data[2:5]) + bytes.fromhex("82028281830100")
            tr = bytes([0x80, 0x14, 0x00, 0x00, len(tr_payload)]) + tr_payload
            _, sw1, sw2 = self.modem.transmit(tr)

    def test_06_pin_status_probes_allow_headless_attach(self) -> None:
        # Default PIN1 / UPIN are provisioned disabled for the built-in
        # profile. A modem probing with Lc=0 must therefore see success
        # and continue toward network AKA without a user PIN prompt.
        for reference in (0x01, 0x81):
            _data, sw1, sw2 = self.modem.transmit(bytes([0x00, 0x20, 0x00, reference, 0x00]))
            self.assertEqual(
                (sw1, sw2),
                (0x90, 0x00),
                msg=f"VERIFY status ref={reference:02X} -> {sw1:02X}{sw2:02X}",
            )

    def test_07_read_ef_imsi_round_trips_to_default(self) -> None:
        self._select_active_usim()
        self._select_get_fcp("00A40004026F07")  # EF.IMSI
        body = self._read_binary(0x09)
        self.assertEqual(decode_imsi_ef(body), "001010000000001")

    def test_08_read_ef_ad_advertises_mnc_length(self) -> None:
        self._select_active_usim()
        self._select_get_fcp("00A40004026FAD")
        body = self._read_binary(0x04)
        # TS 31.102 §4.2.18: octet 4 lower nibble = MNC length.
        self.assertEqual(body[3] & 0x0F, 2)

    def test_09_read_ef_ust_advertises_5g_services(self) -> None:
        self._select_active_usim()
        self._select_get_fcp("00A40004026F38")
        body = self._read_binary(0x11)  # 17 bytes covers service 130
        for service_number in (122, 124, 125, 129, 130):
            byte_index = (service_number - 1) // 8
            bit_index = (service_number - 1) % 8
            self.assertTrue(
                body[byte_index] & (1 << bit_index),
                msg=f"EF.UST service {service_number} not advertised",
            )

    def test_10_authenticate_returns_db_tag_with_milenage_vectors(self) -> None:
        profile = _resolve_active_profile(self.engine.state)
        self.assertIsNotNone(profile)
        profile.auth_config.sqn = b"\x00" * 6

        rand = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        sqn = bytes.fromhex("000000000010")
        amf = b"\x80\x00"
        autn = build_milenage_autn(
            profile.auth_config.ki,
            profile.auth_config.opc,
            rand,
            sqn,
            amf,
        )
        # Payload = '10' RAND || '10' AUTN per TS 31.102 §7.1.2.1.
        payload = b"\x10" + rand + b"\x10" + autn
        self._select_active_usim()
        apdu = bytes([0x00, 0x88, 0x00, 0x81, len(payload)]) + payload + b"\x00"
        data, sw1, sw2 = self.modem.transmit(apdu)
        if sw1 == 0x61:
            data, sw1, sw2 = self._follow_get_response(sw1, sw2)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # TS 31.102 §7.1.2.1: tag 'DB' = 3G context success.
        self.assertEqual(data[0], 0xDB)
        cursor = 1
        res_len = data[cursor]
        cursor += 1
        res = data[cursor : cursor + res_len]
        cursor += res_len
        ck_len = data[cursor]
        cursor += 1
        ck = data[cursor : cursor + ck_len]
        cursor += ck_len
        ik_len = data[cursor]
        cursor += 1
        ik = data[cursor : cursor + ik_len]
        cursor += ik_len
        kc_len = data[cursor]
        cursor += 1
        kc = data[cursor : cursor + kc_len]

        textbook = milenage_vectors(
            profile.auth_config.ki,
            profile.auth_config.opc,
            rand,
            sqn,
            amf,
        )
        self.assertEqual(res, textbook.res)
        self.assertEqual(ck, textbook.ck)
        self.assertEqual(ik, textbook.ik)
        self.assertEqual(kc, textbook.kc)

    def test_11_select_df_5gs_and_read_routing_indicator(self) -> None:
        self._select_active_usim()
        self._select_get_fcp("00A40004025FC0")  # DF.5GS
        self._select_get_fcp("00A40004024F0A")  # EF.ROUTING-INDICATOR
        body = self._read_binary(0x02)
        self.assertEqual(body.hex().upper(), "00FF")

    def test_12_get_identity_returns_null_suci_matching_imsi(self) -> None:
        self._select_active_usim()
        suci, sw1, sw2 = self.modem.transmit(bytes.fromhex("80780001") + b"\x00")
        if sw1 == 0x61:
            suci, sw1, sw2 = self._follow_get_response(sw1, sw2)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        suci_bytes = bytes(suci)
        # Octet 1: SUPI format=0 (IMSI), type-of-identity=001 (SUCI)
        self.assertEqual(suci_bytes[0], 0x01)
        self.assertEqual(suci_bytes[1:4].hex().upper(), "00F110")  # MCC=001 MNC=01
        self.assertEqual(suci_bytes[4:6].hex().upper(), "00FF")    # RI '00'
        self.assertEqual(suci_bytes[6], int(ProtectionScheme.NULL))
        self.assertEqual(suci_bytes[7], 0x00)
        self.assertEqual(decode_msin_bcd(suci_bytes[8:]), "0000000001")

    def test_13_5g_aka_populates_ef_5gauthkeys(self) -> None:
        profile = _resolve_active_profile(self.engine.state)
        self.assertIsNotNone(profile)
        profile.auth_config.sqn = b"\x00" * 6
        rand = b"\x42" * 16
        sqn = bytes.fromhex("000000000020")
        autn = build_milenage_autn(
            profile.auth_config.ki,
            profile.auth_config.opc,
            rand,
            sqn,
            b"\x80\x00",
        )
        vector = self.engine.auth.derive_5g_vector(
            "5G:mnc001.mcc001.3gppnetwork.org",
            rand,
            autn,
        )
        self.assertIsNotNone(vector)

        # Read EF.5GAUTHKEYS back through the modem channel.
        self._select_active_usim()
        self._select_get_fcp("00A40004025FC0")
        self._select_get_fcp("00A40004024F05")
        body = self._read_binary(0x44)  # 68 = 2+32+2+32

        self.assertEqual(len(body), 68)
        self.assertEqual(body[0], 0x80)
        self.assertEqual(body[1], 0x20)
        self.assertEqual(body[2:34], vector.k_ausf)
        self.assertEqual(body[34], 0x81)
        self.assertEqual(body[35], 0x20)
        self.assertEqual(body[36:68], vector.k_seaf)


if __name__ == "__main__":
    unittest.main()
