from __future__ import annotations

import types
import unittest

from SIMCARD.auth import AuthLogic, build_milenage_autn
from SIMCARD.etsi_fs import EtsiFileSystem, build_default_state
from SIMCARD.naa import NaaLogic
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import parse_apdu, read_tlv
from SCP03.logic.security import AUTH_TEST_VECTOR
from Tools.HilBridge.sim_modem import LEGACY_ISIM_AID, LEGACY_USIM_AID, SimulatedModemCardChannel

ACTUAL_USIM_AID = bytes.fromhex("A0000000871002FF86FF112233445566")


class _SimpleSimulatedConnection:
    def __init__(self) -> None:
        state = build_default_state()
        fs = EtsiFileSystem(state)
        self._engine = types.SimpleNamespace(state=state, fs=fs)
        self._auth = AuthLogic(state)
        self._naa = NaaLogic(state)
        self._toolkit = ToolkitLogic(state)

    def disconnect(self) -> None:
        return

    def getATR(self):
        return list(self._engine.state.atr)

    def transmit(self, apdu):
        parsed = parse_apdu(bytes(apdu))
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        data = bytes(parsed["data"] or b"")
        le = parsed["le"]
        le_value = None if le is None else int(le)

        if ins == 0xB0:
            offset = (p1 << 8) | p2
            response_data, sw1, sw2 = self._engine.fs.read_binary(offset=offset, le=le_value)
            return list(response_data), sw1, sw2
        if ins == 0xB2:
            response_data, sw1, sw2 = self._engine.fs.read_record(record_number=p1, le=le_value)
            return list(response_data), sw1, sw2
        if ins == 0x20:
            response_data, sw1, sw2 = self._naa.verify(p2, data)
            return list(response_data), sw1, sw2
        if ins == 0x2C:
            response_data, sw1, sw2 = self._naa.unblock_chv(p2, data)
            return list(response_data), sw1, sw2
        if ins == 0x88:
            response_data, sw1, sw2 = self._auth.internal_authenticate(p2, data)
            return list(response_data), sw1, sw2
        if ins == 0xAA and (int(parsed["cla"]) & 0x80):
            response_data, sw1, sw2 = self._toolkit.handle_terminal_capability(data)
            return list(response_data), sw1, sw2
        if ins == 0x10 and (int(parsed["cla"]) & 0x80):
            response_data, sw1, sw2 = self._toolkit.handle_terminal_profile(data)
            return list(response_data), sw1, sw2
        if ins == 0xF2 and (int(parsed["cla"]) & 0x80):
            response_data, sw1, sw2 = self._toolkit.handle_status(p1, p2, data)
            return list(response_data), sw1, sw2
        if ins == 0x12 and (int(parsed["cla"]) & 0x80):
            response_data, sw1, sw2 = self._toolkit.handle_fetch()
            return list(response_data), sw1, sw2
        if ins == 0x14 and (int(parsed["cla"]) & 0x80):
            response_data, sw1, sw2 = self._toolkit.handle_terminal_response(data)
            return list(response_data), sw1, sw2

        return [], 0x6D, 0x00


class HilBridgeSimulatedModemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = _SimpleSimulatedConnection()
        self.channel = SimulatedModemCardChannel(self.connection)

    def _drain_get_response(self, cla: int, sw2: int) -> tuple[bytes, int, int]:
        get_response = bytes((cla & 0xFF, 0xC0, 0x00, 0x00, sw2 & 0xFF))
        return self.channel.transmit(get_response)

    def _command_details(self, payload: bytes) -> tuple[int, int, int]:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(payload, 0)
        self.assertEqual(root_tag, b"\xD0")
        tag_bytes, value_bytes, _command_tlv, _command_next = read_tlv(root_value, 0)
        self.assertIn(tag_bytes, (b"\x01", b"\x81"))
        self.assertEqual(len(value_bytes), 3)
        return value_bytes[0], value_bytes[1], value_bytes[2]

    def test_select_mf_is_announced_via_get_response(self) -> None:
        data, sw1, sw2 = self.channel.transmit(bytes.fromhex("00A40004023F00"))

        self.assertEqual(data, b"")
        self.assertEqual(sw1, 0x61)
        self.assertGreater(sw2, 0)

        response_data, response_sw1, response_sw2 = self._drain_get_response(0x00, sw2)

        self.assertEqual(response_sw1, 0x90)
        self.assertEqual(response_sw2, 0x00)
        self.assertEqual(response_data[0], 0x62)
        self.assertIn(bytes.fromhex("83023F00"), response_data)
        self.assertIn(bytes.fromhex("8A0105"), response_data)

    def test_select_legacy_usim_aid_rewrites_fcp_and_ef_dir_records(self) -> None:
        select_data, select_sw1, select_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )

        self.assertEqual(select_data, b"")
        self.assertEqual(select_sw1, 0x61)

        fcp_data, fcp_sw1, fcp_sw2 = self._drain_get_response(0x00, select_sw2)

        self.assertEqual(fcp_sw1, 0x90)
        self.assertEqual(fcp_sw2, 0x00)
        self.assertIn(LEGACY_USIM_AID, fcp_data)
        self.assertNotIn(ACTUAL_USIM_AID, fcp_data)

        ef_dir_select_data, ef_dir_select_sw1, ef_dir_select_sw2 = self.channel.transmit(bytes.fromhex("00A40004022F00"))
        self.assertEqual(ef_dir_select_data, b"")
        self.assertEqual(ef_dir_select_sw1, 0x61)
        _, dir_sw1, dir_sw2 = self._drain_get_response(0x00, ef_dir_select_sw2)
        self.assertEqual((dir_sw1, dir_sw2), (0x90, 0x00))

        record_data, record_sw1, record_sw2 = self.channel.transmit(bytes.fromhex("00B201041E"))

        self.assertEqual(record_sw1, 0x90)
        self.assertEqual(record_sw2, 0x00)
        self.assertIn(LEGACY_USIM_AID, record_data)
        self.assertNotIn(ACTUAL_USIM_AID, record_data)

    def test_select_path_uses_current_application_root_alias(self) -> None:
        _, select_sw1, select_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )
        self.assertEqual(select_sw1, 0x61)
        _, response_sw1, response_sw2 = self._drain_get_response(0x00, select_sw2)
        self.assertEqual((response_sw1, response_sw2), (0x90, 0x00))

        path_data, path_sw1, path_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F07"))

        self.assertEqual(path_data, b"")
        self.assertEqual(path_sw1, 0x61)

        fcp_data, fcp_sw1, fcp_sw2 = self._drain_get_response(0x00, path_sw2)

        self.assertEqual((fcp_sw1, fcp_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83026F07"), fcp_data)

    def test_terminal_capability_and_logical_channel_alias_flow(self) -> None:
        # Mirror the bootstrap body sent by the SCP11 orchestrator after the
        # TERMINAL CAPABILITY change: tag 0x82 advertises extended logical
        # channels and tag 0x84 advertises eUICC support, both required by
        # eUICC stacks that gate ES10 STORE DATA on the eUICC bit.
        capability_data, capability_sw1, capability_sw2 = self.channel.transmit(
            bytes.fromhex("80AA00000DA90B8100820101830107840101")
        )
        self.assertEqual(capability_data, b"")
        self.assertEqual((capability_sw1, capability_sw2), (0x90, 0x00))

        open_data, open_sw1, open_sw2 = self.channel.transmit(bytes.fromhex("0070000001"))
        self.assertEqual(open_data, bytes((0x01,)))
        self.assertEqual((open_sw1, open_sw2), (0x90, 0x00))

        select_data, select_sw1, select_sw2 = self.channel.transmit(
            bytes([0x01, 0xA4, 0x04, 0x04, len(LEGACY_ISIM_AID)]) + LEGACY_ISIM_AID
        )
        self.assertEqual(select_data, b"")
        self.assertEqual(select_sw1, 0x61)

        fcp_data, fcp_sw1, fcp_sw2 = self._drain_get_response(0x01, select_sw2)
        self.assertEqual((fcp_sw1, fcp_sw2), (0x90, 0x00))
        self.assertIn(LEGACY_ISIM_AID, fcp_data)

    def test_trace_style_pin_probe_and_isim_channel_do_not_block_auth(self) -> None:
        _, usim_sw1, usim_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )
        self.assertEqual(usim_sw1, 0x61)
        _, usim_drain_sw1, usim_drain_sw2 = self._drain_get_response(0x00, usim_sw2)
        self.assertEqual((usim_drain_sw1, usim_drain_sw2), (0x90, 0x00))

        for reference in (0x01, 0x81):
            data, sw1, sw2 = self.channel.transmit(bytes([0x00, 0x20, 0x00, reference, 0x00]))
            self.assertEqual(data, b"")
            self.assertEqual((sw1, sw2), (0x90, 0x00))

        open_data, open_sw1, open_sw2 = self.channel.transmit(bytes.fromhex("0070000001"))
        self.assertEqual(open_data, bytes((0x01,)))
        self.assertEqual((open_sw1, open_sw2), (0x90, 0x00))

        _, isim_sw1, isim_sw2 = self.channel.transmit(
            bytes([0x01, 0xA4, 0x04, 0x04, len(LEGACY_ISIM_AID)]) + LEGACY_ISIM_AID
        )
        self.assertEqual(isim_sw1, 0x61)
        _, isim_drain_sw1, isim_drain_sw2 = self._drain_get_response(0x01, isim_sw2)
        self.assertEqual((isim_drain_sw1, isim_drain_sw2), (0x90, 0x00))

        _, li_sw1, li_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F05"))
        self.assertEqual(li_sw1, 0x61)
        li_fcp, li_drain_sw1, li_drain_sw2 = self._drain_get_response(0x00, li_sw2)
        self.assertEqual((li_drain_sw1, li_drain_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83026F05"), li_fcp)

        auth_config = self.connection._engine.state.profiles[0].auth_config
        self.assertIsNotNone(auth_config)
        assert auth_config is not None
        autn = build_milenage_autn(
            bytes(auth_config.ki),
            bytes(auth_config.opc),
            bytes.fromhex(AUTH_TEST_VECTOR["RAND"]),
            bytes(auth_config.sqn),
            bytes(auth_config.amf),
        )
        auth_apdu = (
            bytes.fromhex("00880081")
            + bytes((0x22, 0x10))
            + bytes.fromhex(AUTH_TEST_VECTOR["RAND"])
            + bytes((0x10,))
            + autn
        )
        auth_data, auth_sw1, auth_sw2 = self.channel.transmit(auth_apdu)
        self.assertEqual(auth_data, b"")
        self.assertEqual(auth_sw1, 0x61)
        response_data, response_sw1, response_sw2 = self._drain_get_response(0x00, auth_sw2)
        self.assertEqual((response_sw1, response_sw2), (0x90, 0x00))
        self.assertEqual(response_data[:2], bytes.fromhex("DB08"))

    def test_toolkit_status_fetch_and_terminal_response_flow(self) -> None:
        profile_data, profile_sw1, profile_sw2 = self.channel.transmit(bytes.fromhex("8010000001FF"))

        self.assertEqual(profile_data, b"")
        self.assertEqual(profile_sw1, 0x91)
        self.assertGreater(profile_sw2, 0)

        status_data, status_sw1, status_sw2 = self.channel.transmit(bytes.fromhex("80F2000000"))

        self.assertEqual(status_data, b"")
        self.assertEqual(status_sw1, 0x91)
        self.assertEqual(status_sw2, profile_sw2)

        fetch_data, fetch_sw1, fetch_sw2 = self.channel.transmit(bytes([0x80, 0x12, 0x00, 0x00, status_sw2]))

        self.assertEqual((fetch_sw1, fetch_sw2), (0x90, 0x00))
        command_number, command_type, qualifier = self._command_details(fetch_data)
        self.assertEqual(command_type, 0x26)

        status_again_data, status_again_sw1, status_again_sw2 = self.channel.transmit(bytes.fromhex("80F2000000"))

        self.assertEqual(status_again_data, b"")
        self.assertEqual(status_again_sw1, 0x91)
        self.assertEqual(status_again_sw2, len(fetch_data))

        terminal_response = (
            bytes([0x80, 0x14, 0x00, 0x00, 0x0C])
            + bytes.fromhex("8103")
            + bytes((command_number, command_type, qualifier))
            + bytes.fromhex("82028281")
            + bytes.fromhex("030100")
        )
        response_data, response_sw1, response_sw2 = self.channel.transmit(terminal_response)

        self.assertEqual(response_data, b"")
        self.assertEqual(response_sw1, 0x91)
        self.assertGreater(response_sw2, 0)

    def test_current_application_alias_survives_mf_side_trip(self) -> None:
        # Activate USIM via legacy AID select.
        _, select_sw1, select_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )
        self.assertEqual(select_sw1, 0x61)
        _, drain_sw1, drain_sw2 = self._drain_get_response(0x00, select_sw2)
        self.assertEqual((drain_sw1, drain_sw2), (0x90, 0x00))

        # First 7FFF/6F07 walk lands on EF.IMSI under USIM.
        _, first_sw1, first_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F07"))
        self.assertEqual(first_sw1, 0x61)
        first_fcp, first_drain_sw1, first_drain_sw2 = self._drain_get_response(0x00, first_sw2)
        self.assertEqual((first_drain_sw1, first_drain_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83026F07"), first_fcp)

        # Modem-style MF side-trip: SELECT 2F00 (EF.DIR) under MF via path
        # walks the cursor out of the USIM subtree.
        _, side_trip_sw1, _ = self.channel.transmit(bytes.fromhex("00A40804022F00"))
        self.assertEqual(side_trip_sw1, 0x61)

        # 7FFF/<EF> must still resolve to the previously activated USIM
        # because TS 102 221 §8.4.2.3 keeps the "currently selected
        # application" sticky until an explicit SELECT-by-AID switches
        # it.
        _, post_sw1, post_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F07"))
        self.assertEqual(post_sw1, 0x61)
        post_fcp, post_drain_sw1, post_drain_sw2 = self._drain_get_response(0x00, post_sw2)
        self.assertEqual((post_drain_sw1, post_drain_sw2), (0x90, 0x00))
        self.assertIn(bytes.fromhex("83026F07"), post_fcp)

    def test_select_by_aid_switches_sticky_application(self) -> None:
        # Anchor on USIM.
        _, usim_sw1, usim_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )
        self.assertEqual(usim_sw1, 0x61)
        _, drain_sw1, _ = self._drain_get_response(0x00, usim_sw2)
        self.assertEqual(drain_sw1, 0x90)

        # 7FFF resolves to USIM root before the switch.
        _, pre_sw1, pre_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F07"))
        self.assertEqual(pre_sw1, 0x61)
        pre_fcp, _, _ = self._drain_get_response(0x00, pre_sw2)
        self.assertIn(bytes.fromhex("83026F07"), pre_fcp)

        # Switch to ISIM via AID.
        _, isim_sw1, isim_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_ISIM_AID)]) + LEGACY_ISIM_AID
        )
        self.assertEqual(isim_sw1, 0x61)
        _, isim_drain_sw1, _ = self._drain_get_response(0x00, isim_sw2)
        self.assertEqual(isim_drain_sw1, 0x90)

        # 7FFF must now resolve to ISIM. EF.IMPI lives at 6F02 under ISIM.
        _, post_sw1, post_sw2 = self.channel.transmit(bytes.fromhex("00A40804047FFF6F02"))
        self.assertEqual(post_sw1, 0x61)
        post_fcp, _, _ = self._drain_get_response(0x00, post_sw2)
        self.assertIn(bytes.fromhex("83026F02"), post_fcp)

    def test_internal_authenticate_is_exposed_via_get_response(self) -> None:
        _, select_sw1, select_sw2 = self.channel.transmit(
            bytes([0x00, 0xA4, 0x04, 0x04, len(LEGACY_USIM_AID)]) + LEGACY_USIM_AID
        )
        self.assertEqual(select_sw1, 0x61)
        _, response_sw1, response_sw2 = self._drain_get_response(0x00, select_sw2)
        self.assertEqual((response_sw1, response_sw2), (0x90, 0x00))

        auth_config = self.connection._engine.state.profiles[0].auth_config
        self.assertIsNotNone(auth_config)
        assert auth_config is not None
        autn = build_milenage_autn(
            bytes(auth_config.ki),
            bytes(auth_config.opc),
            bytes.fromhex(AUTH_TEST_VECTOR["RAND"]),
            bytes(auth_config.sqn),
            bytes(auth_config.amf),
        )
        auth_apdu = bytes.fromhex("00880081") + bytes((0x22,)) + bytes((0x10,)) + bytes.fromhex(
            AUTH_TEST_VECTOR["RAND"]
        ) + bytes((0x10,)) + autn
        auth_data, auth_sw1, auth_sw2 = self.channel.transmit(auth_apdu)

        self.assertEqual(auth_data, b"")
        self.assertEqual(auth_sw1, 0x61)
        self.assertGreater(auth_sw2, 0)

        response_data, response_sw1, response_sw2 = self._drain_get_response(0x00, auth_sw2)

        self.assertEqual((response_sw1, response_sw2), (0x90, 0x00))
        self.assertEqual(response_data[:2], bytes.fromhex("DB08"))
        self.assertEqual(len(response_data), 53)


if __name__ == "__main__":
    unittest.main()
