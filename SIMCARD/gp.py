from __future__ import annotations

from SIMCARD.etsi_fs import USIM_AID, ISIM_AID
from SIMCARD.state import SimCardState
from SIMCARD.utils import tlv


class SimulatedSecureSession:
    """Fallback secure session for simulator paths that remain plaintext."""

    def __init__(self, protocol_name: str = "SCP03") -> None:
        self.protocol_name = str(protocol_name or "SCP03").strip().upper() or "SCP03"
        self.is_authenticated = True
        self.chaining_value = b"\x00" * 16
        self.ssc = 0

    def reset_state(self) -> None:
        self.is_authenticated = False
        self.chaining_value = b"\x00" * 16
        self.ssc = 0

    def wrap_apdu(self, apdu):
        return list(apdu)

    def unwrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        del sw1, sw2
        return bytes(data)

    def encrypt_key_data(self, key_bytes: bytes) -> bytes:
        return bytes(key_bytes)


class GpLogic:
    def __init__(self, state: SimCardState) -> None:
        self.state = state

    def handle_get_data(self, p1: int, p2: int) -> tuple[bytes, int, int]:
        tag_hex = f"{p1:02X}{p2:02X}"
        if tag_hex == "005A":
            return tlv("5A", bytes.fromhex(self.state.eid)), 0x90, 0x00
        if tag_hex == "00E0":
            return self._build_key_information_template(), 0x90, 0x00
        if tag_hex == "FF40":
            return tlv("FF40", b""), 0x90, 0x00
        return b"", 0x6A, 0x88

    def handle_get_status(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        del p2, data
        if p1 == 0x80:
            entries = [
                self._status_entry(self.state.isdr_aid, 0x0F, bytes.fromhex("9EFE80")),
                self._status_entry(self.state.ecasd_aid, 0x0F, bytes.fromhex("9EFE80")),
                self._status_entry(self.state.mno_sd_aid, 0x07, bytes.fromhex("80")),
            ]
            return b"".join(entries), 0x90, 0x00
        if p1 == 0x40:
            entries = [
                self._status_entry(USIM_AID, 0x07, b""),
                self._status_entry(ISIM_AID, 0x07, b""),
            ]
            entries.extend(self._status_entry(profile.aid, 0x07, b"") for profile in self.state.profiles)
            return b"".join(entries), 0x90, 0x00
        return b"", 0x6A, 0x88

    def _build_key_information_template(self) -> bytes:
        kvn = int(self.state.scp03_session.key_version) & 0xFF
        entries = []
        for key_id in (1, 2, 3):
            entries.append(bytes([0xC0, 0x04, key_id, kvn, 0x88, 0x10]))
        return b"".join(entries)

    @staticmethod
    def _status_entry(aid_hex: str, life_cycle_state: int, privileges: bytes) -> bytes:
        body = tlv("4F", bytes.fromhex(aid_hex)) + tlv("9F70", bytes([life_cycle_state & 0xFF]))
        if len(privileges) > 0:
            body += tlv("C5", bytes(privileges))
        return tlv("E3", body)
