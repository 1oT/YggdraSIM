# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP02 session key derivation bridging pySim's GpCardKeyset to the YggdraSIM transport."""
try:
    from pySim.global_platform import GpCardKeyset
    from pySim.global_platform.scp import SCP02
except Exception:
    GpCardKeyset = None
    SCP02 = None


class Scp02SessionAdapter:
    def __init__(self, enc: bytes, mac: bytes, dek: bytes, kvn: int) -> None:
        if GpCardKeyset is None or SCP02 is None:
            raise RuntimeError("SCP02 support requires the pySim GlobalPlatform library.")
        self._enc = bytes(enc)
        self._mac = bytes(mac)
        self._dek = bytes(dek)
        self._kvn = int(kvn)
        self.protocol_name = "SCP02"
        self.sec_level = 0x00
        self.is_authenticated = False
        self.chaining_value = b"\x00" * 8
        self.ssc = 0
        self.dek = bytes(dek)
        self._scp = self._build_scp()

    def _build_scp(self) -> SCP02:
        keyset = GpCardKeyset(self._kvn, self._enc, self._mac, self._dek)
        return SCP02(card_keys=keyset)

    def reset_state(self) -> None:
        self.is_authenticated = False
        self.sec_level = 0x00
        self.chaining_value = b"\x00" * 8
        self.ssc = 0
        self._scp = self._build_scp()

    def gen_init_update_apdu(self, host_challenge: bytes) -> bytes:
        return self._scp.gen_init_update_apdu(host_challenge=bytes(host_challenge))

    def parse_init_update_resp(self, response: bytes) -> None:
        self._scp.parse_init_update_resp(bytes(response))

    def gen_ext_auth_apdu(self, security_level: int = 0x03) -> bytes:
        self.sec_level = int(security_level)
        return self._scp.gen_ext_auth_apdu(security_level)

    def wrap_apdu(self, apdu: list[int]) -> list[int]:
        if self.is_authenticated is False:
            return list(apdu)
        wrapped = self._scp.wrap_cmd_apdu(bytes(apdu))
        return list(wrapped)

    def unwrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        return bytes(data)

    def encrypt_key_data(self, key_bytes: bytes) -> bytes:
        return self._scp.dek_encrypt(bytes(key_bytes))
