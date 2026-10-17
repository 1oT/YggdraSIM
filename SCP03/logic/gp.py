# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""GlobalPlatform card administration: INSTALL, LOAD, DELETE, PUT KEY, and status commands (GP Card Spec v2.3.1)."""

import os
from typing import Optional, List, Dict, Any, Tuple

from SCP03.config import Config, enforce_demo_key_policy
from yggdrasim_common.apdu_chunking import plan_chunked_apdus
from SCP03.core.utils import HexUtils, TlvParser
from SCP03.core.cap import CapFileParser
from SCP03.crypto.session import Scp03Session
from SCP03.crypto.scp02_session import Scp02SessionAdapter
from SCP03.logic.sgp22 import Sgp22Manager
from yggdrasim_common.card_backend import is_simulated_card_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import cmac


class GlobalPlatformManager:
    MAX_GET_STATUS_PAGES = 256
    # GPC v2.3.1 §11.4.2.2 Table 11-34: b2 = 1 selects the TLV response format,
    # b1 = 1 requests the next occurrence(s).
    GET_STATUS_P2_FIRST = 0x02
    GET_STATUS_P2_NEXT = 0x03

    def __init__(self, transport, config_keys):
        self.tp = transport
        self.raw_keys = config_keys
        self.scp03_keys = {
            "kenc": HexUtils.to_bytes(
                config_keys.get("scp03_kenc", Config.DEFAULT_KEYS["scp03_kenc"])
            ),
            "kmac": HexUtils.to_bytes(
                config_keys.get("scp03_kmac", Config.DEFAULT_KEYS["scp03_kmac"])
            ),
            "dek": HexUtils.to_bytes(
                config_keys.get("scp03_dek", Config.DEFAULT_KEYS["scp03_dek"])
            ),
        }
        self.scp02_keys = {
            "enc": HexUtils.to_bytes(
                config_keys.get("scp02_enc", Config.DEFAULT_KEYS["scp02_enc"])
            ),
            "mac": HexUtils.to_bytes(
                config_keys.get("scp02_mac", Config.DEFAULT_KEYS["scp02_mac"])
            ),
            "dek": HexUtils.to_bytes(
                config_keys.get("scp02_dek", Config.DEFAULT_KEYS["scp02_dek"])
            ),
        }
        self.target_aid = HexUtils.to_bytes(
            config_keys.get("aid", Config.DEFAULT_KEYS["aid"])
        )
        self.scp03_kvn = int(
            config_keys.get("scp03_kvn", Config.DEFAULT_KEYS["scp03_kvn"]), 16
        )
        self.scp02_kvn = int(
            config_keys.get("scp02_kvn", Config.DEFAULT_KEYS["scp02_kvn"]), 16
        )
        self.active_scp_protocol = "SCP03"

        backend_label = "sim" if is_simulated_card_backend() else "reader"
        # ``enforce_demo_key_policy`` used to stderr-write synchronously,
        # which got wiped by the shell's screen-clear redraw. It now
        # returns the banner text (or None) so the caller decides when
        # to surface it; the dispatcher flushes after the banner is drawn.
        self.pending_demo_keys_warning = enforce_demo_key_policy(
            config_keys,
            backend_label=backend_label,
        )

        self.sgp22 = Sgp22Manager(transport)

    def get_active_protocol_name(self) -> str:
        return self.active_scp_protocol

    def get_active_kvn_hex(self) -> str:
        if self.active_scp_protocol == "SCP02":
            return f"{self.scp02_kvn:02X}"
        return f"{self.scp03_kvn:02X}"

    @staticmethod
    def _encode_apdu_lc(data_len: int) -> str:
        if data_len <= 0xFF:
            return f"{data_len:02X}"
        if data_len <= 0xFFFF:
            return f"00{data_len:04X}"
        raise ValueError("APDU data field exceeds extended length capability.")

    @staticmethod
    def _build_case3_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes) -> str:
        lc_hex = GlobalPlatformManager._encode_apdu_lc(len(data))
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc_hex}{data.hex()}"

    @staticmethod
    def _build_case4_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes) -> str:
        """Case-4 APDU with Le '00' (GPC v2.3.1 §11.1.5).

        Every GlobalPlatform command that expects response data carries
        Le = '00'. An extended Lc is paired with a two-byte Le so the APDU
        keeps one length format throughout.
        """
        lc_hex = GlobalPlatformManager._encode_apdu_lc(len(data))
        le_hex = "0000" if len(data) > 0xFF else "00"
        return f"{cla:02X}{ins:02X}{p1:02X}{p2:02X}{lc_hex}{data.hex()}{le_hex}"

    @staticmethod
    def _encode_ber_length(length: int) -> bytes:
        """BER length as GPC v2.3.1 §11.1.5 codes LV fields.

        One byte up to 127, '81 xx' up to 255, '82 xx xx' up to 65535.
        """
        if length < 0:
            raise ValueError("Length cannot be negative.")
        if length <= 0x7F:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82]) + length.to_bytes(2, "big")
        raise ValueError("Length exceeds the three-byte BER encoding.")

    @staticmethod
    def _lv(value: bytes) -> bytes:
        """Length-value field with a BER-coded length (GPC v2.3.1 §11.5.2.3)."""
        return GlobalPlatformManager._encode_ber_length(len(value)) + bytes(value)

    def get_config_key_fields_for_protocol(
        self, protocol_name: str = None
    ) -> Tuple[str, str, str, str]:
        """Return (ENC-key-hex, MAC-key-hex, DEK-key-hex, KVN-hex) from the keyset config for *protocol_name*."""
        protocol = self.active_scp_protocol
        if protocol_name is not None:
            protocol = str(protocol_name).strip().upper()
        if protocol == "SCP02":
            return ("scp02_enc", "scp02_mac", "scp02_dek", "scp02_kvn")
        return ("scp03_kenc", "scp03_kmac", "scp03_dek", "scp03_kvn")

    def verify_adm(self, key_hex: Optional[str] = None):
        """Send VERIFY PIN for ADM1 (TS 102 221 v18.4 §11.1.9, key reference '0A' of Table 9.3) with the configured or supplied key."""
        target_key = key_hex
        if not target_key:
            target_key = self.raw_keys.get("adm")

        if not target_key:
            print(
                f"{Config.Colors.FAIL}[-] Error: No ADM key provided.{Config.Colors.ENDC}"
            )
            return

        target_key = target_key.replace(" ", "")
        if len(target_key) != 16:
            print(
                f"{Config.Colors.WARNING}[!] Warning: ADM key should be 16 hex digits.{Config.Colors.ENDC}"
            )

        if self.tp.session and self.tp.session.is_authenticated:
            active_protocol = getattr(self.tp.session, "protocol_name", "SCP")
            print(
                f"{Config.Colors.WARNING}[!] Warning: Switching to MF will terminate {active_protocol} session.{Config.Colors.ENDC}"
            )
            self.tp.reset_session_state()

        print(f"{Config.Colors.CYAN}[*] Selecting MF (3F00)...{Config.Colors.ENDC}")
        self.tp.transmit("00A40004023F00", silent=True)

        cmd = f"0020000A{len(target_key) // 2:02X}{target_key}"
        print(f"{Config.Colors.CYAN}[*] Verifying ADM...{Config.Colors.ENDC}")
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(
                f"{Config.Colors.GREEN}[+] ADM Verified Successfully.{Config.Colors.ENDC}"
            )
        elif sw1 == 0x63:
            # TS 102 221 v18.4 §11.1.9.1.1: '63CX' leaves X attempts.
            retries = sw2 & 0x0F
            print(
                f"{Config.Colors.FAIL}[-] ADM Failed: Wrong code. Retries remaining: {retries}{Config.Colors.ENDC}"
            )
        elif sw1 == 0x69 and sw2 == 0x83:
            print(
                f"{Config.Colors.FAIL}[-] ADM Failed: Key Blocked.{Config.Colors.ENDC}"
            )
        else:
            print(
                f"{Config.Colors.FAIL}[-] ADM Failed: SW {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    def authenticate(self, protocol_name: str = "SCP03") -> bool:
        protocol = str(protocol_name).strip().upper()
        if protocol == "SCP02":
            return self.authenticate_scp02()
        return self.authenticate_scp03()

    @staticmethod
    def _preferred_scp03_security_level(i_parameter: int) -> int:
        """Choose the strongest security level advertised by SCP03 ``i``."""
        response_mode = int(i_parameter) & 0x60
        if response_mode == 0x40:
            raise ValueError("SCP03 i parameter uses the reserved response mode 10b.")
        security_level = 0x03  # C-MAC + C-DECRYPTION
        if response_mode in (0x20, 0x60):
            security_level |= 0x10  # R-MAC
        if response_mode == 0x60:
            security_level |= 0x20  # R-ENCRYPTION
        return security_level

    def authenticate_scp03(self) -> bool:
        """Run INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE to open an SCP03 admin session; return True on success."""
        if self.tp.session:
            self.tp.reset_session_state()

        target_hex = self.target_aid.hex().upper()
        print(
            f"{Config.Colors.CYAN}[*] Authenticating to Security Domain via SCP03: {target_hex}...{Config.Colors.ENDC}"
        )

        self.tp.transmit(f"00A40400{len(self.target_aid):02X}{target_hex}", silent=True)

        attempted_kvns = [self.scp03_kvn]
        if self.scp03_kvn != 0:
            attempted_kvns.append(0)

        data = b""
        sw1 = 0x6F
        sw2 = 0x00
        host_challenge = b""
        used_kvn = self.scp03_kvn
        for kvn_candidate in attempted_kvns:
            host_challenge = os.urandom(8)
            # Amd D v1.1.2 Table 7-2: P2 '00', Lc '08', Le '00'.
            cmd = f"8050{kvn_candidate:02X}0008{host_challenge.hex()}00"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x90:
                used_kvn = kvn_candidate
                break

        if sw1 != 0x90:
            print(
                f"{Config.Colors.FAIL}[-] INITIALIZE UPDATE Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return False

        try:
            self.tp.session = Scp03Session(self.scp03_keys)
            self.tp.session.derive_keys(host_challenge, data)
            security_level = self._preferred_scp03_security_level(
                self.tp.session.i_parameter
            )
            self.tp.session.sec_level = security_level
        except Exception as e:
            print(
                f"{Config.Colors.FAIL}[-] Key Derivation Failed: {e}{Config.Colors.ENDC}"
            )
            return False

        host_crypto = self.tp.session.calculate_host_cryptogram()
        self.tp.session.chaining_value = b"\x00" * 16

        header = bytes([0x84, 0x82, security_level, 0x00, 0x10])

        c_mac = cmac.CMAC(algorithms.AES(self.tp.session.s_mac))
        c_mac.update(self.tp.session.chaining_value + header + host_crypto)
        full_mac = c_mac.finalize()
        self.tp.session.chaining_value = full_mac

        cmd_bytes = list(header) + list(host_crypto) + list(full_mac[:8])
        data, sw1, sw2 = self.tp.connection.transmit(cmd_bytes)

        if sw1 == 0x90:
            self.scp03_kvn = used_kvn
            self.active_scp_protocol = "SCP03"
            self.tp.session.ssc = 1
            self.tp.session.is_authenticated = True
            print(
                f"{Config.Colors.GREEN}[+] SCP03 Authenticated (Level 0x{security_level:02X}, KVN 0x{used_kvn:02X}){Config.Colors.ENDC}"
            )
            self.get_keys_info(silent=True)
            return True
        self.tp.reset_session_state()
        print(
            f"{Config.Colors.FAIL}[-] EXTERNAL AUTH Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
        )
        return False

    def authenticate_scp02(self) -> bool:
        """Run INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE to open an SCP02 admin session; return True on success."""
        if self.tp.session:
            self.tp.reset_session_state()

        target_hex = self.target_aid.hex().upper()
        print(
            f"{Config.Colors.CYAN}[*] Authenticating to Security Domain via SCP02: {target_hex}...{Config.Colors.ENDC}"
        )

        self.tp.transmit(f"00A40400{len(self.target_aid):02X}{target_hex}", silent=True)

        if is_simulated_card_backend():
            from SIMCARD.gp import SimulatedSecureSession

            self.tp.session = SimulatedSecureSession("SCP02")
            self.active_scp_protocol = "SCP02"
            print(
                f"{Config.Colors.GREEN}[+] SCP02 simulated session activated (plaintext simulator mode).{Config.Colors.ENDC}"
            )
            return True

        session = Scp02SessionAdapter(
            self.scp02_keys["enc"],
            self.scp02_keys["mac"],
            self.scp02_keys["dek"],
            self.scp02_kvn,
        )
        host_challenge = os.urandom(8)
        init_apdu = session.gen_init_update_apdu(host_challenge)
        data, sw1, sw2 = self.tp.connection.transmit(list(init_apdu))
        if sw1 != 0x90:
            print(
                f"{Config.Colors.FAIL}[-] INITIALIZE UPDATE Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return False

        try:
            session.parse_init_update_resp(bytes(data))
            ext_auth_apdu = session.gen_ext_auth_apdu(0x03)
        except Exception as e:
            print(
                f"{Config.Colors.FAIL}[-] SCP02 Session Setup Failed: {e}{Config.Colors.ENDC}"
            )
            return False

        _, sw1, sw2 = self.tp.connection.transmit(list(ext_auth_apdu))
        if sw1 != 0x90:
            print(
                f"{Config.Colors.FAIL}[-] EXTERNAL AUTH Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return False

        session.is_authenticated = True
        self.tp.session = session
        self.active_scp_protocol = "SCP02"
        print(
            f"{Config.Colors.GREEN}[+] SCP02 Authenticated (Level 0x03, KVN 0x{self.scp02_kvn:02X}){Config.Colors.ENDC}"
        )
        self.get_keys_info(silent=True)
        return True

    def store_data(
        self, data_hex: str, p1: Optional[int] = None, p2: Optional[int] = None
    ):
        """
        GlobalPlatform STORE DATA (GPCS 11.11).
        Features automatic chunking if P1/P2 are not provided manually.
        """
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        payload = HexUtils.to_bytes(data_hex)

        if p1 is not None and p2 is not None:
            print(
                f"{Config.Colors.CYAN}[*] STORE DATA (P1={p1:02X}, P2={p2:02X}) Len={len(payload)}...{Config.Colors.ENDC}"
            )
            cmd = f"80E2{p1:02X}{p2:02X}{len(payload):02X}{payload.hex()}"
            if p1 & 0x01:
                # Table 11-88: Le '00' when P1.b1 flags an ISO case 4 command.
                cmd += "00"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x90:
                print(
                    f"{Config.Colors.GREEN}[+] STORE DATA Success.{Config.Colors.ENDC}"
                )
            else:
                print(
                    f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                )
            return

        print(
            f"{Config.Colors.CYAN}[*] STORE DATA (Auto-chunking {len(payload)} bytes)...{Config.Colors.ENDC}"
        )
        # Table 11-89: P1.b8 = 0 announces more blocks, 1 marks the last; the
        # 240-byte block leaves room for a C-MAC under a secure channel.
        plan = plan_chunked_apdus(payload, cla=0x80, ins=0xE2, p1_last=0x80, chunk_size=240)

        for chunk in plan:
            _, sw1, sw2 = self.tp.transmit(chunk.apdu_hex, silent=True)

            print(
                f"\r    Sending Block {chunk.index + 1}/{chunk.total} "
                f"[P1={chunk.p1:02X} P2={chunk.p2:02X}]...",
                end="",
                flush=True,
            )

            if sw1 != 0x90:
                print(
                    f"\n{Config.Colors.FAIL}[-] Failed at block {chunk.index + 1}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                )
                return

        print(
            f"\n{Config.Colors.GREEN}[+] STORE DATA Success ({len(plan)} blocks).{Config.Colors.ENDC}"
        )

    #: GPC v2.3.1 Table 11-16: '80' is DES; '81'..'84' are "reserved for
    #: historical reasons" DES codings that older tooling still emits. Both
    #: take the DES check value of Annex B.8.
    _DES_KEY_TYPES = frozenset({0x80, 0x81, 0x82, 0x83, 0x84})
    _AES_KEY_TYPE = 0x88
    _SM4_KEY_TYPE = 0x89

    @classmethod
    def _key_check_value(cls, key_type: int, raw_key: bytes) -> bytes:
        """Key Check Value of GPC v2.3.1 Annex B.8.

        Three highest-order bytes of one block encrypted under the key:
        eight '00' bytes for DES, sixteen '01' bytes for AES, sixteen '02'
        bytes for SM4. Other key types carry no check value (§11.8.2.3.5
        and §11.8.2.3.6 set its length to '00').
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        if key_type in cls._DES_KEY_TYPES:
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:
                TripleDES = algorithms.TripleDES
            algorithm = TripleDES(raw_key)
            block = b"\x00" * 8
        elif key_type == cls._AES_KEY_TYPE:
            algorithm = algorithms.AES(raw_key)
            block = b"\x01" * 16
        elif key_type == cls._SM4_KEY_TYPE:
            algorithm = algorithms.SM4(raw_key)
            block = b"\x02" * 16
        else:
            return b""
        encryptor = Cipher(algorithm, modes.ECB()).encryptor()
        return (encryptor.update(block) + encryptor.finalize())[:3]

    @staticmethod
    def _dek_block_size(session: Any) -> int:
        """Block size of the Key-DEK cipher: 8 for SCP02 (3DES), 16 for SCP03 (AES)."""
        protocol = str(getattr(session, "protocol_name", "SCP03") or "SCP03").upper()
        if protocol == "SCP02":
            return 8
        return 16

    def _wrap_key_component(self, raw_key: bytes, session: Any) -> bytes:
        """Key Component Block of GPC v2.3.1 §11.8.2.3.2.

        A component whose length is a multiple of the DEK block size is sent
        as the bare ciphertext (Table 11-71). Otherwise it is right-padded
        before encryption and the block starts with the clear-text length
        (Table 11-70); Amd D v1.1.2 §6.2.8 is the 24-byte AES case, padded
        with eight bytes.
        """
        if session is None:
            return bytes(raw_key)
        block_size = self._dek_block_size(session)
        remainder = len(raw_key) % block_size
        if remainder == 0:
            return bytes(session.encrypt_key_data(bytes(raw_key)))
        padded = bytes(raw_key) + b"\x00" * (block_size - remainder)
        return self._encode_ber_length(len(raw_key)) + bytes(
            session.encrypt_key_data(padded)
        )

    def put_key(
        self,
        old_kvn: int,
        key_id: int,
        new_kvn: int,
        new_keys: list,
        key_type: int = 0x88,
    ) -> bool:
        """Send PUT KEY (GPC v2.3.1 §11.8) to add or replace a key set.

        P1 carries the Key Version Number being replaced ('00' adds a new
        set, Table 11-65), P2 the first Key Identifier with b8 set when
        several keys follow (Table 11-66). The data field is the new KVN
        followed by one Format 1 key data field per key (Table 11-68): key
        type, BER length, Key Component Block, then the Annex B.8 check
        value.
        """
        if not 0 <= int(old_kvn) <= 0x7F:
            print("[-] Error: P1 Key Version Number must be 00..7F (Table 11-65).")
            return False
        if not 0 <= int(key_id) <= 0x7F:
            print("[-] Error: Key Identifier must be 00..7F (Table 11-66).")
            return False
        if not 0x01 <= int(new_kvn) <= 0x7F:
            print("[-] Error: New Key Version Number must be 01..7F (§11.8.2.3).")
            return False
        if len(new_keys) == 0:
            print("[-] Error: PUT KEY needs at least one key.")
            return False

        session = getattr(self.tp, "session", None)

        payload = bytearray()
        payload.append(int(new_kvn))
        key_check_values = bytearray()

        for index, key_hex in enumerate(new_keys):
            raw_key = HexUtils.to_bytes(key_hex)
            if len(raw_key) not in (16, 24, 32):
                print(f"[-] Error: Key {index + 1} length invalid for crypto operations.")
                return False

            try:
                component_block = self._wrap_key_component(raw_key, session)
            except Exception as e:
                print(f"[-] Encryption Error: {e}")
                return False

            try:
                kcv = self._key_check_value(int(key_type), raw_key)
            except Exception as e:
                print(f"[-] Key Check Value Error: {e}")
                return False

            payload.append(int(key_type) & 0xFF)
            payload.extend(self._lv(component_block))
            payload.append(len(kcv))
            payload.extend(kcv)
            key_check_values.extend(kcv)

        if len(payload) > 0xFF:
            print(
                "[-] Error: PUT KEY data exceeds 255 bytes; command chaining "
                "(§11.1.5.1) is not implemented."
            )
            return False

        p1 = int(old_kvn)
        p2 = int(key_id)
        if len(new_keys) > 1:
            p2 = p2 | 0x80

        # Table 11-64: Le '00'; §11.8.3.1 returns the KVN and check values.
        cmd = f"80D8{p1:02X}{p2:02X}{len(payload):02X}{payload.hex().upper()}00"
        res, sw1, sw2 = self.tp.transmit(cmd)

        if sw1 != 0x90:
            print(f"[-] PUT KEY Failed: {sw1:02X}{sw2:02X}")
            return False

        echoed = bytes(res or b"")
        if len(echoed) >= 1 and echoed[0] != int(new_kvn):
            print(
                f"[-] PUT KEY response reports KVN {echoed[0]:02X}, "
                f"expected {int(new_kvn):02X}."
            )
            return False
        if len(echoed) > 1 and echoed[1:] != bytes(key_check_values):
            print(
                f"[-] PUT KEY response check values {echoed[1:].hex().upper()} "
                f"differ from the computed {bytes(key_check_values).hex().upper()}."
            )
            return False
        print(f"[+] PUT KEY (Type 0x{int(key_type):02X}) Successful.")
        return True

    def _parse_cap_file_for_install(self, filename: str):
        if not os.path.exists(filename):
            print(
                f"{Config.Colors.FAIL}[!] File not found: {filename}{Config.Colors.ENDC}"
            )
            return None

        print(
            f"{Config.Colors.CYAN}[*] Parsing CAP file: {filename}...{Config.Colors.ENDC}"
        )
        try:
            parsed_cap = CapFileParser.parse_with_metadata(filename)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return None

        return parsed_cap

    def _load_cap_file_to_card(
        self, parsed_cap, load_chunk_size: Optional[int] = None
    ) -> bool:
        """Run INSTALL [for load] and LOAD for a parsed CAP/IJC package."""

        load_data = parsed_cap.load_block
        pkg_aid = parsed_cap.package_aid

        print(f"    Package AID: {pkg_aid.hex().upper()}")
        print(f"    Size: {len(load_data)} bytes")

        print(f"\n{Config.Colors.CYAN}[*] INSTALL [for load]...{Config.Colors.ENDC}")
        install_load_data = bytearray()
        install_load_data.append(len(pkg_aid))
        install_load_data.extend(pkg_aid)
        install_load_data.extend(b"\x00\x00\x00\x00")

        # Table 11-42 with an empty Security Domain AID, hash, parameters and
        # token; Table 11-40 makes INSTALL a case 4 command (Le '00').
        cmd_hex = f"80E60200{len(install_load_data):02X}{install_load_data.hex()}00"
        _, sw1, sw2 = self.tp.transmit(cmd_hex, silent=True)

        if sw1 != 0x90:
            print(
                f"{Config.Colors.FAIL}[-] Install [for load] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return False

        print(
            f"{Config.Colors.CYAN}[*] Loading {len(load_data)} bytes...{Config.Colors.ENDC}"
        )
        chunk_size = 240
        if load_chunk_size is not None:
            if load_chunk_size > 0:
                chunk_size = load_chunk_size

        is_secure_load = False
        if self.tp.session:
            if self.tp.session.is_authenticated:
                if self.tp.session.sec_level & 0x02:
                    is_secure_load = True

        if is_secure_load:
            if chunk_size > 239:
                chunk_size = 239
        try:
            load_chunks = CapFileParser.plan_load_chunks(parsed_cap, chunk_size)
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Chunk Plan Error: {e}{Config.Colors.ENDC}")
            return False

        total_chunks = len(load_chunks)

        for i, chunk_info in enumerate(load_chunks):
            chunk = chunk_info.payload

            p1 = 0x00
            if i >= total_chunks - 1:
                p1 = 0x80

            p2 = i % 256

            # Table 11-57: P1.b8 = 1 marks the last block; Table 11-56: Le '00'.
            cmd = f"80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk.hex()}00"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

            print(f"\r    Sending Block {i + 1}/{total_chunks}...", end="", flush=True)

            if sw1 != 0x90:
                print(
                    f"\n{Config.Colors.FAIL}[-] LOAD Failed at block {i}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                )
                return False

        print(f"\n{Config.Colors.GREEN}[+] Load Complete.{Config.Colors.ENDC}")
        return True

    @staticmethod
    def _extract_install_apdu_data(apdu: bytes) -> bytes:
        if len(apdu) < 5:
            raise ValueError("INSTALL APDU must include CLA INS P1 P2 Lc.")

        lc_byte = apdu[4]
        data_offset = 5
        data_len = lc_byte
        max_trailing = 1

        if lc_byte == 0x00:
            if len(apdu) < 7:
                raise ValueError(
                    "Extended-length INSTALL APDU is missing the two-byte Lc."
                )
            data_len = int.from_bytes(apdu[5:7], "big")
            data_offset = 7
            max_trailing = 2

        data_end = data_offset + data_len
        if len(apdu) < data_end:
            raise ValueError("INSTALL APDU Lc exceeds the supplied APDU length.")

        trailing_len = len(apdu) - data_end
        if trailing_len > max_trailing:
            raise ValueError("INSTALL APDU has extra bytes after the data field.")

        return apdu[data_offset:data_end]

    @staticmethod
    def _first_lv_value(data: bytes, field_name: str) -> bytes:
        if len(data) < 1:
            raise ValueError(f"INSTALL APDU data is missing {field_name} length.")

        value_len = data[0]
        value_end = 1 + value_len
        if len(data) < value_end:
            raise ValueError(f"INSTALL APDU {field_name} LV overruns the data field.")

        return data[1:value_end]

    @staticmethod
    def _normalize_install_for_install_apdu(install_apdu: str) -> Tuple[str, bytes]:
        try:
            apdu = HexUtils.to_bytes(install_apdu)
        except ValueError:
            raise ValueError("INSTALL APDU is not valid hexadecimal data.")

        if len(apdu) < 5:
            raise ValueError("INSTALL APDU must include CLA INS P1 P2 Lc.")

        if apdu[1] != 0xE6:
            raise ValueError("Supplied APDU must use INSTALL instruction E6.")

        if apdu[2] not in (0x04, 0x0C):
            raise ValueError(
                "Supplied APDU must be INSTALL [for install] P1=04 or P1=0C."
            )

        if apdu[3] != 0x00:
            raise ValueError("Supplied INSTALL APDU must use P2=00.")

        data = GlobalPlatformManager._extract_install_apdu_data(apdu)
        load_file_aid = GlobalPlatformManager._first_lv_value(data, "Load File AID")
        return apdu.hex().upper(), load_file_aid

    def install_cap_file_with_install_apdu(
        self, filename: str, install_apdu: str, load_chunk_size: Optional[int] = None
    ) -> bool:
        """Load a CAP/IJC package and send a caller-supplied INSTALL [for install] APDU."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}"
            )
            return False

        try:
            final_apdu, install_load_file_aid = (
                self._normalize_install_for_install_apdu(install_apdu)
            )
        except ValueError as e:
            print(
                f"{Config.Colors.FAIL}[!] Invalid INSTALL APDU: {e}{Config.Colors.ENDC}"
            )
            return False

        parsed_cap = self._parse_cap_file_for_install(filename)
        if parsed_cap is None:
            return False

        pkg_aid = parsed_cap.package_aid
        if install_load_file_aid != pkg_aid:
            print(
                f"{Config.Colors.FAIL}[!] INSTALL APDU Load File AID "
                f"{install_load_file_aid.hex().upper()} does not match CAP package AID "
                f"{pkg_aid.hex().upper()}.{Config.Colors.ENDC}"
            )
            return False

        loaded = self._load_cap_file_to_card(
            parsed_cap, load_chunk_size=load_chunk_size
        )
        if not loaded:
            return False

        print(
            f"{Config.Colors.CYAN}[*] INSTALL [for install] from supplied APDU...{Config.Colors.ENDC}"
        )
        _, sw1, sw2 = self.tp.transmit(final_apdu, silent=True)

        if sw1 == 0x90:
            print(
                f"{Config.Colors.GREEN}[+] Applet Installed Successfully.{Config.Colors.ENDC}"
            )
            return True

        print(
            f"{Config.Colors.FAIL}[-] Install Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
        )
        return False

    def install_cap_file(
        self,
        filename: str,
        privileges: str = "00",
        install_params: str = "C900",
        instantiate: bool = True,
        target_app_aid: str = None,
        target_module_aid: str = None,
        load_chunk_size: Optional[int] = None,
    ):
        """
        GlobalPlatform INSTALL (GPCS 11.5).
        Handles INSTALL [for load], LOAD (80 E8), and INSTALL [for install].
        """
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated (AUTH) first.{Config.Colors.ENDC}"
            )
            return

        parsed_cap = self._parse_cap_file_for_install(filename)
        if parsed_cap is None:
            return

        pkg_aid = parsed_cap.package_aid
        app_aids = parsed_cap.applet_aids

        loaded = self._load_cap_file_to_card(
            parsed_cap, load_chunk_size=load_chunk_size
        )
        if not loaded:
            return

        if not instantiate:
            print(
                f"{Config.Colors.CYAN}[*] Skipping instantiation (LOAD only mode).{Config.Colors.ENDC}"
            )
            return

        if not app_aids and not target_app_aid:
            print(
                f"{Config.Colors.GREEN}[+] Library Loaded (No Applets to install).{Config.Colors.ENDC}"
            )
            return

        applet_aid = app_aids[0]
        if target_app_aid:
            applet_aid = HexUtils.to_bytes(target_app_aid)

        module_aid = applet_aid
        if target_module_aid:
            module_aid = HexUtils.to_bytes(target_module_aid)

        print(
            f"{Config.Colors.CYAN}[*] INSTALL [for install] Applet: {applet_aid.hex().upper()}...{Config.Colors.ENDC}"
        )
        print(f"    Module    : {module_aid.hex().upper()}")
        print(f"    Privileges: {privileges}")
        print(f"    Params    : {install_params}")

        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = HexUtils.to_bytes(install_params)

        install_data = bytearray()
        install_data.append(len(pkg_aid))
        install_data.extend(pkg_aid)
        install_data.append(len(module_aid))
        install_data.extend(module_aid)
        install_data.append(len(applet_aid))
        install_data.extend(applet_aid)

        install_data.append(len(priv_bytes))
        install_data.extend(priv_bytes)
        install_data.extend(self._lv(param_bytes))
        install_data.append(0x00)

        cmd = self._build_case4_apdu(0x80, 0xE6, 0x0C, 0x00, bytes(install_data))
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(
                f"{Config.Colors.GREEN}[+] Applet Installed Successfully.{Config.Colors.ENDC}"
            )
        else:
            print(
                f"{Config.Colors.FAIL}[-] Install Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    def get_keys_info(self, target_aid_hex: Optional[str] = None, silent=False):
        """Print the installed key information from GET KEY INFORMATION DATA for the active or target SD."""
        if target_aid_hex:
            if not silent:
                print(
                    f"{Config.Colors.CYAN}[*] Selecting AID: {target_aid_hex}...{Config.Colors.ENDC}"
                )
            self.tp.transmit(
                f"00A40400{len(target_aid_hex) // 2:02X}{target_aid_hex}", silent=True
            )
        else:
            if not self.tp.session or not self.tp.session.is_authenticated:
                aid_hex = self.target_aid.hex().upper()
                self.tp.transmit(
                    f"00A40400{len(self.target_aid):02X}{aid_hex}", silent=True
                )

        if not silent:
            print(
                f"{Config.Colors.CYAN}[*] Retrieving Key Information Template...{Config.Colors.ENDC}"
            )

        data, sw1, sw2 = self.tp.transmit("80CA00E000", silent=silent)

        if sw1 == 0x90 and not silent:
            self._decode_key_template(data)
        elif sw1 != 0x90 and not silent:
            print(
                f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    #: GPC v2.3.1 Table 11-16 key type coding. '81'..'84', '90' and '91'
    #: are "reserved for historical reasons" and stay as their hex value.
    _KEY_TYPE_NAMES = {
        0x80: "DES",
        0x85: "TLS PSK",
        0x88: "AES",
        0x89: "SM4",
        0xA0: "RSA public exponent",
        0xA1: "RSA public modulus",
        0xA2: "RSA private modulus",
        0xA3: "RSA private exponent",
        0xA4: "RSA CRT P",
        0xA5: "RSA CRT Q",
        0xA6: "RSA CRT PQ",
        0xA7: "RSA CRT DP1",
        0xA8: "RSA CRT DQ1",
        0xB0: "ECC public",
        0xB1: "ECC private",
        0xB2: "ECC parameter P",
        0xB3: "ECC parameter A",
        0xB4: "ECC parameter B",
        0xB5: "ECC parameter G",
        0xB6: "ECC parameter N",
        0xB7: "ECC parameter k",
        0xB8: "SM2 public",
        0xB9: "SM2 private",
        0xF0: "ECC parameters reference",
    }

    def _parse_key_template_entries(self, data: bytes) -> List[Dict[str, Any]]:
        """Decode GP Key Information Template (E0/C0) entries (GPC v2.3.1 §11.3.3.1.1).

        A basic C0 value starts with KID/KVN and may contain more than one
        key-type/key-length component pair.  The previous byte scanner only
        recognized ``C0 04`` and could also false-match C0 bytes inside an
        unrelated value.
        """
        try:
            parsed = TlvParser.parse(bytes(data))
        except ValueError:
            return []

        template = parsed
        if 0xE0 in parsed:
            template = parsed[0xE0]
            if isinstance(template, bytes):
                try:
                    template = TlvParser.parse(template)
                except ValueError:
                    return []
        if not isinstance(template, dict):
            return []

        raw_c0_values = template.get(0xC0, [])
        if isinstance(raw_c0_values, bytes):
            raw_c0_values = [raw_c0_values]
        if not isinstance(raw_c0_values, list):
            return []

        type_map = self._KEY_TYPE_NAMES
        entries: List[Dict[str, Any]] = []
        for raw_value in raw_c0_values:
            if not isinstance(raw_value, (bytes, bytearray, memoryview)):
                return []
            value = bytes(raw_value)
            if len(value) < 4:
                return []

            kid = value[0]
            kver = value[1]
            components: List[Dict[str, Any]] = []
            usage_qualifier = b""
            access_condition = b""
            if value[2] == 0xFF:
                cursor = 2
                while cursor + 4 <= len(value) and value[cursor] == 0xFF:
                    extended_type = f"FF{value[cursor + 1]:02X}"
                    extended_length = int.from_bytes(
                        value[cursor + 2 : cursor + 4], "big"
                    )
                    if extended_length < 1 or extended_length > 0x7FFF:
                        return []
                    components.append(
                        {
                            "type": extended_type,
                            "type_code": extended_type,
                            "length": extended_length,
                        }
                    )
                    cursor += 4
                if len(components) == 0 or cursor >= len(value):
                    return []
                usage_length = value[cursor]
                cursor += 1
                if usage_length > 2 or cursor + usage_length > len(value):
                    return []
                usage_qualifier = value[cursor : cursor + usage_length]
                cursor += usage_length
                if cursor >= len(value):
                    return []
                access_length = value[cursor]
                cursor += 1
                if access_length > 1 or cursor + access_length != len(value):
                    return []
                access_condition = value[cursor : cursor + access_length]
                entry_format = "extended"
            else:
                component_data = value[2:]
                if len(component_data) % 2 != 0:
                    return []
                for offset in range(0, len(component_data), 2):
                    key_type = component_data[offset]
                    key_length = component_data[offset + 1]
                    if key_type == 0xFF:
                        return []
                    component: Dict[str, Any] = {
                        "type": type_map.get(key_type, f"{key_type:02X}"),
                        "type_code": f"{key_type:02X}",
                        "length": ">=256" if key_length == 0 else key_length,
                    }
                    if key_length == 0:
                        component["length_code"] = "00"
                        component["minimum_length"] = 256
                    if key_type == 0x80:
                        component["deprecated"] = True
                    if key_type == 0xF0:
                        # §11.3.3.1.1: for 'F0' the length byte carries the
                        # Key Parameter Reference instead of a length.
                        component["key_parameter_reference"] = f"{key_length:02X}"
                    components.append(component)
                entry_format = "basic"

            first_component = components[0]
            entries.append(
                {
                    "version": f"{kver:02X}",
                    "id": f"{kid:02X}",
                    "type": first_component["type"],
                    "length": first_component["length"],
                    "format": entry_format,
                    "components": components,
                    "key_usage_qualifier": usage_qualifier.hex().upper(),
                    "key_access_condition": access_condition.hex().upper(),
                    "raw_hex": value.hex().upper(),
                }
            )
        return entries

    def get_keys_info_data(
        self, target_aid_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return a dict of installed key information from GET KEY INFORMATION DATA."""
        if target_aid_hex:
            self.tp.transmit(
                f"00A40400{len(target_aid_hex) // 2:02X}{target_aid_hex}", silent=True
            )
        else:
            has_session = False
            if self.tp.session:
                has_session = True
            is_auth = False
            if has_session:
                if self.tp.session.is_authenticated:
                    is_auth = True
            if not is_auth:
                aid_hex = self.target_aid.hex().upper()
                self.tp.transmit(
                    f"00A40400{len(self.target_aid):02X}{aid_hex}", silent=True
                )

        data, sw1, sw2 = self.tp.transmit("80CA00E000", silent=True)
        out: Dict[str, Any] = {
            "status": f"{sw1:02X}{sw2:02X}",
            "raw_hex": data.hex().upper(),
        }
        if sw1 == 0x90:
            out["entries"] = self._parse_key_template_entries(data)
        return out

    # GPC v2.3.1 §11.4.2.1: '80' reports the Issuer Security Domain only, so a
    # Supplementary Security Domain is reached through the '40' subset and told
    # apart from an Application by the Security Domain privilege (Table 11-7,
    # byte 1 b8). The SD view therefore reads both subsets.
    REGISTRY_P1_BY_KIND = {"APPS": 0x40, "PACKAGES": 0x20, "SD": 0x80}
    SECURITY_DOMAIN_PRIVILEGE = 0x80

    def _collect_get_status(
        self, p1: int, silent: bool
    ) -> Tuple[bytes, int, int, int, bool]:
        """Run one GET STATUS subset to exhaustion and return its concatenated data.

        Returns ``(data, sw1, sw2, pages, truncated)``. GPC v2.3.1 §11.4.2.2
        Table 11-34: P2.b2 = 1 requests the Table 11-36 / 11-37 response format
        (b2 = 0 is deprecated and may be rejected) and P2.b1 = 1 asks for the
        next occurrences, which Table 11-38 '63 10' invites.
        """
        p2 = self.GET_STATUS_P2_FIRST
        full_data = bytearray()
        pages = 0
        last_sw1 = 0x6F
        last_sw2 = 0x00
        truncated = False

        while True:
            pages += 1
            cmd = f"80F2{p1:02X}{p2:02X}024F0000"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=silent)
            last_sw1 = sw1
            last_sw2 = sw2

            if sw1 in (0x90, 0x63) and len(data) > 0:
                full_data.extend(data)

            if sw1 == 0x90:
                break
            if sw1 == 0x63 and sw2 == 0x10:
                if pages >= self.MAX_GET_STATUS_PAGES:
                    truncated = True
                    break
                p2 = self.GET_STATUS_P2_NEXT
                continue
            break

        return bytes(full_data), last_sw1, last_sw2, pages, truncated

    def _is_security_domain_row(self, privileges_hex: str) -> bool:
        """True when the privileges byte 1 carries the Security Domain bit (Table 11-7)."""
        text = str(privileges_hex or "").strip()
        if len(text) < 2:
            return False
        try:
            first_byte = int(text[0:2], 16)
        except ValueError:
            return False
        return (first_byte & self.SECURITY_DOMAIN_PRIVILEGE) != 0

    def _supplementary_domain_rows(
        self, silent: bool
    ) -> List[Tuple[str, int, str]]:
        """Return the '40' subset rows that carry the Security Domain privilege."""
        data, _sw1, _sw2, _pages, _truncated = self._collect_get_status(0x40, silent)
        rows = self._registry_rows_from_data(data, "APPS")
        return [row for row in rows if self._is_security_domain_row(row[2])]

    def list_registry(self, kind="APPS"):
        """Print the GET STATUS application/package/SD registry for *kind* (APPS, PACKAGES, or SD)."""
        kind = str(kind).strip().upper()
        if kind not in self.REGISTRY_P1_BY_KIND:
            raise ValueError("Registry kind must be APPS, PACKAGES, or SD.")
        p1 = self.REGISTRY_P1_BY_KIND[kind]

        full_data, sw1, sw2, pages, truncated = self._collect_get_status(p1, silent=False)
        if truncated:
            print(
                f"{Config.Colors.FAIL}[-] Registry response exceeded "
                f"{self.MAX_GET_STATUS_PAGES} pages; stopping.{Config.Colors.ENDC}"
            )
        if sw1 not in (0x90, 0x63, 0x6A):
            print(
                f"{Config.Colors.FAIL}[-] Error listing registry: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

        supplementary: List[Tuple[str, int, str]] = []
        if kind == "SD":
            supplementary = self._supplementary_domain_rows(False)
        self._parse_registry_response(full_data, kind, supplementary)

    def _parse_registry_response(
        self,
        data,
        kind,
        supplementary: Optional[List[Tuple[str, int, str]]] = None,
    ):
        """Print one registry subset.

        ``supplementary`` carries the Security Domain rows read from the '40'
        subset for the SD view. Their Life Cycle State follows GPC v2.3.1
        Table 11-5, not the card's Table 11-6, so they are rendered with the
        Application/Security Domain names.
        """
        last_col = "Privileges"
        if kind == "PACKAGES":
            last_col = "Assoc SD"

        print(
            f"\n{Config.Colors.HEADER}--- GlobalPlatform Registry ({kind}) ---{Config.Colors.ENDC}"
        )
        print(f"{'AID':<34} | {'State':<12} | {last_col}")
        print("-" * 65)

        payload = bytes(data or b"")
        rows = self._registry_rows_from_data(payload, kind)
        extra_rows = list(supplementary or [])
        if len(rows) == 0 and len(extra_rows) == 0:
            if len(payload) > 0 and payload[0] == 0x62:
                print(
                    f"{Config.Colors.WARNING}[!] Response is an FCP template, not a GP registry response.{Config.Colors.ENDC}"
                )
            else:
                print(
                    f"{Config.Colors.WARNING}[!] No GP registry entries decoded from response.{Config.Colors.ENDC}"
                )
            return

        seen = set()
        for aid, state_byte, extra in rows:
            seen.add(aid)
            self._print_registry_row(aid, state_byte, extra, kind)
        for aid, state_byte, extra in extra_rows:
            if aid in seen:
                continue
            self._print_registry_row(aid, state_byte, extra, "APPS")

    def _print_registry_row(self, aid, lcs_byte, extra, kind: str = "APPS"):
        state_str = self._state_to_string(lcs_byte, kind)
        print(f"{aid:<34} | {state_str:<12} | {extra}")

    # GPC v2.3.1 §11.1.1 codes the Life Cycle State on one byte, read against
    # the table the GET STATUS subset selects: Table 11-3 for Executable Load
    # Files, Tables 11-4 / 11-5 for Applications and Security Domains, and
    # Table 11-6 (card Life Cycle) for the Issuer Security Domain.
    _ELF_LIFE_CYCLE_NAMES = {0x00: "LOGICALLY_DELETED", 0x01: "LOADED"}
    _CARD_LIFE_CYCLE_NAMES = {
        0x01: "OP_READY",
        0x07: "INITIALIZED",
        0x0F: "SECURED",
        0x7F: "CARD_LOCKED",
        0xFF: "TERMINATED",
    }
    _APPLICATION_LIFE_CYCLE_NAMES = {
        0x03: "INSTALLED",
        0x07: "SELECTABLE",
        0x0F: "PERSONALIZED",
    }

    @classmethod
    def _state_to_string(cls, lcs_byte: int, kind: str = "APPS") -> str:
        state = int(lcs_byte) & 0xFF
        kind_upper = str(kind or "APPS").strip().upper()
        if kind_upper == "PACKAGES":
            return cls._ELF_LIFE_CYCLE_NAMES.get(state, f"0x{state:02X}")
        if kind_upper == "SD":
            return cls._CARD_LIFE_CYCLE_NAMES.get(state, f"0x{state:02X}")
        if state & 0x83 == 0x83:
            # Tables 11-4 / 11-5: b8 = 1 with b2b1 = 11 is LOCKED whatever
            # the remaining bits hold.
            return "LOCKED"
        if state in cls._APPLICATION_LIFE_CYCLE_NAMES:
            return cls._APPLICATION_LIFE_CYCLE_NAMES[state]
        if state & 0x87 == 0x07:
            # Table 11-4: b3..b1 = 111 with b7..b4 free is an application
            # specific state.
            return f"APP_SPECIFIC_0x{state:02X}"
        return f"0x{state:02X}"

    @classmethod
    def _is_known_life_cycle(cls, lcs_byte: int, kind: str) -> bool:
        return not cls._state_to_string(lcs_byte, kind).startswith("0x")

    @classmethod
    def _compact_registry_entry_at(
        cls, data: bytes, offset: int, kind: str
    ) -> Optional[Tuple[str, int, str, int]]:
        if offset >= len(data):
            return None

        aid_len = data[offset]
        if not (5 <= aid_len <= 16):
            return None

        aid_start = offset + 1
        aid_end = aid_start + aid_len
        min_end = aid_end + 2
        if min_end > len(data):
            return None

        state_byte = data[aid_end]
        if not cls._is_known_life_cycle(state_byte, kind):
            return None

        extra_byte = data[aid_end + 1]
        next_offset = aid_end + 2
        extra = f"{extra_byte:02X}"

        if kind == "PACKAGES" and extra_byte > 0:
            if extra_byte > 16:
                return None
            if next_offset + extra_byte > len(data):
                return None
            extra = data[next_offset : next_offset + extra_byte].hex().upper()
            next_offset += extra_byte

        aid = data[aid_start:aid_end].hex().upper()
        return aid, state_byte, extra, next_offset

    @staticmethod
    def _registry_ber_length_at(data: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(data):
            raise ValueError("Registry TLV is missing its length.")
        first = data[offset]
        offset += 1
        if first < 0x80:
            return first, offset
        count = first & 0x7F
        if count == 0:
            raise ValueError("Registry TLV uses an indefinite BER length.")
        if count > 4 or offset + count > len(data):
            raise ValueError("Registry TLV has a truncated BER length.")
        if data[offset] == 0x00:
            raise ValueError("Registry TLV uses a non-minimal BER length.")
        length = int.from_bytes(data[offset : offset + count], "big")
        if length < 0x80:
            raise ValueError("Registry TLV uses a non-minimal BER length.")
        return length, offset + count

    @staticmethod
    def _registry_first_bytes(value: Any) -> Optional[bytes]:
        if isinstance(value, list):
            if len(value) == 0:
                return None
            value = value[0]
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        return None

    def _registry_rows_from_data(
        self, data: bytes, kind: str
    ) -> List[Tuple[str, int, str]]:
        rows: List[Tuple[str, int, str]] = []
        if len(data) > 0 and data[0] == 0xE3:
            i = 0
            while i < len(data):
                if data[i] != 0xE3:
                    return []
                try:
                    tag_len, value_offset = self._registry_ber_length_at(data, i + 1)
                except ValueError:
                    return []
                end = value_offset + tag_len
                if end > len(data):
                    return []
                entry = data[value_offset:end]
                i = end
                try:
                    parsed = TlvParser.parse(entry)
                except ValueError:
                    return []

                aid_value = self._registry_first_bytes(parsed.get(0x4F))
                lcs_value = self._registry_first_bytes(parsed.get(0x9F70))
                if aid_value is None or not (5 <= len(aid_value) <= 16):
                    return []
                if lcs_value is None or len(lcs_value) != 1:
                    return []
                aid = aid_value.hex().upper()
                lcs_byte = lcs_value[0]

                extra = ""
                extra_value = self._registry_first_bytes(parsed.get(0xC5))
                if extra_value is None and kind == "PACKAGES":
                    # Table 11-37: an Executable Load File entry carries no
                    # privileges; show the associated Security Domain instead.
                    extra_value = self._registry_first_bytes(parsed.get(0xCC))
                if extra_value is not None:
                    extra = extra_value.hex().upper()

                rows.append((aid, lcs_byte, extra))
            return rows

        i = 0
        while i < len(data):
            entry = self._compact_registry_entry_at(data, i, kind)
            if entry is None:
                return []

            aid, lcs_byte, extra, next_i = entry
            rows.append((aid, lcs_byte, extra))
            i = next_i
        return rows

    def _registry_entries_from_data(
        self, data: bytes, kind: str
    ) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for aid, lcs_byte, extra in self._registry_rows_from_data(data, kind):
            entries.append(
                {
                    "aid": aid,
                    "state": self._state_to_string(lcs_byte, kind),
                    "extra": extra,
                }
            )
        return entries

    def get_registry_data(self, kind: str = "APPS") -> Dict[str, Any]:
        """Return a dict of GET STATUS registry entries for *kind* (APPS, PACKAGES, or SD)."""
        kind = str(kind).strip().upper()
        if kind not in self.REGISTRY_P1_BY_KIND:
            raise ValueError("Registry kind must be APPS, PACKAGES, or SD.")
        p1 = self.REGISTRY_P1_BY_KIND[kind]

        full_data, last_sw1, last_sw2, pages, truncated = self._collect_get_status(
            p1, silent=True
        )
        entries = self._registry_entries_from_data(bytes(full_data), kind)
        if kind == "SD":
            # §11.4.2.1: the '80' subset holds the Issuer Security Domain only,
            # so the Supplementary Security Domains come from the '40' subset,
            # rendered with the Table 11-5 names rather than the card's.
            known = {str(entry.get("aid", "")) for entry in entries}
            for aid, lcs_byte, extra in self._supplementary_domain_rows(True):
                if aid in known:
                    continue
                entries.append(
                    {
                        "aid": aid,
                        "state": self._state_to_string(lcs_byte, "APPS"),
                        "extra": extra,
                    }
                )
        return {
            "kind": kind,
            "status": f"{last_sw1:02X}{last_sw2:02X}",
            "pages": pages,
            "truncated": truncated,
            "count": len(entries),
            "entries": entries,
            "raw_hex": bytes(full_data).hex().upper(),
        }

    def _decode_key_template(self, data: bytes):
        from SCP03.config import Config

        print(f"\n{Config.Colors.HEADER}--- Card Key Registry ---{Config.Colors.ENDC}")
        print(f"{'Version':<10} | {'ID':<10} | {'Type':<12} | {'Length'}")
        print("-" * 50)
        entries = self._parse_key_template_entries(data)
        for entry in entries:
            version = str(entry.get("version", "00"))
            key_id = str(entry.get("id", "00"))
            components = entry.get("components", [])
            if not isinstance(components, list):
                components = []
            for component_index, component in enumerate(components):
                if not isinstance(component, dict):
                    continue
                type_text = str(component.get("type", "Unknown"))
                length = component.get("length", "Unknown")
                version_text = f"0x{version}" if component_index == 0 else ""
                id_text = f"0x{key_id}" if component_index == 0 else ""
                print(
                    f"{version_text:<10} | {id_text:<10} | {type_text:<12} | {length}"
                )

        if not entries:
            print("  (No valid keys detected or parsing failed)")
        print("-" * 50 + "\n")

    def get_cplc(self):
        """Send GET DATA 9F7F and print the Card Production Life Cycle data.

        Tag '9F7F' is proprietary data as far as GPC v2.3.1 §11.3 goes, and
        no document in the specification library defines its field layout,
        so the value is shown as hex only.
        """
        cmd = "80CA9F7F00"
        data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
        if sw1 != 0x90:
            print(
                f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return
        value = bytes(data)
        try:
            parsed = TlvParser.parse(value)
        except Exception:
            parsed = {}
        inner = parsed.get(0x9F7F)
        if isinstance(inner, list) and len(inner) > 0:
            inner = inner[0]
        if isinstance(inner, (bytes, bytearray)):
            value = bytes(inner)
        print(f"{Config.Colors.HEADER}--- CPLC (tag 9F7F) ---{Config.Colors.ENDC}")
        print(f"    Length : {len(value)} bytes")
        print(f"    Value  : {value.hex().upper()}")

    def get_cplc_data(self) -> Tuple[Optional[bytes], int, int]:
        """Return CPLC data and status without printing. For use in export/report."""
        cmd = "80CA9F7F00"
        data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        return (data if sw1 == 0x90 else None, sw1, sw2)

    def get_data_raw(self, p1: int, p2: int) -> Tuple[bytes, int, int]:
        if p1 == 0x2F and p2 == 0x00:
            cmd = f"80CA{p1:02X}{p2:02X}025C0000"
        else:
            cmd = f"80CA{p1:02X}{p2:02X}00"
        return self.tp.transmit(cmd, silent=True)

    def get_data(self, p1: int, p2: int):
        """Send GET DATA for the given P1/P2 tag pair and print the decoded response."""
        print(
            f"{Config.Colors.CYAN}[*] GET DATA Tag: {p1:02X}{p2:02X}...{Config.Colors.ENDC}"
        )

        if p1 == 0x2F and p2 == 0x00:
            cmd = f"80CA{p1:02X}{p2:02X}025C0000"
        else:
            cmd = f"80CA{p1:02X}{p2:02X}00"

        data, sw1, sw2 = self.tp.transmit(cmd, silent=False)

        if sw1 == 0x90:
            try:
                parsed = TlvParser.parse(data)
                self.print_tlv_data(parsed)
            except Exception:
                pass
        else:
            err_map = {
                0x6A88: "Referenced Data Not Found (Tag not supported or empty)",
                0x6A81: "Function Not Supported",
                0x6982: "Security Status Unsatisfied",
                0x6985: "Conditions Not Satisfied",
            }
            sw_full = (sw1 << 8) | sw2
            err_msg = err_map.get(sw_full, "Unknown Error")
            print(
                f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X} -> {err_msg}{Config.Colors.ENDC}"
            )

    def print_tlv_data(self, tlv_dict: Dict[int, Any], indent: int = 0):
        """Recursively print a tag→value dict as an indented TLV tree."""
        indent_str = "  " * indent
        for tag, val in tlv_dict.items():
            tag_hex = f"{tag:02X}" if tag <= 0xFF else f"{tag:04X}"

            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        print(
                            f"{indent_str}{Config.Colors.BOLD}Tag {tag_hex}:{Config.Colors.ENDC}"
                        )
                        self.print_tlv_data(item, indent + 1)
                    elif isinstance(item, bytes):
                        item_hex = item.hex().upper()
                        print(f"{indent_str}Tag {tag_hex} (L={len(item)}): {item_hex}")
                continue
            if isinstance(val, dict):
                print(
                    f"{indent_str}{Config.Colors.BOLD}Tag {tag_hex}:{Config.Colors.ENDC}"
                )
                self.print_tlv_data(val, indent + 1)
            elif isinstance(val, bytes):
                val_hex = val.hex().upper()
                ascii_str = ""
                try:
                    s = val.decode("utf-8")
                    safe_chars = set(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.:/,"
                    )
                    if len(s) > 1 and all(c in safe_chars for c in s):
                        ascii_str = f" ('{s}')"
                except UnicodeDecodeError:
                    pass

                print(f"{indent_str}Tag {tag_hex} (L={len(val)}): {val_hex}{ascii_str}")

    def set_status(self, target_aid, state_byte: int, status_type: int = 0x40):
        """Send SET STATUS (GPCS 2.3.1 §11.10) to transition a life-cycle state.

        P1 carries the Status Type of Table 11-86, not zero: '80' for the
        Issuer Security Domain, '40' for an Application or Supplementary
        Security Domain, '60' for a Security Domain and its associated
        Applications. Callers targeting an application AID want '40',
        which is the default here.
        """
        target = HexUtils.to_bytes(target_aid)
        state_name = f"{state_byte:02X}"
        if state_byte == 0x80:
            state_name = "LOCKED"
        elif state_byte == 0x07:
            state_name = "SELECTABLE"

        print(
            f"{Config.Colors.CYAN}[*] Setting Status of {target.hex().upper()} to {state_name}...{Config.Colors.ENDC}"
        )
        cmd = f"80F0{status_type:02X}{state_byte:02X}{len(target):02X}{target.hex()}"
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Status Updated.{Config.Colors.ENDC}")
        else:
            print(
                f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    def delete_object(self, target_aid, recursive=True):
        """Send DELETE (GP Card Spec v2.3 §11.2) to remove an application or load-file by AID."""
        target = HexUtils.to_bytes(target_aid)
        p2 = 0x00
        if recursive:
            p2 = 0x80

        tlv = f"4F{len(target):02X}{target.hex()}"
        # Table 11-20: Le '00'; the response carries the delete confirmation.
        cmd = f"80E400{p2:02X}{len(bytes.fromhex(tlv)):02X}{tlv}00"
        print(
            f"{Config.Colors.WARNING}[!] Deleting {target.hex()}...{Config.Colors.ENDC}"
        )
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)
        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Deleted.{Config.Colors.ENDC}")
        else:
            print(
                f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )

    def _send_install_cmd(self, p1: int, data: bytes, description: str) -> bool:
        """Generic helper for INSTALL commands."""
        print(f"{Config.Colors.CYAN}[*] INSTALL [{description}]...{Config.Colors.ENDC}")
        cmd = self._build_case4_apdu(0x80, 0xE6, p1, 0x00, data)
        _, sw1, sw2 = self.tp.transmit(cmd, silent=True)

        if sw1 == 0x90:
            print(f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
            return True
        else:
            print(
                f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
            )
            return False

    def install_for_load(
        self,
        load_file_aid_hex: str,
        security_domain_aid_hex: str = "",
        load_file_hash_hex: str = "",
        params: str = "",
        token: str = "",
    ):
        """GP INSTALL [for load] (P1=0x02) with explicit LV fields."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        load_file_aid = HexUtils.to_bytes(load_file_aid_hex)
        security_domain_aid = b""
        if security_domain_aid_hex:
            security_domain_aid = HexUtils.to_bytes(security_domain_aid_hex)
        load_file_hash = b""
        if load_file_hash_hex:
            load_file_hash = HexUtils.to_bytes(load_file_hash_hex)
        param_bytes = b""
        if params:
            param_bytes = HexUtils.to_bytes(params)
        token_bytes = b""
        if token:
            token_bytes = HexUtils.to_bytes(token)

        payload = bytearray()
        payload.append(len(load_file_aid))
        payload.extend(load_file_aid)
        payload.append(len(security_domain_aid))
        payload.extend(security_domain_aid)
        # Table 11-42: the hash length is one byte ('00'-'7F'); the parameter
        # and token lengths are BER-coded.
        payload.append(len(load_file_hash))
        payload.extend(load_file_hash)
        payload.extend(self._lv(param_bytes))
        payload.extend(self._lv(token_bytes))

        self._send_install_cmd(0x02, payload, "For Load")

    def install_make_selectable(
        self, aid_hex: str, privileges: str = "00", params: str = "", token: str = ""
    ):
        """GP INSTALL [for make selectable] (P1=0x08)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = b""
        if params:
            param_bytes = HexUtils.to_bytes(params)
        token_bytes = b""
        if token:
            token_bytes = HexUtils.to_bytes(token)

        # Table 11-44: two empty length fields, then the Application AID,
        # privileges, Make Selectable parameters and token.
        payload = bytearray()
        payload.append(0x00)
        payload.append(0x00)
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes)
        payload.extend(self._lv(param_bytes))
        payload.extend(self._lv(token_bytes))

        self._send_install_cmd(0x08, payload, "Make Selectable")

    def install_extradition(
        self, aid_hex: str, sd_aid_hex: str, token: str = "", params: str = ""
    ):
        """GP INSTALL [for extradition] (P1=0x10, GPC v2.3.1 Table 11-45)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        sd_bytes = HexUtils.to_bytes(sd_aid_hex)
        param_bytes = b""
        if params:
            param_bytes = HexUtils.to_bytes(params)
        token_bytes = b""
        if token:
            token_bytes = HexUtils.to_bytes(token)

        # Table 11-45: Security Domain AID, an empty length, the Application
        # or ELF AID, another empty length, then parameters and token.
        payload = bytearray()
        payload.append(len(sd_bytes))
        payload.extend(sd_bytes)
        payload.append(0x00)
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(0x00)
        payload.extend(self._lv(param_bytes))
        payload.extend(self._lv(token_bytes))

        self._send_install_cmd(0x10, payload, "Extradition")

    def install_personalization(self, aid_hex: str):
        """GP INSTALL [for personalization] (P1=0x20)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)

        # Table 11-47: two empty length fields, the Application AID, then
        # three more empty length fields.
        payload = bytearray()
        payload.append(0x00)
        payload.append(0x00)
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(0x00)
        payload.append(0x00)
        payload.append(0x00)

        self._send_install_cmd(0x20, payload, "Personalization")

    def get_ecasd_data(self):
        """Retrieves SGP.02/SGP.22 metadata from ECASD."""
        # SGP.22 v3.1 §2.4.2: the ECASD AID follows SGP.02, which the
        # specification library does not hold; the value is not verified.
        ECASD_AID = "A0000005591010FFFFFFFF8900000200"

        print(f"{Config.Colors.CYAN}[*] Selecting ECASD...{Config.Colors.ENDC}")
        self.tp.transmit(f"00A40400{len(ECASD_AID) // 2:02X}{ECASD_AID}", silent=True)

        queries = {
            "EID (5A)": "5A",
            "CIN (45)": "45",
            "IIN (42)": "42",
            "CPLC (9F7F)": "9F7F",
            "Key Info (E0)": "E0",
        }

        print(
            f"{Config.Colors.HEADER}--- ECASD Data (SGP.02/22) ---{Config.Colors.ENDC}"
        )

        for label, tag in queries.items():
            cmd = f"80CA{tag}00"
            if len(tag) > 2:
                cmd = f"80CA{tag}00"

            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x90 or sw1 == 0x61:
                hex_val = data.hex().upper()
                parsed = TlvParser.parse(data)

                tag_int = int(tag, 16)
                if tag_int in parsed:
                    val = parsed[tag_int]
                    if isinstance(val, bytes):
                        hex_val = val.hex().upper()

                print(f"{label:<15}: {hex_val}")
            else:
                print(
                    f"{label:<15}: {Config.Colors.FAIL}Not Found / Error {sw1:02X}{sw2:02X}{Config.Colors.ENDC}"
                )

    def install_app(
        self,
        pkg_aid_hex: str,
        app_aid_hex: str,
        mod_aid_hex: Optional[str] = None,
        privileges: str = "00",
        params: str = "C900",
        make_selectable: bool = True,
    ):
        """GP INSTALL [for install] / [for install and make selectable] (P1=0x04 / 0x0C)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        pkg_bytes = HexUtils.to_bytes(pkg_aid_hex)
        app_bytes = HexUtils.to_bytes(app_aid_hex)

        mod_bytes = app_bytes
        if mod_aid_hex:
            mod_bytes = HexUtils.to_bytes(mod_aid_hex)

        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = HexUtils.to_bytes(params)

        payload = bytearray()
        payload.append(len(pkg_bytes))
        payload.extend(pkg_bytes)
        payload.append(len(mod_bytes))
        payload.extend(mod_bytes)
        payload.append(len(app_bytes))
        payload.extend(app_bytes)
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes)
        payload.extend(self._lv(param_bytes))
        payload.append(0x00)

        p1 = 0x04
        desc = "Install"
        if make_selectable:
            p1 = 0x0C
            desc = "Install and Make Selectable"

        self._send_install_cmd(p1, payload, desc)

    def install_registry_update(
        self,
        aid_hex: str,
        privileges: str = "00",
        params: str = "",
        sd_aid_hex: str = "",
        token: str = "",
    ):
        """GP INSTALL [for registry update] (P1=0x40, GPC v2.3.1 Table 11-46)."""
        if not self.tp.session or not self.tp.session.is_authenticated:
            print(
                f"{Config.Colors.FAIL}[!] Error: Must be authenticated.{Config.Colors.ENDC}"
            )
            return

        aid_bytes = HexUtils.to_bytes(aid_hex)
        sd_bytes = b""
        if sd_aid_hex:
            sd_bytes = HexUtils.to_bytes(sd_aid_hex)
        priv_bytes = HexUtils.to_bytes(privileges)
        param_bytes = b""
        if params:
            param_bytes = HexUtils.to_bytes(params)
        token_bytes = b""
        if token:
            token_bytes = HexUtils.to_bytes(token)

        # Table 11-46: optional Security Domain AID (extradition target), an
        # empty length, the Application AID, privileges, parameters, token.
        payload = bytearray()
        payload.append(len(sd_bytes))
        payload.extend(sd_bytes)
        payload.append(0x00)
        payload.append(len(aid_bytes))
        payload.extend(aid_bytes)
        payload.append(len(priv_bytes))
        payload.extend(priv_bytes)
        payload.extend(self._lv(param_bytes))
        payload.extend(self._lv(token_bytes))

        self._send_install_cmd(0x40, payload, "Registry Update")
