# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from typing import Optional, Tuple
from SCP03.config import Config
from SCP03.core.utils import TlvParser

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False

# 3GPP TS 35.207 Table 1 – Test set 1 (Milenage)
AUTH_TEST_VECTOR = {
    "RAND": "23553CBE9637A89D218AE64DAE47BF35",
    "Ki": "465B5CE8B199B49FAA5F0A2EE238A6BC",
    "OP": "CDC202D5123E20F62B6D676AC72CB318",
    "OPc": "CD63CB71954A9F4E48A5994E37A02BAF",
    "RES": "A54211D5E3BA50BF",
    "CK": "B40BA9A3C58B2A05BBF0D987B21BF8CB",
    "IK": "F769BC432284C6FE2B7066554707B8D0",
}


class SecurityController:
    # [UPDATED] Init now accepts fs_ctrl to sync state during auto-selection
    def __init__(self, transport, fs_ctrl=None):
        self.tp = transport
        self.fs = fs_ctrl 

    def _pad_pin(self, pin_str: str) -> str:
        """Pads numeric PIN string to 8 bytes with 0xFF (ISO 7816-4)."""
        pin_bytes = str(pin_str).encode('ascii')
        if len(pin_bytes) > 8: return pin_bytes[:8].hex().upper()
        padding = b'\xFF' * (8 - len(pin_bytes))
        return (pin_bytes + padding).hex().upper()

    def verify_pin(self, pin_ref: str, pin_value: str):
        try:
            ref_byte = int(str(pin_ref), 16) if len(str(pin_ref)) > 1 else int(str(pin_ref))
            hex_data = self._pad_pin(pin_value)
            cmd = f"002000{ref_byte:02X}08{hex_data}"
            print(f"{Config.Colors.CYAN}[*] Verifying PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] PIN Verified.{Config.Colors.ENDC}")
            elif sw1 == 0x63: print(f"{Config.Colors.FAIL}[-] Failed. {sw2 & 0x0F} attempts remaining.{Config.Colors.ENDC}")
            elif sw1 == 0x69 and sw2 == 0x83: print(f"{Config.Colors.FAIL}[-] PIN Blocked.{Config.Colors.ENDC}")
            elif sw1 == 0x69 and sw2 == 0x84: print(f"{Config.Colors.FAIL}[-] PIN Blocked (Ref Invalidated).{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    # ... (Keep change_pin, disable_pin, enable_pin, unblock_pin as they were) ...
    def change_pin(self, pin_ref: str, old_pin: str, new_pin: str):
        try:
            ref_byte = int(str(pin_ref), 16) if len(str(pin_ref)) > 1 else int(str(pin_ref))
            payload = self._pad_pin(old_pin) + self._pad_pin(new_pin)
            cmd = f"002400{ref_byte:02X}10{payload}"
            print(f"{Config.Colors.CYAN}[*] Changing PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] PIN Changed.{Config.Colors.ENDC}")
            elif sw1 == 0x63: print(f"{Config.Colors.FAIL}[-] Failed. {sw2 & 0x0F} attempts remaining.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Error: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def disable_pin(self, pin_ref: str, pin_value: str):
        try:
            ref_byte = int(str(pin_ref), 16) if len(str(pin_ref)) > 1 else int(str(pin_ref))
            hex_data = self._pad_pin(pin_value)
            cmd = f"002600{ref_byte:02X}08{hex_data}"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] PIN Disabled.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def enable_pin(self, pin_ref: str, pin_value: str):
        try:
            ref_byte = int(str(pin_ref), 16) if len(str(pin_ref)) > 1 else int(str(pin_ref))
            hex_data = self._pad_pin(pin_value)
            cmd = f"002800{ref_byte:02X}08{hex_data}"
            _, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] PIN Enabled.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def unblock_pin(self, pin_ref: str, puk: str, new_pin: str):
        try:
            ref_byte = int(str(pin_ref), 16) if len(str(pin_ref)) > 1 else int(str(pin_ref))
            payload = self._pad_pin(puk) + self._pad_pin(new_pin)
            cmd = f"002C00{ref_byte:02X}10{payload}"
            print(f"{Config.Colors.CYAN}[*] Unblocking PIN (Ref: {ref_byte:02X})...{Config.Colors.ENDC}")
            _, sw1, sw2 = self.tp.transmit(cmd, silent=False)
            if sw1 == 0x90: print(f"{Config.Colors.GREEN}[+] PIN Unblocked.{Config.Colors.ENDC}")
            else: print(f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        except Exception as e: print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    @staticmethod
    def derive_opc(ki_hex: str, op_hex: str) -> str:
        """
        Derive OPc from Ki and OP per 3GPP TS 35.206:
        OPc = AES-128(Ki, OP) XOR OP.
        ki_hex, op_hex: 32 hex chars (16 bytes). Returns 32 hex chars OPc.
        """
        if not _AES_AVAILABLE:
            raise RuntimeError("cryptography required for OPc derivation")
        ki_hex = ki_hex.replace(" ", "").upper()
        op_hex = op_hex.replace(" ", "").upper()
        if len(ki_hex) != 32 or len(op_hex) != 32:
            raise ValueError("Ki and OP must be 32 hex chars (16 bytes) each")
        key = bytes.fromhex(ki_hex)
        plain = bytes.fromhex(op_hex)
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        enc = encryptor.update(plain) + encryptor.finalize()
        opc = bytes(a ^ b for a, b in zip(enc, plain))
        return opc.hex().upper()

    def run_auth_test_vector(self):
        """
        Run authentication using 3GPP TS 35.207 test set 1 and print expected vs card output.
        """
        print(f"{Config.Colors.HEADER}=== Milenage Test Vector (3GPP TS 35.207) ==={Config.Colors.ENDC}")
        print(f"  RAND: {AUTH_TEST_VECTOR['RAND']}")
        print(f"  Ki:   {AUTH_TEST_VECTOR['Ki']}")
        print(f"  OP:   {AUTH_TEST_VECTOR['OP']}")
        try:
            derived = self.derive_opc(AUTH_TEST_VECTOR["Ki"], AUTH_TEST_VECTOR["OP"])
            print(f"  OPc (derived): {derived}")
            print(f"  OPc (expected): {AUTH_TEST_VECTOR['OPc']}")
            match = "OK" if derived == AUTH_TEST_VECTOR["OPc"] else "MISMATCH"
            print(f"  OPc check: {Config.Colors.GREEN if match == 'OK' else Config.Colors.FAIL}{match}{Config.Colors.ENDC}")
        except Exception as e:
            print(f"  OPc derivation: {Config.Colors.FAIL}{e}{Config.Colors.ENDC}")
        print(f"  Expected RES: {AUTH_TEST_VECTOR['RES']}")
        print(f"  Expected CK:  {AUTH_TEST_VECTOR['CK']}")
        print(f"  Expected IK:  {AUTH_TEST_VECTOR['IK']}")
        print(f"{Config.Colors.CYAN}[*] Sending RAND to card (USIM auth)...{Config.Colors.ENDC}")
        self.run_auth(AUTH_TEST_VECTOR["RAND"], autn=None, app_context="USIM")

    def _smart_select_app(self, target_type: str) -> bool:
        # 1. Silent Scan Setup
        self.tp.transmit("00A40004023F00", silent=True)
        data, sw1, sw2 = self.tp.transmit("00A40004022F00", silent=True)
        if sw1 != 0x90 and sw1 != 0x61: return False

        # 2. Iterate Records
        found_aid = None
        for r in range(1, 30):
            cmd = f"00B2{r:02X}0400"
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True)
            if sw1 == 0x6C:
                data, sw1, sw2 = self.tp.transmit(f"00B2{r:02X}04{sw2:02X}", silent=True)
            if sw1 != 0x90: break 
            
            clean_data = data.rstrip(b'\xff')
            if not clean_data: continue

            try:
                rec = TlvParser.parse(clean_data)
                if 0x61 in rec:
                    inner_data = rec[0x61]
                    inner = TlvParser.parse(inner_data) if isinstance(inner_data, bytes) else inner_data
                    
                    aid = inner.get(0x4F, b'').hex().upper()
                    label = inner.get(0x50, b'').decode('ascii', 'ignore') if inner.get(0x50) else "Unknown"
                    
                    is_match = False
                    if target_type == "USIM" and aid.startswith("A000000087") and "1002" in aid: is_match = True
                    elif target_type == "ISIM" and aid.startswith("A000000087") and "1004" in aid: is_match = True
                    elif target_type == "GSM" and (aid.startswith("A000000009") or "GSM" in label): is_match = True
                    
                    if is_match:
                        print(f"{Config.Colors.CYAN}[*] Found {target_type} App: {label} ({aid}){Config.Colors.ENDC}")
                        found_aid = aid
                        break
            except: continue
            
        # 3. Select (SILENTLY)
        if found_aid:
             if self.fs:
                 print(f"{Config.Colors.CYAN}[*] Auto-selecting AID...{Config.Colors.ENDC}")
                 # [FIX] Silent=True suppresses the FCP dump
                 return self.fs.select(found_aid, silent=True)
             else:
                 _, sw1, sw2 = self.tp.transmit(f"00A40400{len(found_aid)//2:02X}{found_aid}")
                 return (sw1 == 0x90 or sw1 == 0x61)
        return False

    def run_auth(self, rand: str, autn: Optional[str] = None, app_context: str = "USIM"):
        try:
            rand_hex = rand.replace(" ", "").upper()
            if len(rand_hex) != 32: print(f"{Config.Colors.FAIL}[!] RAND must be 32 hex chars.{Config.Colors.ENDC}"); return

            if autn:
                autn_hex = autn.replace(" ", "").upper()
                if len(autn_hex) != 32: print(f"{Config.Colors.FAIL}[!] AUTN must be 32 hex chars.{Config.Colors.ENDC}"); return
                payload = f"10{rand_hex}10{autn_hex}"
                cmd = f"00880081{len(payload)//2:02X}{payload}00"
                msg = app_context 
            else:
                cmd = f"0088008010{rand_hex}00"
                msg = "GSM"

            print(f"{Config.Colors.CYAN}[*] Running {msg} Authentication...{Config.Colors.ENDC}")
            data, sw1, sw2 = self.tp.transmit(cmd, silent=True) # Silent first try
            
            # Smart Retry
            if sw1 == 0x69 and sw2 == 0x85:
                if self._smart_select_app(msg):
                    # [FIX] Updated String
                    print(f"{Config.Colors.CYAN}[*] Authenticating...{Config.Colors.ENDC}")
                    data, sw1, sw2 = self.tp.transmit(cmd, silent=False)
                else:
                    print(f"{Config.Colors.FAIL}[-] No {msg} Application found.{Config.Colors.ENDC}")
                    print(f"{Config.Colors.FAIL}[-] Auth Failed: 6985{Config.Colors.ENDC}")
                    return

            # Process Result
            if sw1 == 0x90 or sw1 == 0x61:
                self._parse_auth_response(data)
            elif sw1 == 0x98 and sw2 == 0x62:
                print(f"{Config.Colors.FAIL}[-] Auth Error: MAC verification failed (Key Mismatch?){Config.Colors.ENDC}")
            elif sw1 == 0xDC: 
                print(f"{Config.Colors.WARNING}[!] Sync Failure (AUTS returned){Config.Colors.ENDC}")
            else:
                print(f"{Config.Colors.FAIL}[-] Auth Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Error: {e}{Config.Colors.ENDC}")

    def _parse_auth_response(self, data: bytes):
        if not data: return
        if data[0] == 0xDC:
            print(f"{Config.Colors.WARNING}[!] Synchronization Failure (AUTS returned){Config.Colors.ENDC}")
            if len(data) > 2: print(f"    AUTS: {data[2:].hex().upper()}")
            return

        if data[0] == 0xDB:
            print(f"{Config.Colors.GREEN}[+] Authentication Successful{Config.Colors.ENDC}")
            idx = 1
            if idx < len(data) and data[idx] > 0x80: idx += 1 # Skip len if extended
            elif idx < len(data): idx += 1

            try:
                # 1. RES
                if idx < len(data):
                    res_len = data[idx]; idx += 1
                    print(f"    RES : {Config.Colors.GREEN}{data[idx:idx+res_len].hex().upper()}{Config.Colors.ENDC}")
                    idx += res_len
                # 2. CK
                if idx < len(data):
                    ck_len = data[idx]; idx += 1
                    print(f"    CK  : {Config.Colors.GREEN}{data[idx:idx+ck_len].hex().upper()}{Config.Colors.ENDC}")
                    idx += ck_len
                # 3. IK
                if idx < len(data):
                    ik_len = data[idx]; idx += 1
                    print(f"    IK  : {Config.Colors.GREEN}{data[idx:idx+ik_len].hex().upper()}{Config.Colors.ENDC}")
                    idx += ik_len
                # 4. Kc
                if idx < len(data):
                    kc_len = data[idx]; idx += 1
                    print(f"    Kc  : {Config.Colors.GREEN}{data[idx:idx+kc_len].hex().upper()}{Config.Colors.ENDC}")
            except:
                print(f"{Config.Colors.WARNING}[!] Output truncated{Config.Colors.ENDC}")
        # Plain GSM Response (SRES+Kc)
        elif len(data) >= 12: 
             print(f"    SRES: {Config.Colors.GREEN}{data[:4].hex().upper()}{Config.Colors.ENDC}")
             print(f"    Kc  : {Config.Colors.GREEN}{data[4:12].hex().upper()}{Config.Colors.ENDC}")