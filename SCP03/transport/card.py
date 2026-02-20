import traceback
from typing import Tuple, List, Optional
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

# Internal Project Imports
from SCP03.config import Config
from SCP03.core.utils import HexUtils
from SCP03.crypto.session import Scp03Session

class CardTransporter:
    def __init__(self):
        self.connection: Optional[CardConnection] = None
        self.session = Scp03Session({'kenc':b'','kmac':b''}) 
        self.verbose = False
        self.debug = False
        if not self.connect(): raise Exception("Could not connect to a smart card reader.")

    def connect(self) -> bool:
        try:
            r_list = readers()
            
            is_empty = False
            if not r_list:
                is_empty = True
                
            if is_empty: 
                print(f"{Config.Colors.FAIL}[!] No readers found.{Config.Colors.ENDC}")
                return False
                
            reader = r_list[0]
            print(f"{Config.Colors.CYAN}[*] CONNECTED{Config.Colors.ENDC}")
            
            self.connection = reader.createConnection()
            self.connection.connect()
            
            return True
        except Exception as e:
            print(f"{Config.Colors.FAIL}[!] Connection failed: {e}{Config.Colors.ENDC}")
            self.connection = None
            return False

    def disconnect(self):
        if self.connection: self.connection.disconnect()
        self.session.is_authenticated = False

    def logout(self) -> bool:
        if not self.session: return False
        was_active = bool(self.session.is_authenticated)
        self.session.is_authenticated = False
        self.session.chaining_value = b'\x00' * 16
        self.session.ssc = 0
        return was_active

    def reset(self) -> bool:
        if self.connection is None: return self.connect()
        try:
            self.connection.disconnect()
            self.connection.connect()
            return True
        except Exception as e:
            print(f"{Config.Colors.FAIL}[-] Reset Error: {e}{Config.Colors.ENDC}")
            return False

    def transmit(self, apdu_hex: str, silent: bool = False) -> Tuple[bytes, int, int]:
        if self.connection is None:
            if not self.connect(): return b'', 0x6F, 0x00
        try:
            raw = list(HexUtils.to_bytes(apdu_hex))
            
            # Encrypt if authenticated
            final_apdu = self.session.wrap_apdu(raw)

            # Transmit (No sending log)
            data, sw1, sw2 = self._transmit_recursive(final_apdu)

            # Decrypt if authenticated
            if self.session.is_authenticated and data:
                 try:
                     final_data = self.session.unwrap_response(bytes(data), sw1, sw2)
                     if final_data is not None: 
                         data = list(final_data)
                 except Exception as e:
                     if not silent: 
                         print(f"{Config.Colors.FAIL}[!] Response Unwrapping Failed: {e}{Config.Colors.ENDC}")

            # Standardized Output: [<--] DATA SW (No Spaces)
            if not silent:
                print(f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {bytes(data).hex().upper()} {sw1:02X}{sw2:02X}")
                
            return bytes(data), sw1, sw2
        except Exception as e:
            if not silent: 
                print(f"{Config.Colors.FAIL}[!] Transmit Error: {e}{Config.Colors.ENDC}")
            return b'', 0x6F, 0x00

    def _transmit_recursive(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        data, sw1, sw2 = self.connection.transmit(apdu)
        if sw1 == 0x6C:
            apdu = apdu[:4] + [sw2]
            return self._transmit_recursive(apdu)
        if sw1 == 0x61:
            accumulated = list(data)
            while sw1 == 0x61:
                chunk, sw1, sw2 = self.connection.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
                accumulated.extend(chunk)
            return accumulated, sw1, sw2
        return data, sw1, sw2