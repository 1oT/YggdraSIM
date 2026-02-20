from typing import List, Dict, Any, Union

class HexUtils:
    """Static helpers for byte manipulation."""
    @staticmethod
    def to_bytes(data: Union[str, bytes, List[int]]) -> bytes:
        if isinstance(data, bytes): return data
        if isinstance(data, list): return bytes(data)
        # Clean hex string (remove spaces, 0x prefix)
        clean = data.strip().replace(' ', '').replace(':', '').replace('0x', '')
        return bytes.fromhex(clean)

    @staticmethod
    def to_hex(data: bytes, space: bool = False) -> str:
        s = data.hex().upper()
        return ' '.join(s[i:i+2] for i in range(0, len(s), 2)) if space else s

class TlvParser:
    """Robust TLV Decoding Engine with Multi-byte Tag Support."""
    @staticmethod
    def parse(data: bytes) -> Dict[int, Any]:
        i, parsed = 0, {}
        while i < len(data):
            if i >= len(data): break
            
            # --- Tag Decoding ---
            tag_val = data[i]
            i += 1
            
            # Multi-byte tag check (if lower 5 bits are 11111)
            if (tag_val & 0x1F) == 0x1F:
                tag_val = tag_val << 8
                while i < len(data):
                    next_byte = data[i]
                    tag_val |= next_byte
                    i += 1
                    # If MSB is 0, it's the last byte of the tag
                    if not (next_byte & 0x80):
                        break
                    tag_val = tag_val << 8
            
            if i >= len(data): break
            
            # --- Length Decoding ---
            length = data[i]
            i += 1
            
            if length & 0x80:
                n_bytes = length & 0x7F
                if i + n_bytes > len(data): break
                length = int.from_bytes(data[i:i+n_bytes], 'big')
                i += n_bytes
            
            if i + length > len(data): break
            val = data[i:i+length]
            i += length
            
            # --- Recursive Parsing ---
            # Check the first byte of the tag to see if it is Constructed (bit 6 set)
            # We shift right to get the leading byte
            first_tag_byte = tag_val
            while first_tag_byte > 0xFF:
                first_tag_byte >>= 8
            
            if first_tag_byte & 0x20: 
                # Constructed -> Recurse
                parsed[tag_val] = TlvParser.parse(val)
            else: 
                # Primitive -> Raw Bytes
                parsed[tag_val] = val
                
        return parsed

class StatusWordTranslator:
    """Translates ISO 7816-4 and GlobalPlatform Status Words into human-readable strings."""
    
    SW_MAP = {
        0x9000: "Success",
        0x6100: "More data available",
        0x6283: "Selected file invalidated",
        0x6300: "Authentication failed",
        0x6400: "State of non-volatile memory unchanged",
        0x6700: "Wrong length",
        0x6881: "Logical channel not supported",
        0x6882: "Secure messaging not supported",
        0x6982: "Security status not satisfied",
        0x6983: "Authentication method blocked",
        0x6984: "Referenced data invalidated",
        0x6985: "Conditions of use not satisfied",
        0x6A80: "Incorrect parameters in data field",
        0x6A81: "Function not supported",
        0x6A82: "File not found / Applet not found",
        0x6A83: "Record not found",
        0x6A84: "Not enough memory space in file",
        0x6A86: "Incorrect parameters P1-P2",
        0x6A88: "Referenced data not found",
        0x6D00: "Instruction code not supported or invalid",
        0x6E00: "Class not supported",
        0x6F00: "Unknown error / No precise diagnosis"
    }

    @staticmethod
    def translate(sw1: int, sw2: int) -> str:
        sw = (sw1 << 8) | sw2
        
        if sw in StatusWordTranslator.SW_MAP:
            return StatusWordTranslator.SW_MAP[sw]
            
        if sw1 == 0x61:
            return f"Success. {sw2} bytes of data available to read."
            
        if sw1 == 0x6C:
            return f"Wrong Le length. Correct length is {sw2}."
            
        if sw1 == 0x63:
            if (sw2 & 0xF0) == 0xC0:
                retries = sw2 & 0x0F
                return f"Verification failed. {retries} retries remaining."
                
        return "Unknown Status"