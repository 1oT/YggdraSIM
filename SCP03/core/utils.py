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