import os
import sys
from config import ConfigManager
from builder import OtaPacketBuilder
from transport import Transport
from crypto import CryptoEngine
from utils import Colors

try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    scp03_path = os.path.abspath(os.path.join(current_dir, '../SCP03'))
    if scp03_path not in sys.path: sys.path.insert(0, scp03_path)
    from core.decoders import ContentDecoder
    from logic.fs import FileSystemController
    SCP03_AVAIL = True
except ImportError:
    SCP03_AVAIL = False

try:
    import readline
except ImportError:
    readline = None

APP_NAME = "YggdraSIM OTA Simulator"
VERSION = "2.6.0"

class SmartDecoder:
    def __init__(self):
        if SCP03_AVAIL:
            ContentDecoder.init_registry()
            self.fid_lookup = {}
            for name, fids in FileSystemController.DEFAULT_MAP.items():
                if isinstance(fids, list):
                    for f in fids: self.fid_lookup[f] = name
                else:
                    self.fid_lookup[fids] = name

    def sniff_context(self, full_apdu: str):
        idx = 0; current_fid = None; last_le = 0
        s = full_apdu.upper().replace(" ", "")
        try:
            while idx < len(s):
                if idx + 8 > len(s): break
                ins = int(s[idx+2:idx+4], 16)
                idx += 8
                lc = 0; le = 0
                if idx + 2 <= len(s):
                    next_byte = int(s[idx:idx+2], 16)
                    if ins == 0xA4:
                        lc = next_byte; idx += 2
                        if idx + (lc*2) <= len(s): current_fid = s[idx : idx+(lc*2)]; idx += (lc * 2)
                        else: break
                    elif ins in [0xD6, 0xDC]: lc = next_byte; idx += 2 + (lc * 2)
                    elif ins in [0xB0, 0xB2]: le = next_byte; idx += 2; last_le = le
                    else:
                        if idx + 2 == len(s): le = next_byte; idx += 2; last_le = le
                        else: lc = next_byte; idx += 2 + (lc * 2)
                else: break
        except: pass
        return current_fid, last_le

    def try_decode(self, fid, le, por_hex):
        if not SCP03_AVAIL or not por_hex: return
        payload = ""
        # Heuristic: If SW is 9000/91xx, data is before it. 
        # But PoR structure varies. Simplest is last Le bytes if Le is known.
        if le > 0 and len(por_hex) >= (le * 2):
            # Grab last Le bytes (ignoring potential SW padding at very end if strict)
            # Actually, PoR ends with SW. If PoR is D0...DataSW.
            # Let's try to grab the last (Le*2) characters *before* the SW if possible, 
            # or just the end if we assume the tool strips outer SW.
            payload = por_hex[-(le*2):]
        
        if fid and payload:
            fid_name = self.fid_lookup.get(fid, fid)
            decoded = ContentDecoder.decode(fid, payload)
            if decoded:
                print(f"{Colors.CYAN}--- Decoded ({fid_name}) ---{Colors.ENDC}")
                for line in decoded.strip().split('\n'):
                    print(f"    {Colors.GREEN}{line}{Colors.ENDC}")

class OtaShell:
    def __init__(self):
        self.config = ConfigManager()
        self.builder = OtaPacketBuilder(self.config)
        self.transport = Transport(self.config)
        self.history_file = os.path.expanduser("~/.scp80_history")
        self.decoder = SmartDecoder()

    def _setup_history(self):
        if not readline: return
        try:
            if os.path.exists(self.history_file): readline.read_history_file(self.history_file)
            readline.set_history_length(1000)
        except: pass

    def run(self):
        print(f"{Colors.GREEN}[+] {APP_NAME} v{VERSION}{Colors.ENDC}")
        self._setup_history()
        if self.config.get("transport") == "reader": self.transport.connect()
        print("Type 'help' for commands. Use Arrow Keys to scroll history.")
        while True:
            try:
                mode = "OTA" if self.config.get("transport") == "reader" else "PRINT"
                line = input(f"\n{Colors.CYAN}[{mode}]{Colors.ENDC} > ").strip()
                if not line: continue
                if readline: 
                    try: readline.write_history_file(self.history_file)
                    except: pass
                if not self._process_line(line): break
            except EOFError: 
                print("\nExiting..."); self._process_line("quit"); break
            except KeyboardInterrupt: 
                print("\nUse 'quit' to exit."); continue
            except Exception as e: print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    def _process_line(self, line: str) -> bool:
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ["quit", "exit", "q"]:
            self.config.save(); self.transport.disconnect(); return False
        if hasattr(self, f"do_{cmd}"): getattr(self, f"do_{cmd}")(*args)
        elif all(c in "0123456789ABCDEFabcdef " for c in line): self.do_ota(line)
        else: print(f"{Colors.FAIL}Unknown command or invalid hex.{Colors.ENDC}")
        return True

    def do_history(self, *args):
        if not readline: return
        for i in range(1, readline.get_current_history_length() + 1):
            print(f"{i:4}: {readline.get_history_item(i)}")

    def do_show(self, *args):
        print(f"{Colors.CYAN}--- Configuration ---{Colors.ENDC}")
        hidden = ["header", "cla", "sender"]
        for k, v in self.config.data.items():
            if k in hidden: continue
            val = CryptoEngine.describe_keyset(v) if k in ["kic", "kid"] else v
            print(f"{k:<12}: {val}")
        print(f"{Colors.CYAN}---------------------{Colors.ENDC}")

    def do_set(self, *args):
        if len(args) >= 2: self.config.set(args[0].lower(), args[1])

    def do_build(self, *args):
        try: print(f"APDU: {self.builder.build(True)}")
        except Exception as e: print(f"Error: {e}")

    def do_send(self, *args):
        verbose = "-v" in args
        try: 
            result = self.transport.send_ota(self.builder.build(verbose=verbose), verbose=verbose)
            self._print_result(result)
        except Exception as e: print(f"{Colors.FAIL}Send Error: {e}{Colors.ENDC}")

    def do_sendraw(self, *args):
        if args: self.transport.transmit("".join(args))

    def do_reset(self, *args):
        self.transport.reset_connection()

    def do_script(self, *args):
        if not args: print("Usage: script <file>"); return
        if not os.path.exists(args[0]): print("File not found"); return
        print(f"{Colors.CYAN}[*] Executing script: {args[0]}{Colors.ENDC}")
        with open(args[0], 'r') as f:
            for line in f:
                if not line.strip() or line.startswith("#"): continue
                print(f"{Colors.BOLD}> {line.strip()}{Colors.ENDC}")
                if not self._process_line(line.strip()): break

    def do_ota(self, *args):
        raw_apdu = "".join(args).replace(" ", "")
        fid, le = self.decoder.sniff_context(raw_apdu)
        
        try:
            apdu_to_send = self.builder.build(verbose=False, override_payload=raw_apdu)
            result = self.transport.send_ota(apdu_to_send, verbose=False)
            self._print_result(result)
            
            # Decode Logic
            por = result.get("por")
            if por:
                self.decoder.try_decode(fid, le, por)
                
                # [NEW] Check for 6C XX (Wrong Length)
                # The SW is typically the last 2 bytes of the PoR payload
                if len(por) >= 4:
                    sw_in_por = por[-4:] # Last 2 bytes (4 chars)
                    if sw_in_por.startswith("6C"):
                        correct_le = sw_in_por[2:]
                        self._handle_wrong_length(raw_apdu, correct_le)

        except Exception as e:
            print(f"{Colors.FAIL}OTA Error: {e}{Colors.ENDC}")

    # [NEW] Handle 6C XX Re-send Logic
    def _handle_wrong_length(self, original_apdu, correct_le):
        print(f"{Colors.WARNING}[?] Target indicates wrong length. Correct Le: 0x{correct_le}{Colors.ENDC}")
        q = input(f"{Colors.WARNING}[?] Resend with Le={correct_le}? [Y/n] > {Colors.ENDC}").strip().lower()
        if q in ['', 'y', 'yes']:
            new_apdu = self._reconstruct_apdu(original_apdu, correct_le)
            print(f"{Colors.CYAN}[*] Retrying with: {new_apdu}{Colors.ENDC}")
            self.do_ota(new_apdu)

    # [NEW] Helper to intelligently replace/append Le
    def _reconstruct_apdu(self, apdu_hex, new_le):
        # We need to find the last command in the chain to decide if we replace or append
        idx = 0
        last_cmd_start = 0
        s = apdu_hex.upper()
        
        # Iterate to find the start of the last command
        while idx < len(s):
            last_cmd_start = idx
            if idx + 8 > len(s): break # Should not happen on valid APDU
            ins = int(s[idx+2:idx+4], 16)
            idx += 8 # Skip Header
            
            if idx >= len(s): break # End of string (Case 1: 4 bytes)
            
            # Check Lc/Le byte
            byte_val = int(s[idx:idx+2], 16)
            
            # Check for Lc (Command with data)
            has_lc = False
            # Standard ISO case 3/4 logic or specific INS check
            if ins in [0xA4, 0xD6, 0xDC, 0x20, 0x24, 0x26, 0x28, 0x2C]: # Select, Update, Pin
                has_lc = True
            
            if has_lc:
                lc = byte_val
                idx += 2 + (lc * 2) # Skip Lc byte + Data
                # If we are at end, we are done. If more, it might be Le? 
                # (Case 4: Data + Le). But simpler to assume Case 3.
                if idx < len(s):
                     # If we have bytes left, check if it's start of next cmd or Le
                     # Heuristic: If we are exactly 2 chars from end, it's Le
                     if idx + 2 == len(s): 
                         idx += 2 # Consume Le
            else:
                # Case 2: No data, just Le (Read Binary, Read Record, Get Data, Get Response)
                idx += 2 # Consume Le
        
        # Now analyze the last command segment
        last_cmd = s[last_cmd_start:]
        
        # If last command is 5 bytes (10 chars), it has Le -> Replace
        # If last command is 4 bytes (8 chars), it has no Le -> Append
        # If last command > 5 bytes (Case 4 with data+Le?), check length.
        
        if len(last_cmd) == 10: # Standard 5-byte command (Header + Le)
            return s[:-2] + new_le
        elif len(last_cmd) == 8: # Standard 4-byte command (Header)
            return s + new_le
        else:
            # Fallback: If length is odd (ends with byte), replace. If even (ends with data), append?
            # User example: 00 B2 01 04 FF (5 bytes) -> Replace
            # User example: 00 B2 01 04 (4 bytes) -> Append
            if (len(last_cmd) // 2) % 2 != 0: # Odd number of bytes (5, 7...)
                 return s[:-2] + new_le
            else:
                 return s + new_le

    def _print_result(self, result):
        sw = result.get("sw")
        por = result.get("por")
        if por:
            print(f"{Colors.BLUE}[<--]{Colors.ENDC} {por} {sw}")
        else:
            print(f"{Colors.BLUE}[<--]{Colors.ENDC} {sw}")

    def do_help(self, *args):
        print("Commands:")
        print("  <hex string>    - Direct OTA wrap and send")
        print("  ota <hex>       - Explicit OTA wrap and send")
        print("  script <file>   - Execute commands from file")
        print("  history         - Show command history")
        print("  set <k> <v>     - Update parameter")
        print("  send [-v]       - Send configured payload")
        print("  build           - View current OTA APDU")
        print("  show            - View parameters")
        print("  sendraw <hex>   - Send raw APDU (no OTA)")
        print("  reset           - Re-initialize STK")
        print("  quit            - Exit")