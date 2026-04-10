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
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

import os 
import re
import sys 

from yggdrasim_common.process_debug import is_global_debug_enabled
from yggdrasim_common.quit_control import quit_all

if __package__ :
    from .config import ConfigManager 
    from .builder import OtaPacketBuilder 
    from .transport import Transport 
    from .crypto import CryptoEngine 
    from .utils import Colors 
else :
    from config import ConfigManager 
    from builder import OtaPacketBuilder 
    from transport import Transport 
    from crypto import CryptoEngine 
    from utils import Colors 

try :
    current_dir =os .path .dirname (os .path .abspath (__file__ ))
    scp03_path =os .path .abspath (os .path .join (current_dir ,'../SCP03'))
    if scp03_path not in sys .path :sys .path .insert (0 ,scp03_path )
    from core .decoders import ContentDecoder 
    from logic .fs import FileSystemController 
    SCP03_AVAIL =True 
except ImportError :
    SCP03_AVAIL =False 

try :
    import readline 
except ImportError :
    readline =None 

APP_NAME ="YggdraSIM OTA Simulator"
VERSION ="2.6.0"

class SmartDecoder :
    def __init__ (self ):
        if SCP03_AVAIL :
            ContentDecoder .init_registry ()
            self .fid_lookup ={}
            for name ,fids in FileSystemController .DEFAULT_MAP .items ():
                if isinstance (fids ,list ):
                    for f in fids :self .fid_lookup [f ]=name 
                else :
                    self .fid_lookup [fids ]=name 

    def sniff_context (self ,full_apdu :str ):
        idx =0 ;current_fid =None ;last_le =0 
        s =full_apdu .upper ().replace (" ","")
        try :
            while idx <len (s ):
                if idx +8 >len (s ):break 
                ins =int (s [idx +2 :idx +4 ],16 )
                idx +=8 
                lc =0 ;le =0 
                if idx +2 <=len (s ):
                    next_byte =int (s [idx :idx +2 ],16 )
                    if ins ==0xA4 :
                        lc =next_byte ;idx +=2 
                        if idx +(lc *2 )<=len (s ):current_fid =s [idx :idx +(lc *2 )];idx +=(lc *2 )
                        else :break 
                    elif ins in [0xD6 ,0xDC ]:lc =next_byte ;idx +=2 +(lc *2 )
                    elif ins in [0xB0 ,0xB2 ]:le =next_byte ;idx +=2 ;last_le =le 
                    else :
                        if idx +2 ==len (s ):le =next_byte ;idx +=2 ;last_le =le 
                        else :lc =next_byte ;idx +=2 +(lc *2 )
                else :break 
        except :pass 
        return current_fid ,last_le 

    def try_decode (self ,fid ,le ,por_hex ):
        if not SCP03_AVAIL or not por_hex :return 
        payload =""


        if le >0 and len (por_hex )>=(le *2 ):




            payload =por_hex [-(le *2 ):]

        if fid and payload :
            fid_name =self .fid_lookup .get (fid ,fid )
            decoded =ContentDecoder .decode (fid ,payload )
            if decoded :
                print (f"{Colors.CYAN}--- Decoded ({fid_name}) ---{Colors.ENDC}")
                for line in decoded .strip ().split ('\n'):
                    print (f"    {Colors.GREEN}{line}{Colors.ENDC}")

class OtaShell :
    def __init__ (self ):
        self .config =ConfigManager ()
        self .builder =OtaPacketBuilder (self .config )
        self .transport =Transport (self .config )
        self .history_file =os .path .expanduser ("~/.scp80_history")
        self .decoder =SmartDecoder ()
        self .last_command_ok =True 
        self .current_iccid =""
        self .global_debug =is_global_debug_enabled ()

    def _bind_inventory_profile (self ,iccid :str ,announce :bool =True )->bool :
        normalized_iccid =''.join (ch for ch in str (iccid or "")if ch .isdigit ())
        if len (normalized_iccid )==0 :
            return False 
        payload =self .config .bind_iccid_profile (normalized_iccid )
        self .current_iccid =normalized_iccid 
        if announce :
            if isinstance (payload ,dict )and len (payload )>0 :
                print (
                f"{Colors.GREEN}[+] Loaded SCP80 inventory profile for ICCID "
                f"{normalized_iccid}.{Colors.ENDC}"
                )
            else :
                print (
                f"{Colors.CYAN}[*] Seeded SCP80 inventory profile for ICCID "
                f"{normalized_iccid} using current defaults.{Colors.ENDC}"
                )
        return True 

    def _refresh_inventory_from_reader (self ,announce :bool =True )->bool :
        iccid =""
        try :
            iccid =self .transport .read_iccid ()
        except Exception as e :
            if announce :
                print (f"{Colors.FAIL}[!] Could not read ICCID: {e}{Colors.ENDC}")
            return False 
        if len (iccid )==0 :
            if announce :
                print (f"{Colors.WARNING}[*] ICCID not available from current reader session.{Colors.ENDC}")
            return False 
        return self ._bind_inventory_profile (iccid ,announce =announce )

    @staticmethod
    def _normalize_script_hex_line (line :str )->str :
        line_body =line .split ('#',1 )[0 ]
        match =re .match (r"^\s*([0-9A-Fa-f][0-9A-Fa-f\s]*)",line_body )
        if match is None :
            return ""
        return ''.join (match .group (1 ).split ())

    def _setup_history (self ):
        if not readline :return 
        try :
            if os .path .exists (self .history_file ):readline .read_history_file (self .history_file )
            readline .set_history_length (1000 )
        except :pass 

    def run (self ):
        is_nt =False 
        if os .name =='nt':
            is_nt =True 

        if is_nt :
            os .system ('cls')

        is_posix =False 
        if os .name !='nt':
            is_posix =True 

        if is_posix :
            os .system ('clear')

        print (f"{Colors.HEADER}")
        print (r" __   __               _               ____ ___ __  __ ")
        print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print (r"      |___/  |___/                                     ")
        print (r"                    ___ _____  _    ")
        print (r"                   / _ \_   _|/ \   ")
        print (r"                  | | | || | / _ \  ")
        print (r"                  | |_| || |/ ___ \ ")
        print (r"                   \___/ |_/_/   \_"+"\\")
        print (f"")
        print (f"=== Remote File Management & Over-The-Air Payload Generator ===")
        print (f" Created and maintained by Hampus Hellsberg and contributors")
        print (f"{Colors.ENDC}")

        self ._setup_history ()

        is_reader =False 
        if self .config .get ("transport")=="reader":
            is_reader =True 

        if is_reader :
            self .transport .connect ()
            self ._refresh_inventory_from_reader (announce =True )

        while True :
            try :
                mode ="PRINT"
                if is_reader :
                    mode ="OTA"

                line =input (f"\n{Colors.CYAN}[{mode}]{Colors.ENDC} > ").strip ()

                is_empty =False 
                if not line :
                    is_empty =True 

                if is_empty :
                    continue 

                has_readline =False 
                if 'readline'in globals ()or 'readline'in locals ():
                    has_readline =True 

                if has_readline :
                    try :
                        import readline 
                        readline .write_history_file (self .history_file )
                    except Exception :
                        pass 

                processed =self ._process_line (line )

                is_processed =False 
                if processed :
                    is_processed =True 

                is_failed =False 
                if is_processed ==False :
                    is_failed =True 

                if is_failed :
                    break 

            except EOFError :
                print ("\nExiting...")
                self ._process_line ("quit")
                break 

            except KeyboardInterrupt :
                print ("\nUse 'quit' to leave the SCP80 shell or 'qa' to exit YggdraSIM.")
                continue 

            except Exception as e :
                print (f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    def run_commands (self ,cmd_line :str )->None :
        for raw_command in str (cmd_line or "").split (';'):
            command_text =str (raw_command or "").strip ()
            if len (command_text )==0 :
                continue
            keep_running =self ._process_line (command_text )
            if keep_running ==False :
                break

    def _process_line (self ,line :str )->bool :
        self .last_command_ok =True 
        cmd_parts =line .split ()
        if not cmd_parts :
            return True 
        cmd =cmd_parts [0 ].lower ()
        args =cmd_parts [1 :]

        is_admin =False 
        if cmd =="admin":
            is_admin =True 

        if is_admin :
            self ._run_scp03_tool ()
            return True 
        if cmd =="qa":
            self .config .save ()
            self .transport .disconnect ()
            quit_all ()
        if cmd in ["quit","exit","q"]:
            self .config .save ();self .transport .disconnect ();return False 
        if hasattr (self ,f"do_{cmd}"):getattr (self ,f"do_{cmd}")(*args )
        elif all (c in "0123456789ABCDEFabcdef "for c in line ):self .do_ota (line )
        else :print (f"{Colors.FAIL}Unknown command or invalid hex.{Colors.ENDC}")
        return True 

    def do_history (self ,*args ):
        if not readline :return 
        for i in range (1 ,readline .get_current_history_length ()+1 ):
            print (f"{i:4}: {readline.get_history_item(i)}")

    def do_show (self ,*args ):
        print (f"{Colors.CYAN}--- Configuration ---{Colors.ENDC}")
        if len (self .current_iccid )>0 :
            print (f"{'iccid':<12}: {self.current_iccid}")
        hidden =["header","cla","sender"]
        for k ,v in self .config .data .items ():
            if k in hidden :continue 
            val =CryptoEngine .describe_keyset (v )if k in ["kic","kid"]else v 
            print (f"{k:<12}: {val}")
        self ._print_reader_protocol_caveat ()
        print (f"{Colors.CYAN}---------------------{Colors.ENDC}")

    def do_set (self ,*args ):
        if len (args )<2 :
            print ("Usage: set <k> <v>")
            return 
        try :
            self .config .set (args [0 ].lower (),args [1 ])
            self .config .save ()
            print (f"{Colors.GREEN}[+] {args[0].lower()} updated.{Colors.ENDC}")
        except ValueError as e :
            print (f"{Colors.FAIL}[!] {e}{Colors.ENDC}")

    def do_iccid (self ,*args ):
        if len (args )==0 :
            if self .config .get ("transport")=="reader":
                self ._refresh_inventory_from_reader (announce =True )
                return 
            if len (self .current_iccid )>0 :
                print (f"{Colors.CYAN}[*] Active ICCID: {self.current_iccid}{Colors.ENDC}")
                return 
            print ("Usage: iccid <decimal-iccid>")
            return 
        iccid =''.join (ch for ch in str (args [0 ])if ch .isdigit ())
        if len (iccid )==0 :
            print (f"{Colors.FAIL}[!] ICCID must contain digits only.{Colors.ENDC}")
            return 
        self ._bind_inventory_profile (iccid ,announce =True )

    @staticmethod
    def _override_payload_from_args (args )->str :
        payload_parts =[]
        for arg in args :
            if arg =="-v":
                continue 
            payload_parts .append (arg )
        return ''.join (payload_parts )

    def _print_build_plan (self ,plan ):
        if len (plan .apdus )==1 :
            print (f"APDU: {plan.apdus[0].apdu_hex}")
            return 
        print (f"APDUs ({len(plan.apdus)} concatenated SMS segments):")
        for apdu in plan .apdus :
            print (f"  [{apdu.index +1}/{apdu.total}] {apdu.apdu_hex}")
        if self .config .get ("transport")=="reader"and len (plan .reader_apdus )>0 :
            print ("  [reader] Direct reader mode sends one reassembled ENVELOPE APDU.")
            print (f"  [reader] {plan.reader_apdus[0]}")
            self ._print_reader_protocol_caveat (multipart_required =True )

    def _print_reader_protocol_caveat (self ,multipart_required :bool =False ):
        if self .config .get ("transport")!="reader":
            return 
        info =self .transport .get_protocol_summary ()
        if info .get ("available")==False :
            return 
        if multipart_required and info .get ("supports_t1"):
            return 
        atr_hex =info .get ("atr_hex")or "Unknown"
        active_protocol =info .get ("active_protocol")or "UNKNOWN"
        if info .get ("supports_t1"):
            print (f"{Colors.CYAN}[reader]{Colors.ENDC} ATR advertises T=1. Active protocol: {active_protocol}.")
            return 
        print (f"{Colors.WARNING}[caveat]{Colors.ENDC} Current ATR does not advertise T=1. Active protocol: {active_protocol}.")
        print (f"{Colors.WARNING}[caveat]{Colors.ENDC} ATR: {atr_hex}")
        if multipart_required :
            print (f"{Colors.WARNING}[caveat]{Colors.ENDC} Multipart SCP80 in reader mode will require an extended ENVELOPE and is expected to fail on this path.")

    def _plan_apdu_list_for_transport (self ,plan ):
        is_reader =self .config .get ("transport")=="reader"
        if is_reader and plan .is_concatenated and len (plan .reader_apdus )>0 :
            return plan .reader_apdus 
        return [apdu .apdu_hex for apdu in plan .apdus ]

    def do_build (self ,*args ):
        verbose =bool (getattr (self ,"global_debug",False ))or "-v"in args 
        override_payload =self ._override_payload_from_args (args )
        try :
            payload_override =None 
            if len (override_payload )>0 :
                payload_override =override_payload 
            plan =self .builder .build_plan (verbose =verbose ,override_payload =payload_override )
            self ._print_build_plan (plan )
        except Exception as e :
            print (f"Error: {e}")

    def do_send (self ,*args ):
        verbose =bool (getattr (self ,"global_debug",False ))or "-v"in args 
        try :
            override_payload =self ._override_payload_from_args (args )
            payload_override =None 
            if len (override_payload )>0 :
                payload_override =override_payload 
            plan =self .builder .build_plan (verbose =verbose ,override_payload =payload_override )
            if plan .is_concatenated :
                self ._print_reader_protocol_caveat (multipart_required =True )
            result =self .transport .send_ota_sequence (self ._plan_apdu_list_for_transport (plan ),verbose =verbose )
            self .last_command_ok =bool (result .get ("delivered"))
            self ._print_result (result )
        except Exception as e :
            self .last_command_ok =False 
            print (f"{Colors.FAIL}Send Error: {e}{Colors.ENDC}")

    def do_sendraw (self ,*args ):
        if args :self .transport .transmit ("".join (args ))

    def do_reset (self ,*args ):
        self .transport .reset_connection ()
        if self .config .get ("transport")=="reader":
            self ._refresh_inventory_from_reader (announce =True )

    def do_script (self ,*args ):
        if not args :print ("Usage: script <file>");return 
        if not os .path .exists (args [0 ]):print ("File not found");return 
        print (f"{Colors.CYAN}[*] Executing script: {args[0]}{Colors.ENDC}")
        with open (args [0 ],'r')as f :
            for line in f :
                normalized_line =self ._normalize_script_hex_line (line )
                if len (normalized_line )==0 :
                    continue 
                print (f"{Colors.BOLD}> {normalized_line}{Colors.ENDC}")
                if not self ._process_line (normalized_line ):break 
                if self .last_command_ok ==False :
                    print (f"{Colors.FAIL}[!] Script aborted: OTA delivery failed and the counter was not advanced.{Colors.ENDC}")
                    break 

    def do_ota (self ,*args ):
        raw_apdu =''.join ("".join (args ).split ())
        fid ,le =self .decoder .sniff_context (raw_apdu )

        try :
            verbose =bool (getattr (self ,"global_debug",False ))
            plan =self .builder .build_plan (verbose =verbose ,override_payload =raw_apdu )
            if plan .is_concatenated :
                self ._print_reader_protocol_caveat (multipart_required =True )
            result =self .transport .send_ota_sequence (self ._plan_apdu_list_for_transport (plan ),verbose =verbose )
            self .last_command_ok =bool (result .get ("delivered"))
            self ._print_result (result )


            por =result .get ("por")
            if por :
                self .decoder .try_decode (fid ,le ,por )



                if len (por )>=4 :
                    sw_in_por =por [-4 :]
                    if sw_in_por .startswith ("6C"):
                        correct_le =sw_in_por [2 :]
                        self ._handle_wrong_length (raw_apdu ,correct_le )

        except Exception as e :
            self .last_command_ok =False 
            print (f"{Colors.FAIL}OTA Error: {e}{Colors.ENDC}")


    def _handle_wrong_length (self ,original_apdu ,correct_le ):
        print (f"{Colors.WARNING}[?] Target indicates wrong length. Correct Le: 0x{correct_le}{Colors.ENDC}")
        q =input (f"{Colors.WARNING}[?] Resend with Le={correct_le}? [Y/n] > {Colors.ENDC}").strip ().lower ()
        if q in ['','y','yes']:
            new_apdu =self ._reconstruct_apdu (original_apdu ,correct_le )
            print (f"{Colors.CYAN}[*] Retrying with: {new_apdu}{Colors.ENDC}")
            self .do_ota (new_apdu )


    def _reconstruct_apdu (self ,apdu_hex ,new_le ):

        idx =0 
        last_cmd_start =0 
        s =apdu_hex .upper ()


        while idx <len (s ):
            last_cmd_start =idx 
            if idx +8 >len (s ):break 
            ins =int (s [idx +2 :idx +4 ],16 )
            idx +=8 

            if idx >=len (s ):break 


            byte_val =int (s [idx :idx +2 ],16 )


            has_lc =False 

            if ins in [0xA4 ,0xD6 ,0xDC ,0x20 ,0x24 ,0x26 ,0x28 ,0x2C ]:
                has_lc =True 

            if has_lc :
                lc =byte_val 
                idx +=2 +(lc *2 )


                if idx <len (s ):


                     if idx +2 ==len (s ):
                         idx +=2 
            else :

                idx +=2 


        last_cmd =s [last_cmd_start :]





        if len (last_cmd )==10 :
            return s [:-2 ]+new_le 
        elif len (last_cmd )==8 :
            return s +new_le 
        else :



            if (len (last_cmd )//2 )%2 !=0 :
                 return s [:-2 ]+new_le 
            else :
                 return s +new_le 

    def _print_result (self ,result ):
        sw =result .get ("sw")
        por =result .get ("por")
        error =result .get ("error")
        segment_count =result .get ("segment_count")
        failed_segment =result .get ("failed_segment")
        if segment_count is not None :
            if segment_count >1 :
                print (f"{Colors.CYAN}[SMS]{Colors.ENDC} Concatenated sequence with {segment_count} segments.")
        if por :
            print (f"{Colors.BLUE}[<--]{Colors.ENDC} {por} {sw}")
        else :
            print (f"{Colors.BLUE}[<--]{Colors.ENDC} {sw}")
        if failed_segment is not None :
            print (f"{Colors.FAIL}[!] Failed at segment {failed_segment}.{Colors.ENDC}")
        if error :
            print (f"{Colors.FAIL}[!] {error}{Colors.ENDC}")

    def do_help (self ,*args ):
        print ("Commands:")
        print ("  <hex string>    - Direct OTA wrap and send")
        print ("  ota <hex>       - Explicit OTA wrap and send")
        print ("  iccid [value]   - Read or bind ICCID-specific inventory profile")
        print ("  script <file>   - Execute commands from file")
        print ("  history         - Show command history")
        print ("  set <k> <v>     - Update parameter")
        print ("  send [-v] [hex] - Send configured or inline payload")
        print ("  build [-v] [hex]- View OTA APDU or multipart sequence")
        print ("  show            - View parameters")
        print ("  sendraw <hex>   - Send raw APDU (no OTA)")
        print ("  reset           - Re-initialize STK")
        print ("  quit            - Exit SCP80 shell")
        print ("  qa              - Exit YggdraSIM")
        print ("")
        print ("Config keys:")
        print ("  concat_sms      - ON or OFF automatic concatenation")
        print ("  tp_ud_max       - Per-segment TP-UD ceiling (8-140)")

    def _run_scp03_tool (self ):
        print (f"{Colors.HEADER}=== Switching to SCP03 Admin Shell ==={Colors.ENDC}")
        print (f"{Colors.WARNING}[*] Releasing Card Reader...{Colors.ENDC}")

        has_transport =False 
        if self .transport :
            has_transport =True 

        if has_transport :
            try :
                self .transport .disconnect ()
            except Exception :
                pass 

        try :
            print (f"{Colors.CYAN}[*] Starting SCP03 Module...{Colors.ENDC}")
            import sys 
            import importlib 
            import os 

            current_dir =os .path .dirname (os .path .abspath (__file__ ))
            root_path =os .path .abspath (os .path .join (current_dir ,'..'))

            is_missing_path =False 
            if root_path not in sys .path :
                is_missing_path =True 

            if is_missing_path :
                sys .path .insert (0 ,root_path )

            import SCP03 .main as scp03_entry 
            importlib .reload (scp03_entry )

            scp03_entry .entry ()

        except SystemExit :

            is_nt =False 
            if os .name =='nt':
                is_nt =True 

            if is_nt :
                os .system ('cls')

            if is_nt ==False :
                os .system ('clear')

        except ImportError as e :
            print (f"{Colors.FAIL}[!] Import Error: {e}{Colors.ENDC}")
        except Exception as e :
            print (f"{Colors.FAIL}[!] SCP03 Tool Crashed: {e}{Colors.ENDC}")


        print (f"{Colors.HEADER}")
        print (r" __   __               _               ____ ___ __  __ ")
        print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print (r"      |___/  |___/                                     ")
        print (r"                   ___ _____ / \  ")
        print (r"                  / _ \_   _/ _ \ ")
        print (r"                 | | | || |/ ___ \ ")
        print (r"                 | |_| || / ___  \ ")
        print (r"                  \___/ |_/_/   \_"+"\\")
        print (f"")
        print (f"=== Remote File Management & Over-The-Air Payload Generator ===")
        print (f" Created and maintained by Hampus Hellsberg and contributors")
        print (f"{Colors.ENDC}")

        print (f"\n{Colors.HEADER}=== Returning to SCP80 OTA Tool ==={Colors.ENDC}")
        print (f"{Colors.WARNING}[*] Re-acquiring Card Reader...{Colors.ENDC}")

        try :
            is_reader_mode =False 
            if self .config .get ("transport")=="reader":
                is_reader_mode =True 

            if is_reader_mode :
                self .transport .connect ()
                print (f"{Colors.GREEN}[+] Card Reader Re-connected.{Colors.ENDC}")

        except Exception as e :
            print (f"{Colors.FAIL}[!] Failed to reconnect reader: {e}{Colors.ENDC}")

        self ._setup_history ()

    def run_standalone ():
        """Entry point for switching from other modules."""
        if __package__ :
            from .cli import OtaShell 
        else :
            from cli import OtaShell 

        try :


            shell =OtaShell ()
            shell .run ()
        except Exception as e :

            print (f"[-] SCP80 Execution Error: {e}")