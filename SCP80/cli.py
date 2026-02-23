# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os 
import sys 
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
        print (f" Created and maintained by Hampus Hellsberg")
        print (f"{Colors.ENDC}")

        self ._setup_history ()

        is_reader =False 
        if self .config .get ("transport")=="reader":
            is_reader =True 

        if is_reader :
            self .transport .connect ()

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
                print ("\nUse 'quit' to exit.")
                continue 

            except Exception as e :
                print (f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    def _process_line (self ,line :str )->bool :
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
        hidden =["header","cla","sender"]
        for k ,v in self .config .data .items ():
            if k in hidden :continue 
            val =CryptoEngine .describe_keyset (v )if k in ["kic","kid"]else v 
            print (f"{k:<12}: {val}")
        print (f"{Colors.CYAN}---------------------{Colors.ENDC}")

    def do_set (self ,*args ):
        if len (args )>=2 :self .config .set (args [0 ].lower (),args [1 ])

    def do_build (self ,*args ):
        try :print (f"APDU: {self.builder.build(True)}")
        except Exception as e :print (f"Error: {e}")

    def do_send (self ,*args ):
        verbose ="-v"in args 
        try :
            result =self .transport .send_ota (self .builder .build (verbose =verbose ),verbose =verbose )
            self ._print_result (result )
        except Exception as e :print (f"{Colors.FAIL}Send Error: {e}{Colors.ENDC}")

    def do_sendraw (self ,*args ):
        if args :self .transport .transmit ("".join (args ))

    def do_reset (self ,*args ):
        self .transport .reset_connection ()

    def do_script (self ,*args ):
        if not args :print ("Usage: script <file>");return 
        if not os .path .exists (args [0 ]):print ("File not found");return 
        print (f"{Colors.CYAN}[*] Executing script: {args[0]}{Colors.ENDC}")
        with open (args [0 ],'r')as f :
            for line in f :
                if not line .strip ()or line .startswith ("#"):continue 
                print (f"{Colors.BOLD}> {line.strip()}{Colors.ENDC}")
                if not self ._process_line (line .strip ()):break 

    def do_ota (self ,*args ):
        raw_apdu ="".join (args ).replace (" ","")
        fid ,le =self .decoder .sniff_context (raw_apdu )

        try :
            apdu_to_send =self .builder .build (verbose =False ,override_payload =raw_apdu )
            result =self .transport .send_ota (apdu_to_send ,verbose =False )
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
        if por :
            print (f"{Colors.BLUE}[<--]{Colors.ENDC} {por} {sw}")
        else :
            print (f"{Colors.BLUE}[<--]{Colors.ENDC} {sw}")

    def do_help (self ,*args ):
        print ("Commands:")
        print ("  <hex string>    - Direct OTA wrap and send")
        print ("  ota <hex>       - Explicit OTA wrap and send")
        print ("  script <file>   - Execute commands from file")
        print ("  history         - Show command history")
        print ("  set <k> <v>     - Update parameter")
        print ("  send [-v]       - Send configured payload")
        print ("  build           - View current OTA APDU")
        print ("  show            - View parameters")
        print ("  sendraw <hex>   - Send raw APDU (no OTA)")
        print ("  reset           - Re-initialize STK")
        print ("  quit            - Exit")

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
        print (f" Created and maintained by Hampus Hellsberg")
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
        from cli import OtaShell 

        try :


            shell =OtaShell ()
            shell .run ()
        except Exception as e :

            print (f"[-] SCP80 Execution Error: {e}")