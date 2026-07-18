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

"""GP card management wizards: PUT KEY, DGI personalisation, and applet install flows."""
import os 
from typing import Tuple 
from SCP03 .config import Config 
from SCP03 .core .cap import CapFileParser 
from SCP03 .core .utils import HexUtils 
from SCP03 .interface .wizards_ui import InteractiveWizard 

try :
    from SCP80 .builder import OtaPacketBuilder 
    SCP80_PREVIEW_AVAIL =True 
except ImportError :
    SCP80_PREVIEW_AVAIL =False 

class InteractiveWizards :
    """Provides interactive prompts and dry-run APDU builders for complex GP commands."""

    @staticmethod 
    def _encode_ber_length_bytes (length :int )->bytes :
        len_hex =InteractiveWizards ._encode_ber_tlv_length (length )
        return bytes .fromhex (len_hex )

    @staticmethod 
    def _build_tlv (tag_hex :str ,value :bytes )->bytes :
        tag_bytes =bytes .fromhex (tag_hex )
        return tag_bytes +InteractiveWizards ._encode_ber_length_bytes (len (value ))+value 

    @staticmethod
    def _is_skip_value (value)->bool :
        if value is None :
            return True
        text =str (value ).strip ()
        if len (text )==0 :
            return False
        return text .upper ()=="SKIP"

    @staticmethod
    def _clean_hex_input (value ,label :str ="hex",allow_empty :bool =True )->str :
        if value is None :
            if allow_empty :
                return ""
            raise ValueError (f"{label} is required.")

        cleaned =str (value ).strip ().replace (" ","").replace (":","")
        if cleaned .lower ().startswith ("0x"):
            cleaned =cleaned [2 :]

        if len (cleaned )==0 :
            if allow_empty :
                return ""
            raise ValueError (f"{label} is required.")

        if len (cleaned )%2 !=0 :
            raise ValueError (f"{label} must contain an even number of hex digits.")

        try :
            bytes .fromhex (cleaned )
        except ValueError :
            raise ValueError (f"{label} contains non-hexadecimal characters.")

        return cleaned .upper ()

    @staticmethod
    def _hex_bytes (value ,label :str ="hex",allow_empty :bool =True )->bytes :
        cleaned =InteractiveWizards ._clean_hex_input (value ,label ,allow_empty )
        if len (cleaned )==0 :
            return b""
        return bytes .fromhex (cleaned )

    @staticmethod
    def _normalize_hex_byte (value ,default :str ,label :str )->str :
        text =value
        if value is None or len (str (value ).strip ())==0 :
            text =default
        cleaned =InteractiveWizards ._clean_hex_input (text ,label ,allow_empty =False )
        if len (cleaned )!=2 :
            raise ValueError (f"{label} must be exactly one byte.")
        return cleaned

    @staticmethod
    def _is_single_tlv_for_tag (value :bytes ,tag_hex :str )->bool :
        tag_bytes =bytes .fromhex (tag_hex )
        if not value .startswith (tag_bytes ):
            return False

        offset =len (tag_bytes )
        if offset >=len (value ):
            return False

        first_len =value [offset ]
        offset +=1
        if first_len <=0x7F :
            length =first_len
        else :
            length_octets =first_len &0x7F
            if length_octets ==0 :
                return False
            if offset +length_octets >len (value ):
                return False
            length =int .from_bytes (value [offset :offset +length_octets ],"big")
            offset +=length_octets

        return offset +length ==len (value )

    @staticmethod
    def _coerce_c9_install_parameter (value)->bytes :
        if InteractiveWizards ._is_skip_value (value ):
            return b""

        raw =InteractiveWizards ._hex_bytes (value ,"C9 install parameter",allow_empty =True )
        if len (raw )==0 :
            return b""

        if InteractiveWizards ._is_single_tlv_for_tag (raw ,"C9"):
            return raw

        return InteractiveWizards ._build_tlv ("C9",raw )

    @staticmethod 
    def _encode_apdu_lc (data_len :int )->str :
        if data_len <=0xFF :
            return f"{data_len:02X}"
        if data_len <=0xFFFF :
            return f"00{data_len:04X}"
        raise ValueError ("APDU data field exceeds extended length capability.")

    @staticmethod
    def _normalize_numeric_choice (value :str ,default :str ="")->str :
        if value is None :
            return default

        cleaned =str (value ).strip ().lower ()
        if len (cleaned )==0 :
            return default

        if cleaned .startswith ("0x"):
            cleaned =cleaned [2 :]

        if len (cleaned )==0 :
            return default

        try :
            return str (int (cleaned ,16 ))
        except ValueError :
            return cleaned

    @staticmethod
    def _hex_size_validator (
        label :str ,
        *,
        exact_bytes :int |None =None ,
        minimum_bytes :int |None =None ,
        maximum_bytes :int |None =None ,
        multiple_bytes :int |None =None ,
        minimum_value :int |None =None ,
        maximum_value :int |None =None ,
    ):
        def validate (value )->str |None :
            if InteractiveWizards ._is_skip_value (value )or value =="":
                return None
            raw =bytes .fromhex (str (value ))
            byte_len =len (raw )
            if exact_bytes is not None and byte_len !=exact_bytes :
                return f"{label} must be exactly {exact_bytes} byte(s)."
            if minimum_bytes is not None and byte_len <minimum_bytes :
                return f"{label} must be at least {minimum_bytes} byte(s)."
            if maximum_bytes is not None and byte_len >maximum_bytes :
                return f"{label} must be at most {maximum_bytes} byte(s)."
            if multiple_bytes is not None and byte_len %multiple_bytes !=0 :
                return f"{label} length must be a multiple of {multiple_bytes} bytes."
            numeric =int .from_bytes (raw ,"big")if raw else 0
            if minimum_value is not None and numeric <minimum_value :
                return f"{label} must be at least {minimum_value:02X}."
            if maximum_value is not None and numeric >maximum_value :
                return f"{label} must not exceed {maximum_value:02X}."
            return None
        return validate

    @staticmethod
    def _normalize_user_path (value )->str :
        text =str (value or "").strip ()
        if len (text )>=2 and text [0 ]==text [-1 ]and text [0 ]in ("'",'"'):
            text =text [1 :-1 ]
        if os .name !="nt":
            text =text .replace ("\\ "," ")
        return os .path .expanduser (os .path .expandvars (text ))

    @staticmethod 
    def run_wizard_menu (tp_ctrl =None ,target_aid :str ="A000000151000000",gp_ctrl =None ):
        """Display an interactive wizard menu and return the user's selection."""
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

        print (f"\n{Config.Colors.HEADER}=== GlobalPlatform Execution Wizards ==={Config.Colors.ENDC}")
        print ("Select Execution Variant:")
        print ("  1. INSTALL [for load] - open load context for an Executable Load File")
        print ("  2. INSTALL [for install] - instantiate an applet from a loaded package")
        print ("  3. INSTALL [for make selectable] - make an existing applet selectable")
        print ("  4. INSTALL [for extradition] - transfer control to another Security Domain")
        print ("  5. INSTALL [for registry update] - update registry data for an application/ELF")
        print ("  6. INSTALL [for personalization] / STORE DATA helper")
        print ("  7. INSTALL [for install and make selectable] - single-step instantiate + selectable")
        print ("  8. Full CAP Install Sequence - build or execute INSTALL/LOAD/INSTALL from CAP/IJC")
        print ("  0. Exit Menu")

        try :
            raw_choice =input ("\nChoice [0-8, CANCEL to abort]: ").strip ()
        except (EOFError ,KeyboardInterrupt ):
            print ("\n[-] Wizard menu cancelled.")
            return
        if raw_choice .upper ()in ("CANCEL","/CANCEL","ABORT","/ABORT"):
            print ("[-] Wizard menu cancelled.")
            return
        choice =InteractiveWizards ._normalize_numeric_choice (raw_choice )

        is_zero =False 
        if choice =='0':
            is_zero =True 

        if is_zero :
            return 

        is_one =False 
        if choice =='1':
            is_one =True 

        if is_one :
            InteractiveWizards ._run_install_load (tp_ctrl ,gp_ctrl )
            return 

        is_two =False 
        if choice =='2':
            is_two =True 

        if is_two :
            InteractiveWizards ._run_install_install (tp_ctrl ,gp_ctrl ,"04","INSTALL [for install]")
            return 

        is_three =False 
        if choice =='3':
            is_three =True 

        if is_three :
            InteractiveWizards ._run_install_make_selectable (tp_ctrl ,gp_ctrl )
            return 

        is_four =False 
        if choice =='4':
            is_four =True 

        if is_four :
            InteractiveWizards ._run_install_extradition (tp_ctrl ,gp_ctrl )
            return 

        is_five =False 
        if choice =='5':
            is_five =True 

        if is_five :
            InteractiveWizards ._run_install_registry_update (tp_ctrl ,gp_ctrl )
            return 

        is_six =False 
        if choice =='6':
            is_six =True 

        if is_six :
            is_tp_missing =False 
            if tp_ctrl is None :
                is_tp_missing =True 

            if is_tp_missing :
                print (f"{Config.Colors.FAIL}[!] Transmission controller required for Option 6.{Config.Colors.ENDC}")
                return 

            InteractiveWizards .run_dgi_personalization (tp_ctrl ,gp_ctrl ,target_aid )
            return 

        is_seven =False 
        if choice =='7':
            is_seven =True 

        if is_seven :
            InteractiveWizards ._run_install_install (tp_ctrl ,gp_ctrl ,"0C","INSTALL [for install and make selectable]")
            return 

        is_eight =False 
        if choice =='8':
            is_eight =True 

        if is_eight :
            try :
                filename =input ("Enter path to CAP/IJC file (or CANCEL): ").strip ()
            except (EOFError ,KeyboardInterrupt ):
                print ("\n[-] CAP install wizard cancelled.")
                return
            if filename .upper ()in ("CANCEL","/CANCEL","ABORT","/ABORT"):
                print ("[-] CAP install wizard cancelled.")
                return
            filename =InteractiveWizards ._normalize_user_path (filename )
            InteractiveWizards .build_install_apdu (tp_ctrl ,filename ,gp_ctrl )
            return 

        print (f"{Config.Colors.FAIL}[!] Invalid choice.{Config.Colors.ENDC}")

    @staticmethod 
    def _build_system_parameters_ef ()->bytes :
        wiz =InteractiveWizard ("GP System Specific Parameters (Tag EF) Builder",Config .Colors ,"Reference: GPCS 11.1.5")
        wiz .add_step ("c6","Volatile Memory Quota (Tag C6) [Hex, e.g. 0100 for 256B]:",default ="SKIP")
        wiz .add_step ("c7","Non-Volatile Memory Quota (Tag C7) [Hex, e.g. 0100]:",default ="SKIP")
        wiz .add_step ("c8","Global Service Parameters (Tag C8) [Hex]:",default ="SKIP")
        wiz .add_step ("c9","Implicit Selection Parameter (Tag C9) [Hex]:",default ="SKIP")
        wiz .add_step ("ca","Volatile Reserved Memory (Tag CA) [Hex]:",default ="SKIP")
        wiz .add_step ("cb","Non-Volatile Reserved Memory (Tag CB) [Hex]:",default ="SKIP")

        res =wiz .run ()
        if res is None :
            return None
        payload =bytearray ()

        try :
            tag_steps =(
            ("c6","C6","volatile memory quota"),
            ("c7","C7","non-volatile memory quota"),
            ("c8","C8","global service parameters"),
            ("c9","C9","implicit selection parameter"),
            ("ca","CA","volatile reserved memory"),
            ("cb","CB","non-volatile reserved memory"),
            )
            for step_id ,tag_hex ,label in tag_steps :
                value =res .get (step_id )
                if InteractiveWizards ._is_skip_value (value ):
                    continue
                b =InteractiveWizards ._hex_bytes (value ,label )
                payload .extend (InteractiveWizards ._build_tlv (tag_hex ,b ))

            is_payload_empty =False 
            if len (payload )==0 :
                is_payload_empty =True 

            if is_payload_empty :
                return b''

            ef_tlv =InteractiveWizards ._build_tlv ("EF",bytes (payload ))
            print (f"{Config.Colors.GREEN}[+] EF Tag Generated: {ef_tlv.hex().upper()}{Config.Colors.ENDC}")
            return ef_tlv 

        except ValueError as e :
            print (f"{Config.Colors.FAIL}[!] {e} Skipping Tag EF.{Config.Colors.ENDC}")
            return b''

    @staticmethod 
    def _build_access_domain_parameter (tag_hex :int ,tag_name :str )->bytes :
        wiz =InteractiveWizard (f"{tag_name} (ETSI TS 102 226 8.2.1.3.2.5)",Config .Colors )
        wiz .add_step (
        "choice",
        "1=Full(00), 2=UICC(02), 3=No Access(FF), 4=Raw Hex [Default: 4]:",
        default ="4",choices =("1","2","3","4"),
        )

        def uicc_cond (values ):
            return values .get ("choice")=="2"

        def raw_cond (values ):
            return values .get ("choice")=="4"

        wiz .add_step (
        "add","Access Domain Data (ADD, exactly 3 bytes) [Hex]:",
        default ="",condition =uicc_cond,is_mandatory =True,input_kind ="hex",
        validator =InteractiveWizards ._hex_size_validator (
        "Access Domain Data",exact_bytes =3
        ),
        )
        wiz .add_step (
        "raw","Raw access-domain parameter value [Hex]:",
        default ="",condition =raw_cond,is_mandatory =True,input_kind ="hex",
        )

        res =wiz .run ()
        if res is None :
            return None
        choice =InteractiveWizards ._normalize_numeric_choice (res .get ("choice"))

        is_opt_1 =False 
        if choice =='1':
            is_opt_1 =True 

        if is_opt_1 :
            val =bytes ([0x00 ])
            return InteractiveWizards ._build_tlv (f"{tag_hex:02X}",val )

        is_opt_3 =False 
        if choice =='3':
            is_opt_3 =True 

        if is_opt_3 :
            val =bytes ([0xFF ])
            return InteractiveWizards ._build_tlv (f"{tag_hex:02X}",val )

        is_opt_2 =False 
        if choice =='2':
            is_opt_2 =True 

        if is_opt_2 :
            add_val =res .get ("add")
            if InteractiveWizards ._is_skip_value (add_val ):
                return b''

            try :
                add_bytes =InteractiveWizards ._hex_bytes (add_val ,"access domain data")
                is_add_len_invalid =False 
                if len (add_bytes )!=3 :
                    is_add_len_invalid =True 
                if is_add_len_invalid :
                    print (f"{Config.Colors.FAIL}[!] ADD must be exactly 3 bytes for ADP=02 (ETSI TS 102 226). Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                    return b''
                val =bytes ([0x02 ])+add_bytes 
                return InteractiveWizards ._build_tlv (f"{tag_hex:02X}",val )
            except ValueError :
                print (f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                return b''

        is_raw =False 
        if is_opt_1 ==False :
            if is_opt_2 ==False :
                if is_opt_3 ==False :
                    is_raw =True 

        if is_raw :
            raw_val =res .get ("raw")
            if InteractiveWizards ._is_skip_value (raw_val ):
                return b''

            try :
                b_raw =InteractiveWizards ._hex_bytes (raw_val ,"raw access domain parameter")
                return InteractiveWizards ._build_tlv (f"{tag_hex:02X}",b_raw )
            except ValueError :
                print (f"{Config.Colors.FAIL}[!] Invalid Hex. Skipping Tag {tag_hex:02X}.{Config.Colors.ENDC}")
                return b''

        return b''

    @staticmethod 
    def _build_toolkit_parameters_ea ()->bytes :
        wiz_main =InteractiveWizard ("UICC System Specific Parameters (Tag EA) Builder",Config .Colors ,"Reference: ETSI TS 102 226 Section 8.2.1.3.2.2")
        wiz_main .add_step ("inc_80","Include Toolkit Parameters (Tag 80)? [y/N]:",default =False ,is_bool =True )
        wiz_main .add_step ("inc_c3","Include Toolkit Parameters DAP (Tag C3)? [y/N]:",default =False ,is_bool =True )
        wiz_main .add_step ("inc_81","Include Access Parameters (Tag 81)? [y/N]:",default =False ,is_bool =True )
        wiz_main .add_step ("inc_82","Include Admin Access Parameters (Tag 82)? [y/N]:",default =False ,is_bool =True )
        wiz_main .add_step ("inc_83","Include Update Access Parameters (Tag 83)? [y/N]:",default =False ,is_bool =True )
        res_main =wiz_main .run ()
        if res_main is None :
            return None

        payload_ea =bytearray ()

        is_80_y =False 
        if res_main .get ("inc_80"):
            is_80_y =True 

        if is_80_y :
            wiz_80 =InteractiveWizard ("Toolkit Parameters (8.2.1.3.2.2.1)",Config .Colors )
            byte_validator =InteractiveWizards ._hex_size_validator
            wiz_80 .add_step (
            "prio","Priority Level (01-FF) [Default: 01]:",default ="01",
            input_kind ="hex",validator =byte_validator (
            "Priority",exact_bytes =1,minimum_value =1
            ),
            )
            wiz_80 .add_step (
            "timers","Max Timers (00-08) [Default: 00]:",default ="00",
            input_kind ="hex",validator =byte_validator (
            "Maximum timers",exact_bytes =1,maximum_value =8
            ),
            )
            wiz_80 .add_step (
            "text","Max Menu Text Length (Hex) [Default: 00]:",default ="00",
            input_kind ="hex",validator =byte_validator (
            "Maximum menu text length",exact_bytes =1
            ),
            )
            wiz_80 .add_step (
            "menu","Max Menu Entries (Hex) [Default: 00]:",default ="00",
            input_kind ="hex",validator =byte_validator (
            "Maximum menu entries",exact_bytes =1
            ),
            )
            wiz_80 .add_step (
            "menu_list","Menu Entries List (Position + ID hex string) [SKIP]:",
            default ="SKIP",input_kind ="hex",
            validator =byte_validator (
            "Menu entries list",maximum_bytes =510,multiple_bytes =2
            ),
            )
            wiz_80 .add_step (
            "msl","Minimum Security Level (MSL) [Hex]:",
            default ="SKIP",input_kind ="hex",
            validator =byte_validator ("MSL",maximum_bytes =0xFF ),
            )
            wiz_80 .add_step (
            "tar","TAR Value(s) (3 bytes each) [Hex]:",
            default ="SKIP",input_kind ="hex",
            validator =byte_validator (
            "TAR values",maximum_bytes =0xFF,multiple_bytes =3
            ),
            )
            wiz_80 .add_step (
            "chan","Max BIP Channels (Hex, 1 byte):",
            default ="SKIP",input_kind ="hex",
            validator =byte_validator (
            "Maximum BIP channels",exact_bytes =1,maximum_value =7
            ),
            )
            wiz_80 .add_step (
            "srv","Max Services (Hex, 1 byte):",
            default ="SKIP",input_kind ="hex",
            validator =byte_validator (
            "Maximum services",exact_bytes =1,maximum_value =8
            ),
            )
            res_80 =wiz_80 .run ()
            if res_80 is None :
                return None

            try :
                payload_80 =bytearray ()
                payload_80 .append (int (res_80 .get ("prio"),16 ))
                timers_count =int (res_80 .get ("timers"),16 )
                is_timers_invalid =False 
                if timers_count >0x08 :
                    is_timers_invalid =True 
                if is_timers_invalid :
                    raise ValueError ("Max Timers exceeds ETSI limit (08).")
                payload_80 .append (timers_count )
                payload_80 .append (int (res_80 .get ("text"),16 ))
                payload_80 .append (int (res_80 .get ("menu"),16 ))

                menu_list =res_80 .get ("menu_list")
                has_menu_list =False 
                if not InteractiveWizards ._is_skip_value (menu_list ):
                    has_menu_list =True 
                if has_menu_list :
                    payload_80 .extend (InteractiveWizards ._hex_bytes (menu_list ,"menu entries list"))

                msl_val =res_80 .get ("msl")
                has_msl =False 
                if not InteractiveWizards ._is_skip_value (msl_val ):
                    has_msl =True 

                tar_val =res_80 .get ("tar")
                has_tar =False 
                if not InteractiveWizards ._is_skip_value (tar_val ):
                    has_tar =True 

                chan_val =res_80 .get ("chan")
                has_channels =False 
                if not InteractiveWizards ._is_skip_value (chan_val ):
                    has_channels =True 

                srv_val =res_80 .get ("srv")
                has_services =False 
                if not InteractiveWizards ._is_skip_value (srv_val ):
                    has_services =True 

                has_any_opt =False 
                if has_msl :
                    has_any_opt =True 
                if has_tar :
                    has_any_opt =True 
                if has_channels :
                    has_any_opt =True 
                if has_services :
                    has_any_opt =True 

                if has_any_opt :
                    msl_bytes =b''
                    if has_msl :
                        msl_bytes =InteractiveWizards ._hex_bytes (msl_val ,"minimum security level")

                    payload_80 .append (len (msl_bytes ))
                    payload_80 .extend (msl_bytes )

                    has_tar_or_channels =False 
                    if has_tar :
                        has_tar_or_channels =True 
                    if has_channels :
                        has_tar_or_channels =True 
                    if has_services :
                        has_tar_or_channels =True 

                    if has_tar_or_channels :
                        tar_bytes =b''
                        if has_tar :
                            tar_bytes =InteractiveWizards ._hex_bytes (tar_val ,"TAR values")

                        is_tar_len_invalid =False 
                        if len (tar_bytes )%3 !=0 :
                            is_tar_len_invalid =True 
                        if is_tar_len_invalid :
                            raise ValueError ("TAR field length must be a multiple of 3 bytes.")

                        payload_80 .append (len (tar_bytes ))
                        payload_80 .extend (tar_bytes )

                        if has_channels :
                            channels_count =int (chan_val ,16 )
                            is_channels_invalid =False 
                            if channels_count >0x07 :
                                is_channels_invalid =True 
                            if is_channels_invalid :
                                raise ValueError ("Max BIP Channels exceeds ETSI limit (07).")
                            payload_80 .append (channels_count )
                        else :
                            if has_services :
                                payload_80 .append (0x00 )

                        if has_services :
                            services_count =int (srv_val ,16 )
                            is_services_invalid =False 
                            if services_count >0x08 :
                                is_services_invalid =True 
                            if is_services_invalid :
                                raise ValueError ("Max Services exceeds ETSI limit (08).")
                            payload_80 .append (services_count )

                payload_ea .extend (InteractiveWizards ._build_tlv ("80",bytes (payload_80 )))
            except ValueError as e :
                msg =str (e )
                is_msg_empty =False 
                if len (msg )==0 :
                    is_msg_empty =True 
                if is_msg_empty :
                    print (f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag 80.{Config.Colors.ENDC}")
                if is_msg_empty ==False :
                    print (f"{Config.Colors.FAIL}[!] {msg} Skipping Tag 80.{Config.Colors.ENDC}")

        is_c3_y =False 
        if res_main .get ("inc_c3"):
            is_c3_y =True 

        if is_c3_y :
            wiz_c3 =InteractiveWizard ("Toolkit Parameters DAP (Tag C3)",Config .Colors )
            wiz_c3 .add_step ("dap","DAP [Raw Hex]:",default ="SKIP")
            res_c3 =wiz_c3 .run ()
            if res_c3 is None :
                return None
            dap_val =res_c3 .get ("dap")
            if not InteractiveWizards ._is_skip_value (dap_val ):
                try :
                    dap_bytes =InteractiveWizards ._hex_bytes (dap_val ,"toolkit parameters DAP")
                    payload_ea .extend (InteractiveWizards ._build_tlv ("C3",dap_bytes ))
                except ValueError :
                    print (f"{Config.Colors.FAIL}[!] Invalid Hex provided. Skipping Tag C3.{Config.Colors.ENDC}")

        is_81_y =False 
        if res_main .get ("inc_81"):
            is_81_y =True 

        if is_81_y :
            tag_81_bytes =InteractiveWizards ._build_access_domain_parameter (0x81 ,"Access Parameters")
            if tag_81_bytes is None :
                return None
            payload_ea .extend (tag_81_bytes )

        is_82_y =False 
        if res_main .get ("inc_82"):
            is_82_y =True 

        if is_82_y :
            tag_82_bytes =InteractiveWizards ._build_access_domain_parameter (0x82 ,"Admin Access Parameters")
            if tag_82_bytes is None :
                return None
            payload_ea .extend (tag_82_bytes )

        is_83_y =False 
        if res_main .get ("inc_83"):
            is_83_y =True 

        if is_83_y :
            tag_83_bytes =InteractiveWizards ._build_access_domain_parameter (0x83 ,"Update Access Parameters")
            if tag_83_bytes is None :
                return None
            payload_ea .extend (tag_83_bytes )

        is_ea_empty =False 
        if len (payload_ea )==0 :
            is_ea_empty =True 

        if is_ea_empty :
            return b''

        ea_tlv =InteractiveWizards ._build_tlv ("EA",bytes (payload_ea ))
        print (f"{Config.Colors.GREEN}[+] EA Tag Generated: {ea_tlv.hex().upper()}{Config.Colors.ENDC}")
        return ea_tlv 

    @staticmethod 
    def _build_install_parameters_tlv ()->str :
        wiz =InteractiveWizard ("Install Parameters (TLV Builder)",Config .Colors ,"Constructs the concatenated TLV field for Install Parameters.")
        wiz .add_step ("c9","Tag C9 (Application Specific) [Full C9 TLV or value hex, Default: C900]:",default ="C900")
        wiz .add_step ("ef","Build GP System Specific Parameters (Tag EF)? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_system_parameters_ef )
        wiz .add_step ("ca","Tag CA (SIM File Access) [Raw Hex]:",default ="SKIP",warning ="ETSI TS 102 226: Tag 'CA' and 'EA' cannot coexist.")

        def ea_cond (res ):
            """Return an EXTERNAL AUTHENTICATE condition predicate for the wizard flow."""
            ca_val =res .get ("ca")
            is_ca_skip =False 
            if ca_val =="SKIP":
                is_ca_skip =True 
            if ca_val is None :
                is_ca_skip =True 
            return is_ca_skip 

        wiz .add_step ("ea","Build UICC System Specific Parameters (Tag EA)? [y/N]:",default =False ,is_bool =True ,condition =ea_cond ,builder_func =InteractiveWizards ._build_toolkit_parameters_ea )

        res =wiz .run ()
        if res is None :
            return None
        payload =bytearray ()

        c9_val =res .get ("c9")
        has_c9 =False 
        if not InteractiveWizards ._is_skip_value (c9_val ):
            has_c9 =True 

        if has_c9 :
            try :
                payload .extend (InteractiveWizards ._coerce_c9_install_parameter (c9_val ))
            except ValueError as e :
                print (f"{Config.Colors.FAIL}[!] {e} Skipping C9.{Config.Colors.ENDC}")

        is_ef =False 
        if res .get ("ef"):
            is_ef =True 

        if is_ef :
            ef_bytes =res .get ("ef_built")
            has_ef_bytes =False 
            if ef_bytes is not None :
                has_ef_bytes =True 
            if has_ef_bytes :
                payload .extend (ef_bytes )

        ca_val =res .get ("ca")
        has_ca =False 
        if not InteractiveWizards ._is_skip_value (ca_val ):
            has_ca =True 

        if has_ca :
            try :
                b =InteractiveWizards ._hex_bytes (ca_val ,"CA install parameter")
                payload .extend (InteractiveWizards ._build_tlv ("CA",b ))
                print (f"{Config.Colors.GREEN}[+] CA Tag Generated: {InteractiveWizards ._build_tlv('CA',b).hex().upper()}{Config.Colors.ENDC}")
            except ValueError as e :
                print (f"{Config.Colors.FAIL}[!] {e} Skipping CA.{Config.Colors.ENDC}")

        is_ca_missing =False 
        if has_ca ==False :
            is_ca_missing =True 

        if is_ca_missing :
            is_ea =False 
            if res .get ("ea"):
                is_ea =True 

            if is_ea :
                ea_bytes =res .get ("ea_built")
                has_ea_bytes =False 
                if ea_bytes is not None :
                    has_ea_bytes =True 
                if has_ea_bytes :
                    payload .extend (ea_bytes )

        res_hex =payload .hex ().upper ()

        is_empty =False 
        if len (res_hex )==0 :
            is_empty =True 

        if is_empty :
            return ""

        print (f"\n{Config.Colors.GREEN}[+] Overall Install Parameters Generated: {res_hex}{Config.Colors.ENDC}")
        return res_hex 

    @staticmethod 
    def _build_lv_field (hex_val :str )->bytes :
        if InteractiveWizards ._is_skip_value (hex_val ):
            return bytes ([0x00 ])

        b =InteractiveWizards ._hex_bytes (hex_val ,"LV field")
        if len (b )>255 :
            raise ValueError ("LV field length exceeds 255 bytes.")
        return bytes ([len (b )])+b

    @staticmethod 
    def _build_privileges ()->str :
        wiz =InteractiveWizard ("Privileges Builder (GPCS 11.1.2)",Config .Colors )
        wiz .add_step ("b7","Security Domain (Bit 7)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b6","DAP Verification (Bit 6)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b5","Delegated Management (Bit 5)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b4","Card Lock (Bit 4)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b3","Card Terminate (Bit 3)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b2","Default Selected (Bit 2)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b1","CVM Management (Bit 1)? [y/N]:",default =False ,is_bool =True ,indent =1 )
        wiz .add_step ("b0","Mandated DAP Verification (Bit 0)? [y/N]:",default =False ,is_bool =True ,indent =1 )

        res =wiz .run ()
        if res is None :
            return None
        priv =0x00 

        has_b7 =False 
        if res .get ("b7"):
            has_b7 =True 
        if has_b7 :
            priv |=0x80 

        has_b6 =False 
        if res .get ("b6"):
            has_b6 =True 
        if has_b6 :
            priv |=0x40 

        has_b5 =False 
        if res .get ("b5"):
            has_b5 =True 
        if has_b5 :
            priv |=0x20 

        has_b4 =False 
        if res .get ("b4"):
            has_b4 =True 
        if has_b4 :
            priv |=0x10 

        has_b3 =False 
        if res .get ("b3"):
            has_b3 =True 
        if has_b3 :
            priv |=0x08 

        has_b2 =False 
        if res .get ("b2"):
            has_b2 =True 
        if has_b2 :
            priv |=0x04 

        has_b1 =False 
        if res .get ("b1"):
            has_b1 =True 
        if has_b1 :
            priv |=0x02 

        has_b0 =False 
        if res .get ("b0"):
            has_b0 =True 
        if has_b0 :
            priv |=0x01 

        res_hex =f"{priv:02X}"
        print (f"[+] Generated Privilege Bitmask: {res_hex}")
        return res_hex 

    @staticmethod 
    def _run_install_load (tp_ctrl ,gp_ctrl =None )->None :
        wiz =InteractiveWizard ("Building INSTALL [for load] (P1=02)",Config .Colors )
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        lv_validator =InteractiveWizards ._hex_size_validator
        wiz .add_step (
        "lf_aid","Executable Load File AID [Hex]:",default ="",
        is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "sd_aid","Target Security Domain AID [Hex, optional]:",default ="",
        input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "lf_hash","Load File Data Block Hash [Hex, optional]:",default ="",
        input_kind ="hex",validator =lv_validator (
        "Load File hash",maximum_bytes =255
        ),
        )
        wiz .add_step ("params","Launch Load Parameters TLV Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_install_parameters_tlv )

        def params_cond (res ):
            is_y =False 
            if res .get ("params")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_params","Load Parameters [Raw Hex only, optional]:",
        default ="",condition =params_cond,input_kind ="hex",
        validator =lv_validator ("Load parameters",maximum_bytes =255 ),
        )
        wiz .add_step (
        "token","Load Token [Hex, optional]:",default ="",input_kind ="hex",
        validator =lv_validator ("Load token",maximum_bytes =255 ),
        )

        res =wiz .run ()
        if res is None :
            return
        payload =bytearray ()

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("lf_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("sd_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("lf_hash")))

        is_params_y =False 
        if res .get ("params"):
            is_params_y =True 

        params_hex =""
        if is_params_y :
            built_val =res .get ("params_built")
            has_built =False 
            if built_val is not None :
                has_built =True 
            if has_built :
                params_hex =built_val 

        is_params_n =False 
        if is_params_y ==False :
            is_params_n =True 

        if is_params_n :
            params_hex =res .get ("raw_params")

        payload .extend (InteractiveWizards ._build_lv_field (params_hex ))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("token")))

        InteractiveWizards ._finalize_and_transmit (tp_ctrl ,gp_ctrl ,"02",payload )

    @staticmethod 
    def _run_install_install (tp_ctrl ,gp_ctrl ,p1_hex :str ,desc :str )->None :
        wiz =InteractiveWizard (f"Building {desc} (P1={p1_hex})",Config .Colors )
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        lv_validator =InteractiveWizards ._hex_size_validator
        wiz .add_step (
        "elf_aid","Executable Load File AID / Package AID [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "em_aid","Executable Module AID [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "app_aid","Target Application / Applet AID [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step ("priv","Launch Privileges Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_privileges )

        def priv_cond (res ):
            is_y =False 
            if res .get ("priv")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_priv","Privileges [Raw Hex bitmask, default 00]:",
        default ="00",condition =priv_cond,input_kind ="hex",
        validator =lv_validator ("Privileges",minimum_bytes =1,maximum_bytes =3 ),
        )
        wiz .add_step ("params","Launch Install Parameters TLV Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_install_parameters_tlv )

        def params_cond (res ):
            is_y =False 
            if res .get ("params")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_params","Install Parameters [Raw Hex TLV, default C900]:",
        default ="C900",condition =params_cond,input_kind ="hex",
        validator =lv_validator ("Install parameters",maximum_bytes =255 ),
        )
        wiz .add_step (
        "token","Install Token [Hex, optional]:",default ="",input_kind ="hex",
        validator =lv_validator ("Install token",maximum_bytes =255 ),
        )

        res =wiz .run ()
        if res is None :
            return
        payload =bytearray ()

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("elf_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("em_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("app_aid")))

        is_priv_y =False 
        if res .get ("priv"):
            is_priv_y =True 

        priv_hex ="00"
        if is_priv_y :
            built_val =res .get ("priv_built")
            has_built =False 
            if built_val is not None :
                has_built =True 
            if has_built :
                priv_hex =built_val 

        is_priv_n =False 
        if is_priv_y ==False :
            is_priv_n =True 

        if is_priv_n :
            priv_hex =res .get ("raw_priv")

        payload .extend (InteractiveWizards ._build_lv_field (priv_hex ))

        is_params_y =False 
        if res .get ("params"):
            is_params_y =True 

        params_hex ="C900"
        if is_params_y :
            built_params =res .get ("params_built")
            has_built =False 
            if built_params is not None :
                if len (built_params )>0 :
                    has_built =True 
            if has_built :
                params_hex =built_params 

        is_params_n =False 
        if is_params_y ==False :
            is_params_n =True 

        if is_params_n :
            params_hex =res .get ("raw_params")

        payload .extend (InteractiveWizards ._build_lv_field (params_hex ))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("token")))

        InteractiveWizards ._finalize_and_transmit (tp_ctrl ,gp_ctrl ,p1_hex ,payload )

    @staticmethod 
    def _run_install_make_selectable (tp_ctrl ,gp_ctrl =None )->None :
        wiz =InteractiveWizard ("Building INSTALL [for make selectable] (P1=08)",Config .Colors )
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        lv_validator =InteractiveWizards ._hex_size_validator
        wiz .add_step (
        "app_aid","Target Application / Applet AID [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step ("priv","Launch Privileges Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_privileges )

        def priv_cond (res ):
            is_y =False 
            if res .get ("priv")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_priv","Privileges [Raw Hex bitmask, default 00]:",
        default ="00",condition =priv_cond,input_kind ="hex",
        validator =lv_validator ("Privileges",minimum_bytes =1,maximum_bytes =3 ),
        )
        wiz .add_step ("params","Launch Install Parameters TLV Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_install_parameters_tlv )

        def params_cond (res ):
            is_y =False 
            if res .get ("params")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_params","Install Parameters [Raw Hex TLV, optional]:",
        default ="",condition =params_cond,input_kind ="hex",
        validator =lv_validator ("Install parameters",maximum_bytes =255 ),
        )
        wiz .add_step (
        "token","Install Token [Hex, optional]:",default ="",input_kind ="hex",
        validator =lv_validator ("Install token",maximum_bytes =255 ),
        )

        res =wiz .run ()
        if res is None :
            return
        payload =bytearray ()

        payload .extend (InteractiveWizards ._build_lv_field (""))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("app_aid")))

        is_priv_y =False 
        if res .get ("priv"):
            is_priv_y =True 

        priv_hex ="00"
        if is_priv_y :
            built_val =res .get ("priv_built")
            has_built =False 
            if built_val is not None :
                has_built =True 
            if has_built :
                priv_hex =built_val 

        is_priv_n =False 
        if is_priv_y ==False :
            is_priv_n =True 

        if is_priv_n :
            priv_hex =res .get ("raw_priv")

        payload .extend (InteractiveWizards ._build_lv_field (priv_hex ))

        is_params_y =False 
        if res .get ("params"):
            is_params_y =True 

        params_hex =""
        if is_params_y :
            built_params =res .get ("params_built")
            has_built =False 
            if built_params is not None :
                if len (built_params )>0 :
                    has_built =True 
            if has_built :
                params_hex =built_params 

        is_params_n =False 
        if is_params_y ==False :
            is_params_n =True 

        if is_params_n :
            params_hex =res .get ("raw_params")

        payload .extend (InteractiveWizards ._build_lv_field (params_hex ))

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("token")))

        InteractiveWizards ._finalize_and_transmit (tp_ctrl ,gp_ctrl ,"08",payload )

    @staticmethod 
    def _run_install_extradition (tp_ctrl ,gp_ctrl =None )->None :
        wiz =InteractiveWizard ("Building INSTALL [for extradition] (P1=10)",Config .Colors )
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        wiz .add_step (
        "sd_aid","Destination Security Domain AID [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "app_aid","Application / ELF AID being extradited [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step (
        "token","Extradition Token [Hex, optional]:",default ="",input_kind ="hex",
        validator =InteractiveWizards ._hex_size_validator (
        "Extradition token",maximum_bytes =255
        ),
        )

        res =wiz .run ()
        if res is None :
            return
        payload =bytearray ()

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("sd_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (""))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("app_aid")))
        payload .extend (InteractiveWizards ._build_lv_field (res .get ("token")))
        payload .extend (InteractiveWizards ._build_lv_field (""))

        InteractiveWizards ._finalize_and_transmit (tp_ctrl ,gp_ctrl ,"10",payload )

    @staticmethod 
    def _run_install_registry_update (tp_ctrl ,gp_ctrl =None )->None :
        wiz =InteractiveWizard ("Building INSTALL [for registry update] (P1=40)",Config .Colors )
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        lv_validator =InteractiveWizards ._hex_size_validator
        wiz .add_step (
        "app_aid","Application / ELF AID to update [Hex]:",
        default ="",is_mandatory =True,input_kind ="hex",validator =aid_validator,
        )
        wiz .add_step ("priv","Launch Privileges Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_privileges )

        def priv_cond (res ):
            is_y =False 
            if res .get ("priv")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_priv","Privileges [Raw Hex bitmask, default 00]:",
        default ="00",condition =priv_cond,input_kind ="hex",
        validator =lv_validator ("Privileges",minimum_bytes =1,maximum_bytes =3 ),
        )
        wiz .add_step ("params","Launch Install Parameters TLV Builder? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_install_parameters_tlv )

        def params_cond (res ):
            is_y =False 
            if res .get ("params")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_params","Install Parameters [Raw Hex TLV, optional]:",
        default ="",condition =params_cond,input_kind ="hex",
        validator =lv_validator ("Install parameters",maximum_bytes =255 ),
        )
        wiz .add_step (
        "token","Install Token [Hex, optional]:",default ="",input_kind ="hex",
        validator =lv_validator ("Install token",maximum_bytes =255 ),
        )

        res =wiz .run ()
        if res is None :
            return
        payload =bytearray ()

        payload .append (0x00 )
        payload .append (0x00 )

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("app_aid")))

        is_priv_y =False 
        if res .get ("priv"):
            is_priv_y =True 

        priv_hex ="00"
        if is_priv_y :
            built_val =res .get ("priv_built")
            has_built =False 
            if built_val is not None :
                has_built =True 
            if has_built :
                priv_hex =built_val 

        is_priv_n =False 
        if is_priv_y ==False :
            is_priv_n =True 

        if is_priv_n :
            priv_hex =res .get ("raw_priv")

        payload .extend (InteractiveWizards ._build_lv_field (priv_hex ))

        is_params_y =False 
        if res .get ("params"):
            is_params_y =True 

        params_hex =""
        if is_params_y :
            built_params =res .get ("params_built")
            has_built =False 
            if built_params is not None :
                if len (built_params )>0 :
                    has_built =True 
            if has_built :
                params_hex =built_params 

        is_params_n =False 
        if is_params_y ==False :
            is_params_n =True 

        if is_params_n :
            params_hex =res .get ("raw_params")

        payload .extend (InteractiveWizards ._build_lv_field (params_hex ))

        payload .extend (InteractiveWizards ._build_lv_field (res .get ("token")))

        InteractiveWizards ._finalize_and_transmit (tp_ctrl ,gp_ctrl ,"40",payload )

    @staticmethod 
    def _ensure_auth_sd (gp_ctrl )->bool :
        if gp_ctrl is None :
            print (f"{Config.Colors.FAIL}[!] AUTH-SD controller unavailable. Cannot open SCP03 session for live transmission.{Config.Colors.ENDC}")
            return False 
        print (f"{Config.Colors.CYAN}[*] AUTH-SD: opening SCP03 session before transmission...{Config.Colors.ENDC}")
        auth_ok =gp_ctrl .authenticate ()
        if auth_ok ==False :
            print (f"{Config.Colors.FAIL}[-] AUTH-SD failed. Transmission aborted.{Config.Colors.ENDC}")
            return False 
        return True 

    @staticmethod 
    def _finalize_and_transmit (tp_ctrl ,gp_ctrl ,p1_hex :str ,payload :bytearray )->None :
        try :
            lc_hex =InteractiveWizards ._encode_apdu_lc (len (payload ))
        except ValueError as e :
            print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")
            return 
        apdu =f"80E6{p1_hex}00{lc_hex}{payload.hex().upper()}"
        print (f"\n[*] Generated APDU:\n    {apdu}")

        is_tp_present =False 
        if tp_ctrl is not None :
            is_tp_present =True 

        if is_tp_present :
            wiz =InteractiveWizard ("Transmit Confirmation",Config .Colors )
            wiz .add_step ("tx","Transmit APDU to card? [y/N]:",default =False ,is_bool =True )
            res_wiz =wiz .run ()
            if res_wiz is None :
                return

            do_send =False 
            if res_wiz .get ("tx"):
                do_send =True 

            if do_send :
                auth_ok =InteractiveWizards ._ensure_auth_sd (gp_ctrl )
                if auth_ok ==False :
                    return 
                res ,sw1 ,sw2 =tp_ctrl .transmit (apdu )
                is_success =False 
                if sw1 ==0x90 :
                    if sw2 ==0x00 :
                        is_success =True 

                if is_success :
                    print ("[+] Sequence executed successfully.")

                is_fail =False 
                if is_success ==False :
                    is_fail =True 

                if is_fail :
                    print (f"[-] Command rejected: {sw1:02X}{sw2:02X}")

    @staticmethod 
    def build_install_apdu (tp_ctrl ,filename :str ,gp_ctrl =None ):
        """Build a GP INSTALL [for install] APDU from the supplied parameters."""
        filename =InteractiveWizards ._normalize_user_path (filename )
        is_valid_file =False 
        if filename :
            if os .path .isfile (filename ):
                is_valid_file =True 

        if is_valid_file ==False :
            print (f"{Config.Colors.FAIL}[!] Valid CAP file required: {filename}{Config.Colors.ENDC}")
            return 

        print (f"\n{Config.Colors.HEADER}=== Full CAP Install Sequence ==={Config.Colors.ENDC}")

        try :
            parsed_cap =CapFileParser .parse_with_metadata (filename )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Parse Error: {e}{Config.Colors.ENDC}")
            return 

        pkg_aid =parsed_cap .package_aid 
        app_aids =parsed_cap .applet_aids 

        print (f"Extracted Package AID: {pkg_aid.hex().upper()}")

        def_app_aid =""

        has_app_aids =False 
        if len (app_aids )>0 :
            has_app_aids =True 

        if has_app_aids :
            def_app_aid =app_aids [0 ].hex ().upper ()

        print (f"Extracted Applet AID : {def_app_aid or '(none found)'}")

        wiz =InteractiveWizard ("CAP File Install Configuration",Config .Colors ,"Build dry-run APDUs, or execute the full CAP load directly on the connected SIM.")
        aid_validator =InteractiveWizards ._hex_size_validator (
        "AID",minimum_bytes =5,maximum_bytes =16
        )
        wiz .add_step (
        "app_aid",
        f"Target Applet AID [Hex, default from CAP: {def_app_aid or 'none'}]:",
        default =def_app_aid,is_mandatory =True,input_kind ="hex",
        validator =aid_validator,
        )

        def module_validator (value )->str |None :
            if str (value ).strip ().upper ()=="MIRROR":
                return None
            try :
                cleaned =InteractiveWizards ._clean_hex_input (
                value ,"module AID",allow_empty =False
                )
            except ValueError as error :
                return str (error )
            return aid_validator (cleaned )

        wiz .add_step (
        "mod_aid",
        "Target Module AID [Hex, default=MIRROR -> same as applet AID]:",
        default ="MIRROR",input_kind ="text",validator =module_validator,
        )
        wiz .add_step (
        "priv","Privileges [Hex bitmask, default 00]:",default ="00",
        input_kind ="hex",validator =InteractiveWizards ._hex_size_validator (
        "Privileges",minimum_bytes =1,maximum_bytes =3
        ),
        )
        wiz .add_step ("run_b","Launch interactive TLV builder for Install Parameters? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_install_parameters_tlv )

        def run_b_cond (res ):
            is_y =False 
            if res .get ("run_b")==True :
                is_y =True 
            return not is_y 

        wiz .add_step (
        "raw_p","Install Parameters [Raw Hex TLV, default C900]:",
        default ="C900",condition =run_b_cond,input_kind ="hex",
        validator =InteractiveWizards ._hex_size_validator (
        "Install parameters",maximum_bytes =255
        ),
        )
        wiz .add_step ("ota","Format LOAD blocks for OTA / SMS-PP size limits? [y/N]:",default =False ,is_bool =True )

        def ota_cond (values ):
            return bool (values .get ("ota"))

        wiz .add_step (
        "algo","OTA encryption profile [1=3DES-sized chunks, 2=AES-sized chunks]:",
        default ="1",condition =ota_cond,choices =("1","2"),
        )
        if gp_ctrl is not None :
            wiz .add_step ("execute","Execute full CAP install directly on the connected SIM after generation? [y/N]:",default =False ,is_bool =True )

        res =wiz .run ()
        if res is None :
            return

        app_aid_hex =res .get ("app_aid")

        mod_aid_hex =res .get ("mod_aid")
        is_mirror =False 
        if str (mod_aid_hex ).strip ().upper ()=="MIRROR":
            is_mirror =True 

        if is_mirror :
            mod_aid_hex =app_aid_hex 
        else :
            mod_aid_hex =InteractiveWizards ._clean_hex_input (
            mod_aid_hex ,"module AID",allow_empty =False
            )

        priv_hex =res .get ("priv")

        is_run_builder_y =False 
        if res .get ("run_b"):
            is_run_builder_y =True 

        params_hex ="C900"
        if is_run_builder_y :
            built_params =res .get ("run_b_built")
            has_built =False 
            if built_params is not None :
                if len (built_params )>0 :
                    has_built =True 
            if has_built :
                params_hex =built_params 

        is_run_builder_n =False 
        if is_run_builder_y ==False :
            is_run_builder_n =True 

        if is_run_builder_n :
            params_hex =res .get ("raw_p")

        is_params_empty =False 
        if len (params_hex )==0 :
            is_params_empty =True 

        if is_params_empty :
            params_hex ="C900"

        chunk_size =240 

        is_ota_y =False 
        if res .get ("ota"):
            is_ota_y =True 

        if is_ota_y :
            algo_choice =InteractiveWizards ._normalize_numeric_choice (res .get ("algo"),"1")

            is_algo_2 =False 
            if algo_choice =='2':
                is_algo_2 =True 

            if is_algo_2 :
                chunk_size =103 

            is_algo_1 =False 
            if is_algo_2 ==False :
                is_algo_1 =True 

            if is_algo_1 :
                chunk_size =111 

        print (f"\n{Config.Colors.HEADER}=== GENERATED APDUs (Dry Run) ==={Config.Colors.ENDC}")

        install_load_data =bytearray ()
        install_load_data .append (len (pkg_aid ))
        install_load_data .extend (pkg_aid )
        install_load_data .append (0x00 )
        install_load_data .append (0x00 )
        install_load_data .append (0x00 )
        install_load_data .append (0x00 )

        print (f"{Config.Colors.BOLD}1. INSTALL [for load]{Config.Colors.ENDC}")
        il_lc =InteractiveWizards ._encode_apdu_lc (len (install_load_data ))
        print (f"80E60200{il_lc}{install_load_data.hex().upper()}\n")

        try :
            load_chunks =CapFileParser .plan_load_chunks (parsed_cap ,chunk_size )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Chunk Plan Error: {e}{Config.Colors.ENDC}")
            return 

        total_chunks =len (load_chunks )
        print (f"{Config.Colors.BOLD}2. LOAD (Transmitted in {total_chunks} blocks){Config.Colors.ENDC}")

        if is_ota_y :
            print (f"   (Formatted for SMS-PP, Chunk Size: {chunk_size} bytes)")
            if SCP80_PREVIEW_AVAIL :
                print ("   (SCP80 transport auto-falls back to concatenated SMS when required)")

        ota_cipher_mode ="3DES"
        if is_ota_y and algo_choice =='2':
            ota_cipher_mode ="AES"

        for i ,chunk_info in enumerate (load_chunks ):
            chunk =chunk_info .payload 

            p1 =0x00 
            if i >=(total_chunks -1 ):
                p1 =0x80 

            p2 =i %256 

            chunk_hex =chunk .hex ().upper ()
            print (f"  [Block {i+1}] 80E8{p1:02X}{p2:02X}{len(chunk):02X}{chunk_hex}")
            if is_ota_y and SCP80_PREVIEW_AVAIL :
                inner_apdu_len =5 +len (chunk )
                sms_segments =OtaPacketBuilder .estimate_segment_count (inner_apdu_len ,ota_cipher_mode )
                if sms_segments >1 :
                    print (f"           -> SCP80 SMS: {sms_segments} concatenated segments")
                else :
                    print ("           -> SCP80 SMS: single segment")

        app_aid_bytes =HexUtils .to_bytes (app_aid_hex )
        mod_aid_bytes =HexUtils .to_bytes (mod_aid_hex )
        priv_bytes =HexUtils .to_bytes (priv_hex )
        param_bytes =HexUtils .to_bytes (params_hex )

        install_data =bytearray ()
        install_data .append (len (pkg_aid ))
        install_data .extend (pkg_aid )
        install_data .append (len (mod_aid_bytes ))
        install_data .extend (mod_aid_bytes )
        install_data .append (len (app_aid_bytes ))
        install_data .extend (app_aid_bytes )
        install_data .append (len (priv_bytes ))
        install_data .extend (priv_bytes )
        install_data .append (len (param_bytes ))
        install_data .extend (param_bytes )
        install_data .append (0x00 )

        print (f"\n{Config.Colors.BOLD}3. INSTALL [for install]{Config.Colors.ENDC}")
        i_lc =InteractiveWizards ._encode_apdu_lc (len (install_data ))
        install_apdu =f"80E60C00{i_lc}{install_data.hex().upper()}"
        print (f"{install_apdu}\n")

        do_execute =False 
        if gp_ctrl is not None :
            if res .get ("execute"):
                do_execute =True 

        if do_execute :
            auth_ok =InteractiveWizards ._ensure_auth_sd (gp_ctrl )
            if auth_ok ==False :
                return 
            print (f"{Config.Colors.CYAN}[*] Executing CAP install sequence on connected SIM...{Config.Colors.ENDC}")
            gp_ctrl .install_cap_file_with_install_apdu (
            filename ,
            install_apdu ,
            load_chunk_size =chunk_size
            )

    @staticmethod 
    def run_dgi_personalization (tp_ctrl ,gp_ctrl ,target_aid :str )->None :
        """Run the interactive DGI personalisation wizard for a loaded CAP package."""
        mode_wiz =InteractiveWizard ("Personalization / STORE DATA",Config .Colors ,"Choose whether to open INSTALL [for personalization] against a target AID first, or to send STORE DATA directly.")
        mode_wiz .add_step (
        "target_mode",
        "Mode [1=Target AID via INSTALL for personalization, "
        "2=Direct STORE DATA only]:",
        default ="1",choices =("1","2"),
        )

        def target_aid_cond (res ):
            return InteractiveWizards ._normalize_numeric_choice (res .get ("target_mode","1"),"1")=='1'

        def raw_mode_cond (res ):
            return InteractiveWizards ._normalize_numeric_choice (res .get ("input_mode","1"),"1")=='2'

        def builder_mode_cond (res ):
            return InteractiveWizards ._normalize_numeric_choice (res .get ("input_mode","1"),"1")!='2'

        mode_wiz .add_step (
        "target_aid",
        f"Target AID for INSTALL [for personalization] [Hex, default: {target_aid}]:",
        default =target_aid ,condition =target_aid_cond,is_mandatory =True,
        input_kind ="hex",validator =InteractiveWizards ._hex_size_validator (
        "Target AID",minimum_bytes =5,maximum_bytes =16
        ),
        )
        mode_wiz .add_step (
        "input_mode",
        "STORE DATA payload input [1=Structured TLV builder, 2=Raw payload hex only]:",
        default ="2",choices =("1","2"),
        )
        one_byte =InteractiveWizards ._hex_size_validator
        mode_wiz .add_step (
        "store_p1","STORE DATA P1 [Hex, default 90]:",default ="90",
        input_kind ="hex",validator =one_byte ("STORE DATA P1",exact_bytes =1 ),
        )
        mode_wiz .add_step (
        "store_p2","STORE DATA P2 [Hex, default 00]:",default ="00",
        input_kind ="hex",validator =one_byte ("STORE DATA P2",exact_bytes =1 ),
        )
        mode_wiz .add_step (
        "raw_payload","STORE DATA payload only [Hex, no CLA/INS/P1/P2/Lc]:",
        default ="",condition =raw_mode_cond,is_mandatory =True,input_kind ="hex",
        )
        mode_wiz .add_step ("42","Issuer/SD ID (Tag 42) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("45","Card/SD Image Number (Tag 45) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("4F","Issuer Security Domain AID (Tag 4F) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("66","Card/SD Recognition Data (Tag 66) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("67","Launch Card Capability Info Builder (Tag 67)? [y/N]:",default =False ,is_bool =True ,builder_func =InteractiveWizards ._build_tag_67 ,condition =builder_mode_cond )
        mode_wiz .add_step ("5F50","SD Manager URL (Tag 5F50) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("86","Security Level (Tag 86) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("8A","Admin IP/Host (Tag 8A) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        mode_wiz .add_step ("8C","Admin URL (Tag 8C) [Hex, Default: SKIP]:",default ="SKIP",condition =builder_mode_cond )
        def tlv_stream_validator (value )->str |None :
            if InteractiveWizards ._is_skip_value (value ):
                return None
            try :
                InteractiveWizards ._remove_tag_from_payload (str (value ),"00")
            except ValueError as error :
                return f"Custom TLV stream is invalid: {error}"
            return None

        mode_wiz .add_step (
        "custom","Add Custom TLV String [Hex, Default: SKIP]:",
        default ="SKIP",condition =builder_mode_cond,input_kind ="hex",
        validator =tlv_stream_validator,
        )

        res =mode_wiz .run ()
        if res is None :
            return

        payload =""
        is_raw_mode =False 
        if InteractiveWizards ._normalize_numeric_choice (res .get ("input_mode","1"),"1")=='2':
            is_raw_mode =True 

        if is_raw_mode :
            try :
                payload =InteractiveWizards ._clean_hex_input (res .get ("raw_payload",""),"STORE DATA payload").upper ()
            except ValueError as e :
                print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")
                return
        else :
            def append_simple_tlv (tag_hex :str ,value)->None :
                nonlocal payload
                if InteractiveWizards ._is_skip_value (value ):
                    return
                value_bytes =InteractiveWizards ._hex_bytes (value ,f"tag {tag_hex} value")
                payload +=tag_hex +InteractiveWizards ._encode_ber_tlv_length (len (value_bytes ))+value_bytes .hex ().upper ()

            val_42 =res .get ("42")
            append_simple_tlv ("42",val_42 )

            val_45 =res .get ("45")
            append_simple_tlv ("45",val_45 )

            val_4f =res .get ("4F")
            append_simple_tlv ("4F",val_4f )

            val_66 =res .get ("66")
            append_simple_tlv ("66",val_66 )

            is_67 =False 
            if res .get ("67"):
                is_67 =True 
            if is_67 :
                res_67 =res .get ("67_built")
                has_67_val =False 
                if res_67 is not None :
                    if len (res_67 )>0 :
                        has_67_val =True 
                if has_67_val :
                    payload +=res_67 

            val_5f50 =res .get ("5F50")
            append_simple_tlv ("5F50",val_5f50 )

            val_86 =res .get ("86")
            append_simple_tlv ("86",val_86 )

            val_8a =res .get ("8A")
            append_simple_tlv ("8A",val_8a )

            val_8c =res .get ("8C")
            append_simple_tlv ("8C",val_8c )

            val_custom =res .get ("custom")
            has_custom =False 
            if not InteractiveWizards ._is_skip_value (val_custom ):
                has_custom =True 
            if has_custom :
                payload +=InteractiveWizards ._clean_hex_input (val_custom ,"custom TLV string").upper ()

        is_payload_empty =False 
        if len (payload )==0 :
            is_payload_empty =True 

        if is_payload_empty :
            print ("[-] No parameters provided. Aborting.")
            return 

        try :
            p1_hex =InteractiveWizards ._normalize_hex_byte (res .get ("store_p1","90"),"90","STORE DATA P1")
            p2_hex =InteractiveWizards ._normalize_hex_byte (res .get ("store_p2","00"),"00","STORE DATA P2")
        except ValueError as e :
            print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")
            return
        target_mode =InteractiveWizards ._normalize_numeric_choice (res .get ("target_mode","1"),"1")

        print (f"\n[+] Final STORE DATA Payload: {payload}")

        install_apdu =None 
        if target_mode =='1':
            try :
                target_val =InteractiveWizards ._clean_hex_input (res .get ("target_aid",target_aid ),"target AID",allow_empty =False )
                install_apdu =InteractiveWizards ._build_install_perso (target_val )
            except ValueError as e :
                print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")
                return
            print (f"\n[*] Generated INSTALL APDU:\n    {install_apdu}")

        try :
            store_data_apdu =InteractiveWizards ._build_store_data_with_params (payload ,p1_hex ,p2_hex )
        except ValueError as e :
            print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")
            return
        print (f"[*] Generated STORE DATA APDU (P1={p1_hex}, P2={p2_hex}):\n    {store_data_apdu}")

        tx_wiz =InteractiveWizard ("Transmit Confirmation",Config .Colors )
        tx_wiz .add_step ("tx","Transmit the generated INSTALL / STORE DATA sequence to the card now? [y/N]:",default =False ,is_bool =True )
        res_tx =tx_wiz .run ()
        if res_tx is None :
            return

        do_transmit =False 
        if res_tx .get ("tx"):
            do_transmit =True 

        if do_transmit :
            InteractiveWizards ._execute_sequence (tp_ctrl ,gp_ctrl ,install_apdu ,store_data_apdu )

    @staticmethod 
    def _patch_dgi (base_dgi :str ,new_tlv :str )->str :
        try :
            base_dgi =InteractiveWizards ._clean_hex_input (
            base_dgi ,"base DGI",allow_empty =False
            )
            new_tlv =InteractiveWizards ._clean_hex_input (
            new_tlv ,"replacement TLV",allow_empty =False
            )
            if len (base_dgi )<6 :
                raise ValueError ("Base DGI must contain a two-byte tag and a length.")
            dgi_tag =base_dgi [:4 ]
            remainder =base_dgi [4 :]

            dgi_len ,len_bytes_consumed =InteractiveWizards ._decode_ber_tlv_length (remainder )
            payload_start_idx =len_bytes_consumed *2 
            dgi_payload =remainder [payload_start_idx :]
            if len (dgi_payload )!=dgi_len *2 :
                raise ValueError (
                f"Base DGI declares {dgi_len} bytes but contains "
                f"{len(dgi_payload)//2}."
                )

            target_tag_hex =InteractiveWizards ._extract_tag_from_tlv (new_tlv )
            tag_chars =len (target_tag_hex )
            new_len ,new_len_bytes =InteractiveWizards ._decode_ber_tlv_length (
            new_tlv [tag_chars :]
            )
            expected_new_chars =tag_chars +(new_len_bytes *2 )+(new_len *2 )
            if expected_new_chars !=len (new_tlv ):
                raise ValueError ("Replacement TLV length does not match its value.")

            cleaned_payload =InteractiveWizards ._remove_tag_from_payload (dgi_payload ,target_tag_hex )
            new_payload =cleaned_payload +new_tlv 

            new_payload_len =len (new_payload )//2 
            new_len_hex =InteractiveWizards ._encode_ber_tlv_length (new_payload_len )

            return dgi_tag +new_len_hex +new_payload 

        except Exception as e :
            print (f"[-] Parser Error during DGI reconstruction: {e}")
            return ""

    @staticmethod 
    def _decode_ber_tlv_length (hex_str :str )->Tuple [int ,int ]:
        cleaned =InteractiveWizards ._clean_hex_input (
        hex_str ,"BER length",allow_empty =False
        )
        first_byte =int (cleaned [:2 ],16 )
        if first_byte <=0x7F :
            return first_byte ,1

        num_bytes =first_byte &0x7F 
        if num_bytes ==0 :
            raise ValueError ("Indefinite BER lengths are not supported.")
        if num_bytes >2 :
            raise ValueError ("BER lengths longer than two bytes are not supported.")
        if len (cleaned )<2 +(num_bytes *2 ):
            raise ValueError ("Truncated BER length.")
        length_hex =cleaned [2 :2 +(num_bytes *2 )]
        if length_hex .startswith ("00"):
            raise ValueError ("BER length contains a redundant leading zero.")
        return int (length_hex ,16 ),1 +num_bytes 

    @staticmethod 
    def _encode_ber_tlv_length (length :int )->str :
        if length <0 :
            raise ValueError ("BER-TLV length cannot be negative.")
        is_short =False 
        if length <=0x7F :
            is_short =True 

        if is_short :
            return f"{length:02X}"

        is_medium =False 
        if length <=0xFF :
            is_medium =True 

        if is_medium :
            return f"81{length:02X}"

        is_long =False 
        if length <=0xFFFF :
            is_long =True 

        if is_long :
            return f"82{length:04X}"

        raise ValueError ("BER-TLV length exceeds two-byte definite length support.")

    @staticmethod 
    def _extract_tag_from_tlv (tlv :str )->str :
        cleaned =InteractiveWizards ._clean_hex_input (
        tlv ,"BER-TLV",allow_empty =False
        )
        first_byte =int (cleaned [:2 ],16 )
        if first_byte in (0x00 ,0xFF ):
            raise ValueError (f"Reserved BER tag octet {first_byte:02X}.")
        if (first_byte &0x1F )!=0x1F :
            return cleaned [:2 ]

        offset =2
        tag_bytes =1
        while True :
            if offset +2 >len (cleaned ):
                raise ValueError ("Truncated high-tag-number BER tag.")
            current =int (cleaned [offset :offset +2 ],16 )
            if tag_bytes ==1 and (current &0x7F )==0 :
                raise ValueError ("Invalid high-tag-number BER tag.")
            if tag_bytes ==1 and (current &0x80 )==0 and current <0x1F :
                raise ValueError ("Non-minimal high-tag-number BER tag.")
            offset +=2
            tag_bytes +=1
            if tag_bytes >4 :
                raise ValueError ("BER tags longer than four bytes are not supported.")
            if (current &0x80 )==0 :
                return cleaned [:offset ]

    @staticmethod 
    def _remove_tag_from_payload (payload :str ,target_tag :str )->str :
        payload =InteractiveWizards ._clean_hex_input (payload ,"TLV payload")
        target_tag =InteractiveWizards ._clean_hex_input (
        target_tag ,"target tag",allow_empty =False
        )
        idx =0 
        rebuilt_payload =""

        while idx <len (payload ):
            current_tag =InteractiveWizards ._extract_tag_from_tlv (payload [idx :])
            tag_len_chars =len (current_tag )

            remainder =payload [idx +tag_len_chars :]
            tlv_len ,len_bytes =InteractiveWizards ._decode_ber_tlv_length (remainder )

            total_tlv_chars =tag_len_chars +(len_bytes *2 )+(tlv_len *2 )
            if idx +total_tlv_chars >len (payload ):
                raise ValueError (
                f"TLV {current_tag} length exceeds the remaining payload."
                )
            full_current_tlv =payload [idx :idx +total_tlv_chars ]

            is_match =False 
            if current_tag ==target_tag :
                is_match =True 

            if is_match ==False :
                rebuilt_payload +=full_current_tlv 

            idx +=total_tlv_chars 

        if idx !=len (payload ):
            raise ValueError ("TLV payload contains trailing data.")
        return rebuilt_payload 

    @staticmethod 
    def _build_install_perso (target_aid :str )->str :
        target_aid =InteractiveWizards ._clean_hex_input (target_aid ,"target AID",allow_empty =False )
        data ="00"
        data +="00"
        data +=f"{len(target_aid)//2:02X}{target_aid}"
        data +="00"
        data +="00"
        data +="00"

        lc_hex =InteractiveWizards ._encode_apdu_lc (len (data )//2 )
        apdu =f"80E62000{lc_hex}{data}"
        return apdu 

    @staticmethod 
    def _build_store_data (payload :str )->str :
        payload =InteractiveWizards ._clean_hex_input (payload ,"STORE DATA payload")
        lc_hex =InteractiveWizards ._encode_apdu_lc (len (payload )//2 )
        apdu =f"80E28000{lc_hex}{payload}"
        return apdu 

    @staticmethod
    def _build_store_data_with_params (payload :str ,p1_hex :str ="80",p2_hex :str ="00")->str :
        p1_hex =InteractiveWizards ._normalize_hex_byte (p1_hex ,"80","STORE DATA P1")
        p2_hex =InteractiveWizards ._normalize_hex_byte (p2_hex ,"00","STORE DATA P2")
        payload =InteractiveWizards ._clean_hex_input (payload ,"STORE DATA payload")
        lc_hex =InteractiveWizards ._encode_apdu_lc (len (payload )//2 )
        apdu =f"80E2{p1_hex}{p2_hex}{lc_hex}{payload}"
        return apdu 

    @staticmethod 
    def _execute_sequence (tp_ctrl ,gp_ctrl ,install_apdu :str ,store_data_apdu :str )->None :
        auth_ok =InteractiveWizards ._ensure_auth_sd (gp_ctrl )
        if auth_ok ==False :
            return 
        if install_apdu is not None :
            print ("\n[*] Transmitting INSTALL [for personalization]...")
            res ,sw1 ,sw2 =tp_ctrl .transmit (install_apdu )

            is_install_success =False 
            if sw1 ==0x90 :
                if sw2 ==0x00 :
                    is_install_success =True 

            if is_install_success ==False :
                print (f"[-] INSTALL rejected: {sw1:02X}{sw2:02X}. Process aborted.")
                return 

            print ("[+] Session opened. Transmitting STORE DATA...")
        else :
            print ("\n[*] Transmitting STORE DATA...")
        res ,sw1 ,sw2 =tp_ctrl .transmit (store_data_apdu )

        is_store_success =False 
        if sw1 ==0x90 :
            if sw2 ==0x00 :
                is_store_success =True 

        if is_store_success :
            print ("[+] Registry parameters successfully updated in Data Store.")

        if is_store_success ==False :
            print (f"[-] STORE DATA rejected: {sw1:02X}{sw2:02X}.")

    @staticmethod 
    def _prompt_flat_tag (tag_hex_str :str ,tag_name :str )->str |None :
        wiz =InteractiveWizard (f"Build {tag_name}",Config .Colors )
        wiz .add_step ("add",f"Add {tag_name} (Tag {tag_hex_str})? [y/N]:",default =False ,is_bool =True )
        wiz .add_step (
        "val","Enter Value (Hex):",default ="",
        condition =lambda values :bool (values .get ("add")),
        is_mandatory =True,input_kind ="hex",
        )
        res =wiz .run ()
        if res is None :
            return None

        if not res .get ("add"):
            return ""

        val =str (res .get ("val"))
        val_bytes =bytes .fromhex (val )
        len_hex =InteractiveWizards ._encode_ber_tlv_length (len (val_bytes ))
        return tag_hex_str +len_hex +val .upper ()

    @staticmethod 
    def _build_tag_67 ()->str |None :
        wiz =InteractiveWizard ("Card Capability Info (Tag 67)",Config .Colors )
        wiz .add_step ("scp","Add Secure Channel Protocol (SCP) Info (Tag A0)? [y/N]:",default =False ,is_bool =True )

        def scp_cond (values ):
            return bool (values .get ("scp"))

        one_byte =InteractiveWizards ._hex_size_validator
        wiz .add_step (
        "scp_id","SCP Identifier (Tag 80) [Hex, e.g. 03]:",
        default ="SKIP",condition =scp_cond,input_kind ="hex",
        validator =one_byte ("SCP identifier",exact_bytes =1 ),
        )
        wiz .add_step (
        "scp_opt","SCP Options (Tag 81) [Hex, e.g. 70 or 7071]:",
        default ="SKIP",condition =scp_cond,input_kind ="hex",
        validator =one_byte ("SCP options",minimum_bytes =1,maximum_bytes =255 ),
        )
        wiz .add_step (
        "scp_mask","SCP Mask Options (Tag 91) [Hex]:",
        default ="SKIP",condition =scp_cond,input_kind ="hex",
        validator =one_byte ("SCP mask options",minimum_bytes =1,maximum_bytes =255 ),
        )

        def tlv_stream_validator (value )->str |None :
            if InteractiveWizards ._is_skip_value (value ):
                return None
            try :
                InteractiveWizards ._remove_tag_from_payload (str (value ),"00")
            except ValueError as error :
                return f"Capability TLV stream is invalid: {error}"
            return None

        wiz .add_step (
        "other","Add other capabilities to Tag 67 [BER-TLV Hex]:",
        default ="SKIP",input_kind ="hex",validator =tlv_stream_validator,
        )

        res =wiz .run ()
        if res is None :
            return None

        payload_67 =""

        if res .get ("scp"):
            payload_a0 =""

            for tag ,field_name in (("80","scp_id"),("81","scp_opt"),("91","scp_mask")):
                value =res .get (field_name )
                if InteractiveWizards ._is_skip_value (value ):
                    continue
                value_bytes =bytes .fromhex (str (value ))
                payload_a0 +=(
                tag
                +InteractiveWizards ._encode_ber_tlv_length (len (value_bytes ))
                +str (value ).upper ()
                )

            if payload_a0 :
                a0_len =InteractiveWizards ._encode_ber_tlv_length (len (payload_a0 )//2 )
                payload_67 +="A0"+a0_len +payload_a0 

        other_67 =res .get ("other")
        if not InteractiveWizards ._is_skip_value (other_67 ):
            payload_67 +=str (other_67 ).upper ()

        if payload_67 :
            len_67 =InteractiveWizards ._encode_ber_tlv_length (len (payload_67 )//2 )
            return "67"+len_67 +payload_67 

        return ""
