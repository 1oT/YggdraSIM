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

"""SCP03 interactive shell: cmd.Cmd subclass providing APDU and GP administration commands."""
import sys 
import os 
import configparser 
import atexit 
import io 
import re 
import datetime 
import shlex
import yaml 
from typing import Dict ,Optional ,Any ,Tuple 
from pathlib import Path

try :
    from yggdrasim_common.device_inventory import DeviceInventoryStore 
except ImportError :
    repo_root =Path (__file__ ).resolve ().parents [2 ]
    if str (repo_root )not in sys .path :
        sys .path .insert (0 ,str (repo_root ))
    from yggdrasim_common.device_inventory import DeviceInventoryStore 

from yggdrasim_common.progress import progress_session
from yggdrasim_common.quit_control import quit_all

try :
    import readline 
except ImportError :
    readline =None 

from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils ,TlvParser ,StatusWordTranslator 
from SCP03 .core .decoders import ContentDecoder ,AdvancedDecoders 
from SCP03 .transport .card import CardTransporter 
from SCP03 .logic .gp import GlobalPlatformManager 
from SCP03 .logic .fs import FileSystemController 
from SCP03 .logic .security import SecurityController 
from SCP03 .interface .guides import ShellGuides 
from SCP03 .interface .commands import CommandRegistry 
from SCP03 .interface .help_menu import HelpMenu 
from SCP03 .interface .wizards import InteractiveWizards 
from SCP03 .logic .profile_snapshot_diff import combined_profile_unified_diff 

class ShellDispatcher :
    def __init__ (self ):
        self .config =configparser .ConfigParser ()
        self .inventory =DeviceInventoryStore ()
        self .current_iccid =""
        self .current_eid =""
        self ._load_config_file ()
        self .aid_rule_roles ={}
        self .aid_registry =self ._load_aid_registry ()
        self .aid_lookup ={bytes .fromhex (v ):k for k ,v in self .aid_registry .items ()}

        self .debug_mode =False 

        # Buffer for startup stderr notices that would otherwise be lost
        # to the ``run()`` screen-clear redraw (currently: the
        # shipped-demo-keys banner surfaced by ``enforce_demo_key_policy``).
        self ._pending_startup_stderr =None 

        self .transport =None 
        try :
            self .transport =CardTransporter ()
            self ._patch_transport ()
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Critical: {e}{Config.Colors.ENDC}")

        self ._initialize_controllers ()
        self .prompt_str =""
        self ._prompt_context_label =""
        self ._update_prompt_state ()

        self .guide_topics =['GP','ETSI','GSMA','INSTALL','SECURITY','OTA','CONFIG','SAIP','SUCI','CLI']

        self .command_map =CommandRegistry .build (self )
        self .commands ={}
        for k ,v in self .command_map .items ():
            self .commands [k ]=v [0 ]

        self .hidden_commands ={'DEBUG','VERBOSE'}
        self .visible_commands =[]
        for cmd in self .commands .keys ():
            is_hidden =False 
            if cmd in self .hidden_commands :
                is_hidden =True 

            if is_hidden ==False :
                self .visible_commands .append (cmd )

        self ._setup_readline ()
        self ._prime_inventory_profile ()

    def _init_binder (self ):
        from SCP03 .interface .custom_binds import CommandBinder 
        binds_file =Config .BINDS_FILE 
        self .binder =CommandBinder (filepath =binds_file )

    def do_manage_binds (self ,arg_line :str =""):
        """Manage custom key-bindings via an interactive wizard."""
        from SCP03 .interface .custom_binds import manage_binds_wizard 

        has_binder =False 
        if hasattr (self ,'binder'):
            has_binder =True 

        if has_binder :
            manage_binds_wizard (Config .Colors ,self .binder )

        is_missing =False 
        if has_binder ==False :
            is_missing =True 

        if is_missing :
            print (f"{Config.Colors.FAIL}[!] Binder engine not initialized.{Config.Colors.ENDC}")

    def _patch_transport (self ):
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp ==False :
            return 

        has_orig =False 
        if hasattr (self .transport ,'_original_transmit'):
            has_orig =True 

        if has_orig ==False :
            self .transport ._original_transmit =self .transport .transmit 

        def _verbose_transmit (cmd ,silent =False ):
            actual_silent =silent 
            is_debug =False 
            if self .debug_mode :
                is_debug =True 

            if is_debug :
                actual_silent =False 

                display_cmd =""
                is_str =False 
                if isinstance (cmd ,str ):
                    is_str =True 
                if is_str :
                    display_cmd =cmd .upper ()

                is_bytes =False 
                if isinstance (cmd ,bytes ):
                    is_bytes =True 
                if is_bytes :
                    display_cmd =cmd .hex ().upper ()

                is_ba =False 
                if isinstance (cmd ,bytearray ):
                    is_ba =True 
                if is_ba :
                    display_cmd =cmd .hex ().upper ()

                is_list =False 
                if isinstance (cmd ,list ):
                    is_list =True 
                if is_list :
                    display_cmd =bytes (cmd ).hex ().upper ()

                is_other =False 
                if is_str ==False :
                    if is_bytes ==False :
                        if is_ba ==False :
                            if is_list ==False :
                                is_other =True 
                if is_other :
                    display_cmd =str (cmd )

                print (f"{Config.Colors.YELLOW}[-->] {display_cmd}{Config.Colors.ENDC}")

            data ,sw1 ,sw2 =self .transport ._original_transmit (cmd ,silent =actual_silent )

            is_silent =False 
            if actual_silent :
                is_silent =True 

            if is_silent ==False :
                sw_str =StatusWordTranslator .translate (sw1 ,sw2 )
                color =Config .Colors .GREEN 

                is_90 =False 
                if sw1 ==0x90 :
                    is_90 =True 
                is_61 =False 
                if sw1 ==0x61 :
                    is_61 =True 

                is_ok =False 
                if is_90 :
                    is_ok =True 
                if is_61 :
                    is_ok =True 

                is_fail =False 
                if is_ok ==False :
                    is_fail =True 

                if is_fail :
                    color =Config .Colors .FAIL 

                print (f"      {color}=> {sw_str}{Config.Colors.ENDC}")

            return data ,sw1 ,sw2 

        self .transport .transmit =_verbose_transmit 

    def _handle_decode (self ,arg_line :str ):
        is_empty =False 
        if len (arg_line )==0 :
            is_empty =True 

        if is_empty :
            print (f"{Config.Colors.FAIL}[-] Usage: DECODE <Hex>{Config.Colors.ENDC}")
            return 

        hex_data =arg_line .replace (" ","")

        try :
            data =bytes .fromhex (hex_data )
            parse_info =TlvParser .parse_detailed (data )
            parsed =parse_info ["parsed"]
            if parse_info ["complete"]==False or len (parsed )==0 :
                if self ._try_decode_simple_registry_stream (data ):
                    return 
                print (f"{Config.Colors.WARNING}[!] Input does not appear to be valid BER-TLV.{Config.Colors.ENDC}")
                if parse_info ["error"]:
                    print (f"{Config.Colors.WARNING}[!] Parser note: {parse_info['error']}{Config.Colors.ENDC}")
                consumed =parse_info .get ("consumed",0 )
                print (f"{Config.Colors.WARNING}[!] Consumed {consumed} of {len(data)} bytes before stopping.{Config.Colors.ENDC}")
                return 
            self .gp_ctrl .print_tlv_data (parsed )
        except ValueError :
            print (f"{Config.Colors.FAIL}[!] Invalid Hex string provided.{Config.Colors.ENDC}")
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Decode Error: {e}{Config.Colors.ENDC}")

    def _try_decode_simple_registry_stream (self ,data :bytes )->bool :
        entries =[]
        i =0 
        while i <len (data ):
            if i +3 >len (data ):
                return False 
            aid_len =data [i ]
            if aid_len <5 or aid_len >16 :
                return False 
            i +=1 
            if i +aid_len +2 >len (data ):
                return False 
            aid =data [i :i +aid_len ]
            if len (aid )==0 or aid [0 ]!=0xA0 :
                return False 
            i +=aid_len 
            state_byte =data [i ]
            extra_byte =data [i +1 ]
            i +=2 
            entries .append ((aid .hex ().upper (),state_byte ,extra_byte ))

        if len (entries )==0 :
            return False 

        print (f"{Config.Colors.CYAN}[i] Detected simple LV registry stream (not BER-TLV).{Config.Colors.ENDC}")
        print (f"{Config.Colors.HEADER}--- Decoded Registry Stream ---{Config.Colors.ENDC}")
        print (f"{'AID':<34} | {'State':<12} | Extra")
        print ("-"*65 )
        for aid_hex ,state_byte ,extra_byte in entries :
            state_str =self .gp_ctrl ._state_to_string (state_byte )
            print (f"{aid_hex:<34} | {state_str:<12} | {extra_byte:02X}")
        return True 

    def _handle_dump_fs (self ,arg_line :str =""):
        target ="ALL"
        has_arg =False 
        if len (arg_line )>0 :
            has_arg =True 

        if has_arg :
            target =arg_line .strip ()

        self .fs_ctrl .dump_fs (target )

    def _toggle_debug (self ):
        is_debug =False 
        if self .debug_mode :
            is_debug =True 

        if is_debug :
            self .debug_mode =False 

        if is_debug ==False :
            self .debug_mode =True 

        state ="ON"
        is_off =False 
        if self .debug_mode ==False :
            is_off =True 

        if is_off :
            state ="OFF"


        has_tp =False 
        if self .transport :
            has_tp =True 
        if has_tp :
            try :
                self .transport .debug =self .debug_mode 
            except Exception :
                pass 

        print (f"{Config.Colors.WARNING}[*] VERBOSE / DEBUG Mode is now {state}.{Config.Colors.ENDC}")

    def _setup_readline (self ):
        is_none =False 
        if readline is None :
            is_none =True 

        if is_none :
            return 

        self .hist_file =os .path .join (os .path .expanduser ("~"),".yggdrasim_history")
        try :
            has_file =False 
            if os .path .exists (self .hist_file ):
                has_file =True 

            if has_file :
                readline .read_history_file (self .hist_file )
            readline .set_history_length (1000 )
        except Exception :
            pass 

        atexit .register (self ._save_history )
        readline .set_completer (self ._completer )
        readline .set_completer_delims (' \t\n')

        has_libedit =False 
        if 'libedit'in readline .__doc__ :
            has_libedit =True 

        if has_libedit :
            readline .parse_and_bind ("bind ^I rl_complete")

        is_gnu =False 
        if has_libedit ==False :
            is_gnu =True 

        if is_gnu :
            readline .parse_and_bind ("tab: complete")

        try :
            readline .parse_and_bind ("set show-all-if-ambiguous on")
        except Exception :
            pass 

    def _save_history (self ):
        has_readline =False 
        if readline :
            has_readline =True 

        if has_readline :
            try :
                readline .write_history_file (self .hist_file )
            except Exception :
                pass 

    def _completer (self ,text ,state ):
        line_buffer =readline .get_line_buffer ().lstrip ()

        has_space =False 
        if ' 'in line_buffer :
            has_space =True 

        is_no_space =False 
        if has_space ==False :
            is_no_space =True 

        if is_no_space :
            options =[]
            for cmd in self .visible_commands :
                is_match =False 
                if cmd .startswith (text .upper ()):
                    is_match =True 
                if is_match :
                    options .append (cmd )

            is_valid_state =False 
            if state <len (options ):
                is_valid_state =True 

            if is_valid_state :
                is_single =False 
                if len (options )==1 :
                    is_single =True 

                if is_single :
                    return options [0 ]+" "

                is_multi =False 
                if is_single ==False :
                    is_multi =True 

                if is_multi :
                    return options [state ]

        if has_space :
            first_space_idx =line_buffer .index (' ')
            cmd =line_buffer [:first_space_idx ].upper ()
            arg_typed =text .upper ()

            is_select =False 
            if cmd =='SELECT':
                is_select =True 
            if is_select :
                options =[]
                try :
                    for path_name in self .fs_ctrl .fid_map .keys ():
                        if path_name .upper ().startswith (arg_typed ):
                            options .append (path_name )
                    for aid_name in self .aid_registry .keys ():
                        if aid_name .upper ().startswith (arg_typed ):
                            if aid_name not in options :
                                options .append (aid_name )
                    options .sort (key =lambda x :x .upper ())
                except Exception :
                    pass 
                if state <len (options ):
                    return options [state ]+" "
                return None 

            is_guide =False 
            if cmd =='GUIDE':
                is_guide =True 

            if is_guide :
                options =[]
                for topic in self .guide_topics :
                    is_match =False 
                    if topic .startswith (arg_typed ):
                        is_match =True 
                    if is_match :
                        options .append (topic )

                is_valid_state =False 
                if state <len (options ):
                    is_valid_state =True 

                if is_valid_state :
                    is_single =False 
                    if len (options )==1 :
                        is_single =True 

                    if is_single :
                        return options [0 ]+" "

                    is_multi =False 
                    if is_single ==False :
                        is_multi =True 

                    if is_multi :
                        return options [state ]

            is_update =False 
            if cmd =='UPDATE':
                is_update =True 

            if is_update :
                options =[]
                for sub in ['BINARY','RECORD']:
                    is_match =False 
                    if sub .startswith (arg_typed ):
                        is_match =True 
                    if is_match :
                        options .append (sub )

                is_valid_state =False 
                if state <len (options ):
                    is_valid_state =True 

                if is_valid_state :
                    is_single =False 
                    if len (options )==1 :
                        is_single =True 

                    if is_single :
                        return options [0 ]+" "

                    is_multi =False 
                    if is_single ==False :
                        is_multi =True 

                    if is_multi :
                        return options [state ]

        return None 

    def _handle_guide (self ,arg_line :str =""):
        topic =arg_line .strip ().upper ()

        is_empty =False 
        if len (topic )==0 :
            is_empty =True 

        if is_empty :
            ShellGuides .print_guide ("WIZARD")
            return 

        is_wiz =False 
        if topic =="WIZARD":
            is_wiz =True 

        if is_wiz :
            ShellGuides .print_guide ("WIZARD")
            return 

        is_known =False 
        if topic in self .guide_topics :
            is_known =True 

        if is_known :
            ShellGuides .print_guide (topic )

        is_unknown =False 
        if is_known ==False :
            is_unknown =True 

        if is_unknown :
            print (f"{Config.Colors.FAIL}[!] Unknown topic. Available: {', '.join(self.guide_topics)}{Config.Colors.ENDC}")

    def _handle_install_file (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<1 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: INSTALL-INSTALL <cap/ijc> [Privileges] [Params] [AppletAID] [ModuleAID]{Config.Colors.ENDC}")
            return 

        f =parts [0 ]

        p ="00"
        has_p =False 
        if len (parts )>1 :
            has_p =True 
        if has_p :
            p =parts [1 ]

        par ="C900"
        has_par =False 
        if len (parts )>2 :
            has_par =True 
        if has_par :
            par =parts [2 ]

        app_aid =None 
        has_app =False 
        if len (parts )>3 :
            has_app =True 
        if has_app :
            app_aid =parts [3 ]

        mod_aid =None 
        has_mod =False 
        if len (parts )>4 :
            has_mod =True 
        if has_mod :
            mod_aid =parts [4 ]

        self .gp_ctrl .install_cap_file (f ,privileges =p ,install_params =par ,target_app_aid =app_aid ,target_module_aid =mod_aid ,instantiate =True )

    def _handle_install_wizard (self ,arg :str ="")->None :
        target_aid ="A000000151000000"

        has_gp_ctrl =False 
        if hasattr (self ,'gp_ctrl'):
            has_gp_ctrl =True 

        if has_gp_ctrl :
            current_target =self .gp_ctrl .target_aid
            has_current_target =False 
            if current_target is not None :
                if len (current_target )>0 :
                    has_current_target =True 
            if has_current_target :
                target_aid =current_target .hex ().upper ()

        has_config =False 
        if hasattr (self ,'config'):
            has_config =True 

        if has_config :
            has_keys =False 
            if 'KEYS'in self .config :
                has_keys =True 

            if has_keys :
                has_aid_key =False 
                if 'aid'in self .config ['KEYS']:
                    has_aid_key =True 

                if has_aid_key :
                    target_aid =self .config ['KEYS']['aid']

        transport_ctrl =None 
        if hasattr (self ,'transport'):
            transport_ctrl =self .transport 

        gp_ctrl =None 
        if hasattr (self ,'gp_ctrl'):
            gp_ctrl =self .gp_ctrl 

        if transport_ctrl is None and gp_ctrl is None :
            print ("[-] Error: No active transport controller found in shell.")
            return 

        InteractiveWizards .run_wizard_menu (transport_ctrl ,target_aid ,gp_ctrl )

    def _handle_install_app (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<2 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: INSTALL-APP <PkgAID> <AppAID> [ModAID] [Priv] [Params]{Config.Colors.ENDC}")
            return 

        pkg =parts [0 ]
        app =parts [1 ]

        mod =app 
        has_mod =False 
        if len (parts )>2 :
            has_mod =True 
        if has_mod :
            mod =parts [2 ]

        priv ="00"
        has_priv =False 
        if len (parts )>3 :
            has_priv =True 
        if has_priv :
            priv =parts [3 ]

        param ="C900"
        has_param =False 
        if len (parts )>4 :
            has_param =True 
        if has_param :
            param =parts [4 ]

        self .gp_ctrl .install_app (pkg ,app ,mod ,priv ,param ,make_selectable =True )

    def _handle_install_registry (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<1 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: INSTALL-REGISTRY <AID> [Priv] [Params]{Config.Colors.ENDC}")
            return 

        aid =parts [0 ]

        priv ="00"
        has_priv =False 
        if len (parts )>1 :
            has_priv =True 
        if has_priv :
            priv =parts [1 ]

        param =""
        has_param =False 
        if len (parts )>2 :
            has_param =True 
        if has_param :
            param =parts [2 ]

        self .gp_ctrl .install_registry_update (aid ,priv ,param )

    def _handle_store_data (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<1 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: STORE-DATA <HexData> [P1] [P2]{Config.Colors.ENDC}")
            return 

        data =parts [0 ]

        p1 =None 
        has_p1 =False 
        if len (parts )>1 :
            has_p1 =True 
        if has_p1 :
            p1 =int (parts [1 ],16 )

        p2 =None 
        has_p2 =False 
        if len (parts )>2 :
            has_p2 =True 
        if has_p2 :
            p2 =int (parts [2 ],16 )

        self .gp_ctrl .store_data (data ,p1 ,p2 )

    def _clear_prompt_context (self )->None :
        self ._prompt_context_label =""

    def _set_prompt_context (self ,label :str )->None :
        self ._prompt_context_label =str (label or "").strip ()

    def _clear_prompt_context_tracking (self )->None :
        self ._clear_prompt_context ()
        fs_ctrl =getattr (self ,'fs_ctrl',None )
        if fs_ctrl is None :
            return
        fs_ctrl .current_path_hint =""

    def _context_label_from_aid (self ,aid_value :Any )->str :
        cleaned =""
        if isinstance (aid_value ,(bytes ,bytearray ,memoryview )):
            cleaned =bytes (aid_value ).hex ().upper ()
        else :
            cleaned =str (aid_value or "").strip ().replace (" ","").upper ()
        if len (cleaned )==0 :
            return ""

        alias_name =None
        try :
            alias_name =self .aid_lookup .get (bytes .fromhex (cleaned ))
        except Exception :
            alias_name =None
        if alias_name :
            return str (alias_name )

        if cleaned =="A0000005591010FFFFFFFF8900000100":
            return "ISD-R"
        if cleaned =="A0000005591010FFFFFFFF8900000200":
            return "ECASD"
        return cleaned

    def _context_label_from_fid (self ,fid_value :str )->str :
        cleaned =str (fid_value or "").strip ().replace (" ","").upper ()
        if len (cleaned )==0 :
            return ""
        if cleaned =="3F00":
            return "MF"

        matches =[]
        fs_ctrl =getattr (self ,'fs_ctrl',None )
        fid_map =getattr (fs_ctrl ,'fid_map',{})
        for name ,values in fid_map .items ():
            normalized_values =values
            if isinstance (values ,list )==False :
                normalized_values =[values ]
            for candidate in normalized_values :
                if str (candidate or "").strip ().upper ()==cleaned :
                    matches .append (str (name ))
                    break

        if len (matches )==0 :
            return cleaned

        if "MF"in matches :
            return "MF"
        for prefix in ["ADF_","EF_"]:
            for name in matches :
                if name .startswith (prefix ):
                    return name
        return matches [0 ]

    def _context_label_from_selection (self ,selected_value :str )->str :
        cleaned =str (selected_value or "").strip ().upper ()
        if len (cleaned )==0 :
            return ""
        if "/"in cleaned :
            return cleaned
        if len (cleaned )>4 :
            return self ._context_label_from_aid (cleaned )
        return self ._context_label_from_fid (cleaned )

    def _current_prompt_context (self )->str :
        label =str (getattr (self ,'_prompt_context_label',"")or "").strip ()
        if len (label )>0 :
            return label
        fs_ctrl =getattr (self ,'fs_ctrl',None )
        path_hint =str (getattr (fs_ctrl ,'current_path_hint',"")or "").strip ()
        if len (path_hint )>0 :
            return self ._context_label_from_selection (path_hint )
        return ""

    def _set_prompt_context_from_gp_target (self ,target_aid_hex :Optional [str ]=None )->None :
        target =target_aid_hex
        has_target =False
        if target is not None :
            if len (str (target ).strip ())>0 :
                has_target =True
        if has_target :
            self ._set_prompt_context (self ._context_label_from_aid (target ))
            return

        gp_ctrl =getattr (self ,'gp_ctrl',None )
        aid_bytes =getattr (gp_ctrl ,'target_aid',b"")
        self ._set_prompt_context (self ._context_label_from_aid (aid_bytes ))

    def _set_prompt_context_from_fs_state (self ,fallback :str ="")->None :
        fs_ctrl =getattr (self ,'fs_ctrl',None )
        path_hint =str (getattr (fs_ctrl ,'current_path_hint',"")or "").strip ()
        if len (path_hint )>0 :
            self ._set_prompt_context (self ._context_label_from_selection (path_hint ))
            return

        fallback_text =str (fallback or "").strip ()
        if len (fallback_text )>0 :
            self ._set_prompt_context (self ._context_label_from_selection (fallback_text ))
            return

        current_fid =str (getattr (fs_ctrl ,'current_fid',"")or "").strip ()
        if len (current_fid )>0 :
            self ._set_prompt_context (self ._context_label_from_selection (current_fid ))
            return

        self ._clear_prompt_context ()

    def _update_prompt_state (self ):
        is_auth =False 
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp :
            has_sess =False 
            if self .transport .session :
                has_sess =True 

            if has_sess :
                is_auth_flag =False 
                if self .transport .session .is_authenticated :
                    is_auth_flag =True 

                if is_auth_flag :
                    is_auth =True 

        is_not_auth =False 
        if is_auth ==False :
            is_not_auth =True 

        context_label =self ._current_prompt_context ()

        if is_not_auth :
            prompt_label ="APDU"
            if len (context_label )>0 :
                prompt_label =f"APDU -> {context_label}"
            self .prompt_str =f"\n{Config.Colors.CYAN}[{prompt_label}] > {Config.Colors.ENDC}"

        if is_auth :
            current_aid =self .gp_ctrl .target_aid 
            name =self .aid_lookup .get (current_aid )
            protocol_name ="SCP"
            if self .transport .session :
                protocol_name =getattr (self .transport .session ,'protocol_name',"SCP")

            display =current_aid .hex ().upper ()

            has_name =False 
            if name :
                has_name =True 

            if has_name :
                display =name 

            prompt_label =f"{protocol_name}:{display}"
            if len (context_label )>0 :
                context_upper =context_label .upper ()
                if context_upper !=display .upper ()and context_upper !=prompt_label .upper ():
                    prompt_label =f"{prompt_label} -> {context_label}"

            self .prompt_str =f"\n{Config.Colors.GREEN}[{prompt_label}] > {Config.Colors.ENDC}"

    def _handle_auth (self ):
        self ._handle_auth_scp03 ()

    def _handle_auth_scp03 (self ):
        is_success =False 
        if self .gp_ctrl .authenticate ("SCP03"):
            is_success =True 

        if is_success :
            self ._set_prompt_context_from_gp_target ()
            self ._update_prompt_state ()

    def _handle_auth_scp02 (self ):
        is_success =False 
        if self .gp_ctrl .authenticate ("SCP02"):
            is_success =True 

        if is_success :
            self ._set_prompt_context_from_gp_target ()
            self ._update_prompt_state ()

    def _handle_logout (self ):
        self .logout ()
        self ._update_prompt_state ()

    def _resolve_mixed_aid (self ,arg :str )->str :
        is_empty =False 
        if len (arg )==0 :
            is_empty =True 

        if is_empty :
            return ""

        clean =arg .strip ().upper ()

        is_known =False 
        if clean in self .aid_registry :
            is_known =True 

        if is_known :
            print (f"{Config.Colors.CYAN}[*] Resolved '{clean}' -> {self.aid_registry[clean]}{Config.Colors.ENDC}")
            return self .aid_registry [clean ]

        return arg 

    @staticmethod
    def _is_hex_aid_value (value :str )->bool :
        cleaned =str (value ).strip ().replace (" ","").upper ()
        if len (cleaned )==0 :
            return False 
        if len (cleaned )%2 !=0 :
            return False 
        for char in cleaned :
            if char not in "0123456789ABCDEF":
                return False 
        return True 

    @staticmethod
    def _parse_aid_registry_line (raw_line :str )->Tuple [str ,str ,str ]:
        raw_text =str (raw_line ).strip ()
        if len (raw_text )==0 :
            return "","",""
        if raw_text .startswith ("#"):
            return "","",""

        body =raw_text 
        comment ="" 
        if "#"in raw_text :
            body ,comment =raw_text .split ("#",1 )

        part_values =[]
        for part in body .split (":"):
            cleaned_part =part .strip ().upper ()
            if len (cleaned_part )>0 :
                part_values .append (cleaned_part )

        if len (part_values )<2 :
            return "","",""

        name =part_values [0 ]
        aid_hex =""
        role_name =""

        if len (part_values )>=3 :
            second_value =part_values [1 ]
            third_value =part_values [2 ]
            if second_value in ("ARAM","ARAC")and ShellDispatcher ._is_hex_aid_value (third_value ):
                role_name =second_value 
                aid_hex =third_value 
            elif third_value in ("ARAM","ARAC")and ShellDispatcher ._is_hex_aid_value (second_value ):
                aid_hex =second_value 
                role_name =third_value 
            elif ShellDispatcher ._is_hex_aid_value (second_value ):
                aid_hex =second_value 

        if len (aid_hex )==0 :
            second_value =part_values [1 ]
            if ShellDispatcher ._is_hex_aid_value (second_value ):
                aid_hex =second_value 

        if len (aid_hex )==0 :
            return "","",""

        if len (role_name )==0 :
            if re .search (r"\bARAM\b",comment .upper ()):
                role_name ="ARAM"
            elif re .search (r"\bARAC\b",comment .upper ()):
                role_name ="ARAC"

        if len (role_name )==0 :
            if name in ("ARAM","ARAC"):
                role_name =name 

        return name ,aid_hex ,role_name 

    def _resolve_aid_rule_role (self ,alias_name :str )->str :
        clean_name =str (alias_name ).strip ().upper ()
        if len (clean_name )==0 :
            return ""
        if clean_name in self .aid_rule_roles :
            return str (self .aid_rule_roles [clean_name ]).strip ().upper ()
        if clean_name in ("ARAM","ARAC"):
            return clean_name 
        return ""

    def _resolve_selected_ara_target (self ,arg_line :str )->Tuple [str ,str ,str ]:
        current_aid =""
        current_fcp =getattr (self .fs_ctrl ,"current_fcp",{})
        if isinstance (current_fcp ,dict ):
            current_aid =str (current_fcp .get ("aid","")).strip ().upper ()

        for alias_name ,role_name in self .aid_rule_roles .items ():
            aid_hex =str (self .aid_registry .get (alias_name ,"")).strip ().upper ()
            if len (aid_hex )==0 :
                continue 
            if aid_hex ==current_aid :
                return alias_name ,aid_hex ,role_name 

        clean_arg =str (arg_line ).strip ().upper ()
        if clean_arg in self .aid_registry :
            aid_hex =str (self .aid_registry [clean_arg ]).strip ().upper ()
            role_name =self ._resolve_aid_rule_role (clean_arg )
            return clean_arg ,aid_hex ,role_name 

        return "","",""

    def _read_ara_rules_for_selection (self ,alias_name :str ,aid_hex :str ,role_name :str )->None :
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp ==False :
            return 

        role_label ="ARA-M"
        if role_name =="ARAC":
            role_label ="ARA-C"

        print (f"{Config.Colors.HEADER}--- {role_label} Rulesets ---{Config.Colors.ENDC}")
        print (
            f"{Config.Colors.CYAN}[*] READ RULES after selecting "
            f"{alias_name} ({aid_hex}).{Config.Colors.ENDC}"
        )

        data ,sw1 ,sw2 =self .transport .transmit ("80CAFF4000",silent =True )
        if sw1 !=0x90 :
            sw_text =StatusWordTranslator .translate (sw1 ,sw2 )
            print (
                f"{Config.Colors.FAIL}[-] READ RULES failed: "
                f"{sw1:02X}{sw2:02X} {sw_text}{Config.Colors.ENDC}"
            )
            return 

        decoded_rules =AdvancedDecoders .decode_ara_rulesets (data .hex ().upper ())
        if len (decoded_rules )==0 :
            print (f"{Config.Colors.WARNING}[!] No ARA rulesets returned.{Config.Colors.ENDC}")
            return 

        for line in decoded_rules :
            print (f"  {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")

    def _maybe_read_ara_rules_for_current_selection (self ,arg_line :str )->None :
        alias_name ,aid_hex ,role_name =self ._resolve_selected_ara_target (arg_line )
        if len (role_name )==0 :
            return 
        self ._read_ara_rules_for_selection (alias_name ,aid_hex ,role_name )

    def _handle_select (self ,arg_line :str )->None :
        did_select =self .fs_ctrl .select (arg_line )
        if did_select ==False :
            return 
        self ._set_prompt_context_from_fs_state (arg_line )
        self ._maybe_read_ara_rules_for_current_selection (arg_line )

    def _handle_scan_tree (self )->None :
        self ._clear_prompt_context_tracking ()
        self .fs_ctrl .scan_tree ()
        self .fs_ctrl .current_path_hint ="MF"
        self ._set_prompt_context_from_fs_state ("MF")

    def _handle_read_binary (self ,arg_line :str ="")->None :
        normalized_arg =str (arg_line or "").strip ()
        if len (normalized_arg )>0 :
            self .fs_ctrl .read_binary (normalized_arg )
            self ._set_prompt_context_from_fs_state (normalized_arg )
            return
        self .fs_ctrl .read_binary ()
        self ._set_prompt_context_from_fs_state ()

    def _handle_read_record (self ,arg_line :str )->None :
        normalized_arg =str (arg_line or "").strip ()
        self .fs_ctrl .read_record (normalized_arg )
        path_hint =""
        parts =normalized_arg .split ()
        if len (parts )>1 :
            path_hint =parts [1 ]
        self ._set_prompt_context_from_fs_state (path_hint )

    def _handle_install_selectable (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<1 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: INSTALL-SELECTABLE <AID> [Privileges] [Params] [Token]{Config.Colors.ENDC}")
            return 

        aid =parts [0 ]

        privs ="00"
        has_privs =False 
        if len (parts )>1 :
            has_privs =True 

        if has_privs :
            privs =parts [1 ]

        params =""
        has_params =False 
        if len (parts )>2 :
            has_params =True 
        if has_params :
            params =parts [2 ]

        token =""
        has_token =False 
        if len (parts )>3 :
            has_token =True 
        if has_token :
            token =parts [3 ]

        self .gp_ctrl .install_make_selectable (aid ,privs ,params ,token )

    def _handle_install_extradition (self ,arg_line ):
        parts =arg_line .split ()
        is_short =False 
        if len (parts )<2 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}Usage: INSTALL-EXTRADITION <App_AID> <SD_AID> [Token]{Config.Colors.ENDC}")
            return 

        token =""
        has_token =False 
        if len (parts )>2 :
            has_token =True 
        if has_token :
            token =parts [2 ]

        self .gp_ctrl .install_extradition (parts [0 ],parts [1 ],token )

    def _handle_keys (self ,arg :Optional [str ]=None ):
        target =None 
        has_arg =False 
        if arg :
            has_arg =True 

        if has_arg :
            target =self ._resolve_mixed_aid (arg )

        self ._set_prompt_context_from_gp_target (target )
        self .gp_ctrl .get_keys_info (target_aid_hex =target )

    def _handle_registry (self ,kind :str )->None :
        self ._set_prompt_context_from_gp_target ()
        self .gp_ctrl .list_registry (kind )

    def _handle_list_profiles (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .list_profiles ()

    def _handle_profile_scan (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .run_sgp22_scan ()

    def _handle_get_euicc_configured_data (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .get_euicc_configured_data ()

    def _handle_get_euicc_certs (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .get_euicc_certs ()

    def _handle_get_eid (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .get_eid ()

    def _handle_get_sgp32_all_data (self )->None :
        self ._set_prompt_context ("ISD-R")
        self .gp_ctrl .sgp22 .get_sgp32_all_data ()

    def _handle_enable_profile (self ,target :str )->bool :
        resolved_target =self ._resolve_mixed_aid (target )
        self ._set_prompt_context ("ISD-R")
        return bool (self .gp_ctrl .sgp22 .enable_profile (resolved_target ))

    def _handle_disable_profile (self ,target :str )->bool :
        resolved_target =self ._resolve_mixed_aid (target )
        self ._set_prompt_context ("ISD-R")
        return bool (self .gp_ctrl .sgp22 .disable_profile (resolved_target ))

    def _handle_delete_profile (self ,target :str )->bool :
        resolved_target =self ._resolve_mixed_aid (target )
        self ._set_prompt_context ("ISD-R")
        return bool (self .gp_ctrl .sgp22 .delete_profile (resolved_target ))

    def _build_euicc_export_report (self ,standard :str ="SGP.32")->Dict :
        report =self .gp_ctrl .sgp22 .get_euicc_report_extended (standard =standard )
        cplc_data ,sw1 ,sw2 =self .gp_ctrl .get_cplc_data ()
        has_cplc =False 
        if cplc_data and sw1 ==0x90 :
            has_cplc =True 
        if has_cplc :
            report ["cplc_hex"]=cplc_data .hex ().upper ()
        report ["generated"]=datetime .datetime .now ().isoformat ()
        return report 

    def _build_mnosd_export_report (self ,adm_hex :str ="",authenticate_sd :bool =True )->Dict :
        report :Dict [str ,Any ]={}
        adm_clean =adm_hex .strip ().replace (" ","").upper ()
        has_adm =False 
        if len (adm_clean )>0 :
            if adm_clean !="SKIP":
                has_adm =True 
        report ["adm_attempted"]=has_adm 
        if has_adm :
            print (f"{Config.Colors.CYAN}[*] Verifying ADM before MNO-SD sequence...{Config.Colors.ENDC}")
            self .gp_ctrl .verify_adm (adm_clean )

        report ["auth_attempted"]=authenticate_sd 
        auth_ok =False 
        if authenticate_sd :
            print (f"{Config.Colors.CYAN}[*] Authenticating SD before MNO-SD sequence...{Config.Colors.ENDC}")
            auth_ok =self .gp_ctrl .authenticate ()
            report ["auth_ok"]=auth_ok 
        else :
            report ["auth_ok"]=False 

        def _print_sw (label :str ,status :str )->None :
            is_ok =False 
            if status =="9000":
                is_ok =True 
            if is_ok ==False :
                print (f"{Config.Colors.WARNING}[!] {label} SW={status}{Config.Colors.ENDC}")

        report ["keys"]=self .gp_ctrl .get_keys_info_data ()
        _print_sw ("MNO-SD KEYS",str (report ["keys"].get ("status","")))

        report ["apps"]=self .gp_ctrl .get_registry_data ("APPS")
        _print_sw ("MNO-SD APPS",str (report ["apps"].get ("status","")))

        report ["pkgs"]=self .gp_ctrl .get_registry_data ("PACKAGES")
        _print_sw ("MNO-SD PKGS",str (report ["pkgs"].get ("status","")))

        report ["sd"]=self .gp_ctrl .get_registry_data ("SD")
        _print_sw ("MNO-SD SD",str (report ["sd"].get ("status","")))

        def _tlv_to_plain (node ):
            if isinstance (node ,dict ):
                out ={}
                for key ,value in node .items ():
                    k_text =str (key )
                    if isinstance (key ,int ):
                        if key <=0xFF :
                            k_text =f"{key:02X}"
                        else :
                            k_text =f"{key:04X}"
                    out [k_text ]=_tlv_to_plain (value )
                return out 
            if isinstance (node ,list ):
                out_list =[]
                for item in node :
                    out_list .append (_tlv_to_plain (item ))
                return out_list 
            if isinstance (node ,bytes ):
                return node .hex ().upper ()
            return node 

        covered_get_data_tags =[]
        covered_get_data_tags .append ("00E0")
        get_data_candidates =[
        ("sd_management_data",0x00 ,0x66 ),
        ("card_capabilities",0x00 ,0x67 ),
        ("cplc",0x9F ,0x7F ),
        ("issuer_identification_number",0x00 ,0x42 ),
        ("card_image_number",0x00 ,0x45 ),
        ("eid",0x00 ,0x5A ),
        ("isd_aid",0x00 ,0x4F ),
        ]
        get_data_out :Dict [str ,Any ]={}
        executed_tags =[]
        skipped_tags =[]
        for name ,p1 ,p2 in get_data_candidates :
            tag_text =f"{p1:02X}{p2:02X}"
            is_covered =False
            if tag_text in covered_get_data_tags :
                is_covered =True
            if is_covered :
                skipped_tags .append (tag_text )
                continue
            data ,sw1 ,sw2 =self .gp_ctrl .get_data_raw (p1 ,p2 )
            entry :Dict [str ,Any ]={
            "tag":tag_text ,
            "status":f"{sw1:02X}{sw2:02X}",
            "raw_hex":data .hex ().upper ()
            }
            if sw1 ==0x90 and len (data )>0 :
                try :
                    parsed =TlvParser .parse (data )
                    entry ["decoded"]=_tlv_to_plain (parsed )
                except Exception :
                    pass 
            get_data_out [name ]=entry 
            executed_tags .append (tag_text )
            _print_sw (f"MNO-SD GET-DATA {tag_text}",entry ["status"])
        report ["get_data"]={
        "policy":"Execute only additional GET DATA P1/P2 combinations not covered by KEYS/APPS/PKGS/SD commands.",
        "covered_by_commands":covered_get_data_tags ,
        "skipped_tags":skipped_tags ,
        "executed_tags":executed_tags ,
        "entries":get_data_out 
        }
        report ["generated"]=datetime .datetime .now ().isoformat ()
        return report 

    def _build_combined_profile_dict (
        self ,
        standard :str ,
        adm_hex :str ="" ,
        authenticate_sd :bool =False ,
    )->Dict [str ,Any ]:
        """
        Same structure as REPORT wizard combined export: FS YAML + eUICC report + MNO-SD report.
        Performs card resets between phases (matches wizard behaviour).
        """
        import tempfile 

        temp_name =""
        with tempfile .NamedTemporaryFile (prefix ="fs_report_",suffix =".yaml",delete =False )as temp_file :
            temp_name =temp_file .name 

        try :
            # Three deterministic collection phases — FS YAML,
            # eUICC report, MNO-SD report — each preceded by a card
            # reset. Sticky footer surfaces which collection is
            # active for operators watching a long combined sweep.
            with progress_session ("SCP03 combined report",total =3 )as bar :
                bar .advance ("file-system collection")
                print (f"{Config.Colors.CYAN}[*] Resetting card before File System collection...{Config.Colors.ENDC}")
                self ._handle_reset ()
                adm_clean =adm_hex .strip ().upper ()
                has_adm =False 
                if len (adm_clean )>0 :
                    if adm_clean !="SKIP":
                        has_adm =True 
                if has_adm :
                    self .gp_ctrl .verify_adm (adm_hex )

                self .fs_ctrl .dump_fs_to_yaml (temp_name )
                fs_data :Dict [str ,Any ]={}
                with open (temp_name ,"r",encoding ="utf-8")as fsf :
                    loaded =yaml .safe_load (fsf )
                    if isinstance (loaded ,dict ):
                        fs_data =loaded 

                bar .advance ("eUICC collection")
                print (f"{Config.Colors.CYAN}[*] Resetting card before eUICC collection...{Config.Colors.ENDC}")
                self ._handle_reset ()
                euicc_report =self ._build_euicc_export_report (standard =standard )

                bar .advance ("MNO-SD collection")
                print (f"{Config.Colors.CYAN}[*] Resetting card before MNO-SD collection...{Config.Colors.ENDC}")
                self ._handle_reset ()
                mnosd_report =self ._build_mnosd_export_report (
                    adm_hex =adm_hex ,
                    authenticate_sd =authenticate_sd ,
                )

            return {
                "generated":euicc_report .get ("generated"),
                "standard":standard ,
                "file_system_report":fs_data ,
                "euicc_report":euicc_report ,
                "mnosd_report":mnosd_report ,
            }
        finally :
            if len (temp_name )>0 :
                if os .path .exists (temp_name ):
                    os .remove (temp_name )

    def _get_gold_profile_settings (self )->Dict [str ,Any ]:
        out :Dict [str ,Any ]={
        "path":"",
        "standard":"SGP.32",
        "authenticate_sd":False ,
        }
        has_gp =False 
        if 'GOLD_PROFILE'in self .config :
            has_gp =True 
        if has_gp ==False :
            return out 

        sec =self .config ['GOLD_PROFILE']
        path_raw =str (sec .get ('path','')or '').strip ()
        if path_raw !="":
            out ['path']=os .path .expanduser (path_raw )

        std_raw =str (sec .get ('standard','SGP.32')or 'SGP.32').strip ().upper ()
        if len (std_raw )>0 :
            out ['standard']=std_raw 

        auth_raw =str (sec .get ('authenticate_sd','false')or 'false').strip ().lower ()
        out ['authenticate_sd']=auth_raw in ('1','true','yes','on')
        return out 

    def _handle_set_gold_profile (self ,arg_line :str =""):
        parts =shlex .split (arg_line .strip ())
        if len (parts )<1 :
            print (
                f"{Config.Colors.FAIL}[!] Usage: SET-GOLD-PROFILE <path> [SGP.32|SGP.22|SGP.02] "
                f"[AUTH=Y|AUTH=N]{Config.Colors.ENDC}"
            )
            return 

        path_exp =os .path .expanduser (parts [0 ].strip ())
        std ="SGP.32"
        if len (parts )>=2 :
            std =parts [1 ].strip ().upper ()
        allowed =("SGP.32","SGP.22","SGP.02")
        if std not in allowed :
            print (f"{Config.Colors.FAIL}[!] Standard must be one of: {', '.join (allowed)}{Config.Colors.ENDC}")
            return 

        if 'GOLD_PROFILE'not in self .config :
            self .config ['GOLD_PROFILE']={}

        auth_token =""
        if len (parts )>=3 :
            auth_token =parts [2 ].strip ().upper ()

        auth_val ='false'
        if auth_token in ("AUTH=Y","Y","YES","TRUE","1"):
            auth_val ='true'
        if auth_token in ("AUTH=N","N","NO","FALSE","0"):
            auth_val ='false'

        self .config ['GOLD_PROFILE']['path']=path_exp 
        self .config ['GOLD_PROFILE']['standard']=std 
        if auth_token !="":
            self .config ['GOLD_PROFILE']['authenticate_sd']=auth_val 
        if 'authenticate_sd'not in self .config ['GOLD_PROFILE']:
            self .config ['GOLD_PROFILE']['authenticate_sd']='false'

        self ._save_to_disk ()
        print (f"{Config.Colors.GREEN}[+] Gold combined profile YAML path saved to SQLite state.{Config.Colors.ENDC}")
        print (f"    path={path_exp}")
        print (f"    standard={std}")
        print (
            f"    authenticate_sd={self .config ['GOLD_PROFILE']['authenticate_sd']} "
            f"(optional 3rd arg AUTH=Y|AUTH=N)"
        )

    def _handle_show_gold_profile (self ,arg_line :str =""):
        settings =self ._get_gold_profile_settings ()
        print (f"{Config.Colors.HEADER}--- Gold profile reference (SQLite [GOLD_PROFILE]) ---{Config.Colors.ENDC}")
        print (f"  path             : {settings ['path']or '(not set)'}")
        print (f"  standard         : {settings ['standard']}")
        print (f"  authenticate_sd  : {settings ['authenticate_sd']}")
        print ("  PROFILE-DIFF reads the card and diffs against this YAML (or an override path).")

    def _handle_clear_gold_profile (self ,arg_line :str =""):
        if 'GOLD_PROFILE'not in self .config :
            self .config ['GOLD_PROFILE']={}
        self .config ['GOLD_PROFILE']['path']=''
        self ._save_to_disk ()
        print (f"{Config.Colors.GREEN}[+] Cleared gold profile path (standard/auth prefs kept).{Config.Colors.ENDC}")

    def _handle_profile_diff (self ,arg_line :str =""):
        parts =shlex .split (arg_line .strip ())
        settings =self ._get_gold_profile_settings ()
        gold_path =settings ['path']

        if len (parts )>=1 :
            gold_path =os .path .expanduser (parts [0 ].strip ())

        if gold_path =="" or gold_path is None :
            print (
                f"{Config.Colors.FAIL}[!] No gold YAML: use SET-GOLD-PROFILE <path> or "
                f"PROFILE-DIFF <path.yaml>{Config.Colors.ENDC}"
            )
            return 

        if os .path .isfile (gold_path )is False :
            print (f"{Config.Colors.FAIL}[!] Gold YAML not found: {gold_path}{Config.Colors.ENDC}")
            return 

        arg_standard =""
        if len (parts )>=2 :
            arg_standard =parts [1 ].strip ().upper ()

        with open (gold_path ,"r",encoding ="utf-8")as gf :
            gold_doc =yaml .safe_load (gf )
        if isinstance (gold_doc ,dict )is False :
            print (f"{Config.Colors.FAIL}[!] Gold file must decode to a YAML mapping.{Config.Colors.ENDC}")
            return 

        std =arg_standard 
        if std =="":
            loaded_std =gold_doc .get ("standard")
            if isinstance (loaded_std ,str )and len (loaded_std .strip ())>0 :
                std =loaded_std .strip ().upper ()
        if std =="":
            std =settings ['standard']
        if std =="":
            std ="SGP.32"

        auth_sd =settings ['authenticate_sd']
        if len (parts )>=3 :
            third =parts [2 ].strip ().upper ()
            if third in ("AUTH=Y","Y","YES","TRUE","1"):
                auth_sd =True 
            if third in ("AUTH=N","N","NO","FALSE","0"):
                auth_sd =False 

        adm =""
        has_keys =False 
        if 'KEYS'in self .config :
            has_keys =True 
        if has_keys :
            adm =str (self .config ['KEYS'].get ('adm',''))

        print (
            f"{Config.Colors.CYAN}[*] PROFILE-DIFF: standard={std} authenticate_sd={auth_sd} "
            f"(timestamps stripped){Config.Colors.ENDC}"
        )
        try :
            live =self ._build_combined_profile_dict (
                standard =std ,
                adm_hex =adm ,
                authenticate_sd =auth_sd ,
            )
        except Exception as exc :
            print (f"{Config.Colors.FAIL}[!] Live snapshot failed: {exc}{Config.Colors.ENDC}")
            return 

        ok ,diff_text =combined_profile_unified_diff (
            gold_doc ,
            live ,
            gold_label ="gold:"+gold_path ,
            live_label ="live:pcsc",
        )

        if ok :
            print (f"{Config.Colors.GREEN}[+] PROFILE-DIFF: OK (no differences after normalization).{Config.Colors.ENDC}")
            return 

        print (f"{Config.Colors.WARNING}[!] PROFILE-DIFF: mismatch — unified diff:{Config.Colors.ENDC}")
        print (diff_text )

    def _handle_export_euicc (self ,arg :str ="",standard :str ="SGP.32"):
        """Single-command eUICC report export to YAML."""
        out_path =(arg .strip ()if arg else "euicc_report.yaml").strip ()
        if not out_path :
            out_path ="euicc_report.yaml"
        if not out_path .endswith (".yaml")and not out_path .endswith (".yml"):
            out_path =out_path +".yaml"
        std =standard .strip ().upper ()
        is_std_empty =False 
        if len (std )==0 :
            is_std_empty =True 
        if is_std_empty :
            std ="SGP.32"
        print (f"{Config.Colors.CYAN}[*] Generating eUICC report ({std})...{Config.Colors.ENDC}")
        try :
            report =self ._build_euicc_export_report (standard =std )
            with open (out_path ,"w")as f :
                yaml .dump (report ,f ,default_flow_style =False ,allow_unicode =True ,sort_keys =False )
            print (f"{Config.Colors.GREEN}[+] Report written to {out_path}{Config.Colors.ENDC}")
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Export failed: {e}{Config.Colors.ENDC}")

    def _handle_export_keybag (self ,arg :str =""):
        """Dump the active SCP03 session keys into a HIL keybag JSON.

        Usage: EXPORT-KEYBAG [path.keys.json] [label]

        The keybag can then be paired with a pcap and consumed by the
        HIL decode TUI (see B → [3] Open saved .pcap) to unwrap
        secure-messaging APDUs captured during the same card session.
        """
        tokens =shlex .split (arg .strip ())if arg else []

        out_path ="scp03_session.keys.json"
        if len (tokens )>0 :
            candidate =tokens [0 ].strip ()
            if len (candidate )>0 :
                out_path =candidate

        label ="scp03-live"
        if len (tokens )>1 :
            candidate_label =tokens [1 ].strip ()
            if len (candidate_label )>0 :
                label =candidate_label

        has_session =False 
        if self .transport is not None :
            if self .transport .session is not None :
                has_session =True 

        if has_session ==False :
            print (f"{Config.Colors.FAIL}[!] No active SCP03 session. Run AUTH-SD first.{Config.Colors.ENDC}")
            return 

        session =self .transport .session 
        is_authenticated =bool (getattr (session ,"is_authenticated",False ))
        if is_authenticated ==False :
            print (f"{Config.Colors.FAIL}[!] Session is not authenticated. Run AUTH-SD before EXPORT-KEYBAG.{Config.Colors.ENDC}")
            return 

        aid_hex =""
        target_aid =b""
        gp_ctrl =getattr (self ,"gp_ctrl",None )
        if gp_ctrl is not None :
            target_aid =bytes (getattr (gp_ctrl ,"target_aid",b"")or b"")
        if len (target_aid )>0 :
            aid_hex =target_aid .hex ().upper ()

        try :
            from Tools .HilBridge .scp_keybag_export import (
            entry_from_scp03_session ,
            write_keybag_file ,
            )
        except ImportError as error :
            print (f"{Config.Colors.FAIL}[!] Keybag exporter unavailable: {error}{Config.Colors.ENDC}")
            return 

        try :
            entry =entry_from_scp03_session (
            session ,
            label =label ,
            match_aid_hex =aid_hex ,
            )
        except RuntimeError as error :
            print (f"{Config.Colors.FAIL}[!] {error}{Config.Colors.ENDC}")
            return 
        except Exception as error :
            print (f"{Config.Colors.FAIL}[!] Keybag snapshot failed: {error}{Config.Colors.ENDC}")
            return 

        try :
            written_path =write_keybag_file (out_path ,[entry ],merge_existing =True )
        except Exception as error :
            print (f"{Config.Colors.FAIL}[!] Keybag write failed: {error}{Config.Colors.ENDC}")
            return 

        suffix =""
        if len (aid_hex )>0 :
            suffix =f" (aid={aid_hex})"
        print (f"{Config.Colors.GREEN}[+] Keybag written: {written_path} label={label}{suffix}{Config.Colors.ENDC}")
        print (f"{Config.Colors.CYAN}    Pair with a sibling .pcap (rename to <pcap>.keys.json) for offline HIL replay.{Config.Colors.ENDC}")

    def _handle_read_metadata (self ,arg :str =""):
        """
        Guarded metadata read entry point.
        Metadata retrieval for SGP.32 provisioning flows requires authenticated context
        (typically SCP11/ES10b server authentication and profile/eIM trust context).
        """
        raw =arg .strip ().upper ()
        spec ="SGP.32"
        is_raw_present =False 
        if len (raw )>0 :
            is_raw_present =True 
        if is_raw_present :
            is_sgp22 =False 
            if raw =="SGP.22":
                is_sgp22 =True 
            if raw =="22":
                is_sgp22 =True 
            if is_sgp22 :
                spec ="SGP.22"

            is_sgp32 =False 
            if raw =="SGP.32":
                is_sgp32 =True 
            if raw =="32":
                is_sgp32 =True 
            if is_sgp32 :
                spec ="SGP.32"

            is_valid =False 
            if is_sgp22 :
                is_valid =True 
            if is_sgp32 :
                is_valid =True 
            if is_valid ==False :
                print (f"{Config.Colors.WARNING}[!] Unknown spec '{raw}'. Using SGP.32.{Config.Colors.ENDC}")
                spec ="SGP.32"

        print (f"{Config.Colors.CYAN}[*] READ-METADATA requested for {spec}.{Config.Colors.ENDC}")
        print (f"{Config.Colors.WARNING}[-] Not executed: metadata retrieval is gated behind authenticated provisioning context.{Config.Colors.ENDC}")
        print ("    Required preconditions:")
        print ("    | 1) SCP11 channel and ES10b server authentication established")
        print ("    | 2) Matching eIM/profile trust context for metadata access")
        print ("    | 3) Provisioning flow support enabled (planned SCP11 module)")
        print ("    This command is currently a guarded placeholder to prevent unauthenticated metadata operations.")

    def _handle_arr (self ,arg :str =""):
        """Decode Application Reference Data (security attributes) for MF or USIM."""
        path =arg .strip ()if arg else None 
        self .fs_ctrl .get_arr (path =path )

    def _handle_validate (self ,arg :str =""):
        scope ="ALL"
        metadata =None 
        parts =shlex .split (arg .strip ())
        if len (parts )>0 :
            first_token =parts [0 ].strip ()
            first_upper =first_token .upper ()
            if first_upper in ("ALL","MF","USIM","ISIM"):
                scope =first_upper 
                if len (parts )>1 :
                    metadata =self ._load_validate_metadata (parts [1 ])
            else :
                metadata =self ._load_validate_metadata (first_token )

        from SCP03 .logic .profile_validator import ProfileValidator 

        validator =ProfileValidator (self .fs_ctrl ,profile_metadata =metadata )
        validator .run (scope =scope )

    def _load_validate_metadata (self ,metadata_path :str )->dict :
        workspace_root =Path (Config .BASE_DIR ).resolve ().parent
        candidate_path =Path (metadata_path ).expanduser ()
        if candidate_path .is_absolute ()==False :
            candidate_path =workspace_root /candidate_path
        resolved_path =candidate_path .resolve ()
        try :
            resolved_path .relative_to (workspace_root )
        except ValueError as error :
            raise ValueError (f"Metadata path is outside workspace root: {resolved_path}")from error
        if resolved_path .exists ()==False :
            raise FileNotFoundError (f"Metadata path not found: {resolved_path}")
        from SCP03 .logic .profile_validator import ProfileValidator 
        print (f"{Config.Colors.CYAN}[*] Using profile metadata: {resolved_path}{Config.Colors.ENDC}")
        return ProfileValidator .load_profile_metadata (str (resolved_path ))

    def _handle_derive_opc (self ,arg :str ):
        """Derive OPc from Ki and OP (3GPP TS 35.206). Usage: DERIVE-OPC <Ki_hex> <OP_hex>."""
        parts =arg .split ()
        if len (parts )<2 :
            print (f"{Config.Colors.FAIL}[!] Usage: DERIVE-OPC <Ki_hex> <OP_hex> (32 hex chars each){Config.Colors.ENDC}")
            return 
        try :
            opc =self .sec_ctrl .derive_opc (parts [0 ],parts [1 ])
            print (f"{Config.Colors.GREEN}OPc: {opc}{Config.Colors.ENDC}")
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] {e}{Config.Colors.ENDC}")

    def _handle_cert_info (self ):
        """Decode ECASD/card certificates (subject, issuer, validity)."""
        from SCP03 .core .decoders import AdvancedDecoders 
        from SCP03 .core .utils import TlvParser 
        ECASD_AID ="A0000005591010FFFFFFFF8900000200"
        self ._set_prompt_context ("ECASD")
        print (f"{Config.Colors.CYAN}[*] Selecting ECASD...{Config.Colors.ENDC}")
        self .transport .transmit (f"00A40400{len(ECASD_AID)//2:02X}{ECASD_AID}",silent =True )
        cert_tags =[("5A","EID"),("45","CIN"),("42","IIN"),("E0","Key Info"),("7F21","Certificate")]
        print (f"{Config.Colors.HEADER}--- ECASD / Certificate Info ---{Config.Colors.ENDC}")
        for tag_hex ,label in cert_tags :
            cmd =f"80CA{tag_hex}00"
            data ,sw1 ,sw2 =self .transport .transmit (cmd ,silent =True )
            if sw1 !=0x90 and sw1 !=0x61 :
                print (f"  {label}: Not found ({sw1:02X}{sw2:02X})")
                continue 
            if not data :
                print (f"  {label}: (empty)")
                continue 
            raw =data 
            try :
                parsed =TlvParser .parse (data )
                tag_int =int (tag_hex ,16 )
                extracted =TlvParser .get_first (parsed ,tag_int )
                if isinstance (extracted ,bytes ):
                    raw =extracted 
            except Exception :
                pass 

            debug_enabled =bool (self .debug_mode )
            if debug_enabled :
                try :
                    parsed_full =TlvParser .parse (data )
                    print (f"  {label}:")
                    self .gp_ctrl .sgp22 ._print_tlv_tree (parsed_full ,indent =2 ,parent_tag =None )
                    continue 
                except Exception :
                    print (f"  {label}: {raw.hex().upper()}")
                    continue 

            if len (raw )>=4 and raw [0 ]==0x30 :
                info =AdvancedDecoders .decode_cert_der (raw )
                if info :
                    print (f"  {label}:")
                    for k ,v in info .items ():
                        print (f"    {k}: {v}")
                else :
                    print (f"  {label}: {raw.hex().upper()[:64]}...")
            else :
                print (f"  {label}: {raw.hex().upper()}")

    def _handle_reset (self ):
        print (f"{Config.Colors.WARNING}[*] Resetting card...{Config.Colors.ENDC}")
        was_authenticated =False 
        active_protocol ="SCP03"

        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp :
            has_sess =False 
            if self .transport .session :
                has_sess =True 

            if has_sess :
                is_auth_flag =False 
                if self .transport .session .is_authenticated :
                    is_auth_flag =True 

                if is_auth_flag :
                    was_authenticated =True 
                    active_protocol =getattr (self .transport .session ,'protocol_name',"SCP03")
                    print (f"{Config.Colors.CYAN}[*] Secure Session is active. Will auto-restore.{Config.Colors.ENDC}")

        is_reset_ok =False 
        if self .transport .reset ():
            is_reset_ok =True 

        if is_reset_ok :
            self .transport .reset_session_state ()
            self ._clear_prompt_context_tracking ()

            print (f"{Config.Colors.GREEN}[+] Reset Successful.{Config.Colors.ENDC}")

            if was_authenticated :
                is_auth_success =False 
                if self .gp_ctrl .authenticate (active_protocol ):
                    is_auth_success =True 

                if is_auth_success :
                    self ._set_prompt_context_from_gp_target ()
                    self ._update_prompt_state ()

            is_not_auth =False 
            if was_authenticated ==False :
                is_not_auth =True 

            if is_not_auth :
                self ._update_prompt_state ()

        is_fail =False 
        if is_reset_ok ==False :
            is_fail =True 

        if is_fail :
            print (f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")

    def _handle_update (self ,arg_line :str ):
        parts =arg_line .strip ().split ()

        is_empty =False 
        if len (parts )==0 :
            is_empty =True 

        if is_empty :
            print (f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex] or UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
            return 

        sub_cmd =parts [0 ].upper ()

        is_binary =False 
        if sub_cmd =="BINARY":
            is_binary =True 

        if is_binary :
            is_short =False 
            if len (parts )<2 :
                is_short =True 

            if is_short :
                print (f"{Config.Colors.FAIL}[-] Usage: UPDATE BINARY [Hex]{Config.Colors.ENDC}")
                return 

            hex_val ="".join (parts [1 :])
            self .fs_ctrl .update_binary (hex_val )

        is_record =False 
        if sub_cmd =="RECORD":
            is_record =True 

        if is_record :
            is_short =False 
            if len (parts )<3 :
                is_short =True 

            if is_short :
                print (f"{Config.Colors.FAIL}[-] Usage: UPDATE RECORD [Num] [Hex]{Config.Colors.ENDC}")
                return 

            rec_str =parts [1 ]
            hex_val ="".join (parts [2 :])
            self .fs_ctrl .update_record (rec_str ,hex_val )

        is_unknown =False 
        if is_binary ==False :
            if is_record ==False :
                is_unknown =True 

        if is_unknown :
            hex_val ="".join (parts )
            self .fs_ctrl .update_binary (hex_val )

    def _print_help (self ):
        HelpMenu .print_help ()

    def run_commands (self ,cmd_line :str ,yaml_out :Optional [str ]=None ):
        """
        Execute semicolon-separated commands (e.g. "AUTH-SD; LIST") without interactive loop.
        If yaml_out is set, capture each command output and write to YAML file.
        """
        # Non-interactive paths do not clear the screen, so flushing the
        # deferred startup notice here is safe and keeps the banner
        # visible when operators pipe commands in via ``--cmd``/``--stdin``.
        self ._flush_pending_startup_stderr ()
        commands =[c .strip ()for c in cmd_line .split (";")if c .strip ()]
        results =[]
        for line in commands :
            if line .startswith ("#"):
                continue 
            if yaml_out :
                old_stdout =sys .stdout 
                sys .stdout =mystdout =io .StringIO ()
                try :
                    self ._exec_line (line )
                except Exception as e :
                    print (f"Error: {e}")
                finally :
                    sys .stdout =old_stdout 
                captured =mystdout .getvalue ()
                ansi_escape =re .compile (r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                clean =ansi_escape .sub ("",captured ).strip ()
                results .append ({"command":line ,"output":clean })
                print (captured ,end ="")
            else :
                self ._exec_line (line )
        if yaml_out and results :
            try :
                with open (yaml_out ,"w")as f :
                    f .write ("# YggdraSIM CLI Report\n")
                    f .write (f"# Date: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n")
                    f .write ("steps:\n")
                    for step in results :
                        f .write (f"  - command: \"{step['command']}\"\n")
                        f .write ("    output: |\n")
                        for ln in step ["output"].split ("\n"):
                            f .write (f"      {ln}\n")
            except Exception as e :
                print (f"{Config.Colors.FAIL}[!] Failed to write YAML: {e}{Config.Colors.ENDC}")

    def run_script (self ,arg_line :str ):
        # Scripted runs share the buffer used by the interactive shell;
        # flush here so the shipped-demo-keys banner is not silently
        # discarded when the script path is invoked via ``--script``
        # before the REPL ever gets a chance to redraw.
        """Load and execute an SCP03 shell script from a file path."""
        self ._flush_pending_startup_stderr ()
        parts =arg_line .split ()

        is_empty =False 
        if len (parts )==0 :
            is_empty =True 

        if is_empty :
            print (f"{Config.Colors.FAIL}[!] Usage: RUN <script_file> [output.yaml]{Config.Colors.ENDC}")
            return 

        filename =parts [0 ]

        yaml_out =None 
        has_yaml =False 
        if len (parts )>1 :
            has_yaml =True 

        if has_yaml :
            yaml_out =parts [1 ]

        is_exists =False 
        if os .path .exists (filename ):
            is_exists =True 

        if is_exists ==False :
            print (f"{Config.Colors.FAIL}[!] Script not found: {filename}{Config.Colors.ENDC}")
            return 

        print (f"{Config.Colors.CYAN}[*] Running script: {filename}{Config.Colors.ENDC}")

        has_out =False 
        if yaml_out :
            has_out =True 

        if has_out :
            print (f"{Config.Colors.CYAN}[*] Recording output to: {yaml_out}{Config.Colors.ENDC}")

        results =[]

        try :
            with open (filename ,'r')as f :
                lines =f .readlines ()

            for i ,line in enumerate (lines ):
                line =line .strip ()

                is_line_empty =False 
                if len (line )==0 :
                    is_line_empty =True 

                if is_line_empty :
                    continue 

                is_comment =False 
                if line .startswith ('#'):
                    is_comment =True 

                if is_comment :
                    continue 

                print (f"\n{Config.Colors.YELLOW}[SCRIPT:{i+1}] > {line}{Config.Colors.ENDC}")

                captured_output =""
                is_yaml_present =False 
                if yaml_out :
                    is_yaml_present =True 

                if is_yaml_present :
                    old_stdout =sys .stdout 
                    sys .stdout =mystdout =io .StringIO ()
                    try :
                        self ._exec_line (line )
                    except Exception as e :
                        print (f"Error: {e}")
                    finally :
                        sys .stdout =old_stdout 
                        captured_output =mystdout .getvalue ()
                        print (captured_output ,end ="")

                is_no_yaml =False 
                if is_yaml_present ==False :
                    is_no_yaml =True 

                if is_no_yaml :
                    self ._exec_line (line )

                if is_yaml_present :
                    ansi_escape =re .compile (r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    clean_text =ansi_escape .sub ('',captured_output ).strip ()
                    results .append ({'command':line ,'output':clean_text })

        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Script Error: {e}{Config.Colors.ENDC}")

        is_write_yaml =False 
        if yaml_out :
            is_write_yaml =True 

        if is_write_yaml :
            has_res =False 
            if len (results )>0 :
                has_res =True 

            if has_res :
                try :
                    with open (yaml_out ,'w')as f :
                        f .write ("# YggdraSIM Script Report\n")
                        f .write (f"# Date: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
                        f .write (f"# Script: {filename}\n\n")
                        f .write ("steps:\n")
                        for step in results :
                            f .write (f"  - command: \"{step['command']}\"\n")
                            f .write ("    output: |\n")
                            for out_line in step ['output'].split ('\n'):
                                f .write (f"      {out_line}\n")
                    print (f"{Config.Colors.GREEN}[+] Report saved to {yaml_out}{Config.Colors.ENDC}")
                except Exception as e :
                    print (f"{Config.Colors.FAIL}[!] Failed to write YAML: {e}{Config.Colors.ENDC}")

    def _exec_line (self ,line :str ):
        is_empty =False 
        if len (line )==0 :
            is_empty =True 

        if is_empty :
            return 

        is_comment =False 
        if line .startswith ('#'):
            is_comment =True 

        if is_comment :
            return 
        try :
            parts =line .split (None ,1 )
            cmd =parts [0 ].upper ()

            arg =""
            has_arg =False 
            if len (parts )>1 :
                has_arg =True 

            if has_arg :
                arg =parts [1 ]

            is_known =False 
            if cmd in self .commands :
                is_known =True 

            if is_known :
                args_required ,args_optional =CommandRegistry .get_arg_requirements ()
                try :
                    is_req =False 
                    if cmd in args_required :
                        is_req =True 

                    if is_req :
                        is_arg_missing =False 
                        if len (arg )==0 :
                            is_arg_missing =True 

                        if is_arg_missing :
                            print (f"{Config.Colors.WARNING}[!] Argument required for {cmd}{Config.Colors.ENDC}")

                        has_argument =False 
                        if is_arg_missing ==False :
                            has_argument =True 

                        if has_argument :
                            self .commands [cmd ](arg )

                    is_opt =False 
                    if cmd in args_optional :
                        is_opt =True 

                    if is_opt :
                        has_argument =False 
                        if len (arg )>0 :
                            has_argument =True 

                        if has_argument :
                            self .commands [cmd ](arg )

                        is_arg_missing =False 
                        if has_argument ==False :
                            is_arg_missing =True 

                        if is_arg_missing :
                            self .commands [cmd ]()

                    is_none =False 
                    if is_req ==False :
                        if is_opt ==False :
                            is_none =True 

                    if is_none :
                        self .commands [cmd ]()
                except Exception as e :
                    print (f"{Config.Colors.FAIL}[!] Command Execution Error: {e}{Config.Colors.ENDC}")

            is_unknown =False 
            if is_known ==False :
                is_unknown =True 

            if is_unknown :
                apdu_bytes =self ._parse_manual_apdu_line (line )
                is_apdu =False 
                if apdu_bytes is not None :
                    is_apdu =True 

                if is_apdu :
                    has_tp =False 
                    if self .transport :
                        has_tp =True 

                    if has_tp :
                        data ,sw1 ,sw2 =self .transport .transmit (line ,silent =False )

                        is_success =False 
                        if sw1 ==0x90 :
                            is_success =True 
                        if sw1 ==0x61 :
                            is_success =True 

                        if is_success :
                            self ._sync_manual_command (apdu_bytes ,data )

                    is_no_tp =False 
                    if has_tp ==False :
                        is_no_tp =True 

                    if is_no_tp :
                        print ("No card reader connected.")

                is_invalid =False 
                if is_apdu ==False :
                    is_invalid =True 

                if is_invalid :
                    print (f"{Config.Colors.FAIL}Unknown command: {cmd}{Config.Colors.ENDC}")
        finally :
            self ._update_prompt_state ()

    @staticmethod
    def _parse_manual_apdu_line (line :str )->Optional [bytes ]:
        candidate =str (line or "").strip ()
        if len (candidate )<4 :
            return None
        try :
            return HexUtils .to_bytes (candidate )
        except ValueError :
            return None

    def _sync_manual_command (self ,apdu :bytes ,data :bytes ):
        is_short =False 
        if len (apdu )<4 :
            is_short =True 

        if is_short :
            return 

        ins =apdu [1 ]

        is_a4 =False 
        if ins ==0xA4 :
            is_a4 =True 

        if is_a4 :
            selected_hex =None 
            has_len =False 
            if len (apdu )>5 :
                has_len =True 

            if has_len :
                lc =apdu [4 ]
                has_payload =False 
                if len (apdu )>=5 +lc :
                    has_payload =True 

                if has_payload :
                    selected_hex =apdu [5 :5 +lc ].hex ().upper ()
                    self .fs_ctrl .current_fid =selected_hex 
                    context_label =self ._context_label_from_selection (selected_hex )
                    self .fs_ctrl .current_path_hint =context_label 
                    self ._set_prompt_context (context_label )

            has_data =False 
            if data :
                has_data =True 

            if has_data :
                self .fs_ctrl ._parse_fcp_internal (data ,selected_hex )
                self .fs_ctrl .print_fcp_info ()

        is_b0 =False 
        if ins ==0xB0 :
            is_b0 =True 

        if is_b0 :
            has_data =False 
            if data :
                has_data =True 

            if has_data :
                decoded =ContentDecoder .decode (
                self .fs_ctrl .current_fid ,
                data .hex (),
                context_path =getattr (self .fs_ctrl ,"current_path_hint","")
                )
                has_decoded =False 
                if decoded :
                    has_decoded =True 

                if has_decoded :
                    print (f"{Config.Colors.GREEN}{decoded}{Config.Colors.ENDC}")

        is_b2 =False 
        if ins ==0xB2 :
            is_b2 =True 

        if is_b2 :
            has_data =False 
            if data :
                has_data =True 

            if has_data :
                decoded =ContentDecoder .decode (
                self .fs_ctrl .current_fid ,
                data .hex (),
                context_path =getattr (self .fs_ctrl ,"current_path_hint","")
                )
                has_decoded =False 
                if decoded :
                    has_decoded =True 

                if has_decoded :
                    is_valid =False 
                    if "None"not in decoded :
                        is_valid =True 

                    if is_valid :
                        for line in decoded .strip ().split ('\n'):
                            print (f"          | {Config.Colors.CYAN}{line}{Config.Colors.ENDC}")

        is_ca =False 
        if ins ==0xCA :
            is_ca =True 

        if is_ca :
            has_data =False 
            if data :
                has_data =True 

            if has_data :
                try :
                    parsed =TlvParser .parse (data )
                    self .gp_ctrl .print_tlv_data (parsed )
                except Exception :
                    pass 

    def _print_card_info (self ):
        print (f"\n{Config.Colors.HEADER}=== CARD INFO ==={Config.Colors.ENDC}")
        has_tp =False 
        if self .transport :
            has_tp =True 

        is_no_tp =False 
        if has_tp ==False :
            is_no_tp =True 

        if is_no_tp :
            print (f"{Config.Colors.FAIL}[-] No reader connected.{Config.Colors.ENDC}")
            return 

        reset_ok =self .transport .reset ()
        is_reset_ok =False 
        if reset_ok :
            is_reset_ok =True 

        atr_hex ="Unknown"
        if is_reset_ok :
            try :
                atr =self .transport .connection .getATR ()
                atr_hex =bytes (atr ).hex ().upper ()
            except Exception :
                pass 

        is_fail =False 
        if is_reset_ok ==False :
            is_fail =True 

        if is_fail :
            print (f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")
            return 

        iccid =self ._read_live_iccid ()
        if len (iccid )==0 :
            known_iccid =''.join (ch for ch in str (self .current_iccid or "")if ch .isdigit ())
            if len (known_iccid )>0 :
                iccid =known_iccid 
            else :
                iccid ="Unknown"

        print (f"{Config.Colors.BOLD}ATR   :{Config.Colors.ENDC} {atr_hex}")
        print (f"{Config.Colors.BOLD}ICCID :{Config.Colors.ENDC} {iccid}")

        eid =None 
        std ="Legacy UICC"

        ecasd_aid ="A0000005591010FFFFFFFF8900000200"
        isdr_aid ="A0000005591010FFFFFFFF8900000100"

        res_sel ,sw1_sel ,sw2_sel =self .transport .transmit (f"00A4040010{ecasd_aid}",silent =True )
        valid_ecasd =False 
        if sw1_sel ==0x90 :
            valid_ecasd =True 
        if sw1_sel ==0x61 :
            valid_ecasd =True 

        if valid_ecasd :
            res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("00CA005A00",silent =True )
            if sw1_ca ==0x90 :
                try :
                    eid =self .gp_ctrl .sgp22 ._extract_eid_hex (res_ca )
                except Exception :
                    eid =res_ca .hex ().upper ()

        e2_data ,e2_sw1 ,e2_sw2 =self .gp_ctrl .sgp22 ._retrieve_eid_response ()
        has_es10_eid =False 
        if e2_sw1 ==0x90 and e2_data :
            has_es10_eid =True 
            try :
                eid =self .gp_ctrl .sgp22 ._extract_eid_hex (e2_data )
            except Exception :
                eid =e2_data .hex ().upper ()

        sgp32_probe =self .gp_ctrl .sgp22 ._es10_retrieve_data ("BF5500")
        if sgp32_probe :
            std =f"{Config.Colors.GREEN}SGP.32 (IoT){Config.Colors.ENDC}"
        else :
            if has_es10_eid :
                std =f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
            else :
                configured_probe =self .gp_ctrl .sgp22 ._es10_retrieve_data ("BF3C00")
                info1_probe =self .gp_ctrl .sgp22 ._es10_retrieve_data ("BF2000")
                info2_probe =self .gp_ctrl .sgp22 ._es10_retrieve_data ("BF2200")
                has_es10_profile =False 
                if configured_probe :
                    has_es10_profile =True 
                if info1_probe :
                    has_es10_profile =True 
                if info2_probe :
                    has_es10_profile =True 
                if has_es10_profile :
                    std =f"{Config.Colors.GREEN}SGP.22/32 (Consumer/IoT){Config.Colors.ENDC}"
                else :
                    res_sel_m2m ,sw1_m2m ,sw2_m2m =self .transport .transmit (f"00A4040010{isdr_aid}",silent =True )
                    valid_isdr =False 
                    if sw1_m2m ==0x90 :
                        valid_isdr =True 
                    if sw1_m2m ==0x61 :
                        valid_isdr =True 
                    if valid_isdr :
                        std =f"{Config.Colors.BLUE}SGP.02 (M2M){Config.Colors.ENDC}"

                        is_eid_missing =False 
                        if eid is None :
                            is_eid_missing =True 

                        if is_eid_missing :
                            res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("80CA005A00",silent =True )
                            ca_success =False 
                            if sw1_ca ==0x90 :
                                ca_success =True 
                            if ca_success ==False :
                                res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("00CA005A00",silent =True )
                                if sw1_ca ==0x90 :
                                    ca_success =True 
                            if ca_success :
                                try :
                                    eid =self .gp_ctrl .sgp22 ._extract_eid_hex (res_ca )
                                except Exception :
                                    eid =res_ca .hex ().upper ()

        has_eid =False 
        if eid :
            has_eid =True 

        if has_eid :
            print (f"{Config.Colors.BOLD}eID   :{Config.Colors.ENDC} {eid}")

        print (f"{Config.Colors.BOLD}Spec  :{Config.Colors.ENDC} {std}")
        if iccid !="Unknown":
            self .current_iccid =''.join (ch for ch in str (iccid )if ch .isdigit ())
        if eid :
            self .current_eid =str (eid ).strip ().upper ()
        self ._apply_inventory_profile_for_identifiers (self .current_iccid ,self .current_eid ,announce =True )
        self .transport .reset ()
        self .fs_ctrl .current_fid ="3F00"
        self ._clear_prompt_context_tracking ()
        print ("="*40 +"\n")

    def _print_atr_details (self ):
        print (f"\n{Config.Colors.HEADER}=== ATR DETAILS ==={Config.Colors.ENDC}")
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp ==False :
            print (f"{Config.Colors.FAIL}[-] No reader connected.{Config.Colors.ENDC}")
            return 

        reset_ok =self .transport .reset ()
        if reset_ok ==False :
            print (f"{Config.Colors.FAIL}[-] Card Reset Failed.{Config.Colors.ENDC}")
            return 

        try :
            for line in self .transport .describe_atr ():
                print (line )
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] ATR Parse Error: {e}{Config.Colors.ENDC}")
        self ._clear_prompt_context_tracking ()
        print ("")

    @staticmethod
    def _decode_iccid_bcd (data :bytes )->str :
        hex_value =bytes (data ).hex ().upper ()
        digits =[]
        for index in range (0 ,len (hex_value ),2 ):
            pair =hex_value [index :index +2 ]
            if len (pair )<2 :
                continue 
            digits .append (pair [1 ])
            digits .append (pair [0 ])
        return "".join (digits ).replace ("F","")

    @staticmethod
    def _is_successful_select_sw (sw1 :int )->bool :
        if sw1 ==0x90 :
            return True 
        if sw1 ==0x61 :
            return True 
        if sw1 ==0x9F :
            return True 
        return False 

    @staticmethod
    def _is_usable_read_sw (sw1 :int ,data :bytes )->bool :
        if sw1 ==0x90 :
            return True 
        has_data =False 
        if len (bytes (data or b"" ))>0 :
            has_data =True 
        if has_data ==False :
            return False 
        if sw1 ==0x62 :
            return True 
        if sw1 ==0x63 :
            return True 
        return False 

    def _read_live_iccid (self )->str :
        has_tp =False 
        if self .transport :
            has_tp =True 
        if has_tp ==False :
            return ""
        try :
            self .transport .transmit ("00A40004023F00",silent =True )
            _sel_data ,sel_sw1 ,sel_sw2 =self .transport .transmit ("00A40004022FE2",silent =True )
            if self ._is_successful_select_sw (sel_sw1 )==False :
                return ""
            data ,sw1 ,sw2 =self .transport .transmit ("00B000000A",silent =True )
            if self ._is_usable_read_sw (sw1 ,data )==False :
                return ""
            return self ._decode_iccid_bcd (data )
        except Exception :
            return ""

    def _probe_card_identity (self )->Tuple [str ,str ]:
        has_tp =False 
        if self .transport :
            has_tp =True 
        if has_tp ==False :
            return "",""

        reset_ok =self .transport .reset ()
        if reset_ok ==False :
            return "",""

        iccid =self ._read_live_iccid ()

        eid =""
        try :
            ecasd_aid ="A0000005591010FFFFFFFF8900000200"
            isdr_aid ="A0000005591010FFFFFFFF8900000100"
            res_sel ,sw1_sel ,sw2_sel =self .transport .transmit (f"00A4040010{ecasd_aid}",silent =True )
            valid_ecasd =False 
            if sw1_sel ==0x90 :
                valid_ecasd =True 
            if sw1_sel ==0x61 :
                valid_ecasd =True 
            if valid_ecasd :
                res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("00CA005A00",silent =True )
                if sw1_ca ==0x90 :
                    try :
                        eid =self .gp_ctrl .sgp22 ._extract_eid_hex (res_ca )
                    except Exception :
                        eid =res_ca .hex ().upper ()

            e2_data ,e2_sw1 ,e2_sw2 =self .gp_ctrl .sgp22 ._retrieve_eid_response ()
            if e2_sw1 ==0x90 and e2_data :
                try :
                    eid =self .gp_ctrl .sgp22 ._extract_eid_hex (e2_data )
                except Exception :
                    eid =e2_data .hex ().upper ()

            if len (eid )==0 :
                res_sel_m2m ,sw1_m2m ,sw2_m2m =self .transport .transmit (f"00A4040010{isdr_aid}",silent =True )
                valid_isdr =False 
                if sw1_m2m ==0x90 :
                    valid_isdr =True 
                if sw1_m2m ==0x61 :
                    valid_isdr =True 
                if valid_isdr :
                    res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("80CA005A00",silent =True )
                    ca_success =False 
                    if sw1_ca ==0x90 :
                        ca_success =True 
                    if ca_success ==False :
                        res_ca ,sw1_ca ,sw2_ca =self .transport .transmit ("00CA005A00",silent =True )
                        if sw1_ca ==0x90 :
                            ca_success =True 
                    if ca_success :
                        try :
                            eid =self .gp_ctrl .sgp22 ._extract_eid_hex (res_ca )
                        except Exception :
                            eid =res_ca .hex ().upper ()
        except Exception :
            eid =""

        try :
            self .transport .reset ()
        except Exception :
            pass 
        self .fs_ctrl .current_fid ="3F00"
        return iccid ,eid 

    def _inventory_keys_payload (self )->dict :
        payload ={}
        for key_name in Config .DEFAULT_KEYS .keys ():
            raw_value =""
            if key_name in self .config ['KEYS']:
                raw_value =self .config ['KEYS'][key_name ]
            payload [key_name ]=str (raw_value ).strip ().upper ()
        if len (self .current_eid )>0 :
            payload ["card_eid"]=self .current_eid 
        return payload 

    def _persist_inventory_profile (self )->None :
        if len (self .current_iccid )==0 :
            return 
        self .inventory .replace_namespace (
        "iccid",
        self .current_iccid ,
        "scp03",
        self ._inventory_keys_payload (),
        )

    def _module_state_payload (self )->dict :
        payload ={
        "KEYS":{},
        "GOLD_PROFILE":{},
        }
        if 'KEYS'in self .config :
            payload ["KEYS"]=dict (self .config ['KEYS'])
        if 'GOLD_PROFILE'in self .config :
            payload ["GOLD_PROFILE"]=dict (self .config ['GOLD_PROFILE'])
        return payload 

    def _apply_module_state_payload (self ,payload :dict )->None :
        keys_payload =payload .get ("KEYS",{})
        if isinstance (keys_payload ,dict ):
            if 'KEYS'not in self .config :
                self .config ['KEYS']={}
            for key_name ,value in keys_payload .items ():
                self .config ['KEYS'][str (key_name )]=str (value ).strip ().upper ()
        gold_payload =payload .get ("GOLD_PROFILE",{})
        if isinstance (gold_payload ,dict ):
            if 'GOLD_PROFILE'not in self .config :
                self .config ['GOLD_PROFILE']={}
            for key_name ,value in gold_payload .items ():
                self .config ['GOLD_PROFILE'][str (key_name )]=str (value )

    def _persist_module_state (self )->None :
        self .inventory .replace_module_state (Config .MODULE_STATE_NAME ,self ._module_state_payload ())

    def _apply_inventory_profile_for_identifiers (self ,iccid :str ,eid :str ,announce :bool =False )->None :
        normalized_iccid =''.join (ch for ch in str (iccid or "")if ch .isdigit ())
        normalized_eid =str (eid or "").strip ().upper ()
        if len (normalized_iccid )>0 :
            self .current_iccid =normalized_iccid 
        if len (normalized_eid )>0 :
            self .current_eid =normalized_eid 
        if len (self .current_iccid )==0 :
            return 

        payload =self .inventory .get_namespace ("iccid",self .current_iccid ,"scp03")
        loaded_profile =False 
        if isinstance (payload ,dict )and len (payload )>0 :
            for key_name in Config .DEFAULT_KEYS .keys ():
                if key_name not in payload :
                    continue 
                self .config ['KEYS'][key_name ]=str (payload [key_name ]).strip ().upper ()
            loaded_profile =True 
            self ._initialize_controllers ()
            self ._update_prompt_state ()

        self ._persist_inventory_profile ()
        if announce :
            if loaded_profile :
                print (
                f"{Config.Colors.GREEN}[+] Loaded SCP03 inventory profile for ICCID "
                f"{self.current_iccid}.{Config.Colors.ENDC}"
                )
            else :
                print (
                f"{Config.Colors.HEADER}[*] Seeded SCP03 inventory profile for ICCID "
                f"{self.current_iccid} using current SCP03 defaults.{Config.Colors.ENDC}"
                )

    def _prime_inventory_profile (self )->None :
        try :
            iccid ,eid =self ._probe_card_identity ()
        except Exception :
            return 
        self ._apply_inventory_profile_for_identifiers (iccid ,eid ,announce =False )

    def _load_config_file (self ):
        import os 

        file_exists =False 
        if os .path .exists (Config .INI_FILE ):
            file_exists =True 

        if file_exists :
            self .config .read (Config .INI_FILE )

        has_keys =False 
        if 'KEYS'in self .config :
            has_keys =True 

        is_no_keys =False 
        if has_keys ==False :
            is_no_keys =True 

        if is_no_keys :
            self .config ['KEYS']={}

        legacy_map ={
        'kenc':'scp03_kenc',
        'enc':'scp03_kenc',
        'kmac':'scp03_kmac',
        'mac':'scp03_kmac',
        'dek':'scp03_dek',
        'kvn':'scp03_kvn'
        }
        for legacy_key ,new_key in legacy_map .items ():
            has_legacy =False 
            if legacy_key in self .config ['KEYS']:
                has_legacy =True 
            has_new =False 
            if new_key in self .config ['KEYS']:
                has_new =True 
            if has_legacy and has_new ==False :
                self .config ['KEYS'][new_key ]=self .config ['KEYS'][legacy_key ]

        for key_name ,default_value in Config .DEFAULT_KEYS .items ():
            if key_name not in self .config ['KEYS']:
                self .config ['KEYS'][key_name ]=default_value 

        has_gold =False 
        if 'GOLD_PROFILE'in self .config :
            has_gold =True 
        if has_gold ==False :
            self .config ['GOLD_PROFILE']={}

        gold_sec =self .config ['GOLD_PROFILE']
        if 'path'not in gold_sec :
            gold_sec ['path']=''
        if 'standard'not in gold_sec :
            gold_sec ['standard']='SGP.32'
        if 'authenticate_sd'not in gold_sec :
            gold_sec ['authenticate_sd']='false'

        module_state ={}
        try :
            module_state =self .inventory .get_module_state (Config .MODULE_STATE_NAME )
        except Exception :
            module_state ={}
        if isinstance (module_state ,dict )and len (module_state )>0 :
            self ._apply_module_state_payload (module_state )
        else :
            self ._persist_module_state ()

    def _load_aid_registry (self )->Dict [str ,str ]:
        registry ={}
        self .aid_rule_roles ={}
        is_exists =False 
        if os .path .exists (Config .AID_FILE ):
            is_exists =True 

        if is_exists :
            try :
                with open (Config .AID_FILE ,'r')as f :
                    for line in f :
                        name ,aid ,role_name =self ._parse_aid_registry_line (line )
                        if len (name )==0 :
                            continue 
                        registry [name ]=aid 
                        if len (role_name )>0 :
                            self .aid_rule_roles [name ]=role_name 
            except Exception as e :
                print (f"{Config.Colors.FAIL}[-] aid.txt error: {e}{Config.Colors.ENDC}")

        is_missing =False 
        if is_exists ==False :
            is_missing =True 

        if is_missing :
            registry ={'ISDR':'A0000005591010FFFFFFFF8900000100'}

        return registry 

    def _initialize_controllers (self ):
        keys =Config .DEFAULT_KEYS .copy ()

        has_keys =False 
        if 'KEYS'in self .config :
            has_keys =True 

        if has_keys :
            keys .update (dict (self .config ['KEYS']))

        self .gp_ctrl =GlobalPlatformManager (self .transport ,keys )
        self .fs_ctrl =FileSystemController (self .transport ,self .aid_registry )
        self .sec_ctrl =SecurityController (self .transport ,self .fs_ctrl )
        # ``GlobalPlatformManager`` now returns the demo-keys banner text
        # via ``pending_demo_keys_warning`` instead of writing straight to
        # stderr. Hoist it onto the dispatcher so ``run`` / ``run_commands``
        # / ``run_script`` can surface it after the screen-clear redraw.
        pending_warning =getattr (self .gp_ctrl ,"pending_demo_keys_warning",None )
        if pending_warning :
            existing =getattr (self ,"_pending_startup_stderr",None )
            if existing :
                self ._pending_startup_stderr =existing +"\n"+str (pending_warning )
            else :
                self ._pending_startup_stderr =str (pending_warning )
            self .gp_ctrl .pending_demo_keys_warning =None 

    def _update_config (self ,key :str ,value :Optional [str ]):
        is_empty =False 
        if not value :
            is_empty =True 

        if is_empty :
            print (f"{Config.Colors.FAIL}[-] Usage: SET-{key.upper()} <VALUE>{Config.Colors.ENDC}")
            return 

        self .config ['KEYS'][key ]=value .strip ().upper ()

        self ._save_to_disk ()
        print (f"{Config.Colors.GREEN}[+] {key.upper()} updated.{Config.Colors.ENDC}")
        self ._initialize_controllers ()
        self ._update_prompt_state ()

    def _set_defaults (self ):
        print (f"{Config.Colors.WARNING}[!] Resetting configuration to defaults...{Config.Colors.ENDC}")
        self .config ['KEYS']=Config .DEFAULT_KEYS .copy ()

        has_adm =False 
        if 'adm'in self .config ['KEYS']:
            has_adm =True 

        is_no_adm =False 
        if has_adm ==False :
            is_no_adm =True 

        if is_no_adm :
            self .config ['KEYS']['adm']='0000000000000000'

        self ._save_to_disk ()
        self ._initialize_controllers ()
        print (f"{Config.Colors.GREEN}[+] Reset complete.{Config.Colors.ENDC}")
        self ._update_prompt_state ()

    def _save_to_disk (self ):
        try :
            self ._persist_module_state ()
            self ._persist_inventory_profile ()
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] IO Error: {e}{Config.Colors.ENDC}")

    def show_config (self ):
        """Print the current active SCP03 configuration summary to stdout."""
        print (f"{Config.Colors.HEADER}--- Configuration (SQLite-backed SCP03 state) ---{Config.Colors.ENDC}")
        if len (self .current_iccid )>0 :
            print (f"Active ICCID: {self.current_iccid}")
        if len (self .current_eid )>0 :
            print (f"Observed eID: {self.current_eid}")
        for section in self .config .sections ():
            print (f"[{section}]")
            for key ,value in self .config .items (section ):
                print (f"  {key} = {value}")

    def list_aids (self ):
        """List all registered AID entries from the aid.txt registry."""
        print (f"{Config.Colors.HEADER}--- AID Registry (aid.txt) ---{Config.Colors.ENDC}")

        has_items =False 
        if self .aid_registry :
            has_items =True 

        is_empty =False 
        if has_items ==False :
            is_empty =True 

        if is_empty :
            print ("  (Registry is empty)")
            return 

        for name ,aid in sorted (self .aid_registry .items ()):
            role_name =self ._resolve_aid_rule_role (name )
            role_suffix =""
            if len (role_name )>0 :
                role_suffix =f" [{role_name}]"
            print (f"  {name:<10} : {aid}{role_suffix}")

    def _set_aid_alias (self ,arg_line :Optional [str ]):
        is_empty =False 
        if not arg_line :
            is_empty =True 

        if is_empty :
            print (f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return 

        parts =arg_line .split ()

        is_short =False 
        if len (parts )<2 :
            is_short =True 

        if is_short :
            print (f"{Config.Colors.FAIL}[-] Usage: SET-AID-ALIAS <NAME> <AID_HEX>{Config.Colors.ENDC}")
            return 

        name =parts [0 ].strip ().upper ()
        aid_hex =parts [1 ].strip ().replace (' ','').upper ()

        self .aid_registry [name ]=aid_hex 
        if name in ("ARAM","ARAC"):
            self .aid_rule_roles [name ]=name 
        else :
            if name in self .aid_rule_roles :
                del self .aid_rule_roles [name ]
        self .aid_lookup ={bytes .fromhex (v ):k for k ,v in self .aid_registry .items ()}
        try :
            with open (Config .AID_FILE ,'w')as f :
                for n ,a in sorted (self .aid_registry .items ()):
                    f .write (f"{n}:{a}\n")
            print (f"{Config.Colors.GREEN}[+] AID alias '{name}' saved.{Config.Colors.ENDC}")
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Failed to save aid.txt: {e}{Config.Colors.ENDC}")

    def set_prompt (self ,name :str ):
        """Update the shell prompt to reflect the currently active security domain."""
        is_isd =False 
        if name =="ISD-SECURE":
            is_isd =True 

        if is_isd :
            self .prompt_str =f"\n[{Config.Colors.GREEN}ISD-SECURE{Config.Colors.ENDC}] > "

        is_other =False 
        if is_isd ==False :
            is_other =True 

        if is_other :
            self .prompt_str =f"\n[{Config.Colors.GREEN}{name}{Config.Colors.ENDC}] > "

    def logout (self ):
        """Tear down the current SCP03 session and reset the transport state."""
        has_tp =False 
        if self .transport :
            has_tp =True 

        is_no_tp =False 
        if has_tp ==False :
            is_no_tp =True 

        if is_no_tp :
            print (f"{Config.Colors.WARNING}[!] No reader connected.{Config.Colors.ENDC}")
            return 

        was_active =self .transport .logout ()

        is_active =False 
        if was_active :
            is_active =True 

        if is_active :
            print (f"{Config.Colors.GREEN}[+] Secure session closed.{Config.Colors.ENDC}")

        is_inactive =False 
        if is_active ==False :
            is_inactive =True 

        if is_inactive :
            print (f"{Config.Colors.WARNING}[!] No active secure session.{Config.Colors.ENDC}")
        if is_active :
            self ._set_prompt_context_from_gp_target ()
        self ._update_prompt_state ()

    def _exit (self ):
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp :
            self .transport .disconnect ()

        self ._save_history ()
        sys .exit (0 )

    def _quit_all (self ):
        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp :
            self .transport .disconnect ()

        self ._save_history ()
        quit_all ()

    def _run_scp80_tool (self ):
        print (f"{Config.Colors.HEADER}=== Switching to SCP80 OTA Tool ==={Config.Colors.ENDC}")
        print (f"{Config.Colors.WARNING}[*] Releasing Card Reader...{Config.Colors.ENDC}")

        has_tp =False 
        if self .transport :
            has_tp =True 

        if has_tp :
            self .transport .disconnect ()

        try :
            print (f"{Config.Colors.CYAN}[*] Starting SCP80 Module...{Config.Colors.ENDC}")
            import sys 
            import os 
            import importlib 

            current_dir =os .path .dirname (os .path .abspath (__file__ ))
            scp80_root =os .path .abspath (os .path .join (current_dir ,'../../SCP80'))

            is_missing =False 
            if scp80_root not in sys .path :
                is_missing =True 

            if is_missing :
                sys .path .insert (0 ,scp80_root )

            import main as scp80_main 
            importlib .reload (scp80_main )

            scp80_main .run_standalone ()

        except SystemExit :
            pass 
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] SCP80 Switch Failed: {e}{Config.Colors.ENDC}")

        is_nt =False 
        if os .name =='nt':
            is_nt =True 

        if is_nt :
            os .system ('cls')

        is_posix =False 
        if is_nt ==False :
            is_posix =True 

        if is_posix :
            os .system ('clear')

        print (f"{Config.Colors.HEADER}")
        print (r" __   __               _               ____ ___ __  __ ")
        print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print (r"      |___/  |___/                                     ")
        print (r"             _    ____  __  __ ___ _   _ ")
        print (r"            / \  |  _ \|  \/  |_ _| \ | |")
        print (r"           / _ \ | | | | |\/| || ||  \| |")
        print (r"          / ___ \| |_| | |  | || || |\  |")
        print (r"         /_/   \_\____/|_|  |_|___|_| \_|")
        print ("")
        print ("=== YggdraSIM Administration Shell ===")
        print (" [ GlobalPlatform | ETSI FS | SGP.22 eUICC | Telecom Auth ]")
        print (" Authored and maintained by Hampus Hellsberg for 1oT OÜ")
        print (f"{Config.Colors.ENDC}")

        print (f"\n{Config.Colors.HEADER}=== Returning to SCP03 Shell ==={Config.Colors.ENDC}")
        print (f"{Config.Colors.WARNING}[*] Re-acquiring Card Reader...{Config.Colors.ENDC}")

        try :
            self .transport =CardTransporter ()
            self ._patch_transport ()

            self .gp_ctrl .tp =self .transport 
            self .fs_ctrl .tp =self .transport 
            self .sec_ctrl .tp =self .transport 

            self .transport .reset ()
            print (f"{Config.Colors.GREEN}[+] Card Reader Re-connected.{Config.Colors.ENDC}")
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Failed to reconnect reader: {e}{Config.Colors.ENDC}")

        self ._print_card_info ()
        self ._update_prompt_state ()

    def _run_stk_shell (self ,arg_line :str ="")->None :
        from SCP03 .interface .stk_shell import StkShell

        has_tp =False
        if self .transport :
            has_tp =True
        if has_tp ==False :
            print (f"{Config.Colors.FAIL}[-] No reader connected.{Config.Colors.ENDC}")
            return

        was_authenticated =False
        if self .transport .session :
            if self .transport .session .is_authenticated :
                was_authenticated =True
        if was_authenticated :
            print (
                f"{Config.Colors.WARNING}[!] Entering STK mode will close the active secure session "
                f"and use plain APDUs.{Config.Colors.ENDC}"
            )

        stk_shell =StkShell (self .transport ,debug =self .debug_mode )
        try :
            clean_arg =str (arg_line or "").strip ()
            if len (clean_arg )>0 :
                stk_shell .run_commands (clean_arg )
            else :
                stk_shell .run ()
        finally :
            try :
                self .transport .reset_session_state ()
            except Exception :
                pass
            try :
                self .fs_ctrl .current_fid =None
                self .fs_ctrl .current_fcp ={}
            except Exception :
                pass
            self ._clear_prompt_context_tracking ()
            self ._update_prompt_state ()

    def do_dump_fs (self ,arg :str ="")->None :
        """Dump the UICC file-system tree starting from the current DF to stdout."""
        import os 
        from pathlib import Path 

        output_dir =arg .strip ()

        is_empty =False 
        if len (output_dir )==0 :
            is_empty =True 

        if is_empty :
            prompt_msg ="Enter destination path (default: ~/Documents): "
            user_input =input (prompt_msg ).strip ()

            input_empty =False 
            if len (user_input )==0 :
                input_empty =True 

            if input_empty :
                default_docs =os .path .expanduser ("~/Documents")
                output_dir =str (Path (default_docs )/"FS_DUMP")

            has_input =False 
            if input_empty ==False :
                has_input =True 

            if has_input :
                expanded_input =os .path .expanduser (user_input )
                output_dir =str (Path (expanded_input )/"FS_DUMP")

        has_arg =False 
        if is_empty ==False :
            has_arg =True 

        if has_arg :
            expanded_arg =os .path .expanduser (output_dir )
            output_dir =str (Path (expanded_arg )/"FS_DUMP")

        try :
            self .fs_ctrl .dump_live_fs (output_dir )
        except Exception as error :
            print (f"[!] Command Execution Error: {error}")

    def _flush_pending_startup_stderr (self )->None :
        """Drain the one-shot startup notice buffer to stderr.

        Called from ``run`` after the screen-clear redraw and from the
        non-interactive ``run_commands`` / ``run_script`` surfaces
        before any command output, so operators on a real-reader
        backend always see the shipped-demo-keys banner.
        """
        notice =getattr (self ,"_pending_startup_stderr",None )
        if not notice :
            return 
        self ._pending_startup_stderr =None 
        message =str (notice ).rstrip ("\n")
        if len (message )==0 :
            return 
        sys .stderr .write (message +"\n")
        try :
            sys .stderr .flush ()
        except Exception :
            pass 

    def run (self ):
        """Start the interactive SCP03 shell REPL and block until the user exits."""
        self ._init_binder ()

        is_nt =False 
        if os .name =='nt':
            is_nt =True 

        if is_nt :
            os .system ('cls')

        is_posix =False 
        if is_nt ==False :
            is_posix =True 

        if is_posix :
            os .system ('clear')

        print (f"{Config.Colors.MINT}")
        print (r" __   __               _               ____ ___ __  __ ")
        print (r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print (r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print (r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print (r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print (r"      |___/  |___/                                     ")
        print (r"             _    ____  __  __ ___ _   _ ")
        print (r"            / \  |  _ \|  \/  |_ _| \ | |")
        print (r"           / _ \ | | | | |\/| || ||  \| |")
        print (r"          / ___ \| |_| | |  | || || |\  |")
        print (r"         /_/   \_\____/|_|  |_|___|_| \_|")
        print ("")
        print ("=== YggdraSIM Administration Shell ===")
        print (" [ GlobalPlatform | ETSI FS | SGP.22 eUICC | Telecom Auth ]")
        print (" Authored and maintained by Hampus Hellsberg for 1oT OÜ")
        print (f"{Config.Colors.MINT}")

        has_transport =False 
        if self .transport :
            has_transport =True 

        if has_transport :
            try :
                self ._print_card_info ()
            except Exception as e :
                print (f"{Config.Colors.FAIL}[!] Startup Check Failed: {e}{Config.Colors.ENDC}")

        # Surface any deferred startup notices now that the banner and
        # card info have been drawn; before this change they were emitted
        # during ``__init__`` and wiped by the clear-screen call above.
        self ._flush_pending_startup_stderr ()

        self ._update_prompt_state ()

        is_running =True 
        while is_running :
            try :
                line =input (self .prompt_str ).strip ()

                is_empty =False 
                if len (line )==0 :
                    is_empty =True 

                if is_empty :
                    continue 

                resolved_commands =self .binder .resolve (line )

                for cmd in resolved_commands :
                    is_modified =False 
                    if cmd !=line :
                        is_modified =True 

                    if is_modified :
                        print (f"{Config.Colors.CYAN}[*] Expanded Macro -> {cmd}{Config.Colors.ENDC}")

                    self ._exec_line (cmd )

            except KeyboardInterrupt :
                print ("\nType 'exit' to quit.")
            except Exception as e :
                print (f"{Config.Colors.FAIL}[-] Critical Error: {e}{Config.Colors.ENDC}")