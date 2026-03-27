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

import sys 
import os 
from pathlib import Path 
from configparser import ConfigParser 

from yggdrasim_common.runtime_paths import bundle_path, ensure_runtime_dir

try :
    from yggdrasim_common.device_inventory import DeviceInventoryStore 
except ImportError :
    repo_root =Path (__file__ ).resolve ().parent .parent 
    if str (repo_root )not in sys .path :
        sys .path .insert (0 ,str (repo_root ))
    from yggdrasim_common.device_inventory import DeviceInventoryStore 

class ConfigManager :
    MODULE_STATE_NAME ="scp80_config"
    INVENTORY_NAMESPACE ="scp80"
    INVENTORY_KEYS =(
    "cntr",
    "header",
    "spi",
    "kic",
    "kid",
    "tar",
    "key_enc",
    "key_mac",
    "cla",
    "sender",
    "concat_sms",
    "tp_ud_max",
    )
    DEFAULTS ={
    "cntr":"0000000001",
    "header":"447FF600000000000000",
    "payload":"",
    "spi":"1621",
    "kic":"15",
    "kid":"15",
    "tar":"B00000",
    "key_enc":"1111111111111111",
    "key_mac":"1111111111111111",
    "cla":"80",
    "transport":"print",
    "reader_idx":"0",
    "sender":"82",
    "concat_sms":"ON",
    "tp_ud_max":"140",
    }
    HEX_LENGTHS ={
    "cntr":10,
    "spi":4,
    "kic":2,
    "kid":2,
    "tar":6,
    "cla":2,
    "sender":2,
    }

    def __init__ (self ):
        self .file_path =self ._resolve_config_path ()
        self .data =self .DEFAULTS .copy ()
        self .inventory =DeviceInventoryStore ()
        self .active_iccid =""
        self ._copy_bundled_default_if_missing ()
        self .load ()

    def _resolve_config_path (self )->Path :
        base =Path (ensure_runtime_dir ("SCP80"))
        return base /"ota_config.ini"

    def _copy_bundled_default_if_missing (self ):
        has_user_file =False 
        if self .file_path .exists ():
            has_user_file =True 
        if has_user_file :
            return 
        bundled_dir =Path (bundle_path ("SCP80"))
        bundled_default =bundled_dir /"ota_config.ini"
        has_bundled_default =False 
        if bundled_default .exists ():
            has_bundled_default =True 
        if has_bundled_default ==False :
            return 
        try :
            self .file_path .write_text (bundled_default .read_text ())
        except Exception :
            pass 

    def load (self ):
        module_state =self .inventory .get_module_state (self .MODULE_STATE_NAME )
        if isinstance (module_state ,dict )and len (module_state )>0 :
            self ._apply_module_state_payload (module_state )
            return 

        if self .file_path .exists ():
            parser =ConfigParser ()
            parser .read (self .file_path )
            if "ota"in parser :
                for k ,v in parser ["ota"].items ():
                    if k in self .data :
                        self .data [k ]=self ._normalize_value (k ,v ,strict =False )
        self ._persist_module_state ()

    def save (self ):
        self ._persist_module_state ()
        self .persist_inventory_profile ()

    def get (self ,key :str )->str :
        return self .data .get (key ,self .DEFAULTS .get (key ,""))

    def set (self ,key :str ,value :str ):
        if key in self .data :
            self .data [key ]=self ._normalize_value (key ,value ,strict =True )

    def bind_iccid_profile (self ,iccid :str )->dict :
        normalized_iccid =''.join (ch for ch in str (iccid or "")if ch .isdigit ())
        if len (normalized_iccid )==0 :
            self .active_iccid =""
            return {}
        self .active_iccid =normalized_iccid 
        payload =self .inventory .get_namespace ("iccid",normalized_iccid ,self .INVENTORY_NAMESPACE )
        if isinstance (payload ,dict )and len (payload )>0 :
            self ._apply_inventory_payload (payload )
            return payload 
        self .persist_inventory_profile ()
        return {}

    def _apply_inventory_payload (self ,payload :dict )->None :
        for key in self .INVENTORY_KEYS :
            if key not in payload :
                continue 
            try :
                self .data [key ]=self ._normalize_value (key ,payload [key ],strict =False )
            except Exception :
                continue 

    def inventory_payload (self )->dict :
        payload ={}
        for key in self .INVENTORY_KEYS :
            if key in self .data :
                payload [key ]=self .data [key ]
        return payload 

    def persist_inventory_profile (self )->None :
        if len (self .active_iccid )==0 :
            return 
        self .inventory .replace_namespace (
        "iccid",
        self .active_iccid ,
        self .INVENTORY_NAMESPACE ,
        self .inventory_payload (),
        )

    def _module_state_payload (self )->dict :
        return dict (self .data )

    def _apply_module_state_payload (self ,payload :dict )->None :
        for key ,value in payload .items ():
            if key not in self .data :
                continue 
            try :
                self .data [key ]=self ._normalize_value (key ,value ,strict =False )
            except Exception :
                continue 

    def _persist_module_state (self )->None :
        self .inventory .replace_module_state (self .MODULE_STATE_NAME ,self ._module_state_payload ())

    def _normalize_value (self ,key :str ,value ,strict :bool =False )->str :
        if key =="transport":
            return str (value )
        if key =="concat_sms":
            normalized =str (value ).strip ().upper ()
            if normalized in ["ON","OFF","TRUE","FALSE","YES","NO","1","0"]:
                if normalized in ["ON","TRUE","YES","1"]:
                    return "ON"
                return "OFF"
            if strict :
                raise ValueError ("concat_sms must be ON or OFF.")
            return self .DEFAULTS [key ]
        if key =="tp_ud_max":
            normalized =str (value ).strip ()
            try :
                int_value =int (normalized ,10 )
            except ValueError :
                if strict :
                    raise ValueError ("tp_ud_max must be a decimal value between 8 and 140.")
                return self .DEFAULTS [key ]
            if 8 <=int_value <=140 :
                return str (int_value )
            if strict :
                raise ValueError ("tp_ud_max must be between 8 and 140.")
            return self .DEFAULTS [key ]

        normalized =''.join (str (value ).split ()).upper ()
        if key =="reader_idx":
            return normalized

        expected_len =self .HEX_LENGTHS .get (key )
        if expected_len is not None :
            is_valid_len =len (normalized )==expected_len 
            is_valid_hex =all (c in "0123456789ABCDEF"for c in normalized )
            if is_valid_len and is_valid_hex :
                return normalized
            if strict :
                raise ValueError (f"{key} must be exactly {expected_len} hex chars.")
            return self .DEFAULTS [key ]

        if len (normalized )%2 !=0 :
            if strict :
                raise ValueError (f"{key} must contain a whole number of bytes.")
            return self .DEFAULTS .get (key ,"")

        is_valid_hex =all (c in "0123456789ABCDEF"for c in normalized )
        if is_valid_hex :
            return normalized
        if strict :
            raise ValueError (f"{key} must contain only hex chars.")
        return self .DEFAULTS .get (key ,"")

    def get_int (self ,key :str )->int :
        try :return int (self .data .get (key ,"0"),10 )
        except ValueError :return 0 

    def increment_counter (self ):
        try :
            val =int (self .data ["cntr"],16 )
            val =(val +1 )&0xFFFFFFFFFF 
            self .data ["cntr"]=f"{val:010X}"
            self .save ()
        except ValueError :
            self .data ["cntr"]="0000000001"
            self .save ()