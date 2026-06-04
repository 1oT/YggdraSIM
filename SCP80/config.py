# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 configuration manager: loads KIC/KID keys, algorithm selection, and TAR values from INI config."""
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

_DEMO_KEYS_WARNED =False 
_LEGACY_KEY_RENAME_NOTICE_SHOWN =False 


def enforce_demo_key_policy (kic :str ,kid :str )->None :
    """Warn / fail when OTA SCP80 key slots still carry the shipped weak placeholder.

    Slot names follow ETSI TS 102 225 §5.1.1: ``kic`` is the ciphering key,
    ``kid`` is the integrity (MAC) key. The 1-byte indicator bytes that
    select algorithm + key index live in ``kic_indicator`` / ``kid_indicator``.

    Environment flags:
    - YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 raises RuntimeError so a deployment
      script cannot accidentally ship an OTA packet MAC'd with placeholder keys.
    - YGGDRASIM_ALLOW_DEMO_KEYS=1 silences the warning for the current process.
    """
    global _DEMO_KEYS_WARNED 
    placeholder_kic =ConfigManager .DEFAULTS .get ("kic","")
    placeholder_kid =ConfigManager .DEFAULTS .get ("kid","")
    hits =[]
    if str (kic or "").strip ().upper ()==placeholder_kic .upper ():
        hits .append ("kic")
    if str (kid or "").strip ().upper ()==placeholder_kid .upper ():
        hits .append ("kid")
    if len (hits )==0 :
        return 
    require_flag =os .environ .get ("YGGDRASIM_REQUIRE_NON_DEMO_KEYS","").strip ().lower ()
    if require_flag in ("1","true","yes","on"):
        raise RuntimeError (
        "Refusing to build an SCP80 OTA packet with shipped demo keys in slots: "
        +", ".join (hits )
        +". Populate ota_config.ini with real values or unset "
        "YGGDRASIM_REQUIRE_NON_DEMO_KEYS."
        )
    allow_flag =os .environ .get ("YGGDRASIM_ALLOW_DEMO_KEYS","").strip ().lower ()
    if allow_flag in ("1","true","yes","on"):
        return 
    if _DEMO_KEYS_WARNED :
        return 
    _DEMO_KEYS_WARNED =True 
    sys .stderr .write (
    "[SCP80] WARNING: shipped demo keys active for slots: "
    +", ".join (hits )
    +". Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 "
    "to silence, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast.\n"
    )


def _emit_legacy_rename_notice (renamed :list )->None :
    global _LEGACY_KEY_RENAME_NOTICE_SHOWN 
    if _LEGACY_KEY_RENAME_NOTICE_SHOWN :
        return 
    if len (renamed )==0 :
        return 
    _LEGACY_KEY_RENAME_NOTICE_SHOWN =True 
    sys .stderr .write (
    "[SCP80] note: legacy config keys auto-migrated: "
    +", ".join (renamed )
    +". The on-disk record will be rewritten on next save.\n"
    )


class ConfigManager :
    MODULE_STATE_NAME ="scp80_config"
    INVENTORY_NAMESPACE ="scp80"
    PRINT_ICCID_SENTINEL ="NULL"
    TRANSPORT_MODES =("print","reader")
    INVENTORY_KEYS =(
    "cntr",
    "header",
    "spi",
    "kic_indicator",
    "kid_indicator",
    "tar",
    "kic",
    "kid",
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
    "kic_indicator":"15",
    "kid_indicator":"15",
    "tar":"B00000",
    "kic":"1111111111111111",
    "kid":"1111111111111111",
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
    "kic_indicator":2,
    "kid_indicator":2,
    "tar":6,
    "cla":2,
    "sender":2,
    }
    LEGACY_KEY_RENAMES ={
    "key_enc":"kic",
    "key_mac":"kid",
    }
    LEGACY_INDICATOR_HEX_LEN =2 
    KEY_MATERIAL_BYTE_LENGTHS =(8 ,16 ,24 ,32 )

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
        except OSError :
            pass 

    def load (self ):
        """Load the OTA configuration from the ini file and return the config object."""
        module_state =self .inventory .get_module_state (self .MODULE_STATE_NAME )
        if isinstance (module_state ,dict )and len (module_state )>0 :
            self ._apply_module_state_payload (module_state )
            return 

        if self .file_path .exists ():
            parser =ConfigParser ()
            parser .read (self .file_path )
            if "ota"in parser :
                ini_payload ={k :v for k ,v in parser ["ota"].items ()}
                migrated_payload ,rename_log =self ._migrate_legacy_keys (ini_payload )
                _emit_legacy_rename_notice (rename_log )
                for k ,v in migrated_payload .items ():
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
        """Associate an ICCID with a keyset profile in the runtime config."""
        raw_text =str (iccid or "").strip ()
        if raw_text .upper ()==self .PRINT_ICCID_SENTINEL :
            normalized_iccid =self .PRINT_ICCID_SENTINEL 
        else :
            normalized_iccid =''.join (ch for ch in raw_text if ch .isdigit ())
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
        migrated_payload ,rename_log =self ._migrate_legacy_keys (payload )
        _emit_legacy_rename_notice (rename_log )
        for key in self .INVENTORY_KEYS :
            if key not in migrated_payload :
                continue 
            try :
                self .data [key ]=self ._normalize_value (key ,migrated_payload [key ],strict =False )
            except Exception :
                continue 

    def inventory_payload (self )->dict :
        payload ={}
        for key in self .INVENTORY_KEYS :
            if key in self .data :
                payload [key ]=self .data [key ]
        return payload 

    def persist_inventory_profile (self )->None :
        """Write the current keyset profile assignment to the on-disk inventory."""
        if len (self .active_iccid )==0 :
            return 
        self .inventory .replace_namespace (
        "iccid",
        self .active_iccid ,
        self .INVENTORY_NAMESPACE ,
        self .inventory_payload (),
        )

    @classmethod 
    def _migrate_legacy_keys (cls ,payload :dict )->tuple :
        """Translate pre-rename SCP80 config keys onto the current schema.

        - ``key_enc`` / ``key_mac`` (legacy 16-byte session-key slots) move
          to ``kic`` / ``kid``.
        - 2-hex-char values previously stored under ``kic`` / ``kid``
          (the ETSI TS 102 225 §5.1.1 indicator bytes) move to
          ``kic_indicator`` / ``kid_indicator``.
        Returns ``(migrated_payload, rename_log)`` where ``rename_log`` is a
        list of ``"old -> new"`` strings consumed by the one-shot stderr
        notice.
        """
        migrated =dict (payload )
        rename_log =[]
        for short ,long_name in (("kic","kic_indicator"),("kid","kid_indicator")):
            if short not in migrated :
                continue 
            value =str (migrated [short ]or "").strip ()
            is_legacy_indicator =len (value )==cls .LEGACY_INDICATOR_HEX_LEN 
            already_set =long_name in migrated 
            if is_legacy_indicator and already_set ==False :
                migrated [long_name ]=migrated .pop (short )
                rename_log .append (f"{short} -> {long_name}")
        for legacy_key ,new_key in cls .LEGACY_KEY_RENAMES .items ():
            if legacy_key not in migrated :
                continue 
            if new_key not in migrated :
                migrated [new_key ]=migrated [legacy_key ]
                rename_log .append (f"{legacy_key} -> {new_key}")
            del migrated [legacy_key ]
        return migrated ,rename_log 

    def _module_state_payload (self )->dict :
        return dict (self .data )

    def _apply_module_state_payload (self ,payload :dict )->None :
        migrated_payload ,rename_log =self ._migrate_legacy_keys (payload )
        _emit_legacy_rename_notice (rename_log )
        for key ,value in migrated_payload .items ():
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
            normalized =str (value or "").strip ().lower ()
            if normalized in self .TRANSPORT_MODES :
                return normalized 
            if strict :
                raise ValueError ("transport must be 'print' or 'reader'.")
            return self .DEFAULTS [key ]
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
            if key in ("kic","kid"):
                byte_len =len (normalized )//2
                if byte_len in self .KEY_MATERIAL_BYTE_LENGTHS :
                    return normalized
                allowed =", ".join (str (length )for length in self .KEY_MATERIAL_BYTE_LENGTHS )
                if strict :
                    raise ValueError (f"{key} must be {allowed} bytes.")
                return self .DEFAULTS .get (key ,"")
            return normalized
        if strict :
            raise ValueError (f"{key} must contain only hex chars.")
        return self .DEFAULTS .get (key ,"")

    def get_int (self ,key :str )->int :
        try :return int (self .data .get (key ,"0"),10 )
        except ValueError :return 0 

    def increment_counter (self ):
        """Increment and return the OTA message counter for the active keyset."""
        try :
            val =int (self .data ["cntr"],16 )
            val =(val +1 )&0xFFFFFFFFFF 
            self .data ["cntr"]=f"{val:010X}"
            self .save ()
        except ValueError :
            self .data ["cntr"]="0000000001"
            self .save ()
