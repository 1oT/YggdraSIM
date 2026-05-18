# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP03 key configuration: loads static key sets (ENC, MAC, DEK) from environment or config file."""
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

import os 
import configparser 

from yggdrasim_common.runtime_paths import bundle_path, ensure_seeded_workspace_file, ensure_workspace_dir
from yggdrasim_common.nord_palette import NordHex as _NordHex

try :
    from yggdrasim_common.device_inventory import DeviceInventoryStore 
except ImportError :
    DeviceInventoryStore =None 

class Config :
    """Centralized configuration and constants."""

    BASE_DIR =bundle_path ("Workspace","SCP03")
    CONFIG_DIR =ensure_workspace_dir ("SCP03")

    INI_FILE =ensure_seeded_workspace_file (("SCP03","seeds","keys.ini"),"SCP03","keys.ini")
    FIDS_FILE =ensure_seeded_workspace_file (("SCP03","seeds","fids.txt"),"SCP03","fids.txt")
    AID_FILE =ensure_seeded_workspace_file (("SCP03","seeds","aid.txt"),"SCP03","aid.txt")
    BINDS_FILE =ensure_seeded_workspace_file (("SCP03","seeds","binds.json"),"SCP03","binds.json")

    DEFAULT_KEYS ={
    'scp03_kenc':'1122334455667788AABBCCDDEEFF0011',
    'scp03_kmac':'1122334455667788AABBCCDDEEFF0011',
    'scp03_dek':'1122334455667788AABBCCDDEEFF0011',
    'scp03_kvn':'30',
    'scp02_enc':'1122334455667788AABBCCDDEEFF0011',
    'scp02_mac':'1122334455667788AABBCCDDEEFF0011',
    'scp02_dek':'1122334455667788AABBCCDDEEFF0011',
    'scp02_kvn':'20',
    'aid':'A0000005591010FFFFFFFF8900000100',
    'adm':'0000000000000000'
    }

    DEMO_KEY_SLOTS =(
    'scp03_kenc','scp03_kmac','scp03_dek',
    'scp02_enc','scp02_mac','scp02_dek',
    )

    MODULE_STATE_NAME ="scp03_config"

    class Colors :
        """ANSI terminal colours sourced from the canonical Nord palette.

        The SCP03 banner intentionally swaps the launcher's frost-teal
        header for aurora-purple to keep the protocol header visually
        distinct from the SCP11 / SAIP shells.
        """

        @staticmethod
        def _hex_to_ansi (hex_color ):
            hex_value =hex_color .lstrip ('#')
            red =int (hex_value [0 :2 ],16 )
            green =int (hex_value [2 :4 ],16 )
            blue =int (hex_value [4 :6 ],16 )
            return f'\033[38;2;{red};{green};{blue}m'

        HEADER_HEX =_NordHex .AURORA_PURPLE
        BLUE_HEX =_NordHex .FROST_BLUE
        CYAN_HEX =_NordHex .FROST_CYAN
        GREEN_HEX =_NordHex .AURORA_GREEN
        YELLOW_HEX =_NordHex .AURORA_YELLOW
        WARNING_HEX =YELLOW_HEX
        FAIL_HEX =_NordHex .AURORA_RED
        RED_HEX =FAIL_HEX
        WHITE_HEX =_NordHex .SNOW_2
        MINT_HEX =_NordHex .FROST_TEAL

        HEADER =_hex_to_ansi .__func__ (HEADER_HEX )
        BLUE =_hex_to_ansi .__func__ (BLUE_HEX )
        CYAN =_hex_to_ansi .__func__ (CYAN_HEX )
        GREEN =_hex_to_ansi .__func__ (GREEN_HEX )
        YELLOW =_hex_to_ansi .__func__ (YELLOW_HEX )
        WARNING =_hex_to_ansi .__func__ (WARNING_HEX )
        FAIL =_hex_to_ansi .__func__ (FAIL_HEX )
        RED =_hex_to_ansi .__func__ (RED_HEX )
        WHITE =_hex_to_ansi .__func__ (WHITE_HEX )
        MINT =_hex_to_ansi .__func__ (MINT_HEX )
        ENDC ='\033[0m'
        BOLD ='\033[1m'


_DEMO_KEYS_WARNED =False 


def detect_demo_key_slots (config_keys )->list :
    """Return the list of key slot names currently set to the shipped demo placeholder."""
    placeholder =Config .DEFAULT_KEYS .get ('scp03_kenc','')
    hits =[]
    for slot_name in Config .DEMO_KEY_SLOTS :
        value =str (config_keys .get (slot_name ,Config .DEFAULT_KEYS .get (slot_name ,''))or '').strip ().upper ()
        if value ==placeholder .upper ():
            hits .append (slot_name )
    return hits 


def enforce_demo_key_policy (config_keys ,backend_label :str =""):
    """Warn (always) / fail (opt-in) when the active keyset is still the demo placeholder.

    Behavior:
    - Simulator backend: no warning (demo keys are the intended default).
      Returns ``None``.
    - Any other backend: build a one-shot banner listing the slots using
      the demo placeholder and return it as a string. The caller owns
      when and where to surface it; the previous stderr-write-at-call-
      time path got clobbered by the shell's screen-clear redraw.
    - If YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 is set, raise RuntimeError so
      production-style deployments cannot start with shipped placeholders.
    - YGGDRASIM_ALLOW_DEMO_KEYS=1 silences the warning for the current process.
    - The one-shot guard (``_DEMO_KEYS_WARNED``) still fires: subsequent
      calls in the same process return ``None`` once the caller has
      drained the first banner, matching the previous observable
      behaviour for batch / report surfaces that re-enter the dispatcher.
    """
    global _DEMO_KEYS_WARNED 
    label =str (backend_label or '').strip ().lower ()
    if label =='sim'or label =='simulator':
        return None 
    hits =detect_demo_key_slots (config_keys )
    if len (hits )==0 :
        return None 
    require_flag =os .environ .get ('YGGDRASIM_REQUIRE_NON_DEMO_KEYS','').strip ().lower ()
    if require_flag in ('1','true','yes','on'):
        raise RuntimeError (
        "Refusing to open a secure channel with shipped demo keys in slots: "
        +", ".join (hits )
        +". Populate SCP03/keys.ini (or the inventory store) with real values "
        "before starting, or unset YGGDRASIM_REQUIRE_NON_DEMO_KEYS."
        )
    allow_flag =os .environ .get ('YGGDRASIM_ALLOW_DEMO_KEYS','').strip ().lower ()
    if allow_flag in ('1','true','yes','on'):
        return None 
    if _DEMO_KEYS_WARNED :
        return None 
    _DEMO_KEYS_WARNED =True 
    return (
    "[SCP03] WARNING: shipped demo keys active for slots: "
    +", ".join (hits )
    +". Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 "
    "to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail "
    "fast when placeholders are present."
    )


def _legacy_scp03_parser ()->configparser .ConfigParser :
    parser =configparser .ConfigParser ()
    if os .path .exists (Config .INI_FILE ):
        parser .read (Config .INI_FILE )
    if 'KEYS'not in parser :
        parser ['KEYS']={}
    legacy_map ={
    'kenc':'scp03_kenc',
    'enc':'scp03_kenc',
    'kmac':'scp03_kmac',
    'mac':'scp03_kmac',
    'dek':'scp03_dek',
    'kvn':'scp03_kvn'
    }
    for legacy_key ,new_key in legacy_map .items ():
        if legacy_key in parser ['KEYS']and new_key not in parser ['KEYS']:
            parser ['KEYS'][new_key ]=parser ['KEYS'][legacy_key ]
    for key_name ,default_value in Config .DEFAULT_KEYS .items ():
        if key_name not in parser ['KEYS']:
            parser ['KEYS'][key_name ]=default_value 
    if 'GOLD_PROFILE'not in parser :
        parser ['GOLD_PROFILE']={}
    gold_sec =parser ['GOLD_PROFILE']
    if 'path'not in gold_sec :
        gold_sec ['path']=''
    if 'standard'not in gold_sec :
        gold_sec ['standard']='SGP.32'
    if 'authenticate_sd'not in gold_sec :
        gold_sec ['authenticate_sd']='false'
    return parser 


def load_scp03_runtime_parser ()->configparser .ConfigParser :
    """Build and return an argparse parser pre-loaded with SCP03 runtime flags."""
    parser =_legacy_scp03_parser ()
    if DeviceInventoryStore is None :
        return parser 
    try :
        inventory =DeviceInventoryStore ()
        payload =inventory .get_module_state (Config .MODULE_STATE_NAME )
    except Exception :
        return parser 
    if isinstance (payload ,dict )==False or len (payload )==0 :
        return parser 
    keys_payload =payload .get ('KEYS',{})
    if isinstance (keys_payload ,dict ):
        for key_name ,value in keys_payload .items ():
            parser ['KEYS'][str (key_name )]=str (value )
    gold_payload =payload .get ('GOLD_PROFILE',{})
    if isinstance (gold_payload ,dict ):
        for key_name ,value in gold_payload .items ():
            parser ['GOLD_PROFILE'][str (key_name )]=str (value )
    return parser 