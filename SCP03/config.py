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
import sys 
import shutil 
import configparser 

from yggdrasim_common.runtime_paths import bundle_path, ensure_runtime_dir, runtime_path

try :
    from yggdrasim_common.device_inventory import DeviceInventoryStore 
except ImportError :
    DeviceInventoryStore =None 

class Config :
    """Centralized configuration and constants."""

    BASE_DIR =bundle_path ("SCP03")
    CONFIG_DIR =ensure_runtime_dir ("SCP03")

    INI_FILE =os .path .join (CONFIG_DIR ,'keys.ini')
    FIDS_FILE =os .path .join (CONFIG_DIR ,'fids.txt')
    AID_FILE =os .path .join (CONFIG_DIR ,'aid.txt')
    BINDS_FILE =os .path .join (CONFIG_DIR ,'binds.json')


    for filename in ['fids.txt','aid.txt','keys.ini']:
        user_path =os .path .join (CONFIG_DIR ,filename )
        bundled_path =os .path .join (BASE_DIR ,filename )
        if not os .path .exists (user_path )and os .path .exists (bundled_path ):
            try :
                shutil .copy2 (bundled_path ,user_path )
            except Exception as e :
                print (f"Warning: Could not copy default {filename} to {CONFIG_DIR}: {e}")


    user_binds_path =os .path .join (CONFIG_DIR ,'binds.json')
    bundled_binds_candidates =[
    os .path .join (BASE_DIR ,'binds.json')
    ]
    if not os .path .exists (user_binds_path ):
        for bundled_binds_path in bundled_binds_candidates :
            has_bundled =os .path .exists (bundled_binds_path )
            if has_bundled :
                try :
                    shutil .copy2 (bundled_binds_path ,user_binds_path )
                except Exception as e :
                    print (f"Warning: Could not copy default binds.json to {CONFIG_DIR}: {e}")
                break 

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

    MODULE_STATE_NAME ="scp03_config"

    class Colors :
        """ANSI terminal colors derived from hex palette values."""

        @staticmethod
        def _hex_to_ansi (hex_color ):
            hex_value =hex_color .lstrip ('#')
            red =int (hex_value [0 :2 ],16 )
            green =int (hex_value [2 :4 ],16 )
            blue =int (hex_value [4 :6 ],16 )
            return f'\033[38;2;{red};{green};{blue}m'

        HEADER_HEX ='#FF8FFF'
        BLUE_HEX ='#8AA7FF'
        CYAN_HEX ='#93F7FF'
        GREEN_HEX ='#8DFF8D'
        YELLOW_HEX ='#FFF08F'
        WARNING_HEX =YELLOW_HEX
        FAIL_HEX ='#FF9A9A'
        RED_HEX =FAIL_HEX
        WHITE_HEX ='#F7FCFF'
        MINT_HEX ='#5FDCCB'

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