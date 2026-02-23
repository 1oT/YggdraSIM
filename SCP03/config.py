# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os 
import sys 
import shutil 

class Config :
    """Centralized configuration and constants."""

    BASE_DIR =os .path .dirname (os .path .abspath (__file__ ))


    if getattr (sys ,'frozen',False ):
        CONFIG_DIR =os .path .dirname (sys .executable )
    else :
        CONFIG_DIR =BASE_DIR 

    INI_FILE =os .path .join (CONFIG_DIR ,'keys.ini')
    FIDS_FILE =os .path .join (CONFIG_DIR ,'fids.txt')
    AID_FILE =os .path .join (CONFIG_DIR ,'aid.txt')
    BINDS_FILE =os .path .join (CONFIG_DIR ,'binds.json')


    if getattr (sys ,'frozen',False ):
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
    'kenc':'1122334455667788AABBCCDDEEFF0011',
    'kmac':'1122334455667788AABBCCDDEEFF0011',
    'dek':'1122334455667788AABBCCDDEEFF0011',
    'kvn':'30',
    'aid':'A0000005591010FFFFFFFF8900000100',
    'adm':'0000000000000000'
    }

    class Colors :
        HEADER ='\033[95m'
        BLUE ='\033[94m'
        CYAN ='\033[96m'
        GREEN ='\033[92m'
        YELLOW ='\033[93m'
        WARNING ='\033[93m'
        FAIL ='\033[91m'
        RED ='\033[91m'
        ENDC ='\033[0m'
        BOLD ='\033[1m'
        WHITE ='\033[97m'