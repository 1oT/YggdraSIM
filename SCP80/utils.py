# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import binascii 

class Colors :
    HEADER ='\033[95m'
    BLUE ='\033[94m'
    CYAN ='\033[96m'
    GREEN ='\033[92m'
    WARNING ='\033[93m'
    FAIL ='\033[91m'
    ENDC ='\033[0m'
    BOLD ='\033[1m'

class Utils :
    @staticmethod 
    def to_bytes (hex_str :str )->bytes :
        return binascii .unhexlify (hex_str .replace (" ","").strip ())

    @staticmethod 
    def to_hex (data :bytes ,space :bool =False )->str :
        s =data .hex ().upper ()
        if space :
            return ' '.join (s [i :i +2 ]for i in range (0 ,len (s ),2 ))
        return s 

    @staticmethod 
    def pad_key_3des (key :bytes )->bytes :
        return key if len (key )==24 else key +key [:8 ]