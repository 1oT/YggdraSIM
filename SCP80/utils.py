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

import binascii

from yggdrasim_common.nord_palette import NordHex as _NordHex

class Colors :
    """ANSI terminal colours sourced from the canonical Nord palette."""

    @staticmethod 
    def _hex_to_ansi (hex_color ):
        hex_value =hex_color .lstrip ('#')
        red =int (hex_value [0 :2 ],16 )
        green =int (hex_value [2 :4 ],16 )
        blue =int (hex_value [4 :6 ],16 )
        return f'\033[38;2;{red};{green};{blue}m'

    HEADER_HEX =_NordHex .FROST_TEAL
    BLUE_HEX =_NordHex .FROST_BLUE
    CYAN_HEX =_NordHex .FROST_CYAN
    GREEN_HEX =_NordHex .AURORA_GREEN
    WARNING_HEX =_NordHex .AURORA_YELLOW
    FAIL_HEX =_NordHex .AURORA_RED

    HEADER =_hex_to_ansi .__func__ (HEADER_HEX )
    BLUE =_hex_to_ansi .__func__ (BLUE_HEX )
    CYAN =_hex_to_ansi .__func__ (CYAN_HEX )
    GREEN =_hex_to_ansi .__func__ (GREEN_HEX )
    WARNING =_hex_to_ansi .__func__ (WARNING_HEX )
    FAIL =_hex_to_ansi .__func__ (FAIL_HEX )
    ENDC ='\033[0m'
    BOLD ='\033[1m'

class Utils :
    @staticmethod 
    def to_bytes (hex_str :str )->bytes :
        normalized =''.join (str (hex_str ).split ())
        try :
            return binascii .unhexlify (normalized )
        except binascii .Error as exc :
            raise ValueError (f"Invalid hex input ({len(normalized)} chars): {normalized}")from exc

    @staticmethod 
    def to_hex (data :bytes ,space :bool =False )->str :
        s =data .hex ().upper ()
        if space :
            return ' '.join (s [i :i +2 ]for i in range (0 ,len (s ),2 ))
        return s 

    @staticmethod 
    def pad_key_3des (key :bytes )->bytes :
        return key if len (key )==24 else key +key [:8 ]