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

from typing import List ,Dict ,Any ,Union 

class HexUtils :
    """Static helpers for byte manipulation."""
    @staticmethod 
    def to_bytes (data :Union [str ,bytes ,List [int ]])->bytes :
        if isinstance (data ,bytes ):return data 
        if isinstance (data ,list ):return bytes (data )

        clean =data .strip ().replace (' ','').replace (':','').replace ('0x','')
        return bytes .fromhex (clean )

    @staticmethod 
    def to_hex (data :bytes ,space :bool =False )->str :
        s =data .hex ().upper ()
        return ' '.join (s [i :i +2 ]for i in range (0 ,len (s ),2 ))if space else s 

class TlvParser :
    """TLV decoder with multi-byte tag support."""
    @staticmethod 
    def get_first (parsed :Dict [int ,Any ],tag :int ,default :Any =None )->Any :
        """
        Return the first value for a tag from parsed TLV dict.
        Supports duplicate-tag representation where parsed[tag] may be a list.
        """
        if tag not in parsed :
            return default 
        value =parsed [tag ]
        if isinstance (value ,list ):
            if len (value )==0 :
                return default 
            return value [0 ]
        return value 

    @staticmethod 
    def as_list (value :Any )->List [Any ]:
        """Normalize parsed TLV value to list form."""
        if value is None :
            return []
        if isinstance (value ,list ):
            return value 
        return [value ]

    @staticmethod 
    def _store_tag (parsed :Dict [int ,Any ],tag_val :int ,value :Any )->None :
        """
        Store TLV value while preserving duplicate tags.
        - First occurrence: parsed[tag] = value
        - Repeated occurrence: parsed[tag] = [first, second, ...]
        """
        has_tag =False 
        if tag_val in parsed :
            has_tag =True 

        if has_tag ==False :
            parsed [tag_val ]=value 
            return 

        current =parsed [tag_val ]
        if isinstance (current ,list ):
            current .append (value )
            return 

        parsed [tag_val ]=[current ,value ]

    @staticmethod 
    def parse_detailed (data :bytes )->Dict [str ,Any ]:
        i ,parsed =0 ,{}
        while i <len (data ):
            item_offset =i 
            if i >=len (data ):
                break 

            tag_val =data [i ]
            i +=1 

            if (tag_val &0x1F )==0x1F :
                tag_val =tag_val <<8 
                saw_terminal =False 
                while i <len (data ):
                    next_byte =data [i ]
                    tag_val |=next_byte 
                    i +=1 
                    if not (next_byte &0x80 ):
                        saw_terminal =True 
                        break 
                    tag_val =tag_val <<8 
                if saw_terminal ==False :
                    return {"parsed":parsed ,"consumed":item_offset ,"complete":False ,"error":"Truncated multi-byte tag."}

            if i >=len (data ):
                return {"parsed":parsed ,"consumed":item_offset ,"complete":False ,"error":"Missing TLV length field."}

            length =data [i ]
            i +=1 

            if length &0x80 :
                n_bytes =length &0x7F 
                if n_bytes ==0 :
                    return {"parsed":parsed ,"consumed":item_offset ,"complete":False ,"error":"Indefinite BER length is not supported."}
                if i +n_bytes >len (data ):
                    return {"parsed":parsed ,"consumed":item_offset ,"complete":False ,"error":"Truncated BER length field."}
                length =int .from_bytes (data [i :i +n_bytes ],'big')
                i +=n_bytes 

            if i +length >len (data ):
                return {"parsed":parsed ,"consumed":item_offset ,"complete":False ,"error":"TLV value overruns input buffer."}
            val =data [i :i +length ]
            i +=length 

            first_tag_byte =tag_val 
            while first_tag_byte >0xFF :
                first_tag_byte >>=8 

            if first_tag_byte &0x20 :
                nested_info =TlvParser .parse_detailed (val )
                nested =nested_info ["parsed"]
                if nested_info ["complete"]and nested_info ["consumed"]==len (val ):
                    TlvParser ._store_tag (parsed ,tag_val ,nested )
                else :
                    TlvParser ._store_tag (parsed ,tag_val ,val )
            else :
                TlvParser ._store_tag (parsed ,tag_val ,val )

        return {"parsed":parsed ,"consumed":i ,"complete":True ,"error":None }

    @staticmethod 
    def parse (data :bytes )->Dict [int ,Any ]:
        return TlvParser .parse_detailed (data )["parsed"]

class StatusWordTranslator :
    """Translates ISO 7816-4 and GlobalPlatform Status Words into human-readable strings."""

    SW_MAP ={
    0x9000 :"Success",
    0x6100 :"More data available",
    0x6283 :"Selected file invalidated",
    0x6300 :"Authentication failed",
    0x6310 :"More data available (GET STATUS continuation)",
    0x6400 :"State of non-volatile memory unchanged",
    0x6700 :"Wrong length",
    0x6881 :"Logical channel not supported",
    0x6882 :"Secure messaging not supported",
    0x6982 :"Security status not satisfied",
    0x6983 :"Authentication method blocked",
    0x6984 :"Referenced data invalidated",
    0x6985 :"Conditions of use not satisfied",
    0x6A80 :"Incorrect parameters in data field",
    0x6A81 :"Function not supported",
    0x6A82 :"File not found / Applet not found",
    0x6A83 :"Record not found",
    0x6A84 :"Not enough memory space in file",
    0x6A86 :"Incorrect parameters P1-P2",
    0x6A88 :"Referenced data not found",
    0x6D00 :"Instruction code not supported or invalid",
    0x6E00 :"Class not supported",
    0x6F00 :"Unknown error / No precise diagnosis"
    }

    @staticmethod 
    def translate (sw1 :int ,sw2 :int )->str :
        sw =(sw1 <<8 )|sw2 

        if sw in StatusWordTranslator .SW_MAP :
            return StatusWordTranslator .SW_MAP [sw ]

        if sw1 ==0x61 :
            return f"Success. {sw2} bytes of data available to read."

        if sw1 ==0x6C :
            return f"Wrong Le length. Correct length is {sw2}."

        if sw1 ==0x63 :
            if (sw2 &0xF0 )==0xC0 :
                retries =sw2 &0x0F 
                return f"Verification failed. {retries} retries remaining."

        return "Unknown Status"