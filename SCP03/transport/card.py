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

import traceback 
from typing import Tuple ,List ,Optional 
from smartcard .System import readers 
from smartcard .CardConnection import CardConnection 


from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils 
from SCP03 .crypto .session import Scp03Session 

class CardTransporter :
    FI_TABLE ={
    0x1 :(372 ,5 ),
    0x2 :(558 ,6 ),
    0x3 :(744 ,8 ),
    0x4 :(1116 ,12 ),
    0x5 :(1488 ,16 ),
    0x6 :(1860 ,20 ),
    0x9 :(512 ,5 ),
    0xA :(768 ,7.5 ),
    0xB :(1024 ,10 ),
    0xC :(1536 ,15 ),
    0xD :(2048 ,20 ),
    }
    DI_TABLE ={
    0x1 :1 ,
    0x2 :2 ,
    0x3 :4 ,
    0x4 :8 ,
    0x5 :16 ,
    0x6 :32 ,
    0x8 :12 ,
    0x9 :20 ,
    }

    def __init__ (self ):
        self .connection :Optional [CardConnection ]=None 
        self .session =Scp03Session ({'kenc':b'','kmac':b'','dek':b''})
        self .verbose =False 
        self .debug =False 
        if not self .connect ():raise Exception ("Could not connect to a smart card reader.")

    def connect (self )->bool :
        try :
            r_list =readers ()

            is_empty =False 
            if not r_list :
                is_empty =True 

            if is_empty :
                print (f"{Config.Colors.FAIL}[!] No readers found.{Config.Colors.ENDC}")
                return False 

            reader =r_list [0 ]
            print (f"{Config.Colors.CYAN}[*] CONNECTED{Config.Colors.ENDC}")

            self .connection =reader .createConnection ()
            self .connection .connect ()

            return True 
        except Exception as e :
            print (f"{Config.Colors.FAIL}[!] Connection failed: {e}{Config.Colors.ENDC}")
            self .connection =None 
            return False 

    def disconnect (self ):
        if self .connection :self .connection .disconnect ()
        self ._reset_session_state ()

    def logout (self )->bool :
        if not self .session :return False 
        was_active =bool (self .session .is_authenticated )
        self ._reset_session_state ()
        return was_active 

    def _reset_session_state (self )->None :
        if not self .session :
            return 
        has_method =False 
        if hasattr (self .session ,'reset_state'):
            has_method =True 
        if has_method :
            self .session .reset_state ()
            return 
        self .session .is_authenticated =False 
        if hasattr (self .session ,'chaining_value'):
            self .session .chaining_value =b'\x00'*16 
        if hasattr (self .session ,'ssc'):
            self .session .ssc =0 

    def reset_session_state (self )->None :
        self ._reset_session_state ()

    def reset (self )->bool :
        if self .connection is None :return self .connect ()
        try :
            self .connection .disconnect ()
            self .connection .connect ()
            return True 
        except Exception as e :
            print (f"{Config.Colors.FAIL}[-] Reset Error: {e}{Config.Colors.ENDC}")
            return False 

    def get_atr_bytes (self )->bytes :
        if self .connection is None :
            return b""
        try :
            return bytes (self .connection .getATR ())
        except Exception :
            return b""

    @staticmethod
    def _format_atr_bytes (atr_bytes :bytes )->str :
        return " ".join (f"{b:02X}"for b in atr_bytes )

    @classmethod
    def _decode_ta1 (cls ,value :int )->List [str ]:
        lines :List [str ]=[]
        fi_idx =(value >>4 )&0x0F 
        di_idx =value &0x0F 
        fi_entry =cls .FI_TABLE .get (fi_idx )
        di_entry =cls .DI_TABLE .get (di_idx )
        if fi_entry is None or di_entry is None :
            lines .append (f"    TA(1) raw decode unavailable for {value:02X}")
            return lines 

        fi ,fmax =fi_entry 
        di =di_entry 
        etu_cycles =fi /di 
        nominal_rate =(di *4000000 )/fi 
        max_rate =(di *(fmax *1000000 ))/fi 
        lines .append (f"    TA(1) = {value:02X} --> Fi={fi}, Di={di}, {etu_cycles:g} cycles/ETU")
        lines .append (f"      {nominal_rate:g} bits/s at 4 MHz, fMax for Fi = {fmax:g} MHz => {max_rate:g} bits/s")
        return lines 

    @staticmethod
    def _decode_ta3 (value :int )->str :
        clock_stop_bits =(value >>6 )&0x03 
        clock_stop ="not supported"
        if clock_stop_bits ==1 :
            clock_stop ="state L"
        if clock_stop_bits ==2 :
            clock_stop ="state H"
        if clock_stop_bits ==3 :
            clock_stop ="no preference"

        classes :List [str ]=[]
        if value &0x01 :
            classes .append ("A 5V")
        if value &0x02 :
            classes .append ("B 3V")
        if value &0x04 :
            classes .append ("C 1.8V")

        class_text ="not indicated"
        if len (classes )>0 :
            class_text ="(3G) " +" ".join (classes )
        return f"  TA(3) = {value:02X} --> Clock stop: {clock_stop} - Class accepted by the card: {class_text}"

    @staticmethod
    def _protocol_label (protocol :int )->str :
        if protocol ==15 :
            return "15 - Global interface bytes following"
        return str (protocol )

    @staticmethod
    def _decode_card_service_data (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Card service data byte: {value:02X}")
        if value &0x80 :
            lines .append ("        - Application selection: by full DF name")
        if value &0x40 :
            lines .append ("        - Application selection: by partial DF name")
        if value &0x20 :
            lines .append ("        - BER-TLV data objects available in EF.DIR")
        if value &0x10 :
            lines .append ("        - EF.DIR and EF.ATR access services: by GET RECORD(s) command")
        if value &0x08 :
            lines .append ("        - Card with MF")
        return lines 

    @staticmethod
    def _decode_selection_methods (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Selection methods: {value:02X}")
        if value &0x80 :
            lines .append ("        - DF selection by full DF name")
        if value &0x40 :
            lines .append ("        - DF selection by partial DF name")
        if value &0x20 :
            lines .append ("        - DF selection by path")
        if value &0x10 :
            lines .append ("        - DF selection by file identifier")
        if value &0x08 :
            lines .append ("        - Implicit DF selection")
        if value &0x04 :
            lines .append ("        - Short EF identifier supported")
        if value &0x02 :
            lines .append ("        - Record number supported")
        if value &0x01 :
            lines .append ("        - Record identifier supported")
        return lines 

    @staticmethod
    def _decode_data_coding (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Data coding byte: {value:02X}")
        write_mode ={0 :"one-time write",1 :"proprietary",2 :"OR",3 :"AND"}.get ((value >>5 )&0x03 ,"unknown")
        lines .append (f"        - Behaviour of write functions: {write_mode}")
        ff_rule ="invalid"
        if value &0x10 :
            ff_rule ="valid"
        lines .append (f"        - Value 'FF' for the first byte of BER-TLV tag fields: {ff_rule}")
        unit_power =value &0x0F 
        data_unit =1 <<unit_power 
        lines .append (f"        - Data unit in quartets: {data_unit}")
        return lines 

    @staticmethod
    def _decode_card_capabilities (value :int )->List [str ]:
        lines :List [str ]=[]
        lines .append (f"      Command chaining, length fields and logical channels: {value:02X}")
        channel_bits =value &0x03 
        max_channels ={0 :1 ,1 :4 ,2 :8 ,3 :8 }.get (channel_bits ,1 )
        if value &0x10 :
            lines .append ("        - Logical channel number assignment: by the interface device and card")
        elif value &0x08 :
            lines .append ("        - Logical channel number assignment: by the card")
        else :
            lines .append ("        - Logical channel number assignment: not indicated")
        lines .append (f"        - Maximum number of logical channels: {max_channels}")
        if value &0x80 :
            lines .append ("        - Command chaining supported")
        if value &0x40 :
            lines .append ("        - Extended Lc and Le fields supported")
        return lines 

    @classmethod
    def _decode_compact_tlv_historical (cls ,historical :bytes )->List [str ]:
        lines :List [str ]=[]
        if len (historical )==0 :
            return lines 
        category =historical [0 ]
        if category !=0x80 :
            lines .append (f"  Category indicator byte: {category:02X}")
            return lines 

        lines .append ("  Category indicator byte: 80 (compact TLV data object)")
        index =1 
        while index <len (historical ):
            descriptor =historical [index ]
            index +=1 
            if descriptor ==0x00 :
                break 
            tag =(descriptor >>4 )&0x0F 
            length =descriptor &0x0F 
            if index +length >len (historical ):
                break 
            value =historical [index :index +length ]
            index +=length 
            if tag ==0x3 and length ==1 :
                lines .append ("    Tag: 3, len: 1 (card service data byte)")
                lines .extend (cls ._decode_card_service_data (value [0 ]))
                continue 
            if tag ==0x7 and length ==3 :
                lines .append ("    Tag: 7, len: 3 (card capabilities)")
                lines .extend (cls ._decode_selection_methods (value [0 ]))
                lines .extend (cls ._decode_data_coding (value [1 ]))
                lines .extend (cls ._decode_card_capabilities (value [2 ]))
                continue 
            if tag ==0x6 :
                lines .append (f"    Tag: 6, len: {length} (pre-issuing data)")
                lines .append (f"      Data: {value.hex().upper()}")
                continue 
            lines .append (f"    Tag: {tag}, len: {length}")
            lines .append (f"      Data: {value.hex().upper()}")
        return lines 

    def describe_atr (self )->List [str ]:
        atr_bytes =self .get_atr_bytes ()
        lines :List [str ]=[]
        if len (atr_bytes )==0 :
            lines .append ("ATR unavailable.")
            return lines 

        lines .append (f"ATR: {self._format_atr_bytes(atr_bytes)}")
        ts =atr_bytes [0 ]
        convention ="Unknown Convention"
        if ts ==0x3B :
            convention ="Direct Convention"
        if ts ==0x3F :
            convention ="Inverse Convention"
        lines .append (f"+ TS = {ts:02X} --> {convention}")

        if len (atr_bytes )<2 :
            return lines 

        t0 =atr_bytes [1 ]
        y =t0 >>4 
        k =t0 &0x0F 
        lines .append (f"+ T0 = {t0:02X}, Y(1): {y:04b}, K: {k} (historical bytes)")

        index =2 
        group =1 
        while True :
            if y &0x1 :
                if index >=len (atr_bytes ):
                    break 
                ta_value =atr_bytes [index ]
                index +=1 
                if group ==1 :
                    lines .extend (self ._decode_ta1 (ta_value ))
                else :
                    if group ==3 :
                        lines .append (self ._decode_ta3 (ta_value ))
                    else :
                        lines .append (f"  TA({group}) = {ta_value:02X}")
            if y &0x2 :
                if index >=len (atr_bytes ):
                    break 
                tb_value =atr_bytes [index ]
                index +=1 
                lines .append (f"  TB({group}) = {tb_value:02X}")
            if y &0x4 :
                if index >=len (atr_bytes ):
                    break 
                tc_value =atr_bytes [index ]
                index +=1 
                lines .append (f"  TC({group}) = {tc_value:02X}")
            if y &0x8 :
                if index >=len (atr_bytes ):
                    break 
                td_value =atr_bytes [index ]
                index +=1 
                next_y =(td_value >>4 )&0x0F 
                protocol =td_value &0x0F 
                protocol_label =self ._protocol_label (protocol )
                lines .append (f"  TD({group}) = {td_value:02X} --> Y(i+1) = {next_y:04b}, Protocol T = {protocol_label} ")
                lines .append ("-----")
                y =next_y 
                group +=1 
                continue 
            break 

        historical =atr_bytes [index :index +k ]
        if len (historical )>0 :
            lines .append (f"+ Historical bytes: {self._format_atr_bytes(historical)}")
            lines .extend (self ._decode_compact_tlv_historical (historical ))
        index +=k 

        if index <len (atr_bytes ):
            tck =atr_bytes [index ]
            checksum =0 
            for byte in atr_bytes [1 :index +1 ]:
                checksum ^=byte 
            if checksum ==0 :
                lines .append (f"+ TCK = {tck:02X} (correct checksum)")
            else :
                lines .append (f"+ TCK = {tck:02X} (checksum mismatch)")
        return lines 

    def transmit (self ,apdu_hex :str ,silent :bool =False )->Tuple [bytes ,int ,int ]:
        if self .connection is None :
            if not self .connect ():return b'',0x6F ,0x00 
        try :
            raw =list (HexUtils .to_bytes (apdu_hex ))


            final_apdu =self .session .wrap_apdu (raw )


            data ,sw1 ,sw2 =self ._transmit_recursive (final_apdu )


            if self .session .is_authenticated and data :
                 try :
                     final_data =self .session .unwrap_response (bytes (data ),sw1 ,sw2 )
                     if final_data is not None :
                         data =list (final_data )
                 except Exception as e :
                     if not silent :
                         print (f"{Config.Colors.FAIL}[!] Response Unwrapping Failed: {e}{Config.Colors.ENDC}")


            if not silent :
                print (f"{Config.Colors.BLUE}[<--]{Config.Colors.ENDC} {bytes(data).hex().upper()} {sw1:02X}{sw2:02X}")

            return bytes (data ),sw1 ,sw2 
        except Exception as e :
            if not silent :
                print (f"{Config.Colors.FAIL}[!] Transmit Error: {e}{Config.Colors.ENDC}")
            return b'',0x6F ,0x00 

    def _transmit_recursive (self ,apdu :List [int ])->Tuple [List [int ],int ,int ]:
        data ,sw1 ,sw2 =self .connection .transmit (apdu )
        if sw1 ==0x6C :
            apdu =apdu [:4 ]+[sw2 ]
            return self ._transmit_recursive (apdu )
        if sw1 ==0x61 :
            accumulated =list (data )
            get_response_cla =0x00
            if len (apdu )>0 :
                get_response_cla =apdu [0 ]&0x03
            while sw1 ==0x61 :
                chunk ,sw1 ,sw2 =self .connection .transmit ([get_response_cla ,0xC0 ,0x00 ,0x00 ,sw2 ])
                accumulated .extend (chunk )
            return accumulated ,sw1 ,sw2 
        if sw1 ==0x9F :
            accumulated =list (data )
            get_response_cla =0x00
            if len (apdu )>0 :
                get_response_cla =apdu [0 ]&0x03
            while sw1 ==0x9F :
                chunk ,sw1 ,sw2 =self .connection .transmit ([get_response_cla ,0xC0 ,0x00 ,0x00 ,sw2 ])
                accumulated .extend (chunk )
            return accumulated ,sw1 ,sw2 
        return data ,sw1 ,sw2 