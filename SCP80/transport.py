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

from typing import Tuple ,Optional ,Dict ,Any ,List 
from yggdrasim_common .card_backend import create_card_connection ,is_simulated_card_backend
if __package__ :
    from .config import ConfigManager 
    from .utils import Utils ,Colors 
else :
    from config import ConfigManager 
    from utils import Utils ,Colors 

try :
    from smartcard .CardConnection import CardConnection 
    from smartcard .ATR import ATR 
    PYSCRARD_AVAIL =True 
except ImportError :
    PYSCRARD_AVAIL =False 
    ATR =None
    class CardConnection :  # type: ignore[no-redef]
        T0_protocol =0
        T1_protocol =1
        RAW_protocol =2

class Transport :
    def __init__ (self ,config :ConfigManager ):
        self .cfg =config 
        self .conn :Optional [CardConnection ]=None 
        self .active_protocol =None

    def connect (self ,protocol =None )->bool :
        if not PYSCRARD_AVAIL and not is_simulated_card_backend ():
            print (f"{Colors.FAIL}[!] pyscard library missing.{Colors.ENDC}")
            return False 
        try :
            idx =self .cfg .get_int ("reader_idx")
            self .conn =create_card_connection (reader_index =idx ,protocol =protocol )
            try :
                self .active_protocol =self .conn .getProtocol ()
            except Exception :
                self .active_protocol =protocol 
            self ._stk_bootstrap ()
            return True 
        except Exception as e :
            print (f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
            return False 

    def disconnect (self ):
        if self .conn :
            try :self .conn .disconnect ()
            except :pass 
        self .conn =None 
        self .active_protocol =None

    def reset_connection (self ):
        print (f"{Colors.CYAN}[RESET] Reconnecting and re-initializing STK...{Colors.ENDC}")
        self .disconnect ()
        self .connect ()

    @staticmethod
    def _decode_iccid_bytes (data :bytes )->str :
        hex_value =bytes (data ).hex ().upper ()
        digits =[]
        for index in range (0 ,len (hex_value ),2 ):
            pair =hex_value [index :index +2 ]
            if len (pair )<2 :
                continue 
            digits .append (pair [1 ])
            digits .append (pair [0 ])
        return "".join (digits ).replace ("F","")

    def read_iccid (self )->str :
        if self .conn is None :
            if self .connect ()==False :
                return ""
        self .transmit ("00A40004023F00",silent =True ,log_tx =False ,log_rx =False )
        self .transmit ("00A40004022FE2",silent =True ,log_tx =False ,log_rx =False )
        data ,sw =self .transmit ("00B000000A",silent =True ,log_tx =False ,log_rx =False )
        if sw !=0x9000 :
            return ""
        return self ._decode_iccid_bytes (data )

    @staticmethod
    def _requires_extended_apdu (apdu_hex :str )->bool :
        return len (Utils .to_bytes (apdu_hex ))>261 

    @staticmethod
    def _protocol_name (protocol )->str :
        if protocol ==CardConnection .T0_protocol :
            return "T=0"
        if protocol ==CardConnection .T1_protocol :
            return "T=1"
        if protocol ==CardConnection .RAW_protocol :
            return "RAW"
        if protocol is None :
            return "UNKNOWN"
        return str (protocol )

    def get_protocol_summary (self )->Dict [str ,Any ]:
        info ={
        "available":False ,
        "atr_hex":None ,
        "supported_protocols":{},
        "supports_t1":False ,
        "active_protocol":None ,
        "error":None ,
        }
        if PYSCRARD_AVAIL ==False :
            info ["error"]="pyscard library missing."
            return info 

        if self .conn is None :
            if self .connect ()==False :
                info ["error"]="Reader connection unavailable."
                return info 

        try :
            atr_bytes =bytes (self .conn .getATR ())
            info ["atr_hex"]=atr_bytes .hex ().upper ()
            if ATR is not None :
                parsed_atr =ATR (list (atr_bytes ))
                info ["supported_protocols"]=parsed_atr .getSupportedProtocols ()
                info ["supports_t1"]=bool (info ["supported_protocols"].get ("T=1"))
            info ["active_protocol"]=self ._protocol_name (self .active_protocol )
            info ["available"]=True 
        except Exception as e :
            info ["error"]=str (e )
        return info 

    def _ensure_reader_protocol (self ,apdu_hex_list :List [str ])->bool :
        needs_extended =False 
        for apdu_hex in apdu_hex_list :
            if self ._requires_extended_apdu (apdu_hex ):
                needs_extended =True 
                break 

        if needs_extended ==False :
            if self .conn is None :
                return self .connect ()
            return True 

        if self .conn is not None and self .active_protocol ==CardConnection .T1_protocol :
            return True 

        self .disconnect ()
        return self .connect (CardConnection .T1_protocol )

    def transmit (self ,apdu_hex :str ,silent :bool =False ,log_tx :bool =True ,log_rx :bool =True )->Tuple [bytes ,int ]:
        if not self .conn :return b'',0x6F00 
        raw =Utils .to_bytes (apdu_hex )
        if not silent and log_tx :
            print (f"  {Colors.WARNING}[ -> ]{Colors.ENDC} {apdu_hex}")
        data ,sw1 ,sw2 =self .conn .transmit (list (raw ))
        sw =(sw1 <<8 )|sw2 
        if not silent and log_rx :
            print (f"  {Colors.GREEN}[ <- ]{Colors.ENDC} SW: {sw:04X} Data: {Utils.to_hex(bytes(data))}")
        return bytes (data ),sw 

    def _stk_bootstrap (self ):
        tp_apdu ="8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00"
        _ ,sw =self .transmit (tp_apdu ,silent =True )
        while (sw >>8 )==0x91 :
            length =sw &0xFF 
            data ,sw =self .transmit (f"80120000{length:02X}",silent =True )
            tr_body =data +bytes .fromhex ("81830100")
            _ ,sw =self .transmit (f"80140000{len(tr_body):02X}"+Utils .to_hex (tr_body ),silent =True )


    def _send_single_ota_apdu (self ,apdu_hex :str ,verbose :bool =False ,require_por :bool =True )->Dict [str ,Any ]:
        result ={"sw":None ,"por":None ,"delivered":False ,"error":None }
        data ,sw =self .transmit (apdu_hex ,log_tx =verbose ,log_rx =verbose )
        result ["sw"]=f"{sw:04X}"

        if (sw >>8 )==0x91 or (sw >>8 )==0x61 :
            por_data =self ._recv_por (sw ,verbose )
            if por_data :
                result ["por"]=por_data .hex ().upper ()
                result ["delivered"]=True 
                return result 
            if require_por :
                result ["error"]="No POR body received after proactive fetch."
                return result 
            result ["delivered"]=True 
            return result 

        if sw ==0x9000 :
            if require_por :
                result ["error"]="No POR received. OTA command did not reach the Security Domain."
                return result 
            result ["delivered"]=True 
            return result 

        result ["error"]=f"Unexpected transport status {sw:04X} without POR."
        return result 

    def send_ota_sequence (self ,apdu_hex_list :List [str ] ,verbose :bool =False )->Dict [str ,Any ]:
        result ={
        "sw":None ,
        "por":None ,
        "delivered":False ,
        "error":None ,
        "segment_count":len (apdu_hex_list ),
        "segment_results":[],
        "failed_segment":None ,
        }
        if len (apdu_hex_list )==0 :
            result ["error"]="No OTA APDUs to send."
            return result 

        if self .cfg .get ("transport")!="reader":
            for apdu_hex in apdu_hex_list :
                print (f"\n{Colors.WARNING}[PRINT ONLY]{Colors.ENDC} {apdu_hex}")
            self .cfg .increment_counter ()
            result ["delivered"]=True 
            return result 

        if self ._ensure_reader_protocol (apdu_hex_list )==False :
            needs_extended =False 
            for apdu_hex in apdu_hex_list :
                if self ._requires_extended_apdu (apdu_hex ):
                    needs_extended =True 
                    break 
            if needs_extended :
                result ["error"]="Reader transport requires T=1 for extended ENVELOPE delivery, but this card/reader path rejected T=1."
            else :
                result ["error"]="Reader connection unavailable."
            return result 

        last_index =len (apdu_hex_list )-1 
        for index ,apdu_hex in enumerate (apdu_hex_list ):
            require_por =index ==last_index 
            segment_result =self ._send_single_ota_apdu (
            apdu_hex ,
            verbose =verbose ,
            require_por =require_por ,
            )
            result ["segment_results"].append (segment_result )
            result ["sw"]=segment_result .get ("sw")
            result ["por"]=segment_result .get ("por")
            if segment_result .get ("delivered")==False :
                result ["failed_segment"]=index +1 
                result ["error"]=segment_result .get ("error")
                return result 

        if result ["por"]:
            self ._emulate_me_response ()
        self .cfg .increment_counter ()
        result ["delivered"]=True 
        return result 

    def send_ota (self ,apdu_hex :str ,verbose :bool =False )->Dict [str ,Any ]:
        return self .send_ota_sequence ([apdu_hex ],verbose =verbose )


    def _recv_por (self ,initial_sw :int ,verbose :bool =False )->bytes :
        por_acc ,current_sw =b"",initial_sw 
        while True :
            sw1 ,sw2 =(current_sw >>8 )&0xFF ,current_sw &0xFF 
            if sw1 ==0x91 :
                data ,current_sw =self .transmit (f"80120000{sw2:02X}",log_tx =verbose ,log_rx =verbose )
                por_acc +=data 
                continue 
            if sw1 ==0x61 :
                data ,current_sw =self .transmit (f"00C00000{sw2:02X}",log_tx =verbose ,log_rx =verbose )
                por_acc +=data 
                continue 
            break 
        return por_acc 

    def _emulate_me_response (self ):
        mo_sms_ctrl ="80C2000021D51F0202828106069154395437000606915443680500130942F0802EF5203AA33F"
        self .transmit (mo_sms_ctrl ,silent =True )
        self .transmit ("801400000C810301130002028281030100",silent =True )