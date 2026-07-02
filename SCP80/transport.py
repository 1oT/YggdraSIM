# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 transport: wraps the pySim OTA keyset and dispatches APDU envelopes over the active card connection."""
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

_POR_STATUS_MEANINGS ={
0x00 :"PoR OK",
0x01 :"RC/CC/DS failed",
0x02 :"CNTR low",
0x03 :"CNTR high",
0x04 :"CNTR blocked",
0x05 :"Ciphering error",
0x06 :"Unidentified security error",
0x07 :"Insufficient memory to process incoming message",
0x08 :"More time required",
0x09 :"TAR unknown",
0x0A :"Insufficient security level",
0x0B :"Reserved for 3GPP",
0x0C :"Reserved for 3GPP",
}

class Transport :
    def __init__ (self ,config :ConfigManager ):
        self .cfg =config 
        self .conn :Optional [CardConnection ]=None 
        self .active_protocol =None
        self ._stk_bootstrap_trace :List [Dict [str ,Any ]]=[]
        self ._stk_bootstrap_trace_printed =False

    def connect (self ,protocol =None ,verbose :bool =False )->bool :
        """Connect to the reader or simulated card backend; return True on success."""
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
            self ._stk_bootstrap (verbose =verbose )
            return True 
        except Exception as e :
            print (f"{Colors.FAIL}[!] Connection error: {e}{Colors.ENDC}")
            return False 

    def disconnect (self ):
        if self .conn :
            try :self .conn .disconnect ()
            except Exception :pass 
        self .conn =None 
        self .active_protocol =None
        self ._stk_bootstrap_trace =[]
        self ._stk_bootstrap_trace_printed =False

    def reset_connection (self ,verbose :bool =False ):
        print (f"{Colors.CYAN}[RESET] Reconnecting and re-initializing STK...{Colors.ENDC}")
        self .disconnect ()
        self .connect (verbose =verbose )

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
        """Read and return the ICCID from EF.ICCID via the active connection."""
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
        """Return a JSON-serialisable dict summarising the current card connection and ATR."""
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

    def _ensure_reader_protocol (self ,apdu_hex_list :List [str ],verbose :bool =False )->bool :
        needs_extended =False 
        for apdu_hex in apdu_hex_list :
            if self ._requires_extended_apdu (apdu_hex ):
                needs_extended =True 
                break 

        if needs_extended ==False :
            if self .conn is None :
                return self .connect (verbose =verbose )
            return True 

        if self .conn is not None and self .active_protocol ==CardConnection .T1_protocol :
            return True 

        self .disconnect ()
        return self .connect (CardConnection .T1_protocol ,verbose =verbose )

    def transmit (self ,apdu_hex :str ,silent :bool =False ,log_tx :bool =True ,log_rx :bool =True )->Tuple [bytes ,int ]:
        """Send one APDU hex string and return (response_bytes, status_word) as an int."""
        if not self .conn :return b'',0x6F00 
        raw =Utils .to_bytes (apdu_hex )
        if not silent and log_tx :
            print (f"  {Colors.WARNING}[ -> ]{Colors.ENDC} {apdu_hex}")
        data ,sw1 ,sw2 =self .conn .transmit (list (raw ))
        sw =(sw1 <<8 )|sw2 
        if not silent and log_rx :
            print (f"  {Colors.GREEN}[ <- ]{Colors.ENDC} SW: {sw:04X} Data: {Utils.to_hex(bytes(data))}")
        return bytes (data ),sw 

    def _stk_bootstrap (self ,verbose :bool =False )->None :
        self ._stk_bootstrap_trace =[]
        self ._stk_bootstrap_trace_printed =False
        tp_apdu ="8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00"
        if verbose :
            print (f"{Colors.CYAN}[STK]{Colors.ENDC} Bootstrap")
        _ ,sw =self .transmit (tp_apdu ,silent =not verbose ,log_tx =verbose ,log_rx =verbose )
        self ._record_stk_bootstrap_exchange ("TERMINAL PROFILE",tp_apdu ,b"",sw )
        while (sw >>8 )==0x91 :
            length =sw &0xFF 
            fetch_apdu =f"80120000{length:02X}"
            data ,sw =self .transmit (
            fetch_apdu ,
            silent =not verbose ,
            log_tx =verbose ,
            log_rx =verbose ,
            )
            self ._record_stk_bootstrap_exchange ("FETCH",fetch_apdu ,data ,sw )
            terminal_response =self ._terminal_response_for_proactive (data )
            if terminal_response is None :
                break
            _ ,sw =self .transmit (
            terminal_response ,
            silent =not verbose ,
            log_tx =verbose ,
            log_rx =verbose ,
            )
            self ._record_stk_bootstrap_exchange ("TERMINAL RESPONSE",terminal_response ,b"",sw )
        if verbose :
            self ._stk_bootstrap_trace_printed =True

    def _record_stk_bootstrap_exchange (self ,label :str ,apdu_hex :str ,data :bytes ,sw :int )->None :
        self ._stk_bootstrap_trace .append ({
        "label":label ,
        "apdu":apdu_hex ,
        "data":Utils .to_hex (bytes (data or b"")) ,
        "sw":f"{int(sw)&0xFFFF:04X}",
        })

    def print_stk_bootstrap_trace (self )->None :
        if self ._stk_bootstrap_trace_printed :
            return
        if len (self ._stk_bootstrap_trace )==0 :
            return
        print (f"{Colors.CYAN}[STK]{Colors.ENDC} Bootstrap (connection init)")
        for entry in self ._stk_bootstrap_trace :
            print (f"  {Colors.WARNING}[ -> ]{Colors.ENDC} {entry.get('apdu')} ({entry.get('label')})")
            print (f"  {Colors.GREEN}[ <- ]{Colors.ENDC} SW: {entry.get('sw')} Data: {entry.get('data')}")
        self ._stk_bootstrap_trace_printed =True


    def _send_single_ota_apdu (self ,apdu_hex :str ,verbose :bool =False ,require_por :bool =True )->Dict [str ,Any ]:
        result ={"sw":None ,"por":None ,"por_decoded":None ,"delivered":False ,"error":None }
        data ,sw =self .transmit (apdu_hex ,log_tx =verbose ,log_rx =verbose )
        result ["sw"]=f"{sw:04X}"

        if (sw >>8 )==0x91 or (sw >>8 )==0x61 :
            por_data =self ._recv_por (sw ,verbose )
            if por_data :
                result ["por"]=por_data .hex ().upper ()
                result ["por_decoded"]=self .decode_por (por_data ,sw )
                result ["delivered"]=True 
                return result 
            if require_por :
                result ["error"]="No POR body received after proactive fetch."
                return result 
            result ["delivered"]=True 
            return result 

        if sw ==0x9000 :
            if data :
                result ["por"]=data .hex ().upper ()
                result ["por_decoded"]=self .decode_por (data ,sw )
                result ["delivered"]=True
                return result
            if require_por :
                result ["error"]="No POR returned by card (SW 9000 confirms the ENVELOPE reached the Security Domain)."
            result ["delivered"]=True
            return result

        result ["error"]=f"Unexpected transport status {sw:04X} without POR."
        return result 

    def send_ota_sequence (self ,apdu_hex_list :List [str ] ,verbose :bool =False )->Dict [str ,Any ]:
        """Send a list of SCP80 OTA APDUs in sequence and return a result dict with SW and POR."""
        result ={
        "sw":None ,
        "por":None ,
        "por_decoded":None ,
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

        if self ._ensure_reader_protocol (apdu_hex_list ,verbose =verbose )==False :
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

        if verbose :
            self .print_stk_bootstrap_trace ()

        last_index =len (apdu_hex_list )-1
        spi_expects_por =self ._spi_expects_por ()
        for index ,apdu_hex in enumerate (apdu_hex_list ):
            require_por =(index ==last_index )and spi_expects_por
            segment_result =self ._send_single_ota_apdu (
            apdu_hex ,
            verbose =verbose ,
            require_por =require_por ,
            )
            result ["segment_results"].append (segment_result )
            result ["sw"]=segment_result .get ("sw")
            result ["por"]=segment_result .get ("por")
            result ["por_decoded"]=segment_result .get ("por_decoded")
            if segment_result .get ("error"):
                result ["error"]=segment_result .get ("error")
            if segment_result .get ("delivered")==False :
                result ["failed_segment"]=index +1 
                result ["error"]=segment_result .get ("error")
                return result 

        self .cfg .increment_counter ()
        result ["delivered"]=True 
        return result 

    def send_ota (self ,apdu_hex :str ,verbose :bool =False )->Dict [str ,Any ]:
        return self .send_ota_sequence ([apdu_hex ],verbose =verbose )


    def _recv_por (self ,initial_sw :int ,verbose :bool =False )->bytes :
        por_acc ,current_sw =b"",initial_sw 
        fetched_proactive =False
        while True :
            sw1 ,sw2 =(current_sw >>8 )&0xFF ,current_sw &0xFF 
            if sw1 ==0x91 :
                data ,current_sw =self .transmit (f"80120000{sw2:02X}",log_tx =verbose ,log_rx =verbose )
                por_acc +=data 
                fetched_proactive =True
                continue 
            if sw1 ==0x61 :
                data ,current_sw =self .transmit (f"00C00000{sw2:02X}",log_tx =verbose ,log_rx =verbose )
                por_acc +=data 
                continue 
            break 
        if fetched_proactive :
            self ._acknowledge_sms_por (por_acc ,verbose )
        return por_acc

    def _acknowledge_sms_por (self ,fetch_body :bytes ,verbose :bool =False )->None :
        terminal_response =self ._terminal_response_for_sms_por (fetch_body )
        if terminal_response is None :
            return
        self .transmit (
        terminal_response ,
        silent =not verbose ,
        log_tx =verbose ,
        log_rx =verbose ,
        )

    @classmethod
    def decode_por (cls ,fetch_body :bytes ,fetch_sw =None )->Dict [str ,Any ]:
        decoded ={
        "valid":False ,
        "fetch_sw":cls ._format_sw (fetch_sw ),
        "status_code":None ,
        "status_meaning":None ,
        "tar":None ,
        "cntr":None ,
        "pcntr":None ,
        "command_count":None ,
        "command_response":None ,
        "command_sw":None ,
        "error":None ,
        }
        sms_tpdu =cls ._proactive_sms_tpdu (fetch_body )
        if sms_tpdu is None :
            decoded ["error"]="PoR proactive command does not contain an SMS TPDU."
            return decoded
        decoded ["sms_tpdu"]=Utils .to_hex (sms_tpdu )
        response_packet =cls ._sms_tpdu_response_packet (sms_tpdu )
        if response_packet is None :
            decoded ["error"]="SMS TPDU does not contain a parseable 03.48 response packet."
            return decoded
        decoded ["response_packet"]=Utils .to_hex (response_packet )
        if len (response_packet )<13 :
            decoded ["error"]="03.48 response packet shorter than RPL/RHL/TAR/CNTR/PCNTR/status."
            return decoded

        rpl =int .from_bytes (response_packet [0 :2 ],"big")
        rhl =response_packet [2 ]&0xFF
        header_end =3 +rhl
        if rhl <10 or len (response_packet )<header_end :
            decoded ["error"]="03.48 response packet has an unsupported response header length."
            return decoded

        status_code =response_packet [12 ]&0xFF
        response_data =response_packet [header_end :]
        decoded .update ({
        "valid":True ,
        "rpl":f"{rpl:04X}",
        "rpl_expected":f"{max(len(response_packet)-2,0):04X}",
        "rpl_matches":rpl ==len (response_packet )-2 ,
        "rhl":f"{rhl:02X}",
        "tar":Utils .to_hex (response_packet [3 :6 ]),
        "cntr":Utils .to_hex (response_packet [6 :11 ]),
        "pcntr":f"{response_packet[11]&0xFF:02X}",
        "status_code":f"{status_code:02X}",
        "status_meaning":cls ._por_status_meaning (status_code ),
        "response_data":Utils .to_hex (response_data ),
        })
        if status_code ==0x00 and len (response_data )>0 :
            command_count =response_data [0 ]&0xFF
            command_response =response_data [1 :]
            decoded ["command_count"]=command_count
            decoded ["command_response"]=Utils .to_hex (command_response )
            if command_count ==1 and len (command_response )>=2 :
                decoded ["command_sw"]=Utils .to_hex (command_response [-2 :])
        return decoded

    @staticmethod
    def _format_sw (sw )->str :
        if sw is None :
            return None
        if isinstance (sw ,str ):
            return sw .upper ()
        try :
            return f"{int(sw)&0xFFFF:04X}"
        except Exception :
            return str (sw )

    @staticmethod
    def _por_status_meaning (status_code :int )->str :
        value =int (status_code )&0xFF
        if value in _POR_STATUS_MEANINGS :
            return _POR_STATUS_MEANINGS [value ]
        if 0x0D <=value <=0xBF :
            return "Reserved for future use"
        if 0xC0 <=value <=0xFE :
            return "Reserved for proprietary use"
        return "Reserved for future use"

    @classmethod
    def _proactive_sms_tpdu (cls ,fetch_body :bytes )->bytes :
        for tag ,value ,_raw in cls ._iter_proactive_tlvs (fetch_body ):
            if len (tag )==1 and (tag [0 ]&0x7F )==0x0B :
                return value
        return None

    @classmethod
    def _sms_tpdu_response_packet (cls ,sms_tpdu :bytes )->bytes :
        tp_ud =cls ._sms_tpdu_user_data (sms_tpdu )
        if tp_ud is None :
            return None
        if len (tp_ud )==0 :
            return None
        first_octet =bytes (sms_tpdu or b"")[0 ]&0xFF
        if first_octet &0x40 :
            udhl =tp_ud [0 ]&0xFF
            if len (tp_ud )<1 +udhl :
                return None
            return tp_ud [1 +udhl :]
        return tp_ud

    @staticmethod
    def _sms_tpdu_user_data (sms_tpdu :bytes )->bytes :
        raw =bytes (sms_tpdu or b"")
        if len (raw )<4 :
            return None
        first_octet =raw [0 ]&0xFF
        mti =first_octet &0x03
        if mti ==0x01 :
            if len (raw )<4 :
                return None
            addr_digits =raw [2 ]&0xFF
            addr_bytes =(addr_digits +1 )//2
            cursor =4 +addr_bytes
            if len (raw )<cursor +3 :
                return None
            cursor +=2
            vpf =(first_octet >>3 )&0x03
            if vpf ==0x02 :
                cursor +=1
            elif vpf in (0x01 ,0x03 ):
                cursor +=7
            if len (raw )<=cursor :
                return None
            tp_udl =raw [cursor ]&0xFF
            cursor +=1
        elif mti ==0x00 :
            addr_digits =raw [1 ]&0xFF
            addr_bytes =(addr_digits +1 )//2
            cursor =3 +addr_bytes +2 +7
            if len (raw )<=cursor :
                return None
            tp_udl =raw [cursor ]&0xFF
            cursor +=1
        else :
            return None
        end =cursor +tp_udl
        if end >len (raw ):
            return None
        return raw [cursor :end]

    @classmethod
    def _terminal_response_for_sms_por (cls ,fetch_body :bytes )->str :
        command_details =cls ._proactive_command_details_tlv (fetch_body )
        if command_details is None :
            return None
        command_details_raw ,command_details_value =command_details
        if len (command_details_value )!=3 :
            return None
        command_type =command_details_value [1 ]&0xFF
        if command_type !=0x13 :
            return None
        if cls ._proactive_has_sms_tpdu (fetch_body )==False :
            return None
        return cls ._terminal_response_for_proactive (fetch_body )

    @classmethod
    def _terminal_response_for_proactive (cls ,fetch_body :bytes )->str :
        command_details =cls ._proactive_command_details_tlv (fetch_body )
        if command_details is None :
            return None
        command_details_raw ,command_details_value =command_details
        if len (command_details_value )!=3 :
            return None
        tr_body =command_details_raw +bytes .fromhex ("82028281030100")
        return f"80140000{len(tr_body):02X}"+Utils .to_hex (tr_body )

    @classmethod
    def _proactive_command_details_tlv (cls ,fetch_body :bytes )->tuple :
        for tag ,value ,raw in cls ._iter_proactive_tlvs (fetch_body ):
            if len (tag )==1 and (tag [0 ]&0x7F )==0x01 :
                return raw ,value
        return None

    @classmethod
    def _proactive_has_sms_tpdu (cls ,fetch_body :bytes )->bool :
        for tag ,_value ,_raw in cls ._iter_proactive_tlvs (fetch_body ):
            if len (tag )==1 and (tag [0 ]&0x7F )==0x0B :
                return True
        return False

    @classmethod
    def _iter_proactive_tlvs (cls ,fetch_body :bytes ):
        root =cls ._read_ber_tlv (bytes (fetch_body or b""),0 )
        if root is None :
            return
        root_tag ,root_value ,_root_raw ,_root_next =root
        if root_tag ==b"\xD0":
            body =root_value
        else :
            body =bytes (fetch_body or b"")
        offset =0
        while offset <len (body ):
            parsed =cls ._read_ber_tlv (body ,offset )
            if parsed is None :
                return
            tag ,value ,raw ,offset =parsed
            yield tag ,value ,raw

    @staticmethod
    def _read_ber_tlv (data :bytes ,offset :int )->tuple :
        raw =bytes (data or b"")
        start =int (offset )
        if start <0 or start >=len (raw ):
            return None
        cursor =start +1
        if raw [start ]&0x1F ==0x1F :
            while cursor <len (raw ):
                current =raw [cursor ]
                cursor +=1
                if current &0x80 ==0 :
                    break
        tag_end =cursor
        if cursor >=len (raw ):
            return None
        first_len =raw [cursor ]
        cursor +=1
        if first_len &0x80 :
            count =first_len &0x7F
            if count ==0 or cursor +count >len (raw ):
                return None
            length =int .from_bytes (raw [cursor :cursor +count ],"big")
            cursor +=count
        else :
            length =first_len
        end =cursor +length
        if end >len (raw ):
            return None
        return raw [start :tag_end ],raw [cursor :end ],raw [start :end ],end

    def _spi_expects_por (self )->bool :
        """Return True when the active SPI requests a PoR from the card.

        ETSI TS 102 225 §5.2.1 — SPI byte 2, bits 2-1 (b2-b1):
          00 = No PoR reply
          01 = PoR always required
          10 = PoR required on error (treat as required so errors surface)
          11 = Reserved (treat as required defensively)
        """
        spi_hex =self .cfg .get ("spi")
        if not spi_hex :
            return True
        try :
            spi_bytes =Utils .to_bytes (spi_hex )
        except ValueError :
            return True
        if len (spi_bytes )<2 :
            return True
        por_field =spi_bytes [1 ]&0x03
        return por_field !=0x00
