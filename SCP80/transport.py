# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from typing import Tuple ,Optional ,Dict ,Any 
from config import ConfigManager 
from utils import Utils ,Colors 

try :
    from smartcard .System import readers 
    from smartcard .CardConnection import CardConnection 
    PYSCRARD_AVAIL =True 
except ImportError :
    PYSCRARD_AVAIL =False 
    readers =None 

class Transport :
    def __init__ (self ,config :ConfigManager ):
        self .cfg =config 
        self .conn :Optional [CardConnection ]=None 

    def connect (self )->bool :
        if not PYSCRARD_AVAIL :
            print (f"{Colors.FAIL}[!] pyscard library missing.{Colors.ENDC}")
            return False 
        try :
            r_list =readers ()
            if not r_list :
                print (f"{Colors.FAIL}[!] No readers found.{Colors.ENDC}")
                return False 
            idx =self .cfg .get_int ("reader_idx")
            if idx >=len (r_list ):idx =0 
            self .conn =r_list [idx ].createConnection ()
            self .conn .connect ()
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

    def reset_connection (self ):
        print (f"{Colors.CYAN}[RESET] Reconnecting and re-initializing STK...{Colors.ENDC}")
        self .disconnect ()
        self .connect ()

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


    def send_ota (self ,apdu_hex :str ,verbose :bool =False )->Dict [str ,Any ]:
        result ={"sw":None ,"por":None }
        if self .cfg .get ("transport")!="reader":
            print (f"\n{Colors.WARNING}[PRINT ONLY]{Colors.ENDC} {apdu_hex}")
            self .cfg .increment_counter ()
            return result 

        if not self .conn and not self .connect ():return result 


        data ,sw =self .transmit (apdu_hex ,log_tx =verbose ,log_rx =verbose )
        result ["sw"]=f"{sw:04X}"

        if (sw >>8 )==0x91 or (sw >>8 )==0x61 :

            por_data =self ._recv_por (sw ,verbose )
            if por_data :
                result ["por"]=por_data .hex ().upper ()
                self ._emulate_me_response ()

        self .cfg .increment_counter ()
        return result 


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