# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 OTA packet builder: assembles RAM/RFM envelope APDUs from key material and script payload (ETSI TS 102 225)."""
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

from dataclasses import dataclass
from typing import List ,Optional

if __package__ :
    from .utils import Utils ,Colors 
    from .crypto import CryptoEngine 
    from .config import ConfigManager ,enforce_demo_key_policy 
else :
    from utils import Utils ,Colors 
    from crypto import CryptoEngine 
    from config import ConfigManager ,enforce_demo_key_policy 


@dataclass
class OtaEnvelopeApdu :
    index :int
    total :int
    apdu_hex :str
    tp_ud_length :int
    is_concatenated :bool
    concat_ref :Optional [int ]


@dataclass
class OtaBuildPlan :
    apdus :List [OtaEnvelopeApdu ]
    reader_apdus :List [str ]
    cipher_mode :str
    mac_mode :str
    cntr_hex :str
    block_0348 :bytes
    payload_hex :str

    @property
    def is_concatenated (self )->bool :
        return len (self .apdus )>1


class OtaPacketBuilder :
    SMS_TPDU_PREFIX =bytes .fromhex ("4005811250F341F6222222222222222502")
    SINGLE_SMS_TPDU_PREFIX =bytes .fromhex ("4005811250F341F62222222222222225027000")
    TPDU_PID_OFFSET =6
    TPDU_DCS_OFFSET =7
    ENVELOPE_PREFIX =bytes .fromhex ("0202828106028001")
    CONCAT_UDH_PREFIX =bytes .fromhex ("050003")
    SINGLE_UDH =b"\x00"
    DEFAULT_TP_UD_MAX =140 

    def __init__ (self ,config :ConfigManager ):
        self .cfg =config 

    @staticmethod
    def _encode_ber_length (length :int )->bytes :
        if length <=0x7F :
            return bytes ([length ])
        if length <=0xFF :
            return bytes ([0x81 ,length ])
        if length <=0xFFFF :
            return bytes ([0x82 ,(length >>8 )&0xFF ,length &0xFF ])
        raise ValueError ("OTA BER length exceeds two-octet long-form support.")

    @staticmethod
    def _block_size_for_cipher (cipher_mode :str )->int :
        if cipher_mode =="AES":
            return 16 
        return 8 

    @classmethod
    def estimate_segment_count (cls ,payload_len :int ,cipher_mode :str ,max_tp_ud :int =None )->int :
        """Return the number of SMS segments required for *payload_len* bytes with *cipher_mode* (TS 102 225 §7)."""
        tp_ud_max =cls .DEFAULT_TP_UD_MAX if max_tp_ud is None else max_tp_ud 
        block_size =cls ._block_size_for_cipher (cipher_mode )
        pcntr =CryptoEngine .compute_pcntr (payload_len ,block_size ,8 )
        ct_len =5 +1 +8 +payload_len +pcntr 
        block_0348_len =3 +7 +ct_len 
        single_tp_ud_len =1 +block_0348_len 
        if single_tp_ud_len <=tp_ud_max :
            return 1 
        concat_budget =tp_ud_max -6 
        if concat_budget <=0 :
            raise ValueError ("TP-UD ceiling too small for concatenated SMS.")
        return (block_0348_len +concat_budget -1 )//concat_budget 

    def _get_tp_ud_max (self )->int :
        configured =self .cfg .get_int ("tp_ud_max")
        if configured <=0 :
            return self .DEFAULT_TP_UD_MAX 
        if configured >140 :
            return 140 
        return configured 

    def _concat_enabled (self )->bool :
        raw_value =self .cfg .get ("concat_sms").strip ().lower ()
        if raw_value in ["","1","true","on","yes","y"]:
            return True 
        return False 

    @staticmethod
    def _concat_reference (cntr_hex :str )->int :
        try :
            return int (cntr_hex ,16 )&0xFF 
        except ValueError :
            return 0 

    def _build_0348_block (self ,payload :bytes )->tuple :
        spi_hex =self .cfg .get ("spi")
        kic_ind_hex =self .cfg .get ("kic_indicator")
        kid_ind_hex =self .cfg .get ("kid_indicator")
        tar_hex =self .cfg .get ("tar")
        cntr_hex =self .cfg .get ("cntr")
        enforce_demo_key_policy (self .cfg .get ("kic"),self .cfg .get ("kid"))
        kic_key =Utils .to_bytes (self .cfg .get ("kic"))
        kid_key =Utils .to_bytes (self .cfg .get ("kid"))

        cipher_mode =CryptoEngine .get_algo_type (kic_ind_hex )
        mac_mode =CryptoEngine .get_algo_type (kid_ind_hex )
        block_size =self ._block_size_for_cipher (cipher_mode )

        param_data =(Utils .to_bytes (spi_hex )[:2 ]+Utils .to_bytes (kic_ind_hex )[:1 ]+
        Utils .to_bytes (kid_ind_hex )[:1 ]+Utils .to_bytes (tar_hex )[:3 ])
        cntr_bytes =Utils .to_bytes (cntr_hex )[:5 ]

        pcntr =CryptoEngine .compute_pcntr (len (payload ),block_size ,8 )
        pcntr_byte =bytes ([pcntr ])
        payload_padded =payload +(b'\x00'*pcntr )

        ct_len =5 +1 +8 +len (payload_padded )
        chl_byte =b'\x15'
        cpl_val =len (chl_byte )+len (param_data )+ct_len 
        cpl_byte =bytes ([cpl_val ])
        chi_byte =b'\x00'
        header_blob =chi_byte +cpl_byte +chl_byte 

        mac_input =header_blob +param_data +cntr_bytes +pcntr_byte +payload_padded 
        cc =CryptoEngine .compute_cc (mac_mode ,kid_key ,mac_input )
        enc_input =cntr_bytes +pcntr_byte +cc +payload_padded 
        ct =CryptoEngine .encrypt_ct (cipher_mode ,kic_key ,enc_input )
        block_0348 =header_blob +param_data +ct 

        return (
        block_0348 ,
        cipher_mode ,
        mac_mode ,
        cntr_hex ,
        chi_byte ,
        cpl_byte ,
        chl_byte ,
        param_data ,
        cntr_bytes ,
        pcntr ,
        cc ,
        ct ,
        )

    def _tpdu_prefix (self ,template :bytes )->bytes :
        prefix =bytearray (template )
        prefix [self .TPDU_PID_OFFSET ]=int (self .cfg .get ("pid"),16 )&0xFF
        prefix [self .TPDU_DCS_OFFSET ]=int (self .cfg .get ("dcs"),16 )&0xFF
        return bytes (prefix )

    def _build_single_sms_tpdu (self ,block_0348 :bytes )->tuple :
        sms_tpdu =self ._tpdu_prefix (self .SINGLE_SMS_TPDU_PREFIX )+block_0348 
        tp_ud_length =1 +len (block_0348 )
        return sms_tpdu ,tp_ud_length 

    def _build_concat_sms_tpdu (self ,fragment :bytes ,concat_ref :int ,total :int ,sequence :int )->tuple :
        tp_ud =self .CONCAT_UDH_PREFIX +bytes ([concat_ref ,total ,sequence ])+fragment 
        sms_tpdu =self ._tpdu_prefix (self .SMS_TPDU_PREFIX )+bytes ([len (tp_ud )])+tp_ud 
        return sms_tpdu ,len (tp_ud )

    def _wrap_sms_tpdu (self ,sms_tpdu :bytes ,allow_extended_apdu :bool =False )->str :
        d1_content =self .ENVELOPE_PREFIX +bytes ([0x8B ])+self ._encode_ber_length (len (sms_tpdu ))+sms_tpdu 
        d1_tag =bytes ([0xD1 ])+self ._encode_ber_length (len (d1_content ))+d1_content 
        cla_byte =int (self .cfg .get ("cla"),16 )
        if len (d1_tag )<=0xFF :
            apdu =bytes ([cla_byte ,0xC2 ,0x00 ,0x00 ,len (d1_tag )])+d1_tag 
            return apdu .hex ().upper ()
        if allow_extended_apdu ==False :
            raise ValueError ("OTA envelope exceeds APDU short-length capacity.")
        if len (d1_tag )>0xFFFF :
            raise ValueError ("OTA envelope exceeds APDU extended-length capacity.")
        apdu =bytes ([
        cla_byte ,
        0xC2 ,
        0x00 ,
        0x00 ,
        0x00 ,
        (len (d1_tag )>>8 )&0xFF ,
        len (d1_tag )&0xFF ,
        ])+d1_tag 
        return apdu .hex ().upper ()

    def build_plan (self ,verbose :bool =False ,override_payload :str =None )->OtaBuildPlan :
        """Build the full OTA send plan: SPI bytes, CC, CT, and SMS-PP APDU list (TS 102 225 §7).

        Returns an ``OtaBuildPlan`` dataclass with the APDU hex list, keyset summary,
        and debug fields. Raises ``ValueError`` when the payload is empty.
        """
        payload_hex =override_payload if override_payload else self .cfg .get ("payload")
        if not payload_hex :
            raise ValueError ("Payload is empty")

        payload =Utils .to_bytes (payload_hex )
        block_data =self ._build_0348_block (payload )
        block_0348 =block_data [0 ]
        cipher_mode =block_data [1 ]
        mac_mode =block_data [2 ]
        cntr_hex =block_data [3 ]
        chi_byte =block_data [4 ]
        cpl_byte =block_data [5 ]
        chl_byte =block_data [6 ]
        param_data =block_data [7 ]
        cntr_bytes =block_data [8 ]
        pcntr =block_data [9 ]
        cc =block_data [10 ]
        ct =block_data [11 ]

        tp_ud_max =self ._get_tp_ud_max ()
        single_tp_ud_len =1 +len (block_0348 )
        apdus :List [OtaEnvelopeApdu ]=[]
        reader_apdus :List [str ]=[]

        if single_tp_ud_len <=tp_ud_max :
            sms_tpdu ,tp_ud_length =self ._build_single_sms_tpdu (block_0348 )
            apdu_hex =self ._wrap_sms_tpdu (sms_tpdu )
            apdus .append (OtaEnvelopeApdu (
            index =0 ,
            total =1 ,
            apdu_hex =apdu_hex ,
            tp_ud_length =tp_ud_length ,
            is_concatenated =False ,
            concat_ref =None ,
            ))
            reader_apdus .append (apdu_hex )
        else :
            if self ._concat_enabled ()==False :
                raise ValueError ("Payload exceeds single-SMS capacity and concatenation is disabled.")

            concat_budget =tp_ud_max -6 
            if concat_budget <=0 :
                raise ValueError ("TP-UD ceiling too small for concatenated SMS.")

            concat_ref =self ._concat_reference (cntr_hex )
            total =len (block_0348 )//concat_budget 
            if len (block_0348 )%concat_budget !=0 :
                total +=1 

            start =0 
            sequence =1 
            while start <len (block_0348 ):
                end =start +concat_budget 
                fragment =block_0348 [start :end ]
                sms_tpdu ,tp_ud_length =self ._build_concat_sms_tpdu (
                fragment ,
                concat_ref ,
                total ,
                sequence ,
                )
                apdus .append (OtaEnvelopeApdu (
                index =sequence -1 ,
                total =total ,
                apdu_hex =self ._wrap_sms_tpdu (sms_tpdu ),
                tp_ud_length =tp_ud_length ,
                is_concatenated =True ,
                concat_ref =concat_ref ,
                ))
                start =end 
                sequence +=1 

            single_sms_tpdu ,_ =self ._build_single_sms_tpdu (block_0348 )
            reader_apdus .append (self ._wrap_sms_tpdu (single_sms_tpdu ,allow_extended_apdu =True ))

        plan =OtaBuildPlan (
        apdus =apdus ,
        reader_apdus =reader_apdus ,
        cipher_mode =cipher_mode ,
        mac_mode =mac_mode ,
        cntr_hex =cntr_hex ,
        block_0348 =block_0348 ,
        payload_hex =payload_hex ,
        )

        if verbose :
            self ._print_verbose (
            plan ,
            chi_byte ,
            cpl_byte ,
            chl_byte ,
            param_data ,
            cntr_bytes ,
            pcntr ,
            cc ,
            ct ,
            )
        return plan 

    def build (self ,verbose :bool =False ,override_payload :str =None )->str :
        plan =self .build_plan (verbose =verbose ,override_payload =override_payload )
        if len (plan .apdus )!=1 :
            raise ValueError ("Payload requires concatenated SMS. Use build_plan() to inspect all segments.")
        return plan .apdus [0 ].apdu_hex 

    def _print_verbose (self ,plan :OtaBuildPlan ,chi ,cpl ,chl ,params ,cntr ,pcntr ,cc ,ct ):
        print (f"\n{Colors.CYAN}[=== 03.48 BLOCK BREAKDOWN ===]{Colors.ENDC}")
        print (f"ALG:    {plan.cipher_mode} / {plan.mac_mode}")
        print (f"CNTR:   {plan.cntr_hex}")
        if plan .is_concatenated :
            print (f"SMS:    {len(plan.apdus)} concatenated segments")
        else :
            print ("SMS:    single segment")
        for apdu in plan .apdus :
            label ="APDU"
            if plan .is_concatenated :
                label =f"APDU[{apdu.index +1}/{apdu.total}]"
            print (f"{label}: {Colors.GREEN}{apdu.apdu_hex}{Colors.ENDC}")
        if plan .is_concatenated and len (plan .reader_apdus )>0 :
            print ("READER: direct reader mode uses reassembled ENVELOPE APDU")
