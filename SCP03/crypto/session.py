# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

from typing import List ,Dict ,Optional 
from cryptography .hazmat .primitives .ciphers import Cipher ,algorithms ,modes 
from cryptography .hazmat .primitives import cmac 


from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils 

class Scp03Session :
    def __init__ (self ,static_keys :Dict [str ,bytes ]):
        self .k_enc =static_keys ['kenc']
        self .k_mac =static_keys ['kmac']
        self .s_enc =None 
        self .s_mac =None 
        self .s_rmac =None 
        self .chaining_value =b'\x00'*16 
        self .ssc =0 
        self .is_authenticated =False 
        self .card_challenge =b''
        self .host_challenge =b''
        self .sec_level =0x33 
        self .proprietary_iv =None 
        self .last_cmd_header =b''

    def derive_keys (self ,host_challenge :bytes ,card_response :bytes ):
        self .host_challenge =host_challenge 
        self .card_challenge =card_response [13 :21 ]
        card_cryptogram =card_response [21 :29 ]
        self .ssc =0 
        context =self .host_challenge +self .card_challenge 
        self .s_enc =self ._kdf (self .k_enc ,b'\x04',context ,128 )
        self .s_mac =self ._kdf (self .k_mac ,b'\x06',context ,128 )
        self .s_rmac =self ._kdf (self .k_mac ,b'\x07',context ,128 )
        expected =self ._gen_crypto (b'\x00')
        if expected !=card_cryptogram :
            raise Exception (f"Card Cryptogram Mismatch! Expected {expected.hex().upper()}")
        self .proprietary_iv =None 

    def calculate_host_cryptogram (self )->bytes :
        return self ._gen_crypto (b'\x01')

    def _kdf (self ,key :bytes ,constant :bytes ,context :bytes ,bit_len :int )->bytes :
        input_data =(b'\x00'*11 )+constant +b'\x00'+bit_len .to_bytes (2 ,'big')+b'\x01'+context 
        c =cmac .CMAC (algorithms .AES (key ))
        c .update (input_data )
        return c .finalize ()[:(bit_len //8 )]

    def _gen_crypto (self ,constant :bytes )->bytes :
        context =self .host_challenge +self .card_challenge 
        data =(b'\x00'*11 )+constant +b'\x00'+b'\x00\x40'+b'\x01'+context 
        c =cmac .CMAC (algorithms .AES (self .s_mac ))
        c .update (data )
        return c .finalize ()[:8 ]

    def _generate_iv_from_bytes (self ,iv_input :bytes )->bytes :
        cipher =Cipher (algorithms .AES (self .s_enc ),modes .ECB ())
        return cipher .encryptor ().update (iv_input )+cipher .encryptor ().finalize ()

    def wrap_apdu (self ,apdu :List [int ])->List [int ]:
        if not self .is_authenticated :return apdu 

        self .ssc +=1 
        cla ,ins ,p1 ,p2 =apdu [0 ],apdu [1 ],apdu [2 ],apdu [3 ]
        self .last_cmd_header =bytes ([cla ,ins ,p1 ,p2 ])

        lc_original =0 
        le_original =-1 
        payload =b''

        if len (apdu )==5 :
            le_original =apdu [4 ]
        elif len (apdu )>5 :
            lc_original =apdu [4 ]
            payload =bytes (apdu [5 :5 +lc_original ])
            if len (apdu )>5 +lc_original :
                le_original =apdu [5 +lc_original ]

        is_ext_auth =(ins ==0x82 )
        enc_payload =payload 

        if payload and (self .sec_level &0x02 )and not is_ext_auth :
            iv_ssc =(self .ssc -1 ).to_bytes (16 ,'big')
            iv =self ._generate_iv_from_bytes (iv_ssc )
            cipher =Cipher (algorithms .AES (self .s_enc ),modes .CBC (iv ))
            pad_len =16 -(len (payload )%16 )
            padded =payload +b'\x80'+(b'\x00'*(pad_len -1 ))
            enc_payload =cipher .encryptor ().update (padded )+cipher .encryptor ().finalize ()

        mod_cla =cla |0x04 
        header =bytes ([mod_cla ,ins ,p1 ,p2 ,len (enc_payload )+8 ])

        c =cmac .CMAC (algorithms .AES (self .s_mac ))
        c .update (self .chaining_value +header +enc_payload )
        self .chaining_value =c .finalize ()

        final_apdu =list (header )+list (enc_payload )+list (self .chaining_value [:8 ])

        if ins ==0xF2 :final_apdu .append (0x00 )
        elif le_original !=-1 :final_apdu .append (le_original )


        return final_apdu 

    def unwrap_response (self ,data :bytes ,sw1 :int ,sw2 :int )->bytes :
        if not self .is_authenticated or not data :return data 
        if not (self .sec_level &0x20 ):return data 
        if len (data )<8 :return data 

        payload =data [:-8 ]
        if len (payload )==0 :return b''

        iv_candidates =[]
        if self .ssc >=1 :
            ssc_val =self .ssc -1 
            ssc_bytes_mod =bytearray (ssc_val .to_bytes (16 ,'big'))
            ssc_bytes_mod [0 ]=0x80 
            iv_candidates .append (self ._generate_iv_from_bytes (bytes (ssc_bytes_mod )))
            iv_candidates .append (self ._generate_iv_from_bytes (ssc_val .to_bytes (16 ,'big')))

        iv_candidates .append (self ._generate_iv_from_bytes (self .ssc .to_bytes (16 ,'big')))
        if self .proprietary_iv :iv_candidates .insert (0 ,self .proprietary_iv )

        for iv in iv_candidates :
            try :
                cipher =Cipher (algorithms .AES (self .s_enc ),modes .CBC (iv ))
                dec =cipher .decryptor ().update (payload )+cipher .decryptor ().finalize ()

                pad_idx =dec .rfind (b'\x80')
                if pad_idx !=-1 and all (b ==0 for b in dec [pad_idx +1 :]):
                    unpadded =dec [:pad_idx ]
                    if len (unpadded )>0 :
                        return unpadded 
            except :
                pass 

        return payload 

    def encrypt_key_data (self ,key_bytes :bytes )->bytes :
        from cryptography .hazmat .primitives .ciphers import Cipher ,algorithms ,modes 
        import binascii 
        import configparser 
        import os 

        target_dek =None 

        dek_names =['dek','k_dek','kdek','key_dek','static_dek']
        for name in dek_names :
            has_attr =False 
            if hasattr (self ,name ):
                has_attr =True 

            if has_attr :
                val =getattr (self ,name )

                is_valid =False 
                if val is not None :
                    is_valid =True 

                if is_valid :
                    target_dek =val 
                    break 

        is_missing =False 
        if target_dek is None :
            is_missing =True 

        if is_missing :
            config_exists =False 
            from SCP03 .config import Config 
            if os .path .exists (Config .INI_FILE ):
                config_exists =True 

            if config_exists :
                config =configparser .ConfigParser ()
                config .read (Config .INI_FILE )

                has_keys_section =False 
                if 'KEYS'in config :
                    has_keys_section =True 

                if has_keys_section :
                    has_dek_entry =False 
                    if 'dek'in config ['KEYS']:
                        has_dek_entry =True 

                    if has_dek_entry :
                        target_dek =config ['KEYS']['dek'].strip ()
                        is_missing =False 

        if is_missing :
            raise Exception ("DEK attribute is missing from session and keys.ini.")

        is_string =False 
        if isinstance (target_dek ,str ):
            is_string =True 

        if is_string :
            target_dek =binascii .unhexlify (target_dek )

        iv =b'\x00'*16 
        cipher =Cipher (algorithms .AES (target_dek ),modes .CBC (iv ))
        encryptor =cipher .encryptor ()

        encrypted_chunk =encryptor .update (key_bytes )
        encrypted_final =encryptor .finalize ()

        result =bytearray ()
        result .extend (encrypted_chunk )
        result .extend (encrypted_final )

        return bytes (result )