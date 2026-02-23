# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import os 
from typing import Tuple ,List ,Optional ,Any 
from asn1crypto import core ,x509 
from cryptography .hazmat .primitives import serialization ,hashes 
from cryptography .hazmat .primitives .asymmetric import ec 
from cryptography .hazmat .primitives .asymmetric .utils import decode_dss_signature 
from smartcard .System import readers 
from smartcard .util import toHexString 





class ASN1Registry :
    """Namespace for SGP.22 ASN.1 Data Objects."""


    class TransactionId (core .OctetString ):
        class_ ,tag ,method =2 ,0 ,0 

    class EuiccChallenge (core .OctetString ):
        class_ ,tag ,method =2 ,1 ,0 

    class ServerAddress (core .UTF8String ):
        class_ ,tag ,method =2 ,3 ,0 

    class ServerChallenge (core .OctetString ):
        class_ ,tag ,method =2 ,4 ,0 

    class ServerSignature (core .OctetString ):
        class_ ,tag ,method =1 ,55 ,0 

    class EuiccSignature1 (core .OctetString ):
        class_ ,tag ,method =1 ,55 ,0 

    class VersionType (core .OctetString ):pass 


    class ServerSigned1 (core .Sequence ):
        _fields =[
        ('transactionId',TransactionId ),
        ('euiccChallenge',EuiccChallenge ),
        ('serverAddress',ServerAddress ),
        ('serverChallenge',ServerChallenge )
        ]

    class DeviceCapabilities (core .Sequence ):
        _fields =[
        ('gsmSupportedRelease',VersionType ,{'optional':True }),
        ('utranSupportedRelease',VersionType ,{'optional':True }),
        ('cdma2000onexSupportedRelease',VersionType ,{'optional':True }),
        ('cdma2000hrpdSupportedRelease',VersionType ,{'optional':True }),
        ('cdma2000ehrpdSupportedRelease',VersionType ,{'optional':True }),
        ('eutranEpcSupportedRelease',VersionType ,{'optional':True }),
        ('contactlessSupportedRelease',VersionType ,{'optional':True }),
        ('rspCrlSupportedVersion',VersionType ,{'optional':True })
        ]

    class DeviceInfo (core .Sequence ):
        _fields =[
        ('tac',core .OctetString ),
        ('deviceCapabilities',DeviceCapabilities ),
        ('imei',core .OctetString ,{'optional':True })
        ]

    class CtxParamsForCommonAuthentication (core .Sequence ):
        class_ ,tag ,method =2 ,0 ,1 
        _fields =[
        ('matchingId',core .UTF8String ,{'tag_type':'context','tag':0 ,'optional':True }),
        ('deviceInfo',DeviceInfo ,{'tag_type':'context','tag':1 })
        ]

    class CtxParams1 (core .Choice ):
        _alternatives =[('ctxParamsForCommonAuthentication',CtxParamsForCommonAuthentication )]

    class AuthenticateServerRequest (core .Sequence ):
        class_ ,tag =2 ,56 
        _fields =[
        ('serverSigned1',ServerSigned1 ),
        ('serverSignature1',ServerSignature ),
        ('euiccCiPKIdToBeUsed',core .OctetString ,{'optional':True }),
        ('serverCertificate',x509 .Certificate ),
        ('ctxParams1',CtxParams1 )
        ]


    class EuiccSigned1 (core .Sequence ):
        _fields =[
        ('transactionId',TransactionId ,{'tag_type':'context','tag':0 }),
        ('serverAddress',ServerAddress ,{'tag_type':'context','tag':3 }),
        ('serverChallenge',ServerChallenge ,{'tag_type':'context','tag':4 }),
        ('euiccInfo2',core .Any ,{'tag_type':'context','tag':34 }),
        ('ctxParams1',CtxParams1 )
        ]

    class AuthenticateResponseOk (core .Sequence ):
        class_ ,tag =2 ,0 
        _fields =[
        ('euiccSigned1',EuiccSigned1 ),
        ('euiccSignature1',EuiccSignature1 ),
        ('euiccCertificate',x509 .Certificate ),
        ('nextCertInChain',x509 .Certificate )
        ]

    class AuthenticateResponseError (core .Integer ):
        class_ ,tag =2 ,1 

    class AuthenticateServerResponse (core .Choice ):
        _alternatives =[
        ('authenticateResponseOk',AuthenticateResponseOk ),
        ('authenticateResponseError',AuthenticateResponseError )
        ]


    class SmdpSigned2 (core .Sequence ):
        _fields =[
        ('transactionId',TransactionId ,{'tag_type':'context','tag':0 }),
        ('ccRequiredFlag',core .Boolean ),
        ('bppEuiccOtpk',core .OctetString ,{'tag_type':'application','tag':73 ,'optional':True })
        ]

    class PrepareDownloadRequest (core .Sequence ):
        class_ ,tag =2 ,33 
        _fields =[
        ('smdpSigned2',SmdpSigned2 ),
        ('smdpSignature2',core .OctetString ,{'tag_type':'application','tag':55 }),
        ('hashCc',core .OctetString ,{'optional':True }),
        ('smdpCertificate',x509 .Certificate )
        ]





class SGP22Transport :
    """Handles PC/SC connection, APDU chunking, and logical channel I/O."""

    def __init__ (self ,reader_index :int =0 ):
        self ._conn =self ._connect (reader_index )

    def _connect (self ,index :int ):
        r_list =readers ()
        if not r_list :
            raise RuntimeError ("No smart card readers found.")
        conn =r_list [index ].createConnection ()
        conn .connect ()
        return conn 

    def send (self ,apdu :bytes ,log_name :str )->bytes :
        print (f"\n[{log_name}] > {toHexString(list(apdu))}")
        resp ,sw1 ,sw2 =self ._conn .transmit (list (apdu ))


        while sw1 ==0x61 :
            ext ,sw1 ,sw2 =self ._conn .transmit ([0x00 ,0xC0 ,0x00 ,0x00 ,sw2 ])
            resp +=ext 


        if sw1 ==0x6C :
            return self .send (apdu [:-1 ]+bytes ([sw2 ]),log_name )

        sw_hex =f"{sw1:02X}{sw2:02X}"
        print (f"[{log_name}] < SW: {sw_hex} Data: {toHexString(resp)}")

        if sw_hex not in ("9000","9100"):
            raise IOError (f"APDU Failed: {sw_hex}")

        return bytes (resp )

    def send_chunked (self ,cla :int ,ins :int ,p1 :int ,p2_start :int ,
    payload :bytes ,log_name :str ,chunk_size :int =250 )->bytes :
        total =len (payload )
        offset =0 
        blk =p2_start 
        resp =b''

        print (f"\n--- Transmitting {log_name} ({total} bytes) ---")

        while offset <total :
            end =offset +chunk_size 
            chunk =payload [offset :end ]
            is_last =end >=total 


            curr_p1 =p1 if is_last else 0x11 

            apdu =bytes ([cla ,ins ,curr_p1 ,blk ,len (chunk )])+chunk 
            print (f"  > Block {blk:02X} (Len={len(chunk)}) P1={curr_p1:02X}")

            resp =self .send (apdu ,f"{log_name} [Block {blk}]")

            offset +=chunk_size 
            blk +=1 

        return resp 





class CryptoEngine :
    """Encapsulates key loading, ECDSA signing, and verification."""

    @staticmethod 
    def load_credentials (cert_path :str ,key_path :str )->Tuple [Any ,Any ]:
        if not os .path .exists (cert_path )or not os .path .exists (key_path ):
            raise FileNotFoundError (f"Missing credential files: {cert_path} or {key_path}")

        with open (cert_path ,'rb')as f :
            cert =x509 .Certificate .load (f .read ())

        with open (key_path ,'rb')as f :
            key =serialization .load_pem_private_key (f .read (),password =None )

        return cert ,key 

    @staticmethod 
    def sign_asn1 (asn1_obj :core .Asn1Value ,priv_key :Any )->bytes :
        data =asn1_obj .dump ()
        sig_der =priv_key .sign (data ,ec .ECDSA (hashes .SHA256 ()))
        r ,s =decode_dss_signature (sig_der )
        return r .to_bytes (32 ,'big')+s .to_bytes (32 ,'big')

    @staticmethod 
    def generate_server_challenges (card_challenge :bytes ,server_url :str )->Tuple [Any ,bytes ,bytes ]:
        t_id =os .urandom (16 )
        r_server =os .urandom (16 )

        signed1 =ASN1Registry .ServerSigned1 ({
        'transactionId':ASN1Registry .TransactionId (t_id ),
        'euiccChallenge':ASN1Registry .EuiccChallenge (card_challenge ),
        'serverAddress':ASN1Registry .ServerAddress (server_url ),
        'serverChallenge':ASN1Registry .ServerChallenge (r_server )
        })
        return signed1 ,t_id ,r_server 





class PayloadBuilder :
    """Constructs complex ASN.1 Requests."""

    @staticmethod 
    def build_auth_server (signed1 ,signature ,cert ,ctx_params ,root_ci_id :bytes =None )->bytes :
        ctx_content =ASN1Registry .CtxParamsForCommonAuthentication (ctx_params )

        data ={
        'serverSigned1':signed1 ,
        'serverSignature1':ASN1Registry .ServerSignature (signature ),
        'serverCertificate':cert ,
        'ctxParams1':ASN1Registry .CtxParams1 (
        name ='ctxParamsForCommonAuthentication',
        value =ctx_content 
        )
        }

        if root_ci_id :
            data ['euiccCiPKIdToBeUsed']=core .OctetString (root_ci_id )

        return ASN1Registry .AuthenticateServerRequest (data ).dump ()

    @staticmethod 
    def build_prepare_download (t_id ,euicc_sig1 ,cert ,key )->bytes :
        smdp_signed2 =ASN1Registry .SmdpSigned2 ({
        'transactionId':ASN1Registry .TransactionId (t_id ),
        'ccRequiredFlag':False 
        })


        raw_to_sign =smdp_signed2 .dump ()+euicc_sig1 


        sig_der =key .sign (raw_to_sign ,ec .ECDSA (hashes .SHA256 ()))
        r ,s =decode_dss_signature (sig_der )
        raw_sig =r .to_bytes (32 ,'big')+s .to_bytes (32 ,'big')

        req =ASN1Registry .PrepareDownloadRequest ({
        'smdpSigned2':smdp_signed2 ,
        'smdpSignature2':core .OctetString (raw_sig ),
        'smdpCertificate':cert 
        })
        return req .dump ()