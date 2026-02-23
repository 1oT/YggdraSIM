# -----------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2026 Hampus Hellsberg
# -----------------------------------------------------------------------------

import json 
from typing import List ,Dict ,Optional ,Tuple ,Any 
from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils ,TlvParser 
from SCP03 .core .decoders import AdvancedDecoders 

class Sgp22Manager :
    """
    Implements GSMA SGP.22/SGP.32 data retrieval and local profile state (list, enable, disable, delete).
    Supports ES10c/ES10b retrieval: GetProfilesInfo, GetRAT, RetrieveNotificationsList,
    GetEimConfigurationData (SGP.32 IoT), EuiccInfo1/2, EuiccConfiguredData.
    Does NOT authenticate to ISD-R for provisioning (StoreMetadata, LoadProfile, PrepareDownload, etc.);
    that is planned for the SCP11 module.
    """
    AID_ISD_R ="A0000005591010FFFFFFFF8900000100"


    TAG_GET_PROFILES_INFO =0xBF2D 
    TAG_ENABLE_PROFILE =0xBF31 
    TAG_DISABLE_PROFILE =0xBF32 
    TAG_DELETE_PROFILE =0xBF33 
    TAG_RESULT =0x80 


    TAG_CTX_0 =0xA0 
    TAG_CTX_1 =0xA1 
    TAG_AID =0x4F 
    TAG_ICCID =0x5A 
    TAG_STATE =0x9F70 
    TAG_NICKNAME =0x90 
    TAG_SP_NAME =0x91 
    TAG_NAME =0x92 
    TAG_CLASS =0x95 


    SEQUENCE_SGP22 =[
    ("0070000001","OPEN CHANNEL"),
    ("01A4040010A0000005591010FFFFFFFF8900000200","Select ECASD"),
    ("01CA005A00","EID"),
    ("01A4040010A0000005591010FFFFFFFF8900000100","Select ISDR"),
    ("81E2910003BF2D00","List Profiles"),
    ("81E2910003BF3C00","EuiccConfiguredData"),
    ("81E2910003BF2000","EuiccInfo1"),
    ("81E2910003BF2200","EuiccInfo2"),
    ("81CA00E000","Key Information Template"),
    ("81CA006600","Security Domain Mgmt Data"),
    ("0070800100","CLOSE CHANNEL")
    ]

    SEQUENCE_SGP02 =[
    ("0070000001","OPEN CHANNEL"),
    ("01A4040010A0000005591010FFFFFFFF8900000200","Select eCASD"),
    ("01CA005A00","EID (SGP.02)"),
    ("01A4040010A0000005591010FFFFFFFF8900000100","Select ISDR"),
    ("81CABF30035C0166","ECASD Recognition Data"),
    ("81CABF30045C027F21","ECASD Certificate Store"),
    ("81F2400000","List Profiles (SGP.02)"),
    ("81CA00E000","Key Information Template"),
    ("81CA006600","Security Domain Mgmt Data"),
    ("81CA006700","Card Capability Info"),
    ("81CA2F00025C0000","List Apps in SD"),
    ("0070800100","CLOSE CHANNEL")
    ]

    def __init__ (self ,transport ):
        self .tp =transport 
        self .profile_cache :Dict [str ,Tuple [int ,str ]]={}



    def run_sgp22_scan (self ):
        """Executes the custom SGP.22/SGP.32 scanning sequence."""
        self ._execute_sequence (self .SEQUENCE_SGP22 ,"SGP.22/SGP.32 Scan")

    def run_sgp02_scan (self ):
        """Executes the custom SGP.02 scanning sequence."""
        self ._execute_sequence (self .SEQUENCE_SGP02 ,"SGP.02 Scan")

    def get_euicc_report (self )->Dict [str ,Any ]:
        """
        Runs SGP.22 sequence and returns structured data for export (no print).
        Returns dict with: profiles, eid, euicc_info1, euicc_info2, euicc_configured_data,
        key_info, sd_mgmt_data (hex strings where applicable).
        """
        collected =self ._run_sequence_collect (self .SEQUENCE_SGP22 )
        report ={
        "profiles":[],
        "eid":collected .get ("EID",""),
        "euicc_info1":collected .get ("EuiccInfo1",""),
        "euicc_info2":collected .get ("EuiccInfo2",""),
        "euicc_configured_data":collected .get ("EuiccConfiguredData",""),
        "key_info":collected .get ("Key Information Template",""),
        "sd_mgmt_data":collected .get ("Security Domain Mgmt Data",""),
        }
        list_hex =collected .get ("List Profiles","")
        if list_hex :
            try :
                data =bytes .fromhex (list_hex )
                report ["profiles"]=self ._profile_list_to_dicts (data )
            except Exception :
                report ["profiles"]=[]
        return report 

    def _es10_retrieve_data (self ,payload :str )->bytes :
        self ._select_isd_r ()
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        is_ok =False 
        if sw1 ==0x90 :
            is_ok =True 
        if is_ok :
            return data 
        return b""

    def _safe_parse_tlv (self ,data :bytes )->Dict [int ,Any ]:
        if not data :
            return {}
        try :
            parsed =TlvParser .parse (data )
            if isinstance (parsed ,dict ):
                return parsed 
        except Exception :
            pass 
        return {}

    def _compact_from_payload (self ,payload :str ,root_tag :Optional [int ])->Dict [str ,Any ]:
        data =self ._es10_retrieve_data (payload )
        if not data :
            return {}
        parsed =self ._safe_parse_tlv (data )
        if not parsed :
            return {"raw_hex":data .hex ().upper ()}
        compact =self ._compact_tlv_node (parsed ,root_tag )
        if not isinstance (compact ,dict ):
            return {"raw_hex":data .hex ().upper ()}
        return compact 

    def _collect_cert_summaries (self ,parsed :Dict [int ,Any ])->List [Dict [str ,Any ]]:
        summaries :List [Dict [str ,Any ]]=[]
        seen_serials =set ()
        for blob in self ._iter_byte_values (parsed ):
            is_short =False 
            if len (blob )<32 :
                is_short =True 
            if is_short :
                continue 
            info =AdvancedDecoders .decode_cert_der (blob )
            is_missing =False 
            if not info :
                is_missing =True 
            if is_missing :
                continue 
            serial =str (info .get ("serial",""))
            is_dup =False 
            if serial in seen_serials :
                is_dup =True 
            if is_dup :
                continue 
            seen_serials .add (serial )
            summaries .append (
            {
            "subject":str (info .get ("subject","")),
            "issuer":str (info .get ("issuer","")),
            "serial":serial ,
            "not_valid_before":str (info .get ("not_valid_before","")),
            "not_valid_after":str (info .get ("not_valid_after","")),
            }
            )
        return summaries 

    def get_euicc_report_extended (self ,standard :str ="SGP.32")->Dict [str ,Any ]:
        """
        Build eUICC export payload for REPORT/EXPORT-EUICC.
        Base set is equivalent to GET-IOT scan.
        For SGP.32, include additional retrievals not covered by GET-IOT
        (excluding notifications and EID as requested).
        """
        std =standard .strip ().upper ()
        is_empty =False 
        if len (std )==0 :
            is_empty =True 
        if is_empty :
            std ="SGP.32"

        report =self .get_euicc_report ()
        report ["standard"]=std 

        if std !="SGP.32":
            return report 

        sgp32_section :Dict [str ,Any ]={}

        sgp32_section ["get_rat"]=self ._compact_from_payload ("BF4300",0xBF43 )
        sgp32_section ["get_eim_configuration_data"]=self ._compact_from_payload ("BF5500",0xBF55 )

        cert_data =self ._es10_retrieve_data ("BF5600")
        cert_parsed =self ._safe_parse_tlv (cert_data )
        if cert_parsed :
            sgp32_section ["get_certs_summary"]=self ._collect_cert_summaries (cert_parsed )
            if len (sgp32_section ["get_certs_summary"])==0 :
                sgp32_section ["get_certs_raw"]=cert_data .hex ().upper ()
        elif cert_data :
            sgp32_section ["get_certs_raw"]=cert_data .hex ().upper ()
        else :
            sgp32_section ["get_certs_summary"]=[]

        report ["sgp32_extra"]=sgp32_section 
        return report 

    def _profile_list_to_dicts (self ,data :bytes )->List [Dict ]:
        """Parse BF2D profile list response into list of dicts."""
        out =[]
        i =0 
        while i <len (data ):
            if data [i ]==0xE3 :
                length =data [i +1 ]
                offset =2 
                if length &0x80 :
                    n =length &0x7F 
                    length =int .from_bytes (data [i +2 :i +2 +n ],"big")
                    offset =2 +n 
                blob =data [i +offset :i +offset +length ]
                entry =self ._single_profile_to_dict (blob )
                if entry :
                    out .append (entry )
                i +=offset +length 
            else :
                i +=1 
        return out 

    def _single_profile_to_dict (self ,data :bytes )->Optional [Dict ]:
        """Convert one profile TLV blob to dict."""
        try :
            info =TlvParser .parse (data )
            aid_bytes =TlvParser .get_first (info ,self .TAG_AID )or TlvParser .get_first (info ,self .TAG_CTX_0 )
            iccid_bytes =TlvParser .get_first (info ,self .TAG_ICCID )
            aid_hex =aid_bytes .hex ().upper ()if isinstance (aid_bytes ,bytes )else ""
            iccid_raw =iccid_bytes .hex ().upper ()if isinstance (iccid_bytes ,bytes )else ""
            iccid_display =self ._swap_nibbles (iccid_raw )
            state_val =info .get (self .TAG_STATE ,b"\x00")
            state_int =int .from_bytes (state_val ,"big")if isinstance (state_val ,bytes )else 0 
            state_str ="ENABLED"if state_int ==1 else "DISABLED"
            class_val =info .get (self .TAG_CLASS ,b"\x02")
            class_int =int .from_bytes (class_val ,"big")if isinstance (class_val ,bytes )else 2 
            class_map ={0 :"TEST",1 :"PROV",2 :"OPER"}
            class_str =class_map .get (class_int ,"OPER")
            name_bytes =info .get (self .TAG_NICKNAME )or info .get (self .TAG_NAME )or info .get (self .TAG_SP_NAME )
            name_str ="Unknown"
            if isinstance (name_bytes ,bytes ):
                try :
                    name_str =name_bytes .decode ("utf-8","ignore").strip ()
                except Exception :
                    name_str =name_bytes .hex ()
            if name_str =="Unknown"and iccid_display :
                name_str =f"ICCID-{iccid_display[-4:]}"
            return {
            "state":state_str ,
            "class":class_str ,
            "iccid":iccid_display ,
            "name":name_str ,
            "aid":aid_hex ,
            }
        except Exception :
            return None 

    def _run_sequence_collect (self ,sequence :List [Tuple [str ,str ]])->Dict [str ,str ]:
        """Run sequence and return dict of description -> response hex (successful only)."""
        channel_id =0 
        result ={}
        for apdu_hex ,desc in sequence :
            if desc =="OPEN CHANNEL":
                resp ,sw1 ,sw2 =self .tp .transmit (apdu_hex ,silent =True )
                if sw1 ==0x90 and len (resp )>=1 :
                    channel_id =resp [0 ]
                else :
                    return result 
                continue 
            cmd_bytes =bytearray (HexUtils .to_bytes (apdu_hex ))
            if desc =="CLOSE CHANNEL":
                if len (cmd_bytes )>=4 :
                    cmd_bytes [3 ]=channel_id 
            elif channel_id >0 :
                if not (cmd_bytes [0 ]==0x00 and cmd_bytes [1 ]==0x70 ):
                    cmd_bytes [0 ]=(cmd_bytes [0 ]&0xF0 )|channel_id 
            resp ,sw1 ,sw2 =self .tp .transmit (cmd_bytes .hex ().upper (),silent =True )
            if sw1 ==0x90 or sw1 ==0x61 :
                if resp :
                    result [desc ]=resp .hex ().upper ()
        return result 

    def _execute_sequence (self ,sequence ,title ):
        print (f"\n{Config.Colors.HEADER}=== Running {title} ==={Config.Colors.ENDC}")
        channel_id =0 

        for i ,(apdu_hex ,desc )in enumerate (sequence ):
            is_admin =any (x in desc .upper ()for x in ["OPEN CHANNEL","CLOSE CHANNEL","SELECT "])

            if desc =="OPEN CHANNEL":
                resp ,sw1 ,sw2 =self .tp .transmit (apdu_hex ,silent =True )
                if sw1 ==0x90 and len (resp )>=1 :channel_id =resp [0 ]
                else :
                    print (f"{Config.Colors.FAIL}[!] OPEN CHANNEL Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                    return 
                continue 


            cmd_bytes =bytearray (HexUtils .to_bytes (apdu_hex ))
            if desc =="CLOSE CHANNEL":
                if len (cmd_bytes )>=4 :cmd_bytes [3 ]=channel_id 
            elif channel_id >0 :
                if not (cmd_bytes [0 ]==0x00 and cmd_bytes [1 ]==0x70 ):
                    cmd_bytes [0 ]=(cmd_bytes [0 ]&0xF0 )|channel_id 

            resp ,sw1 ,sw2 =self .tp .transmit (cmd_bytes .hex ().upper (),silent =True )

            if is_admin :
                if sw1 !=0x90 and sw1 !=0x61 :
                    print (f"{Config.Colors.FAIL}[-] {desc} Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
                continue 

            print (f"\n{Config.Colors.BOLD}[+] {desc}{Config.Colors.ENDC}")

            if sw1 ==0x90 or sw1 ==0x61 :
                if "List Profiles"in desc and "SGP.02"not in desc :
                    self ._parse_profile_list (resp )
                elif "EID"in desc :
                     print (f"    | {resp.hex().upper()}")
                elif resp :
                    try :

                        root_tag =None 
                        if "EuiccConfiguredData"in desc :root_tag =0xBF3C 
                        elif "EuiccInfo1"in desc :root_tag =0xBF20 
                        elif "EuiccInfo2"in desc :root_tag =0xBF22 
                        elif "Key Information"in desc :root_tag =0xE0 
                        elif "Security Domain"in desc :root_tag =0x66 
                        elif "Card Capability"in desc :root_tag =0x67 

                        parsed =TlvParser .parse (resp )
                        self ._print_tlv_tree (parsed ,indent =1 ,parent_tag =root_tag )
                    except :
                         print (f"    | {resp.hex().upper()}")
                else :
                    print ("    | (Empty)")
            else :
                print (f"    | {Config.Colors.FAIL}Status: {sw1:02X}{sw2:02X} (Not Found / Error){Config.Colors.ENDC}")



    def _resolve_tag_name (self ,tag :int ,parent :Optional [int ])->str :
        """Context-aware tag naming for SGP.22 & GlobalPlatform."""


        if parent ==0xBF3C :
            if tag ==0x80 :
                return "SM-DP+ Address"
            if tag ==0x81 :
                return "Root SM-DS Address"
            if tag ==0x82 :
                return "Additional Root SM-DS Addresses"
            if tag ==0xA2 :
                return "Additional Root SM-DS Addresses"
            if tag ==0x83 :
                return "Allowed CI PKID"
            if tag ==0x84 :
                return "CI List"
            if tag ==0xA4 :
                return "CI List"


        if parent ==0xBF2B :
            if tag ==0xA0 :
                return "Notification List"
            if tag ==0x81 :
                return "Notifications List Error"
            if tag ==0xA2 :
                return "eUICC Package Result List"


        if parent ==0xBF55 :
            if tag ==0xA0 :
                return "eIM Configuration Data List"


        if parent ==0x84 :
            if tag ==0x81 :return "Installed Apps"
            if tag ==0x82 :return "Free NVM"
            if tag ==0x83 :return "Free RAM"


        if parent in [0xBF20 ,0xBF22 ,0xA9 ,0xAA ,0xB4 ,0xAF ,0xA0 ]:
            if tag ==0x82 :return "Ver Supported"
            if tag ==0x81 :return "Profile Version"
            if tag ==0x83 :return "Firmware Ver"
            if tag ==0x84 :return "Ext Card Res"
            if tag ==0x85 :return "UICC Cap"
            if tag ==0x86 :return "TSCP Base"
            if tag ==0x87 :return "eUICC Category"
            if tag ==0x88 :return "PP Rules"
            if tag ==0x99 :return "PP Version"
            if tag ==0x0C :return "SAS Accr No"
            if tag ==0xA9 :return "CI PK (Verif)"
            if tag ==0xAA :return "CI PK (Sign)"
            if tag ==0x04 :return "Value"
            if tag ==0xAF :return "Forbidden Rules"
            if tag ==0x90 :return "Nickname"
            if tag ==0xB4 :return "Device Capability"
            if tag ==0xA0 :return "GSM/LTE Cap"
            if tag ==0x89 :return "12V Support"


        if parent ==0xE0 :
            if tag ==0xC0 :return "Key Info"


        if parent in [0x66 ,0x73 ,0x60 ,0x63 ,0x64 ]:
            if tag ==0x73 :
                return "SD Mgmt Data"
            if tag ==0x06 :
                return "OID"
            if tag ==0x60 :
                return "Card Mgmt"
            if tag ==0x63 :
                return "Content Mgmt"
            if tag ==0x64 :
                return "Security Mgmt"
            if tag ==0x65 :
                return "App Lifecycle"
            if tag ==0x66 :
                return "Card Lifecycle"


        if parent ==0xBF56 :
            if tag ==0xA0 :
                return "Certificate Set"
            if tag ==0xA5 :
                return "EUM Certificate"
            if tag ==0xA6 :
                return "eUICC Certificate"


        asn1_names ={
        0x30 :"SEQUENCE",
        0x31 :"SET",
        0x02 :"INTEGER",
        0x03 :"BIT STRING",
        0x04 :"OCTET STRING",
        0x05 :"NULL",
        0x06 :"OBJECT IDENTIFIER",
        0x0C :"UTF8String",
        0x13 :"PrintableString",
        0x17 :"UTCTime",
        0x18 :"GeneralizedTime",
        0x01 :"BOOLEAN",
        0xA0 :"[0] EXPLICIT",
        0xA1 :"[1] EXPLICIT",
        0xA2 :"[2] EXPLICIT",
        0xA3 :"[3] EXPLICIT",
        }
        if tag in asn1_names :
            return asn1_names [tag ]


        if tag ==0x5A :return "EID/ICCID"
        if tag ==0x4F :return "AID"
        if tag ==0xBF20 :return "EuiccInfo1"
        if tag ==0xBF22 :return "EuiccInfo2"
        if tag ==0xBF3C :return "EuiccConfiguredData"
        if tag ==0xBF43 :return "RAT (Rules Authorisation Table)"
        if tag ==0xBF2B :return "NotificationsList"
        if tag ==0xBF55 :return "EimConfigurationData"
        if tag ==0xBF56 :return "GetCertsResponse"
        if tag ==0xE0 :return "Key Info Template"
        if tag ==0x66 :return "SD Mgmt Data"
        if tag ==0x67 :return "Card Cap Info"

        common ={
        0x9F70 :"State",0x90 :"Nickname",0x91 :"Svc Provider",
        0x92 :"Profile Name",0x95 :"Profile Class"
        }
        return common .get (tag ,f"{tag:02X}")

    def _decode_oid (self ,raw_oid :bytes )->str :
        """
        Basic ASN.1 OID decoder from BER value bytes.
        Returns dotted string and well-known name if mapped.
        """
        if not raw_oid :
            return ""

        first =raw_oid [0 ]
        oid_parts =[str (first //40 ),str (first %40 )]

        value =0 
        idx =1 
        while idx <len (raw_oid ):
            b =raw_oid [idx ]
            value =(value <<7 )|(b &0x7F )
            if (b &0x80 )==0 :
                oid_parts .append (str (value ))
                value =0 
            idx +=1 

        dotted =".".join (oid_parts )
        known ={
        "1.2.840.113549.1.1.11":"sha256WithRSAEncryption",
        "1.2.840.10045.4.3.2":"ecdsa-with-SHA256",
        "1.2.840.10045.2.1":"id-ecPublicKey",
        "1.2.840.10045.3.1.7":"prime256v1",
        "2.5.4.3":"commonName",
        "2.5.4.6":"countryName",
        "2.5.4.10":"organizationName",
        "2.5.4.11":"organizationalUnitName",
        "2.5.4.5":"serialNumber",
        "2.5.29.14":"subjectKeyIdentifier",
        "2.5.29.15":"keyUsage",
        "2.5.29.17":"subjectAltName",
        "2.5.29.19":"basicConstraints",
        "2.5.29.20":"cRLNumber",
        "2.5.29.23":"holdInstructionCode",
        "2.5.29.30":"nameConstraints",
        "2.5.29.31":"cRLDistributionPoints",
        "2.5.29.35":"authorityKeyIdentifier",
        "1.3.6.1.4.1.11129.2.1.2":"GSMA RSP Policy OID",
        }
        if dotted in known :
            return f"{known[dotted]} ({dotted})"
        return dotted 

    def _decode_value (self ,tag :int ,val :bytes ,parent_tag :Optional [int ])->str :
        """Heuristic value decoder."""
        hex_str =val .hex ().upper ()


        if parent_tag ==0x84 and tag in [0x81 ,0x82 ,0x83 ]:
            int_val =int .from_bytes (val ,'big')
            if tag ==0x81 :return str (int_val )

            if int_val <1024 :return f"{int_val} B"
            return f"{int_val/1024:.1f} KB"



        is_version_tag =tag in [0x81 ,0x82 ,0x86 ,0x87 ,0x88 ,0x99 ]
        is_euicc_context =False 
        if parent_tag in [0xBF20 ,0xBF22 ,0xA9 ,0xAA ,0xB4 ,0xAF ,0xA0 ]:
            is_euicc_context =True 
        if len (val )==3 and is_euicc_context and (is_version_tag or (tag ==0x04 and parent_tag ==0xA0 )):
            return f"v{val[0]}.{val[1]}.{val[2]} ({hex_str})"


        if tag ==0xC0 and len (val )==4 :
            k_type_map ={0x88 :'AES',0x80 :'DES',0x81 :'3DES',0x82 :'RSA'}
            k_type =k_type_map .get (val [2 ],f"{val[2]:02X}")
            return f"ID:{val[0]:02X} Ver:{val[1]:02X} Type:{k_type} Len:{val[3]}"


        if tag ==0x06 :
            return self ._decode_oid (val )


        if tag ==0x01 and len (val )==1 :
            if val [0 ]==0x00 :
                return "FALSE"
            return "TRUE"


        if tag ==0x82 and parent_tag ==0xE1 and len (val )==1 :
            eim_id_type ={
            1 :"eimIdTypeOid",
            2 :"eimIdTypeFqdn",
            3 :"eimIdTypeProprietary",
            }
            v =val [0 ]
            if v in eim_id_type :
                return f"{eim_id_type[v]} ({v})"
            return f"{v} (0x{hex_str})"

        if tag ==0x87 and parent_tag ==0xE1 :
            bitmask =int .from_bytes (val ,"big",signed =False )
            width =len (val )*8 
            set_bits =[]
            for bit_idx in range (width -1 ,-1 ,-1 ):
                is_set =False 
                if ((bitmask >>bit_idx )&0x01 )==0x01 :
                    is_set =True 
                if is_set :
                    set_bits .append (str (bit_idx ))
            if len (set_bits )==0 :
                return f"{hex_str} (bitmask: none)"
            return f"{hex_str} (bitmask set: {', '.join(set_bits)})"


        if tag ==0x17 or tag ==0x18 :
            try :
                return "\""+val .decode ("ascii","ignore")+"\""
            except Exception :
                return hex_str 


        if tag ==0x0C or tag ==0x13 :
            try :
                return "\""+val .decode ("utf-8","ignore")+"\""
            except Exception :
                return hex_str 


        if tag ==0x02 and len (val )>0 and len (val )<=8 :
            as_int =int .from_bytes (val ,"big",signed =False )
            return f"{as_int} (0x{hex_str})"


        if tag ==0x03 and len (val )>1 :
            unused_bits =val [0 ]
            bit_data =val [1 :]
            bit_hex =bit_data .hex ().upper ()
            short_hex =bit_hex if len (bit_hex )<=64 else bit_hex [:64 ]+"..."


            kind ="bits"
            if len (bit_data )>0 :
                first_byte =bit_data [0 ]
                if first_byte ==0x30 :
                    kind ="Signature"
                elif first_byte in [0x02 ,0x03 ,0x04 ]:
                    kind ="PublicKey"

            if unused_bits ==0 :
                return f"{kind}: 0x{short_hex}"
            return f"{kind}: 0x{short_hex} (unused bits={unused_bits})"


        if tag ==0x04 and len (val )>0 :

            try :
                nested =TlvParser .parse (val )
                if nested :
                    return f"TLV[{len(val)}]: {hex_str[:64]}..."
            except Exception :
                pass 
            if len (val )>32 :
                return hex_str [:64 ]+"..."
            return hex_str 


        if tag ==0x9F70 and len (val )>0 :
            state_map ={
            0x00 :"Disabled",
            0x01 :"Enabled",
            }
            state =state_map .get (val [0 ],f"0x{val[0]:02X}")
            return f"{state} ({hex_str})"

        if tag ==0x95 and len (val )>0 :
            class_map ={
            0 :"Test",
            1 :"Provisioning",
            2 :"Operational",
            }
            cls_name =class_map .get (val [0 ],f"0x{val[0]:02X}")
            return f"{cls_name} ({hex_str})"


        if len (val )>2 and all (0x20 <=c <=0x7E for c in val ):
             return f"\"{val.decode('ascii')}\""

        return hex_str 

    def _print_tlv_tree (
    self ,
    tlv_dict :Dict [int ,any ],
    indent :int =0 ,
    parent_tag :Optional [int ]=None ,
    x509_mode :bool =False ,
    context_label :Optional [str ]=None ,
    ):
        """Recursive pretty printer with inline flattening."""
        items =list (tlv_dict .items ())
        for item_idx ,(tag ,val )in enumerate (items ):
            has_next_item =False 
            if item_idx +1 <len (items ):
                has_next_item =True 
            name =self ._resolve_tag_name (tag ,parent_tag )
            prefix ="    "*indent +"| "


            if x509_mode :
                if context_label =="TBSCertificate":
                    if tag ==0xA0 :
                        name ="Version"
                    elif tag ==0x02 :
                        name ="Serial Number"
                    elif tag ==0xA3 :
                        name ="Extensions"
                elif context_label =="Validity":
                    if tag ==0x17 :
                        name ="notBefore (UTCTime)"
                    elif tag ==0x18 :
                        name ="notAfter (GeneralizedTime)"

            def _is_generic_asn1_container (tag_val :int ,tag_name :str )->bool :
                generic_names ={"SEQUENCE","SET","[0] EXPLICIT","[1] EXPLICIT","[2] EXPLICIT","[3] EXPLICIT"}
                if tag_name in generic_names :
                    return True 
                if tag_name .endswith ("EXPLICIT")and "["in tag_name :
                    return True 
                if tag_val in [0x30 ,0x31 ]:
                    return True 
                return False 

            def _should_print_object_separator ()->bool :
                """
                Add blank lines only between semantic object blocks.
                Keep primitive/value rows compact, especially in ASN.1 internals.
                """
                if has_next_item is False :
                    return False 
                if indent >2 :
                    return False 
                if isinstance (val ,bytes ):
                    return False 
                if _is_generic_asn1_container (tag ,name ):
                    return False 
                return True 


            if isinstance (val ,list ):
                is_generic_container =_is_generic_asn1_container (tag ,name )
                base_indent =indent 
                if not is_generic_container :
                    print (f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                    base_indent =indent +1 
                for idx ,item in enumerate (val ,start =1 ):
                    idx_prefix ="    "*base_indent +"| "
                    item_label =f"#{idx}"
                    child_context =context_label 

                    if x509_mode and tag ==0x30 :
                        if parent_tag ==0xA5 or parent_tag ==0xA6 or context_label =="Certificate":
                            if idx ==1 :
                                item_label ="#1 TBSCertificate"
                                child_context ="TBSCertificate"
                            elif idx ==2 :
                                item_label ="#2 SignatureAlgorithm"
                                child_context ="SignatureAlgorithm"
                        elif context_label =="TBSCertificate":
                            tbs_map ={
                            1 :"Signature",
                            2 :"Issuer",
                            3 :"Validity",
                            4 :"Subject",
                            5 :"SubjectPublicKeyInfo",
                            }
                            if idx in tbs_map :
                                item_label =f"#{idx} {tbs_map[idx]}"
                                child_context =tbs_map [idx ]
                        elif context_label =="Extensions":
                            item_label =f"#{idx} Extension"
                            child_context ="Extension"

                    is_semantic_item =item_label !=f"#{idx}"
                    if is_semantic_item :
                        print (f"{idx_prefix}{Config.Colors.BOLD}{item_label}{Config.Colors.ENDC}")
                    if isinstance (item ,dict ):
                        recurse_indent =base_indent +1 
                        if is_semantic_item :
                            recurse_indent =base_indent +1 
                        elif is_generic_container :
                            recurse_indent =base_indent 
                        self ._print_tlv_tree (
                        item ,
                        recurse_indent ,
                        parent_tag =tag ,
                        x509_mode =x509_mode ,
                        context_label =child_context ,
                        )
                    elif isinstance (item ,bytes ):
                        decoded_item =self ._decode_value (tag ,item ,parent_tag )
                        print (f"{'    ' * (base_indent + 1)}| {decoded_item}")
                    else :
                        print (f"{'    ' * (base_indent + 1)}| {str(item)}")
                if _should_print_object_separator ():
                    print ("")
                continue 




            if isinstance (val ,dict )and len (val )==1 :
                sub_tag =list (val .keys ())[0 ]
                sub_val =val [sub_tag ]

                if isinstance (sub_val ,bytes )and len (sub_val )>0 :
                    decoded_sub =self ._decode_value (sub_tag ,sub_val ,tag )

                    if sub_tag in [0x06 ,0x04 ]:
                        print (f"{prefix}{name:<20} : {decoded_sub}")
                        continue 


            if isinstance (val ,bytes )and tag in [0x84 ,0xAF ,0xA0 ]:
                try :
                    nested =TlvParser .parse (val )
                    if nested :
                        if _is_generic_asn1_container (tag ,name ):
                            self ._print_tlv_tree (nested ,indent ,parent_tag =tag ,x509_mode =x509_mode ,context_label =context_label )
                        else :
                            print (f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                            self ._print_tlv_tree (nested ,indent +1 ,parent_tag =tag ,x509_mode =x509_mode ,context_label =context_label )
                        if _should_print_object_separator ():
                            print ("")
                        continue 
                except :pass 


            if isinstance (val ,dict ):

                if indent ==1 and tag ==parent_tag :
                    self ._print_tlv_tree (
                    val ,
                    indent ,
                    parent_tag =tag ,
                    x509_mode =x509_mode ,
                    context_label =context_label ,
                    )
                else :
                    child_context =context_label 
                    if x509_mode and tag ==0x30 and (parent_tag ==0xA5 or parent_tag ==0xA6 ):
                        child_context ="Certificate"
                    if x509_mode and name =="Extensions":
                        child_context ="Extensions"
                    if _is_generic_asn1_container (tag ,name ):
                        self ._print_tlv_tree (
                        val ,
                        indent ,
                        parent_tag =tag ,
                        x509_mode =x509_mode ,
                        context_label =child_context ,
                        )
                    else :
                        print (f"{prefix}{Config.Colors.CYAN}{name}{Config.Colors.ENDC}")
                        self ._print_tlv_tree (
                        val ,
                        indent +1 ,
                        parent_tag =tag ,
                        x509_mode =x509_mode ,
                        context_label =child_context ,
                        )
                if _should_print_object_separator ():
                    print ("")

            elif isinstance (val ,bytes ):
                if len (val )==0 :
                    if name =="OBJECT IDENTIFIER":
                        print (f"{prefix}{name:<20} : (Empty)")
                    else :
                        print (f"{prefix}{Config.Colors.CYAN}{name:<20}{Config.Colors.ENDC} : (Empty)")
                else :
                    decoded =self ._decode_value (tag ,val ,parent_tag )
                    if len (decoded )>50 and " "not in decoded and "."not in decoded :
                        decoded =decoded [:50 ]+"..."
                    if name =="OBJECT IDENTIFIER":
                        print (f"{prefix}{name:<20} : {decoded}")
                    else :
                        print (f"{prefix}{Config.Colors.CYAN}{name:<20}{Config.Colors.ENDC} : {decoded}")

    def _swap_nibbles (self ,s :str )->str :
        if not s :return ""
        res =[]
        for i in range (0 ,len (s ),2 ):
            if i +1 <len (s ):res .append (s [i +1 ]+s [i ])
            else :res .append (s [i ])
        return "".join (res ).replace ('F','')

    def _parse_profile_list (self ,data :bytes ):
        """Decodes BF2D (GetProfilesInfo) into a readable table."""
        print (f"    {'State':<9} | {'Class':<5} | {'ICCID':<20} | {'Name / Provider':<25} | {'AID'}")
        print ("    "+"-"*105 )

        self .profile_cache ={}
        i =0 
        while i <len (data ):
            if data [i ]==0xE3 :
                length =data [i +1 ]
                offset =2 
                if length &0x80 :
                    n =length &0x7F 
                    length =int .from_bytes (data [i +2 :i +2 +n ],'big')
                    offset =2 +n 

                profile_blob =data [i +offset :i +offset +length ]
                self ._print_single_profile (profile_blob )
                i +=offset +length 
            else :
                i +=1 
        print ("")

    def _print_single_profile (self ,data :bytes ):
        info =TlvParser .parse (data )

        aid_bytes =TlvParser .get_first (info ,self .TAG_AID )or TlvParser .get_first (info ,self .TAG_CTX_0 )
        iccid_bytes =TlvParser .get_first (info ,self .TAG_ICCID )

        aid_hex =aid_bytes .hex ().upper ()if isinstance (aid_bytes ,bytes )else ""
        iccid_raw =iccid_bytes .hex ().upper ()if isinstance (iccid_bytes ,bytes )else ""
        iccid_display =self ._swap_nibbles (iccid_raw )

        state_val =TlvParser .get_first (info ,self .TAG_STATE ,b'\x00')
        state_int =int .from_bytes (state_val ,'big')if isinstance (state_val ,bytes )else 0 
        state_str =f"{Config.Colors.GREEN}ENABLED  {Config.Colors.ENDC}"if state_int ==1 else "DISABLED "

        class_val =TlvParser .get_first (info ,self .TAG_CLASS ,b'\x02')
        class_int =int .from_bytes (class_val ,'big')if isinstance (class_val ,bytes )else 2 
        class_map ={0 :'TEST ',1 :'PROV ',2 :'OPER '}
        class_str =class_map .get (class_int ,'UNK  ')

        name_bytes =(
        TlvParser .get_first (info ,self .TAG_NICKNAME )
        or TlvParser .get_first (info ,self .TAG_NAME )
        or TlvParser .get_first (info ,self .TAG_SP_NAME )
        )
        name_str ="Unknown"
        if isinstance (name_bytes ,bytes ):
            try :name_str =name_bytes .decode ('utf-8','ignore').strip ()
            except :name_str =name_bytes .hex ()

        if name_str =="Unknown"and iccid_display :
            name_str =f"ICCID-{iccid_display[-4:]}"

        print (f"    {state_str} | {class_str} | {iccid_display:<20} | {name_str:<25} | {aid_hex}")

        if aid_hex :
            entry =(self .TAG_AID ,aid_hex )
            self .profile_cache [name_str .upper ()]=entry 
            self .profile_cache [aid_hex ]=entry 
        elif iccid_raw :
            entry =(self .TAG_ICCID ,iccid_raw )
            self .profile_cache [name_str .upper ()]=entry 



    def _select_isd_r (self ):
        cmd =f"00A40400{len(self.AID_ISD_R)//2:02X}{self.AID_ISD_R}"
        self .tp .transmit (cmd ,silent =True )

    def list_profiles (self ):
        self ._select_isd_r ()
        payload ="BF2D00"
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print (f"{Config.Colors.CYAN}[*] Retrieving Profile List (ES10c/ES10b.GetProfilesInfo)...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 ==0x90 :
            self ._parse_profile_list (data )
        else :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def _store_named_value (self ,target :Dict [str ,Any ],key :str ,value :Any )->None :
        if key not in target :
            target [key ]=value 
            return 

        existing =target [key ]
        if isinstance (existing ,list ):
            existing .append (value )
            return 

        target [key ]=[existing ,value ]

    def _is_generic_asn1_container_tag (self ,tag :int ,parent_tag :Optional [int ])->bool :
        name =self ._resolve_tag_name (tag ,parent_tag )
        if tag in [0x30 ,0x31 ]:
            return True 
        generic_names ={"SEQUENCE","SET","[0] EXPLICIT","[1] EXPLICIT","[2] EXPLICIT","[3] EXPLICIT"}
        if name in generic_names :
            return True 
        if name .endswith ("EXPLICIT")and "["in name :
            return True 
        return False 

    def _compact_tlv_value (self ,tag :int ,val :Any ,parent_tag :Optional [int ])->Any :
        if isinstance (val ,bytes ):
            decoded =self ._decode_value (tag ,val ,parent_tag )
            if isinstance (decoded ,str )and len (decoded )>=2 and decoded [0 ]=='"'and decoded [-1 ]=='"':
                return decoded [1 :-1 ]
            return decoded 

        if isinstance (val ,dict ):
            return self ._compact_tlv_node (val ,tag )

        if isinstance (val ,list ):
            out =[]
            for item in val :
                if isinstance (item ,bytes ):
                    decoded =self ._decode_value (tag ,item ,parent_tag )
                    if isinstance (decoded ,str )and len (decoded )>=2 and decoded [0 ]=='"'and decoded [-1 ]=='"':
                        out .append (decoded [1 :-1 ])
                    else :
                        out .append (decoded )
                    continue 
                if isinstance (item ,dict ):
                    out .append (self ._compact_tlv_node (item ,tag ))
                    continue 
                if isinstance (item ,list ):
                    nested_list =self ._compact_tlv_value (tag ,item ,parent_tag )
                    if isinstance (nested_list ,list ):
                        out .extend (nested_list )
                    else :
                        out .append (nested_list )
                    continue 
                out .append (item )
            return out 

        return str (val )

    def _compact_tlv_node (self ,node :Dict [int ,Any ],parent_tag :Optional [int ])->Dict [str ,Any ]:
        out :Dict [str ,Any ]={}
        for tag ,val in node .items ():
            if self ._is_generic_asn1_container_tag (tag ,parent_tag ):
                flattened =self ._compact_tlv_value (tag ,val ,parent_tag )
                if isinstance (flattened ,dict ):
                    for child_key ,child_val in flattened .items ():
                        self ._store_named_value (out ,child_key ,child_val )
                elif isinstance (flattened ,list ):
                    for elem in flattened :
                        if isinstance (elem ,dict ):
                            for child_key ,child_val in elem .items ():
                                self ._store_named_value (out ,child_key ,child_val )
                        else :
                            self ._store_named_value (out ,"values",elem )
                else :
                    self ._store_named_value (out ,"value",flattened )
                continue 

            key =self ._resolve_tag_name (tag ,parent_tag )
            value =self ._compact_tlv_value (tag ,val ,parent_tag )
            self ._store_named_value (out ,key ,value )
        return out 

    def _print_compact_json (self ,parsed :Dict [int ,Any ],root_tag :Optional [int ])->None :
        compact =self ._compact_tlv_node (parsed ,root_tag )
        text =json .dumps (compact ,indent =2 ,ensure_ascii =True )
        for line in text .splitlines ():
            stripped =line .lstrip ()
            if stripped .startswith ('"')and ":"in stripped :
                colon_idx =line .find (":")
                key_part =line [:colon_idx +1 ]
                value_part =line [colon_idx +1 :]
                print (f"    {key_part}{Config.Colors.CYAN}{value_part}{Config.Colors.ENDC}")
            else :
                print (f"    {line}")

    def _short_display (self ,value :Any ,max_len :int =84 )->str :
        text =str (value )
        is_short =False 
        if len (text )<=max_len :
            is_short =True 
        if is_short :
            return text 
        return text [:max_len ]+"..."

    def _print_pipe_line (self ,label :str ,value :Any ,depth :int =0 )->None :
        prefix ="  "*depth 
        print (f"    | {prefix}{label:<20}: {Config.Colors.CYAN}{self._short_display(value)}{Config.Colors.ENDC}")

    def _print_compact_pipe_map (self ,node :Dict [str ,Any ],depth :int =0 )->None :
        for key ,value in node .items ():
            if isinstance (value ,dict ):
                self ._print_pipe_line (str (key ),"Present",depth )
                self ._print_compact_pipe_map (value ,depth +1 )
                continue 

            if isinstance (value ,list ):
                list_len =len (value )
                self ._print_pipe_line (str (key ),f"[{list_len}]",depth )
                if list_len ==0 :
                    continue 

                all_scalars =True 
                for item in value :
                    is_scalar =False 
                    if not isinstance (item ,dict ):
                        if not isinstance (item ,list ):
                            is_scalar =True 
                    if is_scalar ==False :
                        all_scalars =False 
                        break 

                if all_scalars :
                    preview_count =2 
                    if list_len <2 :
                        preview_count =list_len 
                    for idx in range (preview_count ):
                        self ._print_pipe_line (f"  Item {idx + 1}",value [idx ],depth )
                    if list_len >preview_count :
                        remaining =list_len -preview_count 
                        self ._print_pipe_line ("  Remaining",remaining ,depth )
                    continue 

                first =value [0 ]
                if isinstance (first ,dict ):
                    self ._print_pipe_line ("  First Entry","Present",depth )
                    self ._print_compact_pipe_map (first ,depth +1 )
                elif isinstance (first ,list ):
                    nested_count =len (first )
                    self ._print_pipe_line ("  First Entry",f"list[{nested_count}]",depth )
                else :
                    self ._print_pipe_line ("  Item 1",first ,depth )
                continue 

            self ._print_pipe_line (str (key ),value ,depth )

    def _print_compact_tlv_section (self ,section_title :str ,parsed :Dict [int ,Any ],root_tag :Optional [int ])->None :
        print (f"\n{Config.Colors.BOLD}[+] {section_title}{Config.Colors.ENDC}")
        compact =self ._compact_tlv_node (parsed ,root_tag )
        is_empty =False 
        if not isinstance (compact ,dict ):
            is_empty =True 
        if isinstance (compact ,dict ):
            if len (compact )==0 :
                is_empty =True 
        if is_empty :
            print ("    | (Empty)")
            return 
        self ._print_compact_pipe_map (compact ,0 )

    def _decode_text_value (self ,tag :int ,value :Any ,parent_tag :Optional [int ])->str :
        if not isinstance (value ,bytes ):
            return ""
        decoded =self ._decode_value (tag ,value ,parent_tag )
        if isinstance (decoded ,str )and len (decoded )>=2 and decoded [0 ]=='"'and decoded [-1 ]=='"':
            return decoded [1 :-1 ]
        return str (decoded )

    def _collect_tag_bytes (self ,node :Any ,wanted_tag :int )->List [bytes ]:
        out :List [bytes ]=[]
        if isinstance (node ,dict ):
            for k ,v in node .items ():
                if k ==wanted_tag :
                    if isinstance (v ,bytes ):
                        out .append (v )
                    elif isinstance (v ,list ):
                        for item in v :
                            if isinstance (item ,bytes ):
                                out .append (item )
                            else :
                                out .extend (self ._collect_tag_bytes (item ,wanted_tag ))
                    else :
                        out .extend (self ._collect_tag_bytes (v ,wanted_tag ))
                else :
                    out .extend (self ._collect_tag_bytes (v ,wanted_tag ))
            return out 
        if isinstance (node ,list ):
            for item in node :
                out .extend (self ._collect_tag_bytes (item ,wanted_tag ))
            return out 
        return out 

    def _collect_tag_nodes (self ,node :Any ,wanted_tag :int )->List [Any ]:
        out :List [Any ]=[]
        if isinstance (node ,dict ):
            for k ,v in node .items ():
                if k ==wanted_tag :
                    if isinstance (v ,list ):
                        for item in v :
                            out .append (item )
                    else :
                        out .append (v )
                out .extend (self ._collect_tag_nodes (v ,wanted_tag ))
            return out 
        if isinstance (node ,list ):
            for item in node :
                out .extend (self ._collect_tag_nodes (item ,wanted_tag ))
            return out 
        return out 

    def _collect_decoded_values (self ,node :Any ,tag :int ,parent_tag :Optional [int ])->List [str ]:
        raw_values =self ._collect_tag_bytes (node ,tag )
        out :List [str ]=[]
        for raw in raw_values :
            decoded =self ._decode_value (tag ,raw ,parent_tag )
            text =str (decoded )
            if len (text )>=2 :
                if text [0 ]=='"'and text [-1 ]=='"':
                    text =text [1 :-1 ]
            if text not in out :
                out .append (text )
        return out 

    def _summarize_cert_block (self ,node :Any )->Dict [str ,Any ]:
        out :Dict [str ,Any ]={}

        summaries :List [Dict [str ,str ]]=[]
        seen_serials =set ()
        for blob in self ._iter_byte_values (node ):
            if len (blob )<32 :
                continue 
            info =AdvancedDecoders .decode_cert_der (blob )
            if not info :
                continue 
            serial =str (info .get ("serial",""))
            if serial in seen_serials :
                continue 
            seen_serials .add (serial )
            summaries .append (
            {
            "subject":str (info .get ("subject","")),
            "issuer":str (info .get ("issuer","")),
            "serial":serial ,
            "notBefore":str (info .get ("not_valid_before","")),
            "notAfter":str (info .get ("not_valid_after","")),
            }
            )
        if summaries :
            out ["certificates"]=summaries 

        bit_strings =self ._collect_tag_bytes (node ,0x03 )
        public_keys :List [str ]=[]
        signatures :List [str ]=[]
        for bit_val in bit_strings :
            label =self ._decode_value (0x03 ,bit_val ,None )
            if isinstance (label ,str )and label .startswith ("PublicKey:"):
                public_keys .append (label .replace ("PublicKey:","",1 ).strip ())
            elif isinstance (label ,str )and label .startswith ("Signature:"):
                signatures .append (label .replace ("Signature:","",1 ).strip ())
        if public_keys :
            out ["publicKeys"]=public_keys 
        if signatures :
            out ["signatures"]=signatures 

        object_identifiers =self ._collect_decoded_values (node ,0x06 ,None )
        if len (object_identifiers )>0 :
            out ["objectIdentifiers"]=object_identifiers 

        utf8_values =self ._collect_decoded_values (node ,0x0C ,None )
        if len (utf8_values )>0 :
            out ["utf8Strings"]=utf8_values 

        printable_values =self ._collect_decoded_values (node ,0x13 ,None )
        if len (printable_values )>0 :
            out ["printableStrings"]=printable_values 

        utc_values =self ._collect_decoded_values (node ,0x17 ,None )
        if len (utc_values )>0 :
            out ["utcTimes"]=utc_values 

        generalized_values =self ._collect_decoded_values (node ,0x18 ,None )
        if len (generalized_values )>0 :
            out ["generalizedTimes"]=generalized_values 

        boolean_values =self ._collect_decoded_values (node ,0x01 ,None )
        if len (boolean_values )>0 :
            out ["booleans"]=boolean_values 

        octet_values =self ._collect_decoded_values (node ,0x04 ,None )
        if len (octet_values )>0 :
            out ["octetStrings"]=octet_values 

        integer_values =self ._collect_decoded_values (node ,0x02 ,None )
        if len (integer_values )>0 :
            out ["integers"]=integer_values 

        return out 

    def _find_eim_entries (self ,node :Any )->List [Dict [int ,Any ]]:
        wanted_tags ={0x80 ,0x81 ,0x82 ,0x84 ,0xA5 ,0xA6 ,0x87 ,0x88 }
        found :List [Dict [int ,Any ]]=[]

        def walk (current :Any ):
            if isinstance (current ,dict ):
                keys =set (current .keys ())
                has_entry_shape =False 
                for k in keys :
                    if k in wanted_tags :
                        has_entry_shape =True 
                        break 
                if has_entry_shape :
                    found .append (current )
                for child in current .values ():
                    walk (child )
                return 

            if isinstance (current ,list ):
                for item in current :
                    walk (item )
                return 

        walk (node )
        return found 

    def _print_eim_configuration_compact_json (self ,parsed :Dict [int ,Any ])->None :
        root =TlvParser .get_first (parsed ,0xBF55 ,parsed )
        entries =self ._find_eim_entries (root )
        if len (entries )==0 :
            entries =self ._find_eim_entries (parsed )
        if len (entries )==0 :
            self ._print_compact_json (parsed ,0xBF55 )
            return 

        result_entries :List [Dict [str ,Any ]]=[]
        for entry in entries :
            row :Dict [str ,Any ]={}
            row ["eimId"]=self ._decode_text_value (0x80 ,TlvParser .get_first (entry ,0x80 ),0xE1 )
            row ["eimFqdn"]=self ._decode_text_value (0x81 ,TlvParser .get_first (entry ,0x81 ),0xE1 )
            row ["eimIdType"]=self ._decode_text_value (0x82 ,TlvParser .get_first (entry ,0x82 ),0xE1 )
            row ["counterValue"]=self ._decode_text_value (0x83 ,TlvParser .get_first (entry ,0x83 ),0xE1 )
            row ["associationToken"]=self ._decode_text_value (0x84 ,TlvParser .get_first (entry ,0x84 ),0xE1 )

            eim_pub_block =TlvParser .get_first (entry ,0xA5 )
            if eim_pub_block is not None :
                row ["eimPublicKeyData"]=self ._summarize_cert_block (eim_pub_block )

            tls_pub_block =TlvParser .get_first (entry ,0xA6 )
            if tls_pub_block is not None :
                row ["trustedPublicKeyDataTls"]=self ._summarize_cert_block (tls_pub_block )

            row ["eimSupportedProtocol"]=self ._decode_text_value (0x87 ,TlvParser .get_first (entry ,0x87 ),0xE1 )
            row ["euiccCiPKId"]=self ._decode_text_value (0x88 ,TlvParser .get_first (entry ,0x88 ),0xE1 )
            row ["indirectProfileDownload"]=self ._decode_text_value (0x89 ,TlvParser .get_first (entry ,0x89 ),0xE1 )

            cleaned_row ={}
            for k ,v in row .items ():
                if v is None :
                    continue 
                if isinstance (v ,str )and v =="":
                    continue 
                if isinstance (v ,dict )and len (v )==0 :
                    continue 
                cleaned_row [k ]=v 
            if cleaned_row :
                result_entries .append (cleaned_row )

        print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
        if len (result_entries )==0 :
            print ("    | (Empty)")
            return 

        def _short (val :Any ,max_len :int =72 )->str :
            text =str (val )
            is_short =False 
            if len (text )<=max_len :
                is_short =True 
            if is_short :
                return text 
            return text [:max_len ]+"..."

        def _first_dict (items :Any )->Optional [Dict [str ,Any ]]:
            if not isinstance (items ,list ):
                return None 
            for item in items :
                if isinstance (item ,dict ):
                    return item 
            return None 

        def _count_items (items :Any )->int :
            if not isinstance (items ,list ):
                return 0 
            return len (items )

        for idx ,row in enumerate (result_entries ,start =1 ):
            has_multiple =False 
            if len (result_entries )>1 :
                has_multiple =True 
            if has_multiple :
                print (f"    | Entry                : {Config.Colors.CYAN}{idx}{Config.Colors.ENDC}")

            field_order =[
            ("eimId","eIM ID"),
            ("eimFqdn","eIM FQDN"),
            ("eimIdType","eIM ID Type"),
            ("counterValue","Counter Value"),
            ("associationToken","Association Token"),
            ("eimSupportedProtocol","Supported Protocol"),
            ("euiccCiPKId","eUICC CI PKId"),
            ("indirectProfileDownload","Indirect Profile DL"),
            ]
            for field_key ,field_name in field_order :
                if field_key not in row :
                    continue 
                print (f"    | {field_name:<20}: {Config.Colors.CYAN}{row[field_key]}{Config.Colors.ENDC}")

            cert_sections =[
            ("eimPublicKeyData","eIM Public Key Data"),
            ("trustedPublicKeyDataTls","Trusted TLS Key Data"),
            ]
            for section_key ,section_name in cert_sections :
                if section_key not in row :
                    continue 
                section_value =row [section_key ]
                if not isinstance (section_value ,dict ):
                    continue 

                certificates =section_value .get ("certificates",[])
                public_keys =section_value .get ("publicKeys",[])
                signatures =section_value .get ("signatures",[])
                object_identifiers =section_value .get ("objectIdentifiers",[])
                cert_count_display =str (_count_items (certificates ))
                has_unsigned_evidence =False 
                if _count_items (certificates )==0 :
                    has_pub =False 
                    if _count_items (public_keys )>0 :
                        has_pub =True 
                    has_sig =False 
                    if _count_items (signatures )>0 :
                        has_sig =True 
                    if has_pub or has_sig :
                        has_unsigned_evidence =True 
                if has_unsigned_evidence :
                    cert_count_display ="n/a (summary unavailable)"

                print (f"    | {section_name:<20}: {Config.Colors.CYAN}Present{Config.Colors.ENDC}")
                print (f"    | {'  Certificates':<20}: {Config.Colors.CYAN}{cert_count_display}{Config.Colors.ENDC}")
                print (f"    | {'  Public Keys':<20}: {Config.Colors.CYAN}{_count_items(public_keys)}{Config.Colors.ENDC}")
                print (f"    | {'  Signatures':<20}: {Config.Colors.CYAN}{_count_items(signatures)}{Config.Colors.ENDC}")
                print (f"    | {'  OIDs':<20}: {Config.Colors.CYAN}{_count_items(object_identifiers)}{Config.Colors.ENDC}")

                first_cert =_first_dict (certificates )
                has_cert =False 
                if first_cert is not None :
                    has_cert =True 
                if has_cert :
                    cert_subject =first_cert .get ("subject","")
                    cert_issuer =first_cert .get ("issuer","")
                    cert_serial =first_cert .get ("serial","")
                    cert_not_before =first_cert .get ("notBefore","")
                    cert_not_after =first_cert .get ("notAfter","")
                    print (f"    | {'  Subject':<20}: {Config.Colors.CYAN}{_short(cert_subject)}{Config.Colors.ENDC}")
                    print (f"    | {'  Issuer':<20}: {Config.Colors.CYAN}{_short(cert_issuer)}{Config.Colors.ENDC}")
                    print (f"    | {'  Serial':<20}: {Config.Colors.CYAN}{cert_serial}{Config.Colors.ENDC}")
                    print (f"    | {'  Validity':<20}: {Config.Colors.CYAN}{cert_not_before} -> {cert_not_after}{Config.Colors.ENDC}")

                has_pub_key =False 
                if isinstance (public_keys ,list ):
                    if len (public_keys )>0 :
                        has_pub_key =True 
                if has_pub_key :
                    print (f"    | {'  Public Key (1st)':<20}: {Config.Colors.CYAN}{_short(public_keys[0])}{Config.Colors.ENDC}")

                has_signature =False 
                if isinstance (signatures ,list ):
                    if len (signatures )>0 :
                        has_signature =True 
                if has_signature :
                    print (f"    | {'  Signature (1st)':<20}: {Config.Colors.CYAN}{_short(signatures[0])}{Config.Colors.ENDC}")

            if idx <len (result_entries ):
                print ("")

    def _es10_retrieve (
    self ,
    payload :str ,
    title :str ,
    root_tag :Optional [int ]=None ,
    compact_json :bool =False ,
    )->None :
        """
        Generic ES10 retrieval helper using STORE DATA (80 E2 91 00).
        payload must include full TLV request object (e.g. BF4300).
        """
        self ._select_isd_r ()
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print (f"{Config.Colors.CYAN}[*] {title}...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 ==0x90 and data :
            print (f"{Config.Colors.HEADER}--- {title} ---{Config.Colors.ENDC}")
            try :
                parsed =TlvParser .parse (data )
                debug_enabled =bool (getattr (self .tp ,"debug",False ))
                if compact_json and not debug_enabled and root_tag ==0xBF55 :
                    self ._print_eim_configuration_compact_json (parsed )
                elif compact_json and not debug_enabled :
                    self ._print_compact_tlv_section (title ,parsed ,root_tag )
                else :
                    self ._print_tlv_tree (parsed ,indent =1 ,parent_tag =root_tag )
            except Exception :
                print (f"    {data.hex().upper()}")
            return 
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return 
        print ("    (Empty)")

    def _iter_byte_values (self ,node :Any ):
        """Yield every bytes leaf from nested parsed TLV structures."""
        if isinstance (node ,bytes ):
            yield node 
            return 
        if isinstance (node ,dict ):
            for v in node .values ():
                yield from self ._iter_byte_values (v )
            return 
        if isinstance (node ,list ):
            for item in node :
                yield from self ._iter_byte_values (item )
            return 

    def _print_cert_summary_from_parsed (self ,parsed :Dict [int ,Any ],title :str )->bool :
        """
        Print a compact certificate summary.
        Returns True if at least one certificate was decoded.
        """
        summaries =[]
        seen_serials =set ()
        for blob in self ._iter_byte_values (parsed ):
            if len (blob )<32 :
                continue 
            info =AdvancedDecoders .decode_cert_der (blob )
            if not info :
                continue 
            serial =str (info .get ("serial",""))
            if serial in seen_serials :
                continue 
            seen_serials .add (serial )
            summaries .append (info )

        if len (summaries )==0 :
            return False 

        print (f"\n{Config.Colors.BOLD}[+] {title}{Config.Colors.ENDC}")
        for idx ,info in enumerate (summaries ,start =1 ):
            has_multi =False 
            if len (summaries )>1 :
                has_multi =True 
            if has_multi :
                print (f"    | Entry                : {Config.Colors.CYAN}{idx}{Config.Colors.ENDC}")
            print (f"    | Subject              : {Config.Colors.CYAN}{self._short_display(info.get('subject', ''))}{Config.Colors.ENDC}")
            print (f"    | Issuer               : {Config.Colors.CYAN}{self._short_display(info.get('issuer', ''))}{Config.Colors.ENDC}")
            print (f"    | Serial               : {Config.Colors.CYAN}{info.get('serial', '')}{Config.Colors.ENDC}")
            print (f"    | Validity             : {Config.Colors.CYAN}{info.get('not_valid_before', '')} -> {info.get('not_valid_after', '')}{Config.Colors.ENDC}")
        return True 

    def _print_cert_block_summary_lines (self ,section_name :str ,section_value :Dict [str ,Any ])->None :
        def _short (val :Any ,max_len :int =72 )->str :
            text =str (val )
            is_short =False 
            if len (text )<=max_len :
                is_short =True 
            if is_short :
                return text 
            return text [:max_len ]+"..."

        def _first_dict (items :Any )->Optional [Dict [str ,Any ]]:
            if not isinstance (items ,list ):
                return None 
            for item in items :
                if isinstance (item ,dict ):
                    return item 
            return None 

        def _count_items (items :Any )->int :
            if not isinstance (items ,list ):
                return 0 
            return len (items )

        certificates =section_value .get ("certificates",[])
        public_keys =section_value .get ("publicKeys",[])
        signatures =section_value .get ("signatures",[])
        object_identifiers =section_value .get ("objectIdentifiers",[])

        cert_count_display =str (_count_items (certificates ))
        has_unsigned_evidence =False 
        if _count_items (certificates )==0 :
            has_pub =False 
            if _count_items (public_keys )>0 :
                has_pub =True 
            has_sig =False 
            if _count_items (signatures )>0 :
                has_sig =True 
            if has_pub or has_sig :
                has_unsigned_evidence =True 
        if has_unsigned_evidence :
            cert_count_display ="n/a (summary unavailable)"

        print (f"    | {section_name:<20}: {Config.Colors.CYAN}Present{Config.Colors.ENDC}")
        print (f"    | {'  Certificates':<20}: {Config.Colors.CYAN}{cert_count_display}{Config.Colors.ENDC}")
        print (f"    | {'  Public Keys':<20}: {Config.Colors.CYAN}{_count_items(public_keys)}{Config.Colors.ENDC}")
        print (f"    | {'  Signatures':<20}: {Config.Colors.CYAN}{_count_items(signatures)}{Config.Colors.ENDC}")
        print (f"    | {'  OIDs':<20}: {Config.Colors.CYAN}{_count_items(object_identifiers)}{Config.Colors.ENDC}")

        first_cert =_first_dict (certificates )
        has_cert =False 
        if first_cert is not None :
            has_cert =True 
        if has_cert :
            cert_subject =first_cert .get ("subject","")
            cert_issuer =first_cert .get ("issuer","")
            cert_serial =first_cert .get ("serial","")
            cert_not_before =first_cert .get ("notBefore","")
            cert_not_after =first_cert .get ("notAfter","")
            print (f"    | {'  Subject':<20}: {Config.Colors.CYAN}{_short(cert_subject)}{Config.Colors.ENDC}")
            print (f"    | {'  Issuer':<20}: {Config.Colors.CYAN}{_short(cert_issuer)}{Config.Colors.ENDC}")
            print (f"    | {'  Serial':<20}: {Config.Colors.CYAN}{cert_serial}{Config.Colors.ENDC}")
            print (f"    | {'  Validity':<20}: {Config.Colors.CYAN}{cert_not_before} -> {cert_not_after}{Config.Colors.ENDC}")

        has_pub_key =False 
        if isinstance (public_keys ,list ):
            if len (public_keys )>0 :
                has_pub_key =True 
        if has_pub_key :
            print (f"    | {'  Public Key (1st)':<20}: {Config.Colors.CYAN}{_short(public_keys[0])}{Config.Colors.ENDC}")

        has_signature =False 
        if isinstance (signatures ,list ):
            if len (signatures )>0 :
                has_signature =True 
        if has_signature :
            print (f"    | {'  Signature (1st)':<20}: {Config.Colors.CYAN}{_short(signatures[0])}{Config.Colors.ENDC}")

    def _print_get_certs_compact (self ,parsed :Dict [int ,Any ])->None :
        root_candidate =TlvParser .get_first (parsed ,0xBF56 ,parsed )
        root =root_candidate 
        is_root_bytes =False 
        if isinstance (root_candidate ,bytes ):
            is_root_bytes =True 
        if is_root_bytes :
            try :
                root =TlvParser .parse (root_candidate )
            except Exception :
                root =parsed 
        is_root_dict =False 
        if isinstance (root ,dict ):
            is_root_dict =True 
        if is_root_dict ==False :
            root =parsed 

        print (f"\n{Config.Colors.BOLD}[+] GetCerts{Config.Colors.ENDC}")
        if not isinstance (root ,dict ):
            print ("    | (Empty)")
            return 

        eim_blocks =self ._collect_tag_nodes (root ,0xA5 )
        tls_blocks =self ._collect_tag_nodes (root ,0xA6 )
        eim_pub =None 
        if len (eim_blocks )>0 :
            eim_pub =eim_blocks [0 ]
        tls_pub =None 
        if len (tls_blocks )>0 :
            tls_pub =tls_blocks [0 ]
        has_any =False 
        if eim_pub is not None :
            has_any =True 
        if tls_pub is not None :
            has_any =True 
        if has_any ==False :
            has_summary =self ._print_cert_summary_from_parsed (parsed ,"GetCerts Summary")
            if has_summary :
                return 
            print ("    | (No certificate blocks found)")
            return 

        if eim_pub is not None :
            eim_sum =self ._summarize_cert_block (eim_pub )
            self ._print_cert_block_summary_lines ("eIM Public Key Data",eim_sum )

        if tls_pub is not None :
            tls_sum =self ._summarize_cert_block (tls_pub )
            self ._print_cert_block_summary_lines ("Trusted TLS Key Data",tls_sum )

    def _print_notifications_list_compact (self ,parsed :Dict [int ,Any ])->None :
        print (f"\n{Config.Colors.BOLD}[+] RetrieveNotificationsList{Config.Colors.ENDC}")
        root =TlvParser .get_first (parsed ,0xBF2B ,parsed )
        entries =self ._collect_tag_nodes (root ,0xBF2F )
        has_entries =False 
        if len (entries )>0 :
            has_entries =True 
        if has_entries ==False :
            print ("    | Notification Entries : (Empty)")
            return 

        print (f"    | Notification Entries : {Config.Colors.CYAN}{len(entries)}{Config.Colors.ENDC}")
        first =entries [0 ]
        if not isinstance (first ,dict ):
            print (f"    | First Entry          : {Config.Colors.CYAN}(Unparsed){Config.Colors.ENDC}")
            return 

        seq_val =self ._decode_text_value (0x80 ,TlvParser .get_first (first ,0x80 ),0xBF2F )
        if len (seq_val )>0 :
            print (f"    | Seq Number           : {Config.Colors.CYAN}{seq_val}{Config.Colors.ENDC}")

        op_val =self ._decode_text_value (0x81 ,TlvParser .get_first (first ,0x81 ),0xBF2F )
        if len (op_val )>0 :
            print (f"    | Operation            : {Config.Colors.CYAN}{op_val}{Config.Colors.ENDC}")

        fqdn_values =self ._collect_decoded_values (first ,0x0C ,None )
        has_fqdn =False 
        if len (fqdn_values )>0 :
            has_fqdn =True 
        if has_fqdn :
            print (f"    | Server/FQDN          : {Config.Colors.CYAN}{self._short_display(fqdn_values[0])}{Config.Colors.ENDC}")

        id_values =self ._collect_decoded_values (first ,0x5A ,None )
        has_id =False 
        if len (id_values )>0 :
            has_id =True 
        if has_id :
            print (f"    | EID/ICCID            : {Config.Colors.CYAN}{id_values[0]}{Config.Colors.ENDC}")

        sig_values =self ._collect_decoded_values (first ,0x03 ,None )
        sig_count =0 
        for item in sig_values :
            if str (item ).startswith ("Signature:"):
                sig_count +=1 
        print (f"    | Signature Items      : {Config.Colors.CYAN}{sig_count}{Config.Colors.ENDC}")

    def _print_rat_compact (self ,parsed :Dict [int ,Any ])->None :
        print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
        compact =self ._compact_tlv_node (parsed ,0xBF43 )
        rat_obj =compact .get ("RAT (Rules Authorisation Table)",compact )
        is_dict =False 
        if isinstance (rat_obj ,dict ):
            is_dict =True 
        if is_dict ==False :
            print ("    | (Empty)")
            return 

        def _bitmap_set_bits (hex_text :str )->str :
            try :
                raw =bytes .fromhex (hex_text )
            except Exception :
                return ""
            bitmask =int .from_bytes (raw ,"big",signed =False )
            width =len (raw )*8 
            set_bits =[]
            for bit_idx in range (width -1 ,-1 ,-1 ):
                is_set =False 
                if ((bitmask >>bit_idx )&0x01 )==0x01 :
                    is_set =True 
                if is_set :
                    set_bits .append (str (bit_idx ))
            if len (set_bits )==0 :
                return "none"
            return ", ".join (set_bits )

        label_map ={
        "80":"Field 80 Values",
        "81":"Field 81 Value",
        "82":"Field 82 Bitmap",
        }

        emitted =0 
        for key ,value in rat_obj .items ():
            key_text =str (key )
            is_tag_hex =False 
            if len (key_text )==2 :
                try :
                    int (key_text ,16 )
                    is_tag_hex =True 
                except Exception :
                    is_tag_hex =False 
            label =key_text 
            if is_tag_hex :
                label =label_map .get (key_text ,f"Tag {key_text}")

            if isinstance (value ,str ):
                is_empty =False 
                if len (value .strip ())==0 :
                    is_empty =True 
                if is_empty :
                    continue 
                suffix =""
                is_tag82 =False 
                if key_text =="82":
                    is_tag82 =True 
                if is_tag82 :
                    bits =_bitmap_set_bits (value )
                    if len (bits )>0 :
                        suffix =f" (set bits: {bits})"
                print (f"    | {label:<20}: {Config.Colors.CYAN}{value}{suffix}{Config.Colors.ENDC}")
                emitted +=1 
                continue 

            if isinstance (value ,list ):
                filtered =[]
                for item in value :
                    text =str (item )
                    if len (text .strip ())==0 :
                        continue 
                    filtered .append (text )
                if len (filtered )==0 :
                    continue 
                preview =", ".join (filtered [:3 ])
                if len (filtered )>3 :
                    preview =preview +f", +{len(filtered) - 3} more"
                count =len (filtered )
                suffix =""
                is_tag82 =False 
                if key_text =="82":
                    is_tag82 =True 
                if is_tag82 :
                    bits =_bitmap_set_bits (filtered [0 ])
                    if len (bits )>0 :
                        suffix =f" (set bits: {bits})"
                print (f"    | {label:<20}: {Config.Colors.CYAN}{preview}{Config.Colors.ENDC}")
                print (f"    | {'  Count':<20}: {Config.Colors.CYAN}{count}{suffix}{Config.Colors.ENDC}")
                emitted +=1 
                continue 

            print (f"    | {label:<20}: {Config.Colors.CYAN}{self._short_display(value)}{Config.Colors.ENDC}")
            emitted +=1 

        if emitted ==0 :
            print ("    | (Empty)")

    def get_euicc_configured_data (self )->None :
        """ES10a.GetEuiccConfiguredData / GetEuiccConfiguredAddresses (retrieval)."""
        self ._es10_retrieve ("BF3C00","EuiccConfiguredData",root_tag =0xBF3C ,compact_json =True )

    def get_euicc_certs (self )->None :
        """ES10b.GetCerts (SGP.22/32 retrieval)."""
        self ._select_isd_r ()
        payload ="BF5600"
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print (f"{Config.Colors.CYAN}[*] GetCerts...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return 
        if not data :
            print ("    (Empty)")
            return 
        try :
            parsed =TlvParser .parse (data )
            debug_enabled =bool (getattr (self .tp ,"debug",False ))
            if debug_enabled :
                print (f"{Config.Colors.HEADER}--- GetCerts ---{Config.Colors.ENDC}")
                self ._print_tlv_tree (parsed ,indent =1 ,parent_tag =0xBF56 ,x509_mode =True )
                return 

            self ._print_get_certs_compact (parsed )
        except Exception :
            print (f"    {data.hex().upper()}")

    def get_eid (self )->None :
        """Retrieve EID from ECASD via GET DATA tag 5A."""
        ECASD_AID ="A0000005591010FFFFFFFF8900000200"
        self .tp .transmit (f"00A40400{len(ECASD_AID)//2:02X}{ECASD_AID}",silent =True )
        data ,sw1 ,sw2 =self .tp .transmit ("00CA005A00",silent =True )
        if sw1 ==0x90 and data :
            print (f"{Config.Colors.HEADER}--- EID ---{Config.Colors.ENDC}")
            try :
                parsed =TlvParser .parse (data )
                eid =TlvParser .get_first (parsed ,0x5A ,data )
                if isinstance (eid ,bytes ):
                    print (f"    {eid.hex().upper()}")
                else :
                    print (f"    {data.hex().upper()}")
            except Exception :
                print (f"    {data.hex().upper()}")
            return 
        print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_rat (self )->None :
        """ES10b.GetRAT (SGP.22/32) – Rules Authorisation Table. Retrieval only."""
        self ._select_isd_r ()
        payload ="BF4300"
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print (f"{Config.Colors.CYAN}[*] GetRAT (Rules Authorisation Table)...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return 
        if not data :
            print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
            print ("    | (Empty)")
            return 
        try :
            parsed =TlvParser .parse (data )
            debug_enabled =bool (getattr (self .tp ,"debug",False ))
            if debug_enabled :
                print (f"{Config.Colors.HEADER}--- GetRAT (Rules Authorisation Table) ---{Config.Colors.ENDC}")
                self ._print_tlv_tree (parsed ,indent =1 ,parent_tag =0xBF43 )
                return 
            self ._print_rat_compact (parsed )
        except Exception :
            print (f"    {data.hex().upper()}")

    def get_notifications_list (self )->None :
        """ES10b.RetrieveNotificationsList (SGP.22/32) – Pending notifications. Retrieval only."""
        self ._select_isd_r ()
        payload ="BF2B00"
        cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        print (f"{Config.Colors.CYAN}[*] RetrieveNotificationsList...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )
        if sw1 !=0x90 :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return 
        if not data :
            print (f"\n{Config.Colors.BOLD}[+] RetrieveNotificationsList{Config.Colors.ENDC}")
            print ("    | (Empty)")
            return 
        try :
            parsed =TlvParser .parse (data )
            debug_enabled =bool (getattr (self .tp ,"debug",False ))
            if debug_enabled :
                print (f"{Config.Colors.HEADER}--- RetrieveNotificationsList ---{Config.Colors.ENDC}")
                self ._print_tlv_tree (parsed ,indent =1 ,parent_tag =0xBF2B )
                return 
            self ._print_notifications_list_compact (parsed )
        except Exception :
            print (f"    {data.hex().upper()}")

    def get_eim_configuration_data (self )->None :
        """ES10b.GetEimConfigurationData (SGP.32 IoT) – eIM configuration data. Retrieval only."""
        self ._es10_retrieve (
        "BF5500",
        "GetEimConfigurationData (eIM config, SGP.32)",
        root_tag =0xBF55 ,
        compact_json =True ,
        )

    def get_sgp32_all_data (self )->None :
        """
        Consolidated SGP.32 read-only retrieval bundle.
        Includes GET-IOT-equivalent scan and additional SGP.32 retrieval commands.
        """
        print (f"\n{Config.Colors.HEADER}=== SGP.32 Consolidated Data Retrieval ==={Config.Colors.ENDC}")
        self .run_sgp22_scan ()
        self ._select_isd_r ()

        rat_data =self ._es10_retrieve_data ("BF4300")
        if rat_data :
            try :
                rat_parsed =TlvParser .parse (rat_data )
                self ._print_rat_compact (rat_parsed )
            except Exception :
                print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
                print (f"    | {rat_data.hex().upper()}")
        else :
            print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
            print (f"    | {Config.Colors.FAIL}Failed / Empty{Config.Colors.ENDC}")

        notif_data =self ._es10_retrieve_data ("BF2B00")
        if notif_data :
            try :
                notif_parsed =TlvParser .parse (notif_data )
                self ._print_notifications_list_compact (notif_parsed )
            except Exception :
                print (f"\n{Config.Colors.BOLD}[+] RetrieveNotificationsList{Config.Colors.ENDC}")
                print (f"    | {notif_data.hex().upper()}")
        else :
            print (f"\n{Config.Colors.BOLD}[+] RetrieveNotificationsList{Config.Colors.ENDC}")
            print (f"    | {Config.Colors.FAIL}Failed / Empty{Config.Colors.ENDC}")

        eim_data =self ._es10_retrieve_data ("BF5500")
        if eim_data :
            try :
                eim_parsed =TlvParser .parse (eim_data )
                self ._print_eim_configuration_compact_json (eim_parsed )
            except Exception :
                print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
                print (f"    | {eim_data.hex().upper()}")
        else :
            print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
            print (f"    | {Config.Colors.FAIL}Failed / Empty{Config.Colors.ENDC}")

        cert_data =self ._es10_retrieve_data ("BF5600")
        if cert_data :
            try :
                cert_parsed =TlvParser .parse (cert_data )
                self ._print_get_certs_compact (cert_parsed )
            except Exception :
                print (f"\n{Config.Colors.BOLD}[+] GetCerts{Config.Colors.ENDC}")
                print (f"    | {cert_data.hex().upper()}")
        else :
            print (f"\n{Config.Colors.BOLD}[+] GetCerts{Config.Colors.ENDC}")
            print (f"    | {Config.Colors.FAIL}Failed / Empty{Config.Colors.ENDC}")

    def enable_profile (self ,identifier :str )->bool :
        return self ._send_cmd (identifier ,self .TAG_ENABLE_PROFILE ,"Enabling")

    def disable_profile (self ,identifier :str )->bool :
        return self ._send_cmd (identifier ,self .TAG_DISABLE_PROFILE ,"Disabling")

    def delete_profile (self ,identifier :str )->bool :
        return self ._send_cmd (identifier ,self .TAG_DELETE_PROFILE ,"Deleting")

    def _send_cmd (self ,identifier :str ,func_tag :int ,action_str :str )->bool :
        resolved =self ._resolve_target (identifier )
        if not resolved :return False 

        tag_type ,value_hex =resolved 
        type_lbl ="ICCID"if tag_type ==self .TAG_ICCID else "AID"
        print (f"{Config.Colors.CYAN}[*] {action_str} Profile ({type_lbl}): {value_hex}...{Config.Colors.ENDC}")

        self ._select_isd_r ()

        val_bytes =bytes .fromhex (value_hex )
        tlv_id =bytes ([tag_type ,len (val_bytes )])+val_bytes 
        tlv_choice =bytes ([self .TAG_CTX_0 ,len (tlv_id )])+tlv_id 
        tlv_refresh =bytes ([0x81 ,0x01 ,0x00 ])

        inner =tlv_choice +tlv_refresh 
        payload =bytes ([func_tag >>8 ,func_tag &0xFF ,len (inner )])+inner 

        cmd =f"80E29100{len(payload):02X}{payload.hex()}"
        data ,sw1 ,sw2 =self .tp .transmit (cmd ,silent =True )

        return self ._check_result (data ,sw1 ,sw2 ,func_tag )

    def _check_result (self ,data ,sw1 ,sw2 ,outer_tag )->bool :
        if sw1 !=0x90 and sw1 !=0x91 :
            print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
            return False 

        if sw1 ==0x91 :
            print (f"{Config.Colors.WARNING}[*] Proactive Command Pending (SW=91xx).{Config.Colors.ENDC}")

        parsed =TlvParser .parse (data )
        outer =TlvParser .get_first (parsed ,outer_tag )
        content =outer if isinstance (outer ,dict )else (TlvParser .parse (outer )if isinstance (outer ,bytes )else parsed )

        if self .TAG_RESULT in content :
            val =content [self .TAG_RESULT ]
            res_code =int .from_bytes (val ,'big')if isinstance (val ,bytes )else 0 
            if res_code ==0 :
                print (f"{Config.Colors.GREEN}[+] Success.{Config.Colors.ENDC}")
                return True 
            else :
                errs ={1 :"Profile Not Found",2 :"Already in State",7 :"Command Error (Struct)",127 :"Undefined Error"}
                print (f"{Config.Colors.FAIL}[-] Error 0x{res_code:02X}: {errs.get(res_code, 'Unknown')}{Config.Colors.ENDC}")
                return False 

        print (f"{Config.Colors.GREEN}[+] Success (No Result Code).{Config.Colors.ENDC}")
        return True 

    def _resolve_target (self ,identifier :str )->Optional [Tuple [int ,str ]]:
        clean =identifier .strip ().upper ()
        if clean in self .profile_cache :return self .profile_cache [clean ]
        if clean .startswith ("A0")and len (clean )>=10 :return (self .TAG_AID ,clean )
        if (clean .startswith ("89")or clean .startswith ("98"))and len (clean )>=18 :
            return (self .TAG_ICCID ,self ._swap_nibbles (clean )if clean .startswith ("89")else clean )
        print (f"{Config.Colors.FAIL}[!] Unknown Profile: '{identifier}'. Run LIST first.{Config.Colors.ENDC}")
        return None 