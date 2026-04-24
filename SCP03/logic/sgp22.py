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

import json 
import re
import shutil 
import textwrap 
from datetime import datetime
from typing import List ,Dict ,Optional ,Tuple ,Any 
from SCP03 .config import Config 
from SCP03 .core .utils import HexUtils ,TlvParser 
from SCP03 .core .decoders import AdvancedDecoders 
from SCP03 .logic .euicc_info2 import build_euicc_info2_detail_lines 
from SCP03 .logic .euicc_info2 import decode_euicc_info2_value 
from SCP03 .logic .euicc_info2 import resolve_euicc_info2_tag_name 
from SCP03 .logic .sgp32_decode import decode_eim_configuration_entries 
from SCP03 .logic .sgp32_decode import decode_get_certs_response 
from SCP03 .logic .sgp32_decode import decode_notifications_response 
from SCP03 .logic .sgp32_decode import decode_rat_rules 
from SCP03 .logic .sgp32_decode import EIM_SUPPORTED_PROTOCOL_FLAGS 
from SCP03 .logic .sgp32_decode import format_named_bit_string 
from yggdrasim_common .euicc_issuer import infer_ecasd_issuer_identity

class Sgp22Manager :
    """
    Implements GSMA SGP.22/SGP.32 data retrieval and local profile state (list, enable, disable, delete).
    Supports ES10c/ES10b retrieval: GetProfilesInfo, GetRAT, RetrieveNotificationsList,
    GetEimConfigurationData (SGP.32 IoT), EuiccInfo1/2, EuiccConfiguredData.
    SCP11 provisioning is handled by the dedicated SCP11 live/test/local_access modules.
    Local STORE DATA retrievals use the retry ladder: base channel, then logical channel 1,
    then STK mode after reset when cards reject the direct path.
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
        """Executes SGP.22/SGP.32 retrievals using the local retry ladder."""
        print (f"\n{Config.Colors.HEADER}=== Running SGP.22/SGP.32 Scan ==={Config.Colors.ENDC}")
        self .get_eid ()
        self .list_profiles ()
        self .get_euicc_configured_data ()
        self ._es10_retrieve ("BF2000","EuiccInfo1",root_tag =0xBF20 )
        self ._es10_retrieve ("BF2200","EuiccInfo2",root_tag =0xBF22 )

    def run_sgp02_scan (self ):
        """Executes the custom SGP.02 scanning sequence."""
        self ._execute_sequence (self .SEQUENCE_SGP02 ,"SGP.02 Scan")

    def get_euicc_report (self )->Dict [str ,Any ]:
        """
        Runs SGP.22 retrieval set and returns structured data for export (no print).
        Returns dict with: profiles, eid, euicc_info1, euicc_info2, euicc_configured_data,
        key_info, sd_mgmt_data (hex strings where applicable).
        """
        list_data =self ._es10_retrieve_data ("BF2D00")
        euicc_info1_data =self ._es10_retrieve_data ("BF2000")
        euicc_info2_data =self ._es10_retrieve_data ("BF2200")
        euicc_cfg_data =self ._es10_retrieve_data ("BF3C00")
        eid_data ,_eid_sw1 ,_eid_sw2 =self ._retrieve_eid_response ()

        list_hex =list_data .hex ().upper ()if list_data else ""
        euicc_info1_raw =euicc_info1_data .hex ().upper ()if euicc_info1_data else ""
        euicc_info2_raw =euicc_info2_data .hex ().upper ()if euicc_info2_data else ""
        euicc_cfg_raw =euicc_cfg_data .hex ().upper ()if euicc_cfg_data else ""
        key_info_raw =""
        sd_mgmt_raw =""
        eid_hex =""
        if eid_data :
            eid_hex =self ._extract_eid_hex (eid_data )

        euicc_info1_decoded =self ._compact_from_hex (euicc_info1_raw ,0xBF20 )
        euicc_info2_decoded =self ._compact_from_hex (euicc_info2_raw ,0xBF22 )
        euicc_cfg_decoded =self ._compact_from_hex (euicc_cfg_raw ,0xBF3C )
        key_info_decoded =self ._compact_from_hex (key_info_raw ,0xE0 )
        sd_mgmt_decoded =self ._compact_from_hex (sd_mgmt_raw ,0x66 )
        report ={
        "profiles":[],
        "eid":eid_hex ,
        "euicc_info1":euicc_info1_decoded if euicc_info1_decoded else euicc_info1_raw ,
        "euicc_info2":euicc_info2_decoded if euicc_info2_decoded else euicc_info2_raw ,
        "euicc_configured_data":euicc_cfg_decoded if euicc_cfg_decoded else euicc_cfg_raw ,
        "key_info":key_info_decoded if key_info_decoded else key_info_raw ,
        "sd_mgmt_data":sd_mgmt_decoded if sd_mgmt_decoded else sd_mgmt_raw ,
        "euicc_info1_raw":euicc_info1_raw ,
        "euicc_info2_raw":euicc_info2_raw ,
        "euicc_configured_data_raw":euicc_cfg_raw ,
        "key_info_raw":key_info_raw ,
        "sd_mgmt_data_raw":sd_mgmt_raw ,
        }
        if list_hex :
            try :
                data =bytes .fromhex (list_hex )
                report ["profiles"]=self ._profile_list_to_dicts (data )
            except Exception :
                report ["profiles"]=[]
        return report 

    def _compact_from_hex (self ,data_hex :str ,root_tag :Optional [int ])->Dict [str ,Any ]:
        if not data_hex :
            return {}
        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return {}

        parsed =self ._safe_parse_tlv (data )
        if not parsed :
            return {}

        compact =self ._compact_tlv_node (parsed ,root_tag )
        if isinstance (compact ,dict ):
            return compact 
        return {}

    def _read_der_length (self ,data :bytes ,length_idx :int )->Tuple [int ,int ]:
        has_len =False 
        if length_idx <len (data ):
            has_len =True 
        if has_len ==False :
            return (0 ,0 )

        first =data [length_idx ]
        is_short =False 
        if (first &0x80 )==0 :
            is_short =True 
        if is_short :
            return (first ,1 )

        n_len =first &0x7F 
        has_len_bytes =False 
        if n_len >0 :
            if n_len <=4 :
                has_len_bytes =True 
        if has_len_bytes ==False :
            return (0 ,0 )

        end =length_idx +1 +n_len 
        in_range =False 
        if end <=len (data ):
            in_range =True 
        if in_range ==False :
            return (0 ,0 )

        length =int .from_bytes (data [length_idx +1 :end ],"big")
        return (length ,1 +n_len )

    def _collect_cert_summaries_from_raw (self ,data :bytes )->List [Dict [str ,Any ]]:
        out :List [Dict [str ,Any ]]=[]
        seen_serials =set ()
        i =0 
        while i <len (data ):
            is_seq =False 
            if data [i ]==0x30 :
                is_seq =True 

            if is_seq ==False :
                i +=1 
                continue 

            der_len ,len_octets =self ._read_der_length (data ,i +1 )
            has_len =False 
            if der_len >0 :
                if len_octets >0 :
                    has_len =True 
            if has_len ==False :
                i +=1 
                continue 

            total_len =1 +len_octets +der_len 
            end_idx =i +total_len 
            in_range =False 
            if end_idx <=len (data ):
                in_range =True 
            if in_range ==False :
                i +=1 
                continue 

            candidate =data [i :end_idx ]
            info =AdvancedDecoders .decode_cert_der (candidate )
            has_info =False 
            if info :
                has_info =True 
            if has_info :
                serial =str (info .get ("serial",""))
                is_new =False 
                if serial not in seen_serials :
                    is_new =True 
                if is_new :
                    seen_serials .add (serial )
                    out .append (
                    {
                    "subject":str (info .get ("subject","")),
                    "issuer":str (info .get ("issuer","")),
                    "serial":serial ,
                    "not_valid_before":str (info .get ("not_valid_before","")),
                    "not_valid_after":str (info .get ("not_valid_after","")),
                    }
                    )
                    i =end_idx 
                    continue 

            i +=1 
        return out 

    def _export_eim_configuration_data (self )->Dict [str ,Any ]:
        data =self ._es10_retrieve_data ("BF5500")
        if not data :
            return {}

        parsed =self ._safe_parse_tlv (data )
        out_entries :List [Dict [str ,Any ]]=[]
        for entry in decode_eim_configuration_entries (data ):
            row :Dict [str ,Any ]=dict (entry )
            eim_pub =entry .get ("eim_public_key_data")
            if isinstance (eim_pub ,bytes ):
                row ["eim_public_key_data_raw_hex"]=eim_pub .hex ().upper ()
                row ["eim_public_key_data"]=self ._summarize_cert_block (eim_pub )
            tls_pub =entry .get ("trusted_tls_public_key_data")
            if isinstance (tls_pub ,bytes ):
                row ["trusted_tls_public_key_data_raw_hex"]=tls_pub .hex ().upper ()
                row ["trusted_tls_public_key_data"]=self ._summarize_cert_block (tls_pub )

            clean_row :Dict [str ,Any ]={}
            for key ,value in row .items ():
                if value is None :
                    continue 
                if isinstance (value ,str ):
                    if len (value )==0 :
                        continue 
                if isinstance (value ,dict ):
                    if len (value )==0 :
                        continue 
                clean_row [key ]=value 

            if len (clean_row )>0 :
                out_entries .append (clean_row )

        if len (out_entries )>0 :
            return {
            "entries":out_entries ,
            "raw_hex":data .hex ().upper ()
            }

        if not parsed :
            return {"raw_hex":data .hex ().upper ()}

        compact =self ._compact_tlv_node (parsed ,0xBF55 )
        return {
        "compact":compact ,
        "raw_hex":data .hex ().upper ()
        }

    def _export_notifications_list (self )->Dict [str ,Any ]:
        data =self ._es10_retrieve_data ("BF2B00")
        if not data :
            return {
            "notifications":[],
            "package_results":[],
            }

        decoded =decode_notifications_response (data )
        out :Dict [str ,Any ]={
        "notifications":decoded .get ("notifications",[]),
        "package_results":[],
        "raw_hex":data .hex ().upper (),
        }
        if "error"in decoded :
            error_text =str (decoded .get ("error","")).strip ()
            if len (error_text )>0 :
                out ["error"]=error_text

        package_results =decoded .get ("package_results",[])
        if isinstance (package_results ,list ):
            out ["package_results"]=[
            item .hex ().upper ()
            for item in package_results
            if isinstance (item ,bytes )
            ]
        return out

    def _export_get_certs (self )->Dict [str ,Any ]:
        data =self ._es10_retrieve_data ("BF5600")
        if not data :
            return {}

        decoded =decode_get_certs_response (data )
        out :Dict [str ,Any ]={
        "raw_hex":data .hex ().upper ()
        }
        error_text =str (decoded .get ("error","")).strip ()
        if len (error_text )>0 :
            out ["error"]=error_text
            return out

        for source_key ,target_key in [
        ("eumCertificate","eum_certificate"),
        ("euiccCertificate","euicc_certificate"),
        ]:
            value =decoded .get (source_key )
            if not isinstance (value ,bytes ):
                continue
            entry :Dict [str ,Any ]={
            "raw_hex":value .hex ().upper ()
            }
            summary =self ._summarize_cert_block (value )
            if len (summary )>0 :
                entry ["summary"]=summary
            out [target_key ]=entry

        has_cert_entries =False
        for key in ("eum_certificate","euicc_certificate"):
            if key in out :
                has_cert_entries =True
                break
        if has_cert_entries :
            return out

        fallback =self ._summarize_cert_block (data )
        if len (fallback )>0 :
            out ["summary"]=fallback
        return out

    def _es10_retrieve_data (self ,payload :str )->bytes :
        self ._select_isd_r ()
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
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

    def _looks_like_profile_node (self ,node :Any )->bool :
        is_dict =False
        if isinstance (node ,dict ):
            is_dict =True
        if is_dict ==False :
            return False
        match_count =0
        for tag in [
        self .TAG_AID ,
        self .TAG_ICCID ,
        self .TAG_STATE ,
        self .TAG_NICKNAME ,
        self .TAG_NAME ,
        self .TAG_SP_NAME ,
        self .TAG_CLASS ,
        ]:
            if tag in node :
                match_count +=1
        if match_count >=2 :
            return True
        has_identity =False
        if self .TAG_AID in node or self .TAG_ICCID in node :
            has_identity =True
        has_name =False
        if self .TAG_NICKNAME in node or self .TAG_NAME in node or self .TAG_SP_NAME in node :
            has_name =True
        if has_identity and has_name :
            return True
        return False

    def _collect_profile_nodes (self ,node :Any )->List [Dict [int ,Any ]]:
        out :List [Dict [int ,Any ]]=[]
        if self ._looks_like_profile_node (node ):
            out .append (node )
            return out
        if isinstance (node ,dict ):
            for value in node .values ():
                out .extend (self ._collect_profile_nodes (value ))
            return out
        if isinstance (node ,list ):
            for item in node :
                out .extend (self ._collect_profile_nodes (item ))
            return out
        if isinstance (node ,(bytes ,bytearray ,memoryview )):
            parsed =self ._safe_parse_tlv (bytes (node ))
            if parsed :
                out .extend (self ._collect_profile_nodes (parsed ))
        return out

    def _scan_profile_blobs_from_raw (self ,data :bytes )->List [bytes ]:
        blobs :List [bytes ]=[]
        i =0
        while i <len (data ):
            if data [i ]!=0xE3 :
                i +=1
                continue
            if i +1 >=len (data ):
                break
            length =data [i +1 ]
            offset =2
            if length &0x80 :
                n =length &0x7F
                if i +2 +n >len (data ):
                    break
                length =int .from_bytes (data [i +2 :i +2 +n ],"big")
                offset =2 +n
            end =i +offset +length
            if end >len (data ):
                break
            blobs .append (data [i +offset :end ])
            i =end
        return blobs

    def _profile_nodes_from_data (self ,data :bytes )->List [Any ]:
        parsed =self ._safe_parse_tlv (data )
        if parsed :
            profile_nodes =self ._collect_profile_nodes (parsed )
            if len (profile_nodes )>0 :
                return profile_nodes
        return self ._scan_profile_blobs_from_raw (data )

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
        For SGP.32, include additional retrievals not covered by GET-IOT,
        preserving the decoded structure for notifications, eIM configuration,
        and certificate material.
        """
        std =standard .strip ().upper ()
        is_empty =False 
        if len (std )==0 :
            is_empty =True 
        if is_empty :
            std ="SGP.32"

        is_sgp02 =False
        if std =="SGP.02":
            is_sgp02 =True
        if std =="02":
            is_sgp02 =True
        if is_sgp02 :
            report_02 =self ._get_euicc_report_sgp02_dual_path ()
            report_02 ["standard"]="SGP.02"
            return report_02

        report =self .get_euicc_report ()
        report ["standard"]=std 

        if std !="SGP.32":
            return report 

        sgp32_section :Dict [str ,Any ]={}

        sgp32_section ["get_rat"]=self ._compact_from_payload ("BF4300",0xBF43 )
        sgp32_section ["retrieve_notifications_list"]=self ._export_notifications_list ()
        sgp32_section ["get_eim_configuration_data"]=self ._export_eim_configuration_data ()
        sgp32_section ["get_certs"]=self ._export_get_certs ()

        report ["sgp32_extra"]=sgp32_section 
        return report 

    def _tlv_to_plain (self ,node :Any )->Any :
        if isinstance (node ,dict ):
            out :Dict [str ,Any ]={}
            for key ,value in node .items ():
                key_text =str (key )
                if isinstance (key ,int ):
                    if key <=0xFF :
                        key_text =f"{key:02X}"
                    else :
                        key_text =f"{key:04X}"
                out [key_text ]=self ._tlv_to_plain (value )
            return out 
        if isinstance (node ,list ):
            out_list :List [Any ]=[]
            for item in node :
                out_list .append (self ._tlv_to_plain (item ))
            return out_list 
        if isinstance (node ,bytes ):
            return node .hex ().upper ()
        return node 

    def _is_success_sw (self ,sw1 :int )->bool :
        if sw1 ==0x90 :
            return True
        if sw1 ==0x61 :
            return True
        return False

    def _probe_get_data_with_cla_candidates (self ,cla_values :List [int ],p1 :int ,p2 :int )->Dict [str ,Any ]:
        attempts :List [Dict [str ,Any ]]=[]
        selected_entry :Dict [str ,Any ]={}
        has_selected =False
        for cla in cla_values :
            apdu =f"{cla:02X}CA{p1:02X}{p2:02X}00"
            data ,sw1 ,sw2 =self .tp .transmit (apdu ,silent =True )
            entry :Dict [str ,Any ]={
            "apdu":apdu ,
            "status":f"{sw1:02X}{sw2:02X}",
            "raw_hex":data .hex ().upper (),
            }
            can_decode =False
            if self ._is_success_sw (sw1 ):
                if len (data )>0 :
                    can_decode =True
            if can_decode :
                try :
                    parsed =TlvParser .parse (data )
                    entry ["decoded"]=self ._tlv_to_plain (parsed )
                except Exception :
                    pass 
            attempts .append (entry )
            if has_selected ==False :
                has_selected =True
                selected_entry =entry 
            if self ._is_success_sw (sw1 ):
                selected_entry =entry 
                break
        out :Dict [str ,Any ]={}
        out ["attempts"]=attempts 
        out ["result"]=selected_entry 
        return out 

    def _run_sgp02_domain_probe (self ,mode_name :str ,use_logical_channel :bool )->Dict [str ,Any ]:
        mode_report :Dict [str ,Any ]={}
        mode_report ["mode"]=mode_name 
        mode_report ["uses_logical_channel"]=use_logical_channel 
        channel_id =0 
        open_status ="SKIPPED"
        if use_logical_channel :
            open_resp ,open_sw1 ,open_sw2 =self .tp .transmit ("0070000001",silent =True )
            open_status =f"{open_sw1:02X}{open_sw2:02X}"
            is_open_ok =False
            if self ._is_success_sw (open_sw1 ):
                if len (open_resp )>=1 :
                    is_open_ok =True
            if is_open_ok :
                channel_id =open_resp [0 ]
            else :
                mode_report ["open_channel_status"]=open_status 
                mode_report ["channel_id"]=channel_id 
                mode_report ["domains"]={}
                mode_report ["close_channel_status"]="SKIPPED"
                return mode_report
        mode_report ["open_channel_status"]=open_status 
        mode_report ["channel_id"]=channel_id 

        domains :List [Tuple [str ,str ,List [Tuple [str ,int ,int ]]]]=[]
        domains .append (
        (
        "ecasd",
        "A0000005591010FFFFFFFF8900000200",
        [
        ("eid",0x00 ,0x5A ),
        ("sd_management_data",0x00 ,0x66 ),
        ("card_capabilities",0x00 ,0x67 ),
        ("issuer_identification_number",0x00 ,0x42 ),
        ("card_image_number",0x00 ,0x45 ),
        ],
        )
        )
        domains .append (
        (
        "isdr",
        "A0000005591010FFFFFFFF8900000100",
        [
        ("key_information_template",0x00 ,0xE0 ),
        ("sd_management_data",0x00 ,0x66 ),
        ("card_capabilities",0x00 ,0x67 ),
        ("applications_in_sd",0x2F ,0x00 ),
        ],
        )
        )

        domain_report :Dict [str ,Any ]={}
        for domain_name ,aid_hex ,tags in domains :
            select_cla =0x00
            if use_logical_channel :
                select_cla =channel_id 
            select_apdu =f"{select_cla:02X}A40400{len(aid_hex)//2:02X}{aid_hex}"
            select_data ,sel_sw1 ,sel_sw2 =self .tp .transmit (select_apdu ,silent =True )
            entry :Dict [str ,Any ]={}
            entry ["aid"]=aid_hex 
            entry ["select_apdu"]=select_apdu 
            entry ["select_status"]=f"{sel_sw1:02X}{sel_sw2:02X}"
            entry ["select_raw_hex"]=select_data .hex ().upper ()
            entry ["tags"]={}
            if self ._is_success_sw (sel_sw1 ):
                for tag_name ,p1 ,p2 in tags :
                    cla_values :List [int ]=[]
                    if use_logical_channel :
                        cla_values .append (channel_id )
                        cla_values .append (0x80 |channel_id )
                    else :
                        cla_values .append (0x00 )
                        cla_values .append (0x80 )
                    probe =self ._probe_get_data_with_cla_candidates (cla_values ,p1 ,p2 )
                    tag_entry :Dict [str ,Any ]={}
                    tag_entry ["tag"]=f"{p1:02X}{p2:02X}"
                    tag_entry ["attempts"]=probe .get ("attempts",[])
                    tag_entry ["result"]=probe .get ("result",{})
                    entry ["tags"][tag_name ]=tag_entry 
            domain_report [domain_name ]=entry 
        mode_report ["domains"]=domain_report 

        close_status ="SKIPPED"
        if use_logical_channel :
            close_apdu =f"007080{channel_id:02X}00"
            _close_data ,close_sw1 ,close_sw2 =self .tp .transmit (close_apdu ,silent =True )
            close_status =f"{close_sw1:02X}{close_sw2:02X}"
        mode_report ["close_channel_status"]=close_status 
        return mode_report 

    @staticmethod
    def _decode_bcd_digits (value :bytes )->str :
        digits =""
        for byte in value :
            high =(byte >>4 )&0x0F 
            low =byte &0x0F 
            for nibble in [high ,low ]:
                if nibble ==0x0F :
                    continue 
                digits +=str (nibble )
        return digits

    def _decode_ecasd_issuer_number_from_result (self ,result_entry :Dict [str ,Any ])->str :
        if isinstance (result_entry ,dict )==False :
            return ""
        raw_hex =str (result_entry .get ("raw_hex","")).strip ().upper ()
        if len (raw_hex )==0 :
            return ""
        raw_bytes =b""
        try :
            raw_bytes =bytes .fromhex (raw_hex )
        except Exception :
            return ""
        try :
            parsed =TlvParser .parse (raw_bytes )
        except Exception :
            return self ._decode_bcd_digits (raw_bytes )
        value =TlvParser .get_first (parsed ,0x42 )
        if isinstance (value ,bytes )==False :
            return self ._decode_bcd_digits (raw_bytes )
        return self ._decode_bcd_digits (value )

    def get_ecasd_issuer_identity (self )->Dict [str ,str ]:
        for use_logical_channel in (False ,True ):
            mode_name ="basic"
            if use_logical_channel :
                mode_name ="logical_channel_01"
            try :
                report =self ._run_sgp02_domain_probe (mode_name ,use_logical_channel )
            except Exception :
                continue 
            domains =report .get ("domains",{})
            if isinstance (domains ,dict )==False :
                continue 
            ecasd =domains .get ("ecasd",{})
            if isinstance (ecasd ,dict )==False :
                continue 
            tags =ecasd .get ("tags",{})
            if isinstance (tags ,dict )==False :
                continue 
            issuer_entry =tags .get ("issuer_identification_number",{})
            if isinstance (issuer_entry ,dict )==False :
                continue 
            result_entry =issuer_entry .get ("result",{})
            issuer_number =self ._decode_ecasd_issuer_number_from_result (result_entry )
            if len (issuer_number )>0 :
                return infer_ecasd_issuer_identity (issuer_number )
        return infer_ecasd_issuer_identity ("")

    def _get_euicc_report_sgp02_dual_path (self )->Dict [str ,Any ]:
        report :Dict [str ,Any ]={}
        report ["approach"]="Dual-path SGP.02 probe (basic channel and logical channel 01)."
        report ["probe_modes"]={}
        report ["probe_modes"]["basic"]=self ._run_sgp02_domain_probe ("basic",False )
        report ["probe_modes"]["logical_channel_01"]=self ._run_sgp02_domain_probe ("logical_channel_01",True )
        return report 

    def _profile_list_to_dicts (self ,data :bytes )->List [Dict ]:
        """Parse BF2D profile list response into list of dicts."""
        out =[]
        for profile_source in self ._profile_nodes_from_data (data ):
            entry =self ._single_profile_to_dict (profile_source )
            if entry :
                out .append (entry )
        return out 

    def _profile_fields_from_source (self ,data :Any )->Optional [Dict [str ,str ]]:
        try :
            info =data
            if isinstance (info ,dict )==False :
                if isinstance (data ,(bytes ,bytearray ,memoryview ))==False :
                    return None
                info =TlvParser .parse (bytes (data ))
            if isinstance (info ,dict )==False :
                return None
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
            "iccid_raw":iccid_raw ,
            "name":name_str ,
            "aid":aid_hex ,
            }
        except Exception :
            return None 

    def _single_profile_to_dict (self ,data :Any )->Optional [Dict ]:
        """Convert one profile TLV blob or parsed node to dict."""
        fields =self ._profile_fields_from_source (data )
        if not fields :
            return None
        return {
        "state":fields .get ("state","") ,
        "class":fields .get ("class","") ,
        "iccid":fields .get ("iccid","") ,
        "name":fields .get ("name","") ,
        "aid":fields .get ("aid","") ,
        }

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
                    except Exception :
                         print (f"    | {resp.hex().upper()}")
                else :
                    print ("    | (Empty)")
            else :
                print (f"    | {Config.Colors.FAIL}Status: {sw1:02X}{sw2:02X} (Not Found / Error){Config.Colors.ENDC}")



    def _resolve_tag_name (self ,tag :int ,parent :Optional [int ])->str :
        """Context-aware tag naming for SGP.22 & GlobalPlatform."""

        euicc_info2_name =resolve_euicc_info2_tag_name (tag ,parent )
        if euicc_info2_name :
            return euicc_info2_name 


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


        if parent in [0xBF20 ,0xA9 ,0xAA ]:
            if tag ==0x82 :return "Ver Supported"
            if tag ==0x81 :return "Profile Version"
            if tag ==0x04 :return "CI PKId"
            if tag ==0xA9 :return "CI PK (Verif)"
            if tag ==0xAA :return "CI PK (Sign)"


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

        euicc_info2_value =decode_euicc_info2_value (tag ,val ,parent_tag )
        if euicc_info2_value is not None :
            return euicc_info2_value 


        if parent_tag ==0x84 and tag in [0x81 ,0x82 ,0x83 ]:
            int_val =int .from_bytes (val ,'big')
            if tag ==0x81 :return str (int_val )

            if int_val <1024 :return f"{int_val} B"
            return f"{int_val/1024:.1f} KB"



        is_version_tag =tag in [0x81 ,0x82 ,0x86 ,0x87 ]
        is_euicc_context =False 
        if parent_tag in [0xBF20 ,0xA0 ]:
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

        if tag in [0x83 ,0x84 ]and parent_tag ==0xE1 :
            return str (int .from_bytes (val ,"big",signed =False ))

        if tag ==0x87 and parent_tag ==0xE1 :
            return format_named_bit_string (val ,EIM_SUPPORTED_PROTOCOL_FLAGS )

        if tag ==0x89 and parent_tag ==0xE1 :
            return "Present"


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


            kind ="bits"
            if len (bit_data )>0 :
                first_byte =bit_data [0 ]
                if first_byte ==0x30 :
                    kind ="Signature"
                elif first_byte in [0x02 ,0x03 ,0x04 ]:
                    kind ="PublicKey"

            if unused_bits ==0 :
                return f"{kind}: 0x{bit_hex}"
            return f"{kind}: 0x{bit_hex} (unused bits={unused_bits})"


        if tag ==0x04 and len (val )>0 :

            try :
                nested =TlvParser .parse (val )
                if nested :
                    return f"TLV[{len(val)}]: {hex_str}"
            except Exception :
                pass 
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
                    print (f"{prefix}{name}")
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
                        print (f"{'    ' * (base_indent + 1)}| {Config.Colors.CYAN}{decoded_item}{Config.Colors.ENDC}")
                    else :
                        print (f"{'    ' * (base_indent + 1)}| {Config.Colors.CYAN}{str(item)}{Config.Colors.ENDC}")
                if _should_print_object_separator ():
                    print ("")
                continue 




            if isinstance (val ,dict )and len (val )==1 :
                sub_tag =list (val .keys ())[0 ]
                sub_val =val [sub_tag ]

                if isinstance (sub_val ,bytes )and len (sub_val )>0 :
                    decoded_sub =self ._decode_value (sub_tag ,sub_val ,tag )

                    if sub_tag in [0x06 ,0x04 ]:
                        print (f"{prefix}{name:<22}: {Config.Colors.CYAN}{decoded_sub}{Config.Colors.ENDC}")
                        continue 


            if isinstance (val ,bytes )and tag in [0x84 ,0xAF ,0xA0 ]:
                try :
                    nested =TlvParser .parse (val )
                    if nested :
                        if _is_generic_asn1_container (tag ,name ):
                            self ._print_tlv_tree (nested ,indent ,parent_tag =tag ,x509_mode =x509_mode ,context_label =context_label )
                        else :
                            print (f"{prefix}{name}")
                            self ._print_tlv_tree (nested ,indent +1 ,parent_tag =tag ,x509_mode =x509_mode ,context_label =context_label )
                        if _should_print_object_separator ():
                            print ("")
                        continue 
                except Exception :pass 


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
                        print (f"{prefix}{name}")
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
                    print (f"{prefix}{name:<22}: {Config.Colors.CYAN}(Empty){Config.Colors.ENDC}")
                else :
                    decoded =self ._decode_value (tag ,val ,parent_tag )
                    if len (decoded )>50 and " "not in decoded and "."not in decoded :
                        decoded =decoded [:50 ]+"..."
                    print (f"{prefix}{name:<22}: {Config.Colors.CYAN}{decoded}{Config.Colors.ENDC}")

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
        printed_count =0
        for profile_source in self ._profile_nodes_from_data (data ):
            was_printed =self ._print_single_profile (profile_source )
            if was_printed :
                printed_count +=1
        if printed_count ==0 :
            if data :
                print (f"    | {Config.Colors.WARNING}(No decodable profiles found in response){Config.Colors.ENDC}")
            else :
                print ("    | (Empty)")
        print ("")

    def _print_single_profile (self ,data :Any )->bool :
        fields =self ._profile_fields_from_source (data )
        if not fields :
            return False

        aid_hex =str (fields .get ("aid",""))
        iccid_raw =str (fields .get ("iccid_raw",""))
        iccid_display =str (fields .get ("iccid",""))
        name_str =str (fields .get ("name","Unknown"))
        state_plain =str (fields .get ("state","DISABLED")).upper ()
        state_str =(
        f"{Config.Colors.GREEN}ENABLED  {Config.Colors.ENDC}"
        if state_plain =="ENABLED"
        else f"{Config.Colors.FAIL}DISABLED {Config.Colors.ENDC}"
        )
        class_str =f"{str(fields .get ('class','OPER')):<5}"

        print (f"    {state_str} | {class_str} | {iccid_display:<20} | {name_str:<25} | {aid_hex}")

        if aid_hex :
            entry =(self .TAG_AID ,aid_hex )
            self .profile_cache [name_str .upper ()]=entry 
            self .profile_cache [aid_hex ]=entry 
        elif iccid_raw :
            entry =(self .TAG_ICCID ,iccid_raw )
            self .profile_cache [name_str .upper ()]=entry 
        return True



    def _select_isd_r (self ):
        cmd =f"00A40400{len(self.AID_ISD_R)//2:02X}{self.AID_ISD_R}"
        self .tp .transmit (cmd ,silent =True )

    def _reset_before_retry (self )->None :
        reset_method =getattr (self .tp ,"reset",None )
        if callable (reset_method ):
            try :
                reset_method ()
            except Exception :
                pass

    def _send_store_data_with_retry_ladder (self ,payload :str )->Tuple [bytes ,int ,int ]:
        base_cmd =f"80E29100{len(bytes.fromhex(payload)):02X}{payload}"
        data ,sw1 ,sw2 =self .tp .transmit (base_cmd ,silent =True )
        if sw1 ==0x90 :
            return data ,sw1 ,sw2

        self ._reset_before_retry ()
        ch1_data ,ch1_sw1 ,ch1_sw2 =self ._send_store_data_on_logical_channel (payload )
        if ch1_sw1 ==0x90 :
            return ch1_data ,ch1_sw1 ,ch1_sw2

        self ._reset_before_retry ()
        stk_data ,stk_sw1 ,stk_sw2 =self ._send_store_data_with_stk_mode (payload )
        if stk_sw1 ==0x90 :
            return stk_data ,stk_sw1 ,stk_sw2
        return stk_data ,stk_sw1 ,stk_sw2

    def _send_store_data_on_logical_channel (self ,payload :str )->Tuple [bytes ,int ,int ]:
        open_resp ,open_sw1 ,open_sw2 =self .tp .transmit ("0070000001",silent =True )
        has_channel =False
        if open_sw1 ==0x90 :
            if len (open_resp )>=1 :
                has_channel =True
        if has_channel ==False :
            return open_resp ,open_sw1 ,open_sw2

        channel_id =open_resp [0 ]
        try :
            select_apdu =f"{channel_id:02X}A40400{len(self.AID_ISD_R)//2:02X}{self.AID_ISD_R}"
            _sel_data ,sel_sw1 ,sel_sw2 =self .tp .transmit (select_apdu ,silent =True )
            if sel_sw1 !=0x90 :
                return b"" ,sel_sw1 ,sel_sw2
            cmd =f"{0x80 |channel_id:02X}E29100{len(bytes.fromhex(payload)):02X}{payload}"
            return self .tp .transmit (cmd ,silent =True )
        finally :
            self .tp .transmit (f"007080{channel_id:02X}00",silent =True )

    def _send_store_data_with_stk_mode (self ,payload :str )->Tuple [bytes ,int ,int ]:
        self .tp .transmit ("80AA00000DA90B8100820101830107840101",silent =True )
        self ._select_isd_r ()
        self .tp .transmit ("80100000010C",silent =True )
        last_data ,last_sw1 ,last_sw2 =b"" ,0x6F ,0x00
        for cla in [0x81 ,0x80 ]:
            if cla ==0x80 :
                self ._select_isd_r ()
            cmd =f"{cla:02X}E29100{len(bytes.fromhex(payload)):02X}{payload}"
            last_data ,last_sw1 ,last_sw2 =self .tp .transmit (cmd ,silent =True )
            if self ._is_success_sw (last_sw1 ):
                return last_data ,last_sw1 ,last_sw2
        return last_data ,last_sw1 ,last_sw2

    def _retrieve_eid_response (self )->Tuple [bytes ,int ,int ]:
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder ("BF3E00")
        if sw1 ==0x90 and data :
            return data ,sw1 ,sw2
        tagged_data ,tagged_sw1 ,tagged_sw2 =self ._send_store_data_with_retry_ladder ("BF3E035C015A")
        if tagged_sw1 ==0x90 and tagged_data :
            return tagged_data ,tagged_sw1 ,tagged_sw2
        return tagged_data ,tagged_sw1 ,tagged_sw2

    def _extract_eid_hex (self ,data :bytes )->str :
        if not data :
            return ""
        try :
            parsed =TlvParser .parse (data )
            eid =TlvParser .get_first (parsed ,0x5A )
            if not isinstance (eid ,bytes ):
                root =TlvParser .get_first (parsed ,0xBF3E )
                if isinstance (root ,dict ):
                    eid =TlvParser .get_first (root ,0x5A )
                elif isinstance (root ,bytes ):
                    try :
                        root_parsed =TlvParser .parse (root )
                        eid =TlvParser .get_first (root_parsed ,0x5A )
                    except Exception :
                        eid =None
            if isinstance (eid ,bytes ):
                return eid .hex ().upper ()
        except Exception :
            pass
        return data .hex ().upper ()

    def list_profiles (self ):
        self ._select_isd_r ()
        payload ="BF2D00"
        print (f"{Config.Colors.CYAN}[*] Retrieving Profile List (ES10c/ES10b.GetProfilesInfo)...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
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
        effective_width =22 -len (prefix )
        if effective_width <len (label ):
            effective_width =len (label )
        self ._print_wrapped_pipe_value (f"{prefix}{label:<{effective_width}}",self ._short_display (value ))

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
        analysis_node =node
        if isinstance (node ,bytes ):
            out ["rawHex"]=node .hex ().upper ()
        if isinstance (node ,bytes ):
            try :
                parsed_node =TlvParser .parse (node )
                if isinstance (parsed_node ,dict ):
                    analysis_node =parsed_node
            except Exception :
                analysis_node =node

        summaries :List [Dict [str ,str ]]=[]
        seen_serials =set ()
        seen_blobs =set ()
        byte_sources =[node ]
        if analysis_node is not node :
            byte_sources .append (analysis_node )
        for source in byte_sources :
            for blob in self ._iter_byte_values (source ):
                blob_hex =blob .hex ()
                if blob_hex in seen_blobs :
                    continue
                seen_blobs .add (blob_hex )
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
        if len (summaries )==0 and isinstance (node ,bytes ):
            summaries =self ._collect_cert_summaries_from_raw (node )
            if len (summaries )>0 :
                seen_serials ={str (item .get ("serial",""))for item in summaries }
        if summaries :
            out ["certificates"]=summaries 

        bit_strings =self ._collect_tag_bytes (analysis_node ,0x03 )
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

        object_identifiers =self ._collect_decoded_values (analysis_node ,0x06 ,None )
        if len (object_identifiers )>0 :
            out ["objectIdentifiers"]=object_identifiers 

        utf8_values =self ._collect_decoded_values (analysis_node ,0x0C ,None )
        if len (utf8_values )>0 :
            out ["utf8Strings"]=utf8_values 

        printable_values =self ._collect_decoded_values (analysis_node ,0x13 ,None )
        if len (printable_values )>0 :
            out ["printableStrings"]=printable_values 

        utc_values =self ._collect_decoded_values (analysis_node ,0x17 ,None )
        if len (utc_values )>0 :
            out ["utcTimes"]=utc_values 

        generalized_values =self ._collect_decoded_values (analysis_node ,0x18 ,None )
        if len (generalized_values )>0 :
            out ["generalizedTimes"]=generalized_values 

        boolean_values =self ._collect_decoded_values (analysis_node ,0x01 ,None )
        if len (boolean_values )>0 :
            out ["booleans"]=boolean_values 

        octet_values =self ._collect_decoded_values (analysis_node ,0x04 ,None )
        if len (octet_values )>0 :
            out ["octetStrings"]=octet_values 

        integer_values =self ._collect_decoded_values (analysis_node ,0x02 ,None )
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
        def _encode_length (length :int )->bytes :
            if length <0x80 :
                return bytes ([length ])
            if length <=0xFF :
                return bytes ([0x81 ,length ])
            return bytes ([0x82 ,(length >>8 )&0xFF ,length &0xFF ])

        raw_hex_values =self ._collect_tag_bytes (parsed ,0xBF55 )
        raw_response =b""
        if len (raw_hex_values )>0 :
            raw_response =bytes .fromhex ("BF55")+_encode_length (len (raw_hex_values [0 ]))+raw_hex_values [0 ]
        entries =decode_eim_configuration_entries (raw_response )
        if len (entries )==0 :
            self ._print_compact_json (parsed ,0xBF55 )
            return 

        result_entries :List [Dict [str ,Any ]]=[]
        for entry in entries :
            row :Dict [str ,Any ]={}
            field_map =[
            ("eim_id","eimId"),
            ("eim_fqdn","eimFqdn"),
            ("eim_id_type","eimIdType"),
            ("counter_value","counterValue"),
            ("association_token","associationToken"),
            ("supported_protocol","eimSupportedProtocol"),
            ("euicc_ci_pkid","euiccCiPKId"),
            ("indirect_profile_download","indirectProfileDownload"),
            ]
            for source_key ,target_key in field_map :
                if source_key in entry :
                    row [target_key ]=entry [source_key ]

            eim_pub_block =entry .get ("eim_public_key_data")
            if isinstance (eim_pub_block ,bytes ):
                row ["eimPublicKeyData"]=self ._summarize_cert_block (eim_pub_block )

            tls_pub_block =entry .get ("trusted_tls_public_key_data")
            if isinstance (tls_pub_block ,bytes ):
                row ["trustedPublicKeyDataTls"]=self ._summarize_cert_block (tls_pub_block )

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
                print (f"    | eimEntry             : {Config.Colors.CYAN}{idx}{Config.Colors.ENDC}")

            field_order =[
            ("eimId","eimId"),
            ("eimFqdn","eimFqdn"),
            ("eimIdType","eimIdType"),
            ("counterValue","counterValue"),
            ("associationToken","associationToken"),
            ("eimSupportedProtocol","eimSupportedProtocol"),
            ("euiccCiPKId","euiccCiPKId"),
            ("indirectProfileDownload","indirectProfileDownload"),
            ]
            for field_key ,field_name in field_order :
                if field_key not in row :
                    continue 
                field_value =row [field_key ]
                self ._print_wrapped_pipe_value (field_name ,field_value )

            cert_sections =[
            ("eimPublicKeyData","eimPublicKeyData"),
            ("trustedPublicKeyDataTls","trustedPublicKeyDataTls"),
            ]
            for section_key ,section_name in cert_sections :
                if section_key not in row :
                    continue 
                section_value =row [section_key ]
                if not isinstance (section_value ,dict ):
                    continue 
                self ._print_cert_block_summary_lines (section_name ,section_value )

            if idx <len (result_entries ):
                print ("")

    def _print_eim_configuration_compact (self ,response :bytes )->None :
        print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
        entries =decode_eim_configuration_entries (response )
        if len (entries )==0 :
            print ("    | (Empty)")
            return

        self ._print_wrapped_pipe_value ("eIM Entries",len (entries ))
        for idx ,entry in enumerate (entries ,start =1 ):
            if len (entries )>1 :
                self ._print_wrapped_pipe_value ("eimEntry",idx )

            field_order =[
            ("eim_id","eimId"),
            ("eim_fqdn","eimFqdn"),
            ("eim_id_type","eimIdType"),
            ("counter_value","counterValue"),
            ("association_token","associationToken"),
            ("supported_protocol","eimSupportedProtocol"),
            ("euicc_ci_pkid","euiccCiPKId"),
            ("indirect_profile_download","indirectProfileDownload"),
            ]
            for source_key ,field_name in field_order :
                value =entry .get (source_key )
                if value is None :
                    continue
                text =str (value ).strip ()
                if len (text )==0 :
                    continue
                self ._print_wrapped_pipe_value (field_name ,text )

            cert_sections =[
            ("eim_public_key_data","eimPublicKeyData"),
            ("trusted_tls_public_key_data","trustedPublicKeyDataTls"),
            ]
            for source_key ,section_name in cert_sections :
                value =entry .get (source_key )
                if not isinstance (value ,bytes ):
                    continue
                summary =self ._summarize_cert_block (value )
                self ._print_cert_block_summary_lines (section_name ,summary )

            if idx <len (entries ):
                print ("")

    def _print_eim_public_key_data_lines (self ,section_name :str ,section_value :Any )->None :
        """
        eIM configuration output should remain config-centric.
        Show the EimConfigurationData CHOICE presence only.
        """
        summary :Dict [str ,Any ]={}
        if isinstance (section_value ,bytes ):
            summary =self ._summarize_cert_block (section_value )
        elif isinstance (section_value ,dict ):
            summary =section_value

        certificates =summary .get ("certificates",[])
        public_keys =summary .get ("publicKeys",[])
        has_certificate =False
        if isinstance (certificates ,list ):
            if len (certificates )>0 :
                has_certificate =True
        has_public_key =False
        if isinstance (public_keys ,list ):
            if len (public_keys )>0 :
                has_public_key =True

        self ._print_wrapped_pipe_value (section_name ,"Present")
        self ._print_wrapped_pipe_value (
        "  eimCertificate",
        "Present"if has_certificate else "Absent",
        )
        self ._print_wrapped_pipe_value (
        "  eimPublicKey",
        "Present"if has_public_key else "Absent",
        )
        if has_public_key :
            first_key =public_keys [0 ]
            self ._print_wrapped_pipe_value ("  eimPublicKey (1st)",first_key )
            decoded_key =self ._decode_public_key_hex_summary (first_key )
            key_summary =decoded_key .get ("summary","")
            if len (key_summary )>0 :
                self ._print_wrapped_pipe_value ("  eimPublicKey Decode",key_summary )
            key_x =decoded_key .get ("x","")
            if len (key_x )>0 :
                self ._print_wrapped_pipe_value ("  eimPublicKey X",key_x )
            key_y =decoded_key .get ("y","")
            if len (key_y )>0 :
                self ._print_wrapped_pipe_value ("  eimPublicKey Y",key_y )

    def _decode_public_key_hex_summary (self ,value :Any )->Dict [str ,str ]:
        """
        Decode common raw public-key encodings for compact EIMCFG display.
        """
        out :Dict [str ,str ]={}
        if not isinstance (value ,str ):
            return out
        text =value .strip ()
        if len (text )==0 :
            return out
        if text .startswith ("0x")or text .startswith ("0X"):
            text =text [2 :]
        hex_chars ="0123456789abcdefABCDEF"
        for ch in text :
            if ch not in hex_chars :
                return out
        if (len (text )%2 )!=0 :
            return out

        try :
            raw =bytes .fromhex (text )
        except Exception :
            return out
        if len (raw )==0 :
            return out

        first =raw [0 ]
        key_len =len (raw )
        if first ==0x04 and key_len >=3 and (key_len %2 )==1 :
            coord_len =(key_len -1 )//2
            x_hex =raw [1 :1 +coord_len ].hex ().upper ()
            y_hex =raw [1 +coord_len :].hex ().upper ()
            curve_name ="unknown"
            if coord_len ==32 :
                curve_name ="prime256v1 / secp256r1"
            elif coord_len ==48 :
                curve_name ="secp384r1"
            elif coord_len ==66 :
                curve_name ="secp521r1"
            out ["summary"]=f"EC uncompressed point ({curve_name}, {key_len} bytes)"
            out ["x"]=f"0x{x_hex}"
            out ["y"]=f"0x{y_hex}"
            return out
        if first in [0x02 ,0x03 ]:
            out ["summary"]=f"EC compressed point ({key_len} bytes, sign=0x{first:02X})"
            return out
        out ["summary"]=f"Raw key bytes={key_len}, prefix=0x{first:02X}"
        return out

    def _decode_pkid_hex_summary (self ,value :Any )->str :
        if not isinstance (value ,str ):
            return ""
        text =value .strip ()
        if len (text )==0 :
            return ""
        if text .startswith ("0x")or text .startswith ("0X"):
            text =text [2 :]
        hex_chars ="0123456789abcdefABCDEF"
        for ch in text :
            if ch not in hex_chars :
                return ""
        if (len (text )%2 )!=0 :
            return ""
        try :
            raw =bytes .fromhex (text )
        except Exception :
            return ""
        if len (raw )==0 :
            return ""
        grouped =":".join ([f"{b:02X}"for b in raw ])
        if len (raw )==20 :
            return f"SubjectKeyIdentifier (20 bytes, hash identifier); fingerprint={grouped}"
        return f"SubjectKeyIdentifier ({len(raw)} bytes, hash identifier); value={grouped}"

    def _extract_hex_from_display (self ,value :Any )->str :
        if not isinstance (value ,str ):
            return ""
        text =value .strip ().upper ()
        if len (text )==0 :
            return ""
        if ":" in text :
            text =text .split (":",1 )[1 ].strip ()
        compact ="".join ([ch for ch in text if ch in "0123456789ABCDEF"])
        if (len (compact )%2 )!=0 :
            return ""
        return compact

    def _decode_extension_blob_lines (self ,value :Any )->List [Tuple [str ,str ]]:
        lines :List [Tuple [str ,str ]]=[]
        hex_text =self ._extract_hex_from_display (value )
        if len (hex_text )==0 :
            return lines
        try :
            raw =bytes .fromhex (hex_text )
        except Exception :
            return lines
        if len (raw )==0 :
            return lines

        # BasicConstraints: 30 06 01 01 FF 02 01 00
        if hex_text .startswith ("30060101FF0201")and len (raw )>=8 :
            path_len =raw [-1 ]
            lines .append (("  basicConstraints","CA=TRUE"))
            lines .append (("  pathLenConstraint",str (path_len )))
            return lines

        # KeyUsage BIT STRING blob, e.g. 03 02 01 06
        if len (raw )>=4 and raw [0 ]==0x03 :
            try :
                length =raw [1 ]
                if length +2 <=len (raw ):
                    unused_bits =raw [2 ]
                    bit_bytes =raw [3 :2 +length ]
                    bit_string ="".join (f"{b:08b}"for b in bit_bytes )
                    if unused_bits >0 and unused_bits <8 :
                        bit_string =bit_string [:len (bit_string )-unused_bits ]
                    ku_names =[
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                    ]
                    active :List [str ]=[]
                    for idx ,name in enumerate (ku_names ):
                        if idx <len (bit_string ):
                            if bit_string [idx ]=="1":
                                active .append (name )
                    if len (active )>0 :
                        lines .append (("  keyUsage",", ".join (active )))
                        return lines
            except Exception :
                pass

        # subjectKeyIdentifier: 04 14 <20 bytes>
        if len (raw )==22 and raw [0 ]==0x04 and raw [1 ]==0x14 :
            ski =raw [2 :22 ].hex ().upper ()
            lines .append (("  subjectKeyIdentifier",ski ))
            return lines

        # authorityKeyIdentifier: 30 16 80 14 <20 bytes>
        if len (raw )>=24 and raw [0 ]==0x30 and raw [1 ]==0x16 and raw [2 ]==0x80 and raw [3 ]==0x14 :
            aki =raw [4 :24 ].hex ().upper ()
            lines .append (("  authorityKeyIdentifier",aki ))
            return lines

        # subjectAltName with registeredID
        if len (raw )>=5 and raw [0 ]==0x30 :
            idx =0
            while idx +2 <=len (raw ):
                if raw [idx ]==0x88 and idx +2 <=len (raw ):
                    oid_len =raw [idx +1 ]
                    end =idx +2 +oid_len
                    if end <=len (raw ):
                        oid_value =raw [idx +2 :end ]
                        oid_text =self ._decode_oid (oid_value )
                        lines .append (("  subjectAltName registeredID",oid_text ))
                        return lines
                idx +=1

        # CRL Distribution Point URI inside blob
        marker =b"http://"
        uri_at =raw .find (marker )
        if uri_at >=0 :
            tail =raw [uri_at :]
            uri_chars :List [str ]=[]
            for b in tail :
                if 32 <=b <=126 :
                    uri_chars .append (chr (b ))
                else :
                    break
            uri ="".join (uri_chars )
            if len (uri )>0 :
                lines .append (("  cRLDistributionPoints",uri ))
                return lines

        return lines

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
        print (f"{Config.Colors.CYAN}[*] {title}...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
        if sw1 ==0x90 and data :
            print (f"{Config.Colors.HEADER}--- {title} ---{Config.Colors.ENDC}")
            try :
                parsed =TlvParser .parse (data )
                debug_enabled =bool (getattr (self .tp ,"debug",False ))
                if compact_json and not debug_enabled and root_tag ==0xBF55 :
                    self ._print_eim_configuration_compact_json (parsed )
                elif root_tag ==0xBF22 and not debug_enabled :
                    self ._print_euicc_info2_detailed (data )
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

    def _print_euicc_info2_detailed (self ,data :bytes )->None :
        print (f"{Config.Colors.BOLD}[+] EuiccInfo2{Config.Colors.ENDC}")
        detail_lines =build_euicc_info2_detail_lines (data )
        label_width =22
        for indent_level ,label ,value in detail_lines :
            display_label =self ._format_euicc_info2_label (label )
            prefix ="  "*indent_level
            effective_width =label_width -len (prefix )
            if effective_width <len (display_label ):
                effective_width =len (display_label )
            label_text =f"{prefix}{display_label:<{effective_width}}"
            self ._print_wrapped_pipe_value (label_text ,value )

    def _get_console_width (self )->int :
        width =120
        try :
            width =shutil .get_terminal_size ((120 ,20 )).columns
        except Exception :
            width =120
        if width <80 :
            return 80
        return width

    def _print_wrapped_pipe_value (self ,label_text :str ,value :Any )->None :
        console_width =self ._get_console_width ()
        stripped_label =label_text .rstrip ()
        min_label_width =25
        if console_width <=90 :
            # Narrow terminal panes should keep ':' and value visible.
            min_label_width =max (8 ,min (16 ,console_width //3 ))
        padded_label =stripped_label
        stripped_len =len (stripped_label )
        if stripped_len <min_label_width :
            padded_label =f"{stripped_label:<{min_label_width}}"
        lead =f"    | {padded_label}: "
        continuation_lead ="    | " +(" "*(len (padded_label )+2 ))
        label_only_mode =False
        if len (lead )>=console_width -4 :
            label_only_mode =True
            lead ="    |   "
            continuation_lead ="    |   "
        wrap_width =console_width -len (continuation_lead )
        if wrap_width <20 :
            wrap_width =20
        value_text =str (value )
        if self ._looks_like_hex_blob (value_text ):
            wrapped_lines =self ._wrap_hex_blob_text (value_text ,wrap_width )
        else :
            wrapped_lines =textwrap .wrap (
            value_text ,
            width =wrap_width ,
            break_long_words =True ,
            break_on_hyphens =False ,
            )
        if len (wrapped_lines )==0 :
            wrapped_lines =[""]
        if label_only_mode :
            print (f"    | {Config.Colors.CYAN}{stripped_label}{Config.Colors.ENDC}")
        print (f"{lead}{Config.Colors.CYAN}{wrapped_lines[0]}{Config.Colors.ENDC}")
        for wrapped_line in wrapped_lines [1 :]:
            print (f"{continuation_lead}{Config.Colors.CYAN}{wrapped_line}{Config.Colors.ENDC}")

    def _looks_like_hex_blob (self ,value_text :str )->bool :
        normalized =value_text .strip ()
        if len (normalized )==0 :
            return False
        if normalized .startswith ("0x")or normalized .startswith ("0X"):
            normalized =normalized [2 :]
        if len (normalized )<16 :
            return False
        if re .fullmatch (r"[0-9A-Fa-f]+",normalized )is None :
            return False
        return True

    def _wrap_hex_blob_text (self ,value_text :str ,wrap_width :int )->List [str ]:
        normalized =value_text .strip ()
        prefix =""
        if normalized .startswith ("0x")or normalized .startswith ("0X"):
            prefix =normalized [:2 ]
            normalized =normalized [2 :]
        if len (normalized )==0 :
            if len (prefix )>0 :
                return [prefix ]
            return [""]
        chunk_width =wrap_width
        if len (prefix )>0 :
            chunk_width -=len (prefix )
        if chunk_width <2 :
            chunk_width =2
        if chunk_width %2 !=0 :
            chunk_width -=1
        if chunk_width <2 :
            chunk_width =2
        wrapped_lines :List [str ]=[]
        start_index =0
        while start_index <len (normalized ):
            end_index =start_index +chunk_width
            if end_index >len (normalized ):
                end_index =len (normalized )
            chunk =normalized [start_index :end_index ]
            if start_index ==0 and len (prefix )>0 :
                wrapped_lines .append (prefix +chunk )
            else :
                wrapped_lines .append (chunk )
            start_index =end_index
        return wrapped_lines

    def _format_euicc_info2_label (self ,label :str )->str :
        label_map ={
        "Profile Version":"Profile Version",
        "Ver Supported (SGP.22 SVN)":"Ver Supported",
        "Firmware Ver":"Firmware Ver",
        "Ext Card Res":"Ext Card Res",
        "Installed Apps":"Installed Apps",
        "Free NVM":"Free NVM",
        "Free RAM":"Free RAM",
        "UICC Capability":"UICC Capability",
        "TS102.241 Version":"TS102.241 Ver",
        "GlobalPlatform Version":"GP Version",
        "RSP Capability":"RSP Capability",
        "CI PKId List For Verification":"CI PKId Verify",
        "CI PKId List For Signing":"CI PKId Sign",
        "Forbidden Profile Policy Rules":"Forbidden PPR",
        "PP Version":"PP Version",
        "SAS Accreditation Number":"SAS Accr. Number",
        "Additional eUICC Profile Package Versions":"Additional PP Vers.",
        "Additional PP Version 1":"Additional PP Ver 1",
        "IPA Mode":"IPA Mode",
        "IoT Specific Info":"IoT Specific Info",
        "IoT Version 1":"IoT Version 1",
        "eCall Supported":"eCall Supported",
        "Fallback Supported":"Fallback Supported",
        "SGP.32 Validation":"SGP.32 Validation",
        "Mandatory Fields":"Mandatory Fields",
        }
        if label in label_map :
            return label_map [label ]
        return label

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
        group_print_state =[False ]

        def _print_group (title :str )->None :
            if group_print_state [0 ]:
                print ("    |")
            print (f"    |   {title}")
            group_print_state [0 ]=True

        def _extract_oid_dotted (oid_text :Any )->str :
            if not isinstance (oid_text ,str ):
                return ""
            text =oid_text .strip ()
            if len (text )==0 :
                return ""
            dotted_match =re .match (r"^(\d+(?:\.\d+)+)",text )
            if dotted_match is not None :
                dotted =dotted_match .group (1 )
                if len (dotted )>0 :
                    return dotted
            if text .endswith (")"):
                left =text .rfind ("(")
                if left >=0 :
                    candidate =text [left +1 :-1 ].strip ()
                    if len (candidate )>0 :
                        return candidate
            return text

        def _oid_legend (oid_text :Any )->str :
            dotted =_extract_oid_dotted (oid_text )
            if len (dotted )==0 :
                return "other"
            if dotted in ["1.2.840.10045.4.3.2","1.2.840.113549.1.1.11"]:
                return "signatureAlgorithm"
            if dotted =="1.2.840.10045.2.1":
                return "subjectPublicKeyInfo"
            if dotted .startswith ("1.2.840.10045.3."):
                return "ecCurve"
            if dotted .startswith ("2.5.4."):
                return "distinguishedName"
            if dotted .startswith ("2.5.29."):
                return "x509Extension"
            if dotted .startswith ("1.3.6.1.5.5.7.3."):
                return "extendedKeyUsage"
            return "other"

        def _oid_dn_name (oid_text :Any )->str :
            dotted =_extract_oid_dotted (oid_text )
            if dotted =="2.5.4.3":
                return "commonName"
            if dotted =="2.5.4.6":
                return "countryName"
            if dotted =="2.5.4.7":
                return "localityName"
            if dotted =="2.5.4.10":
                return "organizationName"
            if dotted =="2.5.4.11":
                return "organizationalUnitName"
            if dotted =="2.5.4.5":
                return "serialNumber"
            return ""

        def _friendly_dn_label (dn_name :str ,idx :int )->str :
            if len (dn_name )>0 :
                return f"  {dn_name}"
            return f"  nameText {idx}"

        def _decode_x509_time_text (time_text :Any )->str :
            if not isinstance (time_text ,str ):
                return ""
            text =time_text .strip ()
            if len (text )==0 :
                return ""
            try :
                if len (text )==13 and text .endswith ("Z"):
                    parsed =datetime .strptime (text ,"%y%m%d%H%M%SZ")
                    return parsed .strftime ("%Y-%m-%d %H:%M:%SZ")
                if len (text )==15 and text .endswith ("Z"):
                    parsed =datetime .strptime (text ,"%Y%m%d%H%M%SZ")
                    return parsed .strftime ("%Y-%m-%d %H:%M:%SZ")
            except Exception :
                return ""
            return ""

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
        utf8_values =section_value .get ("utf8Strings",[])
        printable_values =section_value .get ("printableStrings",[])
        utc_values =section_value .get ("utcTimes",[])
        generalized_values =section_value .get ("generalizedTimes",[])
        octet_values =section_value .get ("octetStrings",[])
        integer_values =section_value .get ("integers",[])
        raw_hex =section_value .get ("rawHex","")

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

        self ._print_wrapped_pipe_value (f"{section_name:<20}","Present")
        self ._print_wrapped_pipe_value (f"{'  Certificate Objects':<20}",cert_count_display )
        self ._print_wrapped_pipe_value (f"{'  Public Key Entries':<20}",_count_items (public_keys ))
        self ._print_wrapped_pipe_value (f"{'  Signature Entries':<20}",_count_items (signatures ))
        self ._print_wrapped_pipe_value (f"{'  Identifier OIDs':<20}",_count_items (object_identifiers ))
        if has_unsigned_evidence :
            self ._print_wrapped_pipe_value (
            f"{'  Structure':<20}",
            "Signed key container (no DER certificate object found)",
            )

        first_cert =_first_dict (certificates )
        has_cert =False 
        if first_cert is not None :
            has_cert =True 
        if has_cert :
            _print_group ("Certificate")
            cert_subject =first_cert .get ("subject","")
            cert_issuer =first_cert .get ("issuer","")
            cert_serial =first_cert .get ("serial","")
            cert_not_before =first_cert .get ("notBefore","")
            cert_not_after =first_cert .get ("notAfter","")
            self ._print_wrapped_pipe_value (f"{'  Subject':<20}",cert_subject )
            self ._print_wrapped_pipe_value (f"{'  Issuer':<20}",cert_issuer )
            self ._print_wrapped_pipe_value (f"{'  Serial Number':<20}",cert_serial )
            self ._print_wrapped_pipe_value (f"{'  Validity':<20}",f"{cert_not_before} -> {cert_not_after}" )

        has_pub_key =False 
        if isinstance (public_keys ,list ):
            if len (public_keys )>0 :
                has_pub_key =True 
        if has_pub_key :
            _print_group ("Subject Public Key Info")
            self ._print_wrapped_pipe_value (f"{'  Public Key (1st)':<20}",public_keys [0 ])

        has_signature =False 
        if isinstance (signatures ,list ):
            if len (signatures )>0 :
                has_signature =True 
        if has_signature :
            _print_group ("Certificate Signature")
            self ._print_wrapped_pipe_value (f"{'  Signature DER (1st)':<20}",signatures [0 ])

        if isinstance (object_identifiers ,list ):
            if len (object_identifiers )>0 :
                _print_group ("Object Identifiers")
        preview_oids :List [Any ]=[]
        if isinstance (object_identifiers ,list ):
            for value in object_identifiers :
                legend =_oid_legend (value )
                if legend =="distinguishedName":
                    continue
                preview_oids .append (value )
                if len (preview_oids )>=3 :
                    break
        for value in preview_oids :
            legend =_oid_legend (value )
            label_text =legend
            if label_text =="other":
                label_text ="identifier"
            label =f"  {label_text}"
            self ._print_wrapped_pipe_value (f"{label:<20}",value )

        dn_oid_names :List [str ]=[]
        if isinstance (object_identifiers ,list ):
            for item in object_identifiers :
                dn_name =_oid_dn_name (item )
                if len (dn_name )>0 :
                    dn_oid_names .append (dn_name )
        dn_name_cursor =0

        preview_utf8 =utf8_values [:2 ]if isinstance (utf8_values ,list )else []
        if len (preview_utf8 )>0 or (isinstance (printable_values ,list )and len (printable_values )>0 ):
            _print_group ("Subject Name Attributes")
        for idx ,value in enumerate (preview_utf8 ,start =1 ):
            dn_name =""
            if dn_name_cursor <len (dn_oid_names ):
                dn_name =dn_oid_names [dn_name_cursor ]
            dn_name_cursor +=1
            label =_friendly_dn_label (dn_name ,idx )
            self ._print_wrapped_pipe_value (f"{label:<20}",value )

        preview_printable =printable_values [:2 ]if isinstance (printable_values ,list )else []
        for idx ,value in enumerate (preview_printable ,start =1 ):
            dn_name =""
            if dn_name_cursor <len (dn_oid_names ):
                dn_name =dn_oid_names [dn_name_cursor ]
            dn_name_cursor +=1
            label =_friendly_dn_label (dn_name ,idx +len (preview_utf8 ))
            self ._print_wrapped_pipe_value (f"{label:<20}",value )

        preview_times :List [str ]=[]
        if isinstance (utc_values ,list ):
            preview_times .extend ([str (item )for item in utc_values [:2 ]])
        if isinstance (generalized_values ,list ):
            preview_times .extend ([str (item )for item in generalized_values [:2 ]])
        if len (preview_times )>0 :
            _print_group ("Validity Period")
        for idx ,value in enumerate (preview_times [:2 ],start =1 ):
            label ="  Not Before"
            if idx >1 :
                label ="  Not After"
            self ._print_wrapped_pipe_value (f"{label:<20}",value )
            decoded_time =_decode_x509_time_text (value )
            if len (decoded_time )>0 :
                self ._print_wrapped_pipe_value (f"{'  Time Decoded':<20}",decoded_time )

        preview_integers =integer_values [:2 ]if isinstance (integer_values ,list )else []
        if len (preview_integers )>0 :
            _print_group ("Version / Serial Hints")
        for idx ,value in enumerate (preview_integers ,start =1 ):
            label ="  Certificate Version"
            if idx >1 :
                label ="  Certificate Serial"
            self ._print_wrapped_pipe_value (f"{label:<20}",value )

        preview_octets =octet_values [:3 ]if isinstance (octet_values ,list )else []
        if len (preview_octets )>0 :
            _print_group ("Extensions")
        for idx ,value in enumerate (preview_octets ,start =1 ):
            self ._print_wrapped_pipe_value (f"{f'  Extension Blob {idx}':<20}",value )
            decoded_lines =self ._decode_extension_blob_lines (value )
            for decoded_label ,decoded_value in decoded_lines :
                self ._print_wrapped_pipe_value (f"{decoded_label:<20}",decoded_value )

        if isinstance (raw_hex ,str ):
            has_raw_hex =False 
            if len (raw_hex )>0 :
                has_raw_hex =True 
            if has_raw_hex :
                self ._print_wrapped_pipe_value (f"{'  Raw Hex (1st)':<20}",raw_hex )

    def _print_get_certs_compact (self ,parsed :Dict [int ,Any ])->None :
        print (f"\n{Config.Colors.BOLD}[+] GetCerts{Config.Colors.ENDC}")
        root_value =TlvParser .get_first (parsed ,0xBF56 )
        if not isinstance (root_value ,bytes ):
            print ("    | (No certificate blocks found)")
            return 

        raw_response =bytes .fromhex ("BF56")
        if len (root_value )<0x80 :
            raw_response +=bytes ([len (root_value )])
        else :
            raw_response +=bytes ([0x81 ,len (root_value )])
        raw_response +=root_value 
        certs =decode_get_certs_response (raw_response )
        if "error"in certs :
            print (f"    | Result               : {Config.Colors.FAIL}{certs['error']}{Config.Colors.ENDC}")
            return 

        eum_cert =certs .get ("eumCertificate")
        euicc_cert =certs .get ("euiccCertificate")
        if not isinstance (eum_cert ,bytes )and not isinstance (euicc_cert ,bytes ):
            print ("    | (No certificate blocks found)")
            return 

        if isinstance (eum_cert ,bytes ):
            eum_sum =self ._summarize_cert_block (eum_cert )
            self ._print_cert_block_summary_lines ("EUM Certificate",eum_sum )

        if isinstance (euicc_cert ,bytes ):
            euicc_sum =self ._summarize_cert_block (euicc_cert )
            self ._print_cert_block_summary_lines ("eUICC Certificate",euicc_sum )

    def _print_get_certs_compact_response (self ,response :bytes )->None :
        print (f"\n{Config.Colors.BOLD}[+] GetCerts{Config.Colors.ENDC}")
        certs =decode_get_certs_response (response )
        if "error"in certs :
            print (f"    | Result               : {Config.Colors.FAIL}{certs['error']}{Config.Colors.ENDC}")
            return

        eum_cert =certs .get ("eumCertificate")
        euicc_cert =certs .get ("euiccCertificate")
        if not isinstance (eum_cert ,bytes )and not isinstance (euicc_cert ,bytes ):
            fallback =self ._summarize_cert_block (response )
            if len (fallback )==0 :
                print ("    | (No certificate blocks found)")
                return
            self ._print_cert_block_summary_lines ("Certificate Data",fallback )
            return

        if isinstance (eum_cert ,bytes ):
            eum_sum =self ._summarize_cert_block (eum_cert )
            self ._print_cert_block_summary_lines ("EUM Certificate",eum_sum )

        if isinstance (euicc_cert ,bytes ):
            euicc_sum =self ._summarize_cert_block (euicc_cert )
            self ._print_cert_block_summary_lines ("eUICC Certificate",euicc_sum )

    def _print_notifications_list_compact (self ,parsed :Dict [int ,Any ])->None :
        print (f"\n{Config.Colors.BOLD}[+] RetrieveNotificationsList{Config.Colors.ENDC}")
        root_value =TlvParser .get_first (parsed ,0xBF2B )
        if not isinstance (root_value ,bytes ):
            self ._print_wrapped_pipe_value ("Notification Entries","(Empty)")
            return 
        raw_response =bytes .fromhex ("BF2B")
        if len (root_value )<0x80 :
            raw_response +=bytes ([len (root_value )])
        else :
            raw_response +=bytes ([0x81 ,len (root_value )])
        raw_response +=root_value 
        decoded =decode_notifications_response (raw_response )
        if len (decoded .get ("error",""))>0 :
            self ._print_wrapped_pipe_value ("Result",decoded ["error"])
            return 
        notifications =decoded .get ("notifications",[])
        package_results =decoded .get ("package_results",[])
        self ._print_wrapped_pipe_value ("Notification Entries",len (notifications ))
        if len (package_results )>0 :
            self ._print_wrapped_pipe_value ("Package Results",len (package_results ))
        if len (notifications )==0 :
            return 
        first =notifications [0 ]
        if "seqNumber"in first :
            self ._print_wrapped_pipe_value ("Seq Number",first ["seqNumber"])
        if "operation"in first :
            self ._print_wrapped_pipe_value ("Operation",first ["operation"])
        if "notificationAddress"in first :
            self ._print_wrapped_pipe_value ("Server/FQDN",first ["notificationAddress"])
        if "iccid"in first :
            self ._print_wrapped_pipe_value ("ICCID",first ["iccid"])

    def _print_rat_compact (self ,parsed :Dict [int ,Any ])->None :
        print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
        root_value =TlvParser .get_first (parsed ,0xBF43 )
        if not isinstance (root_value ,bytes ):
            print ("    | (Empty)")
            return 

        raw_response =bytes .fromhex ("BF43")
        if len (root_value )<0x80 :
            raw_response +=bytes ([len (root_value )])
        else :
            raw_response +=bytes ([0x81 ,len (root_value )])
        raw_response +=root_value 
        rules =decode_rat_rules (raw_response )
        if len (rules )==0 :
            print ("    | (Empty)")
            return 

        self ._print_wrapped_pipe_value ("Rules",len (rules ))
        first_rule =rules [0 ]
        if "pprIdsRaw"in first_rule :
            self ._print_wrapped_pipe_value ("PPR IDs Raw",first_rule ["pprIdsRaw"])
        if "pprIds"in first_rule :
            self ._print_wrapped_pipe_value ("PPR IDs Meaning",first_rule ["pprIds"])
        operators =first_rule .get ("allowedOperators",[])
        if isinstance (operators ,list ):
            self ._print_wrapped_pipe_value ("Allowed Operators",len (operators ))
            if len (operators )>0 :
                first_operator =operators [0 ]
                operator_parts =[]
                if "mccMnc"in first_operator :
                    operator_parts .append (f"mccMnc={first_operator['mccMnc']}")
                if "gid1"in first_operator :
                    operator_parts .append (f"gid1={first_operator['gid1']}")
                if "gid2"in first_operator :
                    operator_parts .append (f"gid2={first_operator['gid2']}")
                self ._print_wrapped_pipe_value ("First Operator",", ".join (operator_parts ))
        if "pprFlagsRaw"in first_rule :
            self ._print_wrapped_pipe_value ("PPR Flags Raw",first_rule ["pprFlagsRaw"])
        if "pprFlags"in first_rule :
            self ._print_wrapped_pipe_value ("PPR Flags Meaning",first_rule ["pprFlags"])

    def _print_rat_compact_response (self ,response :bytes )->None :
        print (f"\n{Config.Colors.BOLD}[+] GetRAT (Rules Authorisation Table){Config.Colors.ENDC}")
        rules =decode_rat_rules (response )
        if len (rules )==0 :
            print ("    | (Empty)")
            if len (response )>0 :
                self ._print_wrapped_pipe_value ("Raw Hex",response .hex ().upper ())
            return

        self ._print_wrapped_pipe_value ("Rules",len (rules ))
        first_rule =rules [0 ]
        if "pprIdsRaw"in first_rule :
            self ._print_wrapped_pipe_value ("PPR IDs Raw",first_rule ["pprIdsRaw"])
        if "pprIds"in first_rule :
            self ._print_wrapped_pipe_value ("PPR IDs Meaning",first_rule ["pprIds"])
        operators =first_rule .get ("allowedOperators",[])
        if isinstance (operators ,list ):
            self ._print_wrapped_pipe_value ("Allowed Operators",len (operators ))
            if len (operators )>0 :
                first_operator =operators [0 ]
                operator_parts =[]
                if "mccMnc"in first_operator :
                    operator_parts .append (f"mccMnc={first_operator['mccMnc']}")
                if "gid1"in first_operator :
                    operator_parts .append (f"gid1={first_operator['gid1']}")
                if "gid2"in first_operator :
                    operator_parts .append (f"gid2={first_operator['gid2']}")
                self ._print_wrapped_pipe_value ("First Operator",", ".join (operator_parts ))
        if "pprFlagsRaw"in first_rule :
            self ._print_wrapped_pipe_value ("PPR Flags Raw",first_rule ["pprFlagsRaw"])
        if "pprFlags"in first_rule :
            self ._print_wrapped_pipe_value ("PPR Flags Meaning",first_rule ["pprFlags"])

    def get_euicc_configured_data (self )->None :
        """ES10a.GetEuiccConfiguredData / GetEuiccConfiguredAddresses (retrieval)."""
        self ._es10_retrieve ("BF3C00","EuiccConfiguredData",root_tag =0xBF3C ,compact_json =True )

    def get_euicc_certs (self )->None :
        """ES10b.GetCerts (SGP.22/32 retrieval)."""
        self ._select_isd_r ()
        payload ="BF5600"
        print (f"{Config.Colors.CYAN}[*] GetCerts...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
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

            self ._print_get_certs_compact_response (data )
        except Exception :
            print (f"    {data.hex().upper()}")

    def get_eid (self )->None :
        """Retrieve EID from ES10 GetEuiccData / GetEID style retrieval."""
        data ,sw1 ,sw2 =self ._retrieve_eid_response ()
        if sw1 ==0x90 and data :
            print (f"{Config.Colors.HEADER}--- EID ---{Config.Colors.ENDC}")
            print (f"    {self._extract_eid_hex(data)}")
            return 
        print (f"{Config.Colors.FAIL}[-] Failed: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")

    def get_rat (self )->None :
        """ES10b.GetRAT (SGP.22/32) – Rules Authorisation Table. Retrieval only."""
        self ._select_isd_r ()
        payload ="BF4300"
        print (f"{Config.Colors.CYAN}[*] GetRAT (Rules Authorisation Table)...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
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
            self ._print_rat_compact_response (data )
        except Exception :
            print (f"    {data.hex().upper()}")

    def get_notifications_list (self )->None :
        """ES10b.RetrieveNotificationsList (SGP.22/32) – Pending notifications. Retrieval only."""
        self ._select_isd_r ()
        payload ="BF2B00"
        print (f"{Config.Colors.CYAN}[*] RetrieveNotificationsList...{Config.Colors.ENDC}")
        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload )
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
                self ._print_rat_compact_response (rat_data )
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
                self ._print_eim_configuration_compact (eim_data )
            except Exception :
                print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
                print (f"    | {eim_data.hex().upper()}")
        else :
            print (f"\n{Config.Colors.BOLD}[+] eIM Configuration Data{Config.Colors.ENDC}")
            print (f"    | {Config.Colors.FAIL}Failed / Empty{Config.Colors.ENDC}")

        cert_data =self ._es10_retrieve_data ("BF5600")
        if cert_data :
            try :
                self ._print_get_certs_compact_response (cert_data )
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

        data ,sw1 ,sw2 =self ._send_store_data_with_retry_ladder (payload .hex ())

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