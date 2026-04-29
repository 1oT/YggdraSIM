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
from typing import Dict ,Any ,Iterable ,List ,Optional 
from SCP03 .core .utils import TlvParser 

try :
    from cryptography import x509 
    from cryptography .hazmat .backends import default_backend 
    _CERT_BACKEND =default_backend ()
except ImportError :
    x509 =None 
    _CERT_BACKEND =None 


class AdvancedDecoders :
    @staticmethod 
    def decode_ef_arr (data_hex :str )->list :
        if not data_hex :
            return ["Empty/Invalid Rule"]
        if data_hex .startswith ('FF'):
            return ["Empty/Invalid Rule"]

        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return ["Hex Decode Error"]

        output =[]
        i =0 
        current_am_str =""

        while i <len (data ):
            try :
                tag =data [i ]
                length =data [i +1 ]
                value =data [i +2 :i +2 +length ]
                total_len =2 +length 

                if tag ==0x80 :
                    am_byte =value [0 ]
                    modes =[]
                    if am_byte &0x01 :
                        modes .append ("READ")
                    if am_byte &0x02 :
                        modes .append ("UPDATE")
                    if am_byte &0x04 :
                        modes .append ("APPEND")
                    if am_byte &0x08 :
                        modes .append ("DEACTIVATE")
                    if am_byte &0x10 :
                        modes .append ("ACTIVATE")
                    if am_byte &0x40 :
                        modes .append ("TERMINATE")

                    if len (modes )>0 :
                        current_am_str ="/".join (modes )
                    if len (modes )==0 :
                        current_am_str =f"Proprietary(0x{am_byte:02X})"

                if tag ==0x90 :
                    output .append (f"{current_am_str}: Always")
                if tag ==0x97 :
                    output .append (f"{current_am_str}: Never")
                if tag ==0xA4 :
                    sc_info =TlvParser .parse (value )
                    key_ref =sc_info .get (0x83 )
                    cond_str ="Unknown SC"

                    if key_ref :
                        ref_val =key_ref [0 ]
                        if ref_val ==0x01 :
                            cond_str ="PIN1"
                        if ref_val ==0x81 :
                            cond_str ="PIN1 (Global)"
                        if ref_val ==0x0A :
                            cond_str ="ADM1"

                        is_known =False 
                        if ref_val ==0x01 :
                            is_known =True 
                        if ref_val ==0x81 :
                            is_known =True 
                        if ref_val ==0x0A :
                            is_known =True 

                        if is_known ==False :
                            cond_str =f"ADM(0x{ref_val:02X})"

                    if current_am_str !="":
                        output .append (f"{current_am_str}: {cond_str}")

                i +=total_len 
                if total_len ==0 :
                    break 
            except IndexError :
                break 

        if len (output )>0 :
            return output 
        return ["No Rules"]

    @staticmethod 
    def decode_gp_seac_arf (data_hex :str )->list :
        """
        Decode GP SEAC ARF-related files (e.g. EF_ACRF/EF_ACCF) as BER-TLV.
        This is a structural decoder focused on tag-level visibility.
        """
        if not data_hex :
            return ["GP_SEAC: Empty/Invalid"]

        cleaned =data_hex .strip ().upper ()
        is_only_ff =True 
        for c in cleaned :
            if c !="F":
                is_only_ff =False 
                break 
        if is_only_ff :
            return ["GP_SEAC: Empty/Invalid"]

        try :
            data =bytes .fromhex (cleaned )
        except Exception :
            return ["GP_SEAC: Hex Decode Error"]

        tag_names ={
        0xE2 :"REF-AR-DO",
        0xE1 :"REF-DO",
        0xE3 :"AR-DO",
        0x4F :"AID-REF-DO",
        0xC1 :"DeviceAppID-REF-DO",
        0xCA :"PkgRef-DO / Ref-DO",
        0xDB :"PERM-AR-DO",
        0xD0 :"APDU-AR-DO",
        0xD1 :"NFC-AR-DO",
        0xD2 :"CarrierPrivilege-AR-DO",
        0xD3 :"Access-Rule-DO",
        0xD4 :"Access-Rule-Ext-DO",
        0xD5 :"Hash-Ref-DO",
        0xD6 :"BundleRef-DO",
        0xD7 :"APDU-Filter-DO",
        }

        parsed =TlvParser .parse (data )
        lines :List [str ]=[]

        def _tag_to_hex (tag :int )->str :
            if tag <=0xFF :
                return f"{tag:02X}"
            if tag <=0xFFFF :
                return f"{tag:04X}"
            return f"{tag:X}"

        def _tag_label (tag :int )->str :
            name =tag_names .get (tag )
            if name is not None :
                return name 
            return "Unknown"

        def _short_hex (raw :bytes ,max_chars :int =96 )->str :
            hex_text =raw .hex ().upper ()
            is_short =False 
            if len (hex_text )<=max_chars :
                is_short =True 
            if is_short :
                return hex_text 
            return hex_text [:max_chars ]+"..."

        def _walk (node :Any ,level :int )->None :
            if isinstance (node ,dict ):
                for tag ,val in node .items ():
                    tag_hex =_tag_to_hex (tag )
                    label =_tag_label (tag )

                    is_dict =False 
                    if isinstance (val ,dict ):
                        is_dict =True 
                    if is_dict :
                        lines .append (f"{'  ' * level}{tag_hex} {label}")
                        _walk (val ,level +1 )
                        continue 

                    is_list =False 
                    if isinstance (val ,list ):
                        is_list =True 
                    if is_list :
                        lines .append (f"{'  ' * level}{tag_hex} {label} [{len(val)}]")
                        for item in val :
                            _walk ({tag :item },level +1 )
                        continue 

                    is_bytes =False 
                    if isinstance (val ,bytes ):
                        is_bytes =True 
                    if is_bytes :
                        lines .append (f"{'  ' * level}{tag_hex} {label}: {_short_hex(val)}")
                        continue 

                    lines .append (f"{'  ' * level}{tag_hex} {label}: {val}")
                return 

            is_list =False 
            if isinstance (node ,list ):
                is_list =True 
            if is_list :
                for item in node :
                    _walk (item ,level )
                return 

            lines .append (f"{'  ' * level}{node}")

        _walk (parsed ,0 )
        if len (lines )==0 :
            return ["GP_SEAC: No TLV entries"]
        return lines 

    @staticmethod
    def decode_ara_rulesets (data_hex :str )->list :
        """
        Decode ARA-M / ARA-C GET DATA [All] payloads into compact ruleset lines.
        """
        if not data_hex :
            return ["ARA Rules: Empty/Invalid"]

        cleaned =data_hex .strip ().upper ()
        if len (cleaned )==0 :
            return ["ARA Rules: Empty/Invalid"]

        is_only_ff =True 
        for char in cleaned :
            if char !="F":
                is_only_ff =False 
                break 
        if is_only_ff :
            return ["ARA Rules: Empty/Invalid"]

        try :
            raw =bytes .fromhex (cleaned )
        except Exception :
            return ["ARA Rules: Hex Decode Error"]

        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["ARA Rules: TLV Parse Error"]

        rule_nodes :List [Dict [int ,Any ]]=[]

        def _as_dict (node :Any )->Optional [Dict [int ,Any ]]:
            if isinstance (node ,dict ):
                return node 
            if isinstance (node ,bytes ):
                try :
                    return TlvParser .parse (node )
                except Exception :
                    return None 
            return None 

        def _collect_rules (node :Any )->None :
            if isinstance (node ,dict ):
                for tag ,value in node .items ():
                    if tag ==0xE2 :
                        for item in TlvParser .as_list (value ):
                            rule_dict =_as_dict (item )
                            if rule_dict is not None :
                                rule_nodes .append (rule_dict )
                        continue 
                    _collect_rules (value )
                return 
            if isinstance (node ,list ):
                for item in node :
                    _collect_rules (item )

        def _ascii_or_hex (value :Any )->str :
            if isinstance (value ,bytes )==False :
                return ""
            if len (value )==0 :
                return ""
            try :
                return value .decode ("ascii")
            except Exception :
                return value .hex ().upper ()

        def _decode_apdu_rule (value :Any )->str :
            if isinstance (value ,bytes )==False :
                return ""
            if len (value )==1 :
                if value [0 ]==0x00 :
                    return "never"
                if value [0 ]==0x01 :
                    return "always"
                return value .hex ().upper ()
            if len (value )%8 !=0 :
                return value .hex ().upper ()
            filters =[]
            offset =0 
            while offset <len (value ):
                header =value [offset :offset +4 ].hex ().upper ()
                mask =value [offset +4 :offset +8 ].hex ().upper ()
                filters .append (f"{header}/{mask}")
                offset +=8 
            return "filter " +", ".join (filters )

        def _decode_nfc_rule (value :Any )->str :
            if isinstance (value ,bytes )==False :
                return ""
            if len (value )!=1 :
                return value .hex ().upper ()
            if value [0 ]==0x00 :
                return "never"
            if value [0 ]==0x01 :
                return "always"
            return value .hex ().upper ()

        _collect_rules (parsed )
        if len (rule_nodes )==0 :
            return ["ARA Rules: No rulesets returned"]

        output =[]
        for idx ,rule_node in enumerate (rule_nodes ,start =1 ):
            ref_do =_as_dict (TlvParser .get_first (rule_node ,0xE1 ,{}))
            ar_do =_as_dict (TlvParser .get_first (rule_node ,0xE3 ,{}))
            if ref_do is None :
                ref_do ={}
            if ar_do is None :
                ar_do ={}

            parts =[]

            aid_ref =TlvParser .get_first (ref_do ,0x4F )
            if isinstance (aid_ref ,bytes )and len (aid_ref )>0 :
                parts .append (f"AID={aid_ref .hex ().upper ()}")
            elif 0xC0 in ref_do :
                parts .append ("AID=Implicit")

            dev_app_id =TlvParser .get_first (ref_do ,0xC1 )
            if isinstance (dev_app_id ,bytes )and len (dev_app_id )>0 :
                parts .append (f"DeviceAppID={dev_app_id .hex ().upper ()}")

            pkg_ref =_ascii_or_hex (TlvParser .get_first (ref_do ,0xCA ))
            if len (pkg_ref )>0 :
                parts .append (f"Package={pkg_ref}")

            apdu_rule =_decode_apdu_rule (TlvParser .get_first (ar_do ,0xD0 ))
            if len (apdu_rule )>0 :
                parts .append (f"APDU={apdu_rule}")

            nfc_rule =_decode_nfc_rule (TlvParser .get_first (ar_do ,0xD1 ))
            if len (nfc_rule )>0 :
                parts .append (f"NFC={nfc_rule}")

            perm_rule =TlvParser .get_first (ar_do ,0xDB )
            if isinstance (perm_rule ,bytes )and len (perm_rule )>0 :
                parts .append (f"Permissions={perm_rule .hex ().upper ()}")

            if len (parts )==0 :
                parts .append ("Empty")

            output .append (f"Ruleset {idx}: " +" | ".join (parts ))

        return output 

    @staticmethod 
    def decode_pkcs15_acrf (data_hex :str )->list :
        """
        Decode PKCS#15 EF_ACRF (FID 4300) into compact rule references.
        Typical shape: SEQUENCE of rules, each with AID/Ref-DO and ACCF path reference.
        """
        if not data_hex :
            return ["PKCS15 ACRF: Empty/Invalid"]
        cleaned =data_hex .strip ().upper ()
        try :
            raw =bytes .fromhex (cleaned )
        except Exception :
            return ["PKCS15 ACRF: Hex Decode Error"]

        while len (raw )>0 and raw [-1 ]==0xFF :
            raw =raw [:-1 ]
        if len (raw )==0 :
            return ["PKCS15 ACRF: Empty/Invalid"]

        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ACRF: TLV Parse Error"]

        seq =TlvParser .get_first (parsed ,0x30 ,parsed )
        rules =[]

        def _collect_rules (node :Any )->None :
            if isinstance (node ,dict ):
                has_ref =False 
                if 0xA0 in node :
                    has_ref =True 
                if 0x30 in node :
                    has_ref =True 
                if has_ref :
                    rules .append (node )
                for v in node .values ():
                    _collect_rules (v )
                return 
            if isinstance (node ,list ):
                for item in node :
                    _collect_rules (item )

        _collect_rules (seq )
        out :List [str ]=[]
        if len (rules )==0 :
            return ["PKCS15 ACRF: No Rule Entries"]

        for idx ,rule in enumerate (rules ,start =1 ):
            aid_ref ="N/A"
            accf_ref ="N/A"

            ref_a0 =TlvParser .get_first (rule ,0xA0 )
            if isinstance (ref_a0 ,dict ):
                aid_oct =TlvParser .get_first (ref_a0 ,0x04 )
                if isinstance (aid_oct ,bytes ):
                    aid_ref =aid_oct .hex ().upper ()

            ref_30 =TlvParser .get_first (rule ,0x30 )
            if isinstance (ref_30 ,dict ):
                path_oct =TlvParser .get_first (ref_30 ,0x04 )
                if isinstance (path_oct ,bytes ):
                    accf_ref =path_oct .hex ().upper ()
            if isinstance (ref_30 ,bytes ):
                try :
                    parsed_30 =TlvParser .parse (ref_30 )
                    path_oct =TlvParser .get_first (parsed_30 ,0x04 )
                    if isinstance (path_oct ,bytes ):
                        accf_ref =path_oct .hex ().upper ()
                except Exception :
                    pass 

            out .append (f"Rule {idx}: AID Ref={aid_ref} | ACCF Ref={accf_ref}")

        return out 

    @staticmethod 
    def decode_pkcs15_accf (data_hex :str )->list :
        """
        Decode PKCS#15 EF_ACCF (FID 4310) access condition file entries.
        Common payload contains certificate hash references (OCTET STRING).
        """
        if not data_hex :
            return ["PKCS15 ACCF: Empty/Invalid"]
        cleaned =data_hex .strip ().upper ()
        try :
            raw =bytes .fromhex (cleaned )
        except Exception :
            return ["PKCS15 ACCF: Hex Decode Error"]

        while len (raw )>0 and raw [-1 ]==0xFF :
            raw =raw [:-1 ]
        if len (raw )==0 :
            return ["PKCS15 ACCF: Empty/Invalid"]

        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ACCF: TLV Parse Error"]

        octets :List [bytes ]=[]

        def _collect_octets (node :Any )->None :
            if isinstance (node ,dict ):
                for k ,v in node .items ():
                    if k ==0x04 :
                        if isinstance (v ,bytes ):
                            octets .append (v )
                        elif isinstance (v ,list ):
                            for item in v :
                                if isinstance (item ,bytes ):
                                    octets .append (item )
                    _collect_octets (v )
                return 
            if isinstance (node ,list ):
                for item in node :
                    _collect_octets (item )

        _collect_octets (parsed )
        if len (octets )==0 :
            return ["PKCS15 ACCF: No OCTET Entries"]

        out :List [str ]=[]
        for idx ,item in enumerate (octets ,start =1 ):
            h =item .hex ().upper ()
            algo ="raw"
            if len (item )==32 :
                algo ="sha256"
            if len (item )==20 :
                algo ="sha1"
            out .append (f"Entry {idx}: Cert Hash ({algo}) = {h}")
        return out 

    @staticmethod 
    def decode_cert_der (data :bytes )->Optional [Dict [str ,Any ]]:
        """Parse DER-encoded X.509 certificate; return subject, issuer, validity or None."""
        if not data or len (data )<4 :
            return None 
        if data [0 ]!=0x30 :
            return None 
        if x509 is None or _CERT_BACKEND is None :
            return {"raw_len":len (data ),"note":"cryptography not available for full decode"}
        try :
            cert =x509 .load_der_x509_certificate (data ,_CERT_BACKEND )
            nb =getattr (cert ,"not_valid_before_utc",None )or getattr (cert ,"not_valid_before",None )
            na =getattr (cert ,"not_valid_after_utc",None )or getattr (cert ,"not_valid_after",None )
            return {
            "subject":cert .subject .rfc4514_string (),
            "issuer":cert .issuer .rfc4514_string (),
            "not_valid_before":nb .isoformat ()if nb else "",
            "not_valid_after":na .isoformat ()if na else "",
            "serial":hex (cert .serial_number ),
            }
        except Exception :
            return None 

    @staticmethod 
    def decode_plmn_list (data_hex :str )->list :
        if not data_hex :
            return ["Empty List"]

        is_empty =True 
        for c in data_hex :
            if c !='F':
                is_empty =False 
        if is_empty :
            return ["Empty List"]

        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return ["PLMN Decode Error"]

        entries =[]
        step =3 

        remainder =len (data )%5 
        if remainder ==0 :
            step =5 

        for i in range (0 ,len (data ),step ):
            if i +3 >len (data ):
                break 

            plmn_bytes =data [i :i +3 ]
            if plmn_bytes ==b'\xFF\xFF\xFF':
                continue 

            b1 =plmn_bytes [0 ]
            b2 =plmn_bytes [1 ]
            b3 =plmn_bytes [2 ]

            mcc =f"{b1 & 0x0F}{b1 >> 4}{b2 & 0x0F}"
            mnc =f"{b3 & 0x0F}{b3 >> 4}"

            if (b2 &0xF0 )!=0xF0 :
                mnc =f"{b2 >> 4}{mnc}"

            entry_str =f"MCC: {mcc}, MNC: {mnc}"

            if step ==5 :
                act_bytes =int .from_bytes (data [i +3 :i +5 ],'big')
                acts =[]
                if act_bytes &0x8000 :
                    acts .append ("UTRAN")
                if act_bytes &0x4000 :
                    acts .append ("E-UTRAN")
                if act_bytes &0x0080 :
                    acts .append ("GSM")
                if act_bytes &0x0008 :
                    acts .append ("NG-RAN")

                if len (acts )>0 :
                    entry_str +=f" | AcT: {', '.join(acts)}"
                if len (acts )==0 :
                    entry_str +=" | AcT: None"

            entries .append (entry_str )

        if len (entries )>0 :
            return entries 
        return ["No Valid Entries"]

    @staticmethod 
    def decode_loci (data_hex :str )->dict :
        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return {"Error":"LOCI Decode Error"}

        if len (data )<11 :
            return {"Error":f"Invalid LOCI Length ({len(data)})"}

        try :
            tmsi =data [0 :4 ].hex ().upper ()
            mcc_mnc_bytes =data [4 :7 ]

            b1 =mcc_mnc_bytes [0 ]
            b2 =mcc_mnc_bytes [1 ]
            b3 =mcc_mnc_bytes [2 ]

            mcc =f"{b1 & 0x0F}{b1 >> 4}{b2 & 0x0F}"
            mnc =f"{b3 & 0x0F}{b3 >> 4}"

            if (b2 &0xF0 )!=0xF0 :
                mnc =f"{b2 >> 4}{mnc}"

            lac =int .from_bytes (data [7 :9 ],'big')
            status_byte =data [10 ]

            status_map ={0 :"Updated",1 :"Not Updated",2 :"PLMN Not Allowed",3 :"Loc Not Allowed"}
            status_str =status_map .get (status_byte &0x03 ,"Unknown")

            return {
            "TMSI":tmsi ,
            "LAI":f"{mcc}-{mnc}",
            "LAC":lac ,
            "Status":status_str 
            }
        except Exception :
            return {"Error":"LOCI Decode Error"}

    @staticmethod 
    def decode_ust (data_hex :str )->dict :
        # 3GPP TS 31.102 §4.2.8 — USIM Service Table. Each bit is a
        # service flag; the file body is the bitmap. Operators asked to
        # see *not-set* services too so the GUI can render a checklist
        # style view (active vs. available-but-disabled) rather than
        # only reporting the active subset.
        if not data_hex :
            return {"error":"Empty","active":[],"inactive":[]}

        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return {"error":"UST Decode Error","active":[],"inactive":[]}

        try :
            ust_map ={
            1 :"Local Phone Book",2 :"FDN",3 :"Extension 2",4 :"SDN",5 :"Extension 3",
            6 :"SMS",7 :"BDN",8 :"OCI",9 :"ICI",10 :"SMS-PP Download",
            11 :"SMS-CB Download",12 :"Call Control by USIM",13 :"MO-SMS Control",
            14 :"RUN AT COMMAND",15 :"Ignored",16 :"Enabled Services Table",17 :"ACL",
            18 :"Depersonalisation Keys",19 :"Co-operative Network List",20 :"GSM Access",
            21 :"OPLMNwAcT",22 :"LOCI",23 :"PSLOCI",24 :"SMSS",25 :"SPN",26 :"ECC",
            27 :"MCC",28 :"Extension 5",29 :"HPLMNwAcT",30 :"CPBCCH",31 :"Inv Scan",
            32 :"MexE",33 :"RPLMNAcT",34 :"HPLMN",35 :"Extension 6",36 :"Extension 7",
            37 :"Extension 8",38 :"Call Control on GPRS",39 :"MMS",40 :"Extension 8",
            41 :"MMS UCP",42 :"NIA",43 :"VGCS/VBS Group ID",44 :"VGCS/VBS Service ID",
            45 :"VGCS Security",46 :"VBS Security",50 :"TIA/EIA-136",52 :"GBA",
            53 :"MMS Prefs",54 :"GBA",55 :"MBMS Security",56 :"USSD Data Download",
            57 :"Equivalent HPLMN",58 :"Terminal Profile",59 :"EHPLMN PI",60 :"Last RPLMN Sel",
            61 :"OMA BCAST",62 :"GBA-PUSH",63 :"PWS Config",64 :"FDN URI",65 :"BDN URI",
            66 :"SDN URI",67 :"OCI URI",68 :"ICI URI",69 :"IAL URI",70 :"IPS URI",
            71 :"IPD URI",72 :"ePDG Config (3GPP)",73 :"ePDG Config (Non-3GPP)",
            74 :"IMS Config Data",75 :"3GPP PS Data Off",76 :"3GPP PS Data Off List",
            77 :"XCAP Config",78 :"EARFCN List",79 :"MuD/MiD Config",80 :"EAKA",81 :"OCST",
            82 :"AC_GBAUAPI",83 :"IMS DCI",84 :"From Preferred",85 :"UICC Access to IMS",
            86 :"Extended LOCI",87 :"Extended PSLOCI",88 :"5GS 3GPP LOCI",89 :"5GS N3GPP LOCI",
            90 :"5GS 3GPP NSC",91 :"5GS N3GPP NSC",92 :"5G Auth Keys",93 :"UAC AIC",
            94 :"SUCI Calc Info",95 :"OPL5G",96 :"SUPI NAI",97 :"Routing Indicator",
            98 :"URSP",99 :"TN3GPPSNN",100 :"CAG",101 :"SOR-CMCI",102 :"DRI",
            103 :"5G SE-DRX",104 :"5G NSWO Conf",105 :"MCHPPLMN",106 :"KAUSF Derivation",
            113 :"5G Parameters"
            }
            return AdvancedDecoders ._build_service_table (
                data ,
                name_map =ust_map ,
                table_name ="UST",
                full_name ="USIM Service Table",
                spec ="3GPP TS 31.102 \u00a74.2.8",
                )
        except Exception :
            return {"error":"UST Decode Error","active":[],"inactive":[]}

    # ---- Service-table encoder (mock-update / staging) ----------------
    #
    # Operators asked for a way to *preview* what a UST / IST / generic
    # service-table EF body would look like after toggling individual
    # service flags, without having to push the new bytes to the card.
    # Pure local math: given a list of active service numbers and the
    # original byte length, build the matching bitmap so the GUI can
    # surface the resulting hex string for copy / inspection / feeding
    # into UPDATE BINARY.
    @staticmethod 
    def encode_service_table (
    active_bits :Iterable [int ],
    *,
    total_bytes :Optional [int ]=None ,
    current_hex :Optional [str ]=None ,
    )->str :
        # Resolve the EF body length. ``total_bytes`` wins; otherwise
        # we infer it from the current hex (so callers staging an edit
        # on an existing EF can omit it). When neither is present we
        # auto-size to fit the highest set bit, which is the right
        # default for a fresh from-scratch encode.
        if total_bytes is None and current_hex is not None :
            cleaned =str (current_hex or "").replace (" ","").replace (":","")
            total_bytes =max (1 ,len (cleaned )//2 )
        bits =sorted ({int (n )for n in active_bits if int (n )>=1 })
        if total_bytes is None :
            highest =bits [-1 ]if len (bits )>0 else 1 
            total_bytes =max (1 ,(highest +7 )//8 )
        buf =bytearray (int (total_bytes ))
        for service_num in bits :
            byte_idx =(service_num -1 )//8 
            bit_idx =(service_num -1 )%8 
            if byte_idx >=len (buf ):
                # Caller wants to set a service beyond the current
                # body — extend the buffer rather than silently dropping
                # the bit. Cards reject oversized payloads at UPDATE
                # time, but for staging we want the operator to *see*
                # the resulting size before submitting.
                buf .extend (b"\x00"*(byte_idx +1 -len (buf )))
            buf [byte_idx ]|=(1 <<bit_idx )
        return buf .hex ().upper ()

    @staticmethod 
    def _build_service_table (
    data :bytes ,
    *,
    name_map :Optional [Dict [int ,str ]]=None ,
    table_name :str ="Service Table",
    full_name :Optional [str ]=None ,
    spec :Optional [str ]=None ,
    )->Dict [str ,Any ]:
        # Shared shape for UST / IST / EST / SST-style bitmap files.
        # Returns ``active`` and ``inactive`` lists in the same
        # ``"<n>: <name>"`` shape so the GUI can render both columns
        # with a single renderer. ``service_table`` is a sentinel the
        # frontend keys off to switch to the checklist layout.
        active =[]
        inactive =[]
        total_bits =len (data )*8 
        named_only =name_map is not None 
        for byte_idx ,byte_val in enumerate (data ):
            for bit_idx in range (8 ):
                service_num =(byte_idx *8 )+bit_idx +1 
                if name_map is not None :
                    name =name_map .get (service_num )
                    if name is None :
                        # Fall through to a generic placeholder so the
                        # operator still sees that bit X exists (helps
                        # diagnose oversized service tables on lab cards).
                        label =f"{service_num}: Service {service_num}"
                    else :
                        label =f"{service_num}: {name}"
                else :
                    label =f"{service_num}"
                is_set =bool (byte_val &(1 <<bit_idx ))
                if is_set :
                    active .append (label )
                else :
                    inactive .append (label )

        result :Dict [str ,Any ]={
        "service_table":True ,
        "table":table_name ,
        "active_count":len (active ),
        "inactive_count":len (inactive ),
        "total_count":total_bits ,
        "summary":f"{len(active)} of {total_bits} active",
        "active":active ,
        "inactive":inactive ,
        "raw":data .hex ().upper (),
        }
        if full_name is not None :
            result ["full_name"]=full_name 
        if spec is not None :
            result ["spec"]=spec 
        return result 

class ContentDecoder :
    _registry ={}

    @classmethod 
    def init_registry (cls ):
        cls ._registry ={
        '2FE2':cls .decode_iccid ,
        '2F00':cls .decode_dir ,
        '2F06':AdvancedDecoders .decode_ef_arr ,
        '6F06':AdvancedDecoders .decode_ef_arr ,
        '2F08':cls .decode_hex_chunks ,
        '4300':cls .decode_pkcs15_acrf_json ,
        '4310':cls .decode_pkcs15_accf_json ,
        '4200':cls .decode_pkcs15_acm ,
        '5031':cls .decode_pkcs15_odf ,
        '5207':cls .decode_pkcs15_dodf ,
        '2F05':cls .decode_language_indicators ,
        '6F07':cls .decode_imsi ,
        '6FAD':cls .decode_ad ,
        '6F08':lambda x :{"Ciphering Keys (Raw)":x },
        '6F78':cls .decode_acc ,
        '6F31':lambda x :{"HPPLMN Search Interval":int (x ,16 )},
        '6F38':AdvancedDecoders .decode_ust ,
        '6F40':cls .decode_msisdn ,
        '6F46':cls .decode_spn ,
        '6F7B':AdvancedDecoders .decode_plmn_list ,
        '6F60':AdvancedDecoders .decode_plmn_list ,
        '6F61':AdvancedDecoders .decode_plmn_list ,
        '6F62':AdvancedDecoders .decode_plmn_list ,
        '6FD9':AdvancedDecoders .decode_plmn_list ,
        '6F7E':AdvancedDecoders .decode_loci ,
        '6F73':AdvancedDecoders .decode_loci ,
        '6FE3':AdvancedDecoders .decode_loci ,
        '4F01':AdvancedDecoders .decode_loci ,
        '6F42':cls .decode_sms_params ,
        '6F3C':cls .decode_sms_record ,
        '6F5B':lambda x :{"START-HFN":x },
        '6F5C':lambda x :{"Threshold":x },
        '6F05':lambda x :{"LI":x },
        '6F37':lambda x :{"ACM Max":x },
        '6F39':lambda x :{"ACM":x },
        '6F3E':lambda x :{"GID1":x },
        '6F3F':lambda x :{"GID2":x },
        '6F56':AdvancedDecoders .decode_ust ,
        '6F41':cls .decode_puct ,
        '6FB7':cls .decode_ecc ,
        '6F3A':cls .decode_adn_like_record ,
        '6F3B':cls .decode_adn_like_record ,
        '6F3D':cls .decode_adn_like_record ,
        '6F49':cls .decode_adn_like_record ,
        '6F43':cls .decode_smss ,
        '6F47':cls .decode_smsr ,
        '6FC5':cls .decode_pnn ,
        '6FC6':cls .decode_opl ,
        '6FCD':cls .decode_spdi ,
        '6FE4':cls .decode_epsnsc ,
        '6FDA':cls .decode_gbanl ,
        '6FDD':cls .decode_nafkca ,
        '6F45':cls .decode_cbmi_list ,
        '6F48':cls .decode_cbmi_list ,
        '6F50':cls .decode_cbmid_range_list ,
        '6FEC':cls .decode_hex_chunks ,
        '6FDE':cls .decode_utf8_or_hex ,
        '6FDF':cls .decode_utf8_or_hex ,
        '6FE2':cls .decode_utf8_or_hex ,
        '6FE6':cls .decode_tlv_as_map ,
        '6FE7':cls .decode_tlv_as_map ,
        '6FE8':cls .decode_tlv_as_map ,
        '6FED':cls .decode_utf8_or_hex ,
        '6FEE':cls .decode_utf8_or_hex ,
        '6FEF':cls .decode_utf8_or_hex ,
        '6FF0':cls .decode_utf8_or_hex ,
        '6FF1':cls .decode_utf8_or_hex ,
        '6FF2':cls .decode_utf8_or_hex ,
        '6FF3':cls .decode_utf8_or_hex ,
        '6FF4':cls .decode_tlv_as_map ,
        '6FF5':cls .decode_utf8_or_hex ,
        '6FF6':cls .decode_tlv_as_map ,
        '6FF7':cls .decode_utf8_or_hex ,
        '6FF8':cls .decode_tlv_as_map ,
        '6FF9':cls .decode_service_table_bits ,
        '6FFA':cls .decode_tlv_as_map ,
        '6FFC':cls .decode_tlv_as_map ,
        '6FFD':cls .decode_hex_chunks ,
        '6FFE':cls .decode_tlv_as_map ,
        }

        cls ._register_context_decoders ()

    @classmethod 
    def _register_context_decoders (cls ):

        cls ._registry ['TELECOM/6F3A']=cls .decode_adn_like_record 
        cls ._registry ['TELECOM/6F3B']=cls .decode_adn_like_record 
        cls ._registry ['TELECOM/6F3C']=cls .decode_sms_record 
        cls ._registry ['TELECOM/6F3D']=cls .decode_adn_like_record 
        cls ._registry ['TELECOM/6F40']=cls .decode_msisdn 
        cls ._registry ['TELECOM/6F42']=cls .decode_sms_params 
        cls ._registry ['TELECOM/6F43']=cls .decode_smss 
        cls ._registry ['TELECOM/6F47']=cls .decode_smsr 
        cls ._registry ['TELECOM/6F49']=cls .decode_adn_like_record 
        cls ._registry ['TELECOM/6F4A']=cls .decode_hex_chunks 
        cls ._registry ['TELECOM/6F4B']=cls .decode_hex_chunks 
        cls ._registry ['TELECOM/6F4C']=cls .decode_hex_chunks 
        cls ._registry ['TELECOM/6F4F']=cls .decode_hex_chunks 


        cls ._registry ['PHONEBOOK/4F22']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F23']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F24']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F30']=cls .decode_tlv_as_map 
        cls ._registry ['PHONEBOOK/4F38']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F40']=cls .decode_utf8_or_hex 
        cls ._registry ['PHONEBOOK/4F48']=cls .decode_utf8_or_hex 
        cls ._registry ['PHONEBOOK/4F50']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F58']=cls .decode_adn_like_record 
        cls ._registry ['PHONEBOOK/4F60']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F68']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F70']=cls .decode_utf8_or_hex 
        cls ._registry ['PHONEBOOK/4F78']=cls .decode_utf8_or_hex 
        cls ._registry ['PHONEBOOK/4F80']=cls .decode_utf8_or_hex 
        cls ._registry ['PHONEBOOK/4F88']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F90']=cls .decode_hex_chunks 
        cls ._registry ['PHONEBOOK/4F98']=cls .decode_hex_chunks 


        cls ._registry ['GRAPHICS/4F20']=cls .decode_hex_chunks 
        cls ._registry ['GRAPHICS/4F21']=cls .decode_hex_chunks 
        cls ._registry ['GRAPHICS/4F40']=cls .decode_hex_chunks 
        cls ._registry ['MULTIMEDIA/4F47']=cls .decode_hex_chunks 
        cls ._registry ['MULTIMEDIA/4F48']=cls .decode_hex_chunks 
        cls ._registry ['MMSS/4F20']=cls .decode_hex_chunks 
        cls ._registry ['MMSS/4F21']=cls .decode_hex_chunks 
        cls ._registry ['MMSS/4F22']=cls .decode_hex_chunks 


        cls ._registry ['MCS/4F01']=cls .decode_service_table_bits 
        cls ._registry ['MCS/4F02']=cls .decode_tlv_as_map 
        cls ._registry ['V2X/4F01']=cls .decode_service_table_bits 
        cls ._registry ['V2X/4F02']=cls .decode_tlv_as_map 
        cls ._registry ['V2X/4F03']=cls .decode_tlv_as_map 
        cls ._registry ['V2X/4F04']=cls .decode_tlv_as_map 
        cls ._registry ['A2X/4F01']=cls .decode_service_table_bits 
        cls ._registry ['A2X/4F02']=cls .decode_tlv_as_map 
        cls ._registry ['A2X/4F03']=cls .decode_tlv_as_map 
        cls ._registry ['A2X/4F04']=cls .decode_tlv_as_map 
        cls ._registry ['A2X/4F05']=cls .decode_tlv_as_map 
        cls ._registry ['A2X/4F06']=cls .decode_tlv_as_map 


        cls ._registry ['EAP/4F01']=cls .decode_hex_chunks 
        cls ._registry ['EAP/4F02']=cls .decode_hex_chunks 
        cls ._registry ['EAP/4F04']=cls .decode_tlv_as_map 
        cls ._registry ['EAP/4F20']=cls .decode_hex_chunks 
        cls ._registry ['EAP/4F21']=cls .decode_hex_chunks 
        cls ._registry ['EAP/4F22']=cls .decode_utf8_or_hex 
        cls ._registry ['EAP/6F01']=cls .decode_utf8_or_hex 
        cls ._registry ['EAP/6F02']=cls .decode_tlv_as_map 


        cls ._registry ['ISIM/6F02']=cls .decode_isim_tlv80_text 
        cls ._registry ['ISIM/6F03']=cls .decode_isim_tlv80_text 
        cls ._registry ['ISIM/6F04']=cls .decode_isim_tlv80_text 
        cls ._registry ['ISIM/6F07']=cls .decode_isim_ist 
        cls ._registry ['ISIM/6F09']=cls .decode_isim_pcscf 
        cls ._registry ['ISIM/6FFA']=cls .decode_isim_tlv80_text 


        cls ._registry ['5GS/4F01']=cls .decode_5gs_loci 
        cls ._registry ['5GS/4F02']=cls .decode_5gs_loci 
        cls ._registry ['5GS/4F03']=cls .decode_5gs_nsc 
        cls ._registry ['5GS/4F04']=cls .decode_5gs_nsc 
        cls ._registry ['5GS/4F05']=cls .decode_5gs_auth_keys 
        cls ._registry ['5GS/4F06']=cls .decode_5gs_uac_aic 
        cls ._registry ['5GS/4F07']=cls .decode_tlv_as_map 
        cls ._registry ['5GS/4F08']=cls .decode_opl 
        cls ._registry ['5GS/4F09']=cls .decode_utf8_or_hex 
        cls ._registry ['5GS/4F0A']=cls .decode_routing_indicator 
        cls ._registry ['5GS/4F0B']=cls .decode_tlv_as_map 
        cls ._registry ['5GS/4F0C']=cls .decode_utf8_or_hex 
        cls ._registry ['5GS/4F0D']=cls .decode_hex_chunks 
        cls ._registry ['5GS/4F0E']=cls .decode_5gs_sor_cmci 
        cls ._registry ['5GS/4F0F']=cls .decode_dri 
        cls ._registry ['5GS/4F10']=cls .decode_hex_chunks 
        cls ._registry ['5GS/4F11']=cls .decode_hex_chunks 
        cls ._registry ['5GS/4F15']=cls .decode_hex_chunks 
        cls ._registry ['5GS/4F16']=cls .decode_tlv_as_map 

        cls ._registry ['SNPN/4F01']=cls .decode_hex_chunks 
        cls ._registry ['SNPN/4F02']=cls .decode_hex_chunks 
        cls ._registry ['SAIP/4F01']=cls .decode_tlv_as_map 
        cls ._registry ['5G_PROSE/4F01']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F02']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F03']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F04']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F05']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F06']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F07']=cls .decode_hex_chunks 
        cls ._registry ['5G_PROSE/4F08']=cls .decode_hex_chunks 

    @staticmethod 
    def _decode_bcd_digits (data :bytes )->str :
        out =[]
        for b in data :
            low =b &0x0F 
            high =(b >>4 )&0x0F 
            if low !=0x0F :
                out .append (str (low ))
            if high !=0x0F :
                out .append (str (high ))
        return "".join (out )

    @staticmethod 
    def _decode_plmn_bytes (plmn_bytes :bytes )->str :
        if len (plmn_bytes )<3 :
            return plmn_bytes .hex ().upper ()
        b1 =plmn_bytes [0 ]
        b2 =plmn_bytes [1 ]
        b3 =plmn_bytes [2 ]
        mcc =f"{b1 & 0x0F}{b1 >> 4}{b2 & 0x0F}"
        mnc =f"{b3 & 0x0F}{b3 >> 4}"
        if (b2 &0xF0 )!=0xF0 :
            mnc =f"{b2 >> 4}{mnc}"
        return f"{mcc}-{mnc}"

    @staticmethod 
    def decode_language_indicators (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            langs =[]
            for i in range (0 ,len (data ),2 ):
                chunk =data [i :i +2 ]
                if len (chunk )<2 :
                    break 
                if chunk ==b"\xFF\xFF":
                    continue 
                langs .append (chunk .decode ("ascii","ignore"))
            return {"Preferred Languages":langs ,"Raw":hex_str }
        except Exception :
            return {"Preferred Languages (Raw)":hex_str }

    @staticmethod 
    def decode_service_table_bits (hex_str :str )->dict :
        # Generic anonymous service-table decoder used by EF_PSISMSC,
        # MCS / V2X / A2X service-table EFs, etc. Without a name map
        # the rows are pure service numbers, but the active/inactive
        # split still gives operators a checklist view in the GUI.
        try :
            data =bytes .fromhex (hex_str )
        except Exception :
            return {"service_table":True ,"error":"Service Table (Raw)",
            "raw":hex_str ,"active":[],"inactive":[]}
        return AdvancedDecoders ._build_service_table (
            data ,
            name_map =None ,
            table_name ="Service Table",
            full_name ="Generic service table (no name map)",
            )

    @staticmethod 
    def decode_cbmi_list (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            ids =[]
            for i in range (0 ,len (data ),2 ):
                chunk =data [i :i +2 ]
                if len (chunk )<2 :
                    break 
                if chunk ==b"\xFF\xFF":
                    continue 
                ids .append (int .from_bytes (chunk ,"big"))
            return {"Message Identifiers":ids ,"Raw":hex_str }
        except Exception :
            return {"CBMI (Raw)":hex_str }

    @staticmethod 
    def decode_cbmid_range_list (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            ranges =[]
            for i in range (0 ,len (data ),4 ):
                chunk =data [i :i +4 ]
                if len (chunk )<4 :
                    break 
                if chunk ==b"\xFF\xFF\xFF\xFF":
                    continue 
                first =int .from_bytes (chunk [0 :2 ],"big")
                last =int .from_bytes (chunk [2 :4 ],"big")
                ranges .append (f"{first}-{last}")
            return {"Message Identifier Ranges":ranges ,"Raw":hex_str }
        except Exception :
            return {"CBMID (Raw)":hex_str }

    @staticmethod 
    def _context_tokens (context_path :Optional [str ])->List [str ]:
        if not context_path :
            return []
        raw =str (context_path ).strip ().upper ()
        if raw =="":
            return []
        parts =[p for p in raw .split ('/')if p ]
        out =[]
        for p in parts :
            v =p 
            if v .startswith ("EF_"):
                v =v [3 :]
            out .append (v )
        return out 

    @classmethod 
    def _resolve_handler (cls ,fid_upper :str ,context_path :Optional [str ]=None ):
        tokens =cls ._context_tokens (context_path )
        for tok in reversed (tokens ):
            key =f"{tok}/{fid_upper}"
            handler =cls ._registry .get (key )
            if handler :
                return handler 
        return cls ._registry .get (fid_upper )

    @staticmethod 
    def decode_spn (hex_str :str )->dict :
        try :
            valid =False 
            if hex_str :
                if len (hex_str )>2 :
                    valid =True 
            if valid :
                return {"SPN":bytes .fromhex (hex_str )[1 :].decode ('utf-8','ignore')}
            return {"SPN":"Invalid SPN"}
        except Exception :
            return {"SPN":"Invalid SPN"}

    @classmethod 
    def decode_raw (cls ,fid :str ,hex_data :str ,context_path :Optional [str ]=None )->Any :
        if not fid :
            return None 
        fid_upper =fid .upper ()

        is_empty =False 
        if not cls ._registry :
            is_empty =True 
        if is_empty :
            cls .init_registry ()

        handler =cls ._resolve_handler (fid_upper ,context_path )
        if handler :
            return handler (hex_data )
        return None 

    @classmethod 
    def decode (cls ,fid :str ,hex_data :str ,context_path :Optional [str ]=None )->Optional [str ]:
        raw =cls .decode_raw (fid ,hex_data ,context_path =context_path )
        if raw is None :
            return None 

        is_list =False 
        if isinstance (raw ,list ):
            is_list =True 
        if is_list :
            return "\n".join (str (x )for x in raw )

        is_dict =False 
        if isinstance (raw ,dict ):
            is_dict =True 
        if is_dict :
            out_lines =[]
            for k ,v in raw .items ():
                out_lines .append (f"{k}: {v}")
            return "\n".join (out_lines )

        return str (raw )

    @classmethod 
    def decode_obj (cls ,fid :str ,hex_data :str ,context_path :Optional [str ]=None )->Optional [Dict [str ,Any ]]:
        raw =cls .decode_raw (fid ,hex_data ,context_path =context_path )
        if raw is None :
            return None 

        is_dict =False 
        if isinstance (raw ,dict ):
            is_dict =True 
        if is_dict :
            return raw 

        is_list =False 
        if isinstance (raw ,list ):
            is_list =True 
        if is_list :
            return {'items':raw }

        return {'description':str (raw )}

    @staticmethod 
    def decode_acc (hex_str :str )->dict :
        try :
            val =int (hex_str ,16 )
            classes =[]
            for i in range (16 ):
                if val &(1 <<i ):
                    classes .append (str (i ))
            return {"Access Control Classes":classes }
        except Exception :
            return {"Error":"ACC Decode Error"}

    @staticmethod 
    def decode_dir (hex_str :str )->dict :
        try :
            is_empty =True 
            for c in hex_str :
                if c !='F':
                    is_empty =False 
            if is_empty :
                return {"Error":"Empty Record"}

            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"Error":"Empty Data"}

            parsed =TlvParser .parse (data )
            app =parsed .get (0x61 )

            if app :
                inner =app 
                if isinstance (app ,bytes ):
                    inner =TlvParser .parse (app )

                aid =inner .get (0x4F ,b'').hex ().upper ()
                label =inner .get (0x50 ,b'').decode ('ascii','ignore').strip ()
                return {"AID":aid ,"Label":label }

            return {"Raw DIR Data":hex_str }
        except Exception as e :
            return {"Error":f"DIR Decode Error: {e}"}

    @staticmethod 
    def decode_msisdn (hex_str :str )->dict :
        try :
            is_empty =True 
            for c in hex_str :
                if c !='F':
                    is_empty =False 
            if is_empty :
                return {"Error":"Empty Record"}

            data =bytes .fromhex (hex_str )
            if len (data )<14 :
                return {"Error":f"Invalid Length ({len(data)})"}

            footer_len =14 
            alpha_len =len (data )-footer_len 

            alpha_id =""
            if alpha_len >0 :
                alpha_id =data [:alpha_len ].decode ('utf-8','ignore').strip ()

            footer =data [alpha_len :]
            ton_npi =footer [1 ]
            bcd_data =footer [2 :12 ].hex ().upper ()

            digits =[]
            for i in range (0 ,len (bcd_data ),2 ):
                digits .append (bcd_data [i +1 ]+bcd_data [i ])

            dial_num ="".join (digits ).replace ('F','')

            out_dict ={}
            if alpha_id !="":
                out_dict ["Alpha ID"]=alpha_id 
            out_dict ["Dialing Number"]=dial_num 
            out_dict ["TON/NPI"]=f"{ton_npi:02X}"
            return out_dict 
        except Exception as e :
            return {"Error":f"MSISDN Decode Error: {e}"}

    @staticmethod 
    def decode_iccid (hex_str :str )->dict :
        try :
            res =[]
            for i in range (0 ,len (hex_str ),2 ):
                res .append (hex_str [i +1 ]+hex_str [i ])
            return {"iccid":"".join (res ).replace ('F','')}
        except Exception :
            return {"iccid_raw":hex_str }

    @staticmethod 
    def decode_imsi (hex_str :str )->dict :
        try :
            imsi_hex =hex_str [2 :]
            res =[imsi_hex [1 ]]
            for i in range (2 ,len (imsi_hex ),2 ):
                res .append (imsi_hex [i +1 ]+imsi_hex [i ])
            return {"imsi":"".join (res ).replace ('F','')}
        except Exception :
            return {"imsi_raw":hex_str }

    @staticmethod 
    def decode_ad (hex_str :str )->dict :
        try :
            mode =int (hex_str [0 :2 ],16 )
            m_map ={0 :"Normal",1 :"Type Approval",2 :"Normal/Internal",4 :"Normal/Internal",128 :"Proprietary"}
            mode_str =m_map .get (mode ,f"0x{mode:02X}")
            return {"Administrative Mode":mode_str }
        except Exception :
            return {"Error":"AD Decode Error"}

    @staticmethod 
    def decode_sms_params (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<12 :
                return {"SMS Params (Raw)":hex_str }
            alpha_len =max (0 ,len (data )-28 )
            alpha =""
            if alpha_len >0 :
                alpha =data [:alpha_len ].decode ("utf-8","ignore").strip ("\x00").strip ()
            p_ind =data [alpha_len ]
            tp_da =data [alpha_len +1 :alpha_len +13 ]
            sca =data [alpha_len +13 :alpha_len +25 ]
            out ={
            "Parameter Indicators":f"{p_ind:02X}",
            "TP-Destination Address":tp_da .hex ().upper (),
            "Service Center Address":sca .hex ().upper (),
            "TP-PID":f"{data[alpha_len + 25]:02X}",
            "TP-DCS":f"{data[alpha_len + 26]:02X}",
            "TP-Validity":f"{data[alpha_len + 27]:02X}",
            }
            if alpha :
                out ["Alpha ID"]=alpha 
            return out 
        except Exception :
            return {"SMS Params (Raw)":f"{hex_str[:64]}..."}

    @staticmethod 
    def decode_puct (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<5 :
                return {"PUCT (Raw)":hex_str }
            currency =data [0 :3 ].decode ("ascii","ignore").strip ()or data [0 :3 ].hex ().upper ()
            eppu =(data [3 ]<<4 )|(data [4 ]&0x0F )
            exp_nibble =(data [4 ]>>4 )&0x0F 
            sign =-1 if (exp_nibble &0x08 )else 1 
            exponent =sign *(exp_nibble &0x07 )
            return {
            "Currency":currency ,
            "EPPU":eppu ,
            "Exponent":exponent ,
            "Price per Unit Formula":f"{eppu} * 10^{exponent}"
            }
        except Exception :
            return {"PUCT (Raw)":hex_str }

    @staticmethod 
    def decode_ecc (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            codes =[]
            for i in range (0 ,len (data ),3 ):
                block =data [i :i +3 ]
                if len (block )<3 :
                    break 
                if block ==b"\xFF\xFF\xFF":
                    continue 
                digits =ContentDecoder ._decode_bcd_digits (block )
                if digits :
                    codes .append (digits )
            return {"Emergency Codes":codes }
        except Exception :
            return {"ECC (Raw)":hex_str }

    @staticmethod 
    def decode_adn_like_record (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<14 :
                return {"ADN-like (Raw)":hex_str }
            alpha_len =len (data )-14 
            alpha =""
            if alpha_len >0 :
                alpha =data [:alpha_len ].decode ("utf-8","ignore").strip ("\x00").strip ()
            footer =data [alpha_len :]
            number_len =footer [0 ]
            ton_npi =footer [1 ]
            number_bcd =footer [2 :12 ]
            ext_id =footer [13 ]
            digits =ContentDecoder ._decode_bcd_digits (number_bcd )
            if number_len >1 :
                max_digits =(number_len -1 )*2 
                digits =digits [:max_digits ]
            out ={
            "Length of BCD Number":number_len ,
            "TON/NPI":f"{ton_npi:02X}",
            "Dialing Number":digits ,
            "Ext Record ID":f"{ext_id:02X}"
            }
            if alpha :
                out ["Alpha ID"]=alpha 
            return out 
        except Exception :
            return {"ADN-like (Raw)":hex_str }

    @staticmethod 
    def decode_smss (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<2 :
                return {"SMSS (Raw)":hex_str }
            return {
            "Last Used TP-MR":data [0 ],
            "Memory Capacity Exceeded Flag":"set"if (data [1 ]&0x01 )==0 else "unset",
            "Raw":hex_str 
            }
        except Exception :
            return {"SMSS (Raw)":hex_str }

    @staticmethod 
    def decode_sms_record (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"SMS":"Empty"}
            status =data [0 ]
            payload =data [1 :]
            return {
            "Record Status":f"{status:02X}",
            "Record State":ContentDecoder ._decode_sms_status (status ),
            "TPDU (raw)":payload .hex ().upper ()
            }
        except Exception :
            return {"SMS Record (Raw)":hex_str }

    @staticmethod 
    def _decode_sms_status (status :int )->str :
        if (status &0x01 )==0 :
            return "Free"
        if (status &0x07 )==0x01 :
            return "Received Read"
        if (status &0x07 )==0x03 :
            return "Received Unread"
        if (status &0x07 )==0x05 :
            return "Stored Sent"
        if (status &0x07 )==0x07 :
            return "Stored Unsent"
        return "Unknown"

    @staticmethod 
    def decode_smsr (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<1 :
                return {"SMSR (Raw)":hex_str }
            return {
            "SMS Record Identifier":data [0 ],
            "Status Report TPDU":data [1 :].hex ().upper ()
            }
        except Exception :
            return {"SMSR (Raw)":hex_str }

    @staticmethod 
    def decode_pnn (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"PNN":"Empty"}
            parsed =TlvParser .parse (data )
            full_name =None 
            short_name =None 
            if isinstance (parsed ,dict ):
                if 0x43 in parsed and isinstance (parsed [0x43 ],bytes ):
                    full_name =parsed [0x43 ].decode ("utf-8","ignore").strip ()
                if 0x45 in parsed and isinstance (parsed [0x45 ],bytes ):
                    short_name =parsed [0x45 ].decode ("utf-8","ignore").strip ()
            out ={"Raw":hex_str }
            if full_name :
                out ["Full Name"]=full_name 
            if short_name :
                out ["Short Name"]=short_name 
            return out 
        except Exception :
            return {"PNN (Raw)":hex_str }

    @staticmethod 
    def decode_opl (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<8 :
                return {"OPL (Raw)":hex_str }
            plmn =ContentDecoder ._decode_plmn_bytes (data [0 :3 ])
            lac1 =int .from_bytes (data [3 :5 ],"big")
            lac2 =int .from_bytes (data [5 :7 ],"big")
            pnn_id =data [7 ]
            return {
            "PLMN":plmn ,
            "LAC Start":f"{lac1:04X}",
            "LAC End":f"{lac2:04X}",
            "PNN Record Identifier":pnn_id 
            }
        except Exception :
            return {"OPL (Raw)":hex_str }

    @staticmethod 
    def decode_spdi (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            plmn_list =[]
            a3 =TlvParser .get_first (parsed ,0xA3 )
            if isinstance (a3 ,bytes ):
                a3 =TlvParser .parse (a3 )
            sp_list =TlvParser .get_first (a3 ,0x80 )
            if isinstance (sp_list ,bytes ):
                for i in range (0 ,len (sp_list ),3 ):
                    chunk =sp_list [i :i +3 ]
                    if len (chunk )<3 :
                        break 
                    if chunk ==b"\xFF\xFF\xFF":
                        continue 
                    plmn_list .append (ContentDecoder ._decode_plmn_bytes (chunk ))
            return {"Service Provider PLMN List":plmn_list ,"Raw":hex_str }
        except Exception :
            return {"SPDI (Raw)":hex_str }

    @staticmethod 
    def decode_epsnsc (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            out ={"Raw":hex_str }
            if len (data )>0 :
                out ["KSI / Header"]=f"{data[0]:02X}"
            if len (data )>=17 :
                out ["KASME (first 16 bytes)"]=data [1 :17 ].hex ().upper ()
            if len (data )>17 :
                out ["Remainder"]=data [17 :].hex ().upper ()
            return out 
        except Exception :
            return {"EPSNSC (Raw)":hex_str }

    @staticmethod 
    def decode_gbanl (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            naf =TlvParser .get_first (parsed ,0x80 )
            b_tid =TlvParser .get_first (parsed ,0x81 )
            out ={"Raw":hex_str }
            if isinstance (naf ,bytes ):
                out ["NAF_ID"]=naf .hex ().upper ()
            if isinstance (b_tid ,bytes ):
                out ["B-TID"]=b_tid .hex ().upper ()
            return out 
        except Exception :
            return {"GBANL (Raw)":hex_str }

    @staticmethod 
    def decode_nafkca (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            val =TlvParser .get_first (parsed ,0x80 )
            if isinstance (val ,bytes ):
                return {
                "NAF Key Centre Address":val .decode ("utf-8","ignore").strip (),
                "Raw":hex_str 
                }
            return {"NAFKCA (Raw)":hex_str }
        except Exception :
            return {"NAFKCA (Raw)":hex_str }

    @staticmethod 
    def decode_isim_tlv80_text (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            val =TlvParser .get_first (parsed ,0x80 )
            if isinstance (val ,bytes ):
                text =val .decode ("utf-8","ignore").strip ()
                return {"Value":text ,"Raw Value":val .hex ().upper ()}
            return {"ISIM (Raw)":hex_str }
        except Exception :
            return {"ISIM (Raw)":hex_str }

    @staticmethod 
    def decode_isim_ist (hex_str :str )->dict :
        # 3GPP TS 31.103 §4.2.7 — ISIM Service Table. Mirrors the UST
        # split so operators see active *and* not-set services in the
        # decoded view.
        try :
            data =bytes .fromhex (hex_str )
        except Exception :
            return {"service_table":True ,"table":"IST","error":"IST (Raw)",
            "raw":hex_str ,"active":[],"inactive":[]}

        service_map ={
        1 :"P-CSCF address",
        2 :"GBA",
        3 :"HTTP Digest",
        4 :"GBA-based Local Key Establishment",
        5 :"P-CSCF discovery for IMS Local Break Out",
        6 :"SMS",
        7 :"SMSR",
        8 :"SM-over-IP via SMS-PP",
        9 :"Communication Control for IMS",
        10 :"UICC access to IMS",
        11 :"URI support by UICC",
        12 :"Media Type support",
        13 :"IMS call disconnection cause",
        14 :"URI support for MO SMS CONTROL",
        15 :"Mission Critical Services",
        16 :"URI support for SMS-PP DOWNLOAD",
        17 :"From Preferred",
        18 :"IMS configuration data",
        19 :"XCAP configuration data",
        20 :"WebRTC URI",
        21 :"MuD/MiD configuration data",
        }
        return AdvancedDecoders ._build_service_table (
            data ,
            name_map =service_map ,
            table_name ="IST",
            full_name ="ISIM Service Table",
            spec ="3GPP TS 31.103 \u00a74.2.7",
            )

    @staticmethod 
    def decode_isim_pcscf (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            t80 =TlvParser .get_first (parsed ,0x80 )
            if isinstance (t80 ,bytes )and len (t80 )>1 :
                addr_type =t80 [0 ]
                addr_raw =t80 [1 :]
                addr_type_map ={0x00 :"FQDN",0x01 :"IPv4",0x02 :"IPv6"}
                addr_text =addr_raw .decode ("utf-8","ignore").strip ()if addr_type ==0x00 else addr_raw .hex ().upper ()
                return {
                "Address Type":addr_type_map .get (addr_type ,f"0x{addr_type:02X}"),
                "Address":addr_text 
                }
            return {"P-CSCF (Raw)":hex_str }
        except Exception :
            return {"P-CSCF (Raw)":hex_str }

    @staticmethod 
    def decode_tlv_as_map (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse (data )
            return {"TLV":ContentDecoder ._tlv_to_obj (parsed )}
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def _tlv_to_obj (node :Any )->Any :
        if isinstance (node ,dict ):
            out ={}
            for k ,v in node .items ():
                out [f"{k:02X}"if isinstance (k ,int )else str (k )]=ContentDecoder ._tlv_to_obj (v )
            return out 
        if isinstance (node ,list ):
            return [ContentDecoder ._tlv_to_obj (v )for v in node ]
        if isinstance (node ,bytes ):
            return node .hex ().upper ()
        return node 

    @staticmethod 
    def decode_utf8_or_hex (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            return {"Text":data .decode ("utf-8","ignore").strip (),"Raw":hex_str }
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_hex_chunks (hex_str :str )->dict :
        return {"Raw":hex_str }

    @staticmethod 
    def _strip_ff_padding (data :bytes )->bytes :
        out =data 
        while len (out )>0 and out [-1 ]==0xFF :
            out =out [:-1 ]
        return out 

    @staticmethod 
    def _json_lines (title :str ,obj :Dict [str ,Any ])->List [str ]:
        lines =[f"{title}"]
        payload =json .dumps (obj ,indent =2 ,ensure_ascii =True )
        for line in payload .splitlines ():
            lines .append (line )
        return lines 

    @staticmethod 
    def _pkcs15_json_lines (file_id :str ,body :Dict [str ,Any ])->List [str ]:
        title =f"PKCS#15 {file_id} (JSON):"
        payload ={
        "schema":"pkcs15_decoder.v1",
        "file_id":file_id ,
        "body":body ,
        }
        return ContentDecoder ._json_lines (title ,payload )

    @staticmethod 
    def _collect_octets (node :Any )->List [bytes ]:
        out :List [bytes ]=[]
        if isinstance (node ,dict ):
            for k ,v in node .items ():
                if k ==0x04 :
                    if isinstance (v ,bytes ):
                        out .append (v )
                    if isinstance (v ,list ):
                        for item in v :
                            if isinstance (item ,bytes ):
                                out .append (item )
                out .extend (ContentDecoder ._collect_octets (v ))
            return out 
        if isinstance (node ,list ):
            for item in node :
                out .extend (ContentDecoder ._collect_octets (item ))
        return out 

    @staticmethod 
    def decode_pkcs15_odf (hex_str :str )->list :
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ODF: Hex Decode Error"]
        raw =ContentDecoder ._strip_ff_padding (raw )
        if len (raw )==0 :
            return ["PKCS15 ODF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ODF: TLV Parse Error"]
        odf_tag_map ={
        0xA0 :"private_keys",
        0xA1 :"public_keys",
        0xA4 :"certificates",
        0xA5 :"authentication_objects",
        0xA7 :"data_objects",
        0xA8 :"auth_keys",
        0xA9 :"trust_points",
        }
        objects =[]
        if isinstance (parsed ,dict ):
            for tag ,val in parsed .items ():
                entry_type =odf_tag_map .get (tag ,f"tag_{tag:02X}")
                octets =ContentDecoder ._collect_octets (val )
                paths =[]
                refs =[]
                for octet in octets :
                    if len (octet )==2 :
                        paths .append (octet .hex ().upper ())
                    else :
                        refs .append (octet .hex ().upper ())
                objects .append ({
                "entry_type":entry_type ,
                "paths":paths ,
                "references":refs ,
                })
        body ={"objects":objects }
        return ContentDecoder ._pkcs15_json_lines ("ODF",body )

    @staticmethod 
    def decode_pkcs15_dodf (hex_str :str )->list :
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 DODF: Hex Decode Error"]
        raw =ContentDecoder ._strip_ff_padding (raw )
        if len (raw )==0 :
            return ["PKCS15 DODF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 DODF: TLV Parse Error"]
        def _collect_tag_values (node :Any ,tag :int )->List [bytes ]:
            values :List [bytes ]=[]
            if isinstance (node ,dict ):
                for k ,v in node .items ():
                    if k ==tag :
                        if isinstance (v ,bytes ):
                            values .append (v )
                        if isinstance (v ,list ):
                            for item in v :
                                if isinstance (item ,bytes ):
                                    values .append (item )
                    values .extend (_collect_tag_values (v ,tag ))
                return values 
            if isinstance (node ,list ):
                for item in node :
                    values .extend (_collect_tag_values (item ,tag ))
            return values 

        label =""
        oid =""
        label_vals =_collect_tag_values (parsed ,0x0C )
        if len (label_vals )>0 :
            label =label_vals [0 ].decode ("utf-8","ignore").strip ()
        oid_vals =_collect_tag_values (parsed ,0x06 )
        if len (oid_vals )>0 :
            oid =oid_vals [0 ].hex ().upper ()
        octets =ContentDecoder ._collect_octets (parsed )
        paths :List [str ]=[]
        for octet in octets :
            if len (octet )==2 :
                p =octet .hex ().upper ()
                if p not in paths :
                    paths .append (p )

        entries =[]
        for p in paths :
            entries .append ({
            "label":label ,
            "oid_hex":oid ,
            "path":p ,
            })
        body ={"data_objects":entries }
        return ContentDecoder ._pkcs15_json_lines ("DODF",body )

    @staticmethod 
    def decode_pkcs15_acm (hex_str :str )->list :
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACM: Hex Decode Error"]
        raw =ContentDecoder ._strip_ff_padding (raw )
        if len (raw )==0 :
            return ["PKCS15 ACM: Empty/Invalid"]
        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ACM: TLV Parse Error"]
        octets =ContentDecoder ._collect_octets (parsed )
        acrf_path =""
        values =[]
        for octet in octets :
            h =octet .hex ().upper ()
            values .append (h )
            if len (octet )==2 and h =="4300":
                acrf_path =h 
        body ={
        "octet_strings":values ,
        "acrf_path":acrf_path ,
        }
        return ContentDecoder ._pkcs15_json_lines ("ACM",body )

    @staticmethod 
    def decode_pkcs15_acrf_json (hex_str :str )->list :
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACRF: Hex Decode Error"]
        raw =ContentDecoder ._strip_ff_padding (raw )
        if len (raw )==0 :
            return ["PKCS15 ACRF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ACRF: TLV Parse Error"]

        seq =TlvParser .get_first (parsed ,0x30 ,parsed )
        rules =[]

        def _collect_rules (node :Any )->None :
            if isinstance (node ,dict ):
                has_ref =False 
                if 0xA0 in node :
                    has_ref =True 
                if 0x30 in node :
                    has_ref =True 
                if has_ref :
                    rules .append (node )
                for v in node .values ():
                    _collect_rules (v )
                return 
            if isinstance (node ,list ):
                for item in node :
                    _collect_rules (item )

        _collect_rules (seq )
        entries =[]
        for idx ,rule in enumerate (rules ,start =1 ):
            aid_ref =""
            accf_ref =""
            ref_a0 =TlvParser .get_first (rule ,0xA0 )
            if isinstance (ref_a0 ,dict ):
                aid_oct =TlvParser .get_first (ref_a0 ,0x04 )
                if isinstance (aid_oct ,bytes ):
                    aid_ref =aid_oct .hex ().upper ()
            ref_30 =TlvParser .get_first (rule ,0x30 )
            if isinstance (ref_30 ,dict ):
                path_oct =TlvParser .get_first (ref_30 ,0x04 )
                if isinstance (path_oct ,bytes ):
                    accf_ref =path_oct .hex ().upper ()
            if isinstance (ref_30 ,bytes ):
                try :
                    parsed_30 =TlvParser .parse (ref_30 )
                    path_oct =TlvParser .get_first (parsed_30 ,0x04 )
                    if isinstance (path_oct ,bytes ):
                        accf_ref =path_oct .hex ().upper ()
                except Exception :
                    pass 
            entries .append ({
            "index":idx ,
            "aid_ref":aid_ref ,
            "accf_ref":accf_ref ,
            })

        body ={"rules":entries }
        return ContentDecoder ._pkcs15_json_lines ("ACRF",body )

    @staticmethod 
    def decode_pkcs15_accf_json (hex_str :str )->list :
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACCF: Hex Decode Error"]
        raw =ContentDecoder ._strip_ff_padding (raw )
        if len (raw )==0 :
            return ["PKCS15 ACCF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse (raw )
        except Exception :
            return ["PKCS15 ACCF: TLV Parse Error"]

        octets =ContentDecoder ._collect_octets (parsed )
        entries =[]
        for idx ,item in enumerate (octets ,start =1 ):
            algo ="raw"
            if len (item )==32 :
                algo ="sha256"
            if len (item )==20 :
                algo ="sha1"
            entries .append ({
            "index":idx ,
            "algo":algo ,
            "hash_hex":item .hex ().upper (),
            })
        body ={"entries":entries }
        return ContentDecoder ._pkcs15_json_lines ("ACCF",body )

    @staticmethod 
    def decode_5gs_loci (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            out ={"Raw":hex_str }
            if len (data )>=7 :
                out ["PLMN"]=ContentDecoder ._decode_plmn_bytes (data [0 :3 ])
                out ["TAI/TAC (raw)"]=data [3 :5 ].hex ().upper ()
                out ["5G-TMSI (part)"]=data [5 :9 ].hex ().upper ()
            return out 
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_5gs_nsc (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            out ={"Raw":hex_str }
            if len (data )>0 :
                out ["Security Header"]=f"{data[0]:02X}"
            if len (data )>1 :
                out ["Security Context Data"]=data [1 :].hex ().upper ()
            return out 
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_5gs_auth_keys (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            return {
            "Length":len (data ),
            "Auth Keys Blob":data .hex ().upper ()
            }
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_5gs_uac_aic (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"UAC_AIC":"Empty"}
            b =data [0 ]
            return {
            "Byte0":f"{b:02X}",
            "Bits Set":[bit for bit in range (8 )if b &(1 <<bit )],
            "Raw":hex_str 
            }
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_routing_indicator (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            digits =ContentDecoder ._decode_bcd_digits (data )
            return {"Routing Indicator":digits ,"Raw":hex_str }
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_5gs_sor_cmci (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"SOR-CMCI":"Empty"}
            return {
            "Control Byte":f"{data[0]:02X}",
            "Raw":hex_str 
            }
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_dri (hex_str :str )->dict :
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"DRI":"Empty"}
            return {"DRI":data .hex ().upper ()}
        except Exception :
            return {"Raw":hex_str }