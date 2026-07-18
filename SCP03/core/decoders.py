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

"""SCP03 response decoders: converts raw EF hex strings to structured Python dicts."""
import ipaddress
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

_GSM7_DEFAULT_ALPHABET =(
"@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
"\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\x1b\u00c6\u00e6\u00df\u00c9"
" !\"#\u00a4%&'()*+,-./"
"0123456789:;<=>?"
"\u00a1ABCDEFGHIJKLMNO"
"PQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7"
"\u00bfabcdefghijklmno"
"pqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)
_GSM7_EXTENSION_TABLE ={
0x0A :"\f",
0x14 :"^",
0x28 :"{",
0x29 :"}",
0x2F :"\\",
0x3C :"[",
0x3D :"~",
0x3E :"]",
0x40 :"|",
0x65 :"\u20ac",
}


def _decode_gsm7_septets (septets :Iterable [int ])->Optional [str ]:
    values =list (septets )
    output =[]
    index =0
    while index <len (values ):
        value =values [index ]
        if not 0 <=value <0x80 :
            return None
        if value ==0x1B :
            index +=1
            if index >=len (values ):
                return None
            extension =_GSM7_EXTENSION_TABLE .get (values [index ])
            if extension is None :
                return None
            output .append (extension )
        else :
            output .append (_GSM7_DEFAULT_ALPHABET [value ])
        index +=1
    return "".join (output )


def _decode_gsm7_packed (data :bytes ,spare_bits :int )->Optional [str ]:
    if spare_bits not in range (8 ):
        return None
    useful_bits =(len (data )*8 )-spare_bits
    if useful_bits <0 or useful_bits %7 !=0 :
        return None
    if spare_bits and data and data [-1 ]&(((1 <<spare_bits )-1 )<<(8 -spare_bits )):
        return None
    packed_value =int .from_bytes (data ,"little")
    septets =[
    (packed_value >>(index *7 ))&0x7F
    for index in range (useful_bits //7 )
    ]
    return _decode_gsm7_septets (septets )


def _decode_network_name_ie (value :bytes )->Dict [str ,Any ]:
    raw =bytes (value )
    if len (raw )==0 :
        return {"text":"","encoding":"empty","raw":""}
    header =raw [0 ]
    if (header &0x80 )==0 :
        try :
            text =raw .decode ("ascii")
        except UnicodeDecodeError :
            text =""
        if text and text .isprintable ():
            return {"text":text ,"encoding":"plain ASCII fallback","raw":raw .hex ().upper ()}
        return {
        "text":"",
        "encoding":"invalid Network Name IE (extension bit not set)",
        "raw":raw .hex ().upper (),
        }
    # TS 24.008 encodes the network-name coding scheme in bits 7..5.
    # Bit 5 is significant: UCS-2 is coding scheme 001 (header 0x90 when
    # the country-initials flag and spare-bit count are both zero).
    coding_scheme =(header >>4 )&0x07
    add_country_initials =bool (header &0x08 )
    spare_bits =header &0x07
    payload =raw [1 :]
    output :Dict [str ,Any ]={
    "text":"",
    "coding_scheme":coding_scheme ,
    "add_country_initials":add_country_initials ,
    "spare_bits":spare_bits ,
    "raw":raw .hex ().upper (),
    }
    if coding_scheme ==0 :
        text =_decode_gsm7_packed (payload ,spare_bits )
        output ["encoding"]="GSM 7-bit packed"
        if text is None :
            output ["error"]="Invalid GSM 7-bit payload or spare-bit count"
        else :
            output ["text"]=text
        return output
    if coding_scheme ==1 :
        output ["encoding"]="UCS-2 big-endian"
        if spare_bits !=0 :
            output ["error"]="UCS-2 Network Name must have zero spare bits"
            return output
        if len (payload )%2 :
            output ["error"]="UCS-2 payload has an odd byte count"
            return output
        try :
            output ["text"]=payload .decode ("utf-16-be").rstrip ("\x00")
        except UnicodeDecodeError :
            output ["error"]="Invalid UCS-2 payload"
        return output
    output ["encoding"]=f"Reserved coding scheme ({coding_scheme})"
    return output


class AdvancedDecoders :
    @staticmethod 
    def decode_ef_arr (data_hex :str )->list :
        """Decode EF.ARR access rule records from raw hex (ETSI TS 102 221 §9.5.1).

        Walks AM/SC TLV pairs and returns a list of human-readable rule strings.
        """
        if not data_hex :
            return ["Empty/Invalid Rule"]
        if data_hex .startswith ('FF'):
            return ["Empty/Invalid Rule"]

        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return ["Hex Decode Error"]
        try :
            TlvParser .parse_padded (data )
        except ValueError as exc :
            return [f"ARR TLV Parse Error: {exc}"]

        def _items (raw :bytes ):
            offset =0
            while offset <len (raw ):
                if all (octet ==0xFF for octet in raw [offset :]):
                    return
                tag_start =offset
                offset +=1
                if (raw [tag_start ]&0x1F )==0x1F :
                    while raw [offset ]&0x80 :
                        offset +=1
                    offset +=1
                tag =int .from_bytes (raw [tag_start :offset ],"big")
                first_length =raw [offset ]
                offset +=1
                if first_length <0x80 :
                    length =first_length
                else :
                    count =first_length &0x7F
                    length =int .from_bytes (raw [offset :offset +count ],"big")
                    offset +=count
                value =raw [offset :offset +length ]
                offset +=length
                yield tag ,value

        output =[]
        current_am_str =""

        def _auth_condition(value: bytes) -> str:
            sc_info = TlvParser.parse(value)
            key_ref = TlvParser.get_first(sc_info, 0x83)
            usage_qualifier = TlvParser.get_first(sc_info, 0x95)
            if usage_qualifier is not None and (
                not isinstance(usage_qualifier, bytes)
                or len(usage_qualifier) != 1
            ):
                raise ValueError(
                    "ARR authentication usage qualifier must contain one byte."
                )
            if isinstance(key_ref, bytes) and len(key_ref) == 1:
                ref_val = key_ref[0]
                if 0x01 <= ref_val <= 0x08:
                    if ref_val == 0x01:
                        return "PIN1 (Application PIN 1)"
                    return f"Application PIN {ref_val}"
                if ref_val == 0x11:
                    return "Universal PIN"
                if 0x81 <= ref_val <= 0x88:
                    app_number = ref_val - 0x80
                    if app_number == 1:
                        return "PIN2 (Application 1)"
                    return f"Second PIN (Application {app_number})"
                if 0x0A <= ref_val <= 0x0E:
                    return f"ADM{ref_val - 0x09}"
                if 0x8A <= ref_val <= 0x8E:
                    return f"ADM{ref_val - 0x84}"
                return f"KeyRef(0x{ref_val:02X})"
            if key_ref is not None:
                raise ValueError(
                    "ARR authentication key reference must contain one byte."
                )
            return "Unknown authentication condition"

        def _security_condition(tag: int, value: bytes, depth: int = 0) -> str:
            if depth > TlvParser.DEFAULT_MAX_DEPTH:
                raise ValueError("ARR security-condition nesting is too deep.")
            if tag == 0x90:
                if value:
                    raise ValueError("ARR tag 90 must have zero length.")
                return "Always"
            if tag == 0x97:
                if value:
                    raise ValueError("ARR tag 97 must have zero length.")
                return "Never"
            if tag == 0xA4:
                return _auth_condition(value)
            operators = {0xA0: "OR", 0xA7: "NOT", 0xAF: "AND"}
            operator = operators.get(tag)
            if operator is not None:
                children = [
                    _security_condition(child_tag, child_value, depth + 1)
                    for child_tag, child_value in _items(value)
                ]
                if operator == "NOT" and len(children) != 1:
                    raise ValueError("ARR NOT condition must contain exactly one child.")
                if operator in ("OR", "AND") and len(children) < 2:
                    raise ValueError(
                        f"ARR {operator} condition must contain at least two children."
                    )
                if operator == "NOT":
                    return f"NOT ({children[0]})"
                return f"{operator} ({', '.join(children)})"
            return f"SC-DO {tag:X} ({value.hex().upper()})"

        for tag ,value in _items (data ):
            if tag ==0x80 :
                if len (value )!=1 :
                    return ["ARR Decode Error: access-mode DO must contain one byte"]
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
                current_am_str ="/".join (modes )if modes else f"Proprietary(0x{am_byte:02X})"
                continue

            if tag ==0x84 :
                if not value:
                    return ["ARR Decode Error: command-header DO must not be empty"]
                known_commands ={0x32 :"INCREASE"}
                if len (value )==1 and value [0 ]in known_commands :
                    current_am_str =(
                    f"{known_commands[value[0]]} (command header {value.hex().upper()})"
                    )
                else :
                    current_am_str =f"Command header {value.hex().upper()}"
                continue

            if tag in (0x90, 0x97, 0xA4, 0xA0, 0xA7, 0xAF):
                if not current_am_str:
                    return [
                        f"ARR Decode Error: security condition {tag:X} "
                        "has no preceding access-mode DO"
                    ]
                try:
                    condition = _security_condition(tag, value)
                except ValueError as exc:
                    return [f"ARR Decode Error: {exc}"]
                output .append (f"{current_am_str}: {condition}")
                current_am_str =""
                continue

        if current_am_str:
            output.append(
                f"ARR Decode Warning: {current_am_str} has no security condition"
            )

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

        try :
            parsed =TlvParser .parse_padded (data )
        except ValueError as exc :
            return [f"GP_SEAC: TLV Parse Error: {exc}"]
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
                decoded =value .decode ("ascii")
                return decoded if decoded .isprintable ()else value .hex ().upper ()
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

        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ACRF: Empty/Invalid"]

        try :
            parsed =TlvParser .parse_padded (raw )
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

        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ACCF: Empty/Invalid"]

        try :
            parsed =TlvParser .parse_padded (raw )
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
    def decode_plmn_list (data_hex :str ,record_size :int =3 )->list :
        """Decode a PLMN list EF to a list of PLMN dicts (3GPP TS 31.102 §4.2.5).

        Each entry carries mcc, mnc, and optional Access Technology bitmask.
        """
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

        if record_size not in (3 ,5 ):
            return ["PLMN Decode Error: record size must be 3 or 5 bytes"]
        if len (data )%record_size !=0 :
            return [
            f"PLMN Decode Error: {len(data)} bytes is not a multiple "
            f"of the {record_size}-byte record size"
            ]

        entries =[]
        for i in range (0 ,len (data ),record_size ):

            plmn_bytes =data [i :i +3 ]
            if plmn_bytes ==b'\xFF\xFF\xFF':
                continue 

            b1 =plmn_bytes [0 ]
            b2 =plmn_bytes [1 ]
            b3 =plmn_bytes [2 ]

            mcc_digits =(b1 &0x0F ,b1 >>4 ,b2 &0x0F )
            mnc3 =b2 >>4
            mnc_digits =(b3 &0x0F ,b3 >>4 )
            if any (digit >9 for digit in mcc_digits +mnc_digits ):
                return [
                f"PLMN Decode Error: invalid BCD digit in record {i // record_size + 1}"
                ]
            if mnc3 >9 and mnc3 !=0x0F :
                return [
                f"PLMN Decode Error: invalid MNC digit in record {i // record_size + 1}"
                ]

            mcc ="".join (str (digit )for digit in mcc_digits )
            mnc ="".join (str (digit )for digit in mnc_digits )
            if mnc3 !=0x0F :
                mnc =f"{mnc3}{mnc}"

            entry_str =f"MCC: {mcc}, MNC: {mnc}"

            if record_size ==5 :
                act_bytes =int .from_bytes (data [i +3 :i +5 ],'big')
                acts =[]
                if act_bytes &0x8000 :
                    acts .append ("UTRAN")
                eutran_bits =act_bytes &0x7000
                if eutran_bits in (0x4000 ,0x7000 ):
                    acts .extend (["E-UTRAN WB-S1","E-UTRAN NB-S1"])
                elif eutran_bits ==0x5000 :
                    acts .append ("E-UTRAN NB-S1")
                elif eutran_bits ==0x6000 :
                    acts .append ("E-UTRAN WB-S1")
                gsm_bits =act_bytes &0x008C
                if gsm_bits in (0x0080 ,0x008C ):
                    acts .extend (["GSM","EC-GSM-IoT"])
                elif gsm_bits ==0x0084 :
                    acts .append ("GSM")
                elif gsm_bits ==0x0088 :
                    acts .append ("EC-GSM-IoT")
                if act_bytes &0x0040 :
                    acts .append ("GSM COMPACT")
                if act_bytes &0x0020 :
                    acts .append ("cdma2000 HRPD")
                if act_bytes &0x0010 :
                    acts .append ("cdma2000 1xRTT")
                if act_bytes &0x0800 :
                    acts .append ("NG-RAN")
                if act_bytes &0x0400 :
                    acts .append ("Satellite NG-RAN")
                if act_bytes &0x0200 :
                    acts .append ("Satellite E-UTRAN WB-S1")
                if act_bytes &0x0100 :
                    acts .append ("Satellite E-UTRAN NB-S1")

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
        """Decode EF.LOCI: Location Information (3GPP TS 31.102 §4.2.17).

        Returns TMSI, LAI components, update-status, and raw hex fallback.
        """
        try :
            data =bytes .fromhex (data_hex )
        except Exception :
            return {"Error":"LOCI Decode Error"}

        if len (data )!=11 :
            return {"Error":f"Invalid LOCI Length ({len(data)})"}

        try:
            tmsi_raw = data[0:4]
            plmn_raw = data[4:7]
            plmn = "Not assigned"
            if plmn_raw != b"\xFF\xFF\xFF":
                plmn = ContentDecoder._decode_plmn_bytes(plmn_raw)
                if plmn.startswith("Invalid"):
                    return {"Error": "LOCI contains an invalid PLMN BCD digit"}

            lac = int.from_bytes(data[7:9], "big")
            status_byte = data[10]
            status_value = status_byte & 0x07
            status_map = {
                0: "Updated",
                1: "Not Updated",
                2: "PLMN Not Allowed",
                3: "Location Area Not Allowed",
            }
            output = {
                "TMSI": tmsi_raw.hex().upper(),
                "TMSI Assigned": tmsi_raw != b"\xFF\xFF\xFF\xFF",
                "LAI": plmn,
                "LAC": lac,
                "RFU Byte": f"{data[9]:02X}",
                "Status": status_map.get(
                    status_value,
                    f"Reserved ({status_value})",
                ),
                "Status Byte": f"{status_byte:02X}",
            }
            warnings = []
            if data[9] != 0xFF:
                warnings.append("LOCI RFU byte is not FF")
            if status_byte & 0xF8:
                warnings.append("LOCI update-status RFU bits 4..8 are non-zero")
            if warnings:
                output["Warnings"] = warnings
            return output
        except Exception:
            return {"Error": "LOCI Decode Error"}

    @staticmethod
    def decode_psloci(data_hex: str) -> dict:
        """Decode the 14-byte EF.PSLOCI layout (3GPP TS 31.102 §4.2.23)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {"Error": "PSLOCI Hex Decode Error"}
        if len(data) != 14:
            return {"Error": f"Invalid PSLOCI Length ({len(data)}; expected 14)"}
        plmn_raw = data[7:10]
        plmn = "Not assigned"
        if plmn_raw != b"\xFF\xFF\xFF":
            plmn = ContentDecoder._decode_plmn_bytes(plmn_raw)
            if plmn.startswith("Invalid"):
                return {"Error": plmn}
        status_byte = data[13]
        status_value = status_byte & 0x07
        status = {
            0: "Updated",
            1: "Not Updated",
            2: "PLMN Not Allowed",
            3: "Routing Area Not Allowed",
        }.get(status_value, f"Reserved ({status_value})")
        output = {
            "P-TMSI": data[0:4].hex().upper(),
            "P-TMSI Assigned": data[0:4] != b"\xFF\xFF\xFF\xFF",
            "P-TMSI Signature": data[4:7].hex().upper(),
            "RAI": {
                "PLMN": plmn,
                "LAC": f"{int.from_bytes(data[10:12], 'big'):04X}",
                "RAC": f"{data[12]:02X}",
            },
            "Status": status,
            "Status Byte": f"{status_byte:02X}",
        }
        if status_byte & 0xF8:
            output["Warning"] = "PSLOCI update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod
    def decode_epsloci(data_hex: str) -> dict:
        """Decode the 18-byte EF.EPSLOCI layout (3GPP TS 31.102 §4.2.91)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {"Error": "EPSLOCI Hex Decode Error"}
        if len(data) != 18:
            return {"Error": f"Invalid EPSLOCI Length ({len(data)}; expected 18)"}

        guti_raw = data[:12]
        guti_assigned = not all(octet == 0xFF for octet in guti_raw)
        guti_plmn = "Not assigned"
        if guti_assigned:
            if data[0] != 0x0B:
                return {
                    "Error": (
                        "EPSLOCI GUTI length octet is "
                        f"{data[0]:02X}; expected 0B"
                    )
                }
            if data[1] != 0xF6:
                return {
                    "Error": (
                        "EPSLOCI GUTI identity header is "
                        f"{data[1]:02X}; expected F6"
                    )
                }
            guti_plmn = ContentDecoder._decode_plmn_bytes(data[2:5])
            if guti_plmn.startswith("Invalid"):
                return {"Error": "EPSLOCI GUTI contains an invalid PLMN BCD digit"}

        tai_plmn = "Not assigned"
        if data[12:15] != b"\xFF\xFF\xFF":
            tai_plmn = ContentDecoder._decode_plmn_bytes(data[12:15])
            if tai_plmn.startswith("Invalid"):
                return {"Error": "EPSLOCI TAI contains an invalid PLMN BCD digit"}

        status_value = data[17] & 0x07
        status = {
            0: "Updated",
            1: "Not Updated",
            2: "Roaming Not Allowed",
        }.get(status_value, f"Reserved ({status_value})")
        output = {
            "GUTI": {
                "Assigned": guti_assigned,
                "Length Octet": f"{data[0]:02X}",
                "Identity Header": f"{data[1]:02X}",
                "PLMN": guti_plmn,
                "MME Group ID": data[5:7].hex().upper(),
                "MME Code": f"{data[7]:02X}",
                "M-TMSI": data[8:12].hex().upper(),
            },
            "Last Visited TAI": {
                "PLMN": tai_plmn,
                "TAC": data[15:17].hex().upper(),
            },
            "Status": status,
            "Status Byte": f"{data[17]:02X}",
        }
        if data[17] & 0xF8:
            output["Warning"] = "EPS update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod 
    def decode_ust (data_hex :str )->dict :
        """Decode EF.UST: USIM Service Table bitfield (3GPP TS 31.102 §4.2.8).

        Splits bits into active and not-set service lists; includes all 256 possible
        service numbers so the GUI can render a complete checklist.
        """
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
            # TS 31.102 §4.2.8. Keep the assigned service number intact:
            # these bits are frequently used to decide whether a dependent EF
            # is valid, so an off-by-one label is operationally misleading.
            ust_map = {
                1: "Local Phone Book",
                2: "FDN",
                3: "Extension 2",
                4: "Service Dialling Numbers (SDN)",
                5: "Extension 3",
                6: "Barred Dialling Numbers (BDN)",
                7: "Extension 4",
                8: "Outgoing Call Information (OCI and OCT)",
                9: "Incoming Call Information (ICI and ICT)",
                10: "Short Message Storage (SMS)",
                11: "Short Message Status Reports (SMSR)",
                12: "Short Message Service Parameters (SMSP)",
                13: "Advice of Charge (AoC)",
                14: "Capability Configuration Parameters 2 (CCP2)",
                15: "Cell Broadcast Message Identifier",
                16: "Cell Broadcast Message Identifier Ranges",
                17: "Group Identifier Level 1",
                18: "Group Identifier Level 2",
                19: "Service Provider Name",
                20: "User controlled PLMN selector with Access Technology",
                21: "MSISDN",
                22: "Image (IMG)",
                23: "Localised Service Areas (SoLSA)",
                24: "Enhanced Multi-Level Precedence and Pre-emption",
                25: "Automatic Answer for eMLPP",
                26: "RFU",
                27: "GSM Access",
                28: "Data download via SMS-PP",
                29: "Data download via SMS-CB",
                30: "Call Control by USIM",
                31: "MO-SMS Control by USIM",
                32: "RUN AT COMMAND",
                33: "Reserved (shall be set)",
                34: "Enabled Services Table",
                35: "APN Control List (ACL)",
                36: "Depersonalisation Control Keys",
                37: "Co-operative Network List",
                38: "GSM security context",
                39: "CPBCCH Information",
                40: "Investigation Scan",
                41: "MexE",
                42: "Operator controlled PLMN selector with Access Technology",
                43: "HPLMN selector with Access Technology",
                44: "Extension 5",
                45: "PLMN Network Name",
                46: "Operator PLMN List",
                47: "Mailbox Dialling Numbers",
                48: "Message Waiting Indication Status",
                49: "Call Forwarding Indication Status",
                50: "Reserved (ignore)",
                51: "Service Provider Display Information",
                52: "Multimedia Messaging Service (MMS)",
                53: "Extension 8",
                54: "Call control on GPRS by USIM",
                55: "MMS User Connectivity Parameters",
                56: "Network indication of alerting (NIA)",
                57: "VGCS Group Identifier List",
                58: "VBS Group Identifier List",
                59: "Pseudonym",
                60: "User controlled PLMN selector for I-WLAN",
                61: "Operator controlled PLMN selector for I-WLAN",
                62: "User controlled WSID list",
                63: "Operator controlled WSID list",
                64: "VGCS security",
                65: "VBS security",
                66: "WLAN Reauthentication Identity",
                67: "Multimedia Messages Storage",
                68: "Generic Bootstrapping Architecture (GBA)",
                69: "MBMS security",
                70: "Data download via USSD and USSD application mode",
                71: "Equivalent HPLMN",
                72: "Additional TERMINAL PROFILE after UICC activation",
                73: "Equivalent HPLMN Presentation Indication",
                74: "Last RPLMN Selection Indication",
                75: "OMA BCAST Smart Card Profile",
                76: "GBA-based Local Key Establishment",
                77: "Terminal Applications",
                78: "Service Provider Name Icon",
                79: "PLMN Network Name Icon",
                80: "Connectivity Parameters for USIM IP connections",
                81: "Home I-WLAN Specific Identifier List",
                82: "I-WLAN Equivalent HPLMN Presentation Indication",
                83: "I-WLAN HPLMN Priority Indication",
                84: "I-WLAN Last Registered PLMN",
                85: "EPS Mobility Management Information",
                86: "Allowed CSG Lists and indications",
                87: "Call control on EPS PDN connection by USIM",
                88: "HPLMN Direct Access",
                89: "eCall Data",
                90: "Operator CSG Lists and indications",
                91: "SM-over-IP",
                92: "CSG Display Control",
                93: "Communication Control for IMS by USIM",
                94: "Extended Terminal Applications",
                95: "UICC access to IMS",
                96: "NAS configuration by USIM",
                97: "PWS configuration by USIM",
                98: "RFU",
                99: "URI support by UICC",
                100: "Extended EARFCN support",
                101: "ProSe",
                102: "USAT Application Pairing",
                103: "Media Type support",
                104: "IMS call disconnection cause",
                105: "URI support for MO SHORT MESSAGE CONTROL",
                106: "ePDG configuration information support",
                107: "ePDG configuration information configured",
                108: "ACDC support",
                109: "Mission Critical Services",
                110: "Emergency ePDG configuration support",
                111: "Emergency ePDG configuration configured",
                112: "eCall Data over IMS",
                113: "URI support for SMS-PP DOWNLOAD",
                114: "From Preferred",
                115: "IMS configuration data",
                116: "TV configuration",
                117: "3GPP PS Data Off",
                118: "3GPP PS Data Off Service List",
                119: "V2X",
                120: "XCAP Configuration Data",
                121: "EARFCN list for MTC/NB-IoT UEs",
                122: "5GS Mobility Management Information",
                123: "5G Security Parameters",
                124: "Subscription identifier privacy support",
                125: "SUCI calculation by the USIM",
                126: "UAC Access Identities support",
                127: "Control-plane steering of UE in VPLMN",
                128: "Call control on PDU Session by USIM",
                129: "5GS Operator PLMN List",
                130: "SUPI of type NSI, GLI, or GCI",
                131: "Separate Home/Roaming 3GPP PS Data Off lists",
                132: "URSP by USIM",
                133: "5G Security Parameters extended",
                134: "MuD and MiD configuration data",
                135: "Trusted non-3GPP access networks by USIM",
                136: "Multiple NAS security-context records",
                137: "Pre-configured CAG information list",
                138: "SOR-CMCI storage in USIM",
                139: "5G ProSe",
                140: "Disaster roaming information in USIM",
                141: "Pre-configured eDRX parameters",
                142: "5G NSWO support",
                143: "PWS configuration for SNPN in USIM",
                144: "Higher-priority PLMN multiplier for satellite NG-RAN",
                145: "KAUSF derivation configuration",
                146: "Network Identifier for SNPN (NID)",
                147: "5MBS UE pre-configuration",
                148: "Operator-controlled signal threshold per access technology",
                149: "A2X",
                150: "IMS Data Channel Indication",
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

    @staticmethod
    def decode_est(data_hex: str) -> dict:
        """Decode EF.EST: Enabled Services Table (3GPP TS 31.102 §4.2.47)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {
                "service_table": True,
                "table": "EST",
                "error": "EST Decode Error",
                "active": [],
                "inactive": [],
            }
        if not data:
            return {
                "service_table": True,
                "table": "EST",
                "error": "Empty",
                "active": [],
                "inactive": [],
            }
        service_map = {
            1: "Fixed Dialling Numbers (FDN)",
            2: "Barred Dialling Numbers (BDN)",
            3: "APN Control List (ACL)",
        }
        result = AdvancedDecoders._build_service_table(
            data,
            name_map=service_map,
            table_name="EST",
            full_name="Enabled Services Table",
            spec="3GPP TS 31.102 §4.2.47",
        )
        if any(data[1:]) or data[0] & 0xF8:
            result["Warning"] = "EF.EST has non-zero unassigned service bits"
        return result

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
        """Re-encode a service-table bitfield from an iterable of active bit positions.

        Uses *current_hex* to preserve the existing byte width when possible;
        falls back to *total_bytes* or the minimum width that covers all set bits.
        """
        # Resolve the EF body length. ``total_bytes`` wins; otherwise
        # we infer it from the current hex (so callers staging an edit
        # on an existing EF can omit it). When neither is present we
        # auto-size to fit the highest set bit, which is the right
        # default for a fresh from-scratch encode.
        if total_bytes is not None :
            if isinstance (total_bytes ,bool )or not isinstance (total_bytes ,int ):
                raise TypeError ("total_bytes must be an integer.")
            if not 1 <=total_bytes <=0xFFFF :
                raise ValueError ("total_bytes must be in range 1..65535.")
        if total_bytes is None and current_hex is not None :
            cleaned =str (current_hex or "").replace (" ","").replace (":","")
            try :
                current_bytes =bytes .fromhex (cleaned )
            except ValueError as exc :
                raise ValueError (f"current_hex is not valid hexadecimal: {exc}")from exc
            if len (current_bytes )==0 :
                raise ValueError ("current_hex must contain at least one byte.")
            total_bytes =len (current_bytes )
        if isinstance (active_bits ,(str ,bytes ,bytearray ,memoryview )):
            raise TypeError ("active_bits must be an iterable of integer service numbers.")
        normalized_bits =set ()
        for raw_number in active_bits :
            if isinstance (raw_number ,bool )or not isinstance (raw_number ,int ):
                raise TypeError ("Service numbers must be positive integers.")
            service_number =raw_number
            if service_number <1 :
                raise ValueError ("Service numbers must be at least 1.")
            if service_number >0xFFFF *8 :
                raise ValueError ("Service number exceeds the maximum EF size.")
            normalized_bits .add (service_number )
        bits =sorted (normalized_bits )
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
        """Populate the FID-to-decoder dispatch table on first access.

        Maps every supported elementary-file FID (string, upper-case) to the
        corresponding static decoder method on this class.
        """
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
        '6F08':cls .decode_sensitive_blob ,
        '6F78':cls .decode_acc ,
        '6F31':lambda x :{"HPPLMN Search Interval":int (x ,16 )},
        '6F38':AdvancedDecoders .decode_ust ,
        '6F40':cls .decode_msisdn ,
        '6F46':cls .decode_spn ,
        '6F7B':AdvancedDecoders .decode_plmn_list ,
        '6F60':lambda x :AdvancedDecoders .decode_plmn_list (x ,record_size =5 ),
        '6F61':lambda x :AdvancedDecoders .decode_plmn_list (x ,record_size =5 ),
        '6F62':lambda x :AdvancedDecoders .decode_plmn_list (x ,record_size =5 ),
        '6FD9':AdvancedDecoders .decode_plmn_list ,
        '6F7E':AdvancedDecoders .decode_loci ,
        '6F73':AdvancedDecoders .decode_psloci ,
        '6FE3':AdvancedDecoders .decode_epsloci ,
        '6F42':cls .decode_sms_params ,
        '6F3C':cls .decode_sms_record ,
        '6F5B':lambda x :{"START-HFN":x },
        '6F5C':lambda x :{"Threshold":x },
        '6F05':lambda x :{"LI":x },
        '6F37':lambda x :{"ACM Max":x },
        '6F39':lambda x :{"ACM":x },
        '6F3E':lambda x :{"GID1":x },
        '6F3F':lambda x :{"GID2":x },
        '6F56':AdvancedDecoders .decode_est ,
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

        # The legacy SIM EF.ECC under DF.GSM is transparent and consists of
        # consecutive three-byte codes. The USIM EF with the same FID is
        # linear-fixed and each record also carries alpha/category fields.
        cls ._registry ['GSM/6FB7']=cls .decode_ecc_legacy


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
        cls ._registry ['5GS/4F08']=cls .decode_opl5g
        cls ._registry ['5GS/4F09']=cls .decode_isim_tlv80_text
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
    def _decode_bcd_digits(data: bytes, *, allow_dial_symbols: bool = True) -> str:
        """Decode telephony BCD, accepting filler only at the encoded tail."""
        symbols = {0x0A: "*", 0x0B: "#", 0x0C: "a", 0x0D: "b", 0x0E: "c"}
        output: List[str] = []
        for index, byte_value in enumerate(data):
            if byte_value == 0xFF:
                if any(item != 0xFF for item in data[index:]):
                    raise ValueError("BCD filler appears before non-padding data.")
                break
            low = byte_value & 0x0F
            high = (byte_value >> 4) & 0x0F
            if low <= 9:
                output.append(str(low))
            elif allow_dial_symbols and low in symbols:
                output.append(symbols[low])
            else:
                raise ValueError(f"Invalid low BCD nibble 0x{low:X}.")
            if high == 0x0F:
                if any(item != 0xFF for item in data[index + 1 :]):
                    raise ValueError("BCD filler appears before non-padding data.")
                break
            if high <= 9:
                output.append(str(high))
            elif allow_dial_symbols and high in symbols:
                output.append(symbols[high])
            else:
                raise ValueError(f"Invalid high BCD nibble 0x{high:X}.")
        return "".join(output)

    @staticmethod 
    def _decode_plmn_bytes (
        plmn_bytes: bytes,
        *,
        allow_wildcard: bool = False,
    ) -> str:
        if len (plmn_bytes )!=3 :
            return f"Invalid PLMN length ({len(plmn_bytes)}; expected 3)"
        b1 =plmn_bytes [0 ]
        b2 =plmn_bytes [1 ]
        b3 =plmn_bytes [2 ]
        mcc_digits =(b1 &0x0F ,b1 >>4 ,b2 &0x0F )
        mnc3 =b2 >>4
        mnc_digits =(b3 &0x0F ,b3 >>4 )
        valid_digits = set(range(10))
        if allow_wildcard:
            valid_digits.add(0x0D)
        if any (digit not in valid_digits for digit in mcc_digits +mnc_digits ):
            return f"Invalid PLMN BCD ({plmn_bytes.hex().upper()})"
        if mnc3 not in valid_digits and mnc3 !=0x0F:
            return f"Invalid PLMN BCD ({plmn_bytes.hex().upper()})"
        render_digit = lambda digit: "*" if digit == 0x0D else str(digit)
        mcc = "".join(render_digit(digit) for digit in mcc_digits)
        mnc = "".join(render_digit(digit) for digit in mnc_digits)
        if mnc3 !=0x0F :
            mnc = f"{render_digit(mnc3)}{mnc}"
        return f"{mcc}-{mnc}"

    @staticmethod
    def _decode_alpha_identifier(data: bytes) -> tuple[str, str]:
        """Decode the common TS 102 221 alpha-identifier forms conservatively."""
        raw = bytes(data)
        if not raw or all(octet == 0xFF for octet in raw):
            return "", "empty"

        if raw[0] == 0x80:
            payload = raw[1:]
            # There is no character count in coding 0x80. Try the least
            # destructive interpretation first and remove only trailing FF
            # padding needed to obtain printable, well-formed UTF-16BE.
            max_padding = 0
            while (
                max_padding < len(payload)
                and payload[len(payload) - 1 - max_padding] == 0xFF
            ):
                max_padding += 1
            for padding_length in range(max_padding + 1):
                end = len(payload) - padding_length
                candidate = payload[:end]
                if len(candidate) % 2:
                    continue
                try:
                    text = candidate.decode("utf-16-be")
                except UnicodeDecodeError:
                    continue
                if text == "" or text.isprintable():
                    return text, "UCS-2"
            return raw.hex().upper(), "invalid/non-printable UCS-2"

        if raw[0] in (0x81, 0x82):
            header_size = 3 if raw[0] == 0x81 else 4
            if len(raw) < header_size:
                return raw.hex().upper(), "truncated compressed UCS-2 header"
            character_count = raw[1]
            payload_end = header_size + character_count
            if payload_end > len(raw):
                return (
                    raw.hex().upper(),
                    "truncated compressed UCS-2 character data",
                )
            trailer = raw[payload_end:]
            if any(octet != 0xFF for octet in trailer):
                return (
                    raw.hex().upper(),
                    "invalid compressed UCS-2 trailing data",
                )
            if raw[0] == 0x81:
                base_pointer = (raw[2] & 0x7F) << 7
            else:
                base_pointer = int.from_bytes(raw[2:4], "big")

            output: List[str] = []
            for encoded in raw[header_size:payload_end]:
                if encoded & 0x80:
                    code_point = base_pointer + (encoded & 0x7F)
                    try:
                        output.append(chr(code_point))
                    except ValueError:
                        return raw.hex().upper(), "invalid compressed UCS-2 code point"
                    continue
                gsm_character = _decode_gsm7_septets([encoded])
                if gsm_character is None:
                    return (
                        raw.hex().upper(),
                        "invalid compressed UCS-2 GSM character",
                    )
                output.append(gsm_character)
            text = "".join(output)
            if text == "" or text.isprintable():
                return text, f"compressed UCS-2 (0x{raw[0]:02X})"
            return raw.hex().upper(), "compressed UCS-2 with non-printable characters"

        value = raw.rstrip(b"\xFF")
        text = _decode_gsm7_septets(value)
        if text is not None and text.isprintable():
            return text, "GSM default alphabet"
        return raw.hex().upper(), "GSM/default alphabet (raw)"

    @staticmethod 
    def decode_language_indicators (hex_str :str )->dict :
        """Decode EF.PL preferred-language pairs (ETSI TS 102 221 §13.1).

        Returns a list of ISO 639-1 two-character language codes.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )%2 !=0 :
                return {
                "Error":f"Language indicator length must be even; got {len(data)} bytes",
                "Raw":hex_str ,
                }
            langs =[]
            invalid =[]
            for i in range (0 ,len (data ),2 ):
                chunk =data [i :i +2 ]
                if chunk ==b"\xFF\xFF":
                    continue 
                try :
                    language =chunk .decode ("ascii")
                except UnicodeDecodeError :
                    invalid .append (chunk .hex ().upper ())
                    continue
                if language .isalpha ()==False :
                    invalid .append (chunk .hex ().upper ())
                    continue
                langs .append (language .lower ())
            result ={"Preferred Languages":langs ,"Raw":hex_str }
            if invalid :
                result ["Invalid Entries"]=invalid
            return result
        except Exception :
            return {"Preferred Languages (Raw)":hex_str }

    @staticmethod 
    def decode_service_table_bits (hex_str :str )->dict :
        """Decode a generic service-table EF to active / not-set service number lists.

        Used for EFs without a named-service map (e.g. EF.PSISMSC, V2X service tables).
        """
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
        """Decode EF.CBMI: Cell Broadcast Message Identifier list (3GPP TS 31.102 §4.2.14).

        Returns a list of 16-bit message identifier integers.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )%2 !=0 :
                return {
                "Error":f"CBMI length must be a multiple of 2 bytes; got {len(data)}",
                "Raw":hex_str ,
                }
            ids =[]
            for i in range (0 ,len (data ),2 ):
                chunk =data [i :i +2 ]
                if chunk ==b"\xFF\xFF":
                    continue 
                ids .append (int .from_bytes (chunk ,"big"))
            return {"Message Identifiers":ids ,"Raw":hex_str }
        except Exception :
            return {"CBMI (Raw)":hex_str }

    @staticmethod 
    def decode_cbmid_range_list (hex_str :str )->dict :
        """Decode EF.CBMIR: Cell Broadcast Message Identifier Range list (3GPP TS 31.102 §4.2.22).

        Returns a list of from/to range pairs.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )%4 !=0 :
                return {
                "Error":f"CBMID range length must be a multiple of 4 bytes; got {len(data)}",
                "Raw":hex_str ,
                }
            ranges =[]
            for i in range (0 ,len (data ),4 ):
                chunk =data [i :i +4 ]
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
        raw =str (context_path ).strip ().upper ().replace ("\\","/")
        if raw =="":
            return []
        parts =[p for p in raw .split ('/')if p ]
        out =[]
        for p in parts :
            value =p .strip ()
            if not value :
                continue
            out .append (value )
            normalized =value .replace ("_","." )
            if "."in normalized :
                leaf =normalized .rsplit (".",1 )[1 ]
                if leaf and leaf not in out :
                    out .append (leaf )
            for prefix in ("EF_","DF_","ADF_"):
                if value .startswith (prefix ):
                    leaf =value [len (prefix ):]
                    if leaf and leaf not in out :
                        out .append (leaf )
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
        """Decode EF.SPN: Service Provider Name (3GPP TS 31.102 §4.2.12).

        Returns display-condition byte and the TS 102 221 alpha identifier.
        """
        try :
            data =bytes .fromhex (hex_str )
        except ValueError :
            return {"Error":"SPN Hex Decode Error"}
        if len (data )<2 or all (octet ==0xFF for octet in data ):
            return {"Error":"Empty or truncated SPN"}
        display_condition =data [0 ]
        name ,encoding =ContentDecoder ._decode_alpha_identifier (data [1 :])
        output ={
        "SPN":name ,
        "Encoding":encoding ,
        "Display Condition":f"{display_condition:02X}",
        "Display Registered PLMN on HPLMN/SPDI PLMN":bool (
            display_condition &0x01
            ),
        "Display SPN outside HPLMN/SPDI PLMN":not bool (
            display_condition &0x02
            ),
        }
        warnings =[]
        if len (data )!=17 :
            warnings .append (f"EF.SPN is {len(data)} bytes; expected 17")
        if display_condition &0xFC :
            warnings .append ("EF.SPN display-condition RFU bits 3..8 are non-zero")
        if warnings :
            output ["Warnings"]=warnings
        return output

    @classmethod 
    def decode_raw (cls ,fid :str ,hex_data :str ,context_path :Optional [str ]=None )->Any :
        """Look up the decoder for *fid* and return its raw Python output.

        Returns ``None`` when no decoder is registered for the given FID.
        """
        if not fid :
            return None 
        fid_upper =str (fid ).strip ().upper ().replace (" ","")
        if fid_upper .startswith ("0X"):
            fid_upper =fid_upper [2 :]

        is_empty =False 
        if not cls ._registry :
            is_empty =True 
        if is_empty :
            cls .init_registry ()

        handler =cls ._resolve_handler (fid_upper ,context_path )
        if handler :
            try :
                return handler (hex_data )
            except Exception as exc :
                return {
                "Error":f"{fid_upper} decoder failed: {exc}",
                }
        return None 

    @classmethod 
    def decode (cls ,fid :str ,hex_data :str ,context_path :Optional [str ]=None )->Optional [str ]:
        """Decode *hex_data* for *fid* and return a JSON-serialisable string.

        Formats the raw decoder output as a pretty-printed JSON string;
        returns ``None`` when no decoder is registered.
        """
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
        """Decode *hex_data* for *fid* and return the raw Python dict or list.

        Returns ``None`` when no decoder is registered for *fid*.
        """
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
        """Decode EF.ACC: Access Control Class bitmask (3GPP TS 31.102 §4.2.15).

        Returns the 16-bit raw value and a list of class labels for each set bit.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )!=2 :
                return {"Error":f"Invalid ACC Length ({len(data)}; expected 2)"}
            val =int .from_bytes (data ,"big")
            classes =[]
            for i in range (16 ):
                if i !=10 and val &(1 <<i ):
                    classes .append (str (i ))
            output ={
            "Access Control Classes":classes ,
            "Raw":data .hex ().upper (),
            }
            if val &(1 <<10 ):
                output ["Warning"]="Reserved EF.ACC bit (byte 1, b3) is set"
            return output
        except Exception :
            return {"Error":"ACC Decode Error"}

    @staticmethod 
    def decode_dir (hex_str :str )->dict :
        """Decode EF.DIR: Application Directory records (ISO 7816-4 §8.3).

        Returns a list of AID hex strings; empty entries (all-FF) are skipped.
        """
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

            parsed =TlvParser .parse_padded (data )
            app_values =TlvParser .as_list (parsed .get (0x61 ))
            applications =[]
            for app in app_values :
                inner =app 
                if isinstance (app ,bytes ):
                    inner =TlvParser .parse (app )
                if isinstance (inner ,dict )==False :
                    continue
                aid_value =TlvParser .get_first (inner ,0x4F ,b"")
                label_value =TlvParser .get_first (inner ,0x50 ,b"")
                if isinstance (aid_value ,bytes )==False :
                    continue
                aid =aid_value .hex ().upper ()
                if len (aid_value )not in range (5 ,17 ):
                    applications .append ({
                    "AID":aid ,
                    "Error":f"Invalid AID length ({len(aid_value)}; expected 5..16)",
                    })
                    continue
                label =""
                if isinstance (label_value ,bytes ):
                    try :
                        decoded_label =label_value .decode ("utf-8")
                        label =decoded_label if decoded_label .isprintable ()else label_value .hex ().upper ()
                    except UnicodeDecodeError :
                        label =label_value .hex ().upper ()
                applications .append ({"AID":aid ,"Label":label })
            if applications :
                result ={"Applications":applications }
                if len (applications )==1 :
                    result .update (applications [0 ])
                return result

            return {"Raw DIR Data":hex_str }
        except Exception as e :
            return {"Error":f"DIR Decode Error: {e}"}

    @staticmethod 
    def decode_msisdn (hex_str :str )->dict :
        """Decode EF.MSISDN: Mobile Station ISDN Number record (3GPP TS 31.102 §4.2.26).

        Returns alphanumeric-tag, TON/NPI, dialling digits, and capability/extension.
        """
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
            alpha_encoding =""
            if alpha_len >0 :
                alpha_id ,alpha_encoding =ContentDecoder ._decode_alpha_identifier (
                    data [:alpha_len ]
                    )

            footer =data [alpha_len :]
            number_len =footer [0 ]
            if number_len ==0xFF :
                return {"Error":"Empty Record"}
            if number_len <1 or number_len >11 :
                return {"Error":f"Invalid BCD number length ({number_len})"}
            ton_npi =footer [1 ]
            bcd_octets =number_len -1
            dial_num =ContentDecoder ._decode_bcd_digits (footer [2 :2 +bcd_octets ])

            out_dict ={}
            if alpha_id !="":
                out_dict ["Alpha ID"]=alpha_id 
                out_dict ["Alpha ID Encoding"]=alpha_encoding
            out_dict ["Length of BCD Number"]=number_len
            out_dict ["Dialing Number"]=dial_num 
            out_dict ["TON/NPI"]=f"{ton_npi:02X}"
            ton =(ton_npi >>4 )&0x07
            npi =ton_npi &0x0F
            out_dict ["TON"]=ContentDecoder ._TON_LABELS .get (ton ,f"Reserved ({ton})")
            out_dict ["NPI"]=ContentDecoder ._NPI_LABELS .get (npi ,f"Reserved ({npi})")
            out_dict ["Capability/Configuration Identifier"]=f"{footer[12]:02X}"
            out_dict ["Extension Record ID"]=f"{footer[13]:02X}"
            return out_dict 
        except Exception as e :
            return {"Error":f"MSISDN Decode Error: {e}"}

    @staticmethod 
    def decode_iccid (hex_str :str )->dict :
        """Decode EF.ICCID: Integrated Circuit Card ID (ETSI TS 102 221 §13.2).

        Nibble-swaps each byte pair to recover the E.118 BCD-encoded serial number.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )!=10 :
                return {"Error":f"Invalid ICCID Length ({len(data)}; expected 10)"}
            digits =ContentDecoder ._decode_bcd_digits (
                data ,
                allow_dial_symbols =False ,
                )
            if len (digits )not in (19 ,20 ):
                return {"Error":f"Invalid ICCID digit count ({len(digits)})"}
            return {"iccid":digits ,"digit_count":len (digits )}
        except Exception as exc :
            return {"Error":f"ICCID Decode Error: {exc}"}

    @staticmethod 
    def decode_imsi (hex_str :str )->dict :
        """Decode EF.IMSI: International Mobile Subscriber Identity (3GPP TS 31.102 §4.2.2).

        The first byte after the length carries the parity / odd-even
        indicator in its low nibble and the first IMSI digit in its high
        nibble (see ``SIMCARD.utils.encode_imsi_ef``).  We pick the high
        nibble as the leading digit and drop the low (parity) nibble.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )!=9 :
                return {"Error":f"Invalid IMSI Length ({len(data)}; expected 9)"}
            if data [0 ]!=8 :
                return {"Error":f"Invalid IMSI length octet ({data[0]}; expected 8)"}
            identity =data [1 ]
            first_digit =(identity >>4 )&0x0F
            if first_digit >9 :
                return {"Error":"Invalid first IMSI digit"}
            type_bits =identity &0x07
            if type_bits !=0x01 :
                return {"Error":f"Invalid IMSI identity type ({type_bits})"}
            odd_digit_count =bool (identity &0x08 )
            remaining =ContentDecoder ._decode_bcd_digits (
                data [2 :] ,
                allow_dial_symbols =False ,
                )
            digits =str (first_digit )+remaining
            if len (digits )>15 :
                return {"Error":f"Invalid IMSI digit count ({len(digits)}; maximum 15)"}
            if bool (len (digits )%2 )!=odd_digit_count :
                return {"Error":"IMSI odd/even indicator does not match digit count"}
            return {
            "imsi":digits ,
            "digit_count":len (digits ),
            "odd_digit_count":odd_digit_count ,
            }
        except Exception as exc :
            return {"Error":f"IMSI Decode Error: {exc}"}

    @staticmethod 
    def decode_ad (hex_str :str )->dict :
        """Decode EF.AD: Administrative Data (3GPP TS 31.102 §4.2.18).

        Returns the administrative mode code, MNC length, and raw AD bytes.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<3 :
                return {"Error":f"Invalid AD Length ({len(data)}; expected at least 3)"}
            mode =data [0 ]
            m_map ={
            0x00 :"Normal operation",
            0x80 :"Type approval operation",
            0x01 :"Normal operation with specific facilities",
            0x81 :"Type approval operation with specific facilities",
            0x02 :"Maintenance (off-line)",
            0x04 :"Cell test operation",
            }
            mode_str =m_map .get (mode ,f"RFU (0x{mode:02X})")
            output ={
            "Administrative Mode":mode_str ,
            "Mode Byte":f"{mode:02X}",
            "Additional Information":data [1 :3 ].hex ().upper (),
            "Raw":data .hex ().upper (),
            }
            if mode &0x01 :
                feature_byte =data [2 ]
                output ["Specific Facilities"]={
                "Ciphering Indicator":bool (feature_byte &0x01 ),
                "Operator CSG Entries Only":bool (feature_byte &0x02 ),
                "ProSe Public Safety":bool (feature_byte &0x04 ),
                "Extended DRX UICC Deactivation":bool (feature_byte &0x08 ),
                "5G ProSe Operator-managed Resources":bool (feature_byte &0x10 ),
                }
            if len (data )>=4 :
                mnc_length =data [3 ]&0x0F
                output ["MNC Length"]=(
                mnc_length
                if mnc_length in (0 ,2 ,3 )
                else f"Reserved ({mnc_length})"
                )
                output ["MNC Length Byte"]=f"{data[3]:02X}"
            else :
                output ["Warning"]="Legacy three-byte EF.AD has no MNC-length field"
            if len (data )>4 :
                output ["Trailing RFU"]=data [4 :].hex ().upper ()
            return output
        except Exception :
            return {"Error":"AD Decode Error"}

    # TS 24.008 §10.5.4.7 / TS 23.040 §9.1.2.5
    _TON_LABELS: dict[int, str] = {
        0: "Unknown",
        1: "International",
        2: "National",
        3: "Network Specific",
        4: "Subscriber Number",
        5: "Alphanumeric",
        6: "Abbreviated",
        7: "Reserved",
    }

    _NPI_LABELS: dict[int, str] = {
        0: "Unknown",
        1: "ISDN / E.164",
        3: "Data / X.121",
        4: "Telex / F.69",
        5: "Service Centre Specific",
        8: "National",
        9: "Private",
        10: "ERMES",
        15: "Reserved",
    }

    # TS 23.040 §9.2.3.9
    _TP_PID_LABELS: dict[int, str] = {
        0x00: "SME-to-SME protocol (no interworking)",
        0x20: "Implicit telematic device",
        0x21: "Telex",
        0x22: "Group 3 telefax",
        0x23: "Group 4 telefax",
        0x24: "Voice telephone",
        0x25: "ERMES",
        0x26: "National paging system",
        0x27: "Videotex",
        0x30: "Message Handling Facility",
        0x31: "X.400",
        0x32: "Internet electronic mail",
        0x40: "Short Message Type 0",
        0x41: "Replace Short Message Type 1",
        0x42: "Replace Short Message Type 2",
        0x43: "Replace Short Message Type 3",
        0x44: "Replace Short Message Type 4",
        0x45: "Replace Short Message Type 5",
        0x46: "Replace Short Message Type 6",
        0x47: "Replace Short Message Type 7",
        0x5F: "Return Call Message",
        0x7C: "ANSI-136 R-DATA",
        0x7D: "ME Data download",
        0x7E: "ME De-personalization",
        0x7F: "SIM Data download",
    }

    @classmethod
    def _decode_address_field(cls, raw: bytes, sc_addr: bool = False) -> dict[str, object]:
        """Decode an address field per TS 24.008 §10.5.4.7.

        For SC addresses (TS 24.011 §8.2.5.2) the length byte counts
        octets including TON/NPI; for destination addresses (TS 23.040
        §9.1.2.5) the length byte counts digits. 0xFF in either case
        means the address is not set.
        """
        if len(raw) < 2:
            return {"raw": raw.hex().upper(), "error": "too short for address field"}

        addr_len = raw[0]
        if addr_len == 0xFF:
            return {"length": addr_len, "present": False, "call_number": ""}
        if addr_len == 0:
            return {"length": 0, "present": False, "call_number": ""}

        ton_npi = raw[1]
        ext = bool(ton_npi & 0x80)
        ton = (ton_npi >> 4) & 0x07
        npi = ton_npi & 0x0F

        if sc_addr:
            if addr_len > len(raw) - 1:
                return {
                    "raw": raw.hex().upper(),
                    "error": f"declared SC address length {addr_len} exceeds field",
                }
            address_octets = addr_len - 1
            digits_expected = address_octets * 2
        else:
            if addr_len > 20:
                return {
                    "raw": raw.hex().upper(),
                    "error": f"declared destination address has {addr_len} digits; maximum is 20",
                }
            address_octets = (addr_len + 1) // 2
            digits_expected = addr_len

        address_bytes = raw[2 : 2 + address_octets]
        if len(address_bytes) != address_octets:
            return {"raw": raw.hex().upper(), "error": "address field is truncated"}
        if ton == 5:
            digits = address_bytes.hex().upper()
            encoding = "alphanumeric GSM 7-bit (raw)"
        else:
            try:
                digits = cls._decode_bcd_digits(address_bytes)
            except ValueError as error:
                return {"raw": raw.hex().upper(), "error": str(error)}
            digits = digits[:digits_expected]
            encoding = "telephony BCD"

        return {
            "length": addr_len,
            "present": True,
            "call_number": digits,
            "encoding": encoding,
            "extension": ext,
            "extension_indicator": "no extension" if ext else "extension follows",
            "ton": cls._TON_LABELS.get(ton, f"Reserved ({ton})"),
            "npi": cls._NPI_LABELS.get(npi, f"Reserved ({npi})"),
            "ton_npi_raw": f"0x{ton_npi:02X}",
        }

    @classmethod
    def _decode_validity_period(cls, vp_byte: int) -> dict[str, object]:
        """Decode TP-Validity Period relative format per TS 23.040 §9.2.3.12."""
        if isinstance(vp_byte, bool) or not isinstance(vp_byte, int) or not 0 <= vp_byte <= 0xFF:
            raise ValueError("TP-Validity Period must be one byte.")
        if vp_byte <= 143:
            minutes = (vp_byte + 1) * 5
            return {"format": "relative (5-min steps)", "minutes": minutes}
        if vp_byte <= 167:
            minutes = 12 * 60 + (vp_byte - 143) * 30
            return {"format": "relative (30-min steps)", "minutes": minutes}
        if vp_byte <= 196:
            days = vp_byte - 166
            return {"format": "relative (days)", "days": days, "minutes": days * 24 * 60}
        weeks = vp_byte - 192
        return {"format": "relative (weeks)", "weeks": weeks, "minutes": weeks * 7 * 24 * 60}

    @staticmethod
    def _decode_tp_dcs(dcs: int) -> str:
        """Decode the TP-DCS coding group per 3GPP TS 23.038 §4."""
        alphabet_names = {
            0: "GSM 7-bit default alphabet",
            1: "8-bit data",
            2: "UCS-2",
            3: "reserved alphabet",
        }
        if (dcs & 0xC0) == 0x00:
            alphabet = alphabet_names[(dcs >> 2) & 0x03]
            parts = [alphabet]
            if dcs & 0x20:
                parts.append("compressed")
            if dcs & 0x10:
                parts.append(f"message class {dcs & 0x03}")
            return ", ".join(parts)
        group = dcs & 0xF0
        if group in (0xC0, 0xD0, 0xE0):
            alphabet = "UCS-2" if group == 0xE0 else "GSM 7-bit default alphabet"
            active = "active" if dcs & 0x08 else "inactive"
            indication = {
                0: "voicemail",
                1: "fax",
                2: "email",
                3: "other",
            }[dcs & 0x03]
            discard = "discard message" if group == 0xC0 else "store message"
            return f"message waiting ({indication}, {active}, {discard}, {alphabet})"
        if group == 0xF0:
            alphabet = "8-bit data" if dcs & 0x04 else "GSM 7-bit default alphabet"
            return f"{alphabet}, message class {dcs & 0x03}"
        return f"reserved/implementation-specific DCS group (0x{dcs:02X})"

    @classmethod
    def decode_sms_params(cls, hex_str: str) -> dict:
        """Decode EF.SMSP per 3GPP TS 31.102 §4.2.27.

        Parses the Parameter Indicators bitmask, TON/NPI + BCD-encoded
        addresses (TS 24.008 §10.5.4.7), TP-PID, TP-DCS, and TP-Validity
        Period into structured fields.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"SMS Params (Raw)": hex_str}

        if len(data) < 28:
            return {
                "Error": f"Invalid SMSP record length ({len(data)}; expected at least 28)",
                "SMS Params (Raw)": hex_str,
            }

        try:
            alpha_len = max(0, len(data) - 28)
            alpha = ""
            alpha_encoding = ""
            if alpha_len > 0:
                alpha, alpha_encoding = cls._decode_alpha_identifier(data[:alpha_len])

            p_ind = data[alpha_len]

            # Parameter Indicators — inverted bitmask: each bit 0 = field
            # present, 1 = field absent. Bit 0 (LSB) = TP-DA, bit 1 =
            # TP-SCA, bit 2 = TP-PID, bit 3 = TP-DCS, bit 4 = TP-VP.
            pi_flags: dict[str, bool] = {}
            for idx, label in enumerate(("TP-Destination Address", "TP-Service Centre Address",
                                          "TP-Protocol Identifier", "TP-Data Coding Scheme",
                                          "TP-Validity Period")):
                pi_flags[label] = not bool(p_ind & (1 << idx))

            tp_da_raw = data[alpha_len + 1 : alpha_len + 13]
            sca_raw = data[alpha_len + 13 : alpha_len + 25]
            tp_pid = data[alpha_len + 25]
            tp_dcs = data[alpha_len + 26]
            tp_vp = data[alpha_len + 27]

            tp_da_present = pi_flags["TP-Destination Address"]
            sca_present = pi_flags["TP-Service Centre Address"]
            pid_present = pi_flags["TP-Protocol Identifier"]
            dcs_present = pi_flags["TP-Data Coding Scheme"]
            vp_present = pi_flags["TP-Validity Period"]

            tp_da = (
                cls._decode_address_field(tp_da_raw, sc_addr=False)
                if tp_da_present
                else {"present": False, "raw": tp_da_raw.hex().upper()}
            )
            sca = (
                cls._decode_address_field(sca_raw, sc_addr=True)
                if sca_present
                else {"present": False, "raw": sca_raw.hex().upper()}
            )
            vp_decoded: object = (
                cls._decode_validity_period(tp_vp)
                if vp_present
                else {"present": False, "raw": f"0x{tp_vp:02X}"}
            )

            pid_label = cls._TP_PID_LABELS.get(tp_pid, "") if pid_present else ""
            dcs_label = cls._decode_tp_dcs(tp_dcs) if dcs_present else ""

            out: dict[str, object] = {
                "Parameter Indicators": {
                    "raw": f"0x{p_ind:02X}",
                    "flags": pi_flags,
                },
                "TP-Destination Address": tp_da,
                "Service Center Address": sca,
                "TP-PID": f"0x{tp_pid:02X}" if pid_present else "Not present",
                "TP-DCS": f"0x{tp_dcs:02X}" if dcs_present else "Not present",
                "TP-Validity Period": vp_decoded,
            }
            if pid_label:
                out["TP-PID Label"] = pid_label
            if dcs_label:
                out["TP-DCS Label"] = dcs_label
            warnings = []
            if (p_ind & 0xE0) != 0xE0:
                warnings.append("Parameter Indicator RFU bits 6..8 are not all one")
            absent_fields = (
                ("TP-Destination Address", tp_da_present, tp_da_raw),
                ("TP-Service Centre Address", sca_present, sca_raw),
                ("TP-Protocol Identifier", pid_present, bytes([tp_pid])),
                ("TP-Data Coding Scheme", dcs_present, bytes([tp_dcs])),
                ("TP-Validity Period", vp_present, bytes([tp_vp])),
            )
            for label, present, raw_field in absent_fields:
                if not present and any(octet != 0xFF for octet in raw_field):
                    warnings.append(f"{label} is marked absent but is not FF")
            if tp_da_present and tp_da.get("present") is False:
                warnings.append(
                    "TP-Destination Address is marked present but has no address"
                )
            if sca_present and sca.get("present") is False:
                warnings.append(
                    "TP-Service Centre Address is marked present but has no address"
                )
            if warnings:
                out["Warnings"] = warnings
            if alpha:
                out["Alpha ID"] = alpha
                out["Alpha ID Encoding"] = alpha_encoding
            return out
        except Exception:
            return {"SMS Params (Raw)": hex_str}

    @staticmethod 
    def decode_puct (hex_str :str )->dict :
        """Decode EF.PUCT: Price per Unit and Currency Table (3GPP TS 31.102 §4.2.13).

        Returns currency string, price-per-unit mantissa/exponent, and raw bytes.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<5 :
                return {"PUCT (Raw)":hex_str }
            try :
                currency =data [0 :3 ].decode ("ascii")
            except UnicodeDecodeError :
                currency =""
            if not currency .isprintable ():
                currency =""
            if currency =="":
                currency =data [0 :3 ].hex ().upper ()
            eppu =(data [3 ]<<4 )|(data [4 ]&0x0F )
            exp_nibble =(data [4 ]>>4 )&0x0F 
            # TS 31.102 Figure 4.2.13: b5 is the sign and b6..b8
            # carry |EX| from least to most significant bit.
            sign =-1 if (exp_nibble &0x01 )else 1
            exponent =sign *((exp_nibble >>1 )&0x07 )
            output ={
            "Currency":currency ,
            "EPPU":eppu ,
            "Exponent":exponent ,
            "Price per Unit Formula":f"{eppu} * 10^{exponent}",
            "Raw":data .hex ().upper (),
            }
            if len (data )!=5 :
                output ["Warning"]=f"EF.PUCT is {len(data)} bytes; expected 5"
            return output
        except Exception :
            return {"PUCT (Raw)":hex_str }

    @staticmethod 
    def decode_ecc (hex_str :str )->dict :
        """Decode EF.ECC: Emergency Call Codes (3GPP TS 31.102 §4.2.21).

        Returns a list of dicts with emergency code digits and category bitmask.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"Emergency Codes":[],"Entries":[]}
            if all (octet ==0xFF for octet in data ):
                return {"Emergency Codes":[],"Entries":[]}
            if len (data )<4 :
                return {
                "Error":f"ECC record must be at least 4 bytes; got {len(data)}",
                "Raw":hex_str ,
                }
            # EF.ECC is linear fixed, so this decoder receives one record at
            # a time. A USIM record is code[3] + optional alpha + category[1];
            # interpreting every four bytes as another record corrupts any
            # alpha identifier whose length happens to make the record a
            # multiple of four.
            code_bytes =data [:3 ]
            digits =ContentDecoder ._decode_bcd_digits (
                code_bytes ,
                allow_dial_symbols =False ,
                )
            if digits =="":
                return {"Error":"ECC record does not contain an emergency code","Raw":hex_str }
            entry ={"Code":digits }
            category_names ={
            0 :"Police",
            1 :"Ambulance",
            2 :"Fire Brigade",
            3 :"Marine Guard",
            4 :"Mountain Rescue",
            5 :"Manually Initiated eCall",
            6 :"Automatically Initiated eCall",
            }
            alpha_bytes =data [3 :-1 ]
            if alpha_bytes :
                alpha ,alpha_encoding =ContentDecoder ._decode_alpha_identifier (
                    alpha_bytes
                    )
                if alpha :
                    entry ["Alpha Identifier"]=alpha
                    entry ["Alpha Identifier Encoding"]=alpha_encoding
            category =data [-1 ]
            entry ["Service Category Raw"]=f"{category:02X}"
            entry ["Service Categories"]=[
            name for bit ,name in category_names .items ()
            if category &(1 <<bit )
            ]
            if category &0x80 :
                entry ["Service Category Warning"]="RFU bit 8 is set"
            return {"Emergency Codes":[digits ],"Entries":[entry ]}
        except Exception as exc :
            return {"Error":f"ECC Decode Error: {exc}","Raw":hex_str }

    @staticmethod
    def decode_ecc_legacy(hex_str: str) -> dict:
        """Decode legacy SIM EF.ECC consecutive three-byte BCD entries."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "Legacy ECC Hex Decode Error"}
        if len(data) % 3:
            return {
                "Error": (
                    "Legacy ECC length must be a multiple of 3 bytes; "
                    f"got {len(data)}"
                ),
                "Raw": hex_str,
            }
        entries = []
        try:
            for offset in range(0, len(data), 3):
                block = data[offset : offset + 3]
                if block == b"\xFF\xFF\xFF":
                    continue
                digits = ContentDecoder._decode_bcd_digits(
                    block,
                    allow_dial_symbols=False,
                )
                if digits:
                    entries.append({"Code": digits})
        except ValueError as exc:
            return {"Error": f"Legacy ECC Decode Error: {exc}", "Raw": hex_str}
        return {
            "Emergency Codes": [entry["Code"] for entry in entries],
            "Entries": entries,
        }

    @staticmethod 
    def decode_adn_like_record (hex_str :str )->dict :
        """Decode an ADN-like linear-fixed record (EF.ADN, EF.FDN, EF.SDN).

        Returns alpha-identifier, TON/NPI, dialling digits, CCP, and extension pointer.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<14 :
                return {"ADN-like (Raw)":hex_str }
            if all (octet ==0xFF for octet in data ):
                return {"Error":"Empty ADN-like record"}
            alpha_len =len (data )-14 
            alpha =""
            alpha_encoding =""
            if alpha_len >0 :
                alpha ,alpha_encoding =ContentDecoder ._decode_alpha_identifier (
                    data [:alpha_len ]
                    )
            footer =data [alpha_len :]
            number_len =footer [0 ]
            ton_npi =footer [1 ]
            if number_len ==0xFF :
                return {"Error":"Empty ADN-like record"}
            if number_len >11 :
                return {"Error":f"Invalid BCD number length ({number_len})"}
            number_octets =max (0 ,number_len -1 )
            number_bcd =footer [2 :2 +number_octets ]
            ccp_id =footer [12 ]
            ext_id =footer [13 ]
            digits =ContentDecoder ._decode_bcd_digits (number_bcd )
            ton =(ton_npi >>4 )&0x07
            npi =ton_npi &0x0F
            out ={
            "Length of BCD Number":number_len ,
            "TON/NPI":f"{ton_npi:02X}",
            "TON":ContentDecoder ._TON_LABELS .get (ton ,f"Reserved ({ton})"),
            "NPI":ContentDecoder ._NPI_LABELS .get (npi ,f"Reserved ({npi})"),
            "Dialing Number":digits ,
            "Capability/Configuration Identifier":f"{ccp_id:02X}",
            "Ext Record ID":f"{ext_id:02X}"
            }
            if alpha :
                out ["Alpha ID"]=alpha 
                out ["Alpha ID Encoding"]=alpha_encoding
            return out 
        except Exception :
            return {"ADN-like (Raw)":hex_str }

    @staticmethod 
    def decode_smss (hex_str :str )->dict :
        """Decode EF.SMSS: SMS Status (3GPP TS 31.102 §4.2.39).

        Returns SMS full flag and memory capacity exceeded indicator.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<2 :
                return {"SMSS (Raw)":hex_str }
            output ={
            "Last Used TP-MR":data [0 ],
            "Memory Capacity Exceeded Flag":"set"if (data [1 ]&0x01 )==0 else "unset",
            "Raw":hex_str ,
            "RFU":data [2 :].hex ().upper (),
            }
            warnings =[]
            if (data [1 ]&0xFE )!=0xFE :
                warnings .append ("SMSS flag RFU bits 2..8 are not all one")
            if any (octet !=0xFF for octet in data [2 :]):
                warnings .append ("SMSS trailing RFU bytes are not FF")
            if warnings :
                output ["Warnings"]=warnings
            return output
        except Exception :
            return {"SMSS (Raw)":hex_str }

    @staticmethod 
    def decode_sms_record (hex_str :str )->dict :
        """Decode a single EF.SMS record (3GPP TS 31.102 §4.2.25).

        Returns record status, message type indicator, originating/destination address,
        and raw payload hex.
        """
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
        """Decode EF.SMSR: SMS Report record (3GPP TS 31.102 §4.2.40).

        Returns record status, SMS reference, and discharge-time string.
        """
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
        """Decode EF.PNN: PLMN Network Name record (3GPP TS 31.102 §4.2.58).

        Returns full-name and short-name strings decoded from TLV 0x43/0x45.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )==0 :
                return {"PNN":"Empty"}
            parsed =TlvParser .parse_padded (data )
            out ={"Raw":hex_str }
            for tag ,label in ((0x43 ,"Full Name"),(0x45 ,"Short Name")):
                value =TlvParser .get_first (parsed ,tag )
                if not isinstance (value ,bytes ):
                    continue
                decoded =_decode_network_name_ie (value )
                out [label]=decoded .get ("text","")
                out [f"{label} Details"]=decoded
            return out 
        except Exception :
            return {"PNN (Raw)":hex_str }

    @staticmethod 
    def decode_opl (hex_str :str )->dict :
        """Decode EF.OPL: Operator PLMN List record (3GPP TS 31.102 §4.2.59).

        Returns PLMN, LAC range, and PNN record number for each 8-byte record.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )<8 :
                return {
                "Error":f"Invalid OPL record length ({len(data)}; expected at least 8)",
                "Raw":hex_str ,
                }
            if all (octet ==0xFF for octet in data ):
                return {"OPL":"Empty"}
            plmn =ContentDecoder ._decode_plmn_bytes (
                data [0 :3 ],
                allow_wildcard =True ,
                )
            if plmn .startswith ("Invalid"):
                return {"Error":plmn ,"Raw":hex_str }
            lac1 =int .from_bytes (data [3 :5 ],"big")
            lac2 =int .from_bytes (data [5 :7 ],"big")
            pnn_id =data [7 ]
            output ={
            "PLMN":plmn ,
            "LAC Start":f"{lac1:04X}",
            "LAC End":f"{lac2:04X}",
            "PNN Record Identifier":pnn_id 
            }
            warnings =[]
            if lac1 >lac2 :
                warnings .append ("LAC/TAC range start is greater than range end")
            if pnn_id ==0 :
                output ["PNN Source"]="Other sources"
            elif pnn_id <=0xFE :
                output ["PNN Source"]=f"EF.PNN record {pnn_id}"
            else :
                warnings .append ("PNN record identifier FF is reserved")
            if any (octet !=0xFF for octet in data [8 :]):
                warnings .append ("OPL trailing record bytes are not FF padding")
            if warnings :
                output ["Warnings"]=warnings
            return output
        except Exception :
            return {"OPL (Raw)":hex_str }

    @staticmethod
    def decode_opl5g(hex_str: str) -> dict:
        """Decode an EF.OPL5G record (3GPP TS 31.102 §4.4.11.9)."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "OPL5G Hex Decode Error"}
        if len(data) < 10:
            return {
                "Error": (
                    f"Invalid OPL5G record length ({len(data)}; expected at least 10)"
                ),
                "Raw": hex_str,
            }
        if all(octet == 0xFF for octet in data):
            return {"OPL5G": "Empty"}

        plmn = ContentDecoder._decode_plmn_bytes(
            data[0:3],
            allow_wildcard=True,
        )
        if plmn.startswith("Invalid"):
            return {"Error": plmn, "Raw": hex_str}

        tac_start = int.from_bytes(data[3:6], "big")
        tac_end = int.from_bytes(data[6:9], "big")
        pnn_id = data[9]
        output = {
            "PLMN": plmn,
            "TAC Start": f"{tac_start:06X}",
            "TAC End": f"{tac_end:06X}",
            "PNN Record Identifier": pnn_id,
        }
        warnings = []
        if tac_start > tac_end:
            warnings.append("TAC range start is greater than TAC range end")
        if pnn_id == 0:
            output["PNN Source"] = "Other sources"
        elif pnn_id <= 0xFE:
            output["PNN Source"] = f"EF.PNN record {pnn_id}"
        else:
            warnings.append("PNN record identifier FF is reserved")
        if any(octet != 0xFF for octet in data[10:]):
            warnings.append("OPL5G trailing record bytes are not FF padding")
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod 
    def decode_spdi (hex_str :str )->dict :
        """Decode EF.SPDI: Service Provider Display Information (3GPP TS 31.102 §4.2.66).

        Returns a list of PLMN strings from the 0xA3/0x80 TLV structure.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
            plmn_list =[]
            a3 =TlvParser .get_first (parsed ,0xA3 )
            if isinstance (a3 ,bytes ):
                a3 =TlvParser .parse (a3 )
            if not isinstance (a3 ,dict ):
                return {"Error":"SPDI does not contain an A3 service-provider template","Raw":hex_str }
            sp_list =TlvParser .get_first (a3 ,0x80 )
            if isinstance (sp_list ,bytes ):
                if len (sp_list )%3 !=0 :
                    return {
                    "Error":f"SPDI PLMN list length is {len(sp_list)}; expected a multiple of 3",
                    "Raw":hex_str ,
                    }
                for i in range (0 ,len (sp_list ),3 ):
                    chunk =sp_list [i :i +3 ]
                    if chunk ==b"\xFF\xFF\xFF":
                        continue 
                    decoded_plmn =ContentDecoder ._decode_plmn_bytes (chunk )
                    if decoded_plmn .startswith ("Invalid"):
                        return {"Error":decoded_plmn ,"Raw":hex_str }
                    plmn_list .append (decoded_plmn )
            return {"Service Provider PLMN List":plmn_list ,"Raw":hex_str }
        except Exception :
            return {"SPDI (Raw)":hex_str }

    @staticmethod 
    def decode_epsnsc (hex_str :str )->dict :
        """Decode EF.EPSNSC: EPS NAS Security Context (3GPP TS 31.102 §4.2.92).

        Returns non-secret metadata only. NAS keys and context bytes are
        deliberately redacted so routine GUI decoding cannot leak them.
        """
        try :
            data =bytes .fromhex (hex_str )
            out ={
            "Length":len (data ),
            "Security Context":"<redacted>",
            "Raw":"<redacted>",
            }
            if len (data )>0 :
                out ["KSI / Header"]=f"{data[0]:02X}"
            return out 
        except Exception :
            return {"Error":"EPSNSC Hex Decode Error"}

    @staticmethod 
    def decode_gbanl (hex_str :str )->dict :
        """Decode EF.GBANL: GBA NAF List (3GPP TS 31.102 §4.4.4).

        Returns NAF FQDN/IMPI pair from the 0x80/0x81 TLV structure.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
            naf =TlvParser .get_first (parsed ,0x80 )
            b_tid =TlvParser .get_first (parsed ,0x81 )
            out ={}
            if isinstance (naf ,bytes ):
                out ["NAF_ID"]=naf .hex ().upper ()
            if isinstance (b_tid ,bytes ):
                out ["B-TID"]="<redacted>"
                out ["B-TID Length"]=len (b_tid )
            return out 
        except Exception :
            return {"Error":"GBANL Decode Error"}

    @staticmethod 
    def decode_nafkca (hex_str :str )->dict :
        """Decode EF.NAFKCA: NAF Key Centre Address (3GPP TS 31.102 §4.4.5).

        Returns the NAF key centre address string from TLV tag 0x80.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
            val =TlvParser .get_first (parsed ,0x80 )
            if isinstance (val ,bytes ):
                try :
                    decoded =val .decode ("utf-8")
                except UnicodeDecodeError :
                    decoded =""
                if decoded and decoded .isprintable ()==False :
                    decoded =""
                return {
                "NAF Key Centre Address":decoded or val .hex ().upper (),
                "Encoding":"UTF-8"if decoded else "Raw hex",
                "Raw":hex_str 
                }
            return {"NAFKCA (Raw)":hex_str }
        except Exception :
            return {"NAFKCA (Raw)":hex_str }

    @staticmethod 
    def decode_isim_tlv80_text (hex_str :str )->dict :
        """Decode an ISIM TLV tag-0x80 UTF-8 text field (3GPP TS 31.103 generic).

        Returns the decoded string; used by EF.IMPI, EF.DOMAIN, and EF.REALM.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
            val =TlvParser .get_first (parsed ,0x80 )
            if isinstance (val ,bytes ):
                try :
                    text =val .decode ("utf-8")
                except UnicodeDecodeError :
                    text =""
                if text and text .isprintable ():
                    return {
                    "Value":text .strip (),
                    "Encoding":"UTF-8",
                    "Raw Value":val .hex ().upper (),
                    }
                return {
                "Value":val .hex ().upper (),
                "Encoding":"Raw hex (invalid/non-printable UTF-8)",
                }
            return {"ISIM (Raw)":hex_str }
        except Exception :
            return {"ISIM (Raw)":hex_str }

    @staticmethod 
    def decode_isim_ist (hex_str :str )->dict :
        """Decode EF.IST: ISIM Service Table (3GPP TS 31.103 §4.2.7).

        Returns active and not-set service-number lists; mirrors UST layout.
        """
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
        """Decode EF.PCSCF: P-CSCF Address List (3GPP TS 31.103 §4.2.8).

        Returns a list of P-CSCF addresses extracted from TLV tag-0x80 records.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
            t80 =TlvParser .get_first (parsed ,0x80 )
            if isinstance (t80 ,bytes )and len (t80 )>1 :
                addr_type =t80 [0 ]
                addr_raw =t80 [1 :]
                addr_type_map ={0x00 :"FQDN",0x01 :"IPv4",0x02 :"IPv6"}
                if addr_type ==0x00 :
                    try :
                        addr_text =addr_raw .decode ("utf-8").strip ()
                    except UnicodeDecodeError :
                        return {"Error":"P-CSCF FQDN is not valid UTF-8","Raw":hex_str }
                    if not addr_text or addr_text .isprintable ()==False :
                        return {"Error":"P-CSCF FQDN is empty or non-printable","Raw":hex_str }
                elif addr_type in (0x01 ,0x02 ):
                    expected =4 if addr_type ==0x01 else 16
                    if len (addr_raw )!=expected :
                        return {
                        "Error":f"P-CSCF {addr_type_map[addr_type]} address has {len(addr_raw)} bytes; expected {expected}",
                        "Raw":hex_str ,
                        }
                    addr_text =str (ipaddress .ip_address (addr_raw ))
                else :
                    addr_text =addr_raw .hex ().upper ()
                return {
                "Address Type":addr_type_map .get (addr_type ,f"0x{addr_type:02X}"),
                "Address":addr_text 
                }
            return {"P-CSCF (Raw)":hex_str }
        except Exception :
            return {"P-CSCF (Raw)":hex_str }

    @staticmethod 
    def decode_tlv_as_map (hex_str :str )->dict :
        """Decode a generic BER-TLV hex blob into a nested tag-value map.

        Used for EFs that carry TLV structures without a dedicated decoder.
        """
        try :
            data =bytes .fromhex (hex_str )
            parsed =TlvParser .parse_padded (data )
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
            try :
                text =data .decode ("utf-8")
            except UnicodeDecodeError :
                return {"Raw":hex_str ,"Encoding":"Hex (invalid UTF-8)"}
            if text and text .isprintable ()==False :
                return {"Raw":hex_str ,"Encoding":"Hex (non-printable UTF-8)"}
            return {"Text":text .strip (),"Raw":hex_str ,"Encoding":"UTF-8"}
        except Exception :
            return {"Raw":hex_str }

    @staticmethod 
    def decode_hex_chunks (hex_str :str )->dict :
        return {"Raw":hex_str }

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
        """Decode PKCS #15 EF.ODF: Object Directory File (ISO 7816-15 §6.7.4).

        Returns a list of PKCS-15 object-class dicts, each carrying the DER-encoded
        ObjectDirectoryFile path pointing to the respective EF.
        """
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ODF: Hex Decode Error"]
        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ODF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse_padded (raw )
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
        """Decode PKCS #15 EF.DODF: Data Objects Directory File (ISO 7816-15 §7.5).

        Returns a list of data-object path records parsed from the SEQUENCE OF DODF structure.
        """
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 DODF: Hex Decode Error"]
        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 DODF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse_padded (raw )
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
        label_encoding =""
        oid =""
        label_vals =_collect_tag_values (parsed ,0x0C )
        if len (label_vals )>0 :
            try :
                candidate =label_vals [0 ].decode ("utf-8")
            except UnicodeDecodeError :
                candidate =""
            if candidate and candidate .isprintable ():
                label =candidate .strip ()
                label_encoding ="UTF-8"
            else :
                label =label_vals [0 ].hex ().upper ()
                label_encoding ="Raw hex"
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
            "label_encoding":label_encoding ,
            "oid_hex":oid ,
            "path":p ,
            })
        body ={"data_objects":entries }
        return ContentDecoder ._pkcs15_json_lines ("DODF",body )

    @staticmethod 
    def decode_pkcs15_acm (hex_str :str )->list :
        """Decode PKCS #15 EF.ACM: Authentication Certificate Mapping (ISO 7816-15 §7.4.2).

        Returns a list of cert-path / key-ref mapping entries.
        """
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACM: Hex Decode Error"]
        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ACM: Empty/Invalid"]
        try :
            parsed =TlvParser .parse_padded (raw )
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
        """Decode PKCS #15 EF.ACRF: Access Control Rule File (GlobalPlatform SEAC §5.2).

        Parses REF-DO and AR-DO TLV structures and returns a flat list of JSON-serialisable
        access-rule dicts.
        """
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACRF: Hex Decode Error"]
        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ACRF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse_padded (raw )
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
        """Decode PKCS #15 EF.ACCF: Access Control Conditions File (GlobalPlatform SEAC §5.3).

        Returns a list of device-application condition objects from the ACCF TLV structure.
        """
        try :
            raw =bytes .fromhex (hex_str )
        except Exception :
            return ["PKCS15 ACCF: Hex Decode Error"]
        if len (raw )==0 or all (octet ==0xFF for octet in raw ):
            return ["PKCS15 ACCF: Empty/Invalid"]
        try :
            parsed =TlvParser .parse_padded (raw )
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
        """Decode EF.5GLOCI: 5GS Location Information (3GPP TS 31.102 §4.4.11.9).

        Returns the embedded 5GS-mobile-identity GUTI, TAI, and update status.
        """
        try :
            data =bytes .fromhex (hex_str )
        except Exception :
            return {"Error":"5GS LOCI Hex Decode Error"}
        if len (data )!=20 :
            return {"Error":f"Invalid 5GS LOCI Length ({len(data)}; expected 20)"}
        guti_raw =data [:13 ]
        guti_assigned =not all (octet ==0xFF for octet in guti_raw )
        guti_plmn ="Not assigned"
        if guti_assigned :
            identity_length =int .from_bytes (data [0 :2 ],"big")
            if identity_length !=11 :
                return {
                "Error":f"5GS GUTI length is {identity_length}; expected 11"
                }
            if data [2 ]!=0xF2 :
                return {
                "Error":f"5GS GUTI identity header is {data[2]:02X}; expected F2"
                }
            guti_plmn =ContentDecoder ._decode_plmn_bytes (data [3 :6 ])
            if guti_plmn .startswith ("Invalid"):
                return {"Error":"5GS GUTI contains an invalid PLMN BCD digit"}
        tai_plmn ="Not assigned"
        if data [13 :16 ]!=b"\xFF\xFF\xFF":
            tai_plmn =ContentDecoder ._decode_plmn_bytes (data [13 :16 ])
            if tai_plmn .startswith ("Invalid"):
                return {"Error":"5GS TAI contains an invalid PLMN BCD digit"}
        status_value =data [19 ]&0x07
        status ={
        0 :"Updated",
        1 :"Not Updated",
        2 :"5U3 Roaming Not Allowed",
        }.get (status_value ,f"Reserved ({status_value})")
        amf_set_pointer =int .from_bytes (data [7 :9 ],"big")
        output ={
        "GUTI":{
        "Assigned":guti_assigned ,
        "Length":int .from_bytes (data [0 :2 ],"big"),
        "Identity Header":f"{data[2]:02X}",
        "PLMN":guti_plmn ,
        "AMF Region ID":f"{data[6]:02X}",
        "AMF Set ID":amf_set_pointer >>6 ,
        "AMF Pointer":amf_set_pointer &0x3F ,
        "AMF Set ID/Pointer":data [7 :9 ].hex ().upper (),
        "5G-TMSI":data [9 :13 ].hex ().upper (),
        },
        "Last Visited TAI":{
        "PLMN":tai_plmn ,
        "TAC":data [16 :19 ].hex ().upper (),
        },
        "Status":status ,
        "Status Byte":f"{data[19]:02X}",
        }
        if data [19 ]&0xF8 :
            output ["Warning"]="5GS update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod 
    def decode_5gs_nsc (hex_str :str )->dict :
        """Decode EF.5GS_NSC: 5GS NAS Security Context (3GPP TS 31.102 §4.4.11.3).

        Returns non-secret header metadata while redacting the NAS context.
        """
        try :
            data =bytes .fromhex (hex_str )
            out ={"Length":len (data ),"Security Context Data":"<redacted>"}
            if len (data )>0 :
                out ["Security Header"]=f"{data[0]:02X}"
            return out 
        except Exception :
            return {"Error":"5GS NSC Hex Decode Error"}

    @staticmethod 
    def decode_5gs_auth_keys (hex_str :str )->dict :
        """Decode EF.5GAUTHKEYS: 5G Authentication Keys (3GPP TS 31.102 §4.4.11.5).

        Returns the key blob length only. Key material is always redacted.
        """
        try :
            data =bytes .fromhex (hex_str )
            return {
            "Length":len (data ),
            "Auth Keys Blob":"<redacted>"
            }
        except Exception :
            return {"Error":"5GS Auth Keys Hex Decode Error"}

    @staticmethod
    def decode_sensitive_blob(hex_str: str) -> dict:
        """Summarise a secret-bearing EF without returning its key material."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "Sensitive EF Hex Decode Error"}
        return {"Length": len(data), "Value": "<redacted>"}

    @staticmethod 
    def decode_5gs_uac_aic (hex_str :str )->dict :
        """Decode EF.UAC_AIC: Unified Access Control Access Identities Configuration (3GPP TS 31.102 §4.4.11.7).

        Returns the two assigned configuration flags and reports non-zero RFU bits.
        """
        try :
            data =bytes .fromhex (hex_str )
        except ValueError :
            return {"Error":"UAC_AIC Hex Decode Error"}
        if len (data )!=4 :
            return {"Error":f"Invalid UAC_AIC Length ({len(data)}; expected 4)"}
        first =data [0 ]
        rfu =bytes ([first &0xFC ])+data [1 :]
        output ={
        "Multimedia Priority Service":bool (first &0x01 ),
        "Mission Critical Services":bool (first &0x02 ),
        "Configuration Byte":f"{first:02X}",
        "RFU Bytes":rfu .hex ().upper (),
        "Raw":data .hex ().upper (),
        }
        if any (rfu ):
            output ["Warning"]="One or more RFU bits are non-zero"
        return output

    @staticmethod 
    def decode_routing_indicator (hex_str :str )->dict :
        """Decode EF.RI: Routing Indicator (3GPP TS 31.102 §4.4.11.11).

        Returns the BCD digits from bytes 1..2 and exposes bytes 3..4 as RFU.
        """
        try :
            data =bytes .fromhex (hex_str )
            if len (data )!=4 :
                return {
                "Error":f"Invalid Routing Indicator Length ({len(data)}; expected 4)"
                }
            digits =ContentDecoder ._decode_bcd_digits (
                data [:2 ],
                allow_dial_symbols =False ,
                )
            if not 1 <=len (digits )<=4 :
                return {
                "Error":f"Invalid Routing Indicator digit count ({len(digits)}; expected 1..4)"
                }
            output ={
            "Routing Indicator":digits ,
            "Digit Count":len (digits ),
            "RFU":data [2 :].hex ().upper (),
            "Raw":data .hex ().upper (),
            }
            if data [2 :]!=b"\x00\x00":
                output ["Warning"]="RFU bytes are not 0000"
            return output
        except Exception as exc :
            return {"Error":f"Routing Indicator Decode Error: {exc}"}

    @staticmethod 
    def decode_5gs_sor_cmci (hex_str :str )->dict :
        """Decode EF.SOR-CMCI (3GPP TS 31.102 §4.4.11.15).

        Returns the optional tag-80 SOR-CMCI parameter object without assigning
        semantics to the TS 24.501 payload bytes.
        """
        try :
            data =bytes .fromhex (hex_str )
        except ValueError :
            return {"Error":"SOR-CMCI Hex Decode Error"}
        if len (data )==0 or all (octet ==0xFF for octet in data ):
            return {"SOR-CMCI Rule Present":False ,"Parameter Length":0 }
        try :
            parsed =TlvParser .parse_padded (data )
        except ValueError as exc :
            return {"Error":f"SOR-CMCI TLV Parse Error: {exc}"}
        unexpected_tags = [tag for tag in parsed if tag != 0x80]
        if unexpected_tags:
            rendered = ", ".join(f"{tag:X}" for tag in unexpected_tags)
            return {
                "Error": f"SOR-CMCI contains unexpected tag(s): {rendered}",
                "Raw": data.hex().upper(),
            }
        parameter_values =TlvParser .as_list (parsed .get (0x80 ))
        if len (parameter_values )==0 :
            return {
            "Error":"SOR-CMCI data does not contain tag 80",
            "Raw":data .hex ().upper (),
            }
        if len (parameter_values )>1 :
            return {
            "Error":"SOR-CMCI data contains more than one tag-80 object",
            "Raw":data .hex ().upper (),
            }
        parameters =parameter_values [0 ]
        if not isinstance (parameters ,bytes ):
            return {"Error":"SOR-CMCI tag 80 is not a primitive value"}
        return {
        "SOR-CMCI Rule Present":len (parameters )>0 ,
        "Parameter Length":len (parameters ),
        "Parameters":parameters .hex ().upper (),
        }

    @staticmethod 
    def decode_dri (hex_str :str )->dict :
        """Decode EF.DRI: Disaster Roaming Information (3GPP TS 31.102 §4.4.11.17).

        Returns the fixed disaster-roaming indicators, wait-range bytes, and
        optional HPLMN-provided PLMN list.
        """
        try :
            data =bytes .fromhex (hex_str )
        except ValueError :
            return {"Error":"DRI Hex Decode Error"}
        if len (data )<7 :
            return {"Error":f"Invalid DRI Length ({len(data)}; expected at least 7)"}

        status =data [1 ]
        parameter_names =(
        "Disaster Roaming Wait Range",
        "Disaster Return Wait Range",
        "VPLMN List Applicability",
        "HPLMN PLMN List",
        )
        parameter_presence ={
        name:not bool (status &(1 <<index ))
        for index ,name in enumerate (parameter_names )
        }
        output ={
        "Disaster Roaming Enabled":bool (data [0 ]&0x01 ),
        "Enable Byte":f"{data[0]:02X}",
        "Parameter Indicator":f"{status:02X}",
        "Parameter Presence":parameter_presence ,
        "Disaster Roaming Wait Range":data [2 :4 ].hex ().upper (),
        "Disaster Return Wait Range":data [4 :6 ].hex ().upper (),
        "VPLMN List Applicability":f"{data[6]:02X}",
        "HPLMN PLMN List":[],
        "Raw":data .hex ().upper (),
        }
        warnings =[]
        if data [0 ]&0xFE :
            warnings .append ("enable byte has non-zero RFU bits")
        if (status &0xF0 )!=0xF0 :
            warnings .append ("parameter-indicator RFU bits 5..8 are not all one")
        fixed_fields = (
            data[2:4],
            data[4:6],
            data[6:7],
        )
        for index, field in enumerate(fixed_fields):
            if not parameter_presence[parameter_names[index]] and any(
                octet != 0xFF for octet in field
            ):
                warnings.append(
                    f"{parameter_names[index]} is marked absent but is not FF"
                )

        suffix =data [7 :]
        if suffix and not all (octet ==0xFF for octet in suffix ):
            try :
                parsed =TlvParser .parse_padded (suffix )
            except ValueError as exc :
                return {"Error":f"DRI PLMN-list TLV Parse Error: {exc}"}
            unexpected_tags = [tag for tag in parsed if tag != 0x80]
            if unexpected_tags:
                rendered = ", ".join(f"{tag:X}" for tag in unexpected_tags)
                return {
                    "Error": f"DRI optional data contains unexpected tag(s): {rendered}"
                }
            plmn_values = TlvParser.as_list(parsed.get(0x80))
            if len(plmn_values) != 1 or not isinstance(plmn_values[0], bytes):
                return {"Error":"DRI optional data does not contain tag-80 PLMN list"}
            plmn_value = plmn_values[0]
            if len (plmn_value )%3 :
                return {
                "Error":f"DRI HPLMN PLMN list length is {len(plmn_value)}; expected a multiple of 3"
                }
            plmns =[]
            for offset in range (0 ,len (plmn_value ),3 ):
                encoded_plmn =plmn_value [offset :offset +3 ]
                if encoded_plmn ==b"\xFF\xFF\xFF":
                    continue
                decoded_plmn =ContentDecoder ._decode_plmn_bytes (encoded_plmn )
                if decoded_plmn .startswith ("Invalid"):
                    return {"Error":decoded_plmn }
                plmns .append (decoded_plmn )
            output ["HPLMN PLMN List"]=plmns
            if not parameter_presence["HPLMN PLMN List"]:
                warnings.append(
                    "HPLMN PLMN List is encoded but marked absent"
                )
        elif parameter_presence["HPLMN PLMN List"]:
            warnings.append("HPLMN PLMN List is marked present but not encoded")
        if warnings :
            output ["Warnings"]=warnings
        return output
