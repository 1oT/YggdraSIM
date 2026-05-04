import io
import sys
import types
import unittest
from contextlib import redirect_stdout

from SCP03.core.decoders import AdvancedDecoders


def _install_smartcard_stubs():
    has_smartcard =False
    if "smartcard" in sys.modules:
        has_smartcard =True
    if has_smartcard:
        return

    smartcard_module =types.ModuleType ("smartcard")
    system_module =types.ModuleType ("smartcard.System")
    card_connection_module =types.ModuleType ("smartcard.CardConnection")

    system_module .readers =lambda :[]
    card_connection_module .CardConnection =type ("CardConnection",(),{})

    smartcard_module .System =system_module
    smartcard_module .CardConnection =card_connection_module

    sys .modules ["smartcard"]=smartcard_module
    sys .modules ["smartcard.System"]=system_module
    sys .modules ["smartcard.CardConnection"]=card_connection_module


_install_smartcard_stubs ()

from SCP03.interface.shell import ShellDispatcher


def _tlv(tag_bytes :bytes ,value :bytes )->bytes :
    return tag_bytes +bytes ([len (value )])+value


def _build_sample_ara_get_all_payload ()->bytes :
    aid_ref =_tlv (b"\x4F",bytes .fromhex ("A000000151"))
    dev_app_id =_tlv (
        b"\xC1",
        bytes .fromhex ("00112233445566778899AABBCCDDEEFF00112233"),
    )
    pkg_ref =_tlv (b"\xCA",b"com.example.app")
    ref_do =_tlv (b"\xE1",aid_ref +dev_app_id +pkg_ref)

    apdu_rule =_tlv (b"\xD0",b"\x01")
    nfc_rule =_tlv (b"\xD1",b"\x00")
    perm_rule =_tlv (b"\xDB",bytes .fromhex ("1122334455667788"))
    ar_do =_tlv (b"\xE3",apdu_rule +nfc_rule +perm_rule)

    ref_ar_do =_tlv (b"\xE2",ref_do +ar_do)
    return _tlv (b"\xFF\x40",ref_ar_do)


class FakeFsController :
    def __init__ (self ,selected_aid :str ):
        self .selected_aid =selected_aid
        self .current_fcp ={}

    def select (self ,arg_line :str )->bool :
        self .current_fcp ={"aid":self .selected_aid }
        return True


class FakeTransport :
    def __init__ (self ,response_data :bytes ):
        self .response_data =response_data
        self .calls =[]

    def transmit (self ,apdu_hex :str ,silent :bool =False ):
        self .calls .append ((apdu_hex ,silent ))
        return self .response_data ,0x90 ,0x00


class Scp03AraRulesTests (unittest .TestCase ):
    def test_parse_aid_registry_line_supports_role_marker_comment (self ):
        name ,aid_hex ,role_name =ShellDispatcher ._parse_aid_registry_line (
            "MYSEAC:A00000015141434C00 # ARAM"
        )

        self .assertEqual (name ,"MYSEAC")
        self .assertEqual (aid_hex ,"A00000015141434C00")
        self .assertEqual (role_name ,"ARAM")

    def test_decode_ara_rulesets_formats_get_all_payload (self ):
        payload =_build_sample_ara_get_all_payload ()

        decoded =AdvancedDecoders .decode_ara_rulesets (payload .hex ().upper ())

        self .assertEqual (len (decoded ),1 )
        self .assertIn ("Ruleset 1:",decoded [0 ])
        self .assertIn ("AID=A000000151",decoded [0 ])
        self .assertIn ("DeviceAppID=00112233445566778899AABBCCDDEEFF00112233",decoded [0 ])
        self .assertIn ("Package=com.example.app",decoded [0 ])
        self .assertIn ("APDU=always",decoded [0 ])
        self .assertIn ("NFC=never",decoded [0 ])
        self .assertIn ("Permissions=1122334455667788",decoded [0 ])

    def test_handle_select_reads_rules_for_marked_aram_alias (self ):
        payload =_build_sample_ara_get_all_payload ()
        shell =ShellDispatcher .__new__ (ShellDispatcher )
        shell .aid_registry ={"MYSEAC":"A00000015141434C00"}
        shell .aid_rule_roles ={"MYSEAC":"ARAM"}
        shell .aid_lookup ={}
        shell .fs_ctrl =FakeFsController ("A00000015141434C00")
        shell .transport =FakeTransport (payload )

        buffer =io .StringIO ()
        with redirect_stdout (buffer ):
            shell ._handle_select ("MYSEAC")

        rendered =buffer .getvalue ()
        self .assertEqual (shell .transport .calls ,[("80CAFF4000",True )])
        self .assertIn ("READ RULES after selecting MYSEAC",rendered )
        self .assertIn ("Ruleset 1:",rendered )
        self .assertIn ("APDU=always",rendered )

    def test_handle_select_skips_rules_for_unmarked_alias (self ):
        payload =_build_sample_ara_get_all_payload ()
        shell =ShellDispatcher .__new__ (ShellDispatcher )
        shell .aid_registry ={"MYAPP":"A00000015141434C00"}
        shell .aid_rule_roles ={}
        shell .aid_lookup ={}
        shell .fs_ctrl =FakeFsController ("A00000015141434C00")
        shell .transport =FakeTransport (payload )

        buffer =io .StringIO ()
        with redirect_stdout (buffer ):
            shell ._handle_select ("MYAPP")

        rendered =buffer .getvalue ()
        self .assertEqual (shell .transport .calls ,[])
        self .assertNotIn ("READ RULES",rendered )


if __name__ =="__main__":
    unittest .main ()
