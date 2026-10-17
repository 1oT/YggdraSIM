# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The UICC System Specific Parameters object the install-script builder adds.

ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2 codes the 'EA' object; clause
8.2.1.3.2.2.1 orders the tag 80 toolkit parameters and makes them mandatory
for a ToolkitInterface applet; clause 8.2.1.3.2.2.2 lists the tag 81 access
entries "L(AID) AID L(AD) AD L(DAP) DAP", the UICC file system entry with an
empty AID and each ADF AID 5 to 16 octets; clause 8.2.1.3.2.5.1 codes the
Access Domain Parameter ('00' full, '02' UICC mechanism + 3-octet ADD, 'FF'
none). The script comment decodes the object back to those names.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_scp03_wizard_apdu_builders import _write_ijc

from SCP03.core import install_script
from SCP03.core.cap import CapFileParser

USIM_AID = "A0000000871002FFFFFFFF8988000001"
ISIM_AID = "A0000000871004FFFFFFFF8988000001"
TOOLKIT_80 = "8008" + "0100000000000000"
FS_ENTRY = "00" + "0100" + "00"
USIM_ENTRY = "10" + USIM_AID + "0100" + "00"


class TestParseAidList:
    @pytest.mark.parametrize("text", ["", "  ", "N", "n", "no", "NONE", "SKIP", None])
    def test_none_words_give_no_aids(self, text) -> None:
        assert install_script.parse_aid_list(text) == []

    def test_separators_and_byte_grouping(self) -> None:
        text = f"0x{USIM_AID}; a0:00:00:00:87:10:04:ff:ff:ff:ff:89:88:00:00:01 , F0 00 00 00 01"
        assert install_script.parse_aid_list(text) == [
            bytes.fromhex(USIM_AID),
            bytes.fromhex(ISIM_AID),
            bytes.fromhex("F000000001"),
        ]

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("A000", "5 to 16 bytes"),
            ("A0" * 17, "5 to 16 bytes"),
            ("A00", "even number"),
            ("A0000000GG", "non-hexadecimal"),
        ],
    )
    def test_bad_aids_are_value_errors(self, text: str, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            install_script.parse_aid_list(text)


class TestBuildUiccSystemParameters:
    def test_one_adf_with_toolkit_parameters(self) -> None:
        built = install_script.build_uicc_system_parameters([bytes.fromhex(USIM_AID)])
        assert built.hex().upper() == "EA24" + TOOLKIT_80 + "8118" + FS_ENTRY + USIM_ENTRY

    def test_toolkit_parameters_declined(self) -> None:
        built = install_script.build_uicc_system_parameters(
            [bytes.fromhex(USIM_AID)], toolkit=False
        )
        assert built.hex().upper() == "EA1A" + "8118" + FS_ENTRY + USIM_ENTRY

    def test_no_adf_grants_the_file_system_only(self) -> None:
        built = install_script.build_uicc_system_parameters([], toolkit=False)
        assert built.hex().upper() == "EA06" + "8104" + FS_ENTRY

    def test_uicc_access_mechanism_domain_applies_to_every_entry(self) -> None:
        built = install_script.build_access_parameters(
            0x82, [bytes.fromhex("F000000001")], bytes.fromhex("02010203")
        )
        # 7-byte file system entry and 12-byte ADF entry: length 13.
        assert built.hex().upper() == (
            "8213" + "00" + "04" + "02010203" + "00" + "05" + "F000000001" + "04" + "02010203" + "00"
        )

    def test_the_long_form_length_appears_past_127_bytes(self) -> None:
        aids = [bytes.fromhex(USIM_AID)] * 7
        built = install_script.build_uicc_system_parameters(aids)
        # 7 x 20-byte ADF entries + 4-byte file system entry = 144 bytes of
        # tag 81 value; 10 bytes of tag 80 and the 3-byte tag 81 header on top.
        assert built[:3].hex().upper() == "EA81" + f"{10 + 3 + 144:02X}"
        assert install_script.iter_tlvs(built)[0][0] == 0xEA


class TestAddUiccSystemParameters:
    EA = bytes.fromhex("EA06" + "8104" + FS_ENTRY)

    def test_appends_after_the_existing_objects(self) -> None:
        merged = install_script.add_uicc_system_parameters(bytes.fromhex("C900"), self.EA)
        assert merged.hex().upper() == "C900" + self.EA.hex().upper()

    def test_refuses_a_second_ea_object(self) -> None:
        with pytest.raises(ValueError, match="already carry Tag EA"):
            install_script.add_uicc_system_parameters(bytes.fromhex("C900EA00"), self.EA)

    @pytest.mark.parametrize("params", ["CA00", "C900CA020100", "EF04CA020100"])
    def test_refuses_a_ca_object_beside_or_inside_ef(self, params: str) -> None:
        with pytest.raises(ValueError, match="cannot coexist with Tag EA"):
            install_script.add_uicc_system_parameters(bytes.fromhex(params), self.EA)

    def test_refuses_parameters_that_are_not_tlvs(self) -> None:
        with pytest.raises(ValueError, match="not a TLV list"):
            install_script.add_uicc_system_parameters(bytes.fromhex("C905"), self.EA)


class TestIterTlvs:
    def test_empty_input(self) -> None:
        assert install_script.iter_tlvs(b"") == []

    @pytest.mark.parametrize(
        ("data", "message"),
        [
            ("C9", "truncated TLV header"),
            ("EA24", "claims 36 bytes"),
            ("C90500", "claims 5 bytes"),
            ("C981", "truncated TLV length"),
            ("C980", "unsupported BER length octet 80"),
            ("C983000001", "unsupported BER length octet 83"),
        ],
    )
    def test_malformed_input_is_a_value_error(self, data: str, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            install_script.iter_tlvs(bytes.fromhex(data))

    def test_short_and_long_length_forms(self) -> None:
        value = bytes(range(130))
        data = bytes.fromhex("C900") + b"\xea\x81\x82" + value + b"\xef\x82\x00\x01\x55"
        assert install_script.iter_tlvs(data) == [
            (0xC9, b""),
            (0xEA, value),
            (0xEF, b"\x55"),
        ]


class TestDescribeInstallParams:
    def test_plain_c9_carries_the_missing_ea_reminder(self) -> None:
        lines = install_script.describe_install_params(bytes.fromhex("C900"))
        assert lines[0] == "Install parameters:"
        assert lines[1] == "  C9 00 -- application specific parameters, empty"
        assert lines[2].startswith("  no EA object: a UICC toolkit or file-access applet gets")

    def test_the_ea_object_is_decoded_to_each_adf(self) -> None:
        params = bytes.fromhex("C900") + install_script.build_uicc_system_parameters(
            [bytes.fromhex(USIM_AID), bytes.fromhex(ISIM_AID)]
        )
        lines = install_script.describe_install_params(params)
        assert lines == [
            "Install parameters:",
            "  C9 00 -- application specific parameters, empty",
            "  EA 38 -- UICC system specific parameters"
            " (ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2)",
            "    80 08 0100000000000000 -- UICC toolkit parameters: priority 01,"
            " timers 00, menu text length 00, menu entries 00, channels 00,"
            " MSL none, TAR none, services 00",
            "    81 2C -- UICC access parameters (clause 8.2.1.3.2.2.2)",
            "      UICC file system: access domain 00 (full access)",
            f"      ADF {USIM_AID}: access domain 00 (full access)",
            f"      ADF {ISIM_AID}: access domain 00 (full access)",
        ]

    def test_toolkit_parameters_with_menu_msl_and_tar(self) -> None:
        # Clause 8.2.1.3.2.2.1 field order: priority, timers, menu text
        # length, m menu entries, 2 x m bytes, channels, L(MSL) MSL, L(TAR)
        # TARs, services.
        field = bytes.fromhex("FF" "00" "10" "01" "000B" "02" "0116" "03B00010" "01")
        assert install_script.describe_uicc_toolkit_parameters(field) == (
            "priority FF, timers 00, menu text length 10, menu entries 01,"
            " menu position and identifier 000B, channels 02, MSL 16, TAR B00010,"
            " services 01"
        )

    def test_a_short_toolkit_field_prints_as_hex(self) -> None:
        assert install_script.describe_uicc_toolkit_parameters(
            bytes.fromhex("0100")
        ) == "fields (not decoded): 0100"
        assert install_script.describe_uicc_toolkit_parameters(
            bytes.fromhex("01000001")
        ) == "fields (not decoded): 01000001"

    def test_access_domain_readings(self) -> None:
        assert install_script.describe_access_parameters(
            bytes.fromhex(
                "00" "02" "0400" "00"
                "05" "F000000001" "04" "02010203" "00"
                "05" "F000000002" "01" "FF" "01" "55"
            )
        ) == [
            "UICC file system: access domain 0400",
            "ADF F000000001: access domain 02 (UICC access mechanism, ADD 010203)",
            "ADF F000000002: access domain FF (no access), DAP 55",
        ]
        assert install_script.describe_access_parameters(b"") == ["no entries"]
        assert install_script.describe_access_parameters(bytes.fromhex("05F0")) == [
            "entries (not decoded): 05F0"
        ]
        assert install_script.describe_access_parameters(bytes.fromhex("00")) == [
            "entries (not decoded): 00"
        ]

    @pytest.mark.parametrize("data", ["", "C9", "EA24", "C90500"])
    def test_malformed_parameters_never_raise(self, data: str) -> None:
        lines = install_script.describe_install_params(bytes.fromhex(data))
        assert len(lines) == 1
        assert lines[0].startswith("Install parameters")

    def test_an_ea_with_a_broken_inner_field_prints_the_hex(self) -> None:
        lines = install_script.describe_install_params(bytes.fromhex("EA03" "8105" "00"))
        assert lines[-1] == "    (not decoded): 810500"


def test_the_rendered_script_carries_the_parameter_comment(tmp_path: Path) -> None:
    ijc_path = _write_ijc(tmp_path, bytes.fromhex("F000000001"), bytes.fromhex("F00000000101"))
    parsed = CapFileParser.parse_with_metadata(str(ijc_path))
    params = bytes.fromhex("C900") + install_script.build_uicc_system_parameters(
        [bytes.fromhex(USIM_AID)]
    )
    plan = install_script.plan_install_sequence(
        parsed,
        applet_aid_hex="F00000000101",
        module_aid_hex="F00000000101",
        privileges_hex="00",
        install_params_hex=params.hex().upper(),
        ota=True,
        cipher_mode="AES",
    )
    lines = install_script.render_install_script(plan, str(ijc_path))
    index = lines.index("# 3. INSTALL [for install and make selectable] (P1=0C)")
    assert lines[index + 1] == "#    Install parameters:"
    assert f"#          ADF {USIM_AID}: access domain 00 (full access)" in lines
    assert lines[-1] == plan.install_apdu
    commands = [line for line in lines if not line.startswith("#")]
    assert commands == list(plan.apdus)
