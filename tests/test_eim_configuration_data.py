# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.32 v1.3 EimConfigurationData, AddInitialEim and eUICCMemoryReset codecs."""

from __future__ import annotations

import pytest

from SCP11.shared.eim_configuration_data import (
    ADD_INITIAL_EIM_RESET_OPTIONS,
    EIM_SUPPORTED_PROTOCOL_BITS,
    KEY_FORM_CERTIFICATE,
    KEY_FORM_PUBLIC_KEY,
    MEMORY_RESET_OPTION_BITS,
    EimConfigurationData,
    KeyData,
    add_initial_eim_problems,
    add_initial_eim_script,
    decode_add_initial_eim_response,
    decode_der_integer,
    decode_euicc_memory_reset_response,
    decode_named_bit_string,
    encode_add_initial_eim_request,
    encode_der_integer,
    encode_eim_configuration_data,
    encode_euicc_memory_reset_request,
    encode_named_bit_string,
    infer_eim_id_type,
    verify_add_initial_eim_request,
)
from tests.eim_builder_support import TEST_EIM_FQDN, TEST_EIM_ID, der, make_certificate

# A SubjectPublicKeyInfo-shaped SEQUENCE: the codec only retags it.
SPKI = bytes.fromhex("3013300706052B8104000A030800AABBCCDDEEFF00")


def _entry(**changes) -> EimConfigurationData:
    values = dict(
        eim_id=TEST_EIM_ID,
        eim_fqdn=TEST_EIM_FQDN,
        eim_id_type=1,
        counter_value=0,
        association_token=-1,
        eim_public_key_data=KeyData(KEY_FORM_PUBLIC_KEY, SPKI),
        eim_supported_protocol=("eimRetrieveHttps",),
        indirect_profile_download=True,
    )
    values.update(changes)
    return EimConfigurationData(**values)


@pytest.mark.parametrize(
    ("value", "contents"),
    [
        (0, "00"),
        (127, "7F"),
        (128, "0080"),
        (255, "00FF"),
        (256, "0100"),
        (-1, "FF"),
        (-128, "80"),
        (-129, "FF7F"),
        (0x7FFFFF, "7FFFFF"),
        (0x800000, "00800000"),
    ],
)
def test_der_integer_is_minimal_twos_complement(value: int, contents: str) -> None:
    assert encode_der_integer(value).hex().upper() == contents
    assert decode_der_integer(bytes.fromhex(contents)) == value


def test_der_integer_refuses_bool_and_empty_contents() -> None:
    with pytest.raises(TypeError):
        encode_der_integer(True)
    with pytest.raises(ValueError):
        decode_der_integer(b"")


def test_named_bit_string_drops_trailing_zero_bits() -> None:
    assert encode_named_bit_string(["eimRetrieveHttps"], EIM_SUPPORTED_PROTOCOL_BITS).hex() == "0780"
    assert encode_named_bit_string(["eimRetrieveHttps", "eimInjectCoaps"], EIM_SUPPORTED_PROTOCOL_BITS).hex() == "0490"
    assert encode_named_bit_string([], EIM_SUPPORTED_PROTOCOL_BITS).hex() == "00"
    with pytest.raises(ValueError):
        encode_named_bit_string(["eimCarrierPigeon"], EIM_SUPPORTED_PROTOCOL_BITS)


def test_named_bit_string_decode_boundaries() -> None:
    assert decode_named_bit_string(bytes.fromhex("0106"), MEMORY_RESET_OPTION_BITS) == ADD_INITIAL_EIM_RESET_OPTIONS
    assert decode_named_bit_string(b"\x00", MEMORY_RESET_OPTION_BITS) == ()
    for bad in (b"", b"\x01", b"\x08\x00"):
        with pytest.raises(ValueError):
            decode_named_bit_string(bad, MEMORY_RESET_OPTION_BITS)


def test_memory_reset_request_matches_the_operator_script() -> None:
    # resetEimConfigData(5) and resetImmediateEnableConfig(6): one octet, one unused bit.
    assert encode_euicc_memory_reset_request().hex().upper() == "BF640482020106"
    with pytest.raises(ValueError):
        encode_euicc_memory_reset_request(())


def test_eim_configuration_data_golden_encoding() -> None:
    encoded = encode_eim_configuration_data(_entry())
    assert encoded.hex().upper() == (
        "3056"
        "801C" + TEST_EIM_ID.encode().hex().upper()
        + "8110" + TEST_EIM_FQDN.encode().hex().upper()
        + "820101"
        "830100"
        "8401FF"
        "A515A013300706052B8104000A030800AABBCCDDEEFF00"
        "87020780"
        "8900"
    )


def test_counter_value_with_the_sign_bit_set_keeps_a_leading_zero() -> None:
    encoded = encode_eim_configuration_data(_entry(counter_value=200))
    assert bytes.fromhex("830200C8") in encoded


def test_certificate_alternative_carries_the_certificate_contents_under_a1() -> None:
    certificate, _key = make_certificate(TEST_EIM_ID)
    raw = der(certificate)
    encoded = encode_eim_configuration_data(_entry(eim_public_key_data=KeyData(KEY_FORM_CERTIFICATE, raw)))
    # The [1] alternative replaces the Certificate's own '30' tag; [5] stays outside.
    assert b"\xA1" + raw[1:] in encoded


def test_eim_id_size_is_bounded_in_bytes() -> None:
    with pytest.raises(ValueError):
        encode_eim_configuration_data(_entry(eim_id=""))
    with pytest.raises(ValueError):
        encode_eim_configuration_data(_entry(eim_id="é" * 65))


def test_add_initial_eim_problems_follow_5_9_4() -> None:
    assert add_initial_eim_problems([_entry()]) == []
    problems = add_initial_eim_problems(
        [_entry(eim_id=None, counter_value=None, eim_public_key_data=None, association_token=5)]
    )
    text = " ".join(problems)
    assert "eimId is mandatory" in text
    assert "counterValue is mandatory" in text
    assert "eimPublicKey or eimCertificate is mandatory" in text
    assert "invalidAssociationToken" in text
    assert any("repeats" in problem for problem in add_initial_eim_problems([_entry(), _entry()]))
    assert add_initial_eim_problems([]) != []


def test_script_starts_with_the_operator_preamble() -> None:
    request = encode_add_initial_eim_request([_entry()])
    steps = add_initial_eim_script(request)
    assert [step.apdu_hex for step in steps[:4]] == [
        "80AA000005A903840101",
        "0070000001",
        "01A4040010A0000005591010FFFFFFFF8900000100",
        "81E2910007BF640482020106",
    ]
    assert steps[4].apdu_hex == "81E29100" + format(len(request), "02X") + request.hex().upper()
    assert len(steps) == 5


def test_script_chains_a_long_request_in_255_byte_blocks() -> None:
    certificate, _key = make_certificate(TEST_EIM_ID)
    raw = der(certificate)
    entry = _entry(
        eim_public_key_data=KeyData(KEY_FORM_CERTIFICATE, raw),
        trusted_public_key_data_tls=KeyData(KEY_FORM_CERTIFICATE, raw),
    )
    request = encode_add_initial_eim_request([entry])
    blocks = add_initial_eim_script(request)[4:]
    assert len(request) > 255
    assert [step.apdu[:4].hex().upper() for step in blocks[:-1]] == [
        f"81E211{index:02X}" for index in range(len(blocks) - 1)
    ]
    assert blocks[-1].apdu[:4].hex().upper() == f"81E291{len(blocks) - 1:02X}"
    assert b"".join(step.apdu[5:] for step in blocks) == request
    assert all(step.apdu[4] == 0xFF for step in blocks[:-1])


def test_script_refuses_anything_but_an_add_initial_eim_request() -> None:
    with pytest.raises(ValueError):
        add_initial_eim_script(encode_euicc_memory_reset_request())


def test_verify_catches_a_request_that_does_not_carry_the_entry() -> None:
    entry = _entry()
    request = encode_add_initial_eim_request([entry])
    verify_add_initial_eim_request(request, [entry])
    tampered = bytearray(request)
    tampered[request.index(b"\x83\x01\x00") + 2] = 0x01
    with pytest.raises(ValueError, match="counterValue"):
        verify_add_initial_eim_request(bytes(tampered), [entry])
    with pytest.raises(ValueError, match="entries"):
        verify_add_initial_eim_request(request, [entry, entry])


def test_add_initial_eim_response_decoding() -> None:
    ok = decode_add_initial_eim_response(bytes.fromhex("BF5707A0058401050500"))
    assert ok.ok is True
    assert ok.entries == ("associationToken 5", "addOk")
    error = decode_add_initial_eim_response(bytes.fromhex("BF5703810102"))
    assert (error.ok, error.error_code, error.error_name) == (False, 2, "associatedEimAlreadyExists")
    assert decode_add_initial_eim_response(bytes.fromhex("BF570381017F")).error_name == "undefinedError"


def test_memory_reset_response_decoding() -> None:
    result = decode_euicc_memory_reset_response(bytes.fromhex("BF6409800100810101820101"))
    assert result.allows_add_initial_eim is True
    assert result.describe() == [
        "resetResult: ok (0)",
        "resetEimResult: nothingToDelete (1)",
        "resetImmediateEnableConfigResult: resetIECNotSupported (1)",
    ]
    assert decode_euicc_memory_reset_response(bytes.fromhex("BF6403800105")).allows_add_initial_eim is False
    empty = decode_euicc_memory_reset_response(bytes.fromhex("BF6400"))
    assert empty.reset_result is None
    assert empty.describe() == ["resetResult: absent"]


@pytest.mark.parametrize(
    "decoder",
    [decode_add_initial_eim_response, decode_euicc_memory_reset_response],
)
@pytest.mark.parametrize("data", [b"", b"\xBF", b"\xBF\x57", b"\xBF\x57\x05\xA0"])
def test_response_decoders_refuse_truncated_input(decoder, data: bytes) -> None:
    with pytest.raises(ValueError):
        decoder(data)


def test_infer_eim_id_type() -> None:
    assert infer_eim_id_type(TEST_EIM_ID) == 1
    assert infer_eim_id_type(TEST_EIM_FQDN) == 2
    assert infer_eim_id_type("eim-one") == 3
    assert infer_eim_id_type("192.0.2.4") == 3


def test_schema_decode_of_the_library_module_agrees() -> None:
    """asn1tools over the SGP.32 v1.3 module reads the bytes back and re-encodes them unchanged."""
    from Tools.Asn1TlvDecode import gsma_schema

    # Without the gitignored library asset the compiled schema is SGP.22 alone (pySim), which
    # declares none of these types; a clean checkout skips here.
    modules = gsma_schema.rsp_specification_status()["modules"]
    if not any(module.startswith("SGP.32 v1.3") for module in modules):
        pytest.skip("The SGP.32 v1.3 ASN.1 module of the specification library is not present.")
    certificate, _key = make_certificate(TEST_EIM_ID)
    entry = _entry(
        counter_value=200,
        eim_public_key_data=KeyData(KEY_FORM_CERTIFICATE, der(certificate)),
        trusted_public_key_data_tls=KeyData(KEY_FORM_PUBLIC_KEY, SPKI),
        eim_supported_protocol=("eimRetrieveHttps", "eimInjectCoaps"),
        euicc_ci_pk_id=bytes.fromhex("F54172"),
    )
    request = encode_add_initial_eim_request([entry])
    value = gsma_schema.decode_type("AddInitialEimRequest", request)
    row = value["eimConfigurationDataList"][0]
    assert row["eimId"] == TEST_EIM_ID
    assert row["counterValue"] == 200
    assert row["associationToken"] == -1
    assert row["eimPublicKeyData"][0] == "eimCertificate"
    assert row["trustedPublicKeyDataTls"][0] == "trustedEimPkTls"
    assert row["eimSupportedProtocol"] == (b"\x90", 4)
    assert gsma_schema.rsp_specification().encode("AddInitialEimRequest", value) == request
    reset = gsma_schema.decode_type("EuiccMemoryResetRequest", encode_euicc_memory_reset_request())
    assert reset["resetOptions"] == (b"\x06", 7)
    assert gsma_schema.decode_type("AddInitialEimResponse", bytes.fromhex("BF5703810102")) == (
        "addInitialEimError",
        2,
    )
