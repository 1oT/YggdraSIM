# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Wave D Pass A — EAP / USIM / TELECOM / common residual EF decoders.

For every EF promoted from the generic opaque pass-through catalog we
verify three invariants:

1. Routing: the ``ef-*`` token dispatches to a semantic decoder (not
   the generic opaque catalog fallback).
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: ``encode_decoded_roundtrip_ef_content`` returns the exact
   input bytes via the ``hex`` field surfaced alongside the named keys.

Spec references:
  ef-imsi            TS 31.102 §4.2.2   (USIM IMSI)
  ef-arr-usim        TS 102 221 §9.4    (Access Rule Reference)
  ef-threshold       TS 31.102 §4.4.3.7 (Threshold)
  ef-eapkeys         TS 102 310 §5.2.2  (EAP MSK/EMSK)
  ef-eapstatus       TS 102 310 §5.2.2  (EAP Status)
  ef-reid            TS 102 310 §5.2.2  (EAP Re-authentication ID)
  ef-model           3GPP2 C.S0023 §3.4.61
  ef-call-count      3GPP2 C.S0023 §3.4.72
  ef-call-prompt     3GPP2 C.S0023 §3.4.55
  ef-applabels       3GPP2 C.S0023 §3.4.60
  ef-auth-capability 3GPP2 C.S0023 §3.4.51
  ef-acp             3GPP2 C.S0023 §3.4.11
  ef-atc             3GPP2 C.S0023 §3.4.14
  ef-namlock         3GPP2 C.S0065 §5.2.33
  ef-usgind          3GPP2 C.S0023 §3.4.67
  ef-dgc             3GPP2 C.S0023 §3.4.57
  ef-term            3GPP2 C.S0023 §3.4.68
  ef-hidden-key      3GPP2 C.S0023 §3.4.75
  ef-csspr           3GPP2 C.S0023 §3.4.37
  ef-rma             TS 31.102 (vendor-specific RMA)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_D_PASS_A_TOKENS: tuple[str, ...] = (
    "ef-imsi",
    "ef-arr-usim",
    "ef-threshold",
    "ef-eapkeys",
    "ef-eapstatus",
    "ef-reid",
    "ef-model",
    "ef-call-count",
    "ef-call-prompt",
    "ef-applabels",
    "ef-auth-capability",
    "ef-acp",
    "ef-atc",
    "ef-namlock",
    "ef-usgind",
    "ef-dgc",
    "ef-term",
    "ef-hidden-key",
    "ef-csspr",
    "ef-rma",
)


def _roundtrip(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=hex_input,
    )
    assert decoded is not None, f"{token} was not routed to a semantic decoder"
    if "hex" in decoded:
        hex_field = str(decoded["hex"])
        assert hex_field.upper() == hex_input.upper(), (
            f"{token} semantic decoder did not preserve input hex"
        )
    encoded = encode_decoded_roundtrip_ef_content(
        token, decoded, target_length=len(hex_input) // 2,
    )
    assert encoded is not None, f"{token} has no registered encoder"
    assert encoded.hex().upper() == hex_input.upper(), (
        f"{token} roundtrip mismatch: "
        f"in={hex_input.upper()} out={encoded.hex().upper()}"
    )
    return decoded


class TestImsi:
    def test_imsi_decoded_with_hex(self) -> None:
        # Packed IMSI: length byte 08, then BCD "910132547698010"
        # (nibble-swapped form "1910325476981 0" style) – we use a
        # well-formed TS 31.102 layout (0x08 + 8 bytes).
        hex_input = "0891103254769810F0"
        decoded = _roundtrip("ef-imsi", hex_input)
        assert decoded["format"] == "USIM IMSI"
        assert "imsi" in decoded
        assert decoded["length"] == 9


class TestArrUsim:
    def test_arr_tlv(self) -> None:
        # A4 06 [ 80 01 03 97 01 AA ] — AM=0x03 + never
        hex_input = "A4068001039701AA"
        decoded = _roundtrip("ef-arr-usim", hex_input)
        assert decoded["format"] == "Access Rule Reference (USIM)"
        items = decoded["items"]
        assert items[0]["tag"] == "A4"


class TestThreshold:
    def test_threshold_three_byte_per_ts_31_102(self) -> None:
        # TS 31.102 §4.2.52: EF.THRESHOLD is 3 bytes carrying the MSB of
        # the maximum allowed STARTCS/STARTPS (hex-integer, unused nibbles
        # coded as F). Round-2 Pass 1 replaced the earlier 1-byte shim
        # with the spec-accurate 3-byte decoder.
        decoded = _roundtrip("ef-threshold", "000005")
        assert decoded["format"] == "Maximum START value"
        assert decoded["maxStart"] == 5
        assert decoded["hex"] == "000005"


class TestEapKeysStatusReid:
    def test_eapkeys_tlvs(self) -> None:
        # 80 04 <MSK> 81 04 <EMSK>
        hex_input = "80041020304081040A0B0C0D"
        decoded = _roundtrip("ef-eapkeys", hex_input)
        assert decoded["format"] == "EAP Keys"
        tags = [item["tag"] for item in decoded["items"]]
        assert tags == ["80", "81"]

    def test_eapstatus_mapped(self) -> None:
        decoded = _roundtrip("ef-eapstatus", "02")
        assert decoded["statusByte"] == "0x02"
        assert "successfully" in decoded["statusLabel"].lower()

    def test_reid_ber_tlv(self) -> None:
        hex_input = "80047573723A"
        decoded = _roundtrip("ef-reid", hex_input)
        assert decoded["format"] == "EAP Re-authentication ID"


class TestModelAndCallCounters:
    def test_model_ascii(self) -> None:
        hex_input = "4D6F64656C2D58"
        decoded = _roundtrip("ef-model", hex_input)
        assert decoded["format"] == "Device Model"
        assert decoded["model"] == "Model-X"

    def test_call_count_big_endian(self) -> None:
        decoded = _roundtrip("ef-call-count", "01FE")
        assert decoded["callCount"] == 0x01FE

    def test_call_prompt_flag(self) -> None:
        decoded = _roundtrip("ef-call-prompt", "01")
        assert decoded["callPromptEnabled"] is True


class TestAnnotatedOpaqueCsimResidualEfs:
    @pytest.mark.parametrize(
        ("token", "expected_format"),
        [
            ("ef-applabels", "CSIM Application Labels"),
            ("ef-auth-capability", "Authentication Capability"),
            ("ef-acp", "Access Channel Parameters"),
            ("ef-atc", "Access Terminal Class"),
            ("ef-namlock", "NAM Lock"),
            ("ef-usgind", "Usage Indicator"),
            ("ef-dgc", "Data Generic Configuration"),
            ("ef-term", "Terminal Capability (CSIM)"),
            ("ef-hidden-key", "Hidden Key"),
            ("ef-csspr", "CSSPR"),
            ("ef-rma", "Remote Management Application"),
        ],
    )
    def test_annotated_opaque(self, token: str, expected_format: str) -> None:
        hex_input = "01020304"
        decoded = _roundtrip(token, hex_input)
        assert decoded["format"] == expected_format
        assert decoded["hex"] == hex_input.upper()
        assert "specReference" in decoded


def test_every_wave_d_pass_a_ef_has_semantic_route() -> None:
    # Ensure each Pass A token dispatches to a format-bearing decoder
    # (i.e. not the generic opaque catalog fallback).
    probes: dict[str, str] = {
        "ef-imsi": "0891103254769810F0",
        "ef-arr-usim": "A4078001039701AA",
        "ef-threshold": "05",
        "ef-eapkeys": "800410203040",
        "ef-eapstatus": "02",
        "ef-reid": "80047573723A",
        "ef-model": "4D6F64656C2D58",
        "ef-call-count": "01FE",
        "ef-call-prompt": "01",
        "ef-applabels": "01020304",
        "ef-auth-capability": "01020304",
        "ef-acp": "01020304",
        "ef-atc": "01020304",
        "ef-namlock": "01020304",
        "ef-usgind": "01020304",
        "ef-dgc": "01020304",
        "ef-term": "01020304",
        "ef-hidden-key": "01020304",
        "ef-csspr": "01020304",
        "ef-rma": "01020304",
    }
    assert set(probes.keys()) == set(_WAVE_D_PASS_A_TOKENS)
    for token, hex_input in probes.items():
        decoded = _decode_known_ef_payload(
            ef_key=token, fid=None, hex_clean=hex_input,
        )
        assert decoded is not None, f"{token} is not routed"
        fmt = decoded.get("format")
        assert fmt, f"{token} has no format"
        # Generic catalog labels are of the shape "Generic opaque EF ...".
        # Data Generic Configuration is a spec-defined name, so we match
        # on the "Generic opaque" prefix rather than the bare word.
        assert "Generic opaque" not in str(fmt), (
            f"{token} fell back to generic catalog: format={fmt!r}"
        )
