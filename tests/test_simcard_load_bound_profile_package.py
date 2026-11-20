# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10b.LoadBoundProfilePackage of the simulated eUICC: the Profile Package and section checks.

A Profile Package outside the SAIP V3.4.1 framing (§8.2 the header first, §8.10 PE-End last)
ends in installFailedDueToPEProcessingError(12) with the interpreter's invalid-request-format(5)
in ppiResponse (SGP.22 v3.1 §2.5.6.1), and a member that runs past the declared length of its
section (§2.5.5) in bspStructureError(7). Each test issues its own PKI, so none needs the
SGP.26 bundle.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import serialization

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.saip_profile import check_profile_package_framing
from SIMCARD.sgp import SgpLogic
from SIMCARD.utils import read_tlv, tlv
from tests.test_simcard_backend import build_minimal_saip_upp, build_signed_bpp_segments, compile_saip_asn1
from tests.test_simcard_server_authentication import (
    DP_AUTH_ROLE,
    DP_PB_ROLE,
    TRANSACTION_ID,
    _authenticate_server,
    _ok_value,
    _prepare_download,
    _root_ca,
    _server_certificate,
)

ICCID = "89881111111111111999"
IMSI = "001010123456789"
IMPI = "bpp@example.test"
PROFILE_NAME = "BPP Profile"


def _minimal_upp() -> bytes:
    return build_minimal_saip_upp(iccid=ICCID, imsi=IMSI, impi=IMPI, profile_name=PROFILE_NAME)


def _profile_elements(upp: bytes) -> list[bytes]:
    elements: list[bytes] = []
    offset = 0
    while offset < len(upp):
        _, _, raw, offset = read_tlv(upp, offset)
        elements.append(raw)
    return elements


def _members(value: bytes) -> dict[bytes, bytes]:
    members: dict[bytes, bytes] = {}
    offset = 0
    while offset < len(value):
        tag, member, _, offset = read_tlv(value, offset)
        members[tag] = member
    return members


def _final_result(pir: bytes) -> tuple[bytes, dict[bytes, bytes]]:
    """finalResult [2] of a ProfileInstallationResult: its CHOICE tag and members by tag."""
    pir_tag, pir_value, _, _ = read_tlv(pir, 0)
    if pir_tag != bytes.fromhex("BF37"):
        raise AssertionError(f"expected a ProfileInstallationResult, got {pir.hex().upper()}")
    _, result_data, _, _ = read_tlv(pir_value, 0)
    choice_tag, choice_value, _, _ = read_tlv(_members(result_data)[b"\xA2"], 0)
    return choice_tag, _members(choice_value)


class ProfilePackageFramingTests(unittest.TestCase):
    def test_minimal_profile_package_is_accepted(self) -> None:
        upp = _minimal_upp()

        check_profile_package_framing(upp)
        # The tags the check reads are the ones the compiled SAIP module encodes.
        elements = _profile_elements(upp)
        self.assertEqual((elements[0][:1], elements[-1][:1]), (b"\xA0", b"\xAA"))

    def test_decode_boundaries_are_refused(self) -> None:
        for raw in (b"", b"\xA0", b"\xA0\x82\x01", b"\xA0\x05\x01", _minimal_upp()[:-1], _minimal_upp() + b"\x00"):
            with self.subTest(raw=raw[:8].hex()):
                with self.assertRaises(ValueError):
                    check_profile_package_framing(raw)

    def test_misplaced_or_repeated_header_and_end_are_refused(self) -> None:
        elements = _profile_elements(_minimal_upp())
        cases = {
            "no header": elements[1:],
            "header second": [elements[1], elements[0], *elements[2:]],
            "two headers": [elements[0], *elements],
            "no end": elements[:-1],
            "two ends": [*elements, elements[-1]],
        }
        for label, case in cases.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    check_profile_package_framing(b"".join(case))

    def test_invalid_request_format_ppi_response_decodes_as_euicc_response(self) -> None:
        decoded = compile_saip_asn1().decode("EUICCResponse", SgpLogic.PPI_RESPONSE_INVALID_REQUEST_FORMAT)

        self.assertEqual(decoded["peStatus"], [{"status": 5}])
        self.assertIn("profileInstallationAborted", decoded)


class LoadBoundProfilePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = build_default_state()
        ci, ci_key = _root_ca("Test CI")
        self.state.ci_certificates = [ci.public_bytes(serialization.Encoding.DER)]
        self.logic = SgpLogic(self.state)
        self.dpauth_der, self.dpauth_key = _server_certificate(ci, ci_key, role_oid=DP_AUTH_ROLE)
        self.dppb_der, self.dppb_key = _server_certificate(ci, ci_key, role_oid=DP_PB_ROLE)

    def _store_data(self, payload: bytes) -> bytes:
        response, sw1, sw2 = self.logic.handle_store_data(payload)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response

    def _segments(self, **kwargs: object) -> dict:
        """Open an RSP Session up to PrepareDownload and bind a BPP to it."""
        _, value, _, _ = read_tlv(self._store_data(bytes.fromhex("BF2E00")), 0)
        _, challenge, _, _ = read_tlv(value, 0)
        request = _authenticate_server(
            challenge,
            self.dpauth_der,
            self.dpauth_key,
            ci_pkid=bytes(self.state.root_ci_pkid),
        )
        ok_value = _ok_value(self._store_data(request))
        _, _, _, offset = read_tlv(ok_value, 0)
        _, euicc_signature1, _, _ = read_tlv(ok_value, offset)
        prepared = _ok_value(self._store_data(_prepare_download(euicc_signature1, self.dppb_der, self.dppb_key)))
        _, euicc_signed2, _, _ = read_tlv(prepared, 0)
        _, _, _, offset = read_tlv(euicc_signed2, 0)
        _, _, euicc_otpk_raw, _ = read_tlv(euicc_signed2, offset)
        return build_signed_bpp_segments(
            transaction_id=TRANSACTION_ID,
            euicc_otpk_raw=euicc_otpk_raw,
            eid_hex=self.state.eid,
            cert_private_key=self.dppb_key,
            iccid=ICCID,
            provider_name="BPP Provider",
            profile_name=PROFILE_NAME,
            imsi=IMSI,
            impi=IMPI,
            **kwargs,
        )

    def _load_up_to_a3(self, segments: dict) -> None:
        for name in ("bootstrap", "a0", "a1"):
            self.assertEqual(self._store_data(segments[name]), b"", name)

    def _installed(self) -> bool:
        return any(profile.iccid == ICCID for profile in self.state.profiles)

    def _assert_failed(self, pir: bytes, bpp_command_id: int, error_reason: int) -> dict[bytes, bytes]:
        choice_tag, members = _final_result(pir)
        self.assertEqual(choice_tag, b"\xA1")
        self.assertEqual((members[b"\x80"], members[b"\x81"]), (bytes([bpp_command_id]), bytes([error_reason])))
        self.assertFalse(self._installed())
        self.assertFalse(self.state.sgp_session.prepare_download_done)
        return members

    def test_profile_package_in_saip_framing_installs(self) -> None:
        segments = self._segments()
        self._load_up_to_a3(segments)

        choice_tag, _ = _final_result(self._store_data(segments["a3"]))

        self.assertEqual(choice_tag, b"\xA0")
        self.assertTrue(self._installed())

    def test_profile_package_outside_saip_framing_is_pe_processing_error(self) -> None:
        elements = _profile_elements(_minimal_upp())
        cases = {
            "garbage": b"garbage",
            "truncated": b"".join(elements)[:-1],
            "no end": b"".join(elements[:-1]),
            "header second": b"".join([elements[1], elements[0], *elements[2:]]),
        }
        for label, upp in cases.items():
            with self.subTest(label):
                segments = self._segments(upp_payload=upp)
                self._load_up_to_a3(segments)

                members = self._assert_failed(self._store_data(segments["a3"]), 5, 12)

                self.assertEqual(members[b"\x82"], SgpLogic.PPI_RESPONSE_INVALID_REQUEST_FORMAT)

    def test_a3_member_running_past_the_declared_section_length_is_bsp_structure_error(self) -> None:
        segments = self._segments()
        self._load_up_to_a3(segments)
        member = segments["a3_members"][0]
        short = tlv("A3", bytes(len(member) - 3))
        self.assertEqual(self._store_data(short[: len(short) - (len(member) - 3)]), b"")

        self._assert_failed(self._store_data(member), 5, 7)

    def test_a3_members_filling_the_declared_section_length_install(self) -> None:
        segments = self._segments()
        self._load_up_to_a3(segments)
        member = segments["a3_members"][0]
        self.assertEqual(self._store_data(tlv("A3", member)[: -len(member)]), b"")

        choice_tag, _ = _final_result(self._store_data(member))

        self.assertEqual(choice_tag, b"\xA0")
        self.assertTrue(self._installed())


if __name__ == "__main__":
    unittest.main()
