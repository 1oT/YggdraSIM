"""SGP.22 §5.7.13 ES10b.LoadCRL -- eUICC-side acceptance.

The simulator persists every CRL DER blob the RSP server pushes
into ``state.loaded_crls`` so reports / GUIs can introspect what
the eIM (or the SM-DP+) has revoked. The eUICC always replies
``ok(0)`` provided the request body is non-empty; an empty body
returns ``invalidSignature(2)``. Revocation enforcement is not
attempted today, but the persistence path lets a future enforcer
walk this list without touching transport.
"""

from __future__ import annotations

import unittest

from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimCardState
from SIMCARD.utils import find_first_tlv, read_tlv, tlv


def _make_sgp_logic() -> SgpLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901234",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    return SgpLogic(state)


class LoadCrlTests(unittest.TestCase):
    def test_non_empty_crl_is_persisted_and_returns_ok(self) -> None:
        logic = _make_sgp_logic()
        crl_body = bytes.fromhex("A0820102") + b"\x00" * 0x102
        request = tlv("BF35", crl_body)

        response, sw1, sw2 = logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertTrue(response.startswith(bytes.fromhex("BF35")))
        # 80 01 00 = ok(0)
        self.assertIn(b"\x80\x01\x00", response)
        self.assertEqual(len(logic.state.loaded_crls), 1)
        self.assertEqual(logic.state.loaded_crls[0], crl_body)

    def test_empty_body_returns_invalid_signature(self) -> None:
        logic = _make_sgp_logic()
        request = bytes.fromhex("BF3500")

        response, sw1, sw2 = logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # 81 01 02 = invalidSignature(2)
        self.assertIn(b"\x81\x01\x02", response)
        self.assertEqual(len(logic.state.loaded_crls), 0)

    def test_multiple_crls_accumulate_in_order(self) -> None:
        logic = _make_sgp_logic()

        first = tlv("BF35", b"\xA0\x02\x11\x22")
        second = tlv("BF35", b"\xA0\x02\x33\x44")
        third = tlv("BF35", b"\xA0\x04\xDE\xAD\xBE\xEF")

        for request in (first, second, third):
            _resp, sw1, sw2 = logic.handle_store_data(request)
            self.assertEqual((sw1, sw2), (0x90, 0x00))

        self.assertEqual(
            logic.state.loaded_crls,
            [
                b"\xA0\x02\x11\x22",
                b"\xA0\x02\x33\x44",
                b"\xA0\x04\xDE\xAD\xBE\xEF",
            ],
        )


if __name__ == "__main__":
    unittest.main()
