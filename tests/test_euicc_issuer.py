import unittest

from SCP03.logic.sgp22 import Sgp22Manager
from yggdrasim_common.euicc_issuer import (
    format_ecasd_issuer_display,
    infer_ecasd_issuer_from_eid,
    infer_ecasd_issuer_identity,
)


class _IssuerProbeTransport:
    def transmit(self, apdu_hex: str, silent: bool = False):
        del silent
        command = str(apdu_hex or "").strip().upper()
        if command == "00A4040010A0000005591010FFFFFFFF8900000200":
            return b"\x6F\x00", 0x90, 0x00
        if command == "00CA004200":
            return bytes.fromhex("420489049032"), 0x90, 0x00
        return b"", 0x6A, 0x88


class EuiccIssuerInferenceTests(unittest.TestCase):
    def test_infer_identity_from_known_ecasd_number(self) -> None:
        identity = infer_ecasd_issuer_identity("89049032")

        self.assertEqual(identity["issuer_number"], "89049032")
        self.assertEqual(identity["issuer_name"], "Giesecke+Devrient")

    def test_infer_identity_from_eid_prefix(self) -> None:
        identity = infer_ecasd_issuer_from_eid("89044045930000000000001492294428")

        self.assertEqual(identity["issuer_number"], "89044045")
        self.assertEqual(identity["issuer_name"], "Kigen")

    def test_format_display_falls_back_to_number(self) -> None:
        display = format_ecasd_issuer_display("", "89086029")

        self.assertEqual(display, "89086029")

    def test_sgp22_manager_reads_ecasd_issuer_number(self) -> None:
        manager = Sgp22Manager(_IssuerProbeTransport())

        identity = manager.get_ecasd_issuer_identity()

        self.assertEqual(identity["issuer_number"], "89049032")
        self.assertEqual(identity["issuer_name"], "Giesecke+Devrient")


if __name__ == "__main__":
    unittest.main()
