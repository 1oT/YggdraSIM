import unittest

from Tools.ProfilePackage.saip_pysim_decode import pysim_try_decode_ef


class SaipPysimDecodeTests(unittest.TestCase):
    def test_iccid_mf_via_pysim(self) -> None:
        hx = "9897012345678901F0F0F0F0F0F0F0FF"
        lines, dec = pysim_try_decode_ef("2FE2", "mf", hx)
        self.assertIsNotNone(lines)
        self.assertIsNotNone(dec)
        blob = "\n".join(lines or []).lower()
        self.assertIn("iccid", blob)
        self.assertIn("iccid", str(dec).lower())

    def test_duplicate_fid_prefers_saip_pe(self) -> None:
        """4F01 exists under DF.5GS and DF.SAIP; df-saip section should prefer SAIP SUCI template."""
        hx = (
            "A00401010000A14A80010A81204E858C4D49D1343E6181284C47CA721730C98742CB7C6182D2E8126E08088D3680010B8120"
            "D1BC365F4997D17CE4374E72181431CBFEBA9E1B98D7618F79D48561B144672A"
        )
        lines, dec = pysim_try_decode_ef("4F01", "df-saip", hx)
        self.assertIsNotNone(dec)
        self.assertIn("prot_scheme", str(dec).lower())
        joined = "\n".join(lines or [])
        self.assertIn("SUCI", joined)


if __name__ == "__main__":
    unittest.main()
