# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_asn1_value import parse_asn1_value_profile
from Tools.ProfilePackage.saip_hex_template import substitute_inline_placeholders
from Tools.ProfilePackage.saip_json_codec import ensure_workspace_pysim_on_path
from Tools.ProfilePackage.saip_pysim_compat import (
    install_base_df_path_compatibility,
    install_lossless_security_domain_encoding,
)
from yggdrasim_common.gui_server.actions.saip import _load_package_from_path

_SD_ASN_SOURCE = """\
securityDomain ProfileElement ::= securityDomain :
{
  sd-Header { mandated NULL, identification 1 },
  instance
  {
    applicationLoadPackageAID 'A0000001515350'H,
    classAID 'A000000151535041'H,
    instanceAID 'A000000151000000'H,
    applicationPrivileges '82DC00'H,
    lifeCycleState '0F'H,
    applicationSpecificParametersC9 '81028000810281048201F08701F0'H,
    applicationParameters
    {
      uiccToolkitApplicationSpecificParametersField
        '01001000000201120300000000'H
    }
  },
  keyList
  {
    {
      keyUsageQualifier '38'H,
      keyAccess '01'H,
      keyIdentifier '01'H,
      keyVersionNumber '03'H,
      keyCounterValue '0000000000'H,
      keyCompontents
      {
        {
          keyType '88'H,
          keyData '[SCP80_KICBINARY16]'H
        }
      }
    },
    {
      keyUsageQualifier '34'H,
      keyAccess 'FF'H,
      keyIdentifier '02'H,
      keyVersionNumber '01'H,
      keyCompontents
      {
        {
          keyType '88'H,
          keyData '11111111111111111111111111111111'H
        }
      }
    }
  }
}
"""


class LosslessSecurityDomainEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(cls.workspace_root)

    def test_installer_is_idempotent(self) -> None:
        from pySim.esim.saip import FsProfileElement, ProfileElementSD

        install_lossless_security_domain_encoding()
        wrapped = ProfileElementSD._pre_encode
        install_base_df_path_compatibility()
        wrapped_add_file = FsProfileElement.add_file

        self.assertFalse(install_lossless_security_domain_encoding())
        self.assertIs(ProfileElementSD._pre_encode, wrapped)
        self.assertFalse(install_base_df_path_compatibility())
        self.assertIs(FsProfileElement.add_file, wrapped_add_file)

    def test_asn_source_and_varder_roundtrip_keep_optional_key_fields(self) -> None:
        parsed_asn = parse_asn1_value_profile(
            _SD_ASN_SOURCE,
            workspace_root=self.workspace_root,
        )
        asn_der = parsed_asn.pes.to_der()

        self.assertEqual(len(asn_der), 169)
        self.assertEqual(len(parsed_asn.inline_placeholder_records), 1)
        record = parsed_asn.inline_placeholder_records[0]
        varder_token = "{SCP80_KICBINARY16}"
        varder_text = (
            asn_der.hex()
            .upper()
            .replace(
                record.sentinel_hex,
                varder_token,
            )
        )
        self.assertIn(varder_token, varder_text)

        substituted_varder, _records = substitute_inline_placeholders(varder_text)
        varder_der = bytes.fromhex(substituted_varder)
        self.assertEqual(varder_der, asn_der)

        with tempfile.TemporaryDirectory() as temp_dir:
            varder_path = Path(temp_dir) / "security-domain.varder"
            varder_path.write_bytes(b"\xef\xbb\xbf" + varder_text.encode("ascii"))
            parsed_varder = _load_package_from_path(varder_path)

        self.assertEqual(parsed_varder["pes"].to_der(), asn_der)
        sd = parsed_varder["pes"].pe_list[0].decoded
        self.assertEqual(sd["keyList"][0]["keyAccess"], b"\x01")
        self.assertEqual(
            sd["keyList"][0]["keyCounterValue"],
            b"\x00\x00\x00\x00\x00",
        )
        self.assertEqual(sd["keyList"][1]["keyAccess"], b"\xff")
        self.assertNotIn("keyCounterValue", sd["keyList"][1])


if __name__ == "__main__":
    unittest.main()
