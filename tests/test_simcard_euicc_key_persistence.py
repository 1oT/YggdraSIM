# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The simulated eUICC signs with the key its own certificate carries, in every process.

When the SGP.26 Variant O eUICC key cannot be read, a generated
SK.EUICC.ECDSA is kept in the eUICC store next to the certificate built from
it. A second engine on the same store stands in for another process: the
eUICC Package Results it signs verify against the certificate the first one
returned from GetCerts (SGP.32 v1.3 §2.11.2.1, p.42-43), and a stored
certificate of some other key is rebuilt rather than served.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from SCP11.eim_local.engine import codec
from SCP11.eim_local.psmo_builders import build_psmo
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimEimEntry

GET_CERTS = bytes.fromhex("BF5600")
EIM_ID = "1.3.6.1.4.1.32473.999.10.124"


def _point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


class EuiccKeyPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "simcard"
        (self.root / "profile_store").mkdir(parents=True, exist_ok=True)

    def _engine(self) -> SimulatedSimCardEngine:
        engine = SimulatedSimCardEngine(
            euicc_store_root=str(self.root),
            profile_store_path=str(self.root / "profile_store"),
            private=True,
        )
        # The generated-key path, whether or not the SGP.26 key is readable here.
        engine.sgp._builtin_euicc_private_key = None
        return engine

    def _certificate(self, engine: SimulatedSimCardEngine) -> bytes:
        response, _sw1, _sw2 = engine.sgp.handle_store_data(GET_CERTS)
        return codec.decode_get_certs_response(response)[1]

    def test_a_second_engine_signs_results_the_first_certificate_verifies(self) -> None:
        first = self._engine()
        certificate = self._certificate(first)
        second = self._engine()
        self.assertEqual(self._certificate(second), certificate)
        self.assertEqual(
            _point(codec.public_key_from_certificate(certificate)),
            _point(second.sgp._euicc_private_key.public_key()),
        )
        eim_key = ec.generate_private_key(ec.SECP256R1())
        second.state.eim_entries = [
            SimEimEntry(
                eim_id=EIM_ID,
                eim_fqdn="eim.example.test",
                eim_id_type=1,
                counter_value=0,
                association_token=0,
                supported_protocol_bits=[0],
                euicc_ci_pkid=bytes(second.state.root_ci_pkid),
                indirect_profile_download=True,
                eim_public_key_data=codec.public_key_der(eim_key),
                trusted_tls_public_key_data=codec.public_key_der(eim_key),
            )
        ]
        signed = codec.build_euicc_package_signed(
            eim_id=EIM_ID, eid=second.state.eid, counter_value=1, transaction_id=b"\x01\x02",
            kind=codec.PACKAGE_PSMO, items=build_psmo({"operation": "list_profile_info"}),
        )
        request = codec.build_euicc_package_request(signed, codec.sign_raw(eim_key, codec.signature_input(signed, 0)))
        answer, _sw1, _sw2 = second.sgp.handle_store_data(request)
        result = codec.decode_euicc_package_result(answer)
        self.assertEqual(result.kind, "result")
        self.assertTrue(codec.verify_euicc_package_result(result, certificate, 0))

    def test_a_stored_certificate_of_another_key_is_rebuilt(self) -> None:
        engine = self._engine()
        own = _point(engine.sgp._euicc_private_key.public_key())
        # What a store written before the key was kept holds: the simulator's
        # own certificate, built from a key no process has any more.
        lost = ec.generate_private_key(ec.SECP256R1())
        engine.state.euicc_certificate_der = engine.sgp._build_self_signed_certificate(
            common_name="Simulated eUICC", private_key=lost
        )
        self.assertEqual(_point(codec.public_key_from_certificate(self._certificate(engine))), own)
        again = self._engine()
        self.assertEqual(_point(again.sgp._euicc_private_key.public_key()), own)
        self.assertEqual(_point(codec.public_key_from_certificate(self._certificate(again))), own)

    def test_a_configured_certificate_is_served_as_given(self) -> None:
        engine = self._engine()
        override = engine.sgp._build_self_signed_certificate(
            common_name="Override eUICC", private_key=ec.generate_private_key(ec.SECP256R1())
        )
        engine.state.euicc_certificate_der = override
        self.assertEqual(self._certificate(engine), override)


if __name__ == "__main__":
    unittest.main()
