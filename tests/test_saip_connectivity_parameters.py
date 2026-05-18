# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_connectivity_parameters``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_connectivity_parameters as C


class CatalogTests(unittest.TestCase):

    def test_catalog_known_bearers(self) -> None:
        catalog = C.bearer_catalog()
        bearers = {entry["bearer"] for entry in catalog}
        self.assertEqual(bearers, {"sms", "cat_tp", "https"})


class SmsRoundTripTests(unittest.TestCase):

    def test_dialing_number_round_trip(self) -> None:
        bearers = [{
            "bearer": "sms",
            "dialing_number": {"ton": "international", "npi": "isdn", "digits": "12025550100"},
            "pid_hex": "7F",
            "dcs_hex": "F6",
        }]
        encoded = C.encode_connectivity_parameters(bearers)
        decoded = C.decode_connectivity_parameters(encoded)
        out = decoded["bearers"][0]
        self.assertEqual(out["bearer"], "sms")
        self.assertEqual(out["dialing_number"]["ton"], "international")
        self.assertEqual(out["dialing_number"]["npi"], "isdn")
        self.assertEqual(out["dialing_number"]["digits"], "12025550100")
        self.assertEqual(out["pid_hex"], "7F")
        self.assertEqual(out["dcs_hex"], "F6")


class HttpsRoundTripTests(unittest.TestCase):

    def test_https_block_round_trip(self) -> None:
        bearers = [{
            "bearer": "https",
            "bearer_description_hex": "020188",
            "network_access_name": {"text": "lab.example.test"},
            "user_login": {"text": "op"},
            "user_password": {"text": "pw"},
            "server_uri": "https://eim.example.test/sgp32",
        }]
        encoded = C.encode_connectivity_parameters(bearers)
        decoded = C.decode_connectivity_parameters(encoded)
        out = decoded["bearers"][0]
        self.assertEqual(out["bearer"], "https")
        self.assertEqual(out["network_access_name"], {"text": "lab.example.test"})
        self.assertEqual(out["server_uri"], "https://eim.example.test/sgp32")


class CatTpRoundTripTests(unittest.TestCase):

    def test_cat_tp_minimal_round_trip(self) -> None:
        bearers = [{
            "bearer": "cat_tp",
            "bearer_description_hex": "010101",
            "network_access_name": {"text": "aps.example.test"},
        }]
        encoded = C.encode_connectivity_parameters(bearers)
        decoded = C.decode_connectivity_parameters(encoded)
        out = decoded["bearers"][0]
        self.assertEqual(out["bearer"], "cat_tp")
        self.assertEqual(out["network_access_name"], {"text": "aps.example.test"})


class UnknownBearerTests(unittest.TestCase):

    def test_unknown_bearer_round_trip(self) -> None:
        bearers = [{"bearer": "unknown", "tag_hex": "AF", "value_hex": "AABBCC"}]
        encoded = C.encode_connectivity_parameters(bearers)
        decoded = C.decode_connectivity_parameters(encoded)
        self.assertEqual(decoded["bearers"][0]["bearer"], "unknown")
        self.assertEqual(decoded["bearers"][0]["tag_hex"], "AF")
        self.assertEqual(decoded["bearers"][0]["value_hex"], "AABBCC")

    def test_unknown_bearer_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            C.encode_connectivity_parameters([{"bearer": "nonsense"}])


if __name__ == "__main__":
    unittest.main()
