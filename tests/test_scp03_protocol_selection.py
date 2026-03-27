import unittest

from SCP03.logic.gp import GlobalPlatformManager


class DummyTransport:
    def __init__(self):
        self.session = None


class GlobalPlatformProtocolTests(unittest.TestCase):
    def setUp(self):
        self.manager = GlobalPlatformManager(
            DummyTransport(),
            {
                "scp03_kenc": "00112233445566778899AABBCCDDEEFF",
                "scp03_kmac": "00112233445566778899AABBCCDDEEFF",
                "scp03_dek": "00112233445566778899AABBCCDDEEFF",
                "scp03_kvn": "30",
                "scp02_enc": "11223344556677889900AABBCCDDEEFF",
                "scp02_mac": "11223344556677889900AABBCCDDEEFF",
                "scp02_dek": "11223344556677889900AABBCCDDEEFF",
                "scp02_kvn": "20",
                "aid": "A0000005591010FFFFFFFF8900000100",
            },
        )

    def test_default_active_protocol_is_scp03(self):
        self.assertEqual(self.manager.get_active_protocol_name(), "SCP03")
        self.assertEqual(self.manager.get_active_kvn_hex(), "30")

    def test_protocol_key_field_mapping(self):
        self.assertEqual(
            self.manager.get_config_key_fields_for_protocol("SCP03"),
            ("scp03_kenc", "scp03_kmac", "scp03_dek", "scp03_kvn"),
        )
        self.assertEqual(
            self.manager.get_config_key_fields_for_protocol("SCP02"),
            ("scp02_enc", "scp02_mac", "scp02_dek", "scp02_kvn"),
        )


if __name__ == "__main__":
    unittest.main()
