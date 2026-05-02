import unittest


class Scp11PackageLayoutTests(unittest.TestCase):
    def test_relay_namespace_imports(self):
        from SCP11.relay import SGP22Client, SGP22Orchestrator, SGPConfig

        self.assertIsNotNone(SGP22Client)
        self.assertIsNotNone(SGP22Orchestrator)
        self.assertIsNotNone(SGPConfig)

    def test_shared_namespace_imports(self):
        from SCP11.shared import ASN1Registry, CryptoEngine, PayloadBuilder, SGP22Transport

        self.assertIsNotNone(ASN1Registry)
        self.assertIsNotNone(CryptoEngine)
        self.assertIsNotNone(PayloadBuilder)
        self.assertIsNotNone(SGP22Transport)


if __name__ == "__main__":
    unittest.main()
