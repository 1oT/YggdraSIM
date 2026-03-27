__all__ = [
    "ASN1Registry",
    "CryptoEngine",
    "PayloadBuilder",
    "RelayHttpClientJsonHex",
    "SGP22Transport",
]


def __getattr__(name):
    if name == "ASN1Registry":
        from .asn1_registry import ASN1Registry
        return ASN1Registry
    if name == "CryptoEngine":
        from .crypto_engine import CryptoEngine
        return CryptoEngine
    if name == "PayloadBuilder":
        from .payload_builder import PayloadBuilder
        return PayloadBuilder
    if name in ("RelayHttpClientJsonHex", "SGP22Transport"):
        from .transport import RelayHttpClientJsonHex, SGP22Transport
        mapping = {
            "RelayHttpClientJsonHex": RelayHttpClientJsonHex,
            "SGP22Transport": SGP22Transport,
        }
        return mapping[name]
    raise AttributeError(name)
