# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

__all__ = [
    "ASN1Registry",
    "CryptoEngine",
    "PayloadBuilder",
    "SGP22Transport",
    "safe_parse",
    "reset_safe_parse_rollup",
    "safe_parse_rollup_snapshot",
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
    if name == "SGP22Transport":
        from .transport import SGP22Transport
        mapping = {
            "SGP22Transport": SGP22Transport,
        }
        return mapping[name]
    if name in ("safe_parse", "reset_safe_parse_rollup", "safe_parse_rollup_snapshot"):
        from .safe_parse import (
            reset_safe_parse_rollup,
            safe_parse,
            safe_parse_rollup_snapshot,
        )
        mapping = {
            "safe_parse": safe_parse,
            "reset_safe_parse_rollup": reset_safe_parse_rollup,
            "safe_parse_rollup_snapshot": safe_parse_rollup_snapshot,
        }
        return mapping[name]
    raise AttributeError(name)
