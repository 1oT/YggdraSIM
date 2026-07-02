# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 shared ASN.1 registry: common SGP.22 OID-to-codec map shared across live, relay, and test variants."""
try:
    from ..asn1_registry import *
except ImportError:
    from SCP11.asn1_registry import *
