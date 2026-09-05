# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP11 shared ASN.1 registry: common SGP.22 OID-to-codec map shared across live, relay, and test variants."""

from SCP11 import asn1_registry as _impl
from SCP11.shared.compat_exports import reexport_public


__all__ = reexport_public(_impl, globals())
