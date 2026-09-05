# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Presence check for the SGP.26 reference certificates.

The bundle is GSMA material: ``.gitignore`` excludes ``*.der`` while the
``.cnf`` files beside them are tracked, so the directory tree exists on a
checkout that holds no certificates at all. A test that guards on the
directory therefore fails on a missing fixture instead of skipping, which
is what CI reported for two suites.

The guard probes the exact files a caller reads. Encrypted checkouts stay
covered: ``read_secret_file_bytes`` decrypts in place rather than reading
a sibling, so a PGP-wrapped certificate occupies the same path.
"""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

SGP26_VALID_ROOT = (
    _REPO_ROOT / "SCP11" / "SGP.26_test_Certs" / "Valid Test Cases"
)
_VARIANT_O_SMDPP = SGP26_VALID_ROOT / "Variant O" / "SM-DP+"

# The Variant O NIST auth/pb pair, which is what both suites resolve.
SGP26_REQUIRED_FILES: tuple[Path, ...] = (
    _VARIANT_O_SMDPP / "SM_DPauth" / "CERT_S_SM_DPauth_VARO_SIG_NIST.der",
    _VARIANT_O_SMDPP / "SM_DPauth" / "SK_S_SM_DPauth_SIG_NIST.pem",
    _VARIANT_O_SMDPP / "SM_DPpb" / "CERT_S_SM_DPpb_VARO_SIG_NIST.der",
    _VARIANT_O_SMDPP / "SM_DPpb" / "SK_S_SM_DPpb_SIG_NIST.pem",
)


def sgp26_bundle_available() -> bool:
    """Report whether every file the suites read is present."""
    return all(path.is_file() for path in SGP26_REQUIRED_FILES)


def require_sgp26_bundle() -> Path:
    """Return the bundle root, or skip when it is not populated."""
    missing = [path for path in SGP26_REQUIRED_FILES if not path.is_file()]
    if len(missing) > 0:
        raise unittest.SkipTest(
            "SGP.26 reference certificates absent from this checkout: "
            f"{missing[0].relative_to(_REPO_ROOT)}"
        )
    return SGP26_VALID_ROOT


__all__ = [
    "SGP26_REQUIRED_FILES",
    "SGP26_VALID_ROOT",
    "require_sgp26_bundle",
    "sgp26_bundle_available",
]
