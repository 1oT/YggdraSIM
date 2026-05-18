"""SUNRISE-6G OpenSDK adapter.

In-process CAMARA Quality-on-Demand v1.0.0 and Location Retrieval
v0.4.0 surfaces, plus an optional bridge to the real
``sunrise6g_opensdk`` SDK when it is installed and an operator has
a SUNRISE-6G testbed reachable. Default mode is fully in-process
(stub) so demos work offline.
"""

from __future__ import annotations

from .models import (
    DeviceIdentity,
    LocationFix,
    LocationVerification,
    LocationVerificationResult,
    QodSession,
    QosProfile,
    QosStatus,
    SUPPORTED_QOS_PROFILES,
)

__all__ = [
    "DeviceIdentity",
    "LocationFix",
    "LocationVerification",
    "LocationVerificationResult",
    "QodSession",
    "QosProfile",
    "QosStatus",
    "SUPPORTED_QOS_PROFILES",
]
