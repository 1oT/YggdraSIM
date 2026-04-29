"""CAMARA-shaped dataclasses used by the Sunrise-6G adapter.

Implements the request/response shapes that the SUNRISE-6G OpenSDK
exposes for:

* CAMARA Quality-on-Demand v1.0.0  -- ``CreateSession`` /
  ``SessionInfo`` / ``QosStatus``.
* CAMARA Location Retrieval v0.4.0 -- ``Device`` / ``Location`` /
  ``Polygon`` / ``Point``.
* CAMARA Location Verification v2.x -- the verify match codes
  ``MATCH`` / ``NO_MATCH`` / ``UNKNOWN`` / ``PARTIAL``.

Everything here is a plain dataclass: no pydantic dep, no
``sunrise6g_opensdk`` import. The bridge layer translates these
into the SDK's pydantic models when the real SDK is installed.

References:

* CAMARA Quality-on-Demand v1.0.0 OpenAPI 3.0
  https://github.com/camaraproject/QualityOnDemand
* CAMARA Location-Retrieval v0.4.0 OpenAPI 3.0
  https://github.com/camaraproject/DeviceLocation
"""

from __future__ import annotations

import datetime as _dt
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


# CAMARA QoD v1.0.0 §4.4 enumerates these four shorthands. Operators
# typically map them to NEF QCI/QI 1..9.
QosProfile = str
SUPPORTED_QOS_PROFILES: tuple[QosProfile, ...] = ("QOS_E", "QOS_S", "QOS_M", "QOS_L")


class QosStatus:
    REQUESTED = "REQUESTED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class LocationVerificationResult:
    """CAMARA Location-Verification §4.3 outcome enum."""

    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


# ----------------------------------------------------------------------
# Device identity
# ----------------------------------------------------------------------


_E164 = re.compile(r"^\+?[1-9]\d{1,14}$")  # ITU-T E.164
_NAI = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # RFC 7542
_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


@dataclass(frozen=True)
class DeviceIdentity:
    """CAMARA Device object.

    At least one of ``phone_number`` / ``network_access_identifier`` /
    ``ipv4_public`` / ``ipv6`` must be supplied; CAMARA APIs require a
    non-empty Device payload to look the UE up.
    """

    phone_number: Optional[str] = None
    network_access_identifier: Optional[str] = None
    ipv4_public: Optional[str] = None
    ipv4_private: Optional[str] = None
    ipv6: Optional[str] = None

    def __post_init__(self) -> None:
        # Skip validation on a fully-empty record so the dataclass can
        # still be instantiated for templating; the bridge enforces
        # at-least-one elsewhere.
        if self.phone_number is not None and not _E164.match(self.phone_number):
            raise ValueError(f"phone_number must be E.164 (got {self.phone_number!r})")
        if self.network_access_identifier is not None and not _NAI.match(
            self.network_access_identifier
        ):
            raise ValueError(
                f"network_access_identifier must be NAI form (got {self.network_access_identifier!r})"
            )
        if self.ipv4_public is not None and not _IPV4.match(self.ipv4_public):
            raise ValueError(f"ipv4_public must be dotted-quad (got {self.ipv4_public!r})")
        if self.ipv4_private is not None and not _IPV4.match(self.ipv4_private):
            raise ValueError(f"ipv4_private must be dotted-quad (got {self.ipv4_private!r})")
        # IPv6 is left to the SDK / NEF to validate; we accept any
        # non-empty string here.

    def is_empty(self) -> bool:
        return not any(
            (
                self.phone_number,
                self.network_access_identifier,
                self.ipv4_public,
                self.ipv4_private,
                self.ipv6,
            )
        )

    def stable_key(self) -> str:
        """Deterministic identity used as the in-stub primary key."""
        if self.phone_number:
            return f"phone:{self.phone_number}"
        if self.network_access_identifier:
            return f"nai:{self.network_access_identifier}"
        if self.ipv4_public:
            return f"ipv4_public:{self.ipv4_public}"
        if self.ipv4_private:
            return f"ipv4_private:{self.ipv4_private}"
        if self.ipv6:
            return f"ipv6:{self.ipv6}"
        return "empty:device"

    def to_camara(self) -> dict[str, Any]:
        camara: dict[str, Any] = {}
        if self.phone_number is not None:
            camara["phoneNumber"] = self.phone_number
        if self.network_access_identifier is not None:
            camara["networkAccessIdentifier"] = self.network_access_identifier
        if self.ipv4_public is not None or self.ipv4_private is not None:
            ipv4: dict[str, Any] = {}
            if self.ipv4_public is not None:
                ipv4["publicAddress"] = self.ipv4_public
            if self.ipv4_private is not None:
                ipv4["privateAddress"] = self.ipv4_private
            camara["ipv4Address"] = ipv4
        if self.ipv6 is not None:
            camara["ipv6Address"] = self.ipv6
        return camara

    @classmethod
    def from_camara(cls, payload: dict[str, Any]) -> "DeviceIdentity":
        ipv4 = payload.get("ipv4Address") or {}
        if isinstance(ipv4, str):
            ipv4 = {"publicAddress": ipv4}
        return cls(
            phone_number=payload.get("phoneNumber"),
            network_access_identifier=payload.get("networkAccessIdentifier"),
            ipv4_public=ipv4.get("publicAddress"),
            ipv4_private=ipv4.get("privateAddress"),
            ipv6=payload.get("ipv6Address"),
        )


# ----------------------------------------------------------------------
# QoD
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class QodSession:
    """In-stub QoS-on-Demand session record.

    Maps 1:1 to CAMARA QoD ``SessionInfo``. ``application_server_ip``
    is the IPv4 of the AS half of the flow; multi-port flows are
    flattened in :meth:`to_camara_session_info`.
    """

    session_id: str
    device: DeviceIdentity
    application_server_ip: str
    qos_profile: QosProfile
    duration_seconds: int
    started_at_unix: float
    sink_url: Optional[str] = None
    device_ports: tuple[int, ...] = field(default_factory=tuple)
    application_server_ports: tuple[int, ...] = field(default_factory=tuple)
    status: str = QosStatus.AVAILABLE

    def __post_init__(self) -> None:
        if self.qos_profile not in SUPPORTED_QOS_PROFILES:
            raise ValueError(
                f"qos_profile must be one of {SUPPORTED_QOS_PROFILES}; got {self.qos_profile!r}"
            )
        if int(self.duration_seconds) < 1 or int(self.duration_seconds) > 86_400:
            raise ValueError(
                "duration_seconds must be in [1, 86400] (CAMARA QoD §4.5)."
            )
        if not _IPV4.match(self.application_server_ip):
            raise ValueError(
                f"application_server_ip must be IPv4 (got {self.application_server_ip!r})"
            )
        if self.device.is_empty():
            raise ValueError("device must carry at least one identifier")
        for port in (*self.device_ports, *self.application_server_ports):
            if not (0 <= int(port) <= 65535):
                raise ValueError(f"port {port!r} out of range")
        if self.status not in (
            QosStatus.REQUESTED,
            QosStatus.AVAILABLE,
            QosStatus.UNAVAILABLE,
        ):
            raise ValueError(f"unknown QoS status {self.status!r}")

    def expires_at_unix(self) -> float:
        return float(self.started_at_unix) + float(self.duration_seconds)

    def is_expired(self, *, now_unix: float) -> bool:
        return now_unix >= self.expires_at_unix()

    def remaining_seconds(self, *, now_unix: float) -> int:
        return max(0, int(self.expires_at_unix() - now_unix))

    def to_camara_session_info(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "sessionId": self.session_id,
            "qosStatus": self.status,
            "qosProfile": self.qos_profile,
            "duration": int(self.duration_seconds),
            "device": self.device.to_camara(),
            "applicationServer": {"ipv4Address": self.application_server_ip},
            "startedAt": _iso8601(self.started_at_unix),
            "expiresAt": _iso8601(self.expires_at_unix()),
        }
        if self.sink_url is not None:
            info["sink"] = self.sink_url
        if self.device_ports:
            info["devicePorts"] = {"ports": list(self.device_ports)}
        if self.application_server_ports:
            info["applicationServerPorts"] = {"ports": list(self.application_server_ports)}
        return info


# ----------------------------------------------------------------------
# Location
# ----------------------------------------------------------------------


_MIN_LAT = -90.0
_MAX_LAT = 90.0
_MIN_LON = -180.0
_MAX_LON = 180.0


@dataclass(frozen=True)
class LocationFix:
    """In-stub location record for one device.

    Maps to the CAMARA Location-Retrieval v0.4.0 ``Location`` shape
    when serialised; we use ``CIRCLE`` so the demo surface stays
    simple. Real SDK callers receive a ``POLYGON`` with the SDK's
    discretised circle.
    """

    device: DeviceIdentity
    latitude: float
    longitude: float
    radius_meters: int
    last_location_time_unix: float

    def __post_init__(self) -> None:
        if not (_MIN_LAT <= float(self.latitude) <= _MAX_LAT):
            raise ValueError(f"latitude {self.latitude!r} out of [-90, 90]")
        if not (_MIN_LON <= float(self.longitude) <= _MAX_LON):
            raise ValueError(f"longitude {self.longitude!r} out of [-180, 180]")
        if int(self.radius_meters) < 1 or int(self.radius_meters) > 200_000:
            raise ValueError(
                "radius_meters must be in [1, 200000] (sane CAMARA bound)."
            )
        if self.device.is_empty():
            raise ValueError("device must carry at least one identifier")

    def to_camara_location(self) -> dict[str, Any]:
        return {
            "lastLocationTime": _iso8601(self.last_location_time_unix),
            "area": {
                "areaType": "CIRCLE",
                "center": {"latitude": float(self.latitude), "longitude": float(self.longitude)},
                "radius": int(self.radius_meters),
            },
        }

    def age_seconds(self, *, now_unix: float) -> int:
        return max(0, int(now_unix - self.last_location_time_unix))

    def is_stale(self, *, now_unix: float, max_age_seconds: int) -> bool:
        return self.age_seconds(now_unix=now_unix) > int(max_age_seconds)

    def is_within(
        self,
        *,
        latitude: float,
        longitude: float,
        accuracy_meters: int,
    ) -> bool:
        """Containment check using accumulated radii.

        Returns True if the great-circle distance between the
        anchored fix and the requested point is at most
        ``radius_meters + accuracy_meters``.
        """
        distance = _haversine_meters(
            self.latitude,
            self.longitude,
            float(latitude),
            float(longitude),
        )
        return distance <= float(self.radius_meters + max(0, int(accuracy_meters)))


@dataclass(frozen=True)
class LocationVerification:
    """CAMARA Location-Verification request payload."""

    device: DeviceIdentity
    latitude: float
    longitude: float
    accuracy_meters: int
    max_age_seconds: int = 60

    def __post_init__(self) -> None:
        if not (_MIN_LAT <= float(self.latitude) <= _MAX_LAT):
            raise ValueError(f"latitude {self.latitude!r} out of [-90, 90]")
        if not (_MIN_LON <= float(self.longitude) <= _MAX_LON):
            raise ValueError(f"longitude {self.longitude!r} out of [-180, 180]")
        if int(self.accuracy_meters) < 1 or int(self.accuracy_meters) > 200_000:
            raise ValueError("accuracy_meters must be in [1, 200000].")
        if int(self.max_age_seconds) < 1 or int(self.max_age_seconds) > 86_400:
            raise ValueError("max_age_seconds must be in [1, 86400].")
        if self.device.is_empty():
            raise ValueError("device must carry at least one identifier")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _iso8601(unix_ts: float) -> str:
    """ISO-8601 UTC string, no microseconds, ``Z`` suffix.

    Matches the CAMARA-recommended representation (``YYYY-MM-DDTHH:MM:SSZ``).
    """
    return (
        _dt.datetime.fromtimestamp(float(unix_ts), tz=_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


_EARTH_RADIUS_METERS = 6_371_008.8


def _haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance using the haversine formula."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return _EARTH_RADIUS_METERS * c


def model_asdict(model: Any) -> dict[str, Any]:
    """Wrapper around :func:`dataclasses.asdict` for frozen dataclasses."""
    return asdict(model)


__all__ = [
    "DeviceIdentity",
    "LocationFix",
    "LocationVerification",
    "LocationVerificationResult",
    "QodSession",
    "QosProfile",
    "QosStatus",
    "SUPPORTED_QOS_PROFILES",
    "model_asdict",
]
