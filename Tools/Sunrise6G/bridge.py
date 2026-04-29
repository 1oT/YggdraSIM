"""Sunrise-6G bridge -- abstracts stub vs real-SDK paths.

Provides a single :class:`Sunrise6gBridge` Protocol covering the
CAMARA QoD + Location surfaces YggdraSIM uses, plus two
implementations:

* :class:`Sunrise6gStubBridge` -- in-process; default, off-network,
  test-friendly. Backed by :class:`QodStubClient` and
  :class:`LocationStubClient`.
* :class:`Sunrise6gSdkBridge`  -- thin wrapper around the real
  ``sunrise6g_opensdk.Sdk`` when it is installed and an operator
  has a SUNRISE-6G testbed reachable.

The bridge factory honours ``YGGDRASIM_SUNRISE6G_MODE``:

* ``stub`` (default): always use :class:`Sunrise6gStubBridge`.
* ``sdk``:            instantiate :class:`Sunrise6gSdkBridge`
                       from env (``..._NETWORK_ADAPTER``,
                       ``..._NETWORK_BASE_URL``,
                       ``..._NETWORK_SCS_AS_ID``).
* ``off``:            every call raises
                       :class:`Sunrise6gBridgeError`.

Mode is read once per call to :func:`get_default_bridge` so a
GUI session can flip ``YGGDRASIM_SUNRISE6G_MODE`` and the next
action picks it up.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional, Protocol, runtime_checkable

from .location import (
    LocationFixNotFoundError,
    LocationStubClient,
    get_default_location_stub_client,
)
from .models import (
    DeviceIdentity,
    LocationVerification,
    LocationVerificationResult,
)
from .qod import QodSessionNotFoundError, QodStubClient, get_default_qod_stub_client


# Env vars
ENV_MODE = "YGGDRASIM_SUNRISE6G_MODE"
ENV_NETWORK_ADAPTER = "YGGDRASIM_SUNRISE6G_NETWORK_ADAPTER"
ENV_NETWORK_BASE_URL = "YGGDRASIM_SUNRISE6G_NETWORK_BASE_URL"
ENV_NETWORK_SCS_AS_ID = "YGGDRASIM_SUNRISE6G_NETWORK_SCS_AS_ID"

VALID_MODES = ("stub", "sdk", "off")
DEFAULT_MODE = "stub"
SUPPORTED_NETWORK_ADAPTERS = ("open5gs", "oai", "open5gcore")


class Sunrise6gBridgeError(RuntimeError):
    """Raised on bridge configuration / dispatch failures."""


class Sunrise6gBridgeOffError(Sunrise6gBridgeError):
    """Raised when the bridge is in ``off`` mode."""


@runtime_checkable
class Sunrise6gBridge(Protocol):
    """The minimum surface YggdraSIM uses for CAMARA QoD + Location."""

    mode: str

    def diagnostics(self) -> dict[str, Any]: ...
    def create_qod_session(self, session_info: dict[str, Any]) -> dict[str, Any]: ...
    def get_qod_session(self, session_id: str) -> dict[str, Any]: ...
    def delete_qod_session(self, session_id: str) -> None: ...
    def list_qod_sessions(self) -> list[dict[str, Any]]: ...
    def retrieve_location(
        self,
        device: DeviceIdentity,
        *,
        max_age_seconds: int = 60,
    ) -> dict[str, Any]: ...
    def verify_location(self, verification: LocationVerification) -> dict[str, Any]: ...


# ----------------------------------------------------------------------
# Stub bridge
# ----------------------------------------------------------------------


class Sunrise6gStubBridge:
    mode = "stub"

    def __init__(
        self,
        *,
        qod_client: Optional[QodStubClient] = None,
        location_client: Optional[LocationStubClient] = None,
    ) -> None:
        self._qod = qod_client or get_default_qod_stub_client()
        self._location = location_client or get_default_location_stub_client()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "qod_session_count": self._qod.session_count(),
            "location_anchor_count": self._location.fix_count(),
        }

    # QoD ---------------------------------------------------------------

    def create_qod_session(self, session_info: dict[str, Any]) -> dict[str, Any]:
        return self._qod.create_qod_session(session_info)

    def get_qod_session(self, session_id: str) -> dict[str, Any]:
        try:
            return self._qod.get_qod_session(session_id)
        except QodSessionNotFoundError as error:
            raise Sunrise6gBridgeError(str(error)) from error

    def delete_qod_session(self, session_id: str) -> None:
        try:
            self._qod.delete_qod_session(session_id)
        except QodSessionNotFoundError as error:
            raise Sunrise6gBridgeError(str(error)) from error

    def list_qod_sessions(self) -> list[dict[str, Any]]:
        return self._qod.list_sessions(include_expired=False)

    # Location ---------------------------------------------------------

    def retrieve_location(
        self,
        device: DeviceIdentity,
        *,
        max_age_seconds: int = 60,
    ) -> dict[str, Any]:
        try:
            return self._location.retrieve_location(
                device,
                max_age_seconds=max_age_seconds,
            )
        except LocationFixNotFoundError as error:
            raise Sunrise6gBridgeError(str(error)) from error

    def verify_location(self, verification: LocationVerification) -> dict[str, Any]:
        return self._location.verify_location(verification)


# ----------------------------------------------------------------------
# Off bridge
# ----------------------------------------------------------------------


class Sunrise6gOffBridge:
    mode = "off"

    def diagnostics(self) -> dict[str, Any]:
        return {"mode": self.mode, "reason": f"{ENV_MODE}=off"}

    def _refuse(self, *_args: Any, **_kwargs: Any) -> Any:
        raise Sunrise6gBridgeOffError(
            f"Sunrise-6G bridge is disabled ({ENV_MODE}=off). "
            f"Set {ENV_MODE}=stub or {ENV_MODE}=sdk to enable."
        )

    create_qod_session = _refuse  # type: ignore[assignment]
    get_qod_session = _refuse  # type: ignore[assignment]
    delete_qod_session = _refuse  # type: ignore[assignment]
    list_qod_sessions = _refuse  # type: ignore[assignment]
    retrieve_location = _refuse  # type: ignore[assignment]
    verify_location = _refuse  # type: ignore[assignment]


# ----------------------------------------------------------------------
# SDK bridge -- talks to the real sunrise6g_opensdk
# ----------------------------------------------------------------------


class Sunrise6gSdkBridge:
    """Thin wrapper around ``sunrise6g_opensdk.Sdk``.

    The constructor lazy-imports the SDK so YggdraSIM can be
    installed without it. The ``adapter_specs`` mirror the SDK's
    own ``create_adapters_from`` shape; we expose just the
    network-side knobs because YggdraSIM does not drive the
    edge-cloud surface.
    """

    mode = "sdk"

    def __init__(
        self,
        *,
        network_adapter: str,
        network_base_url: str,
        network_scs_as_id: str,
        sdk_module: Any = None,
    ) -> None:
        if network_adapter not in SUPPORTED_NETWORK_ADAPTERS:
            raise Sunrise6gBridgeError(
                f"unsupported network adapter {network_adapter!r}; "
                f"choose one of {SUPPORTED_NETWORK_ADAPTERS}"
            )
        self._network_adapter = network_adapter
        self._network_base_url = network_base_url
        self._network_scs_as_id = network_scs_as_id
        self._sdk_module = sdk_module
        self._network_client: Any = None

    def _network(self) -> Any:
        if self._network_client is not None:
            return self._network_client
        sdk_module = self._sdk_module
        if sdk_module is None:
            try:
                from sunrise6g_opensdk.common.sdk import Sdk as sdk_module  # type: ignore[import]
            except ImportError as error:
                raise Sunrise6gBridgeError(
                    "sunrise6g_opensdk is not installed. "
                    "Install with `pip install yggdrasim[sunrise6g]` "
                    "or set YGGDRASIM_SUNRISE6G_MODE=stub."
                ) from error
        adapter_specs = {
            "network": {
                "client_name": self._network_adapter,
                "base_url": self._network_base_url,
                "scs_as_id": self._network_scs_as_id,
            },
        }
        adapters = sdk_module.create_adapters_from(adapter_specs)
        client = adapters.get("network") if hasattr(adapters, "get") else None
        if client is None:
            raise Sunrise6gBridgeError(
                "sunrise6g_opensdk.Sdk.create_adapters_from did not return a 'network' client"
            )
        self._network_client = client
        return client

    def diagnostics(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "network_adapter": self._network_adapter,
            "network_base_url": self._network_base_url,
            "network_scs_as_id": self._network_scs_as_id,
        }

    # QoD ---------------------------------------------------------------

    def create_qod_session(self, session_info: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._network().create_qod_session(session_info)
        except Exception as error:  # noqa: BLE001 -- surface SDK errors
            raise Sunrise6gBridgeError(f"SDK create_qod_session failed: {error}") from error

    def get_qod_session(self, session_id: str) -> dict[str, Any]:
        try:
            return self._network().get_qod_session(session_id=str(session_id))
        except Exception as error:  # noqa: BLE001
            raise Sunrise6gBridgeError(f"SDK get_qod_session failed: {error}") from error

    def delete_qod_session(self, session_id: str) -> None:
        try:
            self._network().delete_qod_session(session_id=str(session_id))
        except Exception as error:  # noqa: BLE001
            raise Sunrise6gBridgeError(f"SDK delete_qod_session failed: {error}") from error

    def list_qod_sessions(self) -> list[dict[str, Any]]:
        # CAMARA QoD v1.0.0 has no list endpoint; the SDK does not
        # expose one either. We return an empty list so the GUI
        # surface is polymorphic.
        return []

    # Location ---------------------------------------------------------

    def retrieve_location(
        self,
        device: DeviceIdentity,
        *,
        max_age_seconds: int = 60,
    ) -> dict[str, Any]:
        request = {
            "device": device.to_camara(),
            "maxAge": int(max_age_seconds),
        }
        try:
            response = self._network().create_monitoring_event_subscription(request)
        except Exception as error:  # noqa: BLE001
            raise Sunrise6gBridgeError(
                f"SDK create_monitoring_event_subscription failed: {error}"
            ) from error
        return _coerce_sdk_location(response)

    def verify_location(self, verification: LocationVerification) -> dict[str, Any]:
        # Sunrise-6G OpenSDK 1.0.x does not expose a verification
        # method directly. The most faithful behaviour is to do the
        # retrieve, then compute the match locally using the same
        # haversine logic the stub uses. This keeps the GUI surface
        # symmetric across modes.
        try:
            location = self.retrieve_location(
                verification.device,
                max_age_seconds=int(verification.max_age_seconds),
            )
        except Sunrise6gBridgeError:
            return {"verificationResult": LocationVerificationResult.UNKNOWN}
        return _verify_against_camara_location(
            location,
            latitude=float(verification.latitude),
            longitude=float(verification.longitude),
            accuracy_meters=int(verification.accuracy_meters),
        )


# ----------------------------------------------------------------------
# Factory
# ----------------------------------------------------------------------


_BRIDGE_LOCK = threading.Lock()
_BRIDGE_OVERRIDE: Optional[Any] = None
_BRIDGE_CACHE: dict[str, Any] = {}


def set_default_bridge_for_testing(bridge: Optional[Any]) -> None:
    """Inject a bridge for tests; pass ``None`` to revert."""
    global _BRIDGE_OVERRIDE
    with _BRIDGE_LOCK:
        _BRIDGE_OVERRIDE = bridge


def get_default_bridge() -> Any:
    """Resolve the active bridge from env vars and cache by mode."""
    if _BRIDGE_OVERRIDE is not None:
        return _BRIDGE_OVERRIDE
    mode = (os.environ.get(ENV_MODE) or DEFAULT_MODE).strip().lower()
    if mode not in VALID_MODES:
        raise Sunrise6gBridgeError(
            f"{ENV_MODE} must be one of {VALID_MODES}; got {mode!r}"
        )
    with _BRIDGE_LOCK:
        cached = _BRIDGE_CACHE.get(mode)
        if cached is not None:
            return cached
        if mode == "stub":
            bridge: Any = Sunrise6gStubBridge()
        elif mode == "off":
            bridge = Sunrise6gOffBridge()
        else:
            adapter = os.environ.get(ENV_NETWORK_ADAPTER, "open5gs").strip().lower()
            base_url = os.environ.get(ENV_NETWORK_BASE_URL)
            scs_as_id = os.environ.get(ENV_NETWORK_SCS_AS_ID)
            if not base_url or not scs_as_id:
                raise Sunrise6gBridgeError(
                    f"{ENV_NETWORK_BASE_URL} and {ENV_NETWORK_SCS_AS_ID} "
                    f"must be set when {ENV_MODE}=sdk."
                )
            bridge = Sunrise6gSdkBridge(
                network_adapter=adapter,
                network_base_url=base_url,
                network_scs_as_id=scs_as_id,
            )
        _BRIDGE_CACHE[mode] = bridge
        return bridge


def reset_default_bridge() -> None:
    """Drop every cached bridge (use between env-var changes)."""
    global _BRIDGE_OVERRIDE
    with _BRIDGE_LOCK:
        _BRIDGE_CACHE.clear()
        _BRIDGE_OVERRIDE = None


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _coerce_sdk_location(response: Any) -> dict[str, Any]:
    """Translate the SDK's pydantic ``Location`` into a plain dict."""
    if isinstance(response, dict):
        return response
    for attr in ("model_dump", "dict"):
        method = getattr(response, attr, None)
        if callable(method):
            return method()
    raise Sunrise6gBridgeError(
        f"unexpected SDK location response type {type(response).__name__}"
    )


def _verify_against_camara_location(
    location: dict[str, Any],
    *,
    latitude: float,
    longitude: float,
    accuracy_meters: int,
) -> dict[str, Any]:
    from .models import _haversine_meters  # type: ignore[attr-defined]

    area = location.get("area") or {}
    centre = area.get("center") or {}
    radius = int(area.get("radius") or 0)
    centre_lat = float(centre.get("latitude") or 0.0)
    centre_lon = float(centre.get("longitude") or 0.0)
    distance = _haversine_meters(centre_lat, centre_lon, latitude, longitude)
    inside = distance + float(radius) <= float(accuracy_meters)
    overlap = distance <= float(accuracy_meters + radius)
    if inside:
        match = LocationVerificationResult.MATCH
    elif overlap:
        match = LocationVerificationResult.PARTIAL
    else:
        match = LocationVerificationResult.NO_MATCH
    return {
        "verificationResult": match,
        "lastLocationTime": location.get("lastLocationTime"),
    }


__all__ = [
    "DEFAULT_MODE",
    "ENV_MODE",
    "ENV_NETWORK_ADAPTER",
    "ENV_NETWORK_BASE_URL",
    "ENV_NETWORK_SCS_AS_ID",
    "SUPPORTED_NETWORK_ADAPTERS",
    "Sunrise6gBridge",
    "Sunrise6gBridgeError",
    "Sunrise6gBridgeOffError",
    "Sunrise6gOffBridge",
    "Sunrise6gSdkBridge",
    "Sunrise6gStubBridge",
    "VALID_MODES",
    "get_default_bridge",
    "reset_default_bridge",
    "set_default_bridge_for_testing",
]
