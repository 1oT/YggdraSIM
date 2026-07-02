# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Loopback HTTP launcher for the YggdraCore stub AUSF.

Runs **off by default**; the launcher refuses to start unless
``YGGDRASIM_5GCORE_MODE=stub`` is exported. The bind address is
forced to a loopback address (127.x / ::1) unless
``YGGDRASIM_5GCORE_ALLOW_NONLOOPBACK=1`` is set, which exists purely
so a sealed lab on a private bridge can run a UE simulator on a
neighbouring container without surrendering safety on a developer
laptop.

Endpoint shape mirrors the 3GPP SBI naming convention so test rigs
that already speak Nausf can be pointed at this server with minimal
shim code:

* ``POST /nausf-auth/v1/ue-authentications``
* ``PUT  /nausf-auth/v1/ue-authentications/{ctxId}/5g-aka-confirmation``
* ``GET  /yggdracore/diagnostics``
* ``GET  /yggdracore/healthz``

The factory :func:`build_app` returns a fresh FastAPI app bound to a
caller-provided :class:`AusfStub` so tests can drive it through
``fastapi.testclient.TestClient`` without touching env vars.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
from typing import Any, Optional

from .ausf_stub import (
    AuthContextNotFoundError,
    AuthVerificationError,
    AusfStub,
    AusfStubError,
    get_default_ausf_stub,
    yggdra_core_mode,
)
from .aanf_stub import get_default_aanf_stub
from .subscription_store import (
    SubscriptionStore,
    get_default_subscription_store,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8089

_LOG = logging.getLogger("yggdrasim.yggdracore.http")


def build_app(
    *,
    ausf_stub: Optional[AusfStub] = None,
    subscription_store: Optional[SubscriptionStore] = None,
) -> Any:
    """Construct the FastAPI app. ``fastapi`` is imported lazily so
    importing this module never pulls FastAPI on systems that only
    use the library API."""
    from fastapi import Body, FastAPI, HTTPException, Path

    stub = ausf_stub or get_default_ausf_stub()
    subscriptions = subscription_store or get_default_subscription_store()
    aanf = get_default_aanf_stub()

    app = FastAPI(
        title="YggdraSIM YggdraCore stub AUSF",
        description=(
            "Loopback test rig exposing the minimum 3GPP SBI surface "
            "(Nausf_UEAuthentication) backed by the simulator's USIM "
            "key material. Off by default; gated behind "
            "YGGDRASIM_5GCORE_MODE=stub."
        ),
        version="0.1.0",
    )

    @app.get("/yggdracore/healthz")
    def _healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/yggdracore/diagnostics")
    def _diagnostics() -> dict[str, Any]:
        return {
            "mode": yggdra_core_mode(),
            "subscriptions": len(subscriptions.list()),
            "aanf_entries": len(aanf.snapshot()),
            "in_flight_auth_contexts": stub.in_flight_context_count(),
        }

    @app.post("/nausf-auth/v1/ue-authentications", status_code=201)
    def _start_auth(payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
        supi = str(payload.get("supiOrSuci") or payload.get("supi") or "").strip()
        sn_name = str(payload.get("servingNetworkName") or "").strip()
        if len(supi) == 0:
            raise HTTPException(status_code=400, detail="supiOrSuci is required.")
        if len(sn_name) == 0:
            raise HTTPException(status_code=400, detail="servingNetworkName is required.")
        try:
            response = stub.start_ue_authentication(supi=supi, sn_name=sn_name)
        except AusfStubError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

        return {
            "ctxId": response.ctx_id,
            "supi": response.supi,
            "authType": response.auth_method,
            "5gAuthData": {
                "rand": response.av.rand.hex().upper(),
                "autn": response.av.autn.hex().upper(),
            },
            "_links": {
                "5g-aka": {
                    "href": f"/nausf-auth/v1/ue-authentications/{response.ctx_id}/5g-aka-confirmation",
                },
            },
        }

    @app.put("/nausf-auth/v1/ue-authentications/{ctx_id}/5g-aka-confirmation")
    def _confirm(
        ctx_id: str = Path(..., min_length=1),
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        res_star_hex = str(payload.get("resStar") or "").strip()
        if len(res_star_hex) == 0:
            raise HTTPException(status_code=400, detail="resStar is required.")
        try:
            res_star_bytes = bytes.fromhex(res_star_hex)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=f"resStar: {error}") from error
        try:
            confirm = stub.confirm_5g_aka(ctx_id=ctx_id, res_star=res_star_bytes)
        except AuthContextNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except AuthVerificationError as error:
            raise HTTPException(status_code=401, detail=str(error)) from error

        body: dict[str, Any] = {
            "authResult": "AUTHENTICATION_SUCCESS",
            "supi": confirm.supi,
            "kSeaf": confirm.k_seaf.hex().upper(),
        }
        if confirm.a_kid is not None and confirm.k_akma is not None:
            body["akma"] = {
                "aKid": confirm.a_kid,
                "kAkma": confirm.k_akma.hex().upper(),
            }
        return body

    return app


# ----------------------------------------------------------------------
# Launcher
# ----------------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() in ("localhost",)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m Tools.YggdraCore.http_app",
        description=(
            "Run the YggdraCore stub AUSF over HTTP. Off by default; "
            "set YGGDRASIM_5GCORE_MODE=stub to enable."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("YGGDRASIM_5GCORE_HOST", DEFAULT_HOST),
        help="Bind address (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("YGGDRASIM_5GCORE_PORT", DEFAULT_PORT)),
        help="Bind port (default: 8089).",
    )
    parser.add_argument(
        "--allow-nonloopback",
        action="store_true",
        default=os.environ.get("YGGDRASIM_5GCORE_ALLOW_NONLOOPBACK", "0") == "1",
        help=(
            "Allow non-loopback host bindings (sealed lab use only)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])

    if yggdra_core_mode() != "stub":
        print(
            "YggdraCore stub AUSF is disabled. Set YGGDRASIM_5GCORE_MODE=stub to enable.",
            file=sys.stderr,
        )
        return 2

    if not _is_loopback(args.host) and not args.allow_nonloopback:
        print(
            (
                f"Refusing to bind to non-loopback host {args.host!r}. "
                "Pass --allow-nonloopback (or set "
                "YGGDRASIM_5GCORE_ALLOW_NONLOOPBACK=1) if this is a sealed lab."
            ),
            file=sys.stderr,
        )
        return 2

    try:
        import uvicorn
    except ImportError as error:  # pragma: no cover -- exercised only without uvicorn
        print(f"uvicorn is required for the launcher: {error}", file=sys.stderr)
        return 3

    app = build_app()
    _LOG.info("YggdraCore stub AUSF listening on %s:%s (mode=stub)", args.host, args.port)
    uvicorn.run(app, host=args.host, port=int(args.port), log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "build_app",
    "main",
]
