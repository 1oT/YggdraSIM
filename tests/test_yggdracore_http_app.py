# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HTTP-surface tests for the YggdraCore stub AUSF launcher.

Exercises the endpoints registered on the FastAPI app directly (no
port binding, client thread, or env vars) so the request/response
shape and declared route status codes are locked independently of
the underlying :class:`AusfStub`.

Coverage:

* ``GET /yggdracore/healthz`` and ``/diagnostics``.
* ``POST /nausf-auth/v1/ue-authentications`` happy path + 400 / 404.
* ``PUT  /nausf-auth/v1/ue-authentications/{ctxId}/5g-aka-confirmation``
  happy path with AKMA payload and 401 on RES* mismatch.
* Launcher refuses to start when ``YGGDRASIM_5GCORE_MODE`` is unset.
* Launcher refuses non-loopback bind without explicit override.

The endpoint tests skip cleanly when FastAPI is missing. The
launcher-safety tests do not need FastAPI and always run.
"""

from __future__ import annotations

import os
import unittest
from typing import Any

from SIMCARD.aka_5g import derive_res_star
from SIMCARD.auth import milenage_vectors
from Tools.YggdraCore.aanf_stub import AAnFStub
from Tools.YggdraCore.ausf_stub import AusfStub
from Tools.YggdraCore.http_app import build_app, main
from Tools.YggdraCore.subscription_store import SubscriptionStore

try:
    from fastapi import HTTPException as _HTTPException

    _HAS_FASTAPI = True
except ImportError:
    _HTTPException = Exception
    _HAS_FASTAPI = False


_K = bytes.fromhex("465B5CE8B199B49FAA5F0A2EE238A6BC")
_OPC = bytes.fromhex("CD63CB71954A9F4E48A5994E37A02BAF")
_FIXED_RAND = bytes.fromhex("23553CBE9637A89D218AE64DAE47BF35")
_AMF = bytes.fromhex("B9B9")
_INITIAL_SQN = bytes.fromhex("FF9BB4D0B606")
_SUPI = "imsi-001010000000001"
_SN_NAME = "5G:mnc001.mcc001.3gppnetwork.org"


def _build_isolated_app(*, akma_enabled: bool = True):
    subscriptions = SubscriptionStore()
    aanf = AAnFStub()
    subscriptions.upsert(
        supi=_SUPI,
        k=_K,
        opc=_OPC,
        amf=_AMF,
        sqn=_INITIAL_SQN,
        mcc="001",
        mnc="01",
        routing_indicator="0",
        akma_enabled=akma_enabled,
    )
    stub = AusfStub(
        subscription_store=subscriptions,
        aanf_stub=aanf,
        rand_source=lambda: _FIXED_RAND,
    )
    app = build_app(ausf_stub=stub, subscription_store=subscriptions)
    return app, stub, subscriptions, aanf


def _ue_compute_res_star() -> bytes:
    sqn_used = bytes.fromhex("FF9BB4D0B607")
    vectors = milenage_vectors(_K, _OPC, _FIXED_RAND, sqn_used, _AMF)
    return derive_res_star(vectors.ck, vectors.ik, _SN_NAME, _FIXED_RAND, vectors.res)


def _route(app: Any, path: str, method: str) -> Any:
    """Return one registered route, failing clearly if the surface changes."""
    method = method.upper()
    for route in app.routes:
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == path and method in methods:
            return route
    raise AssertionError(f"route not registered: {method} {path}")


def _effective_status(route: Any) -> int:
    """FastAPI represents its default successful response status as ``None``."""
    return int(route.status_code or 200)


@unittest.skipUnless(_HAS_FASTAPI, "FastAPI is required for endpoint tests")
class _AppTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.stub, self.subscriptions, self.aanf = _build_isolated_app()
        self.health_route = _route(self.app, "/yggdracore/healthz", "GET")
        self.diagnostics_route = _route(self.app, "/yggdracore/diagnostics", "GET")
        self.start_route = _route(
            self.app,
            "/nausf-auth/v1/ue-authentications",
            "POST",
        )
        self.confirm_route = _route(
            self.app,
            (
                "/nausf-auth/v1/ue-authentications/{ctx_id}"
                "/5g-aka-confirmation"
            ),
            "PUT",
        )

    def assert_http_error(
        self,
        expected_status: int,
        endpoint: Any,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        with self.assertRaises(_HTTPException) as caught:
            endpoint(*args, **kwargs)
        self.assertEqual(caught.exception.status_code, expected_status)


class HealthAndDiagnosticsTests(_AppTestBase):
    def test_healthz_returns_ok(self) -> None:
        self.assertEqual(_effective_status(self.health_route), 200)
        self.assertEqual(self.health_route.endpoint(), {"status": "ok"})

    def test_diagnostics_includes_subscription_count(self) -> None:
        self.assertEqual(_effective_status(self.diagnostics_route), 200)
        body = self.diagnostics_route.endpoint()
        self.assertEqual(body["subscriptions"], 1)
        self.assertIn("aanf_entries", body)
        self.assertIn("in_flight_auth_contexts", body)


class StartAuthenticationHttpTests(_AppTestBase):
    def test_happy_path_returns_201_with_av(self) -> None:
        self.assertEqual(_effective_status(self.start_route), 201)
        body = self.start_route.endpoint(
            payload={"supiOrSuci": _SUPI, "servingNetworkName": _SN_NAME},
        )
        self.assertEqual(body["supi"], _SUPI)
        self.assertEqual(body["authType"], "5G_AKA")
        self.assertEqual(len(body["ctxId"]), 32)
        self.assertEqual(body["5gAuthData"]["rand"], _FIXED_RAND.hex().upper())
        self.assertEqual(len(body["5gAuthData"]["autn"]), 32)
        self.assertIn("_links", body)

    def test_missing_supi_returns_400(self) -> None:
        self.assert_http_error(
            400,
            self.start_route.endpoint,
            payload={"servingNetworkName": _SN_NAME},
        )

    def test_unknown_supi_returns_404(self) -> None:
        self.assert_http_error(
            404,
            self.start_route.endpoint,
            payload={
                "supiOrSuci": "imsi-000000000000000",
                "servingNetworkName": _SN_NAME,
            },
        )


class ConfirmAuthenticationHttpTests(_AppTestBase):
    def _start(self) -> str:
        body = self.start_route.endpoint(
            payload={"supiOrSuci": _SUPI, "servingNetworkName": _SN_NAME},
        )
        return body["ctxId"]

    def test_correct_res_star_returns_success_with_akma_payload(self) -> None:
        ctx_id = self._start()
        ue_res_star = _ue_compute_res_star()
        self.assertEqual(_effective_status(self.confirm_route), 200)
        body = self.confirm_route.endpoint(
            ctx_id=ctx_id,
            payload={"resStar": ue_res_star.hex().upper()},
        )
        self.assertEqual(body["authResult"], "AUTHENTICATION_SUCCESS")
        self.assertEqual(body["supi"], _SUPI)
        self.assertEqual(len(body["kSeaf"]), 64)  # 32 bytes hex.
        self.assertIn("akma", body)
        self.assertIn("aKid", body["akma"])
        self.assertIn("kAkma", body["akma"])

    def test_wrong_res_star_returns_401(self) -> None:
        ctx_id = self._start()
        forged = ("00" * 16)
        self.assert_http_error(
            401,
            self.confirm_route.endpoint,
            ctx_id=ctx_id,
            payload={"resStar": forged},
        )

    def test_unknown_ctx_id_returns_404(self) -> None:
        self.assert_http_error(
            404,
            self.confirm_route.endpoint,
            ctx_id="deadbeef",
            payload={"resStar": "00" * 16},
        )

    def test_missing_res_star_returns_400(self) -> None:
        ctx_id = self._start()
        self.assert_http_error(
            400,
            self.confirm_route.endpoint,
            ctx_id=ctx_id,
            payload={},
        )


class LauncherSafetyTests(unittest.TestCase):
    """The CLI must refuse to start unless explicitly enabled."""

    def setUp(self) -> None:
        self._saved = os.environ.get("YGGDRASIM_5GCORE_MODE")
        if "YGGDRASIM_5GCORE_MODE" in os.environ:
            del os.environ["YGGDRASIM_5GCORE_MODE"]

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("YGGDRASIM_5GCORE_MODE", None)
        else:
            os.environ["YGGDRASIM_5GCORE_MODE"] = self._saved

    def test_main_refuses_when_mode_off(self) -> None:
        rc = main(["--host", "127.0.0.1", "--port", "0"])
        self.assertEqual(rc, 2)

    def test_main_refuses_nonloopback_without_override(self) -> None:
        os.environ["YGGDRASIM_5GCORE_MODE"] = "stub"
        try:
            rc = main(["--host", "192.0.2.1", "--port", "0"])
        finally:
            del os.environ["YGGDRASIM_5GCORE_MODE"]
        self.assertEqual(rc, 2)

    def test_main_refuses_unauthenticated_nonloopback_listener(self) -> None:
        os.environ["YGGDRASIM_5GCORE_MODE"] = "stub"
        try:
            rc = main(
                ["--host", "192.0.2.1", "--port", "0", "--allow-nonloopback", "--no-token"]
            )
        finally:
            del os.environ["YGGDRASIM_5GCORE_MODE"]
        # Reachable from the network AND no credential is the one
        # combination the launcher must not serve.
        self.assertEqual(rc, 2)


@unittest.skipUnless(_HAS_FASTAPI, "FastAPI is required for endpoint tests")
class BearerTokenTests(unittest.TestCase):
    """Bearer auth reuses the Card Bridge token helpers."""

    def _client(self, token: str):
        from fastapi.testclient import TestClient

        from Tools.YggdraCore.http_app import build_app

        return TestClient(build_app(auth_token=token))

    def test_no_token_leaves_every_route_open(self) -> None:
        client = self._client("")
        self.assertEqual(client.get("/yggdracore/diagnostics").status_code, 200)

    def test_healthz_stays_open_so_probes_need_no_credential(self) -> None:
        client = self._client("s3cret-token")
        self.assertEqual(client.get("/yggdracore/healthz").status_code, 200)

    def test_missing_header_is_401(self) -> None:
        client = self._client("s3cret-token")
        response = client.get("/yggdracore/diagnostics")
        self.assertEqual(response.status_code, 401)
        self.assertIn("WWW-Authenticate", response.headers)

    def test_wrong_token_is_403(self) -> None:
        client = self._client("s3cret-token")
        response = client.get(
            "/yggdracore/diagnostics", headers={"Authorization": "Bearer wrong"}
        )
        self.assertEqual(response.status_code, 403)

    def test_correct_token_is_accepted(self) -> None:
        client = self._client("s3cret-token")
        response = client.get(
            "/yggdracore/diagnostics", headers={"Authorization": "Bearer s3cret-token"}
        )
        self.assertEqual(response.status_code, 200)

    def test_authentication_routes_are_guarded_too(self) -> None:
        client = self._client("s3cret-token")
        self.assertEqual(
            client.post("/nausf-auth/v1/ue-authentications", json={}).status_code, 401
        )
        self.assertEqual(
            client.put(
                "/nausf-auth/v1/ue-authentications/abc/5g-aka-confirmation", json={}
            ).status_code,
            401,
        )


class TokenResolutionTests(unittest.TestCase):
    def test_no_token_flag_yields_an_empty_token(self) -> None:
        import argparse

        from Tools.YggdraCore.http_app import resolve_auth_token

        args = argparse.Namespace(no_token=True, token_file="", port=0)
        self.assertEqual(resolve_auth_token(args), "")

    def test_token_file_is_read_when_given(self) -> None:
        import argparse
        import tempfile
        from pathlib import Path

        from Tools.YggdraCore.http_app import resolve_auth_token

        path = Path(tempfile.mkdtemp()) / "token"
        path.write_text("file-sourced-token\n", encoding="utf-8")
        args = argparse.Namespace(no_token=False, token_file=str(path), port=0)
        self.assertEqual(resolve_auth_token(args), "file-sourced-token")


if __name__ == "__main__":
    unittest.main()
