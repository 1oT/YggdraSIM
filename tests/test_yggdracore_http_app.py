# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""HTTP-surface tests for the YggdraCore stub AUSF launcher.

Exercises the FastAPI app via :class:`fastapi.testclient.TestClient`
(no port binding, no env vars) so the wire shape -- request body
keys, response body keys, status codes -- is locked independently
of the underlying :class:`AusfStub`.

Coverage:

* ``GET /yggdracore/healthz`` and ``/diagnostics``.
* ``POST /nausf-auth/v1/ue-authentications`` happy path + 400 / 404.
* ``PUT  /nausf-auth/v1/ue-authentications/{ctxId}/5g-aka-confirmation``
  happy path with AKMA payload and 401 on RES* mismatch.
* Launcher refuses to start when ``YGGDRASIM_5GCORE_MODE`` is unset.
* Launcher refuses non-loopback bind without explicit override.

The HTTP-client tests skip cleanly when ``httpx`` -- a transitive
dependency of FastAPI's TestClient -- is missing so a developer
without the ``test`` extra installed still gets a clean signal from
the rest of the suite. The launcher-safety tests do not need a
client and always run.
"""

from __future__ import annotations

import os
import unittest

from SIMCARD.aka_5g import derive_res_star
from SIMCARD.auth import milenage_vectors
from Tools.YggdraCore.aanf_stub import AAnFStub
from Tools.YggdraCore.ausf_stub import AusfStub
from Tools.YggdraCore.http_app import build_app, main
from Tools.YggdraCore.subscription_store import SubscriptionStore

try:  # FastAPI's TestClient pulls httpx; make the dep visible up-front.
    import httpx as _httpx  # noqa: F401  -- imported only for the gate.

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


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


@unittest.skipUnless(_HAS_HTTPX, "httpx is required for FastAPI TestClient")
class _AppTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        self.app, self.stub, self.subscriptions, self.aanf = _build_isolated_app()
        self.client = TestClient(self.app)


class HealthAndDiagnosticsTests(_AppTestBase):
    def test_healthz_returns_ok(self) -> None:
        response = self.client.get("/yggdracore/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_diagnostics_includes_subscription_count(self) -> None:
        response = self.client.get("/yggdracore/diagnostics")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["subscriptions"], 1)
        self.assertIn("aanf_entries", body)
        self.assertIn("in_flight_auth_contexts", body)


class StartAuthenticationHttpTests(_AppTestBase):
    def test_happy_path_returns_201_with_av(self) -> None:
        response = self.client.post(
            "/nausf-auth/v1/ue-authentications",
            json={"supiOrSuci": _SUPI, "servingNetworkName": _SN_NAME},
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["supi"], _SUPI)
        self.assertEqual(body["authType"], "5G_AKA")
        self.assertEqual(len(body["ctxId"]), 32)
        self.assertEqual(body["5gAuthData"]["rand"], _FIXED_RAND.hex().upper())
        self.assertEqual(len(body["5gAuthData"]["autn"]), 32)
        self.assertIn("_links", body)

    def test_missing_supi_returns_400(self) -> None:
        response = self.client.post(
            "/nausf-auth/v1/ue-authentications",
            json={"servingNetworkName": _SN_NAME},
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_supi_returns_404(self) -> None:
        response = self.client.post(
            "/nausf-auth/v1/ue-authentications",
            json={"supiOrSuci": "imsi-000000000000000", "servingNetworkName": _SN_NAME},
        )
        self.assertEqual(response.status_code, 404)


class ConfirmAuthenticationHttpTests(_AppTestBase):
    def _start(self) -> str:
        response = self.client.post(
            "/nausf-auth/v1/ue-authentications",
            json={"supiOrSuci": _SUPI, "servingNetworkName": _SN_NAME},
        )
        self.assertEqual(response.status_code, 201)
        return response.json()["ctxId"]

    def test_correct_res_star_returns_success_with_akma_payload(self) -> None:
        ctx_id = self._start()
        ue_res_star = _ue_compute_res_star()
        response = self.client.put(
            f"/nausf-auth/v1/ue-authentications/{ctx_id}/5g-aka-confirmation",
            json={"resStar": ue_res_star.hex().upper()},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["authResult"], "AUTHENTICATION_SUCCESS")
        self.assertEqual(body["supi"], _SUPI)
        self.assertEqual(len(body["kSeaf"]), 64)  # 32 bytes hex.
        self.assertIn("akma", body)
        self.assertIn("aKid", body["akma"])
        self.assertIn("kAkma", body["akma"])

    def test_wrong_res_star_returns_401(self) -> None:
        ctx_id = self._start()
        forged = ("00" * 16)
        response = self.client.put(
            f"/nausf-auth/v1/ue-authentications/{ctx_id}/5g-aka-confirmation",
            json={"resStar": forged},
        )
        self.assertEqual(response.status_code, 401)

    def test_unknown_ctx_id_returns_404(self) -> None:
        response = self.client.put(
            "/nausf-auth/v1/ue-authentications/deadbeef/5g-aka-confirmation",
            json={"resStar": "00" * 16},
        )
        self.assertEqual(response.status_code, 404)

    def test_missing_res_star_returns_400(self) -> None:
        ctx_id = self._start()
        response = self.client.put(
            f"/nausf-auth/v1/ue-authentications/{ctx_id}/5g-aka-confirmation",
            json={},
        )
        self.assertEqual(response.status_code, 400)


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


if __name__ == "__main__":
    unittest.main()
