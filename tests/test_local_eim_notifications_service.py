# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The background Local eIM service sends a Notification on after it answered the IPA that handed it over.

The service is started the way SERVE starts it, as a process of its own, and
gets one ProvideEimPackageResult with ePRAndNotifications (SGP.32 v1.3
§5.14.6) from the simulated eUICC. Its forwarding pass then runs without
anyone asking. The simulator's Notifications name a reserved test host, so
the pass contacts nobody; what it did shows in the store and the service log.
"""

from __future__ import annotations

import os
import socket
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine import notifications as outbox
from SCP11.eim_local.engine.server import LOG_FILE, start_background, stop_background
from SCP11.eim_local.engine.service import STATE_SUCCESS, LocalEim, OperationRequest
from tests.test_local_eim_engine import EIM_ID, ENABLED, SimCard


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class ServiceForwardingTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(self.directory)})
        environment.start()
        self.addCleanup(environment.stop)
        self.engine = LocalEim(self.directory)
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        eum, euicc = codec.decode_get_certs_response(self.card.exchange(codec.build_get_certs_request()))
        self.engine.apply_card_reads(self.card.eid, {"euicc_certificate": euicc, "eum_certificate": eum})

    def _result_with_notifications(self, operation_id: int) -> bytes:
        """What an IPA returns for the served package: the card's result and its pending Notifications."""
        served = self.engine.next_package(self.card.eid)
        self.assertEqual(served.operation.id, operation_id)
        answer = self.card.exchange(served.package, "LoadEuiccPackage")
        notifications = codec.decode_notification_list(
            self.card.exchange(codec.build_retrieve_notifications_request(), "RetrieveNotificationsList"))
        self.assertEqual(len(notifications), 1)
        return codec.tlv(b"\x30", answer + codec.tlv(b"\xA0", b"".join(notifications)))

    def test_the_running_service_forwards_after_its_answer(self) -> None:
        operation = self.engine.submit([OperationRequest(eid=self.card.eid, type="DISABLE_PROFILE",
                                                         params={"iccid": ENABLED})])[0]
        status = start_background(self.directory, port=_free_port(), tls_port="off", smdp_tls_port="off")
        self.addCleanup(stop_background, self.directory)
        body = codec.tlv(codec.TAG_PROVIDE_EIM_PACKAGE_RESULT,
                         codec.tlv(b"\x5A", bytes.fromhex(self.card.eid)) + self._result_with_notifications(operation.id))
        request = urllib.request.Request(
            str(status["url"]) + "/gsma/rsp2/asn1", data=body, method="POST",
            headers={"Content-Type": "application/x-gsma-rsp-asn1", "X-Admin-Protocol": "gsma/rsp/v1.3.0"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - the test's own loopback service
            answer = response.read()
        # The answer acknowledges the result and the Notification before anything is sent on.
        self.assertEqual(answer[:2], codec.TAG_PROVIDE_EIM_PACKAGE_RESULT)
        self.assertEqual(self.engine.operation(operation.id).state, STATE_SUCCESS)

        deadline = time.monotonic() + 15
        rows: list[dict] = []
        while time.monotonic() < deadline:
            rows = self.engine.notifications(self.card.eid)
            if rows and rows[0]["state"] != outbox.STATE_PENDING:
                break
            time.sleep(0.1)
        self.assertEqual([(row["event"], row["address"], row["state"]) for row in rows],
                         [("disable", "rsp.example.com", outbox.STATE_FAILED)])
        self.assertIn("reserved or local name", rows[0]["reason"])
        self.assertTrue(stop_background(self.directory))
        log = (self.directory / LOG_FILE).read_text(encoding="utf-8")
        self.assertIn(f"Notification {rows[0]['seq_number']} (disable) of {self.card.eid}: not sent: rsp.example.com is "
                      "a reserved or local name where no Notification Receiver answers", log)


if __name__ == "__main__":
    unittest.main()
