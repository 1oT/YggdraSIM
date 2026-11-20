# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""eIM Package Injection over HTTPS: the IPA's listener, the certificates of both ends, the eIM's client.

SGP.32 v1.3 §3.1.2.1 has the eIM, and only the eIM, authenticated by the IPA.
The listener does that by the client certificate of the call; the tests hold
it to taking no call without one it was told to trust.
"""

from __future__ import annotations

import contextlib
import datetime
import http.client
import io
import os
import socket
import ssl
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from SCP11.eim_local.engine import traffic
from SCP11.eim_local.engine.inject import InjectError, TargetUnreachable, TrafficLog, inject, parse_target, transport_for
from SCP11.eim_local.engine.service import ROUTE_INJECT, STATE_CREATED, STATE_SUCCESS
from SCP11.eim_local.main import EimLocalShell
from SCP11.eim_packages import package_changes_enabled_profile, psmo_operation_tags
from SCP11.live import console as live_console
from SCP11.live import transfer_provider
from SCP11.live.orchestrator import SGP22Orchestrator
from SCP11.live.transfer_provider import TransferListener, listener_tls_context
from SCP11.shared import esipa_transfer as transfer
from SCP11.shared import tls_identity
from tests.test_local_eim_engine import EIM_ID, SimCard
from tests.test_local_eim_inject import InjectBase, SimIpa
from tests.test_scp11_orchestrator import TEST_EID, FakeApduChannel, FakeCfg, FakeProvider

REQUEST = bytes.fromhex("BF4E09BF5306800101800102")
ANSWER = bytes.fromhex("BF4E03BF6000")


def _tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


def _package(*psmos: str) -> bytes:
    """An EuiccPackageRequest shell 'BF51' { '30' { ..., psmoList 'A0' { ... } } } with the PSMO tags given."""
    operations = b"".join(_tlv(tag, _tlv("5A", bytes.fromhex("98882143658709214365"))) for tag in psmos)
    signed = _tlv("80", b"eim") + _tlv("5A", bytes(16)) + _tlv("81", b"\x05") + _tlv("A0", operations)
    return _tlv("BF51", _tlv("30", signed) + _tlv("5F37", bytes(64)))


class Pairs:
    """Certificates for a listener and for callers, in a folder of the test's own."""

    def make_pairs(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)  # type: ignore[attr-defined]
        self.folder = Path(folder.name)
        self.listener_pair = self.make("listener", "ipad.example.test", ["ipad.example.test", "127.0.0.1"],
                                       tls_identity.ROLE_SERVER)
        self.eim_pair = self.make("eim", "eim.example.test", ["eim.example.test"], tls_identity.ROLE_CLIENT)
        self.stranger_pair = self.make("stranger", "other.example.test", [], tls_identity.ROLE_CLIENT)
        self.log: list[str] = []

    def make(self, stem: str, common_name: str, names: list[str], role: str) -> tuple[Path, Path]:
        certificate, key = tls_identity.issue_self_signed(common_name, names, role=role)
        return tls_identity.write_pair(self.folder, stem, certificate, key)

    def context(self, client_ca: Path | None = None, **settings: object) -> ssl.SSLContext:
        context = listener_tls_context(str(self.listener_pair[0]), str(self.listener_pair[1]),
                                       str(client_ca or self.eim_pair[0]))
        for name, value in settings.items():
            setattr(context, name, value)
        return context

    def serve(self, handler, context: ssl.SSLContext | None = None, **options: object) -> TransferListener:
        listener = TransferListener(handler, log=self.log.append, tls_context=context or self.context(), **options)  # type: ignore[arg-type]
        stop = threading.Event()
        thread = threading.Thread(target=listener.serve, kwargs={"stop": stop}, daemon=True)
        thread.start()

        def finish() -> None:
            stop.set()
            thread.join(timeout=5)
            listener.close()
            self.assertFalse(thread.is_alive())  # type: ignore[attr-defined]

        self.addCleanup(finish)  # type: ignore[attr-defined]
        return listener

    @staticmethod
    def caller(pair: tuple[Path, Path] | None = None, **settings: object) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if pair is not None:
            context.load_cert_chain(str(pair[0]), str(pair[1]))
        for name, value in settings.items():
            setattr(context, name, value)
        return context

    @staticmethod
    def post(listener: TransferListener, context: ssl.SSLContext, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection("127.0.0.1", listener.port, timeout=5, context=context)
        try:
            connection.request("POST", transfer.PATH_ASN1, body=REQUEST, headers={
                "Content-Type": transfer.CONTENT_TYPE_ASN1, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL,
                **(headers or {})})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def test_a_pair_is_a_p256_certificate_for_one_role_and_a_key_only_its_owner_reads(self) -> None:
        for role, usage in ((tls_identity.ROLE_SERVER, ExtendedKeyUsageOID.SERVER_AUTH),
                            (tls_identity.ROLE_CLIENT, ExtendedKeyUsageOID.CLIENT_AUTH)):
            with self.subTest(role=role):
                certificate_pem, key_pem = tls_identity.issue_self_signed(
                    "ipad.example.test", ["ipad.example.test", "192.0.2.4", "2001:db8::4"], role=role)
                certificate_path, key_path = tls_identity.write_pair(self.folder, f"pair-{role}", certificate_pem, key_pem)
                certificate = tls_identity.load_certificate(certificate_path)
                self.assertIsInstance(certificate.public_key().curve, ec.SECP256R1)
                self.assertEqual(certificate.subject, certificate.issuer)
                self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [usage])
                self.assertFalse(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
                names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                self.assertEqual(names.get_values_for_type(x509.DNSName), ["ipad.example.test"])
                self.assertEqual([str(address) for address in names.get_values_for_type(x509.IPAddress)],
                                 ["192.0.2.4", "2001:db8::4"])
                self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
                serialization.load_pem_private_key(key_path.read_bytes(), password=None)
                sha256 = tls_identity.certificate_sha256(certificate_path)
                self.assertEqual(sha256, certificate.fingerprint(hashes.SHA256()).hex().upper())
                described = tls_identity.describe(certificate_path)
                self.assertIn("CN=ipad.example.test, names ipad.example.test, 192.0.2.4, 2001:db8::4, valid until ", described)
                self.assertTrue(described.endswith(f"SHA-256 {sha256}"))

    def test_a_file_that_exists_is_never_replaced(self) -> None:
        certificate, key = tls_identity.issue_self_signed("ipad.example.test", role=tls_identity.ROLE_SERVER)
        certificate_path, key_path = tls_identity.write_pair(self.folder, "eim-listen", certificate, key)
        kept = (certificate_path.read_bytes(), key_path.read_bytes())
        other = tls_identity.issue_self_signed("other.example.test", role=tls_identity.ROLE_SERVER)
        with self.assertRaises(tls_identity.TlsIdentityError):
            tls_identity.write_pair(self.folder, "eim-listen", *other)
        key_path.unlink()
        with self.assertRaises(tls_identity.TlsIdentityError):
            tls_identity.write_pair(self.folder, "eim-listen", *other)
        self.assertEqual(certificate_path.read_bytes(), kept[0])
        self.assertFalse(key_path.exists())

    def test_what_cannot_be_a_certificate_is_refused(self) -> None:
        for common_name, names, role in (
            ("", [], tls_identity.ROLE_SERVER), ("x" * 65, [], tls_identity.ROLE_SERVER),
            ("ipad.example.test", ["two words"], tls_identity.ROLE_SERVER),
            ("ipad.example.test", ["https://ipad.example.test"], tls_identity.ROLE_SERVER),
            ("ipad.example.test", [""], tls_identity.ROLE_CLIENT), ("ipad.example.test", [], "both"),
        ):
            with self.subTest(common_name=common_name[:8], names=names, role=role):
                with self.assertRaises(tls_identity.TlsIdentityError):
                    tls_identity.issue_self_signed(common_name, names, role=role)
        for stem in ("", "../up", "a b", ".hidden", "x" * 65):
            with self.subTest(stem=stem):
                with self.assertRaises(tls_identity.TlsIdentityError):
                    tls_identity.pair_paths(self.folder, stem)

    def test_a_file_is_read_as_pem_or_der_and_anything_else_is_named_not_quoted(self) -> None:
        certificate_pem, key_pem = tls_identity.issue_self_signed("ipad.example.test", role=tls_identity.ROLE_SERVER)
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        der = self.folder / "certificate.der"
        der.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
        self.assertEqual(tls_identity.load_certificate(der), certificate)
        key_file = self.folder / "key.pem"
        key_file.write_bytes(key_pem)
        for path in (key_file, self.folder / "absent.pem", self.folder):
            with self.subTest(path=path.name):
                with self.assertRaises(tls_identity.TlsIdentityError) as caught:
                    tls_identity.certificate_sha256(path)
                self.assertNotIn("PRIVATE KEY", str(caught.exception))
                self.assertNotIn(key_pem.decode().splitlines()[1], str(caught.exception))


class ListenerRuleTests(Pairs, unittest.TestCase):
    def setUp(self) -> None:
        self.make_pairs()

    def test_the_context_asks_for_a_client_certificate_and_tls_1_2_at_least(self) -> None:
        context = self.context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)

    def test_files_that_do_not_load_are_named_without_their_content(self) -> None:
        garbage = self.folder / "garbage.pem"
        garbage.write_text("not a certificate\n", encoding="utf-8")
        certificate, key = (str(path) for path in self.listener_pair)
        secret_line = self.listener_pair[1].read_text(encoding="utf-8").splitlines()[1]
        for arguments, expected in (
            ((str(garbage), key, str(self.eim_pair[0])), "the listener's certificate and key do not load"),
            ((certificate, str(self.folder / "absent.pem"), str(self.eim_pair[0])), "the listener's certificate and key do not load"),
            ((certificate, str(self.eim_pair[1]), str(self.eim_pair[0])), "the listener's certificate and key do not load"),
            ((certificate, key, str(garbage)), "client-ca does not load"),
            ((certificate, key, str(self.folder / "absent.pem")), "client-ca does not load"),
            # A key under a pass phrase is refused; nothing asks the terminal for the phrase.
            ((certificate, str(self.encrypted_key()), str(self.eim_pair[0])), "the listener's certificate and key do not load"),
        ):
            with self.subTest(expected=expected, first=Path(arguments[0]).name):
                with self.assertRaises(ValueError) as caught:
                    listener_tls_context(*arguments)
                self.assertIn(expected, str(caught.exception))
                self.assertNotIn(secret_line, str(caught.exception))

    def encrypted_key(self) -> Path:
        key = serialization.load_pem_private_key(self.listener_pair[1].read_bytes(), password=None)
        path = self.folder / "encrypted-key.pem"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.BestAvailableEncryption(b"phrase")))
        return path

    def test_off_the_loopback_it_listens_with_tls_and_a_required_client_certificate_only(self) -> None:
        handler = mock.Mock(return_value=ANSWER)
        for host in ("0.0.0.0", "192.0.2.4", "ipad.example.test"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    TransferListener(handler, host=host)
        for mode in (ssl.CERT_NONE, ssl.CERT_OPTIONAL):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    TransferListener(handler, tls_context=self.context(verify_mode=mode))
        listener = TransferListener(handler, host="0.0.0.0", tls_context=self.context())
        self.addCleanup(listener.close)
        self.assertTrue(listener.secure)
        self.assertEqual(listener.url, f"https://0.0.0.0:{listener.port}")


class HttpsListenerTests(Pairs, unittest.TestCase):
    def setUp(self) -> None:
        self.make_pairs()
        self.handler = mock.Mock(return_value=ANSWER)

    def refused(self, listener: TransferListener, context: ssl.SSLContext) -> None:
        with self.assertRaises((OSError, http.client.HTTPException)):
            self.post(listener, context)

    def test_a_call_with_the_trusted_certificate_is_answered(self) -> None:
        listener = self.serve(self.handler)
        self.assertEqual(self.post(listener, self.caller(self.eim_pair)), (200, ANSWER))
        self.handler.assert_called_once_with(REQUEST)
        self.assertTrue(listener.url.startswith("https://127.0.0.1:"))
        connected = [line for line in self.log if "connected" in line]
        self.assertEqual(len(connected), 1, self.log)
        self.assertIn("client certificate CN=eim.example.test", connected[0])
        self.assertIn(f"SHA-256 {tls_identity.certificate_sha256(self.eim_pair[0])}", connected[0])
        self.assertRegex(connected[0], r"TLSv1\.[23] \S+,")

    def test_tls_1_2_is_taken_and_nothing_older(self) -> None:
        listener = self.serve(self.handler)
        only_1_2 = self.caller(self.eim_pair, maximum_version=ssl.TLSVersion.TLSv1_2)
        self.assertEqual(self.post(listener, only_1_2), (200, ANSWER))
        self.assertIn("TLSv1.2", "".join(self.log))
        self.assertEqual(listener.tls_context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_a_host_name_that_is_no_loopback_name_is_fine_over_tls(self) -> None:
        listener = self.serve(self.handler)
        status, body = self.post(listener, self.caller(self.eim_pair), headers={"Host": "ipad.example.test:8746"})
        self.assertEqual((status, body), (200, ANSWER))

    def test_the_request_still_has_to_be_an_esipa_request(self) -> None:
        listener = self.serve(self.handler)
        connection = http.client.HTTPSConnection("127.0.0.1", listener.port, timeout=5, context=self.caller(self.eim_pair))
        self.addCleanup(connection.close)
        connection.request("POST", transfer.PATH_ASN1, body=REQUEST, headers={"Content-Type": "text/plain"})
        self.assertEqual(connection.getresponse().status, 415)
        self.handler.assert_not_called()

    def test_no_certificate_another_certificate_or_one_for_the_wrong_use_gets_no_answer(self) -> None:
        for tls_version in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
            for label, pair in (("none", None), ("stranger", self.stranger_pair), ("server use", self.listener_pair)):
                with self.subTest(label=label, tls=tls_version.name):
                    self.log.clear()
                    # The listener's own certificate is trusted here on purpose: it is for the server use only.
                    trusted = self.listener_pair[0] if label == "server use" else self.eim_pair[0]
                    handler = mock.Mock(return_value=ANSWER)
                    listener = self.serve(handler, self.context(trusted))
                    self.refused(listener, self.caller(pair, maximum_version=tls_version))
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and not any("failed" in line for line in self.log):
                        time.sleep(0.02)
                    handler.assert_not_called()
                    self.assertEqual(listener.calls, 0)
                    failed = [line for line in self.log if line.startswith("[!] TransferEimPackage: TLS with 127.0.0.1 failed")]
                    self.assertEqual(len(failed), 1, self.log)
                    if label == "server use":
                        self.assertIn("purpose", failed[0].lower())

    def test_it_goes_on_after_a_refused_caller(self) -> None:
        listener = self.serve(self.handler)
        self.refused(listener, self.caller(self.stranger_pair))
        self.refused(listener, self.caller())
        self.assertEqual(self.post(listener, self.caller(self.eim_pair)), (200, ANSWER))
        self.assertEqual(listener.calls, 1)

    def test_a_certificate_under_a_trusted_ca_is_taken(self) -> None:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test eIM client CA")])
        now = datetime.datetime.now(datetime.timezone.utc)

        def issue(subject: x509.Name, public_key, *, ca: bool) -> x509.Certificate:
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(public_key)
                       .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
                       .not_valid_after(now + datetime.timedelta(days=2))
                       .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
            if not ca:
                builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            return builder.sign(ca_key, hashes.SHA256())

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = issue(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eim-under-ca.example.test")]),
                     leaf_key.public_key(), ca=False)
        ca_file = self.folder / "client-ca.pem"
        ca_file.write_bytes(issue(ca_name, ca_key.public_key(), ca=True).public_bytes(serialization.Encoding.PEM))
        leaf_pair = tls_identity.write_pair(
            self.folder, "under-ca", leaf.public_bytes(serialization.Encoding.PEM),
            leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        listener = self.serve(self.handler, self.context(ca_file))
        self.assertEqual(self.post(listener, self.caller(leaf_pair)), (200, ANSWER))
        self.assertIn("CN=eim-under-ca.example.test", "".join(self.log))
        # The eIM's self-signed certificate is not under that CA.
        self.refused(listener, self.caller(self.eim_pair))
        self.assertEqual(listener.calls, 1)

    def test_plain_http_on_the_tls_port_reaches_nothing(self) -> None:
        listener = self.serve(self.handler)
        connection = http.client.HTTPConnection("127.0.0.1", listener.port, timeout=5)
        self.addCleanup(connection.close)
        with self.assertRaises((OSError, http.client.HTTPException)):
            connection.request("POST", transfer.PATH_ASN1, body=REQUEST, headers={
                "Content-Type": transfer.CONTENT_TYPE_ASN1, "X-Admin-Protocol": transfer.ADMIN_PROTOCOL})
            if connection.getresponse().status == 200:
                self.fail("a plain request was answered")
        self.handler.assert_not_called()

    def test_a_caller_that_says_nothing_does_not_hold_the_listener(self) -> None:
        with mock.patch.object(transfer_provider, "CONNECTION_IDLE_S", 0.3):
            listener = self.serve(self.handler)
            silent = socket.create_connection(("127.0.0.1", listener.port), timeout=5)
            self.addCleanup(silent.close)
            started = time.monotonic()
            self.assertEqual(self.post(listener, self.caller(self.eim_pair)), (200, ANSWER))
            self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(any("TLS with 127.0.0.1 failed" in line for line in self.log), self.log)

    def test_the_work_between_calls_runs_after_each_answer_and_cannot_end_the_listener(self) -> None:
        order: list[str] = []
        self.handler.side_effect = lambda _request: order.append("answer") or ANSWER

        def settle() -> None:
            order.append("settle")
            if order.count("settle") == 1:
                raise RuntimeError("the card went away")

        listener = self.serve(self.handler, settle=settle)
        for _ in range(2):
            self.assertEqual(self.post(listener, self.caller(self.eim_pair)), (200, ANSWER))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and order.count("settle") < 2:
            time.sleep(0.02)
        self.assertEqual(order, ["answer", "settle", "answer", "settle"])
        self.assertTrue(any("work after the answer failed: RuntimeError: the card went away" in line for line in self.log))


class EimClientTests(Pairs, InjectBase):
    """The Local eIM as the caller: its own client certificate, and what a refusal costs."""

    def setUp(self) -> None:
        super().setUp()
        self.make_pairs()

    def https(self, client_ca: Path | None = None, **settings: object) -> TransferListener:
        certificate, _key = self.engine.make_inject_client_pair()
        return self.serve(self.ipa.answer, self.context(client_ca or certificate, **settings))

    def run_https(self, listener: TransferListener) -> list:
        target = parse_target(listener.url)
        log = TrafficLog(self.engine, target, self.card.eid)
        self.lines = []
        return inject(self.engine, self.card.eid, transport_for(self.engine, target, timeout=5, record=log),
                      emit=self.lines.append, on_serve=log.serving)

    def test_the_engine_makes_its_client_certificate_once(self) -> None:
        self.assertIsNone(self.engine.inject_client_pair())
        certificate_path, key_path = self.engine.make_inject_client_pair()
        self.assertEqual(certificate_path.parent, self.engine.directory / "inject_client")
        self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
        certificate = tls_identity.load_certificate(certificate_path)
        self.assertEqual(list(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH])
        identity = self.engine.identity_or_none()
        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertIn(common_name, (identity.eim_fqdn, identity.eim_id))
        kept = (certificate_path.read_bytes(), key_path.read_bytes())
        self.assertEqual(self.engine.make_inject_client_pair(), (certificate_path, key_path))
        self.assertEqual((certificate_path.read_bytes(), key_path.read_bytes()), kept)
        self.assertEqual(self.engine.inject_client_pair(), (certificate_path, key_path))

    def test_without_that_certificate_an_https_target_is_refused_before_anything_is_served(self) -> None:
        operation_id = self.queue("PROFILE_INFO_LIST")
        with self.assertRaises(InjectError) as caught:
            transport_for(self.engine, parse_target("https://127.0.0.1:8746"))
        self.assertIn("INJECT-CERT", str(caught.exception))
        self.assertEqual(self.state_of(operation_id), STATE_CREATED)
        # A loopback target over plain HTTP needs none.
        transport_for(self.engine, parse_target("http://127.0.0.1:8746"))

    def test_operations_run_over_https_and_the_traffic_says_so(self) -> None:
        listener = self.https()
        operation_id = self.queue("PROFILE_INFO_LIST")
        steps = self.run_https(listener)
        operation = self.engine.operation(operation_id)
        self.assertEqual((operation.state, operation.route), (STATE_SUCCESS, ROUTE_INJECT), operation.error)
        self.assertTrue(any(step.operation_id == operation_id for step in steps))
        rows = self.engine.store.traffic(limit=50, operation_id=operation_id)
        self.assertTrue(rows)
        for row in rows:
            self.assertRegex(row.tls_version, r"^TLSv1\.[23]$")
            self.assertTrue(row.tls_cipher)
            self.assertIn("inject TLS", traffic.summary_line(row))
            facts = traffic.describe_record(row).rows[-1].value
            self.assertIn(f"{row.tls_version} {row.tls_cipher}, the eIM called", facts)
        self.assertIn(f"CN={tls_identity.load_certificate(self.engine.inject_client_pair()[0]).subject.rfc4514_string()[3:]}",
                      "".join(self.log))

    def test_a_listener_that_does_not_trust_the_eim_costs_no_counter_value(self) -> None:
        self.prime()
        for label, settings in (("TLS 1.3", {}), ("TLS 1.2", {"maximum_version": ssl.TLSVersion.TLSv1_2})):
            with self.subTest(tls=label):
                listener = self.https(self.stranger_pair[0], **settings)
                operation_id = self.queue("PROFILE_INFO_LIST")
                counter = self.engine.record(self.card.eid).counter_value
                packages = len(self.ipa.packages)
                with self.assertRaises(TargetUnreachable) as caught:
                    self.run_https(listener)
                self.assertIn("did not take the TLS connection", str(caught.exception))
                self.assertEqual(self.state_of(operation_id), STATE_CREATED)
                self.assertEqual(self.engine.record(self.card.eid).counter_value, counter)
                self.assertEqual(len(self.ipa.packages), packages)
                # The same operation goes through once the listener trusts this eIM.
                self.run_https(self.https(**settings))
                self.assertEqual(self.state_of(operation_id), STATE_SUCCESS)


class EimShellTests(Pairs, unittest.TestCase):
    """INJECT-CERT and an https target in the eIM-local shell, on a store of the test's own."""

    def setUp(self) -> None:
        self.make_pairs()
        store = tempfile.TemporaryDirectory()
        self.addCleanup(store.cleanup)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": store.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.shell = EimLocalShell()
        self.engine = self.shell._engine_verbs.engine
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)
        self.ipa = SimIpa(self.card)
        reader = mock.patch.object(type(self.shell._engine_verbs), "_with_reader",
                                   side_effect=AssertionError("the reader was opened"))
        reader.start()
        self.addCleanup(reader.stop)

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def test_the_certificate_is_made_once_and_shown_with_what_to_do_with_it(self) -> None:
        first = self.run_line("INJECT-CERT")
        certificate, key = self.engine.inject_client_pair()
        self.assertIn(f"[+] The eIM's client certificate for injection (made now): {certificate}", first)
        self.assertIn(f"SHA-256 {tls_identity.certificate_sha256(certificate)}", first)
        self.assertIn(f"client-ca={certificate}", first)
        self.assertNotIn(key.read_text(encoding="utf-8").splitlines()[1], first)
        second = self.run_line("INJECT-CERT")
        self.assertIn(f"[+] The eIM's client certificate for injection: {certificate}", second)
        self.assertNotIn("made now", second)
        self.assertIn("[!] Usage: INJECT-CERT", self.run_line("INJECT-CERT now"))

    def test_the_gui_action_makes_and_shows_the_same_certificate(self) -> None:
        from yggdrasim_common.gui_server.actions import eim_local_ops
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        spec = next(entry for entry in eim_local_ops.SPECS if entry.id == "eim_local.inject_cert")
        self.assertEqual((spec.title, tuple(spec.inputs)), ("Injection client certificate", ()))
        lines = list(spec.dispatcher(ActionContext())["lines"])
        certificate, _key = self.engine.inject_client_pair()
        self.assertIn(f"[+] The eIM's client certificate for injection (made now): {certificate}", lines)
        self.assertTrue(any(f"SHA-256 {tls_identity.certificate_sha256(certificate)}" in line for line in lines))
        again = list(spec.dispatcher(ActionContext())["lines"])
        self.assertIn(f"[+] The eIM's client certificate for injection: {certificate}", again)

    def test_an_https_target_runs_with_it_and_is_refused_without_it(self) -> None:
        eid = self.card.eid
        self.run_line(f"QUEUE LIST-PROFILES {eid}")
        refused = self.run_line(f"INJECT {eid} target=https://127.0.0.1:9")
        self.assertIn("[!] An https target takes the eIM's client certificate", refused)
        self.assertEqual(self.engine.record(eid).counter_value, 0)
        self.run_line("INJECT-CERT")
        listener = self.serve(self.ipa.answer, self.context(self.engine.inject_client_pair()[0]))
        output = self.run_line(f"INJECT {eid} target={listener.url}")
        self.assertIn(f"injecting to {listener.url} (asn1 binding, HTTPS with the eIM's client certificate).", output)
        self.assertIn("listProfileInfoResult: ok", output)
        self.assertEqual(self.engine.inject_target(eid), {"url": listener.url, "binding": "asn1"})
        self.assertIn("inject TLS", self.run_line("TRAFFIC 4 --brief"))


class StateChangeTests(unittest.TestCase):
    """What the IPAd does between two calls of a listener that stays up."""

    def test_enable_and_disable_are_the_psmos_that_wait_for_a_reset(self) -> None:
        # Psmo CHOICE tags of SGP.32 v1.3 section 2.11.1.1: enable [3], disable [4], delete [5], getRAT [6].
        for psmos, tags, changes in (
            (("A3",), (b"\xA3",), True), (("A4",), (b"\xA4",), True), (("A5",), (b"\xA5",), False),
            (("A6",), (b"\xA6",), False), (("A6", "A3"), (b"\xA6", b"\xA3"), True), ((), (), False),
        ):
            with self.subTest(psmos=psmos):
                package = _package(*psmos)
                self.assertEqual(psmo_operation_tags(package), tags)
                self.assertEqual(package_changes_enabled_profile(package), changes)
        for raw in (b"", b"\xBF", bytes.fromhex("BF51"), bytes.fromhex("BF5103300100"), bytes.fromhex("BF5205A0038001FF")):
            with self.subTest(raw=raw.hex()):
                self.assertEqual(psmo_operation_tags(raw), ())
                self.assertFalse(package_changes_enabled_profile(raw))

    def orchestrator(self, *, reset: object = None) -> SGP22Orchestrator:
        channel = FakeApduChannel()
        if reset is not None:
            channel.reset = reset  # type: ignore[attr-defined]
        orchestrator = SGP22Orchestrator(cfg=FakeCfg(), apdu_channel=channel, profile_provider=FakeProvider(bpp_bytes=b""))
        orchestrator._phase_connect = mock.Mock()
        orchestrator._sync_pending_notifications = mock.Mock()
        orchestrator._relay_eim_package_to_card = mock.Mock(return_value=bytes.fromhex("BF5100"))
        return orchestrator

    def settle(self, orchestrator: SGP22Orchestrator) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            orchestrator._settle_injected_eim_package()
        return output.getvalue()

    def test_after_an_enable_or_a_disable_the_card_is_reset_and_its_notification_synced(self) -> None:
        for psmo in ("A3", "A4"):
            with self.subTest(psmo=psmo):
                reset = mock.Mock()
                orchestrator = self.orchestrator(reset=reset)
                orchestrator._phase_connect_complete = True
                orchestrator._es10b_logical_channel = 1
                with contextlib.redirect_stdout(io.StringIO()):
                    orchestrator._run_injected_eim_package(_package(psmo))
                reset.assert_not_called()
                printed = self.settle(orchestrator)
                reset.assert_called_once_with()
                orchestrator._phase_connect.assert_called_once_with()
                orchestrator._sync_pending_notifications.assert_called_once_with()
                self.assertEqual((orchestrator._phase_connect_complete, orchestrator._es10b_logical_channel), (False, 0))
                self.assertIn("card reset after the Profile state change; new card session.", printed)
                # Once per package: a second settle finds nothing to do.
                self.assertEqual(self.settle(orchestrator), "")
                reset.assert_called_once_with()

    def test_other_packages_leave_the_card_session_alone(self) -> None:
        reset = mock.Mock()
        orchestrator = self.orchestrator(reset=reset)
        for psmos in (("A6",), ("A5",), ()):
            with contextlib.redirect_stdout(io.StringIO()):
                orchestrator._run_injected_eim_package(_package(*psmos))
            self.assertEqual(self.settle(orchestrator), "")
        reset.assert_not_called()
        orchestrator._phase_connect.assert_not_called()

    def test_a_package_the_card_work_failed_on_gets_a_new_session_and_no_sync(self) -> None:
        for failure in (IOError("APDU Failed: 6F00"), b""):
            with self.subTest(failure=repr(failure)):
                reset = mock.Mock()
                orchestrator = self.orchestrator(reset=reset)
                if isinstance(failure, bytes):
                    orchestrator._relay_eim_package_to_card.return_value = failure
                else:
                    orchestrator._relay_eim_package_to_card.side_effect = failure
                with self.assertRaises((IOError, RuntimeError)), contextlib.redirect_stdout(io.StringIO()):
                    orchestrator._run_injected_eim_package(_package("A3"))
                printed = self.settle(orchestrator)
                reset.assert_called_once_with()
                orchestrator._sync_pending_notifications.assert_not_called()
                self.assertIn("card reset after the failed package; new card session.", printed)

    def test_a_session_that_does_not_come_back_is_tried_again_after_the_next_package(self) -> None:
        reset = mock.Mock(side_effect=[RuntimeError("no card"), None])
        orchestrator = self.orchestrator(reset=reset)
        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator._run_injected_eim_package(_package("A4"))
        self.assertIn("[!] eIM package injection: no new card session after the Profile state change: no card",
                      self.settle(orchestrator))
        orchestrator._sync_pending_notifications.assert_not_called()
        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator._run_injected_eim_package(_package("A6"))
        self.assertIn("card reset after the failed package; new card session.", self.settle(orchestrator))
        self.assertEqual(reset.call_count, 2)

    def test_a_channel_without_a_reset_is_said_and_nothing_breaks(self) -> None:
        orchestrator = self.orchestrator()
        with contextlib.redirect_stdout(io.StringIO()):
            orchestrator._run_injected_eim_package(_package("A3"))
        self.assertIn("this card channel has no reset", self.settle(orchestrator))
        orchestrator._phase_connect.assert_not_called()

    def test_injection_over_https_is_declared_while_the_https_listener_is_up_and_only_then(self) -> None:
        orchestrator = self.orchestrator()
        # ipaSupportedProtocols '81': ipaRetrieveHttps (0) alone, then with ipaInjectHttps (2), SGP.32 v1.3 section 4.1.
        self.assertTrue(orchestrator._default_ipa_capabilities_value().endswith(bytes.fromhex("81020780")))
        orchestrator._inject_https_listening = True
        self.assertTrue(orchestrator._default_ipa_capabilities_value().endswith(bytes.fromhex("810205A0")))

    def test_the_listen_entry_serves_https_and_takes_the_declaration_back(self) -> None:
        pairs = Pairs()
        pairs.addCleanup = self.addCleanup  # type: ignore[attr-defined]
        pairs.make_pairs()
        orchestrator = self.orchestrator()
        orchestrator._read_card_eid = lambda reselect_isdr=True: TEST_EID
        orchestrator._close_es10b_logical_channel = mock.Mock()
        seen: list[tuple[bool, str]] = []

        def serve(listener: TransferListener, **_options: object) -> int:
            seen.append((orchestrator._inject_https_listening, listener.url))
            return 0

        output = io.StringIO()
        with mock.patch.object(TransferListener, "serve", serve), contextlib.redirect_stdout(output):
            orchestrator.run_eim_listen(host="0.0.0.0", port=0, tls_context=pairs.context())
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][0])
        self.assertTrue(seen[0][1].startswith("https://0.0.0.0:"))
        self.assertFalse(orchestrator._inject_https_listening)
        printed = output.getvalue()
        self.assertIn("HTTPS: a call is taken only from a client certificate that verifies against client-ca", printed)
        self.assertIn("On the eIM: the address of this host, port", printed)
        self.assertNotIn("INJECT ", printed)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            orchestrator.run_eim_listen(host="0.0.0.0", port=0)
        self.assertFalse(orchestrator._inject_https_listening)


class ConsoleHttpsTests(Pairs, unittest.TestCase):
    def setUp(self) -> None:
        self.make_pairs()
        self.calls: list[dict] = []
        orchestrator = SimpleNamespace(run_eim_listen=lambda **options: self.calls.append(options) or 0)
        client = SimpleNamespace(
            cfg=SimpleNamespace(READER_INDEX=0, READER_NAME="", RSP_SERVER_URL="rsp.example.test",
                                ES9_BASE_URL="https://rsp.example.test", ES9_VERIFY_TLS=True, ES9_CA_BUNDLE_PATH=""),
            apdu_channel=SimpleNamespace(),
            orchestrator=orchestrator,
        )
        self.console = live_console.SCP11Console(client)
        self.console._style = live_console.ConsoleStyle("", "", "", "", "", "", "")

    def run_verb(self, verb: str, argument: str, *, terminal: bool = True) -> str:
        output = io.StringIO()
        self.console._terminal_command_lines = 1 if terminal else 0
        try:
            with contextlib.redirect_stdout(output):
                self.assertTrue(getattr(self.console, verb)(argument))
        finally:
            self.console._terminal_command_lines = 0
        return output.getvalue()

    def tls_options(self) -> str:
        return f"cert={self.listener_pair[0]} key={self.listener_pair[1]} client-ca={self.eim_pair[0]}"

    def test_https_options_reach_the_orchestrator_as_a_context_that_requires_a_client_certificate(self) -> None:
        output = self.run_verb("_cmd_eim_listen", f"host=0.0.0.0 port=8750 {self.tls_options()} notifications=keep")
        self.assertEqual(len(self.calls), 1, output)
        call = self.calls[0]
        self.assertEqual((call["host"], call["port"], call["keep_notifications"]), ("0.0.0.0", 8750, True))
        self.assertIsInstance(call["tls_context"], ssl.SSLContext)
        self.assertEqual(call["tls_context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertIn("on 0.0.0.0, HTTPS with the eIM's client certificate", output)

    def test_what_is_not_a_whole_https_setup_starts_nothing(self) -> None:
        certificate, key = self.listener_pair
        for argument, expected in (
            ("host=0.0.0.0", "off the loopback EIM-LISTEN serves HTTPS only"),
            ("host=192.0.2.4 port=8750", "off the loopback EIM-LISTEN serves HTTPS only"),
            (f"cert={certificate}", "HTTPS takes cert=, key= and client-ca= together"),
            (f"cert={certificate} key={key}", "HTTPS takes cert=, key= and client-ca= together"),
            (f"client-ca={self.eim_pair[0]}", "HTTPS takes cert=, key= and client-ca= together"),
            (f"cert={certificate} key={key} client-ca={self.folder / 'absent.pem'}", "client-ca does not load"),
            (f"cert={key} key={key} client-ca={self.eim_pair[0]}", "the listener's certificate and key do not load"),
            ("host=", "host= needs a value"), ("cert=", "cert= needs a value"), ("tls=on", "is no option of EIM-LISTEN"),
        ):
            with self.subTest(argument=argument[:40]):
                output = self.run_verb("_cmd_eim_listen", argument)
                self.assertTrue(output.startswith("[!] "), output)
                self.assertIn(expected, output.splitlines()[0])
                self.assertIn(f"[!] Usage: {live_console.EIM_LISTEN_USAGE}", output)
        self.assertEqual(self.calls, [])

    def test_files_are_named_from_a_terminal_command_line_only(self) -> None:
        output = self.run_verb("_cmd_eim_listen", f"host=0.0.0.0 {self.tls_options()}", terminal=False)
        self.assertIn("[!] cert=, key= and client-ca= are read from a terminal command line only", output)
        self.assertEqual(self.calls, [])
        out = self.folder / "made"
        refused = self.run_verb("_cmd_eim_listen_cert", f"ipad.example.test out={out}", terminal=False)
        self.assertIn("[!] EIM-LISTEN-CERT writes files: it is read from a terminal command line only.", refused)
        self.assertFalse(out.exists())
        # The loopback listener of a caller that is no terminal line is unchanged.
        self.run_verb("_cmd_eim_listen", "calls=1", terminal=False)
        self.assertEqual([(call["host"], call["tls_context"]) for call in self.calls], [("127.0.0.1", None)])

    def test_a_command_line_counts_as_one_only_while_it_runs(self) -> None:
        seen: list[int] = []
        self.console._dispatch_command_line = lambda _line, _show: seen.append(self.console._terminal_command_lines) or True
        with contextlib.redirect_stdout(io.StringIO()):
            self.console._run_command_line("HELP")
        self.assertEqual((seen, self.console._terminal_command_lines), ([1], 0))

    def test_the_certificate_verb_writes_a_pair_once_and_says_how_to_use_it(self) -> None:
        out = self.folder / "made"
        output = self.run_verb("_cmd_eim_listen_cert", f"ipad.example.test 192.0.2.4 out={out}")
        certificate, key = out / "eim-listen-cert.pem", out / "eim-listen-key.pem"
        self.assertIn(f"[+] Listener certificate: {certificate}", output)
        self.assertIn("CN=ipad.example.test, names ipad.example.test, 192.0.2.4", output)
        self.assertIn(f"SHA-256 {tls_identity.certificate_sha256(certificate)}", output)
        self.assertIn(f"cert={certificate} key={key} client-ca=", output)
        self.assertNotIn(key.read_text(encoding="utf-8").splitlines()[1], output)
        kept = certificate.read_bytes()
        self.assertIn("it is not replaced", self.run_verb("_cmd_eim_listen_cert", f"ipad.example.test out={out}"))
        self.assertEqual(certificate.read_bytes(), kept)
        # The pair serves: a listener built from it takes the eIM's call.
        context = listener_tls_context(str(certificate), str(key), str(self.eim_pair[0]))
        listener = self.serve(mock.Mock(return_value=ANSWER), context)
        self.assertEqual(self.post(listener, self.caller(self.eim_pair)), (200, ANSWER))

    def test_the_certificate_verb_refuses_what_is_no_name(self) -> None:
        for argument, expected in (("", "Usage: EIM-LISTEN-CERT"), (f"out={self.folder}", "Usage: EIM-LISTEN-CERT"),
                                   ("ipad.example.test role=client", "is neither a name, an address nor out="),
                                   ("--force ipad.example.test", "is neither a name, an address nor out="),
                                   (f"'two words' out={self.folder / 'bad'}", "is neither a host name nor an IP address")):
            with self.subTest(argument=argument[:30]):
                self.assertIn(expected, self.run_verb("_cmd_eim_listen_cert", argument))
        self.assertFalse((self.folder / "bad").exists())

    def test_without_out_the_pair_goes_to_the_runtime_directory(self) -> None:
        runtime = self.folder / "runtime"
        with mock.patch.object(live_console, "ensure_runtime_dir", return_value=str(runtime)) as where:
            output = self.run_verb("_cmd_eim_listen_cert", "ipad.example.test")
        where.assert_called_once_with("SCP11", "eim_listen")
        self.assertIn(str(runtime / "eim-listen-cert.pem"), output)
        self.assertTrue((runtime / "eim-listen-key.pem").is_file())

    def test_both_verbs_are_registered_in_the_ipad_section(self) -> None:
        listen = self.console._commands["EIM-LISTEN"]
        made = self.console._commands["EIM-LISTEN-CERT"]
        self.assertEqual((listen.usage, made.usage), (live_console.EIM_LISTEN_USAGE, live_console.EIM_LISTEN_CERT_USAGE))
        self.assertEqual((made.section, made.session_policy),
                         (self.console.HELP_SECTION_IPAD, live_console.SessionPolicy.SHARED))


if __name__ == "__main__":
    unittest.main()
