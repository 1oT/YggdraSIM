# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Leaf variants of a Local eIM TLS setup and the record of what a client did with each.

trustedCertificateTls may be the certificate of the root CA or of an
intermediate CA instead of the eIM's own (SGP.32 v1.3 §2.11.1.1.1), so a setup
issues further leaves under its own CA and swaps the one on its name while the
card's trust stays. Every card-facing handshake is recorded with the SHA-256
of the leaf served and how it ended; the client here is a stock TLS stack
playing the card's IPAe.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import socket
import sqlite3
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from typing import Callable, Iterator
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import codec, tls_results, tls_setup
from SCP11.eim_local.engine.delivery import deliver
from SCP11.eim_local.engine.esipa import (
    ASN1_PATH,
    LocalEimCardTlsServer,
    card_tls_contexts,
    classify_handshake_end,
)
from SCP11.eim_local.engine.server import start_background, stop_background
from SCP11.eim_local.engine.service import STATE_SUCCESS, LocalEim, LocalEimError, OperationRequest
from SCP11.eim_local.engine.store import (
    HANDSHAKE_COMPLETED,
    HANDSHAKE_FAILED,
    HANDSHAKE_LOST,
    HANDSHAKE_REFUSED,
    EimStore,
    TlsHandshake,
    TrafficRecord,
    utc_now_ms,
)
from SCP11.eim_local.engine.traffic import describe_record
from tests.test_local_eim_service import EIM_FQDN, EIM_ID, ServiceTestBase, _free_port
from tests.test_local_eim_tls_setup import (
    STRICT_CIPHER,
    _client_context,
    _implicit,
    _request,
    _Store,
    _stored_tls_trust,
)
from yggdrasim_common.tls_tables import TLS_ALERT_DESCRIPTIONS

FQDN = "eim5.yggdrasim.local"
EID = "89049032123451234512345678901235"


def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


def _file_fingerprint(path: Path) -> str:
    return _fingerprint(x509.load_pem_x509_certificate(path.read_bytes()).public_bytes(serialization.Encoding.DER))


class _Leaves(_Store):
    """A store with one identity; ``build`` makes a CA-trusted setup named ``ca`` on its own FQDN."""

    def build(self, name: str = "ca", **options: str) -> tls_setup.TlsSetup:
        merged = {"chain": "intermediate", "trust": "root", "fqdn": FQDN, **options}
        return tls_setup.build_setup(self.directory, self.identity, tls_setup.parse_options(name, merged))

    def issue(self, name: str, setup: str = "ca", *, replace: bool = False, **options: str) -> tls_setup.LeafVariant:
        variant = tls_setup.parse_leaf_options(tls_setup.load_setup(self.directory, setup), name, options)
        return tls_setup.issue_leaf(self.directory, self.identity, setup, variant, replace=replace)

    def folder(self, name: str = "ca") -> Path:
        return tls_setup.setup_directory(self.directory, name)

    def names(self, name: str = "ca") -> list[str]:
        return [variant.name for variant in tls_setup.list_leaves(self.directory, name)]


class LeafVariantTests(_Leaves):
    def test_a_leaf_is_issued_under_the_setups_ca_and_the_built_one_is_kept(self) -> None:
        self.build()
        folder = self.folder()
        built = _file_fingerprint(folder / "leaf.pem")
        # A setup built before leaves existed reads as it is: one leaf, and reading writes nothing.
        self.assertEqual([(item.name, item.sha256) for item in tls_setup.list_leaves(self.directory, "ca")],
                         [("built", built)])
        tls_setup.describe_leaf(self.directory, "ca", tls_setup.load_leaf(self.directory, "ca", "built"))
        self.assertEqual(tls_setup.leaf_certificate_path(self.directory, "ca", "built"), folder / "leaf.pem")
        self.assertFalse((folder / "leaves").exists())

        variant = self.issue("cn-eimid", cn="eim_id", registered_id="on")
        self.assertEqual(self.names(), ["built", "cn-eimid"])
        # Issuing changes nothing the listener serves.
        self.assertEqual(_file_fingerprint(folder / "leaf.pem"), built)
        self.assertEqual(tls_setup.served_leaf(tls_setup.load_setup(self.directory, "ca")), "built")
        self.assertEqual(_file_fingerprint(folder / "leaves" / "built" / "leaf.pem"), built)

        leaf = x509.load_pem_x509_certificate((folder / "leaves" / "cn-eimid" / "leaf.pem").read_bytes())
        leaf.verify_directly_issued_by(x509.load_pem_x509_certificate((folder / "intermediate.pem").read_bytes()))
        self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, EIM_ID)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(names.get_values_for_type(x509.DNSName), [FQDN])
        self.assertEqual([oid.dotted_string for oid in names.get_values_for_type(x509.RegisteredID)], [EIM_ID])
        self.assertEqual(variant.sha256, _fingerprint(leaf.public_bytes(serialization.Encoding.DER)))
        self.assertEqual(tls_setup.load_leaf(self.directory, "ca", "cn-eimid").sha256, variant.sha256)
        # The chain file follows the setup's send (leaf and intermediate), the key stays private.
        self.assertEqual((folder / "leaves" / "cn-eimid" / "chain.pem").read_bytes().count(b"BEGIN CERTIFICATE"), 2)
        if os.name == "posix":
            self.assertEqual((folder / "leaves" / "cn-eimid" / "leaf_key.pem").stat().st_mode & 0o777, 0o600)
        described = "\n".join(tls_setup.describe_setup(self.directory, tls_setup.load_setup(self.directory, "ca")))
        self.assertIn("leaf variants built, cn-eimid; on the name: built", described)

    def test_use_puts_the_leaf_on_the_name_and_built_takes_it_back(self) -> None:
        self.build(send="full")
        folder = self.folder()
        built = _file_fingerprint(folder / "leaf.pem")
        variant = self.issue("short", send="leaf")
        self.assertEqual(tls_setup.use_leaf(self.directory, "ca", "short"), "built")
        setup = tls_setup.load_setup(self.directory, "ca")
        self.assertEqual((setup.leaf, tls_setup.served_leaf(setup)), ("short", "short"))
        self.assertEqual(_file_fingerprint(folder / "leaf.pem"), variant.sha256)
        self.assertEqual((folder / "chain.pem").read_bytes().count(b"BEGIN CERTIFICATE"), 1)
        material = tls_setup.serving_material(self.directory, self.identity, "ca")
        self.assertEqual((material.leaf, material.leaf_sha256), ("short", variant.sha256))
        # The key on the name is the leaf's own: a listener loads the pair.
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(material.chain_path, material.key_path)
        if os.name == "posix":
            self.assertEqual((folder / "leaf_key.pem").stat().st_mode & 0o777, 0o600)
        self.assertEqual([path.name for path in folder.glob("*.new")], [])
        # The leaf already on the name stays, and says so.
        self.assertEqual(tls_setup.use_leaf(self.directory, "ca", "short"), "short")
        self.assertEqual(tls_setup.use_leaf(self.directory, "ca", "built"), "short")
        self.assertEqual(_file_fingerprint(folder / "leaf.pem"), built)
        self.assertEqual((folder / "chain.pem").read_bytes().count(b"BEGIN CERTIFICATE"), 3)
        self.assertEqual(tls_setup.load_setup(self.directory, "ca").leaf, "")
        self.assertEqual(tls_setup.serving_material(self.directory, self.identity, "ca").leaf, "built")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "has no leaf nope"):
            tls_setup.use_leaf(self.directory, "ca", "nope")

    def test_a_client_that_trusts_the_ca_takes_each_leaf_while_the_trust_stays(self) -> None:
        self.build(chain="root")
        tls_setup.use_setup(self.directory, "ca")
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        for name, options in (("cn-eimid", {"cn": "eim_id"}), ("p384", {"curve": "p384"}), ("no-ski", {"ski": "off"})):
            with self.subTest(name):
                variant = self.issue(name, **options)
                tls_setup.use_leaf(self.directory, "ca", name)
                # What AddInitialEim would carry is the root, whatever leaf is on the name.
                self.assertEqual(tls_setup.trusted_tls_key_data(self.directory, self.identity).der, trust.der)
                server = self.serve()
                with socket.create_connection(server.server_address[:2], timeout=10) as raw:
                    with _client_context(trust).wrap_socket(raw, server_hostname=FQDN) as tls:
                        self.assertEqual(_fingerprint(tls.getpeercert(binary_form=True)), variant.sha256)
                server.stop()

    def test_leaf_options_are_checked(self) -> None:
        self.build()
        setup = tls_setup.load_setup(self.directory, "ca")
        # What belongs to the setup is refused on a leaf, by name.
        for option in ("chain", "trust", "versions", "ciphers", "client_auth", "sni", "fqdn", "ca_layout"):
            with self.assertRaisesRegex(tls_setup.TlsSetupError, f"Unknown leaf option.* {option}"):
                tls_setup.parse_leaf_options(setup, "x", {option: "root"})
        for pairs in ({"cn": "nonsense"}, {"validity": "soon"}, {"curve": "p999"}, {"send": "all"}, {"ski": "maybe"}):
            with self.assertRaises(tls_setup.TlsSetupError):
                tls_setup.parse_leaf_options(setup, "x", pairs)
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "names the leaf the setup was built with"):
            tls_setup.parse_leaf_options(setup, "built", {})
        for name in ("", "no spaces", "../up", "-dash"):
            with self.assertRaisesRegex(tls_setup.TlsSetupError, "A leaf name is"):
                tls_setup.parse_leaf_options(setup, name, {})
        with self.assertRaises(tls_setup.TlsSetupError):
            self.issue("shaped", layout="no-such-entry")
        self.assertEqual(self.names(), ["built"])

        first = self.issue("one")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "has a leaf one"):
            self.issue("one")
        self.assertNotEqual(self.issue("one", replace=True).sha256, first.sha256)
        tls_setup.use_leaf(self.directory, "ca", "one")
        for refused in (lambda: self.issue("one", replace=True), lambda: tls_setup.remove_leaf(self.directory, "ca", "one")):
            with self.assertRaisesRegex(tls_setup.TlsSetupError, "is the one TLS setup ca serves"):
                refused()
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "stays with it"):
            tls_setup.remove_leaf(self.directory, "ca", "built")
        tls_setup.use_leaf(self.directory, "ca", "built")
        tls_setup.remove_leaf(self.directory, "ca", "one")
        self.assertEqual(self.names(), ["built"])
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "has no leaf one"):
            tls_setup.remove_leaf(self.directory, "ca", "one")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "No TLS setup nosuch"):
            tls_setup.list_leaves(self.directory, "nosuch")
        with mock.patch.object(tls_setup, "MAX_LEAVES", 2):
            self.issue("a")
            with self.assertRaisesRegex(tls_setup.TlsSetupError, "At most 2 leaves"):
                self.issue("b")
            # Replacing one that exists adds none.
            self.issue("a", replace=True)

    def test_a_pinned_setup_carries_the_leaf_on_its_name_to_the_card(self) -> None:
        self.build()
        self.assertFalse(tls_setup.trust_follows_leaf(tls_setup.load_setup(self.directory, "ca")))
        for name, trust, member in (("pinned", "leaf", 0), ("key", "leaf_key", 1)):
            with self.subTest(trust):
                self.build(name, chain="self", trust=trust)
                self.assertTrue(tls_setup.trust_follows_leaf(tls_setup.load_setup(self.directory, name)))
                before = tls_setup.trusted_tls_key_data(self.directory, self.identity, name)
                variant = self.issue("second", setup=name)
                leaf = x509.load_pem_x509_certificate(
                    tls_setup.leaf_certificate_path(self.directory, name, "second").read_bytes())
                # A self-signed setup gets another self-signed leaf.
                self.assertEqual(leaf.issuer, leaf.subject)
                leaf.verify_directly_issued_by(leaf)
                self.assertEqual(tls_setup.trusted_tls_key_data(self.directory, self.identity, name).der, before.der)
                tls_setup.use_leaf(self.directory, name, "second")
                after = tls_setup.trusted_tls_key_data(self.directory, self.identity, name)
                self.assertNotEqual(after.der, before.der)
                # The hex LEAF SHOW --der prints is what the association carries for the leaf.
                self.assertEqual(tls_setup.leaf_der(self.directory, name, "second")[member], after.der)
                self.assertEqual(_fingerprint(tls_setup.leaf_der(self.directory, name, "second")[0]), variant.sha256)

    def _references(self) -> tuple[x509.Certificate, x509.Certificate, Path, Path]:
        from tests.test_local_eim_cert_layout import reference_ca, reference_leaf

        ca, _ca_key = reference_ca()
        leaf = reference_leaf()
        leaf_path, ca_path = self.directory / "reference-leaf.pem", self.directory / "reference-root.pem"
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        return leaf, ca, leaf_path, ca_path

    def test_a_shaped_setup_issues_leaves_of_the_same_shape(self) -> None:
        reference, _ca, leaf_path, ca_path = self._references()
        self.build("shaped", layout=str(leaf_path), ca_layout=str(ca_path))
        folder = self.folder("shaped")
        built = x509.load_pem_x509_certificate((folder / "leaf.pem").read_bytes())
        intermediate = x509.load_pem_x509_certificate((folder / "intermediate.pem").read_bytes())
        shape = [(item.oid, item.critical) for item in reference.extensions]
        self.assertEqual([(item.oid, item.critical) for item in built.extensions], shape)
        for name, options, common_name in (("same", {}, "EXAMPLE SM-EIM - CERT.EIM.TLS"), ("cn-host", {"cn": "host"}, FQDN),
                                           ("cn-eimid", {"cn": "eim_id"}, EIM_ID)):
            with self.subTest(name):
                variant = self.issue(name, setup="shaped", **options)
                leaf = x509.load_pem_x509_certificate((folder / "leaves" / name / "leaf.pem").read_bytes())
                # The reference's subject attribute order and its extension set, criticality and order.
                self.assertEqual([item.oid for item in leaf.subject], [item.oid for item in built.subject])
                self.assertEqual([(item.oid, item.critical) for item in leaf.extensions], shape)
                self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, common_name)
                names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                self.assertEqual(names.get_values_for_type(x509.DNSName), [FQDN])
                self.assertEqual([oid.dotted_string for oid in names.get_values_for_type(x509.RegisteredID)], [EIM_ID])
                self.assertEqual(leaf.issuer, intermediate.subject)
                leaf.verify_directly_issued_by(intermediate)
                self.assertNotEqual(leaf.public_key().public_numbers(), built.public_key().public_numbers())
                self.assertIn("end entity EXAMPLE SM-EIM - CERT.EIM.TLS", variant.layout_reference)
                self.assertIn("leaf layout", "\n".join(tls_setup.describe_leaf(self.directory, "shaped", variant)))
        # A leaf may leave the shape: layout=none is the generic one.
        generic = self.issue("generic", setup="shaped", layout="none")
        leaf = x509.load_pem_x509_certificate((folder / "leaves" / "generic" / "leaf.pem").read_bytes())
        self.assertEqual(generic.layout_reference, "")
        self.assertNotEqual([(item.oid, item.critical) for item in leaf.extensions], shape)
        self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, FQDN)
        leaf.verify_directly_issued_by(intermediate)
        # A client that trusts the shaped root takes a shaped leaf on the name.
        tls_setup.use_setup(self.directory, "shaped")
        tls_setup.use_leaf(self.directory, "shaped", "cn-host")
        server = self.serve()
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with _client_context(trust).wrap_socket(raw, server_hostname=FQDN) as tls:
                self.assertEqual(_fingerprint(tls.getpeercert(binary_form=True)),
                                 tls_setup.load_leaf(self.directory, "shaped", "cn-host").sha256)

    def test_a_setup_shaped_by_a_ca_reference_issues_generic_leaves(self) -> None:
        _leaf, _ca, _leaf_path, ca_path = self._references()
        # A CA certificate given as layout shapes the CA members; the leaf of such a setup is generic.
        self.build("ca-shaped", chain="root", layout=str(ca_path))
        folder = self.folder("ca-shaped")
        built = x509.load_pem_x509_certificate((folder / "leaf.pem").read_bytes())
        variant = self.issue("one", setup="ca-shaped", cn="eim_id")
        leaf = x509.load_pem_x509_certificate((folder / "leaves" / "one" / "leaf.pem").read_bytes())
        self.assertEqual(variant.layout_reference, "")
        self.assertEqual([(item.oid, item.critical) for item in leaf.extensions],
                         [(item.oid, item.critical) for item in built.extensions])
        leaf.verify_directly_issued_by(x509.load_pem_x509_certificate((folder / "root.pem").read_bytes()))
        # Named as a leaf's own layout, a CA certificate is refused, on any setup.
        other = self.directory / "another-root.pem"
        other.write_bytes(ca_path.read_bytes())
        self.build()
        for setup in ("ca-shaped", "ca"):
            with self.assertRaisesRegex(tls_setup.TlsSetupError, "is a CA certificate; a leaf takes"):
                self.issue("two", setup=setup, layout=str(other))

    def test_a_rebuild_takes_the_leaves_with_it(self) -> None:
        self.build()
        self.issue("one")
        tls_setup.use_leaf(self.directory, "ca", "one")
        rebuilt = tls_setup.build_setup(self.directory, self.identity, tls_setup.load_setup(self.directory, "ca"),
                                        replace=True)
        self.assertEqual(rebuilt.leaf, "")
        self.assertEqual(self.names(), ["built"])
        self.assertFalse((self.folder() / "leaves").exists())
        self.assertEqual(tls_setup.serving_material(self.directory, self.identity, "ca").leaf, "built")


class _Listening(_Leaves):
    """The ``ca`` setup in use and a listener built the way the service builds its own."""

    def setUp(self) -> None:
        super().setUp()
        self.build(chain="root")
        tls_setup.use_setup(self.directory, "ca")
        self.trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)

    def listen(self) -> LocalEimCardTlsServer:
        group = tls_setup.listener_groups(tls_setup.served_materials(self.directory, self.identity))[0]
        server = LocalEimCardTlsServer(
            self.engine, ("127.0.0.1", 0), card_tls_contexts(group), socket_timeout_s=10.0, tls_label=group[0].label,
            leaves={item.label: (item.leaf, item.leaf_sha256) for item in group})
        server.start_in_thread()
        self.addCleanup(server.stop)
        return server

    @contextlib.contextmanager
    def connect(self, server: LocalEimCardTlsServer, context: ssl.SSLContext | None = None, *, name: str = FQDN,
                session: ssl.SSLSession | None = None) -> Iterator[ssl.SSLSocket]:
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with (context or _client_context(self.trust)).wrap_socket(raw, server_hostname=name, session=session) as tls:
                yield tls

    def ask(self, tls: ssl.SSLSocket) -> int:
        """One ESipa GetEimPackage for an eUICC the eIM does not know; the exchange is recorded either way."""
        return _request(tls, "POST", ASN1_PATH, codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex(EID))))[0]

    def rows(self, settled: Callable[[list[TlsHandshake]], bool]) -> list[TlsHandshake]:
        """The handshake rows once *settled* holds: the worker thread writes after the client's side returns."""
        deadline = time.monotonic() + 10.0
        while True:
            rows = self.engine.store.handshakes(newest_first=False)
            if settled(rows):
                return rows
            if time.monotonic() > deadline:
                self.fail(f"the handshake rows did not settle: {rows}")
            time.sleep(0.02)


class HandshakeRecordTests(_Listening):
    def test_an_accepted_leaf_is_a_full_handshake_that_a_request_followed(self) -> None:
        server = self.listen()
        with self.connect(server) as tls:
            self.assertEqual(self.ask(tls), 200)
            self.assertEqual(self.ask(tls), 200)
        row = self.rows(lambda rows: len(rows) == 1 and rows[0].requests == 2)[0]
        served = tls_setup.serving_material(self.directory, self.identity)
        self.assertEqual(
            (row.outcome, row.server_name, row.tls_setup, row.leaf, row.leaf_sha256, row.resumed, row.alert),
            (HANDSHAKE_COMPLETED, FQDN, "ca", "built", served.leaf_sha256, False, ""))
        self.assertEqual((row.tls_version, row.tls_cipher, row.listener_port, row.peer_host),
                         ("TLSv1.2", STRICT_CIPHER, int(server.server_address[1]), "127.0.0.1"))
        self.assertEqual(row.eid, EID)
        # The exchange carries the same fingerprint, and its listing shows the first octets.
        exchange = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((exchange.tls_setup, exchange.tls_leaf), ("ca", served.leaf_sha256))
        self.assertIn(f"leaf {served.leaf_sha256[:8]}", describe_record(exchange).rows[-1].value)
        result = tls_results.leaf_results(self.engine.store, self.directory, "ca")[0]
        self.assertEqual((result.leaf, result.accepted, result.verdict(), result.eids, result.on_the_name),
                         ("built", 1, tls_results.VERDICT_ACCEPTED, [EID], True))

    def test_a_refused_leaf_names_the_alert_the_client_sent(self) -> None:
        # A client that was given another trust anchor.
        stranger = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        stranger.load_verify_locations(cafile=str(self.identity.tls_certificate_path))
        server = self.listen()
        with self.assertRaises(ssl.SSLCertVerificationError):
            with self.connect(server, stranger):
                pass
        row = self.rows(lambda rows: len(rows) == 1)[0]
        self.assertEqual((row.outcome, row.alert, row.leaf, row.requests), (HANDSHAKE_REFUSED, "unknown_ca", "built", 0))
        server.stop()
        # The same client and trust anchor, a leaf that breaks a rule: the alert says which.
        for name, options, alert in (("expired", {"validity": "expired"}, "certificate_expired"),
                                     ("other-host", {"san": "eim9.yggdrasim.local"}, "bad_certificate")):
            with self.subTest(name):
                variant = self.issue(name, **options)
                tls_setup.use_leaf(self.directory, "ca", name)
                server = self.listen()
                with self.assertRaises(ssl.SSLCertVerificationError):
                    with self.connect(server):
                        pass
                row = self.rows(lambda rows: len(rows) > 0 and rows[-1].leaf == name)[-1]
                self.assertEqual((row.outcome, row.alert, row.leaf_sha256, row.server_name),
                                 (HANDSHAKE_REFUSED, alert, variant.sha256, FQDN))
                server.stop()
        verdicts = {result.leaf: result.verdict()
                    for result in tls_results.leaf_results(self.engine.store, self.directory, "ca")}
        self.assertEqual(verdicts, {"built": "refused: unknown_ca", "expired": "refused: certificate_expired",
                                    "other-host": "refused: bad_certificate"})

    def test_a_handshake_nothing_followed_and_a_resumed_session_are_told_apart(self) -> None:
        server = self.listen()
        with self.connect(server):
            pass
        row = self.rows(lambda rows: len(rows) == 1)[0]
        self.assertEqual((row.outcome, row.resumed, row.requests), (HANDSHAKE_COMPLETED, False, 0))
        # TLS 1.2: the session id of a first connection resumes the second, and no Certificate is sent in it.
        context = _client_context(self.trust)
        with self.connect(server, context) as tls:
            self.assertEqual(self.ask(tls), 200)
            session = tls.session
        with self.connect(server, context, session=session) as tls:
            self.assertTrue(tls.session_reused)
            self.assertEqual(self.ask(tls), 200)
        rows = self.rows(lambda rows: len(rows) == 3 and rows[2].requests == 1)
        self.assertEqual([(item.resumed, item.requests) for item in rows], [(False, 0), (False, 1), (True, 1)])
        # TLS 1.3 resumes by a ticket the server sends after the handshake; the row says what the client saw.
        modern = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        modern.minimum_version = ssl.TLSVersion.TLSv1_3
        modern.load_verify_locations(cadata=self.trust.der)
        with self.connect(server, modern) as tls:
            self.assertEqual(self.ask(tls), 200)
            session = tls.session
        with self.connect(server, modern, session=session) as tls:
            reused = bool(tls.session_reused)
            self.assertEqual(self.ask(tls), 200)
        rows = self.rows(lambda rows: len(rows) == 5 and rows[4].requests == 1)
        self.assertEqual((rows[4].tls_version, rows[4].resumed), ("TLSv1.3", reused))
        # Resumptions are counted apart and decide nothing about the leaf.
        result = tls_results.leaf_results(self.engine.store, self.directory, "ca")[0]
        self.assertEqual((result.silent, result.accepted, result.resumed), (1, 3 - int(reused), 1 + int(reused)))
        self.assertEqual(result.verdict(), tls_results.VERDICT_ACCEPTED)

    def test_a_handshake_this_side_ends_and_one_that_is_dropped(self) -> None:
        server = self.listen()
        # A name that is not a Local eIM name is never answered.
        unchecked = _client_context(self.trust)
        unchecked.check_hostname = False
        with self.assertRaises(ssl.SSLError):
            with self.connect(server, unchecked, name="eim.example.test"):
                pass
        row = self.rows(lambda rows: len(rows) == 1)[0]
        self.assertEqual((row.outcome, row.alert, row.server_name), (HANDSHAKE_FAILED, "unrecognized_name", "eim.example.test"))
        # Something that is not TLS.
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            raw.sendall(b"GET /ping HTTP/1.1\r\nHost: " + FQDN.encode("ascii") + b"\r\n\r\n")
            raw.settimeout(5)
            with contextlib.suppress(OSError):
                raw.recv(64)
        row = self.rows(lambda rows: len(rows) == 2)[1]
        self.assertEqual((row.outcome, row.alert), (HANDSHAKE_FAILED, ""))
        self.assertTrue(row.reason)
        # A client that connects and goes away.
        socket.create_connection(server.server_address[:2], timeout=10).close()
        row = self.rows(lambda rows: len(rows) == 3)[2]
        self.assertEqual((row.outcome, row.alert), (HANDSHAKE_LOST, ""))
        # None of the three was offered a leaf: no chain was picked, or the name was refused.
        rows = self.engine.store.handshakes(newest_first=False)
        self.assertEqual([(item.tls_setup, item.leaf, item.leaf_sha256) for item in rows], [("", "", "")] * 3)
        self.assertEqual(tls_results.leaf_results(self.engine.store, self.directory, "ca")[0].attempts, 0)
        aside = tls_results.leaf_results(self.engine.store, self.directory)[-1]
        self.assertEqual((aside.setup, aside.sha256, sum(aside.failed.values()), aside.lost), ("", "", 2, 1))
        self.assertIn("(none offered)", tls_results.result_lines([aside])[1])
        # A client the picked leaf cannot serve: the chain was picked by name, so the row is the leaf's.
        rsa_only = _client_context(self.trust)
        rsa_only.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        with self.assertRaises(ssl.SSLError):
            with self.connect(server, rsa_only):
                pass
        row = self.rows(lambda rows: len(rows) == 4)[3]
        self.assertEqual((row.outcome, row.tls_setup, row.leaf, row.server_name), (HANDSHAKE_FAILED, "ca", "built", FQDN))
        result = tls_results.leaf_results(self.engine.store, self.directory, "ca")[0]
        self.assertEqual((sum(result.failed.values()), result.lost, result.accepted), (1, 0, 0))
        self.assertTrue(result.verdict().startswith("ended by this side: "), result.verdict())

    def test_the_rows_follow_the_leaf_on_the_name(self) -> None:
        built = tls_setup.serving_material(self.directory, self.identity).leaf_sha256
        server = self.listen()
        with self.connect(server) as tls:
            self.assertEqual(self.ask(tls), 200)
        server.stop()
        variant = self.issue("cn-eimid", cn="eim_id")
        tls_setup.use_leaf(self.directory, "ca", "cn-eimid")
        server = self.listen()
        with self.connect(server) as tls:
            self.assertEqual(_fingerprint(tls.getpeercert(binary_form=True)), variant.sha256)
            self.assertEqual(self.ask(tls), 200)
        rows = self.rows(lambda rows: len(rows) == 2 and all(item.requests == 1 for item in rows))
        self.assertEqual([(item.leaf, item.leaf_sha256) for item in rows],
                         [("built", built), ("cn-eimid", variant.sha256)])
        results = tls_results.leaf_results(self.engine.store, self.directory, "ca")
        self.assertEqual([(item.leaf, item.accepted, item.on_the_name) for item in results],
                         [("built", 1, False), ("cn-eimid", 1, True)])
        # A leaf that is gone keeps its rows, under the fingerprint they were recorded with.
        tls_setup.use_leaf(self.directory, "ca", "built")
        tls_setup.remove_leaf(self.directory, "ca", "cn-eimid")
        results = tls_results.leaf_results(self.engine.store, self.directory, "ca")
        self.assertEqual([(item.leaf, item.sha256, item.accepted) for item in results],
                         [("built", built, 1), ("cn-eimid", variant.sha256, 1)])
        # Every setup at once: the identity's own chain is listed by the rows alone.
        with self.connect(self.listen(), _client_context(
                tls_setup.trusted_tls_key_data(self.directory, self.identity, "identity")), name=EIM_FQDN) as tls:
            self.assertEqual(self.ask(tls), 200)
        self.rows(lambda rows: len(rows) == 3 and rows[2].requests == 1)
        everything = tls_results.leaf_results(self.engine.store, self.directory)
        self.assertIn(("identity", "identity", 1), [(item.setup, item.leaf, item.accepted) for item in everything])


class HandshakeStoreTests(_Store):
    def _row(self, **values: object) -> TlsHandshake:
        merged = {"tls_setup": "ca", "leaf": "built", "leaf_sha256": "AB" * 32, "outcome": HANDSHAKE_COMPLETED, **values}
        return TlsHandshake(id=0, at=utc_now_ms(), **merged)  # type: ignore[arg-type]

    def test_the_store_keeps_the_newest_handshakes_and_counts_their_requests(self) -> None:
        store = self.engine.store
        ids = [store.insert_handshake(self._row(peer_port=1000 + index), cap=3) for index in range(5)]
        rows = store.handshakes(newest_first=False)
        self.assertEqual([row.id for row in rows], ids[2:])
        self.assertEqual([row.peer_port for row in store.handshakes(limit=2)], [1004, 1003])
        store.insert_handshake(self._row(tls_setup="other"), cap=10)
        self.assertEqual([row.tls_setup for row in store.handshakes(setup="other")], ["other"])
        self.assertEqual(len(store.handshakes(setup="ca")), 3)
        # A request names the eUICC once; later ones count and keep it.
        store.note_handshake_request(ids[4], EID)
        store.note_handshake_request(ids[4], "")
        store.note_handshake_request(ids[4], "89049032000000000000000000000001")
        noted = next(row for row in store.handshakes() if row.id == ids[4])
        self.assertEqual((noted.requests, noted.eid), (3, EID))

    def test_an_older_store_gains_the_leaf_column_and_the_handshake_table(self) -> None:
        if sqlite3.sqlite_version_info < (3, 35):
            self.skipTest("this SQLite cannot drop a column to build the older layout")
        path = self.engine.store.path
        connection = sqlite3.connect(path)
        try:
            connection.execute("ALTER TABLE traffic DROP COLUMN tls_leaf")
            connection.execute("DROP TABLE tls_handshake")
            connection.commit()
        finally:
            connection.close()
        store = EimStore(path)
        record = TrafficRecord(id=0, at=utc_now_ms(), peer_host="127.0.0.1", peer_port=1, listener_port=2,
                               tls_setup="ca", tls_version="TLSv1.2", tls_cipher=STRICT_CIPHER, binding="esipa-asn1",
                               path=ASN1_PATH, request=b"\x01", status=200, response=b"\x02", duration_ms=1, eid="",
                               operation_id=None, note="", tls_leaf="CD" * 32)
        store.insert_traffic(record)
        self.assertEqual(store.traffic(limit=1)[0].tls_leaf, "CD" * 32)
        store.insert_handshake(self._row())
        self.assertEqual(len(store.handshakes()), 1)


class HandshakeEndTests(unittest.TestCase):
    @staticmethod
    def _error(kind: type[ssl.SSLError], reason: str) -> ssl.SSLError:
        error = kind(1, f"[SSL: {reason}] text")
        error.reason = reason  # type: ignore[misc]
        return error

    def test_an_alert_from_the_client_is_a_refusal_with_its_registry_name(self) -> None:
        for reason, alert in (
            ("TLSV1_ALERT_UNKNOWN_CA", "unknown_ca"), ("SSLV3_ALERT_BAD_CERTIFICATE", "bad_certificate"),
            ("SSLV3_ALERT_CERTIFICATE_EXPIRED", "certificate_expired"),
            ("SSLV3_ALERT_CERTIFICATE_UNKNOWN", "certificate_unknown"),
            ("SSLV3_ALERT_UNSUPPORTED_CERTIFICATE", "unsupported_certificate"),
            ("SSLV3_ALERT_HANDSHAKE_FAILURE", "handshake_failure"), ("TLSV1_ALERT_DECRYPT_ERROR", "decrypt_error"),
            ("TLSV1_ALERT_PROTOCOL_VERSION", "protocol_version"), ("TLSV1_ALERT_INTERNAL_ERROR", "internal_error"),
            ("TLSV1_ALERT_USER_CANCELLED", "user_canceled"), ("TLSV13_ALERT_CERTIFICATE_REQUIRED", "certificate_required"),
            ("TLSV1_UNRECOGNIZED_NAME", "unrecognized_name"), ("TLSV1_UNSUPPORTED_EXTENSION", "unsupported_extension"),
            ("TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE", "bad_certificate_status_response"),
        ):
            with self.subTest(reason):
                self.assertEqual(classify_handshake_end(self._error(ssl.SSLError, reason)),
                                 (HANDSHAKE_REFUSED, alert, reason))
                # RFC 8446 §6 registry names only, from the shared table.
                self.assertIn(alert, TLS_ALERT_DESCRIPTIONS.values())
        # An alert the table does not know yet is still a refusal, under the library's own word.
        self.assertEqual(classify_handshake_end(self._error(ssl.SSLError, "TLSV1_ALERT_SOMETHING_NEW")),
                         (HANDSHAKE_REFUSED, "something_new", "TLSV1_ALERT_SOMETHING_NEW"))

    def test_what_this_side_ends_and_what_is_dropped(self) -> None:
        for reason in ("NO_SHARED_CIPHER", "PEER_DID_NOT_RETURN_A_CERTIFICATE", "CERTIFICATE_VERIFY_FAILED",
                       "UNSUPPORTED_PROTOCOL", "HTTP_REQUEST", "CALLBACK_FAILED", "WRONG_VERSION_NUMBER"):
            with self.subTest(reason):
                self.assertEqual(classify_handshake_end(self._error(ssl.SSLError, reason)), (HANDSHAKE_FAILED, "", reason))
        for error in (self._error(ssl.SSLEOFError, ""), self._error(ssl.SSLZeroReturnError, ""),
                      self._error(ssl.SSLError, "UNEXPECTED_EOF_WHILE_READING"), self._error(ssl.SSLError, ""),
                      ConnectionResetError(104, "Connection reset by peer"),
                      TimeoutError("The handshake operation timed out"), OSError()):
            with self.subTest(repr(error)):
                outcome, alert, reason = classify_handshake_end(error)
                self.assertEqual((outcome, alert), (HANDSHAKE_LOST, ""))
                self.assertTrue(reason)


class LeafResultTests(unittest.TestCase):
    @staticmethod
    def _row(sha: str, outcome: str = HANDSHAKE_COMPLETED, **values: object) -> TlsHandshake:
        return TlsHandshake(id=0, at=str(values.pop("at", "2026-01-01T00:00:00.000+00:00")), tls_setup="ca",
                            leaf=str(values.pop("leaf", "")), leaf_sha256=sha, outcome=outcome,
                            **values)  # type: ignore[arg-type]

    def _results(self, rows: list[TlsHandshake], names: tuple[str, ...] = ("a",)) -> list[tls_results.LeafResult]:
        leaves = {"ca": [tls_setup.LeafVariant(name=name, sha256=name.upper() * 64) for name in names]}
        return tls_results.summarise(rows, leaves, {"ca": names[0]})

    def test_each_verdict(self) -> None:
        sha = "A" * 64
        full = self._row(sha, requests=1)
        silent = self._row(sha)
        resumed = self._row(sha, resumed=True, requests=1)
        unknown_ca = self._row(sha, HANDSHAKE_REFUSED, alert="unknown_ca")
        bad = self._row(sha, HANDSHAKE_REFUSED, alert="bad_certificate")
        failed = self._row(sha, HANDSHAKE_FAILED, reason="NO_SHARED_CIPHER")
        lost = self._row(sha, HANDSHAKE_LOST, reason="SSLEOFError")
        for rows, verdict in (
            ([], tls_results.VERDICT_NONE),
            ([resumed, resumed], tls_results.VERDICT_RESUMED),
            ([lost, resumed], tls_results.VERDICT_LOST),
            ([failed, lost], "ended by this side: NO_SHARED_CIPHER"),
            ([silent, failed, lost], tls_results.VERDICT_SILENT),
            ([bad, unknown_ca, bad, silent], "refused: bad_certificate, unknown_ca"),
            ([full, resumed, silent, lost], tls_results.VERDICT_ACCEPTED),
            ([full, unknown_ca], tls_results.VERDICT_MIXED),
        ):
            with self.subTest(verdict):
                result = self._results(rows)[0]
                self.assertEqual(result.verdict(), verdict)
                self.assertEqual(result.attempts, len(rows))

    def test_rows_are_grouped_by_the_fingerprint_served(self) -> None:
        rows = [
            self._row("A" * 64, requests=1, eid=EID, at="2026-01-01T00:00:02.000+00:00"),
            self._row("A" * 64, requests=1, eid=EID, at="2026-01-01T00:00:01.000+00:00"),
            self._row("B" * 64, HANDSHAKE_REFUSED, alert="unknown_ca"),
            self._row("F" * 64, requests=1, leaf="gone"),
            self._row("E" * 64, HANDSHAKE_LOST),
        ]
        results = self._results(rows, names=("a", "b", "c"))
        self.assertEqual([(item.leaf, item.sha256[:1], item.attempts, item.on_the_name) for item in results],
                         [("a", "A", 2, True), ("b", "B", 1, False), ("c", "C", 0, False), ("gone", "F", 1, False),
                          ("", "E", 1, False)])
        self.assertEqual((results[0].first_at, results[0].last_at, results[0].eids),
                         ("2026-01-01T00:00:01.000+00:00", "2026-01-01T00:00:02.000+00:00", [EID]))
        lines = tls_results.result_lines(results)
        self.assertEqual(len(lines), 6)
        # Every count carries its word: the GUI's result list collapses the padding.
        self.assertEqual(" ".join(lines[1].split()), f"* ca a {'A' * 8} accepted -- full 2")
        self.assertEqual(" ".join(lines[2].split()), f"ca b {'B' * 8} refused: unknown_ca -- refused 1")
        self.assertEqual(" ".join(lines[3].split()), f"ca c {'C' * 8} {tls_results.VERDICT_NONE}")
        self.assertEqual(" ".join(lines[5].split()), f"ca (earlier leaf) {'E' * 8} {tls_results.VERDICT_LOST} -- lost 1")
        nothing = tls_results.summarise([self._row("", HANDSHAKE_LOST)], {}, {})
        self.assertEqual(" ".join(tls_results.result_lines(nothing)[1].split()),
                         f"ca (none offered) - {tls_results.VERDICT_LOST} -- lost 1")
        busy = self._results([self._row("A" * 64, requests=1), self._row("A" * 64), self._row("A" * 64, resumed=True),
                              self._row("A" * 64, HANDSHAKE_REFUSED, alert="unknown_ca"),
                              self._row("A" * 64, HANDSHAKE_REFUSED, alert="bad_certificate"),
                              self._row("A" * 64, HANDSHAKE_REFUSED, alert="bad_certificate"),
                              self._row("A" * 64, HANDSHAKE_FAILED, reason="NO_SHARED_CIPHER"),
                              self._row("A" * 64, HANDSHAKE_LOST)])[0]
        self.assertEqual(tls_results.count_text(busy),
                         "full 1, full without a request 1, resumed 1, refused 3 (bad_certificate 2, unknown_ca 1), "
                         "ended here 1, lost 1")
        self.assertEqual(json.loads(json.dumps([item.as_dict() for item in results]))[1]["refused"], {"unknown_ca": 1})
        self.assertIn("alert unknown_ca", tls_results.handshake_line(rows[2]))
        self.assertIn("1 request(s)", tls_results.handshake_line(rows[0]))


class SurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.engine = LocalEim(self.directory)
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn=EIM_FQDN)

    def test_the_shell_verb(self) -> None:
        from SCP11.eim_local.engine_shell import EngineVerbs
        from SCP11.eim_local.main import EimLocalShell

        shell = EimLocalShell()

        def run(line: str) -> str:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                shell._dispatch_command_line(line, source="test")
            return buffer.getvalue()

        run(f"TLS-SETUP NEW ca-chain chain=intermediate trust=root fqdn={FQDN}")
        self.assertIn("* built", run("TLS-SETUP LEAF ca-chain"))
        issued = run("TLS-SETUP LEAF ca-chain NEW cn-eimid cn=eim_id --use")
        self.assertIn("Leaf cn-eimid issued under TLS setup ca-chain", issued)
        self.assertIn("serves leaf cn-eimid", issued)
        self.assertIn("before: built", issued)
        self.assertIn("not running", issued)
        self.assertIn("* cn-eimid", run("TLS-SETUP LEAF ca-chain LIST"))
        self.assertIn(", leaf cn-eimid", run("TLS-SETUP"))
        self.assertIn("leaf variants built, cn-eimid; on the name: cn-eimid", run("TLS-SETUP SHOW ca-chain"))
        self.assertIn("still serves cn-eimid", run("TLS-SETUP LEAF ca-chain NEW expired validity=expired"))
        shown = run("TLS-SETUP LEAF ca-chain SHOW cn-eimid --der")
        certificate, public_key = tls_setup.leaf_der(self.directory, "ca-chain", "cn-eimid")
        self.assertIn(f"certificate DER {certificate.hex().upper()}", shown)
        self.assertIn(f"public key DER (SubjectPublicKeyInfo) {public_key.hex().upper()}", shown)
        self.assertNotIn("DER", run("TLS-SETUP LEAF ca-chain SHOW cn-eimid"))
        self.assertIn("Unknown leaf option", run("TLS-SETUP LEAF ca-chain NEW bad chain=root"))
        self.assertIn("is the one TLS setup ca-chain serves", run("TLS-SETUP LEAF ca-chain REMOVE cn-eimid"))
        self.assertIn("already has leaf cn-eimid", run("TLS-SETUP LEAF ca-chain USE cn-eimid"))
        self.assertIn("No TLS setup nosuch", run("TLS-SETUP LEAF nosuch"))
        self.assertIn("has no leaf nosuch", run("TLS-SETUP LEAF ca-chain USE nosuch"))
        for usage in ("TLS-SETUP LEAF", "TLS-SETUP LEAF ca-chain NEW", "TLS-SETUP LEAF ca-chain PAINT x"):
            self.assertIn("Usage:", run(usage), usage)

        # A rebuild or a removal takes the CA and its leaves; both ask first.
        self.assertIn("2 further leaf(s) (cn-eimid, expired); --force rebuilds it anyway",
                      run("TLS-SETUP NEW ca-chain --replace"))
        self.assertIn("--force removes it anyway", run("TLS-SETUP REMOVE ca-chain"))
        self.assertEqual([item.name for item in tls_setup.list_leaves(self.directory, "ca-chain")],
                         ["built", "cn-eimid", "expired"])
        self.assertIn("serves leaf built", run("TLS-SETUP LEAF ca-chain USE built"))
        self.assertIn("removed", run("TLS-SETUP LEAF ca-chain REMOVE cn-eimid"))
        self.assertIn("removed", run("TLS-SETUP LEAF ca-chain REMOVE expired"))
        # A card associated under the setup holds it the same way.
        record = self.engine.register(EID)
        with self.engine.store.transaction() as connection:
            record.data["tls_setup"] = "ca-chain"
            self.engine.store.save_record(record, connection)
        self.assertIn("1 card(s) associated under it (78901235); --force removes it anyway",
                      run("TLS-SETUP REMOVE ca-chain"))
        self.assertIn("TLS setup ca-chain built", run(f"TLS-SETUP NEW ca-chain fqdn={FQDN} --replace --force"))
        self.assertIn("removed", run("TLS-SETUP REMOVE ca-chain --force"))

        # A setup that pins the leaf does not swap without a word on the card. Its name is one the Local
        # eIM never associates under, so no step here could reach a card.
        run("TLS-SETUP NEW pinned trust=leaf fqdn=eim.live.internal")
        run("TLS-SETUP LEAF pinned NEW second")
        refused = run("TLS-SETUP LEAF pinned USE second")
        for part in ("trust the leaf itself (trust=leaf)", "--associate", "--serve-only",
                     "TLS-SETUP LEAF pinned SHOW second --der", "(the certificate for this setup)"):
            self.assertIn(part, refused)
        self.assertIn("* built", run("TLS-SETUP LEAF pinned"))
        # Asked with NEW ... --use, the same refusal comes before anything is issued.
        self.assertIn("trust the leaf itself", run("TLS-SETUP LEAF pinned NEW third --use"))
        self.assertEqual([item.name for item in tls_setup.list_leaves(self.directory, "pinned")], ["built", "second"])
        self.assertIn("refuses this one until it is told", run("TLS-SETUP LEAF pinned NEW third --use --serve-only"))
        self.assertIn("* third", run("TLS-SETUP LEAF pinned"))
        self.assertIn("refuses this one until it is told", run("TLS-SETUP LEAF pinned USE second --serve-only"))
        self.assertIn("* second", run("TLS-SETUP LEAF pinned"))
        with mock.patch.object(EngineVerbs, "cmd_associate") as associate:
            swapped = run("TLS-SETUP LEAF pinned USE built --associate --yes")
        self.assertIn("serves leaf built", swapped)
        associate.assert_called_once_with("setup=pinned --yes")
        run("TLS-SETUP NEW pinned-key trust=leaf_key fqdn=eim.live.internal")
        run("TLS-SETUP LEAF pinned-key NEW second")
        self.assertIn("(the public key for this setup)", run("TLS-SETUP LEAF pinned-key USE second"))

        results = run("TLS-SETUP RESULTS")
        self.assertIn("0 handshake(s) on record", results)
        self.assertIn(tls_results.VERDICT_NONE, results)
        self.engine.store.insert_handshake(TlsHandshake(
            id=0, at=utc_now_ms(), peer_host="127.0.0.1", peer_port=4000, server_name="eim.live.internal",
            tls_setup="pinned", leaf="second", outcome=HANDSHAKE_REFUSED, alert="bad_certificate",
            leaf_sha256=tls_setup.load_leaf(self.directory, "pinned", "second").sha256))
        results = run("TLS-SETUP RESULTS pinned --rows")
        self.assertIn("1 handshake(s) on record", results)
        self.assertIn("refused: bad_certificate", results)
        self.assertIn("127.0.0.1:4000  eim.live.internal  pinned / second", results)
        self.assertNotIn("pinned-key", results)
        listed = json.loads(run("TLS-SETUP RESULTS pinned --rows --json"))
        self.assertEqual([(item["leaf"], item["refused"]) for item in listed["results"]],
                         [("built", {}), ("second", {"bad_certificate": 1}), ("third", {})])
        self.assertEqual(listed["handshakes"][0]["alert"], "bad_certificate")
        self.assertIn("takes a number", run("TLS-SETUP RESULTS n=many"))
        self.assertIn("No TLS setup nosuch", run("TLS-SETUP RESULTS nosuch"))

    def test_the_gui_actions(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        def run(action_id: str, **values: object) -> str:
            spec = next(entry for entry in SPECS if entry.id == action_id)
            return "\n".join(spec.dispatcher(ActionContext(), **values)["lines"])

        run("eim_local.tls_setup_new", name="ca", chain="root", trust="root", fqdn=FQDN, ski=True,
            ca_basic_constraints=True, server_auth=True)
        # The form's defaults: every option on "setup", which keeps the setup's own value.
        defaults = {"cn": "setup", "registered_id": "setup", "san": "", "layout": "", "validity": "setup",
                    "ski": "setup", "server_auth": "setup", "curve": "setup", "send": "setup"}
        plain = run("eim_local.tls_leaf_new", setup="ca", name="plain", replace=False, use=False, **defaults)
        self.assertIn("serverAuth on", plain)
        self.assertIn("still serves built", plain)
        issued = run("eim_local.tls_leaf_new", setup="ca", name="no-eku", replace=False, use=True,
                     **{**defaults, "server_auth": "off", "cn": "eim_id"})
        self.assertIn("CN eim_id", issued)
        self.assertIn("serverAuth off", issued)
        self.assertIn("serves leaf no-eku", issued)
        self.assertIn("* no-eku", run("eim_local.tls_leaf_list", setup="ca"))
        self.assertIn("certificate DER 30", run("eim_local.tls_leaf_show", setup="ca", name="no-eku", der=True))
        self.assertNotIn("DER", run("eim_local.tls_leaf_show", setup="ca", name="no-eku", der=False))
        with self.assertRaisesRegex(ValueError, "Confirm"):
            run("eim_local.tls_leaf_use", setup="ca", name="built", then="associate", confirm=False, reader="")
        self.assertIn("serves leaf built", run("eim_local.tls_leaf_use", setup="ca", name="built", then="serve"))
        self.assertIn("removed", run("eim_local.tls_leaf_remove", setup="ca", name="no-eku"))
        results = run("eim_local.tls_results", setup="ca", rows=True, count=5)
        self.assertIn(tls_results.VERDICT_NONE, results)
        self.assertIn("The newest 0 handshake(s)", results)
        self.assertIn("ca ", run("eim_local.tls_results", setup="", rows=False, count=40))
        # The forms carry the force the shell asks for.
        with self.assertRaisesRegex(LocalEimError, "--force removes it anyway"):
            run("eim_local.tls_setup_remove", name="ca", force=False)
        with self.assertRaisesRegex(LocalEimError, "--force rebuilds it anyway"):
            run("eim_local.tls_setup_new", name="ca", replace=True, force=False)
        self.assertIn("TLS setup ca built", run("eim_local.tls_setup_new", name="ca", replace=True, force=True))
        self.assertIn("removed", run("eim_local.tls_setup_remove", name="ca", force=True))

    def test_the_new_actions_have_a_tab(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

        source = (Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js").read_text(
            encoding="utf-8")
        registered = {spec.id for spec in SPECS}
        for suffix in ("tls_leaf_new", "tls_leaf_list", "tls_leaf_show", "tls_leaf_use", "tls_leaf_remove",
                       "tls_results"):
            self.assertIn(f"eim_local.{suffix}", registered)
            self.assertIn(f'"{suffix}"', source, suffix)


class UpdateEimCarriesALeafTests(ServiceTestBase):
    def test_update_eim_gives_the_card_a_pinned_leaf_without_a_reset(self) -> None:
        identity = self.engine.identity()
        eid = codec.normalize_eid(self.card.eid)
        # trustedCertificateTls [1] for trust=leaf, trustedEimPkTls [0] for trust=leaf_key; LEAF SHOW --der prints both.
        for name, trust, member, tag in (("pinned", "leaf", 0, b"\xA1"), ("pinned-key", "leaf_key", 1, b"\xA0")):
            with self.subTest(trust):
                tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(name, {"trust": trust}))
                tls_setup.use_setup(self.directory, name)
                self.engine.associate(self.card.exchange, self.card.eid, setup=name)
                token = self.engine.store.record(eid).association_token
                built = tls_setup.leaf_der(self.directory, name, "built")[member]
                self.assertEqual(_stored_tls_trust(self.card.exchange(codec.tlv(b"\xBF\x55", b""))), _implicit(tag, built))

                variant = tls_setup.parse_leaf_options(tls_setup.load_setup(self.directory, name), "second", {})
                tls_setup.issue_leaf(self.directory, identity, name, variant)
                given = tls_setup.leaf_der(self.directory, name, "second")[member]
                # updateEim with the eimId and trustedPublicKeyDataTls alone (SGP.32 v1.3 §2.11.1.1.2).
                operation = self.engine.submit([OperationRequest(
                    eid=self.card.eid, type="UPDATE_EIM", params={"eim_id": EIM_ID, "tls_certificate": given.hex()})])[0]
                deliver(self.engine, self.card.exchange, self.card.eid)
                self.assertEqual(self.engine.operation(operation.id).state, STATE_SUCCESS)
                self.assertEqual(_stored_tls_trust(self.card.exchange(codec.tlv(b"\xBF\x55", b""))), _implicit(tag, given))
                # The association is the one the card had: no reset ran.
                self.assertEqual(self.engine.store.record(eid).association_token, token)
                # With the leaf on the name, an association would carry the same.
                tls_setup.use_leaf(self.directory, name, "second")
                self.assertEqual(tls_setup.trusted_tls_key_data(self.directory, identity).der, given)


class BackgroundLeafTests(ServiceTestBase):
    def test_use_restarts_the_service_and_its_rows_name_the_new_leaf(self) -> None:
        from SCP11.eim_local.main import EimLocalShell

        port, card = _free_port(), _free_port()
        identity = self.engine.identity()
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "ca", {"chain": "root", "trust": "root", "fqdn": FQDN}))
        tls_setup.use_setup(self.directory, "ca")
        start_background(self.directory, port=port, tls_port=card)
        self.addCleanup(stop_background, self.directory)
        trust = tls_setup.trusted_tls_key_data(self.directory, identity)

        def served() -> str:
            with socket.create_connection(("127.0.0.1", card), timeout=10) as raw:
                with _client_context(trust).wrap_socket(raw, server_hostname=FQDN) as tls:
                    self.assertEqual(_request(tls, "GET", "/ping")[0], 200)
                    return _fingerprint(tls.getpeercert(binary_form=True))

        built = served()
        self.assertEqual(built, tls_setup.load_leaf(self.directory, "ca", "built").sha256)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            EimLocalShell()._dispatch_command_line("TLS-SETUP LEAF ca NEW cn-eimid cn=eim_id --use", source="test")
        self.assertIn(f"Service restarted: card-facing TLS at https://127.0.0.1:{card}", buffer.getvalue())
        variant = tls_setup.load_leaf(self.directory, "ca", "cn-eimid")
        self.assertEqual(served(), variant.sha256)
        # The service is another process; its rows are in the store this one reads.
        deadline = time.monotonic() + 10.0
        while len(self.engine.store.handshakes()) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        rows = self.engine.store.handshakes(newest_first=False)
        self.assertEqual([(row.tls_setup, row.leaf, row.leaf_sha256, row.outcome) for row in rows],
                         [("ca", "built", built, HANDSHAKE_COMPLETED), ("ca", "cn-eimid", variant.sha256, HANDSHAKE_COMPLETED)])


if __name__ == "__main__":
    unittest.main()
