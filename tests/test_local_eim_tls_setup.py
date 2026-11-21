# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Local eIM TLS setups and the card-facing TLS listener.

A card's IPAe reaches the eIM over TLS with server authentication and trusts
what AddInitialEim put in trustedPublicKeyDataTls (SGP.32 v1.3 §2.6.3.2, p.21-22;
§2.11.1.1.2, p.32-33). The client here plays that IPAe as strictly as a stock
TLS stack allows: TLS 1.2 only, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (one of
the two suites §2.6.3.2 requires), the eIM FQDN as server name, and the trust
anchor taken from the AddInitialEim the engine builds.
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from SCP11.eim_local.engine import codec, tls_setup
from SCP11.eim_local.engine.esipa import ASN1_CONTENT_TYPE, ASN1_PATH, LocalEimCardTlsServer, card_tls_context
from SCP11.eim_local.engine.server import card_port, describe, local_route, restart_background, start_background, stop_background
from SCP11.eim_local.engine.service import STATE_SUCCESS, LocalEim, OperationRequest
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv
from SCP11.shared.eim_configuration_data import (
    KEY_FORM_CERTIFICATE,
    KEY_FORM_PUBLIC_KEY,
    verify_add_initial_eim_request,
)
from tests.test_local_eim_service import EIM_FQDN, EIM_ID, ServiceTestBase, _free_port

STRICT_CIPHER = "ECDHE-ECDSA-AES128-GCM-SHA256"


def _implicit(tag: bytes, der: bytes) -> bytes:
    """*der* under an implicit context tag: trustedEimPkTls [0], trustedCertificateTls [1] (AUTOMATIC TAGS)."""
    return tag + der[1:]


def _entries(answer: bytes) -> list[dict[bytes, bytes]]:
    _tag, listing, _raw = read_single_ber_tlv(answer)
    _tag, entries, _raw = read_single_ber_tlv(listing)
    rows: list[dict[bytes, bytes]] = []
    offset = 0
    while offset < len(entries):
        _tag, entry, _raw, offset = read_ber_tlv(entries, offset)
        members: dict[bytes, bytes] = {}
        inner = 0
        while inner < len(entry):
            tag, value, _raw, inner = read_ber_tlv(entry, inner)
            members[tag] = value
        rows.append(members)
    return rows


def _eim_ids(answer: bytes) -> list[str]:
    return [row.get(b"\x80", b"").decode("utf-8") for row in _entries(answer)]


def _stored_tls_trust(answer: bytes, eim_id: str = EIM_ID) -> bytes | None:
    """trustedPublicKeyDataTls [6] of *eim_id*'s entry in a GetEimConfigurationData answer (SGP.32 v1.3 §5.9.18)."""
    for members in _entries(answer):
        if members.get(b"\x80") == eim_id.encode("utf-8"):
            return members.get(b"\xA6")
    raise AssertionError(f"no entry for {eim_id} on the card")


def _client_context(trust: object, *, partial_chain: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(STRICT_CIPHER)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=trust.der)  # type: ignore[attr-defined]
    if partial_chain:
        # A card may trust an intermediate CA (§2.11.1.1.2); OpenSSL needs the flag to stop there.
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context


def _request(tls: ssl.SSLSocket, method: str, path: str, body: bytes = b"") -> tuple[int, bytes]:
    head = (f"{method} {path} HTTP/1.1\r\nHost: {EIM_FQDN}\r\nContent-Type: {ASN1_CONTENT_TYPE}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
    tls.sendall(head + body)
    reader = tls.makefile("rb")
    status = int(reader.readline().split()[1])
    length = 0
    while True:
        line = reader.readline().strip()
        if not line:
            break
        name, _sep, value = line.decode("latin-1").partition(":")
        if name.lower() == "content-length":
            length = int(value.strip())
    return status, reader.read(length) if length else b""


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": str(self.directory)})
        environment.start()
        self.addCleanup(environment.stop)
        self.engine = LocalEim(self.directory)
        self.identity = self.engine.new_identity(eim_id=EIM_ID, eim_fqdn=EIM_FQDN)

    def serve(self) -> LocalEimCardTlsServer:
        material = tls_setup.serving_material(self.directory, self.identity)
        context = card_tls_context(material.chain_path, material.key_path, versions=material.versions,
                                   ciphers=material.ciphers, client_auth=material.client_auth,
                                   client_ca_path=material.client_ca_path, sni_names=material.sni_names)
        server = LocalEimCardTlsServer(self.engine, ("127.0.0.1", 0), context, socket_timeout_s=10.0)
        server.start_in_thread()
        self.addCleanup(server.stop)
        return server

    def setup(self, name: str, **options: str) -> tls_setup.TlsSetup:
        built = tls_setup.build_setup(self.directory, self.identity, tls_setup.parse_options(name, options))
        tls_setup.use_setup(self.directory, name)
        return built

    def handshake(self, server: LocalEimCardTlsServer, *, partial_chain: bool = False) -> int:
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        context = _client_context(trust, partial_chain=partial_chain)
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=EIM_FQDN) as tls:
                self.assertEqual((tls.version(), tls.cipher()[0]), ("TLSv1.2", STRICT_CIPHER))
                return _request(tls, "GET", "/ping")[0]


class ChainShapeTests(_Store):
    def test_each_chain_shape_verifies_against_what_the_card_is_told_to_trust(self) -> None:
        for name, options, partial in (
            ("self-leaf", {}, False),
            ("root-ca", {"chain": "root", "trust": "root"}, False),
            ("root-leaf", {"chain": "root", "trust": "leaf"}, True),
            ("two-cas", {"chain": "intermediate", "trust": "root"}, False),
            ("mid-ca", {"chain": "intermediate", "trust": "intermediate"}, True),
            ("p384", {"curve": "p384", "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256"}, False),
            ("ed25519", {"curve": "ed25519"}, False),
        ):
            with self.subTest(name):
                self.setup(name, **options)
                self.assertEqual(self.handshake(self.serve(), partial_chain=partial), 200)

    def test_the_identity_certificate_serves_when_no_setup_is_in_use(self) -> None:
        self.assertEqual(tls_setup.active_name(self.directory), "")
        self.assertEqual(tls_setup.serving_material(self.directory, self.identity).label, "identity")
        self.assertEqual(self.handshake(self.serve()), 200)

    def test_a_broken_rule_is_built_as_asked(self) -> None:
        for name, options, failure in (
            ("expired", {"validity": "expired"}, "expired"),
            ("later", {"validity": "not_yet_valid"}, "not yet valid"),
            ("other-name", {"san": "other.example.test"}, "Hostname mismatch"),
            ("leaf-only", {"chain": "intermediate", "trust": "root", "send": "leaf"}, "issuer certificate"),
        ):
            with self.subTest(name):
                self.setup(name, **options)
                with self.assertRaises(ssl.SSLCertVerificationError) as raised:
                    self.handshake(self.serve())
                self.assertIn(failure, str(raised.exception))
        self.setup("bare", chain="root", trust="root", ski="off", ca_basic_constraints="off", server_auth="off")
        folder = tls_setup.setup_directory(self.directory, "bare")
        leaf = x509.load_pem_x509_certificate((folder / "leaf.pem").read_bytes())
        root = x509.load_pem_x509_certificate((folder / "root.pem").read_bytes())
        for certificate, missing in ((leaf, x509.SubjectKeyIdentifier), (leaf, x509.ExtendedKeyUsage),
                                     (root, x509.SubjectKeyIdentifier), (root, x509.BasicConstraints)):
            with self.assertRaises(x509.ExtensionNotFound):
                certificate.extensions.get_extension_for_class(missing)
        self.assertEqual(len((folder / "chain.pem").read_bytes().split(b"-----BEGIN CERTIFICATE-----")) - 1, 1)

    def test_the_listener_sends_what_the_setup_names(self) -> None:
        for send, count in (("leaf", 1), ("chain", 2), ("full", 3)):
            built = self.setup(f"send-{send}", chain="intermediate", trust="root", send=send)
            chain = (tls_setup.setup_directory(self.directory, built.name) / "chain.pem").read_bytes()
            self.assertEqual(chain.count(b"-----BEGIN CERTIFICATE-----"), count, send)

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command")
    def test_the_listener_accepts_a_maximum_fragment_length(self) -> None:
        # A constrained client asks for smaller records (RFC 6066 §4); SGP.32 v1.3 §2.6.3.1
        # (p.21) asks an RSP Server to accept it. OpenSSL's server side does so unasked.
        server = self.serve()
        request = f"GET /ping HTTP/1.1\r\nHost: {EIM_FQDN}\r\nConnection: close\r\n\r\n"
        answer = subprocess.run(
            ["openssl", "s_client", "-connect", "%s:%d" % server.server_address[:2], "-servername", EIM_FQDN,
             "-tls1_2", "-maxfraglen", "512", "-tlsextdebug", "-ign_eof"],
            input=request, capture_output=True, text=True, timeout=20, check=False,
        )
        if answer.returncode != 0 and "maxfraglen" in answer.stderr:
            self.skipTest("this openssl command has no -maxfraglen (before 1.1.1)")
        self.assertIn('TLS server extension "max fragment length"', answer.stdout)
        self.assertIn("HTTP/1.1 200 OK", answer.stdout)

    def test_a_tls_1_3_only_listener_refuses_a_tls_1_2_client(self) -> None:
        self.setup("tls13", versions="1.3")
        with self.assertRaises(ssl.SSLError):
            self.handshake(self.serve())


class TrustAndOptionTests(_Store):
    def test_the_trust_member_follows_the_setup(self) -> None:
        identity_trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        self.assertEqual((identity_trust.form, identity_trust.der), (KEY_FORM_CERTIFICATE, self.identity.tls_certificate_der()))
        self.setup("key", trust="leaf_key")
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        leaf = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, "key") / "leaf.pem").read_bytes())
        spki = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual((trust.form, trust.der), (KEY_FORM_PUBLIC_KEY, spki))
        _reset, request = self.engine.association_requests()
        self.assertIn(_implicit(b"\xA0", spki), request)
        self.setup("root", chain="root", trust="root")
        root_der = x509.load_pem_x509_certificate(
            (tls_setup.setup_directory(self.directory, "root") / "root.pem").read_bytes()
        ).public_bytes(serialization.Encoding.DER)
        self.assertIn(_implicit(b"\xA1", root_der), self.engine.association_requests()[1])
        self.setup("untrusted", trust="none")
        self.assertIsNone(tls_setup.trusted_tls_key_data(self.directory, self.identity))
        # The request re-reads with trustedPublicKeyDataTls [6] absent and every other member as configured.
        expected = replace(self.identity.configuration_data(include_tls=False), trusted_public_key_data_tls=None)
        verify_add_initial_eim_request(self.engine.association_requests()[1], [expected])
        tls_setup.use_setup(self.directory, "identity")
        self.assertIn(_implicit(b"\xA1", self.identity.tls_certificate_der()), self.engine.association_requests()[1])

    def test_options_and_names_are_checked(self) -> None:
        for name, options, message in (
            ("x", {"colour": "red"}, "Unknown TLS setup option"),
            ("x", {"chain": "deep"}, "chain is one of"),
            ("x", {"trust": "root"}, "trust=root needs"),
            ("x", {"chain": "root", "trust": "intermediate"}, "trust=intermediate needs"),
            ("x", {"ski": "maybe"}, "ski is on or off"),
            ("../escape", {}, "setup name"),
            ("", {}, "setup name"),
        ):
            with self.subTest(options or name):
                with self.assertRaisesRegex(tls_setup.TlsSetupError, message):
                    tls_setup.parse_options(name, options)
        self.setup("kept")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "exists"):
            tls_setup.build_setup(self.directory, self.identity, tls_setup.parse_options("kept", {}))
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "in use"):
            tls_setup.remove_setup(self.directory, "kept")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "No TLS setup"):
            tls_setup.use_setup(self.directory, "missing")
        tls_setup.use_setup(self.directory, "identity")
        tls_setup.remove_setup(self.directory, "kept")
        self.assertEqual(tls_setup.list_setups(self.directory), [])

    def test_the_card_port_option(self) -> None:
        self.assertEqual(card_port(8743, "auto"), 8744)
        self.assertEqual(card_port(0, "auto"), 0)
        self.assertIsNone(card_port(8743, "off"))
        self.assertEqual(card_port(8743, "9443"), 9443)
        for bad in ("x", "70000"):
            with self.assertRaises(Exception):
                card_port(8743, bad)


class SetupFqdnAndLayoutTests(_Store):
    def test_a_setup_fqdn_names_the_leaf_and_the_association(self) -> None:
        other = "eim-other.yggdrasim.local"
        built = self.setup("other", fqdn=other, chain="root", trust="root")
        self.assertEqual((built.effective_fqdn, built.leaf_name), (other, other))
        leaf = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, "other") / "leaf.pem").read_bytes())
        self.assertEqual(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                         .get_values_for_type(x509.DNSName), [other])
        self.assertEqual(tls_setup.effective_fqdn(self.directory, self.identity), other)
        self.assertEqual(tls_setup.fqdn_source(self.directory), "TLS setup other")
        configuration = self.engine.association_configuration()
        self.assertEqual(configuration.eim_fqdn, other)
        self.assertEqual(configuration.trusted_public_key_data_tls.form, KEY_FORM_CERTIFICATE)
        server = self.serve()
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        context = _client_context(trust)
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=other) as tls:
                self.assertEqual(_request(tls, "GET", "/ping")[0], 200)
        tls_setup.use_setup(self.directory, "identity")
        self.assertEqual(tls_setup.effective_fqdn(self.directory, self.identity), EIM_FQDN)
        self.assertEqual(tls_setup.fqdn_source(self.directory), "the identity")
        self.assertEqual(self.engine.association_configuration().eim_fqdn, EIM_FQDN)
        self.assertIn("FQDN", tls_setup.describe_setup(self.directory, built)[2])

    def test_a_shaped_chain_follows_the_references_and_verifies(self) -> None:
        from tests.test_local_eim_cert_layout import reference_ca, reference_leaf

        ca, _ca_key = reference_ca()
        leaf_reference = reference_leaf()
        leaf_path = self.directory / "reference-leaf.pem"
        ca_path = self.directory / "reference-root.pem"
        leaf_path.write_bytes(leaf_reference.public_bytes(serialization.Encoding.PEM))
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        built = self.setup("shaped", chain="intermediate", trust="root", layout=str(leaf_path), ca_layout=str(ca_path))
        self.assertIn("end entity EXAMPLE SM-EIM - CERT.EIM.TLS", built.layout_reference)
        self.assertIn("CA EXAMPLE SM IoT ROOT", built.ca_layout_reference)
        folder = tls_setup.setup_directory(self.directory, "shaped")
        leaf = x509.load_pem_x509_certificate((folder / "leaf.pem").read_bytes())
        root = x509.load_pem_x509_certificate((folder / "root.pem").read_bytes())
        intermediate = x509.load_pem_x509_certificate((folder / "intermediate.pem").read_bytes())
        self.assertEqual([(item.oid, item.critical) for item in leaf.extensions],
                         [(item.oid, item.critical) for item in leaf_reference.extensions])
        self.assertEqual([(item.oid, item.critical) for item in root.extensions],
                         [(item.oid, item.critical) for item in ca.extensions])
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [EIM_FQDN])
        self.assertEqual([item.dotted_string for item in san.get_values_for_type(x509.RegisteredID)], [EIM_ID])
        self.assertEqual(leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                         "EXAMPLE SM-EIM - CERT.EIM.TLS")
        self.assertEqual(root.subject, ca.subject)
        self.assertEqual(intermediate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                         "EXAMPLE SM IoT ROOT intermediate CA")
        self.assertEqual(leaf.issuer, intermediate.subject)
        self.assertEqual(self.handshake(self.serve()), 200)
        described = "\n".join(tls_setup.describe_setup(self.directory, built))
        self.assertIn("leaf layout", described)
        self.assertIn("CA layout", described)

    def test_the_shaped_leaf_naming_knobs(self) -> None:
        from tests.test_local_eim_cert_layout import reference_leaf

        leaf_path = self.directory / "reference-leaf.pem"
        leaf_path.write_bytes(reference_leaf().public_bytes(serialization.Encoding.PEM))
        identity = self.engine.identity()
        for name, options, common_name, registered in (
            ("dns-only", {"registered_id": "off"}, "EXAMPLE SM-EIM - CERT.EIM.TLS", []),
            ("cn-host", {"cn": "host"}, EIM_FQDN, [EIM_ID]),
            ("wildcard", {"san": "*.example.test", "cn": "host"}, "*.example.test", [EIM_ID]),
            ("kept", {"cn": "keep"}, "EXAMPLE SM-EIM - CERT.EIM.TLS", [EIM_ID]),
            ("cn-eim-id", {"cn": "eim_id"}, EIM_ID, [EIM_ID]),
        ):
            with self.subTest(name):
                built = tls_setup.build_setup(self.directory, identity,
                                              tls_setup.parse_options(name, {"layout": str(leaf_path), **options}))
                leaf = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, name) / "leaf.pem").read_bytes())
                self.assertEqual(leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, common_name)
                san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                self.assertEqual([item.dotted_string for item in san.get_values_for_type(x509.RegisteredID)], registered)
                self.assertEqual(san.get_values_for_type(x509.DNSName), [options.get("san", EIM_FQDN)])
                self.assertIn(f"registeredID {options.get('registered_id', 'auto')}, CN {options.get('cn', 'auto')}",
                              "\n".join(tls_setup.describe_setup(self.directory, built)))
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "registered_id is one of"):
            tls_setup.parse_options("bad", {"registered_id": "maybe"})
        # A generic leaf (no layout) takes the registeredID only when asked.
        built = tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "generic-oid", {"registered_id": "on", "san": "*.example.test", "chain": "root", "trust": "root"}))
        leaf = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, "generic-oid") / "leaf.pem").read_bytes())
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["*.example.test"])
        self.assertEqual([item.dotted_string for item in san.get_values_for_type(x509.RegisteredID)], [EIM_ID])
        self.assertEqual(leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, "*.example.test")
        self.assertIn("registeredID on", "\n".join(tls_setup.describe_setup(self.directory, built)))
        # cn=eim_id names a generic leaf by the eimId as well; the host stays in the SubjectAltName.
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "generic-cn-oid", {"cn": "eim_id", "registered_id": "on", "chain": "root", "trust": "root"}))
        leaf = x509.load_pem_x509_certificate(
            (tls_setup.setup_directory(self.directory, "generic-cn-oid") / "leaf.pem").read_bytes())
        self.assertEqual(leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, EIM_ID)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), [EIM_FQDN])
        self.assertEqual([item.dotted_string for item in san.get_values_for_type(x509.RegisteredID)], [EIM_ID])
        plain = tls_setup.build_setup(self.directory, identity, tls_setup.parse_options("generic-plain", {}))
        leaf = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, "generic-plain") / "leaf.pem").read_bytes())
        self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                         [x509.DNSName(EIM_FQDN)])
        self.assertNotIn("leaf naming", "\n".join(tls_setup.describe_setup(self.directory, plain)))

    def test_a_ca_given_as_layout_shapes_the_ca_members(self) -> None:
        from tests.test_local_eim_cert_layout import reference_ca

        ca, _ca_key = reference_ca()
        ca_path = self.directory / "reference-root.pem"
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        built = self.setup("ca-shaped", chain="root", trust="root", layout=str(ca_path))
        self.assertEqual(built.layout_reference, "")
        self.assertIn("CA EXAMPLE SM IoT ROOT", built.ca_layout_reference)
        root = x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, "ca-shaped") / "root.pem").read_bytes())
        self.assertTrue(root.extensions.get_extension_for_class(x509.CertificatePolicies).critical)
        self.assertEqual(self.handshake(self.serve()), 200)

    def test_layout_options_are_checked(self) -> None:
        from tests.test_local_eim_cert_layout import reference_ca, reference_leaf

        ca, _ca_key = reference_ca()
        leaf_path = self.directory / "leaf.pem"
        ca_path = self.directory / "root.pem"
        leaf_path.write_bytes(reference_leaf().public_bytes(serialization.Encoding.PEM))
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        identity = self.engine.identity()
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "not a CA certificate"):
            tls_setup.build_setup(self.directory, identity,
                                  tls_setup.parse_options("bad-ca", {"chain": "root", "ca_layout": str(leaf_path)}))
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "give it as ca_layout"):
            tls_setup.build_setup(self.directory, identity,
                                  tls_setup.parse_options("two-cas", {"layout": str(ca_path), "ca_layout": str(ca_path)}))
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "neither a stored certificate"):
            tls_setup.build_setup(self.directory, identity, tls_setup.parse_options("missing", {"layout": "no-such"}))
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "fqdn is a host name"):
            tls_setup.parse_options("bad-name", {"fqdn": "not a host"})

    def test_reserved_test_names(self) -> None:
        for name in ("eim.example.test", "eim.example.com", "EIM.EXAMPLE.ORG.", "a.b.c.invalid", "eim.localhost",
                     "example.net", "x.example"):
            self.assertTrue(tls_setup.reserved_test_name(name), name)
        # Private-use names that cannot resolve, outside RFC 2606 all the same.
        for name in ("eim.example.internal", "eim.corp.internal", "eim.lab.internal", "", "localhost.internal"):
            self.assertFalse(tls_setup.reserved_test_name(name), name)

    def test_local_eim_names(self) -> None:
        self.assertEqual(tls_setup.LOCAL_EIM_NAME_PATTERN, "eim*.yggdrasim.local")
        for name in ("eim.yggdrasim.local", "eim1.yggdrasim.local", "EIM-Other.YggdraSIM.Local.", "eim3x.yggdrasim.local"):
            self.assertTrue(tls_setup.local_eim_name(name), name)
        for name in ("eim1.operator.example.com", "eim3.lab.example.net", "eim.example.test", "eim.lab.yggdrasim.local",
                     "xeim.yggdrasim.local", "smdp.yggdrasim.local", "eim.yggdrasim.local.example.com",
                     "eim_1.yggdrasim.local", "yggdrasim.local", "1.3.6.1.4.1.32473.999.10.124", "", None):
            self.assertFalse(tls_setup.local_eim_name(name), name)


class ClientAuthTests(_Store):
    def _client(self, *, certificate: tuple[Path, Path] | None = None, check_hostname: bool = True) -> ssl.SSLContext:
        context = _client_context(tls_setup.trusted_tls_key_data(self.directory, self.identity))
        context.check_hostname = check_hostname
        if certificate is not None:
            context.load_cert_chain(certfile=str(certificate[0]), keyfile=str(certificate[1]))
        return context

    def _ping(self, server: LocalEimCardTlsServer, context: ssl.SSLContext, server_name: str = EIM_FQDN) -> int:
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                return _request(tls, "GET", "/ping")[0]

    def test_required_client_authentication_takes_only_a_certificate_under_the_setups_ca(self) -> None:
        built = self.setup("mtls", chain="root", trust="root", client_auth="required")
        self.assertIn("own client CA", built.client_ca_reference)
        self.assertTrue((tls_setup.setup_directory(self.directory, "mtls") / tls_setup.CLIENT_CA_KEY_FILE).is_file())
        material = tls_setup.serving_material(self.directory, self.identity)
        self.assertEqual(material.client_auth, "required")
        self.assertTrue(Path(material.client_ca_path).is_file())
        server = self.serve()
        with self.assertRaises((ssl.SSLError, OSError)):
            self._ping(server, self._client())
        issued = tls_setup.issue_client_certificate(self.directory, "mtls", common_name="rig client")
        client = x509.load_pem_x509_certificate(issued[0].read_bytes())
        self.assertEqual(client.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, "rig client")
        self.assertIn(x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                      client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        self.assertEqual(self._ping(server, self._client(certificate=issued)), 200)
        self.assertIn("client auth required", "\n".join(tls_setup.describe_setup(self.directory, built)))
        self.assertIn("client       CN rig client", "\n".join(tls_setup.describe_setup(self.directory, built)))
        # A client certificate from another CA is refused as well.
        self.setup("other-ca", chain="root", trust="root", client_auth="required")
        stranger = tls_setup.issue_client_certificate(self.directory, "other-ca")
        tls_setup.use_setup(self.directory, "mtls")
        with self.assertRaises((ssl.SSLError, OSError)):
            self._ping(server, self._client(certificate=stranger))

    def test_optional_client_authentication_serves_a_client_without_a_certificate(self) -> None:
        self.setup("opt", client_auth="optional")
        server = self.serve()
        self.assertEqual(self._ping(server, self._client()), 200)
        issued = tls_setup.issue_client_certificate(self.directory, "opt")
        self.assertEqual(self._ping(server, self._client(certificate=issued)), 200)

    def test_a_named_client_ca_is_what_the_listener_trusts(self) -> None:
        from tests.test_local_eim_cert_layout import reference_ca

        ca, _key = reference_ca()
        ca_path = self.directory / "client-ca.pem"
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        built = self.setup("named", chain="root", trust="root", client_auth="required", client_ca=str(ca_path))
        self.assertIn("EXAMPLE SM IoT ROOT", built.client_ca_reference)
        bundle = x509.load_pem_x509_certificate(
            (tls_setup.setup_directory(self.directory, "named") / tls_setup.CLIENT_CA_FILE).read_bytes())
        self.assertEqual(bundle.subject, ca.subject)
        # The named CA issues the client certificates; the setup has no key for it.
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "that CA issues them"):
            tls_setup.issue_client_certificate(self.directory, "named")
        self.setup("plain")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "client_auth=none"):
            tls_setup.issue_client_certificate(self.directory, "plain")
        # A client certificate from another setup's client CA is refused by the named one.
        self.setup("other", client_auth="required")
        stranger = tls_setup.issue_client_certificate(self.directory, "other")
        tls_setup.use_setup(self.directory, "named")
        with self.assertRaises((ssl.SSLError, OSError)):
            self._ping(self.serve(), self._client(certificate=stranger))

    def test_a_required_server_name_refuses_a_client_that_names_another_host(self) -> None:
        self.setup("sni", sni="required")
        material = tls_setup.serving_material(self.directory, self.identity)
        self.assertEqual(material.sni_names, (EIM_FQDN,))
        server = self.serve()
        self.assertEqual(self._ping(server, self._client()), 200)
        with self.assertRaises((ssl.SSLError, OSError)):
            self._ping(server, self._client(check_hostname=False), server_name="other.example.test")
        tls_setup.use_setup(self.directory, "identity")
        self.assertEqual(tls_setup.serving_material(self.directory, self.identity).sni_names, ())

    def test_client_authentication_options_are_checked(self) -> None:
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "client_auth is one of"):
            tls_setup.parse_options("bad", {"client_auth": "always"})
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "sni is one of"):
            tls_setup.parse_options("bad", {"sni": "maybe"})
        with self.assertRaisesRegex(tls_setup.TlsSetupError, "client_ca"):
            tls_setup.build_setup(self.directory, self.identity,
                                  tls_setup.parse_options("bad", {"client_auth": "required", "client_ca": "no-such"}))
        with self.assertRaisesRegex(ValueError, "needs the CA file"):
            card_tls_context("x", "y", client_auth="required")


class ServedByNameTests(_Store):
    """Every setup is served at once; the ClientHello's server_name picks the chain, the setup in use is the default."""

    def _serve(self, materials: list[tls_setup.ServingMaterial]) -> LocalEimCardTlsServer:
        from SCP11.eim_local.engine.esipa import card_tls_contexts

        server = LocalEimCardTlsServer(self.engine, ("127.0.0.1", 0), card_tls_contexts(materials), socket_timeout_s=10.0)
        server.start_in_thread()
        self.addCleanup(server.stop)
        return server

    def _peer_cn(self, server: LocalEimCardTlsServer, trust: object, server_name: str, *,
                 certificate: tuple[Path, Path] | None = None, check_hostname: bool = True) -> str:
        context = _client_context(trust)
        context.check_hostname = check_hostname
        if certificate is not None:
            context.load_cert_chain(certfile=str(certificate[0]), keyfile=str(certificate[1]))
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                self.assertEqual(_request(tls, "GET", "/ping")[0], 200)
                subject = dict(item[0] for item in tls.getpeercert()["subject"])
                return str(subject.get("commonName"))

    def test_each_setup_answers_for_its_own_name_and_the_default_for_the_rest(self) -> None:
        identity = self.engine.identity()
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "alpha", {"fqdn": "eim-alpha.yggdrasim.local", "chain": "root", "trust": "root"}))
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "beta", {"fqdn": "eim-beta.yggdrasim.local", "client_auth": "required"}))
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "wild", {"fqdn": "eim-one.yggdrasim.local", "san": "*.yggdrasim.local"}))
        tls_setup.use_setup(self.directory, "alpha")
        materials = tls_setup.served_materials(self.directory, identity)
        self.assertEqual([item.label for item in materials], ["alpha", "beta", "wild", "identity"])
        self.assertEqual(materials[0].names, ("eim-alpha.yggdrasim.local",))
        self.assertEqual((materials[2].names, materials[2].patterns),
                         (("eim-one.yggdrasim.local",), ("*.yggdrasim.local",)))
        self.assertEqual(materials[3].names, (EIM_FQDN,))
        # The verify mode belongs to the listening context, so beta (mutual TLS) gets a listener of its own.
        groups = tls_setup.listener_groups(materials)
        self.assertEqual([[item.label for item in group] for group in groups], [["alpha", "wild", "identity"], ["beta"]])
        server = self._serve(groups[0])
        alpha_trust = tls_setup.trusted_tls_key_data(self.directory, identity, "alpha")
        beta_trust = tls_setup.trusted_tls_key_data(self.directory, identity, "beta")
        wild_trust = tls_setup.trusted_tls_key_data(self.directory, identity, "wild")
        own_trust = tls_setup.trusted_tls_key_data(self.directory, identity, "identity")
        self.assertEqual(self._peer_cn(server, alpha_trust, "eim-alpha.yggdrasim.local"), "eim-alpha.yggdrasim.local")
        # The setup's own name by the exact map, a sibling under the wildcard by the pattern.
        self.assertEqual(self._peer_cn(server, wild_trust, "eim-one.yggdrasim.local"), "*.yggdrasim.local")
        self.assertEqual(self._peer_cn(server, wild_trust, "eim-two.yggdrasim.local"), "*.yggdrasim.local")
        # The exchange record names the chain the server name picked, the peer's port and the TLS version.
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with _client_context(wild_trust).wrap_socket(raw, server_hostname="eim-two.yggdrasim.local") as tls:
                asked = codec.tlv(b"\xBF\x4F", codec.tlv(b"\x5A", bytes.fromhex("89049032123451234512345678901235")))
                self.assertEqual(_request(tls, "POST", ASN1_PATH, asked)[0], 200)
                local_port = int(tls.getsockname()[1])
        recorded = self.engine.store.traffic(limit=1)[0]
        self.assertEqual((recorded.tls_setup, recorded.peer_port, recorded.binding, recorded.status),
                         ("wild", local_port, "esipa-asn1", 200))
        self.assertTrue(recorded.tls_version.startswith("TLSv1"), recorded.tls_version)
        self.assertEqual(self._peer_cn(server, own_trust, EIM_FQDN), EIM_FQDN)
        # Another eIM's name is refused whatever brought the connection to the listener.
        for foreign in ("eim1.operator.example.com", "nobody.example.test", "eim.lab.yggdrasim.local"):
            with self.assertRaisesRegex(ssl.SSLError, "(?i)unrecognized.name"):
                self._peer_cn(server, alpha_trust, foreign, check_hostname=False)
        # beta's own listener asks the client for a certificate under beta's client CA.
        mutual = self._serve(groups[1])
        with self.assertRaises((ssl.SSLError, OSError)):
            self._peer_cn(mutual, beta_trust, "eim-beta.yggdrasim.local")
        issued = tls_setup.issue_client_certificate(self.directory, "beta")
        self.assertEqual(self._peer_cn(mutual, beta_trust, "eim-beta.yggdrasim.local", certificate=issued), "eim-beta.yggdrasim.local")
        # The per-setup views the engine uses for an association.
        self.assertEqual(tls_setup.effective_fqdn(self.directory, identity, "beta"), "eim-beta.yggdrasim.local")
        self.assertEqual(tls_setup.effective_fqdn(self.directory, identity, "identity"), EIM_FQDN)
        self.assertEqual(tls_setup.effective_fqdn(self.directory, identity), "eim-alpha.yggdrasim.local")
        self.assertEqual(tls_setup.serving_material(self.directory, identity, "wild").label, "wild")
        with self.assertRaises(tls_setup.TlsSetupError):
            tls_setup.effective_fqdn(self.directory, identity, "no-such")
        # With a mutual-TLS default, its group comes first.
        tls_setup.use_setup(self.directory, "beta")
        regrouped = tls_setup.listener_groups(tls_setup.served_materials(self.directory, identity))
        self.assertEqual([[item.label for item in group] for group in regrouped], [["beta"], ["alpha", "wild", "identity"]])


class CardSessionTests(ServiceTestBase):
    def test_a_card_session_over_tls_takes_a_package_and_returns_its_result(self) -> None:
        identity = self.engine.identity()
        material = tls_setup.serving_material(self.directory, identity)
        server = LocalEimCardTlsServer(self.engine, ("127.0.0.1", 0),
                                       card_tls_context(material.chain_path, material.key_path), socket_timeout_s=10.0)
        server.start_in_thread()
        self.addCleanup(server.stop)
        operation_id = self.engine.submit([OperationRequest(eid=self.card.eid, type="PROFILE_INFO_LIST")])[0].id
        context = _client_context(tls_setup.trusted_tls_key_data(self.directory, identity))
        eid_tlv = codec.tlv(b"\x5A", bytes.fromhex(self.card.eid))
        with socket.create_connection(server.server_address[:2], timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=EIM_FQDN) as tls:
                status, body = _request(tls, "POST", "/gsma/rsp2/asn1", codec.tlv(b"\xBF\x4F", eid_tlv))
                self.assertEqual(status, 200)
                _tag, package, _raw = read_single_ber_tlv(body)
                result = self.card.exchange(package)
                # The same connection carries the result (HTTP/1.1 keep-alive), as the card's session would.
                status, _answer = _request(tls, "POST", "/gsma/rsp2/asn1", codec.tlv(b"\xBF\x50", eid_tlv + result))
                self.assertEqual(status, 200)
        self.assertEqual(self.engine.operation(operation_id).state, STATE_SUCCESS)

    def test_add_initial_eim_carries_each_trust_form_to_the_card(self) -> None:
        identity = self.engine.identity()
        for name, options in (("key", {"trust": "leaf_key"}), ("root", {"chain": "root", "trust": "root"}),
                              ("mid", {"chain": "intermediate", "trust": "intermediate"}), ("none", {"trust": "none"})):
            with self.subTest(name):
                tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(name, options))
                tls_setup.use_setup(self.directory, name)
                # The card remembers its first association (the identity), so the setup is named.
                lines = self.engine.associate(self.card.exchange, self.card.eid, setup=name)
                self.assertTrue(any(line.startswith("AddInitialEim: ") for line in lines), lines)
                record = self.engine.store.record(codec.normalize_eid(self.card.eid))
                self.assertIsNotNone(record.association_token)
                trust = tls_setup.trusted_tls_key_data(self.directory, identity)
                answer = self.card.exchange(codec.tlv(b"\xBF\x55", b""))
                self.assertEqual(_eim_ids(answer), [EIM_ID])
                stored = _stored_tls_trust(answer)
                if trust is None:
                    self.assertIsNone(stored)
                else:
                    tag = b"\xA0" if trust.form == KEY_FORM_PUBLIC_KEY else b"\xA1"
                    self.assertEqual(stored, _implicit(tag, trust.der))

    def test_a_silent_connection_holds_no_other_client(self) -> None:
        identity = self.engine.identity()
        material = tls_setup.serving_material(self.directory, identity)
        server = LocalEimCardTlsServer(self.engine, ("127.0.0.1", 0),
                                       card_tls_context(material.chain_path, material.key_path), socket_timeout_s=10.0)
        server.start_in_thread()
        self.addCleanup(server.stop)
        silent = socket.create_connection(server.server_address[:2], timeout=10)
        self.addCleanup(silent.close)
        started = time.monotonic()
        context = _client_context(tls_setup.trusted_tls_key_data(self.directory, identity))
        with socket.create_connection(server.server_address[:2], timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=EIM_FQDN) as tls:
                self.assertEqual(_request(tls, "GET", "/ping")[0], 200)
        self.assertLess(time.monotonic() - started, 5.0)


class BackgroundCardListenerTests(ServiceTestBase):
    def test_the_service_reports_its_card_listener_and_a_restart_serves_a_new_setup(self) -> None:
        port, card = _free_port(), _free_port()
        status = start_background(self.directory, port=port, tls_port=card)
        self.addCleanup(stop_background, self.directory)
        self.assertEqual((status["tls_url"], status["tls_setup"]), (f"https://127.0.0.1:{card}", "identity"))
        self.assertEqual(local_route(EIM_FQDN, self.directory), f"http://127.0.0.1:{port}")
        self.assertEqual((status["eim_fqdn"], status["eim_fqdns"]), (EIM_FQDN, [EIM_FQDN]))
        self.assertEqual(status["tls_setups_served"], ["identity"])
        identity = self.engine.identity()
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "ca", {"chain": "root", "trust": "root", "fqdn": "eim-other.yggdrasim.local"}))
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options(
            "aside", {"fqdn": "eim-aside.example.test"}))
        tls_setup.use_setup(self.directory, "ca")
        status = restart_background(self.directory)
        self.assertEqual((status["port"], status["tls_port"], status["tls_setup"]), (port, card, "ca"))
        # The setup's name comes first, the identity's is still answered, and so is every other setup's.
        self.assertEqual(status["eim_fqdn"], "eim-other.yggdrasim.local")
        # A setup under any other name is listed for nobody: nothing routes that name to the service.
        self.assertEqual(status["eim_fqdns"], ["eim-other.yggdrasim.local", EIM_FQDN])
        self.assertEqual(status["tls_setups_served"], ["ca", "aside", "identity"])
        self.assertEqual(len(status["tls_listeners"]), 1)
        self.assertEqual(local_route("eim-aside.example.test", self.directory), "")
        self.assertEqual(local_route("eim-other.yggdrasim.local", self.directory), f"http://127.0.0.1:{port}")
        self.assertEqual(local_route(EIM_FQDN, self.directory), f"http://127.0.0.1:{port}")
        self.assertTrue(describe(self.directory)["answers"])
        stop_background(self.directory)
        status = start_background(self.directory, port=port, tls_port="off")
        self.assertEqual(status["tls_url"], "")
        self.assertIn("off", status["tls_note"])
        self.assertEqual(restart_background(self.directory)["tls_url"], "")

    def test_a_restart_brings_the_listener_back_after_a_start_without_one(self) -> None:
        port, card = _free_port(), _free_port()
        identity = self.engine.identity()
        tls_setup.build_setup(self.directory, identity, tls_setup.parse_options("broken", {}))
        tls_setup.use_setup(self.directory, "broken")
        (tls_setup.setup_directory(self.directory, "broken") / "chain.pem").write_text("not a certificate\n")
        status = start_background(self.directory, port=port, tls_port=card)
        self.addCleanup(stop_background, self.directory)
        self.assertEqual(status["tls_url"], "")
        self.assertIn("broken", status["tls_note"])
        self.assertTrue(describe(self.directory)["answers"])
        tls_setup.use_setup(self.directory, "identity")
        status = restart_background(self.directory)
        self.assertEqual((status["tls_url"], status["tls_setup"]), (f"https://127.0.0.1:{card}", "identity"))


class SurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        environment = mock.patch.dict(os.environ, {"YGGDRASIM_LOCAL_EIM_STORE": folder.name})
        environment.start()
        self.addCleanup(environment.stop)
        LocalEim(Path(folder.name)).new_identity(eim_id=EIM_ID, eim_fqdn=EIM_FQDN)

    def test_the_shell_verb(self) -> None:
        from SCP11.eim_local.main import EimLocalShell

        shell = EimLocalShell()

        def run(line: str) -> str:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                shell._dispatch_command_line(line, source="test")
            return buffer.getvalue()

        built = run("TLS-SETUP NEW ca-chain chain=intermediate trust=root --use")
        self.assertIn("TLS setup ca-chain built", built)
        self.assertIn("intermediate CA", built)
        self.assertIn("not running", built)
        self.assertIn("* ca-chain", run("TLS-SETUP"))
        self.assertIn("(in use)", run("TLS-SETUP SHOW ca-chain"))
        self.assertIn("in use", run("TLS-SETUP REMOVE ca-chain"))
        self.assertIn("Unknown TLS setup option", run("TLS-SETUP NEW bad colour=red"))
        run("TLS-SETUP USE identity")
        self.assertIn("removed", run("TLS-SETUP REMOVE ca-chain"))
        built = run("TLS-SETUP NEW other fqdn=eim-other.yggdrasim.local chain=root trust=root")
        self.assertIn("eIM FQDN eim-other.yggdrasim.local (the setup's own)", built)
        choices = run("ASSOCIATE CHOICES")
        self.assertIn("* identity", choices)
        self.assertIn("other                    FQDN eim-other.yggdrasim.local  trusts root", choices)
        self.assertIn("Stored certificates for ASSOCIATE HANDOVER", choices)
        run("TLS-SETUP USE other")
        self.assertIn("* other", run("ASSOCIATE CHOICES"))
        self.assertIn("FQDN eim-other.yggdrasim.local, chain root", run("TLS-SETUP"))
        # A name the Local eIM does not answer for is refused before any card is touched.
        run("TLS-SETUP NEW live fqdn=eim.live.internal --use")
        refused = run("ASSOCIATE --yes")
        self.assertIn("is not a Local eIM name (eim*.yggdrasim.local)", refused)
        for foreign in ("eim1.operator.example.com", "eim.example.test"):
            run(f"TLS-SETUP NEW live fqdn={foreign} --replace --use")
            self.assertIn(f"eimFqdn {foreign} is not a Local eIM name", run("ASSOCIATE --yes"))
        run("TLS-SETUP NEW twin fqdn=eim-other.yggdrasim.local")
        self.assertIn("eim-other.yggdrasim.local is the FQDN of other, twin", run("ASSOCIATE CHOICES"))
        run("TLS-SETUP REMOVE twin")
        self.assertIn("client auth required", run("TLS-SETUP NEW mtls chain=root trust=root client_auth=required sni=required"))
        self.assertIn("client certificate", run("TLS-SETUP CLIENT-CERT mtls cn=bench"))
        self.assertIn("client auth required, SNI required", run("TLS-SETUP"))
        self.assertIn("needs eim_id=<id> and sign=", run("ASSOCIATE HANDOVER eim_id=2.999.1"))
        self.assertIn("No stored certificate named", run("ASSOCIATE HANDOVER eim_id=2.999.1 sign=no-such-entry --yes"))
        self.assertIn("Usage:", run("ASSOCIATE nonsense"))
        run("TLS-SETUP USE identity")

    def test_the_gui_actions(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        def run(action_id: str, **values: object) -> str:
            spec = next(entry for entry in SPECS if entry.id == action_id)
            return "\n".join(spec.dispatcher(ActionContext(), **values)["lines"])

        built = run("eim_local.tls_setup_new", name="pinned", trust="leaf_key", ski=True,
                    ca_basic_constraints=True, server_auth=False, then="use")
        self.assertIn("serverAuth off", built)
        self.assertIn("* pinned", run("eim_local.tls_setup_list"))
        self.assertIn("leaf_key", run("eim_local.tls_setup_show", name="pinned"))
        with self.assertRaisesRegex(ValueError, "Confirm"):
            run("eim_local.tls_setup_new", name="other", then="apply", confirm=False)
        with self.assertRaisesRegex(ValueError, "Confirm"):
            run("eim_local.tls_setup_use", name="pinned", associate=True, confirm=False)
        run("eim_local.tls_setup_use", name="identity")
        self.assertIn("removed", run("eim_local.tls_setup_remove", name="pinned"))
        shaped = run("eim_local.tls_setup_new", name="other", fqdn="eim-other.yggdrasim.local", chain="root", trust="root")
        self.assertIn("eIM FQDN eim-other.yggdrasim.local (the setup's own)", shaped)
        self.assertIn("FQDN eim-other.yggdrasim.local  trusts root", run("eim_local.associate_choices"))
        with self.assertRaisesRegex(ValueError, "Confirm"):
            run("eim_local.associate_handover", reader="", confirm=False, eim_id="2.999.1", sign="OTHER")
        with self.assertRaisesRegex(ValueError, "Unknown TLS setup option|neither a stored certificate"):
            run("eim_local.tls_setup_new", name="shaped", layout="no-such-entry")
        self.assertIn("client auth optional", run("eim_local.tls_setup_new", name="mtls", client_auth="optional"))
        self.assertIn("client certificate", run("eim_local.tls_setup_client_cert", name="mtls", common_name="bench"))


if __name__ == "__main__":
    unittest.main()
