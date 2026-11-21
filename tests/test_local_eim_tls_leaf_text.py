# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A TLS leaf of the Local eIM issued from its subject and extensions written as text.

What the text gives is built as written and read back before the leaf is
kept; what it leaves out follows the leaf's options. A leaf decoded to text
issues a leaf with the same text, which is what an editor relies on when it
opens a leaf and issues it unchanged. The shell verb and the GUI actions carry
the same text; only a shell line may name a file.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import cert_spec, tls_setup
from SCP11.eim_local.engine.service import LocalEim
from tests.test_local_eim_service import EIM_FQDN, EIM_ID
from tests.test_local_eim_tls_setup import _client_context, _Store

FQDN = "eim5.yggdrasim.local"
REPO = Path(__file__).resolve().parents[1]


class _Texts(_Store):
    def build(self, name: str = "ca", **options: str) -> tls_setup.TlsSetup:
        merged = {"chain": "intermediate", "trust": "root", "fqdn": FQDN, **options}
        return tls_setup.build_setup(self.directory, self.identity, tls_setup.parse_options(name, merged))

    def issue(self, name: str, text: str, setup: str = "ca", **options: str) -> tls_setup.LeafVariant:
        variant = tls_setup.parse_leaf_options(tls_setup.load_setup(self.directory, setup), name, options, spec=text)
        return tls_setup.issue_leaf(self.directory, self.identity, setup, variant)

    def leaf(self, name: str, setup: str = "ca") -> x509.Certificate:
        return x509.load_pem_x509_certificate(tls_setup.leaf_certificate_path(self.directory, setup, name).read_bytes())

    def issuer(self, setup: str = "ca", role: str = "intermediate") -> x509.Certificate:
        return x509.load_pem_x509_certificate((tls_setup.setup_directory(self.directory, setup) / f"{role}.pem").read_bytes())


class LeafFromTextTests(_Texts):
    def test_a_leafs_own_text_issues_a_leaf_with_the_same_text(self) -> None:
        from tests.test_local_eim_cert_layout import reference_ca, reference_leaf

        ca, _ca_key = reference_ca()
        leaf_path, ca_path = self.directory / "reference-leaf.pem", self.directory / "reference-root.pem"
        leaf_path.write_bytes(reference_leaf().public_bytes(serialization.Encoding.PEM))
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        self.build("generic")
        self.build("self-signed", chain="self", trust="leaf")
        self.build("shaped", layout=str(leaf_path), ca_layout=str(ca_path))
        for setup in ("generic", "self-signed", "shaped"):
            with self.subTest(setup):
                # Reading the built leaf writes nothing, as for every other read of a setup.
                text = tls_setup.leaf_text(self.directory, setup, "built")
                self.assertFalse((tls_setup.setup_directory(self.directory, setup) / "leaves").exists())
                self.assertNotIn("DER:", text)
                self.issue("again", text, setup=setup)
                built, again = self.leaf("built", setup), self.leaf("again", setup)
                self.assertEqual(tls_setup.leaf_text(self.directory, setup, "again"), text)
                self.assertEqual(again.subject.public_bytes(), built.subject.public_bytes())
                self.assertEqual([(item.oid, item.critical) for item in again.extensions],
                                 [(item.oid, item.critical) for item in built.extensions])
                self.assertNotEqual(again.public_key().public_numbers(), built.public_key().public_numbers())
                if setup == "self-signed":
                    again.verify_directly_issued_by(again)
                else:
                    again.verify_directly_issued_by(self.issuer(setup))

    def test_the_text_decides_what_it_gives_and_the_options_the_rest(self) -> None:
        setup = self.build()
        only_subject = self.issue("subject-only", "subject = CN={host},OU=Lab,O=Example Org,C=XX", ski="off")
        leaf = self.leaf("subject-only")
        self.assertEqual(leaf.subject.rfc4514_string(), f"CN={FQDN},OU=Lab,O=Example Org,C=XX")
        # The extensions are the options': no SubjectKeyIdentifier was asked for.
        self.assertEqual([item.oid._name for item in leaf.extensions], ["subjectAltName", "extendedKeyUsage", "keyUsage"])
        self.assertEqual(tls_setup.leaf_summary(only_subject),
                         "subject as written, leaf name the setup FQDN, registeredID auto, SKI off, serverAuth on, "
                         "leaf valid, key p256, listener sends chain")

        only_extensions = self.issue(
            "extensions-only", "keyUsage = digitalSignature\nsubjectAltName = critical, DNS:{host}, "
            "DNS:second.example.test, RID:{eim_id}", cn="eim_id")
        leaf = self.leaf("extensions-only")
        self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, EIM_ID)
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertTrue(names.critical)
        # Two DNS names and the eimId: what a layout cannot do.
        self.assertEqual(names.value.get_values_for_type(x509.DNSName), [FQDN, "second.example.test"])
        self.assertEqual([oid.dotted_string for oid in names.value.get_values_for_type(x509.RegisteredID)], [EIM_ID])
        self.assertEqual(len(leaf.extensions), 2)
        self.assertEqual(tls_setup.leaf_summary(only_extensions),
                         "CN eim_id, extensions as written, leaf valid, key p256, listener sends chain")
        # The stored text keeps its placeholders, so the same text suits another setup.
        self.assertEqual(tls_setup.load_leaf(self.directory, "ca", "extensions-only").spec,
                         "keyUsage = digitalSignature\nsubjectAltName = critical, DNS:{host}, DNS:second.example.test, "
                         "RID:{eim_id}")
        described = tls_setup.describe_leaf(self.directory, "ca", only_extensions)
        self.assertEqual(described[0], tls_setup.leaf_summary(only_extensions))

        # An empty subject under a critical SubjectAltName, and a certificate without extensions.
        self.issue("no-subject", "subject = none\nsubjectAltName = critical, DNS:{host}")
        self.assertEqual((len(self.leaf("no-subject").subject.rdns), len(self.leaf("no-subject").extensions)), (0, 1))
        self.issue("bare", "extensions = none")
        self.assertEqual((len(self.leaf("bare").extensions), self.leaf("bare").version), (0, x509.Version.v3))
        # Key identifiers are computed for this leaf and this issuer.
        self.issue("ids", "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid")
        leaf = self.leaf("ids")
        self.assertEqual(leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
                         x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()).digest)
        self.assertEqual(leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,
                         x509.SubjectKeyIdentifier.from_public_key(self.issuer().public_key()).digest)
        for name in ("subject-only", "extensions-only", "no-subject", "bare", "ids"):
            self.leaf(name).verify_directly_issued_by(self.issuer())
        # A leaf without text is what it was before: no field, the options' summary.
        plain = tls_setup.issue_leaf(self.directory, self.identity, "ca", tls_setup.parse_leaf_options(setup, "plain", {}))
        self.assertEqual((plain.spec, tls_setup.leaf_summary(plain).startswith("CN auto, leaf name")), ("", True))

    def test_what_contradicts_or_cannot_be_built_is_refused(self) -> None:
        setup = self.build()
        for text, options, message in (
            ("subject = CN=a", {"cn": "host"}, "The text gives the subject, so cn cannot shape it as well"),
            ("keyUsage = digitalSignature", {"ski": "off"}, "The text gives the extensions, so ski cannot shape them"),
            ("keyUsage = digitalSignature", {"san": "none", "registered_id": "on"}, "so san, registered_id cannot"),
            ("keyUsage = flying", {}, "The leaf's text does not read: line 1: keyUsage: no bit 'flying'"),
            ("colour = red", {}, "The leaf's text does not read: 'colour' names no extension"),
        ):
            with self.subTest(text):
                with self.assertRaises(tls_setup.TlsSetupError) as refused:
                    tls_setup.parse_leaf_options(setup, "bad", options, spec=text)
                self.assertIn(message, str(refused.exception))
        # A subject option beside written extensions, and the other way round, is no contradiction.
        tls_setup.parse_leaf_options(setup, "fine", {"cn": "host"}, spec="keyUsage = digitalSignature")
        tls_setup.parse_leaf_options(setup, "fine", {"ski": "off"}, spec="subject = CN=a")
        # A placeholder that has no value for this identity is refused when the leaf is issued, by name.
        identity = self.engine.new_identity(eim_id="eim.example.test", eim_fqdn=EIM_FQDN, eim_id_type=2)
        variant = tls_setup.parse_leaf_options(setup, "rid", {}, spec="subjectAltName = RID:{eim_id}")
        with self.assertRaisesRegex(tls_setup.TlsSetupError, r"does not build: subjectAltName: RID:eim.example.test"):
            tls_setup.issue_leaf(self.directory, identity, "ca", variant)
        self.assertEqual([item.name for item in tls_setup.list_leaves(self.directory, "ca")], ["built"])
        # A stored certificate is looked up by name alone when the name comes from a request.
        with self.assertRaises(tls_setup.TlsSetupError):
            tls_setup.reference_text(str(self.directory / "tls_setups" / "ca" / "root.pem"), stored_only=True)
        self.assertIn("basicConstraints = critical, CA:TRUE",
                      tls_setup.reference_text(str(self.directory / "tls_setups" / "ca" / "root.pem")))

    def test_a_leaf_that_is_not_the_texts_octets_is_not_kept(self) -> None:
        setup = self.build()
        variant = tls_setup.parse_leaf_options(setup, "checked", {}, spec="keyUsage = critical, digitalSignature")
        with mock.patch.object(cert_spec, "check_built", side_effect=cert_spec.SpecError("extensions differ")):
            with self.assertRaisesRegex(tls_setup.TlsSetupError, "The leaf was not built as written: extensions differ"):
                tls_setup.issue_leaf(self.directory, self.identity, "ca", variant)
        self.assertEqual([item.name for item in tls_setup.list_leaves(self.directory, "ca")], ["built"])
        self.assertFalse((tls_setup.setup_directory(self.directory, "ca") / "leaves" / "checked").exists())

    def test_a_leaf_the_certificate_library_cannot_read_is_still_listed_shown_and_reissued(self) -> None:
        from SCP11.eim_local.engine.overview import build_overview

        self.build(chain="root")
        tls_setup.use_setup(self.directory, "ca")
        for name, text in (
            ("only-encipher", "keyUsage = critical, encipherOnly\nsubjectAltName = DNS:{host}\n"
                              "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid"),
            ("path-length", "basicConstraints = critical, CA:FALSE, pathlen:1\nkeyUsage = critical, digitalSignature\n"
                            "subjectAltName = DNS:{host}\nsubjectKeyIdentifier = hash"),
        ):
            with self.subTest(name):
                variant = self.issue(name, text)
                with self.assertRaises(ValueError):
                    list(self.leaf(name).extensions)
                # Its text is the one it was written with, and issues the same leaf again.
                back = tls_setup.leaf_text(self.directory, "ca", name)
                self.assertEqual(back.splitlines()[1:], text.replace("{host}", FQDN).splitlines())
                self.issue(f"{name}-again", back)
                self.assertEqual(tls_setup.leaf_text(self.directory, "ca", f"{name}-again"), back)
                # Every listing still names it; the summary line points at the text for what it cannot read.
                described = tls_setup.describe_leaf(self.directory, "ca", variant)
                self.assertIn(f"CN {FQDN}; SAN see TEXT;", described[1])
                tls_setup.use_leaf(self.directory, "ca", name)
                self.assertIn("see TEXT", "\n".join(tls_setup.describe_setup(
                    self.directory, tls_setup.load_setup(self.directory, "ca"))))
                served = next(item for item in build_overview(self.engine)["tls"]["served"] if item["label"] == "ca")
                self.assertEqual((served["leaf"], served["leaf_sha256"]), (name, variant.sha256))
                self.assertGreater(len(served["certificates"][0]), 5)

    def test_a_client_meets_a_written_leaf(self) -> None:
        self.build(chain="root")
        tls_setup.use_setup(self.directory, "ca")
        variant = self.issue("written", "subject = CN=a product name,O=Example Org,C=XX\n"
                                        "keyUsage = critical, digitalSignature\nextKeyUsage = serverAuth\n"
                                        "subjectAltName = DNS:{host}, DNS:eim9.yggdrasim.local\n"
                                        "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid")
        tls_setup.use_leaf(self.directory, "ca", "written")
        trust = tls_setup.trusted_tls_key_data(self.directory, self.identity)
        server = self.serve()
        for name in (FQDN, "eim9.yggdrasim.local"):
            with socket.create_connection(server.server_address[:2], timeout=10) as raw:
                with _client_context(trust).wrap_socket(raw, server_hostname=name) as tls:
                    served = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                    self.assertEqual(served.subject.rfc4514_string(), "CN=a product name,O=Example Org,C=XX")
        self.assertEqual(tls_setup.certificate_sha256(tls_setup.leaf_certificate_path(self.directory, "ca", "written")),
                         variant.sha256)


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
        from SCP11.eim_local.main import EimLocalShell

        shell = EimLocalShell()

        def run(line: str) -> str:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                shell._dispatch_command_line(line, source="test")
            return buffer.getvalue()

        run(f"TLS-SETUP NEW ca-chain chain=intermediate trust=root fqdn={FQDN}")
        text = run("TLS-SETUP LEAF ca-chain TEXT built")
        self.assertIn("[*] Leaf built of TLS setup ca-chain as text:", text)
        self.assertIn(f"    subject = CN={FQDN},O=YggdraSIM Local eIM,C=XX", text)
        self.assertIn("    keyUsage = critical, digitalSignature, keyAgreement", text)
        # One option per extension, in the order given; no ';', which a batch line splits on.
        line = ("TLS-SETUP LEAF ca-chain NEW two-names ext.keyUsage=critical,digitalSignature "
                "ext.subjectAltName=DNS:{host},DNS:eim9.yggdrasim.local,RID:{eim_id} "
                "ext.authorityInfoAccess=ocsp:URI:http://ocsp.example.test")
        self.assertEqual(EimLocalShell._split_batch_commands(line + "; TLS-SETUP"), [line, "TLS-SETUP"])
        issued = run(line)
        self.assertIn("Leaf two-names issued", issued)
        self.assertIn("CN auto, extensions as written", issued)
        self.assertEqual(tls_setup.leaf_text(self.directory, "ca-chain", "two-names").splitlines()[1:], [
            "keyUsage = critical, digitalSignature",
            f"subjectAltName = DNS:{FQDN}, DNS:eim9.yggdrasim.local, RID:{EIM_ID}",
            "authorityInfoAccess = ocsp:URI:http://ocsp.example.test",
        ])
        self.assertIn("subject as written", run('TLS-SETUP LEAF ca-chain NEW own-subject subject="CN={host},OU=Lab,C=XX"'))
        self.assertIn("extensions as written", run("TLS-SETUP LEAF ca-chain"))
        bare = run("TLS-SETUP LEAF ca-chain NEW bare subject=none extensions=none")
        self.assertIn("subject as written, extensions as written", bare)

        # A text file: written by TEXT, edited, read by NEW.
        target = self.directory / "leaf.txt"
        written = run(f"TLS-SETUP LEAF ca-chain TEXT two-names out={target}")
        self.assertIn(f"written to {target} (4 lines)", written)
        # out= makes a new file and never writes over one, whatever flag is given.
        before = target.read_text(encoding="utf-8")
        for flag in ("", " --replace", " --force"):
            self.assertIn("exists; out= writes a new file and never over one",
                          run(f"TLS-SETUP LEAF ca-chain TEXT built out={target}{flag}"))
        self.assertEqual(target.read_text(encoding="utf-8"), before)
        target.write_text(target.read_text(encoding="utf-8").replace("digitalSignature", "digitalSignature, keyAgreement")
                          + "2.999.7.1 = DER:0403010203\n", encoding="utf-8")
        self.assertIn("subject as written, extensions as written", run(f"TLS-SETUP LEAF ca-chain NEW edited text={target}"))
        edited = tls_setup.leaf_text(self.directory, "ca-chain", "edited").splitlines()
        self.assertEqual((edited[1], edited[-1]), ("keyUsage = critical, digitalSignature, keyAgreement",
                                                   "2.999.7.1 = DER:0403010203"))
        self.assertIn("(6 lines)", run(f"TLS-SETUP LEAF ca-chain TEXT built out={self.directory / 'built.txt'}"))
        # Any certificate reads the same way.
        root = self.directory / "tls_setups" / "ca-chain" / "root.pem"
        self.assertIn("    basicConstraints = critical, CA:TRUE", run(f"TLS-SETUP TEXT {root}"))
        self.assertIn("neither a stored certificate", run("TLS-SETUP TEXT no-such-entry"))

        for line, message in (
            ("TLS-SETUP LEAF ca-chain NEW bad ext.colour=red", "'colour' names no extension"),
            ("TLS-SETUP LEAF ca-chain NEW bad subject=CN=a cn=host", "so cn cannot shape it as well"),
            (f"TLS-SETUP LEAF ca-chain NEW bad text={target} subject=CN=a", "text=<file> carries the subject"),
            ("TLS-SETUP LEAF ca-chain NEW bad text=/nonexistent/leaf.txt", "does not read"),
            ("TLS-SETUP LEAF ca-chain NEW bad lines=x subject=CN=a", "lines= carries the whole certificate text"),
            ("TLS-SETUP LEAF ca-chain NEW bad extensions=some", "extensions takes only none"),
            ("TLS-SETUP LEAF ca-chain TEXT nosuch", "has no leaf nosuch"),
            ("TLS-SETUP TEXT", "Usage:"),
        ):
            self.assertIn(message, run(line), line)
        self.assertNotIn("bad", [item.name for item in tls_setup.list_leaves(self.directory, "ca-chain")])
        huge = self.directory / "huge.txt"
        huge.write_text("# " + "x" * 70000, encoding="utf-8")
        self.assertIn("is larger than a certificate text", run(f"TLS-SETUP LEAF ca-chain NEW bad text={huge}"))
        # A file that is no certificate text is turned away by line number: nothing of it is shown.
        for content in ("api-token = s3cr3t-value\n", "operator:x:1000:1000:lab\n", "# note\nkeyUsage = digitalSignature\nNOT A LINE s3cr3t\n"):
            foreign = self.directory / "foreign.txt"
            foreign.write_text(content, encoding="utf-8")
            refused = run(f"TLS-SETUP LEAF ca-chain NEW bad text={foreign}")
            self.assertRegex(refused, r"is not a certificate text: line \d is no subject, rdn or extension line")
            for part in ("s3cr3t", "api-token", "operator", "1000"):
                self.assertNotIn(part, refused, content)
        self.assertNotIn("bad", [item.name for item in tls_setup.list_leaves(self.directory, "ca-chain")])
        # A typed line goes through the shell's --log wrapper first; a quoted subject with a space survives it.
        with contextlib.redirect_stdout(io.StringIO()) as typed:
            shell._execute_command_line('TLS-SETUP LEAF ca-chain NEW typed subject="CN={host},O=Example Org,C=XX"')
        self.assertIn("Leaf typed issued", typed.getvalue())
        self.assertEqual(tls_setup.leaf_text(self.directory, "ca-chain", "typed").splitlines()[0],
                         f"subject = CN={FQDN},O=Example Org,C=XX")

    def test_the_gui_actions(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        def run(action_id: str, **values: object) -> dict:
            spec = next(entry for entry in SPECS if entry.id == action_id)
            return spec.dispatcher(ActionContext(), **values)

        run("eim_local.tls_setup_new", name="ca", chain="root", trust="root", fqdn=FQDN, ski=True,
            ca_basic_constraints=True, server_auth=True)
        shown = run("eim_local.tls_leaf_text", setup="ca", name="built")
        # The text action answers with lines alone: nothing for a result list to bury them under.
        self.assertEqual(sorted(shown), ["lines"])
        self.assertEqual(shown["lines"][0], "[*] Leaf built of TLS setup ca as text:")
        self.assertEqual(shown["lines"][1], f"    subject = CN={FQDN},O=YggdraSIM Local eIM,C=XX")
        checked = run("eim_local.tls_leaf_text", text="KEYUSAGE = keyAgreement,digitalSignature")
        self.assertEqual(checked["lines"][1], "    keyUsage = digitalSignature, keyAgreement")
        self.assertIn("nothing is written", run("eim_local.tls_leaf_text")["lines"][0])
        # The editor's action carries the rows, the text and what rows can hold.
        answer = run("eim_local.tls_leaf_rows", setup="ca", name="built")
        self.assertEqual(sorted(answer), ["catalogue", "leaves", "lines", "model", "text"])
        self.assertEqual(answer["lines"],
                         ["[*] Leaf built of TLS setup ca as rows: subject 3 attribute(s), extensions 5 extension(s)."])
        self.assertEqual(answer["text"].splitlines(), [line.strip() for line in shown["lines"][1:]])
        self.assertEqual([(leaf["name"], leaf["served"]) for leaf in answer["leaves"]], [("built", True)])
        json.dumps(answer)
        # What an editor does: rows in, the same text out; issue it unedited, and the leaf reads the same.
        rows = run("eim_local.tls_leaf_rows", model=json.dumps(answer["model"]))
        self.assertEqual(rows["text"], answer["text"])
        issued = run("eim_local.tls_leaf_new", setup="ca", name="from-editor", text=rows["text"], validity="setup",
                     curve="setup", send="setup", use=False, replace=False)
        self.assertIn("subject as written, extensions as written", "\n".join(issued["lines"]))
        again = run("eim_local.tls_leaf_rows", setup="ca", name="from-editor")
        self.assertEqual((again["text"], again["model"]), (answer["text"], answer["model"]))
        self.assertEqual([leaf["name"] for leaf in again["leaves"]], ["built", "from-editor"])
        # An edit on the rows reaches the certificate.
        model = json.loads(json.dumps(answer["model"]))
        names = next(row for row in model["extensions"] if row["name"] == "subjectAltName")
        names["items"].append({"kind": "IP", "value": "192.0.2.4"})
        model["subject"].append([{"oid": "2.5.4.11", "string": "UTF8String", "value": "Lab"}])
        edited = run("eim_local.tls_leaf_rows", model=json.dumps(model))["text"]
        run("eim_local.tls_leaf_new", setup="ca", name="edited", text=edited, use=False, replace=False)
        self.assertIn(f"subjectAltName = DNS:{FQDN}, IP:192.0.2.4", tls_setup.leaf_text(self.directory, "ca", "edited"))
        self.assertIn("subject = OU=Lab,CN=", tls_setup.leaf_text(self.directory, "ca", "edited"))
        # Nothing given is the open certificate, with the setup's leaves and the catalogue.
        empty = run("eim_local.tls_leaf_rows", setup="ca")
        self.assertEqual((empty["text"], empty["model"]), ("", {"subject": None, "extensions": None}))
        self.assertEqual(len(empty["catalogue"]["extensions"]), 17)
        self.assertIn("subject left to the options, extensions left to the options", empty["lines"][0])
        # The form's own text field issues the same way, beside its options.
        form = run("eim_local.tls_leaf_new", setup="ca", name="form", text="subject = CN={host},C=XX", cn="setup",
                   registered_id="setup", san="", layout="", validity="setup", ski="off", server_auth="setup",
                   curve="setup", send="setup", replace=False, use=False)
        self.assertIn("subject as written, leaf name the setup FQDN, registeredID auto, SKI off", "\n".join(form["lines"]))
        for action_id in ("eim_local.tls_leaf_text", "eim_local.tls_leaf_rows"):
            for values, message in (
                ({"text": "colour = red"}, "'colour' names no extension"),
                ({"setup": "ca", "name": "nope"}, "has no leaf nope"),
                ({"setup": "nosuch", "name": "built"}, "No TLS setup nosuch"),
                # No file is opened for a name that comes in a request.
                ({"certificate": str(self.directory / "tls_setups" / "ca" / "root.pem")}, "Certificate name"),
                ({"certificate": "no-such-entry"}, "No stored certificate named"),
            ):
                with self.subTest(action_id + str(values)[:40]):
                    with self.assertRaises(ValueError) as refused:
                        run(action_id, **values)
                    self.assertIn(message, str(refused.exception))
        for model_text, message in (("{not json", "The editor's rows are not JSON"),
                                    (json.dumps({"extensions": [{"oid": "2.5.29.15", "items": ["flying"]}]}),
                                     "extension 1 (keyUsage)")):
            with self.assertRaises(ValueError) as refused:
                run("eim_local.tls_leaf_rows", model=model_text)
            self.assertIn(message, str(refused.exception))
        with self.assertRaisesRegex(ValueError, "so cn cannot shape it as well"):
            run("eim_local.tls_leaf_new", setup="ca", name="clash", text="subject = CN=a", cn="host")

    def test_the_editor_is_wired_into_the_page(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

        source = REPO / "gui_frontend" / "src"
        editor = (source / "js" / "local-eim-leaf-editor.js").read_text(encoding="utf-8")
        page = (source / "js" / "local-eim-page.js").read_text(encoding="utf-8")
        center = (source / "js" / "command-center.js").read_text(encoding="utf-8")
        order = (source / "js" / ".js_order").read_text(encoding="utf-8").split()
        self.assertEqual(order.index("local-eim-leaf-editor.js"), order.index("local-eim-page.js") + 1)
        self.assertIn("views/local-eim-leaf-editor.css", (source / "css" / ".css_order").read_text(encoding="utf-8"))
        registered = {spec.id for spec in SPECS}
        for action_id in ("eim_local.tls_leaf_rows", "eim_local.tls_leaf_new"):
            self.assertIn(f'"{action_id}"', editor, action_id)
            self.assertIn(action_id, registered)
        self.assertIn("eim_local.tls_leaf_text", registered)
        for suffix in ("tls_leaf_text", "tls_leaf_rows"):
            self.assertIn(f'"{suffix}"', center, suffix)
        # A text that does not read stays in the text view, and the rows are turned into text before it opens.
        self.assertIn("function lleApplyText(", editor)
        self.assertIn("lleCheck(ctx, true).then(", editor)
        # The editor builds no markup from strings, holds no parser, and keeps its rows in the page's state.
        self.assertNotIn("innerHTML", editor)
        self.assertNotIn("apiFetch(", editor)
        for parser_sign in ("split(\"=\")", "split(\"\\n\")", "RegExp("):
            self.assertNotIn(parser_sign, editor, parser_sign)
        for hook in ("lleNewEditor(", "lleRender(root, leafEditorContext())", "state.leaf", "state.formOpen = true"):
            self.assertIn(hook, page, hook)
        for label in ("Leaf editor", "Edit a copy of this leaf"):
            self.assertIn(f'"{label}"', page, label)
        # Every widget the catalogue names has a control in the editor.
        widgets = {row["widget"] for row in cert_spec.catalogue()["extensions"]}
        self.assertEqual(widgets, {"key-id", "choice-set", "text-list", "name-list", "basic", "access-list", "raw"})
        for widget in widgets - {"text-list"}:
            self.assertIn(f'"{widget}"', editor, widget)


if __name__ == "__main__":
    unittest.main()
