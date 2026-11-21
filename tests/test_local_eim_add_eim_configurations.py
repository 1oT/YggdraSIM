# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ADD-EIM from a saved eIM configuration of the AddInitialEim builder.

``config=<name>`` on an Add eIM operation takes every field from the
configuration: the eCO then carries the EimConfigurationData the builder would
put on a card with ES10b.AddInitialEim for the same configuration (SGP.32 v1.3
§2.11.1.1.2 addEim, §5.9.4 AddInitialEim), under tag 'A8'. The operation holds
explicit fields, so the configuration can be renamed or deleted afterwards.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine.catalogue import (
    KIND_CONFIGURATION,
    OPERATION_TYPES,
    OperationError,
    build_items,
    configuration_params,
    describe,
    expand_eim_configuration,
    normalize_params,
)
from SCP11.eim_local.engine.delivery import deliver
from SCP11.eim_local.engine.overview import build_overview, operation_detail
from SCP11.eim_local.engine.service import STATE_SUCCESS, LocalEim, OperationRequest
from SCP11.eim_local.main import EimLocalShell
from SCP11.shared import eim_builder, eim_builder_store
from SCP11.shared.ber_tlv import retag_sequence
from SCP11.shared.eim_configuration_data import encode_eim_configuration_data
from tests.test_local_eim_engine import EIM_ID, SimCard

ADD_EIM = OPERATION_TYPES["ADD_EIM"]
OTHER_EIM_ID = "1.3.6.1.4.1.32473.999.10.200"
OTHER_EIM_FQDN = "eim-other.example.test"
CI_PKID = "F54172BDF98A95D65CBEB88A38A1C11D800A85C3"

CONFIGURATIONS: dict[str, dict[str, object]] = {
    # OID eimId with the host beside it, both keys as certificates.
    "oid-with-certificates": {
        "eim_id": OTHER_EIM_ID, "eim_certificate": "other-eim-signing", "eim_key_form": "eimCertificate",
        "eim_id_type": "eimIdTypeOid", "eim_fqdn": OTHER_EIM_FQDN, "counter_value": 0, "association_token": True,
        "tls_certificate": "other-eim-tls-root", "tls_key_form": "trustedCertificateTls",
        "eim_supported_protocol": ["eimRetrieveHttps"], "euicc_ci_pk_id": CI_PKID, "indirect_profile_download": True,
    },
    # The host as the eimId, both keys as public keys, two protocols, no CI key identifier.
    "fqdn-with-public-keys": {
        "eim_id": OTHER_EIM_FQDN, "eim_certificate": "other-eim-signing", "eim_key_form": "eimPublicKey",
        "eim_id_type": "eimIdTypeFqdn", "eim_fqdn": "", "counter_value": 4, "association_token": False,
        "tls_certificate": "other-eim-tls-root", "tls_key_form": "trustedEimPkTls",
        "eim_supported_protocol": ["eimRetrieveHttps", "eimInjectHttps"], "euicc_ci_pk_id": "",
        "indirect_profile_download": False,
    },
    # The least an entry takes: an eimId and the eIM's certificate.
    "bare": {
        "eim_id": "lab-eim-7", "eim_certificate": "other-eim-signing", "eim_key_form": "eimCertificate",
        "eim_id_type": "omit", "eim_fqdn": "", "counter_value": 0, "association_token": False,
        "tls_certificate": "", "tls_key_form": "trustedCertificateTls", "eim_supported_protocol": None,
        "euicc_ci_pk_id": "", "indirect_profile_download": False,
    },
}


def _certificate(common_name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


class ConfigurationTestBase(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.builder_store = self.root / "eim_builder"
        environment = mock.patch.dict(os.environ, {
            "YGGDRASIM_EIM_BUILDER_STORE": str(self.builder_store),
            "YGGDRASIM_LOCAL_EIM_STORE": str(self.root / "local_eim"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        eim_builder_store.import_certificates(_certificate("Other eIM signing"), name="other-eim-signing")
        eim_builder_store.import_certificates(_certificate("Other eIM TLS root"), name="other-eim-tls-root")
        for name, values in CONFIGURATIONS.items():
            eim_builder_store.save_configuration(name, values)

    def builder_entry(self, name: str, **changes: object):
        """The entry AddInitialEim would carry for the configuration, with *changes* to its saved values."""
        values = {**CONFIGURATIONS[name], **changes}
        return eim_builder.build_add_initial_eim(eim_builder.inputs_from_configuration(values), remember=False).entry

    def expanded(self, **values: object) -> dict:
        filled, _notes = expand_eim_configuration(ADD_EIM, dict(values))
        return normalize_params(ADD_EIM, filled)


class ExpansionTests(ConfigurationTestBase):
    def test_the_eco_carries_the_entry_add_initial_eim_would_carry(self) -> None:
        for name in CONFIGURATIONS:
            entry = self.builder_entry(name)
            params = self.expanded(config=name)
            self.assertNotIn("config", params)
            self.assertEqual(build_items(ADD_EIM, params),
                             retag_sequence(b"\xA8", encode_eim_configuration_data(entry)), name)
            # The same octets are what the AddInitialEimRequest of that configuration holds.
            request = eim_builder.build_add_initial_eim(
                eim_builder.inputs_from_configuration(CONFIGURATIONS[name]), remember=False).request
            self.assertIn(encode_eim_configuration_data(entry), request, name)

    def test_the_fields_and_back_lose_nothing(self) -> None:
        for name in CONFIGURATIONS:
            entry = self.builder_entry(name)
            params = configuration_params(entry)
            self.assertEqual(set(params) - {spec.name for spec in ADD_EIM.params}, set(), name)
        params = configuration_params(self.builder_entry("fqdn-with-public-keys"))
        self.assertEqual((params["eim_id"], params["eim_id_type"], params["counter_value"], params["protocols"]),
                         (OTHER_EIM_FQDN, "fqdn", 4, "eimRetrieveHttps,eimInjectHttps"))
        self.assertIn("public_key", params)
        self.assertNotIn("certificate", params)
        self.assertNotIn("eim_fqdn", params)
        self.assertNotIn("association_token", params)

    def test_a_field_given_beside_the_configuration_wins(self) -> None:
        cases = (
            ({"counter_value": "7"}, {"counter_value": 7}),
            ({"association_token": "off"}, {"association_token": False}),
            ({"indirect": "off"}, {"indirect_profile_download": False}),
            ({"protocols": "eimRetrieveHttps,eimInjectHttps"},
             {"eim_supported_protocol": ["eimRetrieveHttps", "eimInjectHttps"]}),
            ({"ci_pkid": ""}, {}),
        )
        for given, saved in cases:
            params = self.expanded(config="oid-with-certificates", **given)
            entry = self.builder_entry("oid-with-certificates", **saved)
            self.assertEqual(build_items(ADD_EIM, params),
                             retag_sequence(b"\xA8", encode_eim_configuration_data(entry)), given)

    def test_a_key_given_by_hand_replaces_the_configuration_s_key_in_either_form(self) -> None:
        stored = eim_builder_store.read_certificate("other-eim-tls-root")
        as_key = self.expanded(config="oid-with-certificates", public_key=stored.spki_der.hex())
        self.assertEqual(as_key["public_key"], stored.spki_der.hex().upper())
        self.assertNotIn("certificate", as_key)
        as_certificate = self.expanded(config="fqdn-with-public-keys", certificate=stored.der.hex())
        self.assertEqual(as_certificate["certificate"].upper(), stored.der.hex().upper())
        self.assertNotIn("public_key", as_certificate)

    def test_without_a_configuration_the_fields_are_what_was_given(self) -> None:
        filled, notes = expand_eim_configuration(ADD_EIM, {"eim_id": OTHER_EIM_ID, "Config": " "})
        self.assertEqual((filled, notes), ({"eim_id": OTHER_EIM_ID}, []))
        enable = OPERATION_TYPES["ENABLE_PROFILE"]
        self.assertEqual(expand_eim_configuration(enable, {"iccid": "8988211111111111129", "config": "bare"}),
                         ({"iccid": "8988211111111111129", "config": "bare"}, []))
        with self.assertRaises(OperationError):
            normalize_params(enable, {"iccid": "8988211111111111129", "config": "bare"})

    def test_only_add_eim_takes_a_configuration(self) -> None:
        takes = [kind.name for kind in OPERATION_TYPES.values()
                 if any(spec.kind == KIND_CONFIGURATION for spec in kind.params)]
        self.assertEqual(takes, ["ADD_EIM"])

    def test_an_unknown_name_is_refused_with_the_saved_ones(self) -> None:
        with self.assertRaises(OperationError) as refusal:
            expand_eim_configuration(ADD_EIM, {"config": "no-such"})
        self.assertIn("No saved eIM configuration 'no-such' (saved: bare, fqdn-with-public-keys, "
                      "oid-with-certificates).", str(refusal.exception))
        for name in list(CONFIGURATIONS):
            eim_builder_store.delete_configuration(name)
        with self.assertRaises(OperationError) as refusal:
            expand_eim_configuration(ADD_EIM, {"config": "bare"})
        self.assertIn("(saved: none)", str(refusal.exception))

    def test_a_configuration_whose_certificate_is_gone_is_refused_by_name(self) -> None:
        eim_builder_store.remove_certificate("other-eim-tls-root")
        with self.assertRaises(OperationError) as refusal:
            expand_eim_configuration(ADD_EIM, {"config": "oid-with-certificates"})
        self.assertIn("eIM configuration 'oid-with-certificates': trustedPublicKeyDataTls:", str(refusal.exception))
        self.assertTrue(self.expanded(config="bare"))

    def test_what_the_builder_warns_about_is_passed_on(self) -> None:
        eim_builder_store.save_configuration("typed-oid-as-fqdn", {
            **CONFIGURATIONS["oid-with-certificates"], "eim_id_type": "eimIdTypeFqdn"})
        filled, notes = expand_eim_configuration(ADD_EIM, {"config": "typed-oid-as-fqdn"})
        # SGP.32 v1.3 §4.3: with eimIdTypeFqdn the host is the eimId.
        self.assertEqual((filled["eim_id"], filled["eim_id_type"]), (OTHER_EIM_FQDN, "fqdn"))
        self.assertEqual(len(notes), 1)
        self.assertTrue(notes[0].startswith("eIM configuration typed-oid-as-fqdn: eimIdType is eimIdTypeFqdn"))

    def test_queueing_writes_nothing_into_the_builder_store(self) -> None:
        before = sorted(path.name for path in self.builder_store.iterdir())
        self.expanded(config="oid-with-certificates")
        self.assertEqual(sorted(path.name for path in self.builder_store.iterdir()), before)
        self.assertNotIn("last_configuration.json", before)


class EngineTests(ConfigurationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.engine = LocalEim(self.root / "local_eim")
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.card = SimCard()
        self.engine.associate(self.card.exchange, self.card.eid)

    def submit(self, **params: object):
        return self.engine.submit([OperationRequest(eid=self.card.eid, type="ADD_EIM", params=dict(params))])[0]

    def test_the_operation_holds_explicit_fields_and_outlives_the_configuration(self) -> None:
        operation = self.submit(config="oid-with-certificates")
        self.assertNotIn("config", operation.params)
        self.assertEqual((operation.params["eim_id"], operation.params["eim_fqdn"]), (OTHER_EIM_ID, OTHER_EIM_FQDN))
        expected = build_items(ADD_EIM, operation.params)
        eim_builder_store.rename_configuration("oid-with-certificates", "renamed")
        eim_builder_store.remove_certificate("other-eim-signing")
        self.assertEqual(build_items(ADD_EIM, self.engine.operation(operation.id).params), expected)
        self.assertEqual(describe(ADD_EIM, self.engine.operation(operation.id).params), f"Add eIM {OTHER_EIM_ID}")

    def test_the_simulated_euicc_takes_the_eim_and_answers_a_token(self) -> None:
        operation = self.submit(config="oid-with-certificates")
        deliver(self.engine, self.card.exchange, self.card.eid)
        finished = self.engine.operation(operation.id)
        self.assertEqual(finished.state, STATE_SUCCESS, finished.error)
        added = next(entry for entry in self.card.state.eim_entries if entry.eim_id == OTHER_EIM_ID)
        self.assertEqual(added.eim_fqdn, OTHER_EIM_FQDN)
        self.assertEqual(added.counter_value, 0)
        self.assertIsNotNone(added.association_token)
        self.assertIn("associationToken", str(finished.result))

    def test_a_plan_shows_the_builder_s_warning_and_stores_nothing(self) -> None:
        eim_builder_store.save_configuration("typed-oid-as-fqdn", {
            **CONFIGURATIONS["oid-with-certificates"], "eim_id_type": "eimIdTypeFqdn"})
        entry = self.engine.plan([OperationRequest(eid=self.card.eid, type="ADD_EIM",
                                                   params={"config": "typed-oid-as-fqdn"})])[0]
        self.assertTrue(any(text.startswith("eIM configuration typed-oid-as-fqdn:") for text in entry.warnings))
        self.assertEqual(entry.params["eim_id"], OTHER_EIM_FQDN)
        self.assertEqual(self.engine.operations(), [])

    def test_an_edit_takes_a_configuration_too(self) -> None:
        operation = self.submit(eim_id="lab-eim-1", certificate="other-eim-signing")
        edited = self.engine.edit(operation.id, {"config": "fqdn-with-public-keys", "counter_value": "9"})
        self.assertNotIn("config", edited.params)
        self.assertEqual((edited.params["eim_id"], edited.params["counter_value"]), (OTHER_EIM_FQDN, 9))
        # The certificate the operation had makes way for the configuration's public key.
        self.assertNotIn("certificate", edited.params)
        entry = self.builder_entry("fqdn-with-public-keys", counter_value=9)
        self.assertEqual(build_items(ADD_EIM, edited.params),
                         retag_sequence(b"\xA8", encode_eim_configuration_data(entry)))


class SurfaceTests(ConfigurationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.shell = EimLocalShell()
        self.engine = self.shell._engine_verbs.engine
        self.engine.new_identity(eim_id=EIM_ID, eim_fqdn="eim.yggdrasim.local")
        self.eid = "89049032123451234512345678901235"
        self.engine.register(self.eid)

    def run_line(self, line: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._dispatch_command_line(line, source="test")
        return buffer.getvalue()

    def test_the_shell_queues_by_name_and_refuses_an_unknown_one_in_a_line(self) -> None:
        planned = self.run_line(f"QUEUE ADD-EIM {self.eid} config=oid-with-certificates counter_value=3 --plan")
        self.assertIn(f"[plan] {self.eid}  ADD_EIM: Add eIM {OTHER_EIM_ID}", planned)
        queued = self.run_line(f"QUEUE ADD-EIM {self.eid} config=oid-with-certificates")
        self.assertIn("[+] Queued 1 operation(s)", queued)
        operation = self.engine.operations()[0]
        self.assertEqual((operation.type, operation.params["eim_id"]), ("ADD_EIM", OTHER_EIM_ID))
        refused = self.run_line(f"QUEUE ADD-EIM {self.eid} config=no-such")
        self.assertIn("[!] No saved eIM configuration 'no-such' (saved: bare, fqdn-with-public-keys, "
                      "oid-with-certificates).", refused)
        self.assertEqual(len(self.engine.operations()), 1)

    def test_the_page_s_form_offers_the_saved_names(self) -> None:
        document = build_overview(self.engine, eid=self.eid)
        add = next(kind for kind in document["catalogue"] if kind["type"] == "ADD_EIM")
        config = add["params"][0]
        self.assertEqual((config["name"], config["kind"], config["required"]), ("config", "configuration", False))
        self.assertEqual(config["choices"], ["bare", "fqdn-with-public-keys", "oid-with-certificates"])
        self.assertEqual([entry["name"] for entry in document["eim_configurations"]], config["choices"])
        self.assertIn(OTHER_EIM_ID, document["eim_configurations"][2]["summary"])
        page = (Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "local-eim-page.js").read_text(
            encoding="utf-8")
        self.assertIn('field.kind === "configuration" && field.read()', page)
        self.assertIn("if (!value && fields[i].required && !filled) {", page)

    def test_the_queue_action_takes_the_name_the_form_sends(self) -> None:
        from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

        queue = next(spec for spec in SPECS if spec.id == "eim_local.op_queue")
        answer = queue.dispatcher(None, operation="ADD-EIM", eid=self.eid, params='config="bare"')
        self.assertTrue(any("Queued 1 operation(s)" in line for line in answer["lines"]), answer)
        self.assertEqual(self.engine.operations()[0].params["eim_id"], "lab-eim-7")
        edit = operation_detail(self.engine, self.engine.operations()[0].id)
        self.assertEqual(edit["param_specs"][0]["choices"], ["bare", "fqdn-with-public-keys", "oid-with-certificates"])


if __name__ == "__main__":
    unittest.main()
