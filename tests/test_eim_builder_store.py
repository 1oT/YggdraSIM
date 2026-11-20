# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The AddInitialEim builder's untracked store: certificates and saved values."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from SCP11.shared import eim_builder_store as store
from tests.eim_builder_support import TEST_EIM_ID, der, make_certificate, pem, private_key_pem


def test_store_dir_defaults_to_the_user_directory_and_honours_the_override(tmp_path: Path) -> None:
    assert store.store_dir({}) == Path(os.path.expanduser("~")) / ".yggdrasim" / "eim_builder"
    assert store.store_dir({store.STORE_DIR_ENV: str(tmp_path)}) == tmp_path


def test_the_test_session_never_points_at_the_real_store() -> None:
    assert store.store_dir() != Path(os.path.expanduser("~")) / ".yggdrasim" / "eim_builder"


def test_import_keeps_the_certificate_and_drops_the_private_key(tmp_path: Path) -> None:
    certificate, key = make_certificate(TEST_EIM_ID)
    report = store.import_certificates(pem(certificate) + private_key_pem(key), directory=tmp_path)
    assert [entry.name for entry in report.stored] == [TEST_EIM_ID]
    assert report.private_keys_dropped == 1
    stored = (tmp_path / "certificates" / f"{TEST_EIM_ID}.pem").read_bytes()
    assert b"PRIVATE KEY" not in stored
    assert store.read_certificate(TEST_EIM_ID, tmp_path).der == der(certificate)
    if sys.platform != "win32":
        assert stat.S_IMODE((tmp_path / "certificates").stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "certificates" / f"{TEST_EIM_ID}.pem").stat().st_mode) == 0o600


def test_import_reads_der_and_hex_and_describes_the_certificate(tmp_path: Path) -> None:
    certificate, _key = make_certificate("eIM TLS Test CA", ca=True)
    report = store.import_certificates(der(certificate), name="tls-ca", directory=tmp_path)
    entry = report.stored[0]
    assert (entry.name, entry.is_ca, entry.key, entry.subject_cn) == ("tls-ca", True, "EC secp256r1", "eIM TLS Test CA")
    assert len(entry.ski_hex) == 40
    assert entry.spki_der.startswith(b"\x30") and entry.spki_der in der(certificate)
    hex_report = store.import_certificates(der(certificate).hex().encode(), name="tls-ca-hex", directory=tmp_path)
    assert hex_report.same_as == {"tls-ca-hex": "tls-ca"}


def test_import_reads_bare_base64_in_both_alphabets(tmp_path: Path) -> None:
    import base64
    import textwrap

    certificate, _ = make_certificate(TEST_EIM_ID)
    raw = der(certificate)
    wrapped = "\n".join(textwrap.wrap(base64.b64encode(raw).decode(), 64)).encode()
    url_safe = base64.urlsafe_b64encode(raw).rstrip(b"=")
    assert store.certificates_from_source(wrapped) == ([raw], 0)
    assert store.certificates_from_source(url_safe) == ([raw], 0)
    report = store.import_certificates(b"  " + wrapped + b"\n", name="from-base64", directory=tmp_path)
    assert report.stored[0].der == raw
    with pytest.raises(store.EimBuilderStoreError, match="not valid base64"):
        store.certificates_from_source(b"MIIBA")
    with pytest.raises(store.EimBuilderStoreError, match="neither PEM nor DER"):
        store.certificates_from_source(b"MIIBAAA")


def test_concatenated_der_certificates_import_and_trailing_bytes_are_named(tmp_path: Path) -> None:
    first, _ = make_certificate("eIM Leaf")
    second, _ = make_certificate("eIM Root CA", ca=True)
    blob = der(first) + der(second)
    assert store.certificates_from_source(blob.hex().encode()) == ([der(first), der(second)], 0)
    report = store.import_certificates(blob, name="chain", directory=tmp_path)
    assert [entry.name for entry in report.stored] == ["chain", "chain-2"]
    with pytest.raises(store.EimBuilderStoreError, match=r"1 DER object\(s\) in its first \d+ bytes, then 3 bytes"):
        store.certificates_from_source(der(first) + b"\x30\x05\x02")
    with pytest.raises(store.EimBuilderStoreError, match="tag 02, not a certificate SEQUENCE"):
        store.certificates_from_source(der(first) + b"\x02\x01\x01")


def test_san_registered_id_is_read(tmp_path: Path) -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eIM with SAN")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(9)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.RegisteredID(ObjectIdentifier("1.3.6.1.4.1.32473.999.10"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    entry = store.import_certificates(der(certificate), name="san", directory=tmp_path).stored[0]
    assert entry.san_registered_ids == ("1.3.6.1.4.1.32473.999.10",)


def test_import_names_every_certificate_of_a_bundle(tmp_path: Path) -> None:
    first, _ = make_certificate("eIM Leaf")
    second, _ = make_certificate("eIM Root CA", ca=True)
    report = store.import_certificates(pem(first) + pem(second), directory=tmp_path)
    assert [entry.name for entry in report.stored] == ["eIM-Leaf", "eIM-Root-CA"]
    named = store.import_certificates(pem(first) + pem(second), name="chain", directory=tmp_path)
    assert [entry.name for entry in named.stored] == ["chain", "chain-2"]


def test_import_refuses_an_existing_name_unless_overwriting(tmp_path: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim", directory=tmp_path)
    with pytest.raises(store.EimBuilderStoreError, match="already uses"):
        store.import_certificates(der(certificate), name="eim", directory=tmp_path)
    replacement, _ = make_certificate("other")
    store.import_certificates(der(replacement), name="eim", overwrite=True, directory=tmp_path)
    assert store.read_certificate("eim", tmp_path).subject_cn == "other"


def test_list_reports_an_unreadable_file_and_remove_deletes_an_entry(tmp_path: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="eim", directory=tmp_path)
    (tmp_path / "certificates" / "broken.pem").write_bytes(b"not a certificate")
    entries, problems = store.list_certificates(tmp_path)
    assert [entry.name for entry in entries] == ["eim"]
    assert len(problems) == 1 and problems[0].startswith("broken.pem")
    assert store.remove_certificate("eim.pem", tmp_path) == "eim"
    with pytest.raises(store.EimBuilderStoreError, match="No stored certificate"):
        store.read_certificate("eim", tmp_path)


@pytest.mark.parametrize("source", [b"", b"\x30", b"\x30\x82", b"\x30\x05\x02\x01", b"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"])
def test_certificate_source_decode_boundaries(source: bytes) -> None:
    with pytest.raises(store.EimBuilderStoreError):
        store.certificates_from_source(source)


def test_a_key_the_build_cannot_load_only_loses_its_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm

    certificate, _ = make_certificate(TEST_EIM_ID)
    real_load = x509.load_der_x509_certificate

    class _NoKey:
        def __init__(self, inner) -> None:
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def public_key(self):
            raise UnsupportedAlgorithm("curve not supported by this build")

    monkeypatch.setattr(x509, "load_der_x509_certificate", lambda raw: _NoKey(real_load(raw)))
    entry = store.import_certificates(der(certificate), name="eim", directory=tmp_path).stored[0]
    assert entry.key == "unsupported key"
    assert entry.spki_der in der(certificate)


def test_a_brainpool_certificate_is_described(tmp_path: Path) -> None:
    import datetime

    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    try:
        key = ec.generate_private_key(ec.BrainpoolP256R1())
    except UnsupportedAlgorithm:
        pytest.skip("This cryptography build has no brainpoolP256r1.")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TEST_EIM_ID)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    entry = store.import_certificates(der(certificate), name="bp", directory=tmp_path).stored[0]
    assert entry.key == "EC brainpoolP256r1"


def test_a_non_certificate_sequence_is_refused_on_import(tmp_path: Path) -> None:
    with pytest.raises(store.EimBuilderStoreError, match="Not an X.509 certificate"):
        store.import_certificates(bytes.fromhex("3003020101"), name="junk", directory=tmp_path)
    assert (tmp_path / "certificates").exists() is False


def test_names_are_validated() -> None:
    assert store.normalise_name("eim-test.pem") == "eim-test"
    for bad in ("", "-leading", "a" * 65, "has space", "../escape"):
        with pytest.raises(store.EimBuilderStoreError):
            store.normalise_name(bad)
    assert store.name_from_subject("eIM / Test CA") == "eIM-Test-CA"
    assert store.name_from_subject("TEST SM eIM - CERT.EIM.ECDSA") == "TEST-SM-eIM-CERT.EIM.ECDSA"
    assert store.name_from_subject("") == "certificate"


def test_values_are_newest_first_deduplicated_and_bounded(tmp_path: Path) -> None:
    for index in range(store.MAX_VALUES_PER_FIELD + 4):
        store.remember_values({"eim_fqdn": f"eim{index}.example.test"}, tmp_path)
    store.remember_values({"eim_fqdn": "eim3.example.test"}, tmp_path)
    values = store.load_values(tmp_path)["eim_fqdn"]
    assert len(values) == store.MAX_VALUES_PER_FIELD
    assert values[0] == "eim3.example.test"
    assert values.count("eim3.example.test") == 1


def test_last_build_records_a_member_left_out(tmp_path: Path) -> None:
    store.remember_values({"eim_id": TEST_EIM_ID, "tls_certificate": "tls-ca"}, tmp_path)
    store.remember_values({"eim_id": TEST_EIM_ID, "tls_certificate": ""}, tmp_path)
    assert store.load_last_build(tmp_path)["tls_certificate"] == ""
    assert store.load_values(tmp_path)["tls_certificate"] == ["tls-ca"]


def test_forget_drops_a_value_from_the_list_and_the_last_build(tmp_path: Path) -> None:
    store.remember_values({"eim_id": TEST_EIM_ID}, tmp_path)
    assert store.forget_value("eim_id", TEST_EIM_ID, tmp_path) is True
    assert store.load_values(tmp_path)["eim_id"] == []
    assert store.load_last_build(tmp_path)["eim_id"] == ""
    assert store.forget_value("eim_id", TEST_EIM_ID, tmp_path) is False
    with pytest.raises(store.EimBuilderStoreError, match="Unknown saved-value field"):
        store.forget_value("imsi", "001010000000001", tmp_path)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{",
        b"[]",
        json.dumps({"schema": "other", "values": {}}).encode(),
        json.dumps({"schema": store.VALUES_SCHEMA, "values": {"eim_id": "not a list"}}).encode(),
        json.dumps({"schema": store.VALUES_SCHEMA, "values": {"eim_id": [1]}}).encode(),
    ],
)
def test_an_unreadable_values_file_is_reported_and_never_overwritten(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / store.VALUES_FILE_NAME
    path.write_bytes(content)
    with pytest.raises(store.EimBuilderStoreError):
        store.load_values(tmp_path)
    with pytest.raises(store.EimBuilderStoreError):
        store.remember_values({"eim_id": TEST_EIM_ID}, tmp_path)
    assert path.read_bytes() == content


def test_values_refuse_control_characters_and_overlong_text(tmp_path: Path) -> None:
    with pytest.raises(store.EimBuilderStoreError, match="control character"):
        store.remember_values({"eim_id": "a\nb"}, tmp_path)
    with pytest.raises(store.EimBuilderStoreError, match="characters"):
        store.remember_values({"eim_fqdn": "a" * (store.MAX_VALUE_LENGTH + 1)}, tmp_path)


def test_rename_follows_into_saved_values_and_configurations(tmp_path: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="before", directory=tmp_path)
    store.remember_values({"eim_certificate": "before", "tls_certificate": "before"}, tmp_path)
    store.save_configuration("cfg", {"eim_certificate": "before", "eim_id": TEST_EIM_ID}, tmp_path)
    renamed, updated = store.rename_certificate("before", "after", tmp_path)
    assert (renamed, updated) == ("after", ["cfg"])
    assert store.read_certificate("after", tmp_path).der == der(certificate)
    assert store.load_values(tmp_path)["eim_certificate"] == ["after"]
    assert store.load_last_build(tmp_path)["tls_certificate"] == "after"
    assert store.load_configurations(tmp_path)["cfg"]["eim_certificate"] == "after"
    store.import_certificates(der(certificate), name="other", directory=tmp_path)
    with pytest.raises(store.EimBuilderStoreError, match="already uses"):
        store.rename_certificate("after", "other", tmp_path)
    with pytest.raises(store.EimBuilderStoreError, match="No stored certificate"):
        store.rename_certificate("missing", "x", tmp_path)


def test_remove_drops_the_name_from_saved_values_but_not_configurations(tmp_path: Path) -> None:
    certificate, _ = make_certificate(TEST_EIM_ID)
    store.import_certificates(der(certificate), name="gone", directory=tmp_path)
    store.remember_values({"eim_certificate": "gone"}, tmp_path)
    store.save_configuration("cfg", {"eim_certificate": "gone"}, tmp_path)
    store.remove_certificate("gone", tmp_path)
    assert store.load_values(tmp_path)["eim_certificate"] == []
    assert store.load_last_build(tmp_path)["eim_certificate"] == ""
    assert store.configurations_using_certificate("gone", tmp_path) == ["cfg"]


def test_edit_value_replaces_in_place(tmp_path: Path) -> None:
    store.remember_values({"eim_id": "first"}, tmp_path)
    store.remember_values({"eim_id": "second"}, tmp_path)
    assert store.edit_value("eim_id", "first", "fixed", tmp_path) is True
    assert store.load_values(tmp_path)["eim_id"] == ["second", "fixed"]
    assert store.edit_value("eim_id", "second", "fixed", tmp_path) is True
    assert store.load_values(tmp_path)["eim_id"] == ["fixed"]
    assert store.load_last_build(tmp_path)["eim_id"] == "fixed"
    assert store.edit_value("eim_id", "absent", "x", tmp_path) is False
    with pytest.raises(store.EimBuilderStoreError, match="new value is required"):
        store.edit_value("eim_id", "fixed", " ", tmp_path)


def test_configurations_save_rename_delete_and_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = {"eim_id": TEST_EIM_ID, "counter_value": 3, "association_token": True, "eim_supported_protocol": ["eimRetrieveHttps"]}
    assert store.save_configuration("one", values, tmp_path) == "one"
    assert store.load_configurations(tmp_path) == {"one": values}
    assert store.rename_configuration("one", "two", tmp_path) == "two"
    store.save_configuration("three", {"eim_id": "x"}, tmp_path)
    with pytest.raises(store.EimBuilderStoreError, match="already exists"):
        store.rename_configuration("two", "three", tmp_path)
    assert store.delete_configuration("two", tmp_path) == "two"
    assert sorted(store.load_configurations(tmp_path)) == ["three"]
    with pytest.raises(store.EimBuilderStoreError, match="No configuration"):
        store.delete_configuration("two", tmp_path)
    for bad in ({"k": {"nested": 1}}, {"k": ["a b"]}, {"bad key": 1}, {"k": "x\n"}):
        with pytest.raises(store.EimBuilderStoreError):
            store.save_configuration("bad", bad, tmp_path)
    monkeypatch.setattr(store, "MAX_CONFIGURATIONS", 1)
    with pytest.raises(store.EimBuilderStoreError, match="delete one first"):
        store.save_configuration("four", {"eim_id": "y"}, tmp_path)
    store.save_configuration("three", {"eim_id": "replaced"}, tmp_path)


@pytest.mark.parametrize("content", [b"", b"{", json.dumps({"schema": "other"}).encode(), json.dumps({"schema": store.CONFIGURATIONS_SCHEMA, "configurations": []}).encode()])
def test_an_unreadable_configurations_file_is_reported(tmp_path: Path, content: bytes) -> None:
    (tmp_path / store.CONFIGURATIONS_FILE_NAME).write_bytes(content)
    with pytest.raises(store.EimBuilderStoreError):
        store.load_configurations(tmp_path)
    with pytest.raises(store.EimBuilderStoreError):
        store.save_configuration("x", {"eim_id": "y"}, tmp_path)
    assert (tmp_path / store.CONFIGURATIONS_FILE_NAME).read_bytes() == content


def test_the_last_configuration_round_trips_and_follows_a_rename(tmp_path: Path) -> None:
    assert store.load_last_configuration(tmp_path) == {}
    certificate, _ = make_certificate("Last Configuration Test")
    store.import_certificates(der(certificate), name="before", directory=tmp_path)
    store.remember_last_configuration(
        {"eim_certificate": "before", "counter_value": 7, "eim_supported_protocol": ["eimRetrieveHttps"]}, tmp_path
    )
    assert store.load_last_configuration(tmp_path)["counter_value"] == 7
    store.rename_certificate("before", "after", tmp_path)
    assert store.load_last_configuration(tmp_path)["eim_certificate"] == "after"


def test_an_unreadable_last_configuration_is_reported(tmp_path: Path) -> None:
    store.last_configuration_path(tmp_path).write_text('{"schema": "something else"}', encoding="utf-8")
    with pytest.raises(store.EimBuilderStoreError, match="last_configuration"):
        store.load_last_configuration(tmp_path)
