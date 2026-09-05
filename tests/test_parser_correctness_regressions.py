# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Boundary and malformed-input regressions for shared protocol codecs."""

from __future__ import annotations

import datetime
import importlib
import random
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SCP11 import eim_packages
from SCP11.live import eim_packages as live_eim_packages
from SIMCARD.scp03 import Scp03CardLogic
from SIMCARD.sgp import SgpLogic
from SIMCARD.sgp32_packages import EuiccPackageDecodeError, decode_euicc_package_request
from SIMCARD.state import SimCardState
from SIMCARD.utils import (
    apdu_encoded_length,
    decode_imsi_ef,
    encode_iccid_ef,
    encode_imsi_ef,
    encode_length,
    parse_apdu,
    read_tlv,
    tlv,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_bytes,
    encode_decoded_roundtrip_oid,
    encode_decoded_roundtrip_scalar,
    roundtrip_capable_fields,
)
from Tools.ProfilePackage.saip_decoded_edit import (
    build_decoded_value_roundtrip_model,
    encode_decoded_value_editor_payload,
)
from yggdrasim_common.remote_lab import registry as remote_registry


def _state() -> SimCardState:
    return SimCardState(
        atr=b"",
        eid="89049032123451234512345678901235",
        iccid="8988000000000000001",
        imsi="001010000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )


@pytest.mark.parametrize(
    ("length", "expected"),
    [
        (0x7F, "7F"),
        (0x80, "8180"),
        (0xFF, "81FF"),
        (0x100, "820100"),
        (0xFFFF, "82FFFF"),
        (0x10000, "83010000"),
    ],
)
def test_ber_length_boundaries_are_minimal(length: int, expected: str) -> None:
    assert encode_length(length).hex().upper() == expected


def test_ber_length_roundtrips_across_large_boundaries() -> None:
    generator = random.Random(0xB3)
    lengths = [0, 1, 126, 127, 128, 255, 256, 65_535, 65_536]
    lengths.extend(generator.randrange(0, 100_000) for _ in range(32))
    for length in lengths:
        encoded = b"\x04" + encode_length(length) + bytes(length)
        tag, value, raw_tlv, next_offset = read_tlv(encoded, 0)
        assert tag == b"\x04"
        assert len(value) == length
        assert raw_tlv == encoded
        assert next_offset == len(encoded)


def test_identity_encoders_enforce_standard_sizes() -> None:
    assert len(encode_iccid_ef("8988000000000000001")) == 10
    assert len(encode_iccid_ef("8988000000000000001F")) == 10
    assert len(encode_iccid_ef("89880000000000000010")) == 10
    for invalid in ("", "123456789012345678", "123456789012345678901", "12A4567890123456789"):
        with pytest.raises(ValueError):
            encode_iccid_ef(invalid)

    imsi = "001010123456789"
    encoded_imsi = encode_imsi_ef(imsi)
    assert len(encoded_imsi) == 9
    assert encoded_imsi[0] == 8
    assert decode_imsi_ef(encoded_imsi) == imsi
    with pytest.raises(ValueError):
        encode_imsi_ef("0010101234567890")


@pytest.mark.parametrize(
    "malformed",
    [
        bytes.fromhex("A1"),
        bytes.fromhex("BF50"),
        bytes.fromhex("A1800000"),
        bytes.fromhex("A10000"),
        bytes.fromhex("A10180"),
        tlv("BF52", tlv(b"\x5C", bytes.fromhex("BF80"))),
    ],
)
def test_eim_parser_rejects_malformed_or_trailing_ber(malformed: bytes) -> None:
    parsed = eim_packages.parse_eim_package(malformed)
    assert parsed.package_type == eim_packages.TYPE_GENERIC
    assert parsed.root_tag == b""
    assert live_eim_packages.parse_eim_package is eim_packages.parse_eim_package


def test_eim_parser_never_leaks_index_errors_for_arbitrary_short_inputs() -> None:
    generator = random.Random(0xE1)
    for length in range(33):
        for _ in range(8):
            raw = bytes(generator.randrange(0, 256) for _ in range(length))
            parsed = eim_packages.parse_eim_package(raw)
            assert isinstance(parsed, eim_packages.ParsedEimPackage)


@pytest.mark.parametrize(
    "malformed",
    [
        bytes.fromhex("00A40000000001AAFF"),
        bytes.fromhex("00A40000000000FF"),
        bytes.fromhex("00A40000000001AA01"),
    ],
)
def test_extended_apdu_rejects_zero_lc_and_one_byte_le(malformed: bytes) -> None:
    with pytest.raises(ValueError):
        parse_apdu(malformed)
    with pytest.raises(ValueError):
        apdu_encoded_length(malformed)


def test_scp03_unwrap_rejects_protected_extended_case_2e() -> None:
    logic = Scp03CardLogic(_state())
    logic.state.scp03_session.authenticated = True
    logic._session_keys = {"s_mac": bytes(16), "s_enc": bytes(16), "s_rmac": bytes(16)}
    logic._authenticated_channel = 0
    logic._cmac = lambda _key, _payload: b"\xAA" * 16  # type: ignore[method-assign]
    protected = bytes.fromhex("84CA0000000008") + (b"\xAA" * 8) + bytes.fromhex("0000")

    plain, error = logic.unwrap_command(protected)

    assert plain is None
    assert error == (b"", 0x67, 0x00)
    assert logic.state.scp03_session.authenticated is False


def test_sgp32_request_rejects_bytes_after_outer_tlv() -> None:
    with pytest.raises(EuiccPackageDecodeError, match="Trailing bytes"):
        decode_euicc_package_request(bytes.fromhex("BF5100FF"))


def _issuer_and_crl(*, revoke_serial: int | None = None) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CRL Issuer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - datetime.timedelta(minutes=1))
        .next_update(now + datetime.timedelta(days=1))
    )
    if revoke_serial is not None:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(revoke_serial)
            .revocation_date(now - datetime.timedelta(seconds=1))
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(key, hashes.SHA256())
    return (
        certificate.public_bytes(serialization.Encoding.DER),
        crl.public_bytes(serialization.Encoding.DER),
    )


def test_load_crl_requires_valid_x509_signature_and_stores_canonical_der() -> None:
    certificate_der, crl_der = _issuer_and_crl()
    logic = SgpLogic(_state())
    logic._ci_certificate_der = certificate_der
    tag, crl_value, _raw, next_offset = read_tlv(crl_der, 0)
    assert tag == b"\x30" and next_offset == len(crl_der)
    request = tlv("BF35", tlv(b"\xA0", crl_value))

    response, sw1, sw2 = logic.handle_store_data(request)

    assert (sw1, sw2) == (0x90, 0x00)
    assert b"\x80\x01\x00" in response
    assert logic.state.loaded_crls == [crl_der]


def test_load_crl_accepts_explicit_certificate_list_wrapper() -> None:
    certificate_der, crl_der = _issuer_and_crl()
    logic = SgpLogic(_state())
    logic._ci_certificate_der = certificate_der

    response, _sw1, _sw2 = logic.handle_store_data(
        tlv("BF35", tlv(b"\xA0", crl_der))
    )

    assert b"\x80\x01\x00" in response
    assert logic.state.loaded_crls == [crl_der]


def test_load_crl_rejects_unparseable_inner_value() -> None:
    logic = SgpLogic(_state())
    response, _sw1, _sw2 = logic.handle_store_data(tlv("BF35", tlv(b"\xA0", b"\x00")))
    assert b"\x81\x01\x02" in response
    assert logic.state.loaded_crls == []


def _invite(token: str) -> dict:
    return {
        "schema": remote_registry.INVITE_SCHEMA,
        "device": {"id": "rig-a", "name": "Rig A"},
        "agent": {"host": "127.0.0.1", "control_port": 8700},
        "stream": {"transport": "http-card-bridge"},
        "auth": {"mode": "bearer", "token": token},
    }


def test_remote_lab_import_rolls_token_back_when_registry_publication_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    original = remote_registry.import_invite(_invite("original-token"))
    original_registry = Path(remote_registry.registry_path()).read_bytes()

    def fail_save(_devices: object) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(remote_registry, "save_registry", fail_save)
    with pytest.raises(OSError, match="publication failure"):
        remote_registry.import_invite(_invite("replacement-token"))

    assert Path(original.token_file).read_text(encoding="utf-8").strip() == "original-token"
    assert Path(remote_registry.registry_path()).read_bytes() == original_registry


def test_remote_lab_replacement_commits_new_token_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
    original = remote_registry.import_invite(_invite("original-token"))
    replacement = remote_registry.import_invite(_invite("replacement-token"))

    assert replacement.token_file != original.token_file
    assert not Path(original.token_file).exists()
    assert Path(replacement.token_file).read_text(encoding="utf-8").strip() == "replacement-token"
    assert remote_registry.load_registry()["rig-a"].token_file == replacement.token_file


def test_scp03_config_import_is_side_effect_free_and_init_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import SCP03.config as scp03_config

    with monkeypatch.context() as scoped:
        scoped.setenv("YGGDRASIM_RUNTIME_ROOT", str(tmp_path))
        importlib.reload(scp03_config)
        assert list(tmp_path.rglob("*")) == []
        scp03_config.Config.initialize_workspace()
        assert Path(scp03_config.Config.INI_FILE).is_file()
        assert Path(scp03_config.Config.FIDS_FILE).is_file()
    importlib.reload(scp03_config)


def test_saip_structural_field_registry_uses_real_asn1_types() -> None:
    fields = roundtrip_capable_fields()
    assert fields["shortEFID"] == "bytes"
    assert fields["templateID"] == "oid"
    assert encode_decoded_roundtrip_scalar("shortEFID", {"decimal": 7}) is None
    assert encode_decoded_roundtrip_scalar("templateID", {"decimal": 1}) is None
    assert encode_decoded_roundtrip_bytes("shortEFID", {"hex": "38"}) == b"\x38"
    assert (
        encode_decoded_roundtrip_oid("templateID", {"oid": "2.23.143.1.2.4"})
        == "2.23.143.1.2.4"
    )
    model = build_decoded_value_roundtrip_model(
        field_name="templateID",
        raw_value="2.23.143.1.2.4",
    )
    assert model is not None and model["payload"] == {"oid": "2.23.143.1.2.4"}
    assert (
        encode_decoded_value_editor_payload(
            field_name="templateID",
            editor_payload={"oid": "2.23.143.1.2.5"},
            editor_kind="roundtrip_decoded",
        )
        == "2.23.143.1.2.5"
    )
