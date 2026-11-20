# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A test PKI and a scripted eUICC for the local SM-DS suites.

The SGP.26 bundle is not on a clean checkout, and under pytest the simulated
eUICC carries no EID in its certificate, so a test issues its own chain here:
an eSIM CA RootCA, a CERT.DSauth.SIG under it (Variant O role), an EUM
certificate with the name constraints of SGP.22 v3.1 Table 12 and a eUICC
certificate for the EID. ``ScriptedEuicc`` signs an AuthenticateServerResponse
with that eUICC key, with every member open to a test that wants it wrong.
"""

from __future__ import annotations

import base64
import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine.smds import AuthCredential, SmdsMaterial
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv
from SCP11.shared.esipa_download import tlv

# SGP.26 v3.0.2 section 3.2.1 Table 5 test EID, and a second one under the same EIN.
EID = "89049032123451234512345678901235"
OTHER_EID = "89049032123451234512345678901243"
EIN = "89049032"
# An EIN inside the same test range that the test EIDs do not start with.
OTHER_EIN = "8904903299"
EUM_ORGANIZATION = "RSP Test EUM"
SMDS_ADDRESS = "smds.example.test"
SMDP_ADDRESS = "smdpp.example.test"
# SGP.22 v3.1 section 2.4a.1.0: id-rspRole-ds-auth-v2 {id-rspRole 7}, the Variant O SM-DS role.
DS_AUTH_ROLE = "2.23.146.1.2.1.7"
SMDS_OID = "2.999.15"
NOW = datetime.datetime.now(datetime.timezone.utc)


def _name(common_name: str, *, organization: str = "YggdraSIM Test", serial_number: str = "") -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                  x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if serial_number:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    return x509.Name(attributes)


def _usage(*, sign: bool, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                         encipher_only=False, decipher_only=False)


def issue(
    subject: x509.Name,
    key: ec.EllipticCurvePrivateKey,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    *,
    ca: bool = False,
    extensions: tuple[tuple[Any, bool], ...] = (),
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> x509.Certificate:
    """One certificate: self-signed without *issuer*, a CA with *ca*; *extensions* are (value, critical) pairs."""
    builder = (
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer[0].subject if issuer is not None else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - datetime.timedelta(days=1))
        .not_valid_after(not_after or NOW + datetime.timedelta(days=30))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(_usage(sign=not ca, ca=ca), critical=True)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[0].public_key()), critical=False)
    for value, critical in extensions:
        builder = builder.add_extension(value, critical=critical)
    return builder.sign(issuer[1] if issuer is not None else key, hashes.SHA256())


def der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def key_identifier(certificate: x509.Certificate) -> bytes:
    return bytes(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)


def raw_signature(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    r_value, s_value = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")


def eum_constraints(organization: str = EUM_ORGANIZATION, ein: str = EIN) -> tuple[Any, bool]:
    """The nameConstraints of a Variant O CERT.EUM.SIG: the organization and the EIN as 'serialNumber'."""
    attributes = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)]
    if ein:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, ein))
    return (x509.NameConstraints(permitted_subtrees=[x509.DirectoryName(x509.Name(attributes))],
                                 excluded_subtrees=None), True)


class Pki:
    """An eSIM CA RootCA with a CERT.DSauth.SIG, an EUM certificate and a eUICC certificate under it."""

    def __init__(self, *, eid: str = EID) -> None:
        self.eid = eid
        self.ci_key = ec.generate_private_key(ec.SECP256R1())
        self.ci = issue(_name("Test CI"), self.ci_key, ca=True)
        self.ds_key = ec.generate_private_key(ec.SECP256R1())
        self.ds = issue(_name("Test SM-DS"), self.ds_key, (self.ci, self.ci_key), extensions=(
            (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(DS_AUTH_ROLE), None)]), True),
            (x509.SubjectAlternativeName([x509.RegisteredID(x509.ObjectIdentifier(SMDS_OID))]), False),
        ))
        self.eum_key = ec.generate_private_key(ec.SECP256R1())
        self.eum = self.eum_certificate()
        self.euicc_key = ec.generate_private_key(ec.SECP256R1())
        self.euicc = self.euicc_certificate()

    def eum_certificate(self, **options: Any) -> x509.Certificate:
        options.setdefault("extensions", (eum_constraints(),))
        return issue(_name("Test EUM", organization=EUM_ORGANIZATION), self.eum_key, (self.ci, self.ci_key),
                     ca=True, **options)

    def euicc_certificate(self, *, eid: str | None = None, organization: str = EUM_ORGANIZATION,
                          eum: x509.Certificate | None = None, **options: Any) -> x509.Certificate:
        subject = _name("Test eUICC", organization=organization, serial_number=self.eid if eid is None else eid)
        return issue(subject, self.euicc_key, (eum or self.eum, self.eum_key), **options)

    @property
    def ci_pkid(self) -> bytes:
        return key_identifier(self.ci)

    def material(self) -> SmdsMaterial:
        return SmdsMaterial(
            credentials=(AuthCredential(der(self.ds), self.ds_key, self.ci_pkid, "test CERT.DSauth"),),
            ci_certificates=(der(self.ci),),
        )

    def euicc_info1(self, *, verification: tuple[bytes, ...] | None = None,
                    signing: tuple[bytes, ...] | None = None, capability: bytes = b"") -> bytes:
        """EUICCInfo1 'BF20': lowestSvn '82', the two key identifier lists 'A9' and 'AA', euiccRspCapability '88'."""
        keys = (self.ci_pkid,)
        body = tlv(b"\x82", bytes.fromhex("020200"))
        body += tlv(b"\xA9", b"".join(tlv(b"\x04", item) for item in (keys if verification is None else verification)))
        body += tlv(b"\xAA", b"".join(tlv(b"\x04", item) for item in (keys if signing is None else signing)))
        if capability:
            body += tlv(b"\x88", capability)
        return tlv(b"\xBF\x20", body)


def _members(value: bytes) -> dict[bytes, bytes]:
    found: dict[bytes, bytes] = {}
    offset = 0
    while offset < len(value):
        tag, item, _raw, offset = read_ber_tlv(value, offset)
        found[tag] = bytes(item)
    return found


class ScriptedEuicc:
    """The eUICC side of the Common Mutual Authentication, signing with the test eUICC key."""

    def __init__(self, pki: Pki) -> None:
        self.pki = pki
        self.challenge = bytes(range(0x10, 0x20))

    def initiate(self, **overrides: Any) -> dict[str, Any]:
        """The input of ES11.InitiateAuthentication in the JSON shape, hex fields."""
        payload = {"euiccChallenge": self.challenge.hex(), "euiccInfo1": self.pki.euicc_info1().hex(),
                   "smdpAddress": SMDS_ADDRESS}
        payload.update(overrides)
        return payload

    def respond(
        self,
        answer: dict[str, Any],
        *,
        matching_id: str | None = None,
        operation_type: bytes | None = None,
        lpa_rsp_capability: bytes | None = None,
        euicc_rsp_capability: bytes | None = None,
        ctx_params1: bytes | None = None,
        transaction_id: bytes | None = None,
        server_challenge: bytes | None = None,
        certificates: tuple[bytes, ...] | None = None,
        other_certificates: tuple[bytes, ...] = (),
        signing_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> bytes:
        """AuthenticateServerResponse 'BF38' for the InitiateAuthentication *answer* (SGP.22 v3.1 section 5.7.13)."""
        signed1 = _members(read_single_ber_tlv(base64.b64decode(answer["serverSigned1"]))[1])
        if ctx_params1 is None:
            device_info = tlv(b"\x80", bytes.fromhex("35290611")) + tlv(b"\xA1", b"")
            if lpa_rsp_capability is not None:
                device_info += tlv(b"\x85", lpa_rsp_capability)
            common = tlv(b"\x80", matching_id.encode("utf-8")) if matching_id is not None else b""
            common += tlv(b"\xA1", device_info)
            if operation_type is not None:
                common += tlv(b"\x82", operation_type)
            ctx_params1 = tlv(b"\xA0", common)
        info2 = tlv(b"\x81", bytes.fromhex("020300"))
        if euicc_rsp_capability is not None:
            info2 += tlv(b"\x88", euicc_rsp_capability)
        euicc_signed1 = tlv(b"\x30", (
            tlv(b"\x80", signed1[b"\x80"] if transaction_id is None else transaction_id)
            + tlv(b"\x83", signed1[b"\x83"])
            + tlv(b"\x84", signed1[b"\x84"] if server_challenge is None else server_challenge)
            + tlv(b"\xBF\x22", info2) + ctx_params1
        ))
        chain = certificates if certificates is not None else (der(self.pki.euicc), der(self.pki.eum))
        body = euicc_signed1 + tlv(b"\x5F\x37", raw_signature(signing_key or self.pki.euicc_key, euicc_signed1))
        body += b"".join(chain)
        if other_certificates:
            body += tlv(b"\xA0", b"".join(other_certificates))
        return tlv(b"\xBF\x38", tlv(b"\xA0", body))
