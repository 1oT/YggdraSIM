# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A eUICC that signs Notifications for the Local eIM tests, and a receiver that records what it is sent.

The eUICC here is a key pair with a self-made certificate: enough for the
Local eIM, which checks a Notification's signature under the certificate on
the eUICC's record and nothing else of the chain.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.notifications import Undelivered
from SCP11.shared.iccid import encode_ef_iccid

# NotificationEvent as BIT STRING contents, unused bits first: the bits are those of ES8+.StoreMetadata
# (SGP.22 v3.1 §5.5.3), and a NotificationMetadata sets exactly one (§5.7.9, ListNotification).
EVENTS = {"install": b"\x07\x80", "enable": b"\x06\x40", "disable": b"\x05\x20", "delete": b"\x04\x10"}
RECEIVER = "smdp.example.test"
OTHER_RECEIVER = "smdp2.example.test"
ICCID = "89881111111111111112"


def _certificate(key: ec.EllipticCurvePrivateKey, common_name: str, serial_number: str = "") -> bytes:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if serial_number:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number))
    name = x509.Name(attributes)
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class SigningEuicc:
    """A eUICC as far as Notifications go: an EID, a signing key, its certificate and an EUM certificate."""

    def __init__(self, eid: str = "89049032123451234512345678901243") -> None:
        self.eid = eid
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.certificate = _certificate(self.key, "Test eUICC", eid)
        self.eum_certificate = _certificate(ec.generate_private_key(ec.SECP256R1()), "Test EUM")

    def sign(self, data: bytes) -> bytes:
        """The raw r || s signature an eUICC puts in tag '5F37'."""
        r, s = decode_dss_signature(self.key.sign(bytes(data), ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def metadata(self, seq_number: int, event: str, address: str, iccid: str = ICCID) -> bytes:
        body = codec.integer_tlv(b"\x80", seq_number) + codec.tlv(b"\x81", EVENTS[event])
        body += codec.tlv(b"\x0C", address.encode("utf-8"))
        if iccid:
            body += codec.tlv(b"\x5A", encode_ef_iccid(iccid))
        return codec.tlv(b"\xBF\x2F", body)

    def other(self, seq_number: int, event: str = "enable", address: str = RECEIVER, iccid: str = ICCID) -> bytes:
        """An OtherSignedNotification (SGP.22 v3.1 §5.7.10) in its full form."""
        metadata = self.metadata(seq_number, event, address, iccid)
        return codec.tlv(b"\x30", metadata + codec.tlv(b"\x5F\x37", self.sign(metadata)) + self.certificate
                         + self.eum_certificate)

    def compact_other(self, seq_number: int, event: str = "enable", address: str = RECEIVER, *,
                      with_eid: bool = True) -> bytes:
        """A compactOtherSignedNotification (SGP.32 v1.3 §5.14.7): the same signature, no certificates."""
        metadata = self.metadata(seq_number, event, address)
        head = codec.tlv(b"\x5A", bytes.fromhex(self.eid)) if with_eid else b""
        return codec.tlv(b"\xA1", head + metadata + codec.tlv(b"\x5F\x37", self.sign(metadata)))

    def installation_result(self, seq_number: int, address: str = RECEIVER, iccid: str = ICCID, *,
                            transaction_id: bytes = bytes(range(16))) -> bytes:
        """A ProfileInstallationResult 'BF37' with a successResult, signed over its 'BF27' (SGP.22 v3.1 §2.5.6)."""
        final = codec.tlv(b"\xA0", codec.tlv(b"\x4F", bytes.fromhex("A0000005591010FFFFFFFF8900001100"))
                          + codec.tlv(b"\x04", bytes.fromhex("3007A00530038001" + "00")))
        data = codec.tlv(b"\xBF\x27", codec.tlv(b"\x80", bytes(transaction_id))
                         + self.metadata(seq_number, "install", address, iccid)
                         + codec.tlv(b"\x06", bytes.fromhex("2B0601040181FA69")) + codec.tlv(b"\xA2", final))
        return codec.tlv(b"\xBF\x37", data + codec.tlv(b"\x5F\x37", self.sign(data)))


class Receiver:
    """A sender for ``notifications.forward`` that records each call and fails the hosts it is told to."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []
        # host -> the Undelivered to raise for it, until removed.
        self.failing: dict[str, Undelivered] = {}

    def __call__(self, host: str, notification: bytes) -> None:
        self.calls.append((host, bytes(notification)))
        failure = self.failing.get(host)
        if failure is not None:
            raise Undelivered(str(failure), retry=failure.retry, expected=failure.expected)

    def fail(self, host: str, text: str = "connection refused", *, retry: bool = True) -> None:
        self.failing[host] = Undelivered(text, retry=retry)

    def recover(self, host: str) -> None:
        self.failing.pop(host, None)

    @property
    def hosts(self) -> list[str]:
        return [host for host, _data in self.calls]
