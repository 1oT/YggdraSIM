# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""NotificationEvent decoding shared by the SCP11 notification consumers.

``profileManagementOperation`` in ``NotificationMetadata`` is a
``NotificationEvent`` BIT STRING carried under the implicit tag ``81``, so its
contents keep the BER value encoding: ITU-T X.690 (02/2021) clause 8.6.2.2
makes the initial octet the count of unused bits in the final octet, and
SGP.22 v3.1 section 5.7.9 allows exactly one bit to be set. Reading the
contents as an integer turns ``07 80`` (notificationInstall) into 1920, which
is why every consumer decodes through this module.
"""

from __future__ import annotations

from typing import Any


NOTIFICATION_OPERATION_BY_BIT = {
    0: (1, "install"),
    1: (2, "enable"),
    2: (3, "disable"),
    3: (4, "delete"),
    4: (5, "rpm-enable"),
    5: (6, "rpm-disable"),
    6: (7, "rpm-delete"),
    7: (8, "load-rpm-package-result"),
}

# The identifiers SGP.22 v3.1 section 5.7.9 gives the NotificationEvent bits.
# NOTIFICATION_OPERATION_BY_BIT above carries the short names the SCP11
# session summaries print; surfaces that echo the ASN.1 use these instead.
NOTIFICATION_EVENT_ASN1_NAME_BY_BIT: dict[int, str] = {
    0: "notificationInstall",
    1: "notificationLocalEnable",
    2: "notificationLocalDisable",
    3: "notificationLocalDelete",
    4: "notificationRpmEnable",
    5: "notificationRpmDisable",
    6: "notificationRpmDelete",
    7: "loadRpmPackageResult",
}


def decode_notification_operation_contents(value: bytes) -> tuple[int, str]:
    """Decode the contents octets of an implicitly tagged ``NotificationEvent``."""

    raw = bytes(value)
    if len(raw) < 2:
        raise ValueError(
            "profileManagementOperation BIT STRING must contain an unused-bit "
            "octet and event bits"
        )

    unused_bits = raw[0]
    event_bytes = raw[1:]
    if unused_bits > 7:
        raise ValueError(
            "profileManagementOperation BIT STRING unused-bit count must be 0..7"
        )
    if unused_bits and event_bytes[-1] & ((1 << unused_bits) - 1):
        raise ValueError(
            "profileManagementOperation BIT STRING has non-zero padding bits"
        )

    significant_bit_count = (len(event_bytes) * 8) - unused_bits
    set_bits = [
        bit_index
        for bit_index in range(significant_bit_count)
        if event_bytes[bit_index // 8] & (0x80 >> (bit_index % 8))
    ]
    if len(set_bits) != 1:
        raise ValueError(
            "profileManagementOperation in NotificationMetadata must set exactly one event bit"
        )

    bit_index = set_bits[0]
    operation = NOTIFICATION_OPERATION_BY_BIT.get(bit_index)
    if operation is None:
        raise ValueError(
            f"profileManagementOperation uses unsupported event bit {bit_index}"
        )
    if significant_bit_count != bit_index + 1:
        raise ValueError(
            "profileManagementOperation BIT STRING is not canonical "
            "(trailing zero event bits)"
        )
    return operation


def decode_notification_operation_decoded(value: Any) -> tuple[int, str]:
    """Normalise a decoded ASN.1 BIT STRING or its implicit TLV contents."""

    if isinstance(value, tuple) and len(value) == 2:
        event_bytes, significant_bit_count = value
        if not isinstance(event_bytes, (bytes, bytearray, memoryview)):
            raise ValueError(
                "decoded profileManagementOperation BIT STRING payload is not bytes"
            )
        if isinstance(significant_bit_count, bool) or not isinstance(
            significant_bit_count, int
        ):
            raise ValueError(
                "decoded profileManagementOperation BIT STRING length is not an integer"
            )
        raw_event_bytes = bytes(event_bytes)
        if significant_bit_count <= 0:
            raise ValueError(
                "profileManagementOperation in NotificationMetadata must set one event bit"
            )
        expected_octets = (significant_bit_count + 7) // 8
        if len(raw_event_bytes) != expected_octets:
            raise ValueError(
                "decoded profileManagementOperation BIT STRING length does not "
                "match its payload"
            )
        unused_bits = (expected_octets * 8) - significant_bit_count
        return decode_notification_operation_contents(
            bytes([unused_bits]) + raw_event_bytes
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        return decode_notification_operation_contents(bytes(value))
    raise ValueError(
        "profileManagementOperation is not a decoded ASN.1 BIT STRING"
    )


def record_notification_parse_error(details: dict, error: object) -> None:
    message = str(error).strip()
    if len(message) == 0:
        return
    existing = details.get("notificationParseError")
    if isinstance(existing, str) and len(existing) > 0:
        if message not in existing:
            details["notificationParseError"] = f"{existing}; {message}"
        return
    details["notificationParseError"] = message
