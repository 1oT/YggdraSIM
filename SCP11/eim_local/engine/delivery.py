# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Direct delivery: the Local eIM as its own IPAd over a card reader.

The engine serves the next operation of the card's EID. A signed eUICC Package
goes to the ISD-R as ES10b.LoadEuiccPackage (SGP.32 v1.3 §5.9.1) and its result
comes straight back, with the pending Notifications when the package held
PSMOs (§3.3.1 step 9, p.73). An IpaEuiccDataRequest is answered from the card
itself: GetCerts, EUICCInfo1/2, the configured SM-DP+ and SM-DS addresses, the
eIM configuration, stored results and Notifications. What the engine
acknowledges is removed with RemoveNotificationFromList (§3.3.1 steps 15-16,
p.74). A profile download trigger stays queued for a route that runs downloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from SCP11.eim_local.engine import codec
from SCP11.eim_local.engine.catalogue import PACKAGE_DOWNLOAD, device_refresh_flag
from SCP11.eim_local.engine.service import ROUTE_DIRECT, LocalEim
from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv, retag_sequence
from SCP11.shared.get_eid import GET_EID_REQUEST, eid_value

Exchange = Callable[[bytes, str], bytes]

EUICC_INFO1_REQUEST = bytes.fromhex("BF2000")
EUICC_INFO2_REQUEST = bytes.fromhex("BF2200")
CONFIGURED_ADDRESSES_REQUEST = bytes.fromhex("BF3C00")
EIM_CONFIGURATION_REQUEST = bytes.fromhex("BF5500")
DEFAULT_MAX_PACKAGES = 32


class DeliveryError(RuntimeError):
    """The card did not answer a delivery step the way SGP.32 describes."""


@dataclass
class DeliveryStep:
    operation_id: int | None
    description: str
    package_hex: str = ""
    response_hex: str = ""
    messages: list[str] = field(default_factory=list)
    acknowledged: list[int] = field(default_factory=list)


def read_eid(exchange: Exchange) -> str:
    """ES10b GetEID: 'BF3E' { tagList '5C' '5A' } answered by 'BF3E' { '5A' eid }."""
    response = exchange(GET_EID_REQUEST, "EIM-LOCAL: GetEID")
    try:
        return codec.eid_from_bytes(eid_value(response))
    except ValueError as error:
        raise DeliveryError(str(error)) from error


def _configured_addresses(exchange: Exchange) -> tuple[str | None, str | None]:
    """EuiccConfiguredData 'BF3C': defaultDpAddress '80', rootDsAddress '81'."""
    try:
        _tag, value, _raw = read_single_ber_tlv(exchange(CONFIGURED_ADDRESSES_REQUEST, "EIM-LOCAL: EuiccConfiguredData"))
    except ValueError:
        return None, None
    default_dp = None
    root_ds = None
    offset = 0
    while offset < len(value):
        try:
            tag, item_value, _raw_item, offset = read_ber_tlv(value, offset)
        except ValueError:
            break
        if tag == b"\x80":
            default_dp = item_value.decode("utf-8", errors="replace")
        elif tag == b"\x81":
            root_ds = item_value.decode("utf-8", errors="replace")
    return default_dp, root_ds


def read_eim_configuration(exchange: Exchange) -> list[dict[str, object]]:
    """GetEimConfigurationData 'BF55' { 'A0' { EimConfigurationData ... } } as eimId, counter, token."""
    entries: list[dict[str, object]] = []
    try:
        _tag, value, _raw = read_single_ber_tlv(exchange(EIM_CONFIGURATION_REQUEST, "EIM-LOCAL: GetEimConfigurationData"))
        _list_tag, rows, _list_raw = read_single_ber_tlv(value)
    except ValueError:
        return entries
    offset = 0
    while offset < len(rows):
        try:
            _row_tag, row, _row_raw, offset = read_ber_tlv(rows, offset)
        except ValueError:
            break
        entry: dict[str, object] = {}
        inner = 0
        while inner < len(row):
            try:
                tag, item_value, _item_raw, inner = read_ber_tlv(row, inner)
            except ValueError:
                break
            if tag == b"\x80":
                entry["eim_id"] = item_value.decode("utf-8", errors="replace")
            elif tag == b"\x81":
                entry["eim_fqdn"] = item_value.decode("utf-8", errors="replace")
            elif tag == b"\x82":
                entry["eim_id_type"] = codec.EIM_ID_TYPE_NAMES.get(int.from_bytes(item_value, "big"), "")
            elif tag == b"\x83":
                entry["counter_value"] = int.from_bytes(item_value, "big", signed=True)
            elif tag == b"\x84":
                entry["association_token"] = int.from_bytes(item_value, "big", signed=True)
        entries.append(entry)
    return entries


def read_certificates(exchange: Exchange, euicc_ci_pkid: bytes = b"") -> tuple[bytes, bytes]:
    return codec.decode_get_certs_response(exchange(codec.build_get_certs_request(euicc_ci_pkid), "EIM-LOCAL: GetCerts"))


def read_profiles(exchange: Exchange) -> list[dict[str, object]]:
    """ES10b GetProfilesInfo 'BF2D' with the SGP.32 default tags plus the fallback ones."""
    request = codec.tlv(b"\xBF\x2D", codec.tlv(b"\x5C", bytes.fromhex("5A4F9F70909192959F269F67")))
    try:
        _tag, value, _raw = read_single_ber_tlv(exchange(request, "EIM-LOCAL: GetProfilesInfo"))
        choice_tag, profiles, _choice_raw = read_single_ber_tlv(value)
    except ValueError as error:
        raise DeliveryError(f"GetProfilesInfo answer does not decode: {error}") from error
    if choice_tag != b"\xA0":
        raise DeliveryError(f"GetProfilesInfo answered alternative {choice_tag.hex().upper()}, not profileInfoListOk.")
    return codec.decode_profile_info_list(profiles)


def read_signing_ci_pkids(exchange: Exchange) -> list[bytes]:
    """euiccCiPKIdListForSigning of EUICCInfo1 (SGP.32 v1.3 §5.9.4: the first is the euiccCiPKId when none is given)."""
    answer = exchange(codec.tlv(b"\xBF\x20", b""), "EIM-LOCAL: GetEUICCInfo1")
    try:
        _tag, value, _raw = read_single_ber_tlv(answer)
    except ValueError as error:
        raise DeliveryError(f"GetEUICCInfo1 answer does not decode: {error}") from error
    pkids: list[bytes] = []
    offset = 0
    while offset < len(value):
        tag, item, _item_raw, offset = read_ber_tlv(value, offset)
        if tag != b"\xAA":
            continue
        inner = 0
        while inner < len(item):
            pkid_tag, pkid, _pkid_raw, inner = read_ber_tlv(item, inner)
            if pkid_tag == b"\x04":
                pkids.append(bytes(pkid))
    return pkids


def read_card(exchange: Exchange) -> dict[str, object]:
    """Everything the eUICC record holds that the card can tell directly."""
    reads: dict[str, object] = {"eid": read_eid(exchange)}
    eum, euicc = read_certificates(exchange)
    reads["eum_certificate"] = eum
    reads["euicc_certificate"] = euicc
    reads["profiles"] = read_profiles(exchange)
    reads["eims"] = read_eim_configuration(exchange)
    default_dp, root_ds = _configured_addresses(exchange)
    if default_dp is not None:
        reads["default_smdp_address"] = default_dp
    if root_ds is not None:
        reads["root_smds_address"] = root_ds
    return reads


def _ipa_request(package: bytes) -> dict[str, object]:
    _tag, value, _raw = read_single_ber_tlv(package)
    request: dict[str, object] = {"tags": b"", "ci": b"", "notification_seq": None, "result_seq": None, "txid": b""}
    offset = 0
    while offset < len(value):
        tag, item_value, _item_raw, offset = read_ber_tlv(value, offset)
        if tag == b"\x5C":
            request["tags"] = bytes(item_value)
        elif tag == b"\x04":
            request["ci"] = bytes(item_value)
        elif tag in (b"\xA1", b"\xA2"):
            inner_tag, inner_value, _inner_raw = read_single_ber_tlv(item_value)
            if inner_tag == b"\x80":
                request["notification_seq" if tag == b"\xA1" else "result_seq"] = int.from_bytes(inner_value, "big")
        elif tag == b"\x83":
            request["txid"] = bytes(item_value)
    return request


def _requested_tags(tag_list: bytes) -> set[str]:
    tags: set[str] = set()
    offset = 0
    while offset < len(tag_list):
        first = tag_list[offset]
        width = 2 if first & 0x1F == 0x1F else 1
        tags.add(tag_list[offset:offset + width].hex().upper())
        offset += width
    return tags


def answer_ipa_euicc_data_request(exchange: Exchange, package: bytes, eim_id: str) -> bytes:
    """Build the IpaEuiccDataResponse 'BF52' an IPAd would return, from card reads (§2.11.2.2).

    Members go in definition order; the two certificates carry their contents
    under the implicit '[5]' / '[6]' tags. IPA capabilities and device
    information are left out: the direct route has no device to describe.
    """
    request = _ipa_request(package)
    tags = _requested_tags(bytes(request["tags"]))
    body = b""
    if "A0" in tags:
        seq = request["notification_seq"]
        notifications = codec.decode_notification_list(
            exchange(codec.build_retrieve_notifications_request(seq if isinstance(seq, int) else None),
                     "EIM-LOCAL: RetrieveNotificationsList")
        )
        body += codec.tlv(b"\xA0", b"".join(notifications))
    default_dp, root_ds = (None, None)
    if "81" in tags or "83" in tags:
        default_dp, root_ds = _configured_addresses(exchange)
    if "81" in tags and default_dp is not None:
        body += codec.tlv(b"\x81", default_dp.encode("utf-8"))
    if "A2" in tags:
        results = codec.decode_package_result_list(
            exchange(codec.build_retrieve_package_results_request(), "EIM-LOCAL: RetrieveNotificationsList (results)")
        )
        wanted = request["result_seq"]
        if isinstance(wanted, int):
            results = [raw for raw in results if codec.decode_euicc_package_result(raw).seq_number == wanted]
        body += codec.tlv(b"\xA2", b"".join(results))
    if "BF20" in tags:
        body += exchange(EUICC_INFO1_REQUEST, "EIM-LOCAL: GetEUICCInfo1")
    if "BF22" in tags:
        body += exchange(EUICC_INFO2_REQUEST, "EIM-LOCAL: GetEUICCInfo2")
    if "83" in tags and root_ds is not None:
        body += codec.tlv(b"\x83", root_ds.encode("utf-8"))
    if "84" in tags:
        for entry in read_eim_configuration(exchange):
            if entry.get("eim_id") == eim_id and entry.get("association_token") is not None:
                body += codec.integer_tlv(b"\x84", int(entry["association_token"]))
                break
    if "A5" in tags or "A6" in tags:
        eum, euicc = read_certificates(exchange, bytes(request["ci"]))
        if "A5" in tags and eum:
            body += retag_sequence(b"\xA5", eum)
        if "A6" in tags:
            body += retag_sequence(b"\xA6", euicc)
    if len(bytes(request["txid"])) > 0:
        body += codec.tlv(b"\x87", bytes(request["txid"]))
    return codec.tlv(codec.TAG_IPA_EUICC_DATA, codec.tlv(b"\xA0", body))


def deliver(
    engine: LocalEim,
    exchange: Exchange,
    eid: str = "",
    *,
    once: bool = False,
    max_packages: int = DEFAULT_MAX_PACKAGES,
    emit: Callable[[str], None] | None = None,
    reset: Callable[[], bool] | None = None,
) -> list[DeliveryStep]:
    """Serve and execute the queued operations of the card behind *exchange* until none is left.

    *reset* resets the card behind *exchange* and says whether it did. After a
    package that enables or disables a Profile it completes the state change
    before the pending Notifications are read: the eUICC generates them upon
    the Terminal Response to its REFRESH or after the RESET (SGP.32 v1.3 §3.3.1
    steps 8a-8b, p.72-73), and a reader session gives it no proactive session
    for the REFRESH. Without one they arrive with a later package.
    """
    say = emit or (lambda _line: None)
    card_eid = codec.normalize_eid(eid) if eid else read_eid(exchange)
    record = engine.record(card_eid) or engine.register(card_eid)
    if len(record.euicc_certificate) == 0:
        eum, euicc = read_certificates(exchange)
        engine.apply_card_reads(card_eid, {"eum_certificate": eum, "euicc_certificate": euicc})
        say(f"[*] {card_eid}: eUICC certificate read with GetCerts")
    identity = engine.identity()
    steps: list[DeliveryStep] = []
    while len(steps) < max_packages:
        served = engine.next_package(card_eid, route=ROUTE_DIRECT, refuse_packages=(PACKAGE_DOWNLOAD,))
        if served.error is not None:
            name = codec.EIM_PACKAGE_ERRORS.get(served.error, str(served.error))
            if served.operation is not None and served.blocked:
                say(f"[!] operation {served.operation.id} is a profile download; serve it over ESipa "
                    "(SERVE, then an IPAe terminal or the eSIM Live console)")
            elif served.operation is not None:
                say(f"[!] operation {served.operation.id}: {served.operation.error or name}")
            else:
                say(f"[*] {card_eid}: {name}")
            break
        operation = served.operation
        package = served.package
        step = DeliveryStep(
            operation_id=operation.id if operation is not None else None,
            description=operation.type if operation is not None else "",
            package_hex=package.hex().upper(),
        )
        if package.startswith(codec.TAG_EUICC_PACKAGE):
            answer = exchange(package, "EIM-LOCAL: LoadEuiccPackage")
            result = answer
            if operation is not None and reset is not None and codec.changes_profile_state(package):
                if reset():
                    say("[*] card reset to complete the Profile state change (SGP.32 v1.3 §3.3.1 step 8b)")
            if operation is not None and codec.holds_psmos(package):
                notifications = codec.decode_notification_list(
                    exchange(codec.build_retrieve_notifications_request(), "EIM-LOCAL: RetrieveNotificationsList")
                )
                if notifications:
                    result = codec.tlv(b"\x30", answer + codec.tlv(b"\xA0", b"".join(notifications)))
        elif package.startswith(codec.TAG_IPA_EUICC_DATA):
            result = answer_ipa_euicc_data_request(exchange, package, identity.eim_id)
        elif package[:2] in codec.DEVICE_FUNCTIONS and operation is not None:
            # A device-side function (SGP.32 v1.3 §5.9.16, §5.9.20, §5.9.21): the reader is the IoT Device, so
            # it runs here and the operation closes with the eUICC's answer. A successful switch is completed
            # by a reset, as a Profile state change in a package is.
            name = codec.DEVICE_FUNCTIONS[package[:2]][0]
            answer = exchange(package, f"EIM-LOCAL: {name}")
            decoded = codec.decode_device_response(package[:2], answer)
            engine.complete_device_function(operation.id, decoded, answer)
            step.response_hex = answer.hex().upper()
            step.messages.append(f"{name}: {decoded.text} ({decoded.code})")
            if decoded.ok and reset is not None and device_refresh_flag(operation.params) and reset():
                say(f"[*] card reset to complete the Profile switch of {name}")
            if len(decoded.euicc_package_result) == 0:
                for message in step.messages:
                    say(f"[+] {message}")
                steps.append(step)
                if once:
                    break
                continue
            # ProfileRollback hands back the eUICC Package Result that replaces the enable's (§3.3.2); the
            # Notifications of the switch travel with it as they do after a PSMO package.
            result = decoded.euicc_package_result
            notifications = codec.decode_notification_list(
                exchange(codec.build_retrieve_notifications_request(), "EIM-LOCAL: RetrieveNotificationsList")
            )
            if notifications:
                result = codec.tlv(b"\x30", result + codec.tlv(b"\xA0", b"".join(notifications)))
        else:
            raise DeliveryError(f"The direct route got package tag {package[:2].hex().upper()} it does not run.")
        step.response_hex = step.response_hex or result.hex().upper()
        accepted = engine.accept_result(card_eid, result, route=ROUTE_DIRECT)
        step.messages = [*step.messages, *accepted.messages]
        for seq_number in accepted.acknowledgements:
            removal = exchange(codec.build_notification_sent(seq_number), "EIM-LOCAL: RemoveNotificationFromList")
            step.acknowledged.append(seq_number)
            if removal[-1:] not in (b"\x00",):
                step.messages.append(f"RemoveNotificationFromList {seq_number} answered {removal.hex().upper()}")
        for message in step.messages:
            say(f"[+] {message}")
        steps.append(step)
        if once:
            break
    return steps


