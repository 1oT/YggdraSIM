# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ProfileInfoListResponse framing shared by the SCP11 profile list decoders.

SGP.22 v3.1 section 5.7.15: ``ProfileInfoListResponse ::= [45] CHOICE {
profileInfoListOk SEQUENCE OF ProfileInfo, profileInfoListError
ProfileInfoListError }``, so a ``BF2D`` response holds either ``A0`` with one
``E3`` ProfileInfo per Profile or ``81`` with an error code. Walking the TLVs
keeps a length octet that happens to be ``E3`` from being read as a Profile.
"""

from __future__ import annotations

from typing import Iterable, Optional

from SCP11.shared.ber_tlv import read_ber_tlv

TAG_PROFILE_INFO_LIST_RESPONSE = bytes.fromhex("BF2D")
TAG_PROFILE_INFO_LIST_OK = b"\xA0"
TAG_PROFILE_INFO_LIST_ERROR = b"\x81"
TAG_PROFILE_INFO = b"\xE3"

# SGP.32 v1.3 §4.4 (p.108): the ProfileInfo of an IoT eUICC, every member in
# definition order. SGP.32 v1.3 §5.9.14 makes ES10b.GetProfilesInfo the SGP.22
# function with this ProfileInfo, and the PSMO listProfileInfo is coded and
# processed as that function (SGP.32 v1.3 §2.11.1.1, p.35): these tags are the
# tagList that asks a v1.3 eUICC for everything it holds about a Profile, and
# profile_info_tag_list is the list for the version an eUICC declares.
PROFILE_INFO_MEMBERS: tuple[tuple[str, str], ...] = (
    ("5A", "iccid"),
    ("4F", "isdpAid"),
    ("9F70", "profileState"),
    ("90", "profileNickname"),
    ("91", "serviceProviderName"),
    ("92", "profileName"),
    ("93", "iconType"),
    ("94", "icon"),
    ("95", "profileClass"),
    ("B6", "notificationConfigurationInfo"),
    ("B7", "profileOwner"),
    ("B8", "dpProprietaryData"),
    ("99", "profilePolicyRules"),
    ("BF22", "serviceSpecificDataStoredInEuicc"),
    ("9F7B", "ecallIndication"),
    ("9F26", "fallbackAttribute"),
    ("9F67", "fallbackAllowed"),
    ("BF64", "iotSpecificProfileInfo"),
)

# SGP.22 v3.1 §5.7.15 (p.343) lists these tags too: they are members of the
# SGP.22 v3 ProfileInfo only, which SGP.32 v1.3 §4.4 replaces, so an
# IoT eUICC holds none of them and the full tagList leaves them out.
PROFILE_INFO_SGP22_V3_ONLY: dict[str, str] = {
    "BA": "rpmConfiguration",
    "9B": "hriServerAddress",
    "BC": "lprConfiguration",
    "BD": "enterpriseConfiguration",
    "9F1F": "serviceDescription",
    "BF20": "deviceChangeConfiguration",
    "9F24": "enabledOnEsimPort",
    "9F25": "profileSize",
}

PROFILE_INFO_ALL_TAGS = "".join(tag for tag, _name in PROFILE_INFO_MEMBERS)

SGP32_V1_2 = (1, 2, 0)
SGP32_V1_3 = (1, 3, 0)
# The SGP.32 version that added a member; one not named here is in SGP.32 v1.2 §4.4 (p.102-103)
# already, whose ProfileInfo ends at fallbackAllowed. iotSpecificProfileInfo came with SGP.32 v1.3
# §4.4 (p.108), and NOTE 2 there (p.109) leaves it empty in that version.
PROFILE_INFO_MEMBER_ADDED_IN: dict[str, tuple[int, int, int]] = {"BF64": SGP32_V1_3}


def profile_info_members(iot_versions: Iterable[tuple[int, ...]] = ()) -> tuple[tuple[str, str], ...]:
    """The ProfileInfo members of the newest SGP.32 version in *iot_versions*, in definition order.

    *iot_versions* is what an eUICC declares in EUICCInfo2 (iotVersion, SGP.32
    v1.3 §5.9.2). None at all, or only versions before v1.2, reads as v1.2:
    the member a later version adds is one an eUICC of an earlier version does
    not define, and a card of v1.2 answered the list of v1.3 with
    incorrectInputValues.
    """
    newest = max((tuple(version) for version in iot_versions), default=SGP32_V1_2)
    return tuple(
        (tag, name) for tag, name in PROFILE_INFO_MEMBERS
        if PROFILE_INFO_MEMBER_ADDED_IN.get(tag, SGP32_V1_2) <= max(newest, SGP32_V1_2)
    )


def profile_info_tag_list(iot_versions: Iterable[tuple[int, ...]] = ()) -> str:
    """The tagList hex that names every ProfileInfo member of the version an eUICC declares."""
    return "".join(tag for tag, _name in profile_info_members(iot_versions))


def _iter_tlvs(data: bytes):
    offset = 0
    while offset < len(data):
        try:
            tag, value, _raw, offset = read_ber_tlv(data, offset)
        except ValueError:
            return
        yield tag, value


def split_profile_info_list(raw: bytes) -> tuple[list[bytes], Optional[int]]:
    """Return the ProfileInfo values of a response and its error code, if any.

    Accepts the complete ``BF2D`` response, the ``profileInfoListOk`` value on
    its own, or a bare run of ``E3`` TLVs. A truncated trailer ends the walk
    with what was collected so far.
    """
    data = bytes(raw or b"")
    if len(data) == 0:
        return [], None
    try:
        tag, value, _raw, end = read_ber_tlv(data, 0)
    except ValueError:
        return [], None
    if tag == TAG_PROFILE_INFO_LIST_RESPONSE and end == len(data):
        data = value
    profiles: list[bytes] = []
    error_code: Optional[int] = None
    for tag, value in _iter_tlvs(data):
        if tag == TAG_PROFILE_INFO_LIST_OK:
            for inner_tag, inner_value in _iter_tlvs(value):
                if inner_tag == TAG_PROFILE_INFO:
                    profiles.append(inner_value)
                elif inner_tag == b"\x30":
                    # Earlier simulator releases wrapped the SEQUENCE OF a
                    # second time; read the entries it holds.
                    for nested_tag, nested_value in _iter_tlvs(inner_value):
                        if nested_tag == TAG_PROFILE_INFO:
                            profiles.append(nested_value)
        elif tag == TAG_PROFILE_INFO_LIST_ERROR and len(value) > 0:
            error_code = int.from_bytes(value, "big", signed=False)
        elif tag == TAG_PROFILE_INFO:
            profiles.append(value)
    return profiles, error_code
