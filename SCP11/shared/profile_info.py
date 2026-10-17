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

from typing import Optional

from SCP11.shared.ber_tlv import read_ber_tlv

TAG_PROFILE_INFO_LIST_RESPONSE = bytes.fromhex("BF2D")
TAG_PROFILE_INFO_LIST_OK = b"\xA0"
TAG_PROFILE_INFO_LIST_ERROR = b"\x81"
TAG_PROFILE_INFO = b"\xE3"


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
