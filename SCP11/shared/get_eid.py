# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ES10 GetEID: the request and the reading of its answer.

GSMA SGP.22 v3.1 §5.7.20 defines ES10c.GetEID as an ISD-R function the LPA
may use at any time, and SGP.32 v1.3 §5.9.19 gives the IPA the same function
as ES10b.GetEID. The request is a GetEuiccDataRequest 'BF3E' whose tag list
'5C' names the one tag '5A'; the answer is a GetEuiccDataResponse 'BF3E'
holding eidValue '5A', sixteen octets.
"""

from __future__ import annotations

from SCP11.shared.ber_tlv import read_ber_tlv, read_single_ber_tlv

GET_EID_REQUEST = bytes.fromhex("BF3E035C015A")
EID_OCTETS = 16


def eid_value(response: bytes) -> bytes:
    """Return the sixteen eidValue octets of a GetEID answer.

    Raises ValueError for an answer that does not decode, or that holds no
    '5A' of sixteen octets.
    """
    try:
        _tag, value, _raw = read_single_ber_tlv(response)
        offset = 0
        while offset < len(value):
            tag, item_value, _item_raw, offset = read_ber_tlv(value, offset)
            if tag == b"\x5A":
                if len(item_value) != EID_OCTETS:
                    raise ValueError(f"eidValue must be {EID_OCTETS} octets, got {len(item_value)}.")
                return bytes(item_value)
    except ValueError as error:
        raise ValueError(f"GetEID answer does not decode: {error}") from error
    raise ValueError("GetEID answer carries no EID '5A'.")
