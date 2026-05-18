# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for SCP11/pysim_support.py public functions.

All functions that depend on pySim return empty/None gracefully when pySim is
absent, which is the case in the standard test environment.  The tests that
do not require pySim (unwrap_tlv_octet_string, pysim_available) are exercised
fully; the remainder verify the no-pySim fallback paths.
"""

from __future__ import annotations

import unittest

from SCP11.pysim_support import (
    decode_authenticate_server_response,
    decode_initialise_secure_channel_request,
    decode_list_notification_response,
    decode_notification_metadata,
    decode_pending_notification,
    decode_prepare_download_response,
    decode_retrieve_notifications_list_response,
    encode_cancel_session_request,
    encode_ctx_params1,
    encode_notification_sent_request,
    encode_rsp_type,
    decode_rsp_type,
    encode_server_signed1,
    encode_smdp_signed2,
    pysim_available,
    pysim_rsp_asn1,
    unwrap_tlv_octet_string,
)


# ---------------------------------------------------------------------------
# pysim_available / pysim_rsp_asn1
# ---------------------------------------------------------------------------

class PysimAvailableTests(unittest.TestCase):

    def test_returns_bool(self) -> None:
        result = pysim_available()
        self.assertIsInstance(result, bool)

    def test_rsp_asn1_none_when_unavailable(self) -> None:
        if pysim_available():
            self.skipTest("pySim available in this environment")
        self.assertIsNone(pysim_rsp_asn1())


# ---------------------------------------------------------------------------
# encode_rsp_type / decode_rsp_type — no-pySim fallback
# ---------------------------------------------------------------------------

class RspTypeCodecTests(unittest.TestCase):

    def setUp(self) -> None:
        if pysim_available():
            self.skipTest("pySim available — fallback path not exercised")

    def test_encode_returns_empty_bytes(self) -> None:
        result = encode_rsp_type("AnyType", {})
        self.assertEqual(result, b"")

    def test_decode_returns_none(self) -> None:
        result = decode_rsp_type("AnyType", b"\x00\x01")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# unwrap_tlv_octet_string — does not require pySim
# ---------------------------------------------------------------------------

class UnwrapTlvOctetStringTests(unittest.TestCase):

    def test_matching_tag_short_form_unwraps(self) -> None:
        tag = bytes([0x04])
        payload = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        wrapped = tag + bytes([len(payload)]) + payload
        result = unwrap_tlv_octet_string(wrapped, tag)
        self.assertEqual(result, payload)

    def test_tag_mismatch_returns_original(self) -> None:
        data = bytes([0x04, 0x02, 0xAA, 0xBB])
        result = unwrap_tlv_octet_string(data, bytes([0x80]))
        self.assertEqual(result, data)

    def test_empty_value_returns_original(self) -> None:
        result = unwrap_tlv_octet_string(b"", bytes([0x04]))
        self.assertEqual(result, b"")

    def test_multi_byte_tag_unwraps(self) -> None:
        tag = bytes([0x5F, 0x37])
        payload = bytes([0x01, 0x02, 0x03])
        wrapped = tag + bytes([len(payload)]) + payload
        result = unwrap_tlv_octet_string(wrapped, tag)
        self.assertEqual(result, payload)

    def test_length_mismatch_returns_original(self) -> None:
        # Length byte claims 4 bytes but only 2 follow
        data = bytes([0x04, 0x04, 0xAA, 0xBB])
        result = unwrap_tlv_octet_string(data, bytes([0x04]))
        self.assertEqual(result, data)

    def test_long_form_length(self) -> None:
        tag = bytes([0x80])
        payload = bytes(range(130))
        length_bytes = bytes([0x81, len(payload)])
        wrapped = tag + length_bytes + payload
        result = unwrap_tlv_octet_string(wrapped, tag)
        self.assertEqual(result, payload)


# ---------------------------------------------------------------------------
# encode_* / decode_* — no-pySim fallback paths
# ---------------------------------------------------------------------------

class EncodeFallbackTests(unittest.TestCase):

    def setUp(self) -> None:
        if pysim_available():
            self.skipTest("pySim available — fallback path not exercised")

    def test_encode_server_signed1_returns_empty(self) -> None:
        result = encode_server_signed1(b"\x00" * 3, b"\x00" * 16, "smdp.example.test", b"\x00" * 16)
        self.assertEqual(result, b"")

    def test_encode_smdp_signed2_returns_empty(self) -> None:
        result = encode_smdp_signed2(b"\x00" * 3, False)
        self.assertEqual(result, b"")

    def test_encode_ctx_params1_returns_empty(self) -> None:
        result = encode_ctx_params1({})
        self.assertEqual(result, b"")

    def test_encode_cancel_session_returns_empty(self) -> None:
        result = encode_cancel_session_request(b"\x00" * 3, 0)
        self.assertEqual(result, b"")

    def test_encode_notification_sent_returns_empty(self) -> None:
        result = encode_notification_sent_request(1)
        self.assertEqual(result, b"")


class DecodeFallbackTests(unittest.TestCase):

    def setUp(self) -> None:
        if pysim_available():
            self.skipTest("pySim available — fallback path not exercised")

    def test_decode_authenticate_server_response_returns_none(self) -> None:
        self.assertIsNone(decode_authenticate_server_response(b"\x00\x01"))

    def test_decode_prepare_download_response_returns_none(self) -> None:
        self.assertIsNone(decode_prepare_download_response(b"\x00\x01"))

    def test_decode_initialise_secure_channel_returns_none(self) -> None:
        self.assertIsNone(decode_initialise_secure_channel_request(b"\x00\x01"))

    def test_decode_notification_metadata_returns_none(self) -> None:
        self.assertIsNone(decode_notification_metadata(b"\x00\x01"))

    def test_decode_pending_notification_returns_none(self) -> None:
        self.assertIsNone(decode_pending_notification(b"\x00\x01"))

    def test_decode_retrieve_notifications_list_returns_none(self) -> None:
        self.assertIsNone(decode_retrieve_notifications_list_response(b"\x00\x01"))

    def test_decode_list_notification_returns_none(self) -> None:
        self.assertIsNone(decode_list_notification_response(b"\x00\x01"))


if __name__ == "__main__":
    unittest.main()
