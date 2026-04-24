"""Regression guard for SGP.22 Annex M BPP segmentation.

Real eUICCs have been observed to misinterpret the first bare 86 TLV
(i.e. a ProtectedProfilePackage command member that arrives without its
owning A3 container header) as a terminal loadProfileElements result
and reply with a spurious ProfileInstallationResult indicating
completion. This leaves the SM-DP+ session pending ("profile in limbo")
because the eUICC never processed the remaining protected segments.

The v1 segmenter keeps the A0 ConfigureISDPRequest wrapped and emits
the A1 / A2 / A3 container headers as their own StoreData chains,
followed by each inner 86 / 88 TLV. This file locks that behaviour in
across every SGP.22 orchestrator copy in the tree so a future refactor
cannot silently strip the headers again.
"""

import unittest

from SCP11.live.orchestrator import SGP22Orchestrator as LiveOrchestrator
from SCP11.test.orchestrator import SGP22Orchestrator as TestOrchestrator
from SCP11.orchestrator import SGP22Orchestrator as MainOrchestrator
from SCP11.local_access.session import LocalIsdrSession

from tests.test_scp11_orchestrator import FakeApduChannel, FakeCfg, wrap_tlv


def _build_reference_bpp() -> bytes:
    bf23_body = wrap_tlv("80", b"\x10" * 16)
    bf23_tlv = wrap_tlv("BF23", bf23_body)
    a0_tlv = wrap_tlv("A0", wrap_tlv("87", b"\xAA\xBB"))
    a1_body = wrap_tlv("88", b"\x01" * 247) + wrap_tlv("89", b"\x02")
    a1_tlv = wrap_tlv("A1", a1_body)
    a3_body = wrap_tlv("86", b"\xCC\xDD") + wrap_tlv("86", b"\xEE\xFF")
    a3_tlv = wrap_tlv("A3", a3_body)
    return wrap_tlv("BF36", bf23_tlv + a0_tlv + a1_tlv + a3_tlv)


def _tag_of_segment(segment: bytes) -> bytes:
    if len(segment) == 0:
        return b""
    if (segment[0] & 0x1F) != 0x1F:
        return segment[:1]
    offset = 1
    while offset < len(segment) and (segment[offset] & 0x80) != 0:
        offset += 1
    if offset < len(segment):
        offset += 1
    return segment[:offset]


class SegmenterAnnexMComplianceTests(unittest.TestCase):
    def _assert_v1_pattern(self, segments: list) -> None:
        # Expected order per SGP.22 Annex M:
        #   1. BF36 bootstrap          (BF36-wrapped BF23)
        #   2. A0 ConfigureISDPRequest (full wrapped TLV)
        #   3. A1 container header     (header only, no body)
        #   4. 88 StoreMetadataRequest member
        #   5. 89 StoreMetadataRequest member
        #   6. A3 container header     (header only, no body)
        #   7. 86 ProtectedProfilePackage member
        #   8. 86 ProtectedProfilePackage member
        self.assertEqual(len(segments), 8)
        self.assertEqual(_tag_of_segment(segments[0]), b"\xBF\x36")
        self.assertEqual(_tag_of_segment(segments[1]), b"\xA0")
        self.assertEqual(_tag_of_segment(segments[2]), b"\xA1")
        self.assertEqual(_tag_of_segment(segments[3]), b"\x88")
        self.assertEqual(_tag_of_segment(segments[4]), b"\x89")
        self.assertEqual(_tag_of_segment(segments[5]), b"\xA3")
        self.assertEqual(_tag_of_segment(segments[6]), b"\x86")
        self.assertEqual(_tag_of_segment(segments[7]), b"\x86")

        # A0 must ship as an entire wrapped TLV, not the inner 87.
        self.assertEqual(segments[1], wrap_tlv("A0", wrap_tlv("87", b"\xAA\xBB")))

        # A1 / A3 headers must be emitted as their own segments with
        # bodies of length zero so the eUICC establishes the section
        # before the 86 / 88 members arrive.
        self.assertEqual(segments[2], bytes.fromhex("A181FD"))
        self.assertEqual(segments[5], bytes.fromhex("A30A"))

    def _make_main_orchestrator(self):
        return MainOrchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

    def _make_test_orchestrator(self):
        return TestOrchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

    def _make_live_orchestrator(self):
        return LiveOrchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None)

    def test_main_orchestrator_segmenter_matches_annex_m(self):
        orchestrator = self._make_main_orchestrator()
        segments = orchestrator._segment_bound_profile_package(_build_reference_bpp())
        self._assert_v1_pattern(segments)

    def test_test_orchestrator_segmenter_matches_annex_m(self):
        orchestrator = self._make_test_orchestrator()
        segments = orchestrator._segment_bound_profile_package(_build_reference_bpp())
        self._assert_v1_pattern(segments)

    def test_live_orchestrator_segmenter_matches_annex_m_by_default(self):
        orchestrator = self._make_live_orchestrator()
        self.assertTrue(orchestrator._bpp_install_uses_section_framing())
        segments = orchestrator._segment_bound_profile_package(_build_reference_bpp())
        self._assert_v1_pattern(segments)

    def test_local_isdr_session_segmenter_matches_annex_m(self):
        session = LocalIsdrSession(apdu_channel=FakeApduChannel())
        segments = session._segment_bound_profile_package(_build_reference_bpp())
        self._assert_v1_pattern(segments)

    def test_rejects_bpp_whose_first_child_is_not_bf23(self):
        malformed_bpp = wrap_tlv("BF36", wrap_tlv("A0", wrap_tlv("87", b"\x00")))
        orchestrator = self._make_main_orchestrator()
        with self.assertRaises(ValueError) as raised:
            orchestrator._segment_bound_profile_package(malformed_bpp)
        self.assertIn("Expected BF23 as first", str(raised.exception))

    def test_rejects_non_bf36_root(self):
        malformed_bpp = wrap_tlv("BF38", wrap_tlv("BF23", b"\x00"))
        orchestrator = self._make_main_orchestrator()
        with self.assertRaises(ValueError) as raised:
            orchestrator._segment_bound_profile_package(malformed_bpp)
        self.assertIn("Unexpected Bound Profile Package root tag", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
