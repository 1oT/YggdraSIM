# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Conformance vectors for SGP.22 Annex M BPP segmentation.

Real eUICCs have been observed to misinterpret the first bare 86 TLV
(i.e. a ProtectedProfilePackage command member that arrives without its
owning A3 container header) as a terminal loadProfileElements result
and reply with a spurious ProfileInstallationResult indicating
completion. This leaves the SM-DP+ session pending ("profile in limbo")
because the eUICC never processed the remaining protected segments.

The v1 segmenter keeps the A0 ConfigureISDPRequest wrapped and emits
the A1 / A2 / A3 container headers as their own StoreData chains,
followed by each inner 86 / 88 TLV.

The tree carries more than one segmenter. Rather than assert against
each by hand -- which let the live copy drift once already -- every
implementation is run over one shared vector table, and an AST sweep
fails when a new copy appears that the table does not cover.
"""

import ast
import unittest
from pathlib import Path

from SCP11.live.orchestrator import SGP22Orchestrator as LiveOrchestrator
from SCP11.test.orchestrator import SGP22Orchestrator as CompatibilityOrchestrator
from SCP11.orchestrator import SGP22Orchestrator as MainOrchestrator
from SCP11.local_access.session import LocalIsdrSession

from tests.test_scp11_orchestrator import FakeApduChannel, FakeCfg, wrap_tlv


REPO_ROOT = Path(__file__).resolve().parents[1]
SEGMENTER_METHOD = "_segment_bound_profile_package"

_BF23 = wrap_tlv("BF23", wrap_tlv("80", b"\x10" * 16))


def _bpp(body: bytes) -> bytes:
    return wrap_tlv("BF36", body)


# (label, BPP, expected ES10b segments in order).
#
# Container headers are spelled as explicit hex because that is where the
# wire risk lives: ``A181FD`` is the long-form length for a 253-octet A1
# body, and an implementation that reframes it is exactly the bug this
# table exists to catch. Bulky members stay constructed for readability.
_VECTORS: tuple[tuple[str, bytes, tuple[bytes, ...]], ...] = (
    (
        # The canonical Annex M shape: wrapped A0, then header-then-members
        # for A1 and A3.
        "reference",
        _bpp(
            _BF23
            + wrap_tlv("A0", wrap_tlv("87", b"\xAA\xBB"))
            + wrap_tlv("A1", wrap_tlv("88", b"\x01" * 247) + wrap_tlv("89", b"\x02"))
            + wrap_tlv("A3", wrap_tlv("86", b"\xCC\xDD") + wrap_tlv("86", b"\xEE\xFF"))
        ),
        (
            bytes.fromhex("BF36820125") + _BF23,
            bytes.fromhex("A0048702AABB"),
            bytes.fromhex("A181FD"),
            wrap_tlv("88", b"\x01" * 247),
            bytes.fromhex("890102"),
            bytes.fromhex("A308"),
            bytes.fromhex("8602CCDD"),
            bytes.fromhex("8602EEFF"),
        ),
    ),
    (
        # A2 takes the same header-then-members treatment as A1 and A3.
        "a2_container",
        _bpp(_BF23 + wrap_tlv("A0", wrap_tlv("87", b"\xAA")) + wrap_tlv("A2", wrap_tlv("88", b"\x07\x08"))),
        (
            bytes.fromhex("BF3620") + _BF23,
            bytes.fromhex("A0038701AA"),
            bytes.fromhex("A204"),
            bytes.fromhex("88020708"),
        ),
    ),
    (
        # An empty container still ships its header. The live segmenter used
        # to drop it, which is how the four copies were found to disagree.
        "empty_a1",
        _bpp(_BF23 + wrap_tlv("A0", wrap_tlv("87", b"\xAA")) + wrap_tlv("A1", b"")),
        (
            bytes.fromhex("BF361C") + _BF23,
            bytes.fromhex("A0038701AA"),
            bytes.fromhex("A100"),
        ),
    ),
    (
        "empty_a0",
        _bpp(_BF23 + wrap_tlv("A0", b"") + wrap_tlv("A1", wrap_tlv("88", b"\x01" * 8))),
        (
            bytes.fromhex("BF3623") + _BF23,
            bytes.fromhex("A000"),
            bytes.fromhex("A10A"),
            bytes.fromhex("88080101010101010101"),
        ),
    ),
    (
        "bootstrap_only",
        _bpp(_BF23),
        (bytes.fromhex("BF3615") + _BF23,),
    ),
    (
        # Five protected members under one A3, so member splitting is
        # exercised beyond the two-member reference case.
        "multi_member_a3",
        _bpp(_BF23 + wrap_tlv("A3", b"".join(wrap_tlv("86", bytes([i]) * 4) for i in range(5)))),
        (
            bytes.fromhex("BF3635") + _BF23,
            bytes.fromhex("A31E"),
            bytes.fromhex("860400000000"),
            bytes.fromhex("860401010101"),
            bytes.fromhex("860402020202"),
            bytes.fromhex("860403030303"),
            bytes.fromhex("860404040404"),
        ),
    ),
)

# (label, BPP, substring the raised ValueError must carry).
_REJECT_VECTORS: tuple[tuple[str, bytes, str], ...] = (
    ("empty_input", b"", "Bound Profile Package is empty"),
    (
        "non_bf36_root",
        wrap_tlv("BF38", wrap_tlv("BF23", b"\x00")),
        "Unexpected Bound Profile Package root tag",
    ),
    (
        "first_child_not_bf23",
        _bpp(wrap_tlv("A0", wrap_tlv("87", b"\x00"))),
        "Expected BF23 as first",
    ),
    (
        "unexpected_child_tag",
        _bpp(_BF23 + wrap_tlv("A5", b"\x00")),
        "Unexpected Bound Profile Package child tag",
    ),
)


def _segmenters() -> tuple[tuple[str, object], ...]:
    """Every segmenter entry point, including inheriting shims."""

    return (
        (
            "SCP11.orchestrator",
            MainOrchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None),
        ),
        (
            "SCP11.live.orchestrator",
            LiveOrchestrator(cfg=FakeCfg(), apdu_channel=FakeApduChannel(), profile_provider=None),
        ),
        (
            "SCP11.test.orchestrator",
            CompatibilityOrchestrator(
                cfg=FakeCfg(),
                apdu_channel=FakeApduChannel(),
                profile_provider=None,
            ),
        ),
        ("SCP11.local_access.session", LocalIsdrSession(apdu_channel=FakeApduChannel())),
    )


# Modules that literally define the method. A shim that inherits it is an
# entry point but not a copy, so it does not belong here.
_DEFINING_MODULES = {
    "SCP11/orchestrator.py",
    "SCP11/live/orchestrator.py",
    "SCP11/local_access/session.py",
}


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


class SegmenterConformanceTests(unittest.TestCase):
    def test_every_segmenter_matches_every_vector(self):
        for label, segmenter in _segmenters():
            for name, package, expected in _VECTORS:
                with self.subTest(segmenter=label, vector=name):
                    self.assertEqual(
                        segmenter._segment_bound_profile_package(package),
                        list(expected),
                    )

    def test_every_segmenter_rejects_every_malformed_vector(self):
        for label, segmenter in _segmenters():
            for name, package, message in _REJECT_VECTORS:
                with self.subTest(segmenter=label, vector=name):
                    with self.assertRaises(ValueError) as raised:
                        segmenter._segment_bound_profile_package(package)
                    self.assertIn(message, str(raised.exception))

    def test_vector_table_covers_every_segmenter_definition_in_the_tree(self):
        """A new segmenter copy must join the table, not drift beside it."""

        found: set[str] = set()
        for path in sorted((REPO_ROOT / "SCP11").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == SEGMENTER_METHOD:
                    found.add(path.relative_to(REPO_ROOT).as_posix())
        self.assertEqual(
            found,
            _DEFINING_MODULES,
            "a BPP segmenter was added or moved; add it to _segmenters() and to "
            "_DEFINING_MODULES so the conformance vectors cover it",
        )


class ReferenceVectorShapeTests(unittest.TestCase):
    """Why the reference vector looks the way it does, per SGP.22 Annex M."""

    def setUp(self) -> None:
        self.segments = MainOrchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=None,
        )._segment_bound_profile_package(_VECTORS[0][1])

    def test_segment_order_is_bootstrap_then_section_framed_members(self):
        self.assertEqual(
            [_tag_of_segment(segment) for segment in self.segments],
            [
                b"\xBF\x36",
                b"\xA0",
                b"\xA1",
                b"\x88",
                b"\x89",
                b"\xA3",
                b"\x86",
                b"\x86",
            ],
        )

    def test_a0_ships_as_a_whole_wrapped_tlv(self):
        self.assertEqual(self.segments[1], wrap_tlv("A0", wrap_tlv("87", b"\xAA\xBB")))

    def test_container_headers_advertise_the_original_der_body_length(self):
        # A1 body = 88-TLV (250) + 89-TLV (3) = 253 octets => A1 81 FD.
        # A3 body = 86-TLV (4) + 86-TLV (4)   = 8 octets   => A3 08.
        self.assertEqual(self.segments[2], bytes.fromhex("A181FD"))
        self.assertEqual(self.segments[5], bytes.fromhex("A308"))


class LiveFramingOptOutTests(unittest.TestCase):
    def test_live_defaults_to_section_framing(self):
        orchestrator = LiveOrchestrator(
            cfg=FakeCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=None,
        )
        self.assertTrue(orchestrator._bpp_install_uses_section_framing())

    def test_legacy_flattened_mode_drops_container_headers(self):
        # The opt-out exists for physical cards that reject section-framed
        # payloads. It is pinned here so nobody mistakes it for the default:
        # it emits exactly the bare members that leave a section-framing
        # eUICC reporting a spurious early ProfileInstallationResult.
        class LegacyCfg(FakeCfg):
            BPP_INSTALL_USE_SECTION_FRAMING: bool = False

        orchestrator = LiveOrchestrator(
            cfg=LegacyCfg(),
            apdu_channel=FakeApduChannel(),
            profile_provider=None,
        )
        self.assertFalse(orchestrator._bpp_install_uses_section_framing())
        segments = orchestrator._segment_bound_profile_package(_VECTORS[0][1])
        self.assertEqual(
            [_tag_of_segment(segment) for segment in segments],
            [b"\xBF\x36", b"\x87", b"\x88", b"\x89", b"\x86", b"\x86"],
        )


if __name__ == "__main__":
    unittest.main()
