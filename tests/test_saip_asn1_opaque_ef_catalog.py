# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Wave B — opaque-passthrough round-trip guards for unmapped EF keys.

Every EF key in ``_OPAQUE_PASSTHROUGH_EF_CATALOG`` is covered by the
decode-side ``_decode_opaque_ef`` / encode-side ``encode_ef_opaque``
pair. The catalog replaces 180 previously ``missing`` entries in the
decoded-editor audit with byte-exact round-trip coverage; any single
entry can later be upgraded to a bespoke decoder without disturbing the
rest of the catalog.

The tests below pin three invariants:

1. Every catalog key is reachable through both dispatchers (decoder
   routes to ``_decode_opaque_ef`` with the expected format label;
   encoder routes to ``encode_ef_opaque``).
2. A sample byte payload round-trips byte-identically for every key.
3. Case-insensitive lookup works for the single mixed-case catalog key
   (``ef-v2xp-Uu``).
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _OPAQUE_PASSTHROUGH_EF_CATALOG,
    _decode_known_ef_payload,
    _lookup_opaque_passthrough_ef,
    opaque_passthrough_ef_keys,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
    roundtrip_capable_ef_keys,
)


_SAMPLE_BYTES = bytes.fromhex("DEADBEEFCAFEBABE01")
_SAMPLE_HEX_UPPER = _SAMPLE_BYTES.hex().upper()


class OpaquePassthroughCatalogTests(unittest.TestCase):
    def test_catalog_is_non_empty(self):
        self.assertGreater(
            len(_OPAQUE_PASSTHROUGH_EF_CATALOG),
            0,
            msg="Opaque catalog must not be empty",
        )

    def test_every_key_is_registered_with_the_dispatcher(self):
        dispatcher_keys = set(roundtrip_capable_ef_keys())
        for raw_key in _OPAQUE_PASSTHROUGH_EF_CATALOG.keys():
            normalized = raw_key.lower()
            self.assertIn(
                normalized,
                dispatcher_keys,
                msg=f"{raw_key!r} not registered in _EF_CONTENT_DISPATCHER",
            )

    def test_helper_exposes_sorted_keys(self):
        exposed = opaque_passthrough_ef_keys()
        self.assertEqual(
            exposed,
            tuple(sorted(_OPAQUE_PASSTHROUGH_EF_CATALOG.keys())),
        )

    def test_label_lookup_is_case_insensitive(self):
        label_verbatim = _lookup_opaque_passthrough_ef("ef-v2xp-Uu")
        label_lower = _lookup_opaque_passthrough_ef("ef-v2xp-uu")
        label_upper = _lookup_opaque_passthrough_ef("EF-V2XP-UU")
        self.assertIsNotNone(label_verbatim)
        self.assertEqual(label_verbatim, label_lower)
        self.assertEqual(label_verbatim, label_upper)

    def test_unknown_key_returns_none(self):
        self.assertIsNone(
            _lookup_opaque_passthrough_ef("ef-definitely-not-a-real-key"),
        )
        self.assertIsNone(_lookup_opaque_passthrough_ef(""))


    def test_label_matches_ef_csim_prefix_clause_when_shadowed(self):
        # Two decoder paths can serve a catalog key:
        #   (a) the explicit ``ef-csim-<suffix>`` prefix branch already in
        #       ``_decode_known_ef_payload`` (predates the Wave B catalog).
        #   (b) the Wave B opaque catalog lookup at the tail of the same
        #       function.
        # When a key is reachable via both, (a) wins because it appears
        # first. The observable contract is unchanged (opaque dict shape
        # with a human-readable ``format``), so we accept either label.
        catalog_label = _lookup_opaque_passthrough_ef("ef-csim-st")
        self.assertIsNotNone(catalog_label)
        decoded = _decode_known_ef_payload(
            ef_key="ef-csim-st",
            fid=None,
            hex_clean=_SAMPLE_HEX_UPPER,
        )
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded.get("hex"), _SAMPLE_HEX_UPPER)
        self.assertIn(
            decoded.get("format"),
            {"CSIM ST", catalog_label},
            msg="ef-csim-st must surface an 'CSIM *' style label",
        )


# Keys whose bespoke decoder may reject synthetic test bytes (e.g.
# ``_decode_imsi`` enforces a 9-byte BCD layout). The catalog still
# registers them in the dispatcher (round-trip coverage) but the
# decoded-view assertion is handled via the bespoke decoder's own
# unit tests; we skip them here so the fallback contract is not
# accidentally re-tested with synthetic data.
_SKIP_DECODE_SHAPE_KEYS: frozenset[str] = frozenset(
    {
        "ef-imsi",
        # Wave C Pass A — keys promoted to length-strict semantic decoders.
        # They reject the synthetic 9-byte sample because the spec fixes
        # their layout at a different length (PWS SNPN: 1 byte; DRI: 7
        # bytes; IPS: 4 bytes). Each has dedicated unit coverage in
        # tests/test_saip_wave_c_pass_a_decoders.py.
        "ef-pws-snpn",
        "ef-dri",
        "ef-ips",
        # Wave C Pass B — keys promoted to fixed-length / BER-TLV
        # semantic decoders. Each rejects the synthetic 9-byte sample
        # because their spec layout is either shorter (1-2 bytes for
        # flag / icon EFs) or requires well-formed BER-TLV content.
        # Dedicated coverage lives in
        # tests/test_saip_wave_c_pass_b_decoders.py.
        "ef-ufc",
        "ef-pws",
        "ef-umpc",
        "ef-eaka",
        "ef-frompreferred",
        "ef-3gpppsdataoff",
        "ef-vgcsca",
        "ef-vbsca",
        "ef-spni",
        "ef-pnni",
        "ef-ext4",
        "ef-ext5",
        "ef-ext8",
        # ADN-like + BER-TLV records need real record shapes; the
        # synthetic 9-byte sample is too small for their spec layout.
        "ef-bdn",
        "ef-bdnuri",
        "ef-msk",
        "ef-muk",
        "ef-ial",
        "ef-ncp-ip",
        "ef-3gpppsdataoffservicelist",
        # Wave C Pass C — MMS storage mode has a strict 1-byte layout;
        # the 9-byte synthetic sample is rejected. Dedicated unit
        # coverage lives in tests/test_saip_wave_c_pass_c_decoders.py.
        "ef-mmssmode",
        # Wave C Pass C — GBABP uses three consecutive length-prefixed
        # fields (rand / b_tid / key_lifetime). The first length byte
        # of the synthetic sample (0xDE = 222) exceeds the remaining
        # bytes, so the length-strict decoder rejects it. Dedicated
        # coverage lives in tests/test_saip_wave_c_pass_c_decoders.py.
        "ef-gbabp",
        # Wave C Pass D — 1-byte CSIM capability/bitmap decoders
        # strictly require exactly one byte; the 9-byte synthetic
        # sample is rejected. Dedicated coverage lives in
        # tests/test_saip_wave_c_pass_d_decoders.py.
        "ef-accolc",
        "ef-mipcap",
        "ef-ipv6cap",
        "ef-smscap",
        "ef-sipcap",
        # Wave C Pass E — ICE-DN uses the 14-byte ADN-like footer;
        # the 9-byte synthetic sample is shorter. Dedicated coverage
        # lives in tests/test_saip_wave_c_pass_e_decoders.py.
        "ef-ice-dn",
        # Wave D Pass A — length-strict decoders rejecting the 9-byte
        # synthetic sample. Dedicated coverage lives in
        # tests/test_saip_wave_d_pass_a_decoders.py.
        "ef-threshold",  # spec-fixed 1 byte
        "ef-eapstatus",  # spec-fixed 1 byte
        "ef-call-count",  # spec-fixed 2 bytes
        "ef-call-prompt",  # spec-fixed 1 byte
        # Deep-sweep additions — pySim-aligned EFs with strict shape
        # requirements. Dedicated coverage lives in
        # tests/test_saip_deep_sweep_additions.py.
        "ef-nid",  # spec-fixed 6-byte record
        "ef-rplmnact",  # multiple of 2 bytes required
        "ef-imsdci",  # spec-fixed 1 byte enum
        "ef-gbauapi",  # BER-TLV 80 record with nested length prefixes
    }
)


class OpaquePassthroughRoundTripTests(unittest.TestCase):
    def test_decoder_returns_some_dict_for_every_catalog_key(self):
        for raw_key in _OPAQUE_PASSTHROUGH_EF_CATALOG.keys():
            token = raw_key.lower()
            if token in _SKIP_DECODE_SHAPE_KEYS:
                continue
            decoded = _decode_known_ef_payload(
                ef_key=token,
                fid=None,
                hex_clean=_SAMPLE_HEX_UPPER,
            )
            self.assertIsInstance(
                decoded,
                dict,
                msg=f"{raw_key!r}: decoder must return a dict",
            )
            self.assertEqual(
                decoded.get("hex"),
                _SAMPLE_HEX_UPPER,
                msg=f"{raw_key!r}: hex payload mismatch",
            )
            self.assertEqual(
                decoded.get("length"),
                len(_SAMPLE_BYTES),
                msg=f"{raw_key!r}: length mismatch",
            )
            format_label = decoded.get("format")
            self.assertIsInstance(
                format_label,
                str,
                msg=f"{raw_key!r}: format must be a string",
            )
            self.assertGreater(
                len(str(format_label)),
                0,
                msg=f"{raw_key!r}: format must be non-empty",
            )

    def test_catalog_label_is_used_when_no_earlier_clause_shadows_key(self):
        # Pick a handful of keys across the major groups that still
        # fall through to the opaque-catalog fallback. Anchors that
        # have been promoted to semantic decoders in Waves C Pass A..E
        # now carry spec-accurate format labels rather than the raw
        # catalog label and are exercised in their dedicated test
        # files instead.
        anchors = (
            ("ef-launchpad", "Operator Launchpad"),
            ("ef-icon", "Icon"),
            ("ef-5g-prose-st", "5G ProSe Service Table"),
            ("ef-eapkeys", "EAP Keys"),
            ("ef-aas", "Phonebook Additional Alpha String"),
            ("ef-v2xp-uu", "V2X Uu Parameters"),
        )
        for token, expected_label in anchors:
            decoded = _decode_known_ef_payload(
                ef_key=token,
                fid=None,
                hex_clean=_SAMPLE_HEX_UPPER,
            )
            self.assertIsInstance(decoded, dict)
            self.assertEqual(
                decoded.get("format"),
                expected_label,
                msg=f"{token}: expected catalog label to win",
            )

    def test_encoder_round_trips_every_catalog_key(self):
        for raw_key in _OPAQUE_PASSTHROUGH_EF_CATALOG.keys():
            token = raw_key.lower()
            payload = {"hex": _SAMPLE_HEX_UPPER}
            encoded = encode_decoded_roundtrip_ef_content(token, payload)
            self.assertEqual(
                encoded,
                _SAMPLE_BYTES,
                msg=f"{raw_key!r}: round-trip byte mismatch",
            )

    def test_encoder_applies_ff_padding_when_target_length_given(self):
        token = "ef-launchpad"
        payload = {"hex": _SAMPLE_HEX_UPPER}
        target_length = len(_SAMPLE_BYTES) + 4
        encoded = encode_decoded_roundtrip_ef_content(
            token,
            payload,
            target_length=target_length,
        )
        self.assertEqual(
            len(encoded),
            target_length,
            msg="target_length padding should reach the requested size",
        )
        self.assertTrue(
            encoded.startswith(_SAMPLE_BYTES),
            msg="Prefix must be the original payload bytes",
        )
        self.assertEqual(
            encoded[len(_SAMPLE_BYTES):],
            b"\xFF" * 4,
            msg="Trailing bytes must be FF padding",
        )

    def test_mixed_case_key_round_trips_through_dispatcher(self):
        # Dispatcher lowercases on lookup; verifies the registration path
        # handles the one mixed-case catalog entry.
        token_mixed = "ef-v2xp-Uu"
        payload = {"hex": _SAMPLE_HEX_UPPER}
        encoded = encode_decoded_roundtrip_ef_content(token_mixed, payload)
        self.assertEqual(encoded, _SAMPLE_BYTES)


if __name__ == "__main__":
    unittest.main()
