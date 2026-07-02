# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for SAIP / TCA Profile Interoperability §8.3.5
explicit ``Fcp.linkPath`` aliases.

A real-world operator BPP encodes most cross-DF aliases through the
``linkPath`` PRIVATE 7 OCTET STRING inside the FCP rather than relying
on the TS 31.102 Annex H "shared EFs" convention. Every USIM-side
EF.IMSI / EF.AD / EF.SPN / EF.HPPLMN points back to DF.GSM via
``7F20 <FID>``, every USIM/ISIM-side EF.SMS / EF.SMSP / EF.SMSR /
EF.SMSS / EF.FDN / EF.MSISDN points to DF.TELECOM via ``7F10 <FID>``,
and the GSM-ACCESS subtree under ADF.USIM points to DF.GSM. Resolving
these links at profile activation time is what lets a modem read
EF.IMSI through the ADF.USIM SELECT path even though the BPP only
ever wrote the bytes under DF.GSM.

Tests in this module pin:

1. The decoder captures every well-formed ``linkPath`` OCTET STRING
   and exposes it on ``SimProfileFsNode.link_path``.
2. The runtime resolver (``etsi_fs._apply_explicit_file_links_from_profile``)
   walks the FID chain MF-down and copies ``data`` / ``records`` /
   ``structure`` from the resolved target into the link slot.
3. Issuer-supplied content always wins -- a slot that already carries
   bytes is never clobbered by a later resolver pass.
4. A USIM-only EF (no link, no DF.GSM peer) is preserved verbatim,
   so the runtime cannot accidentally erase it via either link or
   Annex H mirror.
5. Cycles, self-references and unresolved targets are silent no-ops,
   so a malformed BPP never aborts profile activation.
6. End-to-end against the operator BPP fixture: every FID the modem
   reads via SFI on cold attach now returns the issuer payload that
   would otherwise live only under DF.GSM / DF.TELECOM.

Reference:
    SAIP / TCA Profile Interoperability v2.3.1 §8.3.5
    PE_Definitions ASN.1 ``Fcp.linkPath [PRIVATE 7]``
    3GPP TS 31.102 Annex H (fallback convention)
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path


os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")


from SIMCARD.etsi_fs import (
    EtsiFileSystem,
    _apply_explicit_file_links_from_profile,
    _build_name_path_index,
    _register_node,
    _resolve_link_path_target,
    build_default_state,
    rebuild_runtime_filesystem,
)
from SIMCARD.profile_import import _decode_hex_text_upp
from SIMCARD.saip_profile import (
    _decode_fcp_link_path,
    decode_profile_image,
)
from SIMCARD.state import (
    DEFAULT_SIM_ATR,
    SimCardState,
    SimFileNode,
    SimProfileEntry,
    SimProfileFsNode,
    SimProfileImage,
)


_BPP_PATH = Path("Workspace/LocalSMDPP/profile/89880000000466311335_test.txt")


def _walk_efs(state, root_node_id: str):
    seen: set[str] = set()
    stack: list[str] = [root_node_id]
    while len(stack) > 0:
        current_id = stack.pop()
        if current_id in seen:
            continue
        seen.add(current_id)
        current = state.nodes.get(current_id)
        if current is None:
            continue
        for child_id in current.children:
            child = state.nodes.get(child_id)
            if child is None:
                continue
            if child.kind in ("df", "adf"):
                stack.append(child_id)
            elif child.kind == "ef":
                yield child


def _find_ef(state, root_path: tuple[str, ...], fid: str) -> SimFileNode | None:
    target = fid.upper()
    cursor: str | None = "3F00"
    if "3F00" not in state.nodes:
        return None
    for label in root_path[1:]:
        if cursor is None:
            return None
        node = state.nodes.get(cursor)
        if node is None:
            return None
        next_id = None
        for child_id in node.children:
            child = state.nodes.get(child_id)
            if child is not None and child.name == label:
                next_id = child_id
                break
        cursor = next_id
    if cursor is None:
        return None
    for ef in _walk_efs(state, cursor):
        if ef.fid.upper() == target:
            return ef
    return None


class FcpLinkPathDecoderTests(unittest.TestCase):
    """Unit coverage for ``saip_profile._decode_fcp_link_path``."""

    def test_well_formed_two_fid_chain_yields_tuple(self) -> None:
        # 7F20 = DF.GSM, 6F07 = EF.IMSI.
        descriptor = {"linkPath": bytes.fromhex("7F206F07")}
        self.assertEqual(_decode_fcp_link_path(descriptor), ("7F20", "6F07"))

    def test_three_fid_chain_yields_three_tuples(self) -> None:
        descriptor = {"linkPath": bytes.fromhex("7F205F3B6F20")}
        self.assertEqual(_decode_fcp_link_path(descriptor), ("7F20", "5F3B", "6F20"))

    def test_empty_octet_string_means_no_link(self) -> None:
        # SAIP §8.3.5: an empty linkPath promotes the template link
        # to an independent file. The decoder must not synthesise a
        # bogus path.
        self.assertEqual(_decode_fcp_link_path({"linkPath": b""}), tuple())

    def test_missing_field_is_treated_as_no_link(self) -> None:
        self.assertEqual(_decode_fcp_link_path({}), tuple())
        self.assertEqual(_decode_fcp_link_path({"linkPath": None}), tuple())

    def test_non_dict_descriptor_is_silently_ignored(self) -> None:
        self.assertEqual(_decode_fcp_link_path(None), tuple())
        self.assertEqual(_decode_fcp_link_path(b"raw bytes"), tuple())
        self.assertEqual(_decode_fcp_link_path([]), tuple())

    def test_odd_length_payload_is_dropped(self) -> None:
        # ``linkPath`` must be a whole number of 2-byte FIDs. A 3-byte
        # blob is malformed; we drop the link rather than synthesise
        # a partial path that would mis-resolve at runtime.
        self.assertEqual(_decode_fcp_link_path({"linkPath": b"\x7F\x20\x6F"}), tuple())


class _LinkRuntimeFixture(unittest.TestCase):
    """Hand-roll a minimal ``SimCardState`` with three EFs:

    * ``DF.GSM/EF.IMSI``   : populated 9-byte transparent payload
    * ``DF.TELECOM/EF.SMS``: populated 10-record linear-fixed file
    * ``ADF.USIM/EF.IMSI`` : empty, ``link_path = (7F20, 6F07)``
    * ``ADF.USIM/EF.SMS``  : empty, ``link_path = (7F10, 6F3C)``

    Plus the supporting MF / DF.GSM / DF.TELECOM / ADF.USIM tree.
    """

    def _build_state(self) -> SimCardState:
        state = SimCardState(
            atr=DEFAULT_SIM_ATR,
            eid="89049032000000000000000000000000",
            iccid="89880000000000000000",
            imsi="001010000000001",
            default_dp_address="rsp.example.com",
            root_ci_pkid=b"\x00" * 20,
        )
        nodes = state.nodes
        df_gsm_id = "DFGSM"
        df_tel_id = "DFTEL"
        usim_id = "USIM"

        _register_node(nodes, SimFileNode(node_id="3F00", name="MF", kind="mf", fid="3F00"))
        _register_node(
            nodes,
            SimFileNode(node_id=df_gsm_id, name="DF.GSM", kind="df", fid="7F20", parent_id="3F00"),
        )
        _register_node(
            nodes,
            SimFileNode(node_id=df_tel_id, name="DF.TELECOM", kind="df", fid="7F10", parent_id="3F00"),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id=usim_id,
                name="ADF.USIM",
                kind="adf",
                fid="7FFF",
                aid="A0000000871002",
                label="USIM",
                parent_id="3F00",
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="DFGSM_IMSI",
                name="EF.IMSI",
                kind="ef",
                fid="6F07",
                parent_id=df_gsm_id,
                structure="transparent",
                data=bytes.fromhex("082906101286455686"),
                sfi=0x07,
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="DFTEL_SMS",
                name="EF.SMS",
                kind="ef",
                fid="6F3C",
                parent_id=df_tel_id,
                structure="linear-fixed",
                records=[bytes([0x00] + [0xFF] * 175)] * 10,
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="USIM_IMSI",
                name="EF.IMSI",
                kind="ef",
                fid="6F07",
                parent_id=usim_id,
                structure="transparent",
                data=b"",
                link_path=("7F20", "6F07"),
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="USIM_SMS",
                name="EF.SMS",
                kind="ef",
                fid="6F3C",
                parent_id=usim_id,
                structure="",
                records=[],
                link_path=("7F10", "6F3C"),
            ),
        )
        return state


class ApplyExplicitLinksTests(_LinkRuntimeFixture):
    """Direct coverage for ``_apply_explicit_file_links_from_profile``."""

    def test_link_to_df_gsm_imsi_copies_transparent_payload(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        _apply_explicit_file_links_from_profile(state.nodes, path_index)

        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        self.assertEqual(usim_imsi.data, bytes.fromhex("082906101286455686"))
        self.assertEqual(usim_imsi.structure, "transparent")

    def test_link_to_df_telecom_sms_copies_record_set_and_structure(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        _apply_explicit_file_links_from_profile(state.nodes, path_index)

        usim_sms = _find_ef(state, ("MF", "ADF.USIM"), "6F3C")
        self.assertIsNotNone(usim_sms)
        self.assertEqual(len(usim_sms.records), 10)
        self.assertEqual(usim_sms.structure, "linear-fixed")

    def test_existing_payload_is_never_overwritten(self) -> None:
        # Issuer supplied bytes on the link slot directly. The
        # resolver must treat those as authoritative and skip the
        # copy, because the linkPath was a creation-time hint that
        # has been overridden.
        state = self._build_state()
        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        usim_imsi.data = bytes.fromhex("DEADBEEF" + "FF" * 5)

        path_index = _build_name_path_index(state.nodes)
        _apply_explicit_file_links_from_profile(state.nodes, path_index)

        usim_imsi_after = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertEqual(usim_imsi_after.data, bytes.fromhex("DEADBEEF" + "FF" * 5))

    def test_unresolvable_link_is_silent_noop(self) -> None:
        # Point a link at a FID that does not exist in the tree.
        # The resolver must leave the slot untouched so a downstream
        # default fill-in can still run.
        state = self._build_state()
        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        usim_imsi.link_path = ("7F20", "DEAD")
        usim_imsi.data = b""

        path_index = _build_name_path_index(state.nodes)
        _apply_explicit_file_links_from_profile(state.nodes, path_index)

        usim_imsi_after = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertEqual(usim_imsi_after.data, b"")

    def test_pass_is_idempotent(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)

        _apply_explicit_file_links_from_profile(state.nodes, path_index)
        first = bytes(_find_ef(state, ("MF", "ADF.USIM"), "6F07").data)
        _apply_explicit_file_links_from_profile(state.nodes, path_index)
        second = bytes(_find_ef(state, ("MF", "ADF.USIM"), "6F07").data)

        self.assertEqual(first, second)


class ResolveLinkPathTargetTests(_LinkRuntimeFixture):
    """Cover the lower-level walker independently."""

    def test_two_fid_chain_resolves_to_target_node(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        target = _resolve_link_path_target(state.nodes, path_index, ("7F20", "6F07"))
        self.assertIsNotNone(target)
        self.assertEqual(target.node_id, "DFGSM_IMSI")

    def test_absolute_3F00_prefix_is_accepted(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        target = _resolve_link_path_target(
            state.nodes,
            path_index,
            ("3F00", "7F20", "6F07"),
        )
        self.assertIsNotNone(target)
        self.assertEqual(target.node_id, "DFGSM_IMSI")

    def test_empty_path_returns_none(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        self.assertIsNone(_resolve_link_path_target(state.nodes, path_index, tuple()))

    def test_missing_intermediate_returns_none(self) -> None:
        state = self._build_state()
        path_index = _build_name_path_index(state.nodes)
        # 7F30 is not registered; the walker must abort cleanly.
        self.assertIsNone(_resolve_link_path_target(state.nodes, path_index, ("7F30", "6F07")))


class UsimOnlyEfPreservedTests(unittest.TestCase):
    """Pin the contract that an EF that exists *only* under ADF.USIM
    -- with no ``link_path`` and no DF.GSM counterpart -- is preserved
    verbatim by every runtime pass.

    This is the symmetric guarantee to the link-mirror: the simulator
    must never invent a target nor overwrite the slot just because a
    same-FID file *might* exist in DF.GSM. Operator-private files
    rely on this invariant.
    """

    def _activate_usim_only_ef(self, payload: bytes) -> SimCardState:
        state = build_default_state()
        for profile in state.profiles:
            profile.state = "disabled"

        image = SimProfileImage(
            profile_name="usim-only fixture",
            iccid="8988000000000000001",
            imsi="001010000000002",
            nodes=[
                SimProfileFsNode(
                    path=("MF",),
                    name="MF",
                    kind="mf",
                    fid="3F00",
                ),
                SimProfileFsNode(
                    path=("MF", "ADF.USIM"),
                    name="ADF.USIM",
                    kind="adf",
                    fid="7FFF",
                    aid="A0000000871002FFFFFFFF8907090000",
                    label="USIM",
                ),
                SimProfileFsNode(
                    path=("MF", "ADF.USIM", "EF.OPVENDOR"),
                    name="EF.OPVENDOR",
                    kind="ef",
                    fid="6F30",
                    structure="transparent",
                    data=payload,
                ),
            ],
        )
        state.profiles.append(
            SimProfileEntry(
                aid="LINKPATH-USIM-ONLY",
                iccid=image.iccid,
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = "LINKPATH-USIM-ONLY"
        rebuild_runtime_filesystem(state)
        return state

    def test_usim_only_ef_keeps_payload_verbatim(self) -> None:
        payload = bytes.fromhex("ABBA1234DEADBEEF")
        state = self._activate_usim_only_ef(payload)

        usim_op = _find_ef(state, ("MF", "ADF.USIM"), "6F30")
        self.assertIsNotNone(usim_op)
        self.assertEqual(usim_op.data, payload)
        # Must not have been linked to anything.
        self.assertEqual(getattr(usim_op, "link_path", ()), ())


@unittest.skipUnless(_BPP_PATH.is_file(), "operator BPP fixture missing")
class OperatorBppLinkPathTests(unittest.TestCase):
    """End-to-end: load the user's BPP, rebuild the runtime FS and
    verify that every linkPath the issuer encoded resolves to the
    canonical bytes from DF.GSM / DF.TELECOM.

    Reproduces the original lab failure -- READ BINARY via SFI under
    ADF.USIM returning ``9000`` with empty body -- and asserts the
    fix.
    """

    def _activate_bpp(self) -> SimCardState:
        upp = _decode_hex_text_upp(_BPP_PATH)
        image = decode_profile_image(upp)
        state = build_default_state()
        for profile in state.profiles:
            profile.state = "disabled"
        forced_aid = "LINKPATH-OPBPP"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name or "Linkpath BPP probe",
                imsi=image.imsi or "001010000000001",
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid
        rebuild_runtime_filesystem(state)
        return state

    def test_decoder_picks_up_at_least_thirty_link_paths(self) -> None:
        upp = _decode_hex_text_upp(_BPP_PATH)
        image = decode_profile_image(upp)
        linked = [n for n in image.nodes if n.kind == "ef" and len(n.link_path) > 0]
        # The user's BPP carries 33 known linkPath entries across
        # USIM, ISIM, GSM-ACCESS and DF.GSM. Drop a generous lower
        # bound so the test does not break if the operator adds /
        # removes a couple of optional EFs in a future revision.
        self.assertGreaterEqual(len(linked), 30)

    def test_usim_imsi_mirrors_df_gsm_imsi_via_link_path(self) -> None:
        state = self._activate_bpp()
        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        df_gsm_imsi = _find_ef(state, ("MF", "DF.GSM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        self.assertIsNotNone(df_gsm_imsi)
        self.assertGreater(len(usim_imsi.data), 0)
        self.assertEqual(usim_imsi.data, df_gsm_imsi.data)

    def test_usim_spn_mirrors_df_gsm_spn_via_link_path(self) -> None:
        state = self._activate_bpp()
        usim_spn = _find_ef(state, ("MF", "ADF.USIM"), "6F46")
        df_gsm_spn = _find_ef(state, ("MF", "DF.GSM"), "6F46")
        self.assertIsNotNone(usim_spn)
        self.assertIsNotNone(df_gsm_spn)
        self.assertGreater(len(usim_spn.data), 0)
        self.assertEqual(usim_spn.data, df_gsm_spn.data)

    def test_usim_sms_mirrors_df_telecom_sms_record_set(self) -> None:
        state = self._activate_bpp()
        usim_sms = _find_ef(state, ("MF", "ADF.USIM"), "6F3C")
        df_tel_sms = _find_ef(state, ("MF", "DF.TELECOM"), "6F3C")
        self.assertIsNotNone(usim_sms)
        self.assertIsNotNone(df_tel_sms)
        self.assertGreater(len(usim_sms.records), 0)
        self.assertEqual(
            [bytes(record) for record in usim_sms.records],
            [bytes(record) for record in df_tel_sms.records],
        )

    def test_usim_msisdn_mirrors_df_telecom_msisdn_record_set(self) -> None:
        state = self._activate_bpp()
        usim_msisdn = _find_ef(state, ("MF", "ADF.USIM"), "6F40")
        df_tel_msisdn = _find_ef(state, ("MF", "DF.TELECOM"), "6F40")
        self.assertIsNotNone(usim_msisdn)
        self.assertIsNotNone(df_tel_msisdn)
        self.assertGreater(len(usim_msisdn.records), 0)
        self.assertEqual(
            [bytes(record) for record in usim_msisdn.records],
            [bytes(record) for record in df_tel_msisdn.records],
        )

    def test_isim_sms_mirrors_df_telecom_sms_record_set(self) -> None:
        state = self._activate_bpp()
        isim_sms = _find_ef(state, ("MF", "ADF.ISIM"), "6F3C")
        df_tel_sms = _find_ef(state, ("MF", "DF.TELECOM"), "6F3C")
        self.assertIsNotNone(isim_sms)
        self.assertIsNotNone(df_tel_sms)
        self.assertGreater(len(isim_sms.records), 0)
        self.assertEqual(
            [bytes(record) for record in isim_sms.records],
            [bytes(record) for record in df_tel_sms.records],
        )

    def test_read_binary_via_sfi_for_ef_imsi_returns_full_payload(self) -> None:
        # Reproduces the production trace ``00B0870009`` (READ BINARY
        # SFI=0x07 select-and-read of EF.IMSI through ADF.USIM).
        # Pre-fix: 9000 with empty body. Post-fix: 9 bytes of IMSI.
        state = self._activate_bpp()
        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        state.current_node_id = usim_imsi.parent_id

        fs = EtsiFileSystem(state)
        data, sw1, sw2 = fs.read_binary(p1=0x87, p2=0x00, le=0x09)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(data), 9)
        self.assertEqual(data, usim_imsi.data[:9])


if __name__ == "__main__":
    unittest.main()
