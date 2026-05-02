"""Runtime mirror of TS 31.102 Annex H "EFs shared between SIM and USIM".

A real-world operator BPP only ships the canonical bytes of EF.IMSI /
EF.AD / etc once -- under DF.GSM (FID 7F20) -- and leaves the
same-FID Elementary File under ADF.USIM with an FCP only and no
content. Real dual-mode UICCs satisfy reads in either DF context
because the bytes are physically shared (TS 31.102 Annex H Table H.1).
The simulator emulates that contract in
``rebuild_runtime_filesystem`` via
``_mirror_shared_efs_between_df_gsm_and_adf_usim``.

These tests pin the contract against:

* the user's operator BPP (real bytes, real failure mode) when the
  fixture is checked out;
* a synthetic minimal profile so the regression survives even when
  the operator fixture is absent.

Reference:
    3GPP TS 31.102 v17 Annex H, TCA Profile Interoperability §3.5.5
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path


os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.etsi_fs import (
    EtsiFileSystem,
    build_default_state,
    rebuild_runtime_filesystem,
    _TS_31_102_ANNEX_H_SHARED_EFS,
    _mirror_shared_efs_between_df_gsm_and_adf_usim,
)
from SIMCARD.profile_import import _decode_hex_text_upp
from SIMCARD.saip_profile import decode_profile_image
from SIMCARD.state import (
    SimFileNode,
    SimProfileEntry,
    SimProfileFsNode,
    SimProfileImage,
)


_BPP_PATH = Path("Workspace/LocalSMDPP/profile/89103000000466311335_test.txt")


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
    root_id: str | None = None
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
    root_id = cursor
    for ef in _walk_efs(state, root_id):
        if ef.fid.upper() == target:
            return ef
    return None


class TS31102AnnexHSharedEfMirrorTests(unittest.TestCase):
    """Direct unit coverage for the synthetic mirror helper."""

    def _state_with_two_dfs(self):
        # Hand-roll a minimal SimCardState rather than starting from
        # ``build_default_state()`` so the assertion targets are the
        # exact EF nodes we register here, not the lab-default EFs the
        # default state already lays down under ADF.USIM.
        from SIMCARD.etsi_fs import _register_node
        from SIMCARD.state import DEFAULT_SIM_ATR, SimCardState

        state = SimCardState(
            atr=DEFAULT_SIM_ATR,
            eid="89000000000000000000000000000000",
            iccid="89000000000000000000",
            imsi="001010000000001",
            default_dp_address="rsp.example.com",
            root_ci_pkid=b"\x00" * 20,
        )
        nodes = state.nodes
        df_gsm_id = "3F00::7F20::DFGSM"
        usim_id = "3F00::7FFF::USIM"
        _register_node(
            nodes,
            SimFileNode(
                node_id="3F00",
                name="MF",
                kind="mf",
                fid="3F00",
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id=df_gsm_id,
                name="DF.GSM",
                kind="df",
                fid="7F20",
                parent_id="3F00",
            ),
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
                node_id="USIM_IMSI",
                name="EF.IMSI",
                kind="ef",
                fid="6F07",
                parent_id=usim_id,
                structure="transparent",
                data=b"",
                sfi=0x07,
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="DFGSM_AD",
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                parent_id=df_gsm_id,
                structure="transparent",
                data=bytes.fromhex("00000002"),
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="USIM_AD",
                name="EF.AD",
                kind="ef",
                fid="6FAD",
                parent_id=usim_id,
                structure="transparent",
                data=b"",
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="DFGSM_PROPRIETARY",
                name="EF.OPVENDOR",
                kind="ef",
                fid="6F30",
                parent_id=df_gsm_id,
                structure="transparent",
                data=b"\xAA\xBB",
            ),
        )
        _register_node(
            nodes,
            SimFileNode(
                node_id="USIM_PROPRIETARY",
                name="EF.OPVENDOR",
                kind="ef",
                fid="6F30",
                parent_id=usim_id,
                structure="transparent",
                data=b"",
            ),
        )
        return state

    def test_known_shared_fids_are_copied_when_usim_side_empty(self) -> None:
        from SIMCARD.etsi_fs import _build_name_path_index

        state = self._state_with_two_dfs()
        path_index = _build_name_path_index(state.nodes)
        _mirror_shared_efs_between_df_gsm_and_adf_usim(state.nodes, path_index)

        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        self.assertEqual(usim_imsi.data, bytes.fromhex("082906101286455686"))

        usim_ad = _find_ef(state, ("MF", "ADF.USIM"), "6FAD")
        self.assertIsNotNone(usim_ad)
        self.assertEqual(usim_ad.data, bytes.fromhex("00000002"))

    def test_unknown_fids_are_not_mirrored(self) -> None:
        from SIMCARD.etsi_fs import _build_name_path_index

        state = self._state_with_two_dfs()
        path_index = _build_name_path_index(state.nodes)
        _mirror_shared_efs_between_df_gsm_and_adf_usim(state.nodes, path_index)

        usim_op = _find_ef(state, ("MF", "ADF.USIM"), "6F30")
        self.assertIsNotNone(usim_op)
        self.assertEqual(usim_op.data, b"")

    def test_existing_usim_payload_is_never_overwritten(self) -> None:
        from SIMCARD.etsi_fs import _build_name_path_index

        state = self._state_with_two_dfs()
        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        usim_imsi.data = bytes.fromhex("082911223344556677")

        path_index = _build_name_path_index(state.nodes)
        _mirror_shared_efs_between_df_gsm_and_adf_usim(state.nodes, path_index)

        usim_imsi_after = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertEqual(
            usim_imsi_after.data,
            bytes.fromhex("082911223344556677"),
        )

    def test_helper_is_idempotent(self) -> None:
        from SIMCARD.etsi_fs import _build_name_path_index

        state = self._state_with_two_dfs()
        path_index = _build_name_path_index(state.nodes)

        _mirror_shared_efs_between_df_gsm_and_adf_usim(state.nodes, path_index)
        first_pass = bytes(_find_ef(state, ("MF", "ADF.USIM"), "6F07").data)

        _mirror_shared_efs_between_df_gsm_and_adf_usim(state.nodes, path_index)
        second_pass = bytes(_find_ef(state, ("MF", "ADF.USIM"), "6F07").data)

        self.assertEqual(first_pass, second_pass)

    def test_constant_includes_every_efid_required_by_modems(self) -> None:
        # Sanity: the mirror table must list EF.IMSI / EF.AD / EF.LOCI
        # / EF.LI / EF.FPLMN / EF.SPN / EF.PSLOCI / EF.EPSLOCI / EF.ECC
        # at minimum. These are the EFs every modern modem reads on
        # cold attach via ADF.USIM and that operators routinely ship
        # only under DF.GSM.
        for fid in ("6F05", "6F07", "6F46", "6F7B", "6F7E", "6FAD", "6FB7", "6FE3"):
            self.assertIn(fid, _TS_31_102_ANNEX_H_SHARED_EFS)


@unittest.skipUnless(_BPP_PATH.is_file(), "operator BPP fixture missing")
class OperatorBppRuntimeMirrorTests(unittest.TestCase):
    """End-to-end: load the user's BPP, rebuild the runtime FS and
    verify that EF.IMSI under ADF.USIM exposes the BPP-issued
    contents (from DF.GSM) -- which is the exact byte the modem
    READ BINARY (SFI 0x07) would have returned ``9000`` with no body
    for, prior to the mirror fix.
    """

    def _activate_bpp(self, image: SimProfileImage):
        state = build_default_state()
        for profile in state.profiles:
            profile.state = "disabled"
        forced_aid = "ANNEX-H-MIRROR-PROBE"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name or "Annex-H probe",
                imsi=image.imsi or "001010000000001",
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid
        rebuild_runtime_filesystem(state)
        return state

    def test_ef_imsi_under_adf_usim_serves_bpp_bytes(self) -> None:
        upp = _decode_hex_text_upp(_BPP_PATH)
        image = decode_profile_image(upp)
        state = self._activate_bpp(image)

        usim_imsi = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_imsi)
        self.assertGreater(
            len(usim_imsi.data),
            0,
            "EF.IMSI under ADF.USIM is empty after BPP layering -- "
            "Annex H mirror did not fire.",
        )
        # Must be byte-identical to the DF.GSM-side EF.IMSI the BPP
        # actually populated.
        df_gsm_imsi = _find_ef(state, ("MF", "DF.GSM"), "6F07")
        self.assertIsNotNone(df_gsm_imsi)
        self.assertEqual(usim_imsi.data, df_gsm_imsi.data)

    def test_ef_ad_under_adf_usim_serves_bpp_bytes(self) -> None:
        upp = _decode_hex_text_upp(_BPP_PATH)
        image = decode_profile_image(upp)
        state = self._activate_bpp(image)

        usim_ad = _find_ef(state, ("MF", "ADF.USIM"), "6FAD")
        self.assertIsNotNone(usim_ad)
        self.assertGreater(len(usim_ad.data), 0)
        df_gsm_ad = _find_ef(state, ("MF", "DF.GSM"), "6FAD")
        self.assertIsNotNone(df_gsm_ad)
        self.assertEqual(usim_ad.data, df_gsm_ad.data)

    def test_read_binary_via_sfi_under_usim_returns_imsi_bytes(self) -> None:
        # Reproduces the production trace: READ BINARY P1=0x87
        # (SFI=0x07 select-and-read) P2=0x00 Le=0x09 should now
        # return 9 bytes of EF.IMSI rather than 9000 with empty body.
        upp = _decode_hex_text_upp(_BPP_PATH)
        image = decode_profile_image(upp)
        state = self._activate_bpp(image)

        # Position the FS at ADF.USIM so the SFI lookup operates in
        # the right DF scope.
        usim_node = _find_ef(state, ("MF", "ADF.USIM"), "6F07")
        self.assertIsNotNone(usim_node)
        state.current_node_id = usim_node.parent_id

        fs = EtsiFileSystem(state)
        data, sw1, sw2 = fs.read_binary(p1=0x87, p2=0x00, le=0x09)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(len(data), 9)
        self.assertEqual(data, usim_node.data[:9])


if __name__ == "__main__":
    unittest.main()
