"""SAIP template default-value fill-in regression suite.

Operator BPPs routinely ship skeleton FCPs for template-defined EFs
without any ``fillFileContent`` directive, expecting the card to
materialise the SAIP / TS 31.102 §9 template default at runtime
(``EF.AD = 00000002``, ``EF.HPPLMN = 0A``, ``EF.PSLOCI = FFFFFFFFFF...0000FF01``,
``EF.Keys = 07FF...FF`` and so on). Without this fill-in the modem
sees ``9000`` with an empty body when reading via SFI -- the exact
symptom that surfaced in the
``89103000000466311335`` HIL trace.

These tests pin:

* the lookup registry built from pySim's
  ``FilesUsimMandatoryV2`` / ``FilesUsimOptionalV3`` /
  ``FilesIsimMandatory`` / ``FilesAtMF`` / ``FilesTelecom`` tables;
* the runtime fill-in pass (``_apply_saip_template_defaults_to_runtime``)
  invariants -- issuer wins, ``content_rqd=True`` is never
  fabricated, SFIs / structures are always synced;
* an end-to-end replay of the production cold-attach SFI READ BINARY
  sequence through ``EtsiFileSystem``.

Reference:
    SAIP / TCA Profile Interoperability v2.3.1 §9, 3GPP TS 31.102 §4.4
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.etsi_fs import (
    EtsiFileSystem,
    build_default_state,
    rebuild_runtime_filesystem,
    _apply_saip_template_defaults_to_runtime,
    _build_name_path_index,
    _load_saip_template_defaults_registry,
    _register_node,
)
from SIMCARD.profile_import import import_profile_artifact
from SIMCARD.profile_store import load_profiles_from_store
from SIMCARD.state import (
    DEFAULT_SIM_ATR,
    SimCardState,
    SimFileNode,
)


_BPP_PATH = Path("Workspace/LocalSMDPP/profile/89103000000466311335_test.txt")


def _find_ef(state, parent_name: str, fid: str) -> SimFileNode | None:
    target = fid.upper()
    for node in state.nodes.values():
        if node.kind != "ef":
            continue
        if node.fid.upper() != target:
            continue
        parent = state.nodes.get(node.parent_id)
        if parent is None:
            continue
        if parent.name == parent_name:
            return node
    return None


class SaipTemplateDefaultsRegistryTests(unittest.TestCase):
    def test_registry_contains_core_usim_mandatory_entries(self) -> None:
        registry = _load_saip_template_defaults_registry()
        self.assertGreater(len(registry), 0)
        for fid in ("6F07", "6FAD", "6F31", "6F38", "6F73", "6F7E", "6FE3"):
            self.assertIn(("ADF.USIM", fid), registry, msg=f"missing ADF.USIM/{fid}")

    def test_ef_ad_defaults_match_ts_31_102(self) -> None:
        registry = _load_saip_template_defaults_registry()
        ef_ad = registry[("ADF.USIM", "6FAD")]
        self.assertEqual(ef_ad.default_val, "00000002")
        self.assertEqual(int(ef_ad.sfi), 0x03)
        self.assertEqual(ef_ad.file_size, 4)
        self.assertFalse(bool(ef_ad.content_rqd))

    def test_ef_imsi_template_demands_issuer_content(self) -> None:
        registry = _load_saip_template_defaults_registry()
        ef_imsi = registry[("ADF.USIM", "6F07")]
        self.assertTrue(bool(ef_imsi.content_rqd))
        self.assertIsNone(ef_imsi.default_val)

    def test_mf_and_isim_entries_are_indexed(self) -> None:
        registry = _load_saip_template_defaults_registry()
        # MF skeletons (EF.PL has SFI 5, default 'FF...FF').
        self.assertIn(("MF", "2F05"), registry)
        # ISIM mandatory shells.
        self.assertIn(("ADF.ISIM", "6F02"), registry)


class SaipTemplateDefaultsRuntimeFillInTests(unittest.TestCase):
    def _bare_state_with_usim(self) -> SimCardState:
        state = SimCardState(
            atr=DEFAULT_SIM_ATR,
            eid="89000000000000000000000000000000",
            iccid="89000000000000000000",
            imsi="001010000000001",
            default_dp_address="rsp.example.com",
            root_ci_pkid=b"\x00" * 20,
        )
        _register_node(
            state.nodes,
            SimFileNode(node_id="3F00", name="MF", kind="mf", fid="3F00"),
        )
        _register_node(
            state.nodes,
            SimFileNode(
                node_id="USIM",
                name="ADF.USIM",
                kind="adf",
                fid="7FFF",
                aid="A0000000871002",
                label="USIM",
                parent_id="3F00",
            ),
        )
        return state

    def _add_ef_under_usim(
        self,
        state: SimCardState,
        node_id: str,
        fid: str,
        *,
        data: bytes = b"",
        records: list[bytes] | None = None,
        sfi: int | None = None,
        structure: str = "",
    ) -> SimFileNode:
        node = SimFileNode(
            node_id=node_id,
            name=f"EF_{fid}",
            kind="ef",
            fid=fid,
            parent_id="USIM",
            structure=structure,
            data=data,
            records=list(records or []),
            sfi=sfi,
        )
        _register_node(state.nodes, node)
        return node

    def test_empty_ef_ad_is_filled_from_template(self) -> None:
        state = self._bare_state_with_usim()
        ef_ad = self._add_ef_under_usim(state, "EF_AD", "6FAD")
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        self.assertEqual(ef_ad.data, bytes.fromhex("00000002"))
        self.assertEqual(ef_ad.sfi, 0x03)
        self.assertEqual(ef_ad.structure, "transparent")

    def test_existing_ef_ad_payload_is_not_overwritten(self) -> None:
        state = self._bare_state_with_usim()
        existing = bytes.fromhex("DEADBEEF")
        ef_ad = self._add_ef_under_usim(
            state,
            "EF_AD",
            "6FAD",
            data=existing,
        )
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        self.assertEqual(ef_ad.data, existing)
        # SFI is FCP metadata, still synced from the template even
        # when the payload was pre-existing.
        self.assertEqual(ef_ad.sfi, 0x03)

    def test_content_rqd_efs_are_left_empty(self) -> None:
        state = self._bare_state_with_usim()
        ef_imsi = self._add_ef_under_usim(state, "EF_IMSI", "6F07")
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        # No template default for EF.IMSI -- must be issuer-supplied.
        self.assertEqual(ef_imsi.data, b"")
        # SFI is still synced even though data fill-in is gated.
        self.assertEqual(ef_imsi.sfi, 0x07)

    def test_linear_fixed_template_default_seeds_records(self) -> None:
        state = self._bare_state_with_usim()
        # EF.EPSNSC: linear-fixed, 1 record of 80 bytes, default 'FF...FF'.
        ef = self._add_ef_under_usim(state, "EF_EPSNSC", "6FE4")
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        self.assertEqual(len(ef.records), 1)
        self.assertEqual(ef.records[0], b"\xFF" * 80)
        self.assertEqual(ef.structure, "linear-fixed")
        self.assertEqual(ef.sfi, 0x18)

    def test_psloci_default_pattern_is_expanded_verbatim(self) -> None:
        state = self._bare_state_with_usim()
        ef = self._add_ef_under_usim(state, "EF_PSLOCI", "6F73")
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        # TS 31.102 §4.2.23 / SAIP §9.5.1: 14-byte default
        # 'FFFFFFFFFFFFFFFFFFFF0000FF01'.
        self.assertEqual(ef.data.hex().upper(), "FFFFFFFFFFFFFFFFFFFF0000FF01")
        self.assertEqual(ef.sfi, 0x0C)

    def test_unknown_fids_are_left_untouched(self) -> None:
        state = self._bare_state_with_usim()
        # 6F00 is operator-private here (no template entry).
        ef = self._add_ef_under_usim(state, "EF_PRIV", "6F00")
        path_index = _build_name_path_index(state.nodes)
        _apply_saip_template_defaults_to_runtime(state.nodes, path_index)
        self.assertEqual(ef.data, b"")
        self.assertIsNone(ef.sfi)


@unittest.skipUnless(_BPP_PATH.is_file(), "operator BPP fixture missing")
class OperatorBppEndToEndReplayTests(unittest.TestCase):
    """Replay the production cold-attach SFI READ BINARY sequence
    against the rebuilt runtime FS and assert it matches the bytes a
    real card would have served. This is the fix for the original
    user-reported HIL hang where ``00B0830004`` returned ``6A82``
    and ``00B0870009`` / ``00B0000004`` returned ``9000`` with no
    body.
    """

    def _build_runtime(self) -> SimCardState:
        with tempfile.TemporaryDirectory() as tmpd:
            store = Path(tmpd) / "profile_store.json"
            res = import_profile_artifact(
                str(_BPP_PATH),
                str(store),
                enable=True,
            )
            state = build_default_state()
            state.profiles = load_profiles_from_store(str(store))
            state.active_profile_aid = res.aid
            state.active_profile_iccid = res.iccid
            rebuild_runtime_filesystem(state)
            return state

    def _select_usim_as_current_df(self, state: SimCardState) -> None:
        for node_id, node in state.nodes.items():
            if node.kind == "adf" and node.name == "ADF.USIM":
                state.current_node_id = node_id
                return
        self.fail("ADF.USIM not present in runtime tree")

    def test_sfi_03_read_binary_returns_ef_ad_default(self) -> None:
        state = self._build_runtime()
        self._select_usim_as_current_df(state)
        fs = EtsiFileSystem(state)
        # This is the exact APDU that returned 6A82 in the broken trace.
        data, sw1, sw2 = fs.read_binary(p1=0x83, p2=0x00, le=0x04)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, bytes.fromhex("00000002"))

    def test_sfi_07_read_binary_returns_bpp_imsi_via_mirror(self) -> None:
        state = self._build_runtime()
        self._select_usim_as_current_df(state)
        fs = EtsiFileSystem(state)
        data, sw1, sw2 = fs.read_binary(p1=0x87, p2=0x00, le=0x09)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # 9-byte EF.IMSI from the BPP's DF.GSM/EF.IMSI mirrored in.
        self.assertEqual(len(data), 9)
        self.assertEqual(data.hex().upper(), "082906101286455686")

    def test_ef_psloci_loci_epsloci_serve_template_defaults(self) -> None:
        state = self._build_runtime()

        ef_psloci = _find_ef(state, "ADF.USIM", "6F73")
        self.assertIsNotNone(ef_psloci)
        self.assertEqual(
            ef_psloci.data.hex().upper(),
            "FFFFFFFFFFFFFFFFFFFF0000FF01",
        )

        ef_loci = _find_ef(state, "ADF.USIM", "6F7E")
        self.assertIsNotNone(ef_loci)
        self.assertEqual(
            ef_loci.data.hex().upper(),
            "FFFFFFFFFFFFFF0000FF01",
        )

        ef_epsloci = _find_ef(state, "ADF.USIM", "6FE3")
        self.assertIsNotNone(ef_epsloci)
        self.assertEqual(
            ef_epsloci.data.hex().upper(),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000001",
        )

    def test_keys_and_keysps_seeded_with_cksn_07_no_key(self) -> None:
        state = self._build_runtime()
        ef_keys = _find_ef(state, "ADF.USIM", "6F08")
        self.assertIsNotNone(ef_keys)
        # CKSN 0x07 = "no key set" sentinel (TS 24.008 §10.5.1.2),
        # remainder padded with FF per pySim default 07FF...FF.
        self.assertEqual(len(ef_keys.data), 33)
        self.assertEqual(ef_keys.data[0], 0x07)
        self.assertTrue(all(b == 0xFF for b in ef_keys.data[1:]))

        ef_keys_ps = _find_ef(state, "ADF.USIM", "6F09")
        self.assertIsNotNone(ef_keys_ps)
        self.assertEqual(len(ef_keys_ps.data), 33)
        self.assertEqual(ef_keys_ps.data[0], 0x07)


if __name__ == "__main__":
    unittest.main()
