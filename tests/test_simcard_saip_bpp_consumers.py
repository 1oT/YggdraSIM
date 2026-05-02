"""SAIP BPP consumer regression suite.

Covers the four ProfileElement consumers added in the round closing
out the round-trip from a SAIP-encoded operator BPP into a runtime
``SimCardState``:

* ``pinCodes`` (SAIP §5.6.1)         -> ``SimProfileImage.pin_codes``
* ``pukCodes`` (SAIP §5.6.2)         -> ``SimProfileImage.puk_codes``
* ``securityDomain`` (SAIP §5.5)     -> ``SimProfileImage.security_domains``
* ``rfm`` (SAIP §5.7)                -> ``SimProfileImage.rfm_instances``
* ``genericFileManagement`` (§5.4)   -> ``SimProfileImage.nodes``

Plus the runtime-projection step in ``rebuild_runtime_filesystem``
that lights up ``state.chv_references`` / ``state.gp_apps`` /
``state.scp03_keys`` / ``state.rfm_instances`` from the active
profile's image.

The tests use the reference BPP fixture so the same byte streams
exercised by HIL traces are covered. The fixture is checked out at
``Workspace/LocalSMDPP/profile/89103000000466311335_test.txt``; if
it goes missing the suite skips rather than asserting against
fabricated data.
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
)
from SIMCARD.naa import NaaLogic
from SIMCARD.profile_import import _decode_hex_text_upp
from SIMCARD.saip_profile import decode_profile_image
from SIMCARD.etsi_fs import (
    _hydrate_mno_scp80_keys,
)
from SIMCARD.scp03 import Scp03CardLogic
from SIMCARD.state import (
    SimProfileEntry,
    SimProfileSecurityDomain,
    SimProfileSecurityDomainKey,
)


_BPP_PATH = Path("Workspace/LocalSMDPP/profile/89103000000466311335_test.txt")


def _load_image_or_skip(test_case: unittest.TestCase):
    if _BPP_PATH.is_file() is False:
        test_case.skipTest(f"operator BPP fixture missing at {_BPP_PATH}")
    upp = _decode_hex_text_upp(_BPP_PATH)
    return decode_profile_image(upp)


class SaipPinCodesConsumerTests(unittest.TestCase):
    def test_pin_table_carries_global_local_and_adm_keys(self) -> None:
        image = _load_image_or_skip(self)
        references = {entry.key_reference: entry for entry in image.pin_codes}
        # TS 102 221 §9.5.1: global PIN1 (0x01), administrative key
        # ADM1 (0x0A) and the universal/local PIN1 (0x81) are the
        # three slots a typical USIM/ISIM profile provisions.
        self.assertIn(0x01, references)
        self.assertIn(0x0A, references)
        self.assertIn(0x81, references)
        self.assertEqual(len(references[0x01].value), 8)
        self.assertEqual(len(references[0x81].value), 8)

    def test_global_pin1_is_disabled_and_unblock_target_links_back(self) -> None:
        image = _load_image_or_skip(self)
        global_pin = next(entry for entry in image.pin_codes if entry.key_reference == 0x01)
        # SAIP §5.6.1 attribute byte bit 0 = "PIN enabled". The
        # operator profile under test ships PIN1 disabled at the
        # MF level (modem unlocks freely, app-local PIN takes over).
        self.assertEqual(global_pin.attributes & 0x01, 0x00)
        self.assertEqual(global_pin.unblock_reference, 0x01)

    def test_runtime_chv_table_reflects_bpp_pins_and_puks(self) -> None:
        image = _load_image_or_skip(self)
        state = build_default_state()
        forced_aid = "BPP-PIN-PUK-PROBE"
        for profile in state.profiles:
            profile.state = "disabled"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid

        rebuild_runtime_filesystem(state)

        # PIN1 (global, ref 0x01) ships disabled per the BPP.
        self.assertIn(0x01, state.chv_references)
        global_pin = state.chv_references[0x01]
        self.assertFalse(global_pin.enabled)
        self.assertEqual(global_pin.value, "0000")

        # PIN1 local / universal (ref 0x81) ships enabled at "1234".
        self.assertIn(0x81, state.chv_references)
        local_pin = state.chv_references[0x81]
        self.assertTrue(local_pin.enabled)
        self.assertEqual(local_pin.value, "1234")

        # PUK1 (ref 0x01) and PUK1.local (ref 0x81) link back to the
        # PIN entries with the BPP-issued unblock secret.
        self.assertEqual(global_pin.unblock_value, "12345678")
        self.assertEqual(local_pin.unblock_value, "12345678")
        self.assertEqual(global_pin.unblock_retry_limit, 10)
        self.assertEqual(local_pin.unblock_retry_limit, 10)


class SaipSecurityDomainConsumerTests(unittest.TestCase):
    def test_image_records_instance_aid_and_baseline_keys(self) -> None:
        image = _load_image_or_skip(self)
        self.assertGreaterEqual(len(image.security_domains), 1)
        domain = image.security_domains[0]
        # GP §11.1 ISD-style AID, lifecycle PERSONALIZED (0x0F).
        self.assertEqual(domain.instance_aid, "A000000151000000")
        self.assertEqual(domain.lifecycle_state, 0x0F)
        # SCP03 baseline triplet KVN 0x01 must be complete (KIDs 1,2,3).
        triplet = {key.key_identifier: key for key in domain.keys if key.key_version == 0x01}
        self.assertEqual(set(triplet), {0x01, 0x02, 0x03})
        for key in triplet.values():
            self.assertEqual(len(key.key_data), 16)

    def test_runtime_promotes_mno_sd_aid_and_loads_scp80_keyset(self) -> None:
        image = _load_image_or_skip(self)
        state = build_default_state()
        forced_aid = "BPP-SCP80-PROBE"
        for profile in state.profiles:
            profile.state = "disabled"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid

        # Capture the placeholder defaults so the BPP can be asserted
        # really overrode them rather than coincidentally matching.
        default_key_enc = bytes(state.scp80_security.key_enc)
        default_key_mac = bytes(state.scp80_security.key_mac)

        rebuild_runtime_filesystem(state)

        domain = image.security_domains[0]
        ota_pair = {
            key.key_identifier: key
            for key in domain.keys
            if key.key_version == 0x40 and key.key_identifier in (0x01, 0x02)
        }
        # Sanity: the BPP fixture is expected to ship the OTA pair.
        self.assertEqual(set(ota_pair), {0x01, 0x02})

        self.assertNotEqual(state.scp80_security.key_enc, default_key_enc)
        self.assertNotEqual(state.scp80_security.key_mac, default_key_mac)
        self.assertEqual(state.scp80_security.key_enc, ota_pair[0x01].key_data)
        self.assertEqual(state.scp80_security.key_mac, ota_pair[0x02].key_data)

    def test_runtime_promotes_mno_sd_aid_and_loads_scp03_baseline(self) -> None:
        image = _load_image_or_skip(self)
        state = build_default_state()
        forced_aid = "BPP-SD-PROBE"
        for profile in state.profiles:
            profile.state = "disabled"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid

        rebuild_runtime_filesystem(state)

        domain = image.security_domains[0]
        self.assertEqual(state.mno_sd_aid, domain.instance_aid)

        # SCP03 baseline triplet hits ``state.scp03_keys`` verbatim.
        triplet = {key.key_identifier: key for key in domain.keys if key.key_version == 0x01}
        self.assertEqual(state.scp03_keys.kenc, triplet[0x01].key_data)
        self.assertEqual(state.scp03_keys.kmac, triplet[0x02].key_data)
        self.assertEqual(state.scp03_keys.dek, triplet[0x03].key_data)
        self.assertEqual(state.scp03_keys.kvn, 0x01)

        # GP §11.4 registry carries the SD instance with kind="sd".
        sd_entries = [entry for entry in state.gp_apps if entry.aid == domain.instance_aid]
        self.assertEqual(len(sd_entries), 1)
        self.assertEqual(sd_entries[0].kind, "sd")
        self.assertEqual(sd_entries[0].lifecycle_state, 0x0F)


class SaipRfmConsumerTests(unittest.TestCase):
    def test_image_records_three_rfm_bindings(self) -> None:
        image = _load_image_or_skip(self)
        self.assertEqual(len(image.rfm_instances), 3)
        instance_aids = {entry.instance_aid for entry in image.rfm_instances}
        self.assertEqual(
            instance_aids,
            {
                "A00000055910100001",
                "A00000055910100002",
                "A00000055910100003",
            },
        )
        for entry in image.rfm_instances:
            self.assertGreaterEqual(len(entry.tar_list), 1)
            for tar in entry.tar_list:
                self.assertEqual(len(tar), 3)
            # ETSI TS 102 226 §8.2.1 reserves bits 5-3 of the MSL
            # byte for the secured-packet integrity profile; the
            # operator BPP under test demands ENC+MAC = 0x16.
            self.assertEqual(entry.minimum_security_level, 0x16)

    def test_adf_binding_carries_target_application_aid(self) -> None:
        image = _load_image_or_skip(self)
        usim_binding = next(
            entry for entry in image.rfm_instances if entry.instance_aid == "A00000055910100001"
        )
        self.assertEqual(
            usim_binding.adf_aid,
            "A0000000871002FF34FF0789312E30FF",
        )

    def test_runtime_state_carries_rfm_instances(self) -> None:
        image = _load_image_or_skip(self)
        state = build_default_state()
        forced_aid = "BPP-RFM-PROBE"
        for profile in state.profiles:
            profile.state = "disabled"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid

        rebuild_runtime_filesystem(state)

        self.assertEqual(len(state.rfm_instances), len(image.rfm_instances))
        runtime_aids = {entry.instance_aid for entry in state.rfm_instances}
        self.assertEqual(
            runtime_aids,
            {entry.instance_aid for entry in image.rfm_instances},
        )


class SaipGenericFileManagementConsumerTests(unittest.TestCase):
    def _df_paths(self, image) -> set[str]:
        return {"/".join(node.path) for node in image.nodes if node.kind in ("df", "adf")}

    def _ef_count_under(self, image, path_prefix: tuple[str, ...]) -> int:
        return sum(
            1
            for node in image.nodes
            if node.kind == "ef" and node.path[: len(path_prefix)] == path_prefix
        )

    def test_gfm_introduces_legacy_gsm_and_pkcs15_dfs(self) -> None:
        image = _load_image_or_skip(self)
        df_paths = self._df_paths(image)
        # SAIP §5.4 GFM streams in this BPP register both DF.GSM
        # (legacy 7F20 hierarchy) and DF.PKCS-15 (7F50 with the
        # PKCS-15 AID) on top of the standard MF/ADF tree.
        self.assertIn("MF/DF.GSM", df_paths)
        self.assertIn("MF/DF.PKCS-15", df_paths)
        self.assertIn("MF/DF.TELECOM", df_paths)
        # The PKCS-15 ADF carries the well-known AID.
        pkcs = next(
            node
            for node in image.nodes
            if node.kind in ("df", "adf") and node.fid == "7F50"
        )
        self.assertTrue(pkcs.aid.startswith("A000000063504B43532D3135"))

    def test_gfm_populates_legacy_gsm_efs_with_correct_structure(self) -> None:
        image = _load_image_or_skip(self)
        # DF.GSM should hold the canonical GSM EF set materialised
        # via TS 102 222 CREATE FILE / fillFileContent directives.
        gsm_efs = self._ef_count_under(image, ("MF", "DF.GSM"))
        self.assertGreaterEqual(gsm_efs, 20)

        # EF.IMSI under DF.GSM must be transparent (TS 51.011 §10.3.2).
        gsm_imsi = next(
            node
            for node in image.nodes
            if node.kind == "ef"
            and node.fid == "6F07"
            and node.path[:2] == ("MF", "DF.GSM")
        )
        self.assertEqual(gsm_imsi.structure, "transparent")
        self.assertGreater(len(gsm_imsi.data), 0)

        # EF.MSISDN under DF.TELECOM is linear-fixed (TS 51.011 §10.5.5).
        msisdn = next(
            node
            for node in image.nodes
            if node.kind == "ef"
            and node.fid == "6F40"
            and node.path[:2] == ("MF", "DF.TELECOM")
        )
        self.assertEqual(msisdn.structure, "linear-fixed")
        self.assertGreaterEqual(len(msisdn.records), 1)
        # Each record left-pads the dialling string with 0xFF per
        # TS 51.011 §10.5.5; "FF" is the erased-flash filler.
        self.assertTrue(all(record[0] == 0xFF for record in msisdn.records))

    def test_runtime_filesystem_picks_up_gfm_emitted_efs(self) -> None:
        image = _load_image_or_skip(self)
        state = build_default_state()
        forced_aid = "BPP-GFM-PROBE"
        for profile in state.profiles:
            profile.state = "disabled"
        state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        state.active_profile_aid = forced_aid

        rebuild_runtime_filesystem(state)

        # GFM EFs land in ``state.nodes`` with PROFILE:: node IDs.
        gsm_imsi_runtime = [
            node
            for node in state.nodes.values()
            if node.kind == "ef" and node.fid == "6F07" and "DF.GSM" in node.parent_id
        ]
        self.assertEqual(len(gsm_imsi_runtime), 1)
        self.assertEqual(gsm_imsi_runtime[0].structure, "transparent")
        self.assertGreater(len(gsm_imsi_runtime[0].data), 0)


class Scp80KeysetHydrationUnitTests(unittest.TestCase):
    """Unit-level coverage for ``_hydrate_mno_scp80_keys`` independent
    of any specific BPP. Confirms the GP Amendment B §B.4 / TS 102
    225 §5.1 keyset selection rules.
    """

    @staticmethod
    def _key(kvn: int, kid: int, data: bytes) -> SimProfileSecurityDomainKey:
        return SimProfileSecurityDomainKey(
            usage_qualifier=0x00,
            key_identifier=kid,
            key_version=kvn,
            key_type=0x80,
            key_data=data,
            mac_length=8,
            counter=b"",
            access=0x00,
        )

    def _state_with_known_defaults(self):
        state = build_default_state()
        state.scp80_security.key_enc = bytes.fromhex("00" * 8)
        state.scp80_security.key_mac = bytes.fromhex("00" * 8)
        return state

    def test_hydrator_ignores_scp03_baseline_kvns(self) -> None:
        state = self._state_with_known_defaults()
        domain = SimProfileSecurityDomain(
            instance_aid="A000000151000000",
            keys=[
                self._key(0x01, 0x01, bytes.fromhex("AA" * 16)),
                self._key(0x01, 0x02, bytes.fromhex("BB" * 16)),
                self._key(0x01, 0x03, bytes.fromhex("CC" * 16)),
            ],
        )
        _hydrate_mno_scp80_keys(state, domain)
        # SCP03 baseline at KVN 0x01 must NOT bleed into the SCP80 slot.
        self.assertEqual(state.scp80_security.key_enc, bytes.fromhex("00" * 8))
        self.assertEqual(state.scp80_security.key_mac, bytes.fromhex("00" * 8))

    def test_hydrator_picks_lowest_complete_ota_kvn(self) -> None:
        state = self._state_with_known_defaults()
        # KVN 0x42 carries a complete pair; KVN 0x41 only has one half
        # (incomplete) and KVN 0x44 has another complete pair. The
        # selector must pick 0x42 because it is the lowest *complete*
        # candidate.
        domain = SimProfileSecurityDomain(
            instance_aid="A000000151000000",
            keys=[
                self._key(0x41, 0x01, bytes.fromhex("11" * 16)),
                self._key(0x42, 0x01, bytes.fromhex("22" * 16)),
                self._key(0x42, 0x02, bytes.fromhex("33" * 16)),
                self._key(0x44, 0x01, bytes.fromhex("44" * 16)),
                self._key(0x44, 0x02, bytes.fromhex("55" * 16)),
            ],
        )
        _hydrate_mno_scp80_keys(state, domain)
        self.assertEqual(state.scp80_security.key_enc, bytes.fromhex("22" * 16))
        self.assertEqual(state.scp80_security.key_mac, bytes.fromhex("33" * 16))

    def test_hydrator_skips_kvns_outside_the_ota_range(self) -> None:
        state = self._state_with_known_defaults()
        # KVN 0x30 is reserved for the GP §11.1.2 "production" SCP03
        # keyset; KVN 0x50 is outside the SCP80 range. Neither must
        # be picked as an OTA candidate.
        domain = SimProfileSecurityDomain(
            instance_aid="A000000151000000",
            keys=[
                self._key(0x30, 0x01, bytes.fromhex("AA" * 16)),
                self._key(0x30, 0x02, bytes.fromhex("BB" * 16)),
                self._key(0x50, 0x01, bytes.fromhex("CC" * 16)),
                self._key(0x50, 0x02, bytes.fromhex("DD" * 16)),
            ],
        )
        _hydrate_mno_scp80_keys(state, domain)
        self.assertEqual(state.scp80_security.key_enc, bytes.fromhex("00" * 8))
        self.assertEqual(state.scp80_security.key_mac, bytes.fromhex("00" * 8))


class BppPinLifecycleTests(unittest.TestCase):
    """End-to-end coverage for PIN enable / disable / verify / unblock
    against the CHV table populated from the SAIP ``pinCodes`` /
    ``pukCodes`` PEs.

    The BPP under test ships PIN1 (ref ``0x01``) globally disabled at
    MF and PIN1.local (ref ``0x81``) enabled at ``"1234"`` with PUK
    secret ``"12345678"``. The simulator must:

    * Reflect that disabled flag in ``state.chv_references`` so file
      access checks and SELECT-driven PS_DO advertisements stay in
      sync (TS 102 221 §9.5.1, §11.1.1.4.9).
    * Honour DISABLE PIN / ENABLE PIN APDUs (INS ``0x26`` / ``0x28``)
      on the BPP-supplied references, with the spec-mandated retry
      counter behaviour on wrong values (TS 102 221 §11.1.11/12).
    * Allow UNBLOCK PIN (INS ``0x2C``) using the BPP-supplied PUK and
      transition the linked PIN back to verified state with the
      retry counter restored.
    """

    def setUp(self) -> None:
        self.image = _load_image_or_skip(self)
        self.state = build_default_state()
        forced_aid = "BPP-PIN-LIFECYCLE"
        for profile in self.state.profiles:
            profile.state = "disabled"
        self.state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=self.image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=self.image.profile_name,
                imsi=self.image.imsi,
                profile_image=self.image,
                profile_source="upp",
            )
        )
        self.state.active_profile_aid = forced_aid
        rebuild_runtime_filesystem(self.state)
        self.naa = NaaLogic(self.state)
        self.fs = EtsiFileSystem(self.state)

    @staticmethod
    def _padded(value: str) -> bytes:
        body = value.encode("ascii")
        return body + (b"\xFF" * (8 - len(body)))

    def test_disabled_global_pin1_does_not_block_local_pin_verify(self) -> None:
        # Sanity: the BPP-driven CHV table sets PIN1 disabled / local enabled.
        self.assertFalse(self.state.chv_references[0x01].enabled)
        self.assertTrue(self.state.chv_references[0x81].enabled)
        # VERIFY against the disabled global PIN1 must not affect the
        # local PIN's verified state -- the two references are distinct
        # per TS 102 221 §9.5.1.
        self.naa.verify(0x01, self._padded("0000"))
        self.assertFalse(self.state.chv_references[0x81].verified)

    def test_verify_against_disabled_pin_returns_6984_without_retry_loss(self) -> None:
        # TS 102 221 §11.1.9 / §10.2.1.5: a real comparison attempt
        # (Lc=8) against a disabled PIN must return 69 84
        # ("referenced data invalidated") and NOT consume a retry.
        # Returning 6A 88 ("referenced data not found") would make
        # strict modems treat the slot as missing rather than disabled.
        before = self.state.chv_references[0x01].retries_remaining
        data, sw1, sw2 = self.naa.verify(0x01, self._padded("0000"))
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x69, 0x84))
        self.assertEqual(self.state.chv_references[0x01].retries_remaining, before)

    def test_retry_counter_probe_works_on_disabled_pin(self) -> None:
        # Lc=0 retry-counter probes ("VERIFY without payload") must
        # still report 63 Cx regardless of enable state -- the modem
        # is allowed to query without attempting a comparison.
        self.assertFalse(self.state.chv_references[0x01].enabled)
        data, sw1, sw2 = self.naa.verify(0x01, b"")
        self.assertEqual(data, b"")
        self.assertEqual(sw1, 0x63)
        self.assertEqual(sw2 & 0xF0, 0xC0)
        self.assertEqual(
            sw2 & 0x0F,
            min(0x0F, self.state.chv_references[0x01].retries_remaining),
        )

    def test_unblock_pin_still_works_on_disabled_pin(self) -> None:
        # TS 102 221 §11.1.13: UNBLOCK PIN operates on the PUK / PIN
        # pair regardless of whether the PIN is currently enabled,
        # so an operator can rescue a disabled-but-blocked PIN. The
        # simulator must therefore route UNBLOCK PIN through to the
        # PUK comparator without the disable-flag short-circuit that
        # used to live in ``_reference_state``.
        self.state.chv_references[0x01].retries_remaining = 0
        new_pin = self._padded("9999")
        puk = self._padded("12345678")
        data, sw1, sw2 = self.naa.unblock_chv(0x01, puk + new_pin)
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertGreater(self.state.chv_references[0x01].retries_remaining, 0)

    def test_local_pin_verify_with_correct_value_succeeds(self) -> None:
        data, sw1, sw2 = self.naa.verify(0x81, self._padded("1234"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"")
        self.assertTrue(self.state.chv_references[0x81].verified)

    def test_local_pin_verify_wrong_value_decrements_retries(self) -> None:
        before = self.state.chv_references[0x81].retries_remaining
        data, sw1, sw2 = self.naa.verify(0x81, self._padded("9999"))
        # Mismatched VERIFY returns 63 Cx with x = retries_remaining.
        self.assertEqual(sw1, 0x63)
        self.assertEqual(sw2 & 0xF0, 0xC0)
        self.assertEqual(self.state.chv_references[0x81].retries_remaining, before - 1)
        self.assertFalse(self.state.chv_references[0x81].verified)

    def test_disable_pin_then_enable_pin_via_apdu_round_trips(self) -> None:
        # Start: local PIN enabled. DISABLE PIN with the right secret.
        data, sw1, sw2 = self.naa.disable_chv(0x00, 0x81, self._padded("1234"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertFalse(self.state.chv_references[0x81].enabled)

        # The FCP PS_DO under ADF.USIM must advertise the local
        # PIN as disabled. We pick the ADF root because that is where
        # ETSI TS 102 221 §11.1.1.4.9 expects the fully populated
        # PIN1/Universal-PIN/ADM1 cascade.
        adf_node = next(
            node
            for node in self.state.nodes.values()
            if node.kind == "adf" and node.name == "ADF.USIM"
        )
        fcp_after_disable = self.fs.build_fcp(adf_node)
        # Locate the C6 PS_DO and the 90 bitmap inside it. Tag walk is
        # straight-forward: the PS_DO follows the ARR tag (8B) inside
        # the 62 FCP wrapper.
        ps_do_index = fcp_after_disable.find(b"\xC6")
        self.assertGreater(ps_do_index, 0)
        bitmap_index = fcp_after_disable.find(b"\x90", ps_do_index)
        self.assertGreater(bitmap_index, ps_do_index)
        bitmap_byte = fcp_after_disable[bitmap_index + 2]
        # ADF cascade is [0x01, 0x81, 0x0A]; bitmap bit b8 => PIN1
        # (disabled per BPP), b7 => local PIN (just disabled), b6 => ADM1.
        self.assertEqual(bitmap_byte & 0x40, 0x00)

        # ENABLE PIN with the right secret restores the flag.
        data, sw1, sw2 = self.naa.enable_chv(0x00, 0x81, self._padded("1234"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertTrue(self.state.chv_references[0x81].enabled)

        fcp_after_enable = self.fs.build_fcp(adf_node)
        ps_do_index2 = fcp_after_enable.find(b"\xC6")
        bitmap_index2 = fcp_after_enable.find(b"\x90", ps_do_index2)
        bitmap_byte2 = fcp_after_enable[bitmap_index2 + 2]
        self.assertEqual(bitmap_byte2 & 0x40, 0x40)

    def test_change_pin_refused_while_disabled(self) -> None:
        # First disable the local PIN.
        self.naa.disable_chv(0x00, 0x81, self._padded("1234"))
        self.assertFalse(self.state.chv_references[0x81].enabled)
        # CHANGE PIN must now refuse with 6984 (referenced data invalidated)
        # per TS 102 221 §11.1.10. The simulator's NaaLogic short-circuits
        # before consuming a retry, so ``retries_remaining`` stays put.
        before = self.state.chv_references[0x81].retries_remaining
        old_value = self.state.chv_references[0x81].value
        new_pin_block = self._padded("1234") + self._padded("4321")
        data, sw1, sw2 = self.naa.change_chv(0x81, new_pin_block)
        self.assertEqual((sw1, sw2), (0x69, 0x84))
        self.assertEqual(self.state.chv_references[0x81].retries_remaining, before)
        self.assertEqual(self.state.chv_references[0x81].value, old_value)

    def test_unblock_pin_uses_bpp_supplied_puk(self) -> None:
        local_pin = self.state.chv_references[0x81]
        local_pin.retries_remaining = 0
        # Burn the PIN: VERIFY must now reject with 6983 until UNBLOCK.
        _, sw1, sw2 = self.naa.verify(0x81, self._padded("1234"))
        self.assertEqual((sw1, sw2), (0x69, 0x83))

        new_pin = self._padded("9999")
        puk = self._padded("12345678")
        data, sw1, sw2 = self.naa.unblock_chv(0x81, puk + new_pin)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.state.chv_references[0x81].retries_remaining, local_pin.retry_limit)
        self.assertTrue(self.state.chv_references[0x81].verified)
        # Subsequent VERIFY must now accept the new PIN.
        _, sw1, sw2 = self.naa.verify(0x81, new_pin)
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class Scp03BppKeysWiringTests(unittest.TestCase):
    """Prove that the SCP03 channel processor honours BPP-supplied
    MNO-SD keys end-to-end -- not just at engine boot but also after
    a runtime profile rotation.

    GP Card Spec v2.3.1 §7.1 INITIALIZE UPDATE response carries the
    KeyVersionNumber in byte offset 10 of the data portion. The
    simulator places ``state.scp03_keys.kvn`` there, so a successful
    round-trip through INITIALIZE UPDATE that returns the BPP's KVN
    is the cleanest evidence that the BPP-supplied keyset is the
    one actually being used.
    """

    def _activate_image(self, image) -> None:
        forced_aid = "BPP-SCP03-PROBE"
        for profile in self.state.profiles:
            profile.state = "disabled"
        self.state.profiles.append(
            SimProfileEntry(
                aid=forced_aid,
                iccid=image.iccid or "8988000000000000000",
                state="enabled",
                profile_class="operational",
                profile_name=image.profile_name,
                imsi=image.imsi,
                profile_image=image,
                profile_source="upp",
            )
        )
        self.state.active_profile_aid = forced_aid
        rebuild_runtime_filesystem(self.state)

    def setUp(self) -> None:
        self.state = build_default_state()

    def test_initialize_update_uses_bpp_supplied_kvn_and_keys(self) -> None:
        image = _load_image_or_skip(self)
        self._activate_image(image)

        # The BPP under test ships the SCP03 baseline triplet at
        # KVN 0x01, which is also the simulator default. Force a
        # non-default KVN to make the assertion strict.
        self.state.scp03_keys.kvn = 0x30
        scp03 = Scp03CardLogic(self.state)

        host_challenge = bytes(range(8))
        response, sw1, sw2 = scp03.handle_initialize_update(0x00, host_challenge)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertGreaterEqual(len(response), 22)
        # Byte 10 of the INITIALIZE UPDATE response carries the KVN
        # the card actually selected for the upcoming session.
        self.assertEqual(response[10], 0x30)
        # The processor's cached static keys mirror what the BPP
        # consumer just published into ``state.scp03_keys``.
        domain = image.security_domains[0]
        triplet = {key.key_identifier: key for key in domain.keys if key.key_version == 0x01}
        self.assertEqual(scp03._static_keys["kenc"], triplet[0x01].key_data)
        self.assertEqual(scp03._static_keys["kmac"], triplet[0x02].key_data)
        self.assertEqual(scp03._static_keys["dek"], triplet[0x03].key_data)

    def test_runtime_keyset_rotation_invalidates_cached_static_keys(self) -> None:
        # Simulates: engine boots with profile A active, profile B
        # is later enabled and rewrites ``state.scp03_keys``. The
        # SCP03 logic must pick up the new keyset on the next
        # INITIALIZE UPDATE rather than reusing the cached defaults
        # from boot time.
        scp03 = Scp03CardLogic(self.state)
        original_kenc = scp03._static_keys["kenc"]

        rotated_kenc = bytes.fromhex("11" * 16)
        rotated_kmac = bytes.fromhex("22" * 16)
        rotated_dek = bytes.fromhex("33" * 16)
        self.state.scp03_keys.kenc = rotated_kenc
        self.state.scp03_keys.kmac = rotated_kmac
        self.state.scp03_keys.dek = rotated_dek
        self.state.scp03_keys.kvn = 0x40

        host_challenge = bytes(range(8))
        response, sw1, sw2 = scp03.handle_initialize_update(0x00, host_challenge)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[10], 0x40)
        self.assertNotEqual(original_kenc, rotated_kenc)
        self.assertEqual(scp03._static_keys["kenc"], rotated_kenc)
        self.assertEqual(scp03._static_keys["kmac"], rotated_kmac)
        self.assertEqual(scp03._static_keys["dek"], rotated_dek)

    def test_reset_refreshes_cached_static_keys(self) -> None:
        scp03 = Scp03CardLogic(self.state)
        rotated_kenc = bytes.fromhex("AA" * 16)
        self.state.scp03_keys.kenc = rotated_kenc
        self.state.scp03_keys.kvn = 0x42

        scp03.reset()

        self.assertEqual(scp03._static_keys["kenc"], rotated_kenc)
        self.assertEqual(scp03._static_keys["kvn"], 0x42)
        # ``reset`` also re-arms the pending session with the latched KVN.
        self.assertEqual(self.state.scp03_session.key_version, 0x42)


if __name__ == "__main__":
    unittest.main()
