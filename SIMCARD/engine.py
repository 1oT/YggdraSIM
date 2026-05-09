# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Simulated UICC/eUICC engine: process-wide singleton owning the in-memory file-system, authentication state, and IPA-poll dispatch loop."""
from __future__ import annotations

import collections
import logging
import os
import sys
import traceback

from SIMCARD.auth import AuthLogic
from SIMCARD.euicc_store import (
    default_profile_store_path,
    euicc_store_exists,
    load_euicc_store_into_state,
    resolve_euicc_store_path,
    sync_euicc_store,
)
from SIMCARD.etsi_fs import EtsiFileSystem, build_default_state, rebuild_runtime_filesystem
from SIMCARD.gp import GpLogic
from SIMCARD.identity import IdentityLogic
from SIMCARD.isdr_config import load_isdr_config_into_state
from SIMCARD.naa import NaaLogic
from SIMCARD.profile_store import (
    load_profiles_from_store,
    profile_store_has_entries,
    sync_profiles_to_store,
)
from SIMCARD.quirks import ApduResult, QuirkRegistry, load_quirk_registry
from SIMCARD.scp03 import Scp03CardLogic
from SIMCARD.scp80 import Scp80Logic
from SIMCARD.sgp import SgpLogic
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import parse_apdu
from yggdrasim_common.card_backend import (
    get_sim_eim_identity_path,
    get_sim_euicc_store_root,
    get_sim_isdr_config_path,
    get_sim_profile_store_path,
    get_sim_quirks_path,
)


_LOGGER = logging.getLogger(__name__)


_SIMCARD_SYNC_WARNED: dict[str, bool] = {
    "euicc": False,
    "profiles": False,
}


def _notify_sync_failure(category: str, store_path: str, error: BaseException) -> None:
    """Surface a store-sync error once per category to stderr + logging.

    The simulator used to swallow these outright, which masked disk-full /
    permission-denied conditions and produced a "my profiles vanished"
    support ticket on every restart. We still do not raise (the dispatch
    loop must stay alive) but we:

    * Log via ``logging`` at ``warning`` so CI / daemon wrappers can pick it
      up via their handler configuration.
    * Emit a one-shot stderr banner so an interactive operator running
      the simulator from a terminal sees the problem the first time it
      happens in the process.
    """
    _LOGGER.warning(
        "SIMCARD: failed to persist %s store at %s (%s: %s)",
        category,
        store_path,
        error.__class__.__name__,
        error,
    )
    if _SIMCARD_SYNC_WARNED.get(category, False):
        return
    _SIMCARD_SYNC_WARNED[category] = True
    try:
        sys.stderr.write(
            f"[SIMCARD] WARNING: failed to persist {category} store at "
            f"{store_path or '<unset>'} ({error.__class__.__name__}: {error}). "
            "Subsequent failures in this category will only be logged.\n"
        )
        sys.stderr.flush()
    except Exception:
        pass


class SimulatedSimCardEngine:
    def __init__(
        self,
        quirks_path: str = "",
        isdr_config_path: str = "",
        sim_eim_identity_path: str = "",
        euicc_store_root: str = "",
        profile_store_path: str = "",
    ) -> None:
        self.state = build_default_state()
        self._seed_euicc_store_after_init = False
        selected_isdr_config_path = (
            str(isdr_config_path or "").strip() or get_sim_isdr_config_path()
        )
        load_isdr_config_into_state(selected_isdr_config_path, self.state)
        selected_euicc_store_root = (
            str(euicc_store_root or "").strip() or get_sim_euicc_store_root()
        )
        selected_profile_store_override = str(profile_store_path or "").strip() or get_sim_profile_store_path()
        self.state.euicc_store_path = resolve_euicc_store_path(selected_euicc_store_root, self.state.eid)
        if len(selected_profile_store_override) > 0:
            self.state.profile_store_path = selected_profile_store_override
        else:
            self.state.profile_store_path = default_profile_store_path(self.state.euicc_store_path)
        self._load_or_seed_euicc_store()
        self._load_or_seed_profile_store()
        selected_quirks_path = str(quirks_path or "").strip() or get_sim_quirks_path()
        selected_sim_eim_identity_path = (
            str(sim_eim_identity_path or "").strip() or get_sim_eim_identity_path()
        )
        self.quirks: QuirkRegistry = load_quirk_registry(selected_quirks_path)
        self.quirks.apply_state_hooks(self.state)
        rebuild_runtime_filesystem(self.state)
        self.fs = EtsiFileSystem(self.state)
        self.naa = NaaLogic(self.state)
        self.auth = AuthLogic(self.state, file_system=self.fs)
        self.identity = IdentityLogic(self.state, file_system=self.fs)
        self.scp03 = Scp03CardLogic(self.state)
        self.gp = GpLogic(self.state)
        self.sgp = SgpLogic(self.state, sim_eim_identity_path=selected_sim_eim_identity_path)
        self.scp80 = Scp80Logic(self.state, self.transmit)
        self.toolkit = ToolkitLogic(self.state)
        # SGP.32 §6.5 IPA-side ESipa fan-out. The toolkit emits a BIP
        # poll cycle on TIMER EXPIRATION; when the modem returns the
        # eIM payload via RECEIVE DATA, each parsed EuiccPackage is
        # delivered to ISD-R via the standard STORE DATA path. Wiring
        # the dispatcher here keeps the toolkit module decoupled from
        # ``SgpLogic`` while still letting the simulator behave as a
        # real in-card SGP.32 IPA.
        self.toolkit.set_eim_package_dispatcher(self.sgp.handle_store_data)
        self._fault_ring: "collections.deque[dict[str, str]]" = collections.deque(maxlen=32)
        self._sync_all_stores()

    def _load_or_seed_euicc_store(self) -> None:
        store_path = str(self.state.euicc_store_path or "").strip()
        if len(store_path) == 0:
            return
        try:
            if euicc_store_exists(store_path):
                load_euicc_store_into_state(store_path, self.state)
                return
            self._seed_euicc_store_after_init = True
        except Exception:
            return

    def _load_or_seed_profile_store(self) -> None:
        store_path = str(self.state.profile_store_path or "").strip()
        if len(store_path) == 0:
            return
        try:
            if profile_store_has_entries(store_path):
                loaded_profiles = load_profiles_from_store(store_path)
                if len(loaded_profiles) > 0:
                    self.state.profiles = loaded_profiles
                    self.state.active_profile_aid = ""
                    for profile in loaded_profiles:
                        if str(profile.state).strip().lower() == "enabled":
                            self.state.active_profile_aid = profile.aid
                            break
                return
            sync_profiles_to_store(store_path, self.state.profiles)
        except Exception:
            return

    def _sync_all_stores(self) -> None:
        if self._seed_euicc_store_after_init:
            try:
                sync_euicc_store(self.state)
            except Exception as sync_error:
                _notify_sync_failure(
                    "euicc",
                    str(self.state.euicc_store_path or "").strip(),
                    sync_error,
                )
        profile_store_path = str(self.state.profile_store_path or "").strip()
        try:
            sync_profiles_to_store(profile_store_path, self.state.profiles)
        except Exception as sync_error:
            _notify_sync_failure("profiles", profile_store_path, sync_error)
        self._dispatch_profile_download_hooks()

    # --- Profile-download hook layer -----------------------------------
    #
    # Consumers (notably ``Tools.ProfilePackage.simcard_watch``) want a
    # reliable notification whenever a newly downloaded or freshly
    # installed SAIP profile lands in the profile store. We detect the
    # event by comparing the ICCID set seen on the previous sync against
    # the current one; a brand-new ICCID is an "arrival". This keeps the
    # contract simple (one callback per arrival, fired after the store
    # bytes are on disk) without coupling to ES10b internals.

    def register_profile_download_hook(
        self,
        callback,
    ) -> None:
        """Register a callable invoked whenever a new profile is downloaded.

        The callback receives a single dict with keys ``iccid``,
        ``profile_store_path``, and ``profile`` (the new ``SimProfile`` object).
        """
        if callable(callback) is False:
            raise TypeError("profile-download hook must be callable")
        if getattr(self, "_profile_download_hooks", None) is None:
            self._profile_download_hooks = []
        self._profile_download_hooks.append(callback)

    def unregister_profile_download_hook(
        self,
        callback,
    ) -> None:
        """Remove a previously registered profile-download hook. No-op if not found."""
        hooks = getattr(self, "_profile_download_hooks", None)
        if hooks is None:
            return
        try:
            hooks.remove(callback)
        except ValueError:
            return

    def _known_iccids(self) -> set[str]:
        seen: set[str] = set()
        for profile in self.state.profiles:
            iccid = str(getattr(profile, "iccid", "") or "").strip()
            if len(iccid) > 0:
                seen.add(iccid)
        return seen

    def _dispatch_profile_download_hooks(self) -> None:
        hooks = getattr(self, "_profile_download_hooks", None)
        if hooks is None or len(hooks) == 0:
            self._last_profile_iccids = self._known_iccids()
            return
        current = self._known_iccids()
        previous = getattr(self, "_last_profile_iccids", None)
        if previous is None:
            # First sync after construction — seed the snapshot without
            # firing (the profiles loaded at boot were not "downloaded").
            self._last_profile_iccids = current
            return
        new_iccids = current - previous
        if len(new_iccids) == 0:
            self._last_profile_iccids = current
            return
        profile_store_path = str(self.state.profile_store_path or "").strip()
        for iccid in sorted(new_iccids):
            matching = next(
                (p for p in self.state.profiles if str(getattr(p, "iccid", "") or "").strip() == iccid),
                None,
            )
            for hook in list(hooks):
                try:
                    hook(
                        {
                            "iccid": iccid,
                            "profile_store_path": profile_store_path,
                            "profile": matching,
                        }
                    )
                except Exception as hook_error:
                    _LOGGER.warning(
                        "SIMCARD: profile-download hook raised: %s: %s",
                        hook_error.__class__.__name__,
                        hook_error,
                    )
        self._last_profile_iccids = current

    def reset(self) -> None:
        """Soft-reset the card: clears all sub-module state, queues, and SCP03 session."""
        self.fs.reset()
        self.naa.reset()
        self.auth.reset()
        self.scp03.reset()
        self.sgp.reset()
        self.toolkit.reset()
        self.state.pending_fetch_queue.clear()
        self.state.store_data_buffer = b""
        self.state.store_data_expected_block = 0
        for hook in self.quirks.on_reset_hooks:
            hook(self.state)

    def get_atr(self) -> bytes:
        return bytes(self.state.atr)

    def transmit(self, apdu: bytes) -> ApduResult:
        """Submit one raw APDU and return ``(response_bytes, SW1, SW2)``.

        Applies before/after hooks, transparent SCP03 unwrap/wrap, and
        routes to the appropriate command handler in ``_dispatch``.
        """
        command = bytes(apdu or b"")
        self.state.apdu_history.append(command.hex().upper())

        for hook in self.quirks.before_apdu_hooks:
            overridden = hook(command, self.state)
            if overridden is not None:
                return overridden

        try:
            wrapped = self.scp03.is_wrapped_command(command)
            dispatch_command = command
            if wrapped:
                dispatch_command, sm_result = self.scp03.unwrap_command(command)
                if sm_result is not None:
                    result = sm_result
                else:
                    parsed = parse_apdu(bytes(dispatch_command or b""))
                    result = self._dispatch(parsed)
                    result = (
                        self.scp03.wrap_response(result[0], result[1], result[2]),
                        result[1],
                        result[2],
                    )
            else:
                parsed = parse_apdu(command)
                result = self._dispatch(parsed)
        except Exception as exc:
            self._record_fault(command, exc)
            result = (b"", 0x6F, 0x00)

        self._note_abnormal_result(command, result)

        for hook in self.quirks.after_apdu_hooks:
            overridden = hook(command, result, self.state)
            if overridden is not None:
                result = overridden
        return result

    def recent_faults(self) -> list[dict[str, str]]:
        """Public accessor for the bounded fault ring.

        Returned list is a copy; callers (test suites, admin shell,
        diagnostics overlays) can safely iterate without racing the
        deque during concurrent dispatch.
        """
        return list(self._fault_ring)

    def _note_abnormal_result(self, command: bytes, result: ApduResult) -> None:
        """Route non-exception error-class status words into the fault ring.

        The exception handler only captures unexpected Python-level
        failures. ISO 7816 error classes (6A/6B/6C/6D/6E/6F) produced
        by the dispatcher represent card-level faults that operators
        still want to inspect post-mortem; previously they were only
        visible at the physical transport boundary.
        """
        if not isinstance(result, tuple) or len(result) != 3:
            return
        try:
            sw1 = int(result[1])
            sw2 = int(result[2])
        except (TypeError, ValueError):
            return
        if sw1 < 0x6A or sw1 > 0x6F:
            return
        snapshot = {
            "apdu": bytes(command or b"")[:16].hex().upper(),
            "sw": f"{sw1:02X}{sw2:02X}",
            "source": "dispatch",
        }
        self._fault_ring.append(snapshot)

    def _dispatch(self, parsed: dict[str, int | bytes | None]) -> ApduResult:
        cla = int(parsed["cla"])
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        data = bytes(parsed["data"] or b"")
        le = parsed["le"]
        le_value = None if le is None else int(le)

        if self._is_supported_cla(cla) is False:
            return b"", 0x6E, 0x00

        # ETSI TS 102 221 §11.1.18 TERMINATE CARD USAGE post-condition.
        # A real UICC stops servicing commands once the card has been
        # bricked: only STATUS (INS 0xF2) is allowed so the IFD can
        # still detect presence. Everything else returns 6F00.
        if self.state.terminated_card_usage and ins != 0xF2:
            return b"", 0x6F, 0x00

        if ins == 0xA4:
            return self.fs.select(data, p1=p1, p2=p2)
        if ins == 0xB0:
            return self.fs.read_binary(p1=p1, p2=p2, le=le_value)
        if ins == 0xB2:
            return self.fs.read_record(record_number=p1, p2=p2, le=le_value)
        if ins == 0xA2:
            # ETSI TS 102 221 §11.1.7 SEARCH RECORD. Pattern in body,
            # P1 = starting record, P2 = SFI || mode. Returns a list
            # of matching record numbers under SW 9000.
            return self.fs.search_record(p1=p1, p2=p2, payload=data)
        if ins == 0x04:
            # ETSI TS 102 221 §11.1.13 DEACTIVATE FILE. Targets the
            # currently selected EF/DF and flips its 8A lifecycle byte
            # to 0x04 so subsequent READ/UPDATE return 6283.
            return self.fs.deactivate_file()
        if ins == 0x44:
            # ETSI TS 102 221 §11.1.14 ACTIVATE FILE.
            return self.fs.activate_file()
        if ins == 0xE6 and (cla & 0x80) == 0:
            # ETSI TS 102 221 §11.1.17 TERMINATE DF. The GP variant of
            # 0xE6 (INSTALL) has CLA bit 8 set and is dispatched
            # further down -- this branch only fires when the IFD is
            # speaking the base TS 102 221 surface.
            return self.fs.terminate_df()
        if ins == 0xE8 and (cla & 0x80) == 0:
            # ETSI TS 102 221 §11.1.16 TERMINATE EF. CLA bit 8 cleared
            # disambiguates this from GP LOAD which shares the INS.
            return self.fs.terminate_ef()
        if ins == 0xFE:
            # ETSI TS 102 221 §11.1.18 TERMINATE CARD USAGE. Sets the
            # global flag so subsequent commands except STATUS return
            # 6F00.
            self.state.terminated_card_usage = True
            return b"", 0x90, 0x00
        if ins == 0x32:
            # ETSI TS 102 221 §11.1.8 INCREASE on cyclic EFs.
            return self.fs.increase(data)
        if ins == 0x76:
            # ETSI TS 102 221 §11.1.22 SUSPEND UICC.
            return self._handle_suspend_uicc(p1, p2, data, le_value)
        if ins == 0xD6:
            return self.fs.update_binary(p1=p1, p2=p2, payload=data)
        if ins == 0xDC:
            return self.fs.update_record(record_number=p1, payload=data, p2=p2)
        if ins == 0x20:
            return self.naa.verify(p2, data)
        if ins == 0x24:
            # ETSI TS 102 221 §11.1.10 CHANGE PIN.
            return self.naa.change_chv(p2, data)
        if ins == 0x26:
            # ETSI TS 102 221 §11.1.11 DISABLE PIN.
            return self.naa.disable_chv(p1, p2, data)
        if ins == 0x28:
            # ETSI TS 102 221 §11.1.12 ENABLE PIN.
            return self.naa.enable_chv(p1, p2, data)
        if ins == 0x2C:
            return self.naa.unblock_chv(p2, data)
        if ins == 0x84:
            # ETSI TS 102 221 §11.1.7 GET CHALLENGE. Le selects the
            # length (1..0x100). Modems use this to obtain freshness for
            # OTA / SCP03 host-side cryptogram derivations.
            return self.auth.get_challenge(p1, p2, le_value)
        if ins == 0x88:
            return self.auth.internal_authenticate(p2, data)
        if ins == 0x78 and (cla & 0x80):
            # TS 31.102 §7.1.2.4 GET IDENTITY (CLA=80 INS=78). Wrapped
            # behind the 0x80 CLA proprietary bit because that is what
            # commercial UICCs require; ETSI TS 102 221 reserves the
            # base CLA for ISO 7816-4 commands only.
            return self.identity.handle_get_identity(p1, p2, data)
        if ins == 0x50 and (cla & 0x80):
            return self.scp03.handle_initialize_update(p1, data)
        if ins == 0x82 and (cla & 0x80):
            return self.scp03.handle_external_authenticate(p1, data)
        if ins == 0xCA:
            return self.gp.handle_get_data(p1, p2)
        if ins == 0xCB:
            # ETSI TS 102 221 §11.1.14 RETRIEVE DATA. Distinct from
            # GP GET DATA (CLA=80, INS=CA): the ETSI variant is
            # CLA=00 and addresses card-wide data objects whose tag
            # is encoded in P1||P2.
            return self._handle_retrieve_data(p1, p2, le_value)
        if ins == 0xDB:
            # ETSI TS 102 221 §11.1.15 SET DATA.
            return self._handle_set_data(p1, p2, data)
        if ins == 0xE0 and (cla & 0x80) == 0:
            # ETSI TS 102 222 §6.3 CREATE FILE (CLA=0x00 / 0x0X).
            # Admin-scope: the caller must hold an authenticated
            # SCP03 session because filesystem mutation must be
            # audited via a secure-channel before reaching the
            # runtime tree. The CLA gate keeps INS 0xE0 reserved
            # for the GP-side variant (none currently dispatched
            # here, but the boundary follows the same convention
            # as INS 0xE4 / 0xE6 / 0xE8).
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.fs.create_file(data)
        if ins == 0xD4 and (cla & 0x80) == 0:
            # ETSI TS 102 222 §6.4 RESIZE FILE (CLA=0x00 / 0x0X).
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.fs.resize_file(p1, p2, data)
        if ins == 0xE4 and (cla & 0x80) == 0:
            # ETSI TS 102 222 §6.5 DELETE FILE (CLA=0x00 / 0x0X).
            # The CLA gate is mandatory: the GP variant of INS 0xE4
            # (CLA=0x80) addresses application / package deletion
            # and is dispatched further down via
            # ``self.gp.handle_delete``.
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.fs.delete_file(p1, p2, data)
        if ins == 0xC0:
            # ETSI TS 102 221 §11.1.12 GET RESPONSE. Quirk layers
            # split the response from a previous command into the
            # legacy 61-LL / GET-RESPONSE handshake; the buffered
            # bytes are returned here and consumed atomically.
            return self._handle_get_response(le_value)
        if ins == 0xF2:
            # TS 102 221 §11.1.5 STATUS (CLA bit 8 cleared) returns the
            # FCP / DF-name of the currently selected file. GP Card
            # Spec v2.3.1 §11.4 GET STATUS uses CLA bit 8 set with
            # P1 ∈ {0x10, 0x20, 0x40, 0x60, 0x80}. The TS 102 223
            # toolkit STATUS only fires when the application has
            # signalled willingness to handle it via TERMINAL PROFILE.
            if (cla & 0x80) == 0:
                return self._handle_iso_status(p1, p2)
            is_gp_status = p1 not in (0x00, 0x01)
            if self.toolkit.should_handle_status() and is_gp_status is False:
                return self.toolkit.handle_status(p1, p2, data)
            if is_gp_status and self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_get_status(p1, p2, data)
        if ins == 0xE2:
            return self._handle_store_data(p1, p2, data)
        if ins == 0xE6 and (cla & 0x80):
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_install(p1, p2, data)
        if ins == 0xE8 and (cla & 0x80):
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_load(p1, p2, data)
        if ins == 0xE4 and (cla & 0x80):
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_delete(p1, p2, data)
        if ins == 0xD8 and (cla & 0x80):
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_put_key(p1, p2, data)
        if ins == 0xF0 and (cla & 0x80):
            if self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_set_status(p1, p2, data)
        if ins == 0xAA and (cla & 0x80):
            return self.toolkit.handle_terminal_capability(data)
        if ins == 0xC2:
            return self.toolkit.handle_envelope(data, self.scp80.handle_envelope)
        if ins == 0x10 and (cla & 0x80):
            return self.toolkit.handle_terminal_profile(data)
        if ins == 0x12 and (cla & 0x80):
            return self.toolkit.handle_fetch()
        if ins == 0x14 and (cla & 0x80):
            return self.toolkit.handle_terminal_response(data)
        if ins == 0x70:
            return self._handle_manage_channel(p1, p2, le_value)
        return b"", 0x6D, 0x00

    def _handle_suspend_uicc(
        self,
        p1: int,
        p2: int,
        data: bytes,
        le: int | None,
    ) -> ApduResult:
        """ETSI TS 102 221 §11.1.22 SUSPEND UICC.

        P1 selects the sub-function:

        - ``0x00`` SUSPEND -- the body carries 80/81 minimum / maximum
          suspend-time TLVs (TS 102 221 §11.1.22.2). The card replies
          with the negotiated minimum/maximum durations and an 8-byte
          resume token.
        - ``0x01`` RESUME  -- the body carries the previously issued
          resume token. Mismatched tokens are rejected with 6985.

        P2 must be ``0x00``; anything else is rejected with 6A86. The
        simulator stores the issued token in
        ``state.last_suspend_token`` so a follow-up RESUME can be
        correlated. Tests that need deterministic tokens can patch
        ``secrets.token_bytes``.
        """
        import secrets

        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        if p2_value != 0x00:
            return b"", 0x6A, 0x86

        if p1_value == 0x00:
            payload = bytes(data or b"")
            negotiated_minimum = 0x0001
            negotiated_maximum = 0x000A
            offset = 0
            while offset + 1 < len(payload):
                tag = payload[offset]
                length = payload[offset + 1]
                value_start = offset + 2
                value_end = value_start + length
                if value_end > len(payload):
                    break
                value = payload[value_start:value_end]
                if tag == 0x80 and len(value) >= 2:
                    negotiated_minimum = int.from_bytes(value[:2], "big", signed=False)
                if tag == 0x81 and len(value) >= 2:
                    negotiated_maximum = int.from_bytes(value[:2], "big", signed=False)
                offset = value_end
            if negotiated_maximum < negotiated_minimum:
                negotiated_maximum = negotiated_minimum
            token = secrets.token_bytes(8)
            self.state.last_suspend_token = token
            self.state.last_suspend_duration_seconds = int(negotiated_maximum) & 0xFFFF
            response = (
                bytes((0x80, 0x02)) + negotiated_minimum.to_bytes(2, "big")
                + bytes((0x81, 0x02)) + negotiated_maximum.to_bytes(2, "big")
                + bytes((0x82, 0x08)) + token
            )
            del le
            return response, 0x90, 0x00

        if p1_value == 0x01:
            stored = bytes(self.state.last_suspend_token or b"")
            if len(stored) == 0:
                return b"", 0x69, 0x85
            provided = bytes(data or b"")
            if len(provided) != 8 or provided != stored:
                return b"", 0x69, 0x85
            self.state.last_suspend_token = b""
            self.state.last_suspend_duration_seconds = 0
            return b"", 0x90, 0x00

        return b"", 0x6A, 0x86

    def _handle_iso_status(self, p1: int, p2: int) -> ApduResult:
        """ETSI TS 102 221 §11.1.5 STATUS (CLA bit 8 cleared).

        P1 sub-functions:

        - ``0x00`` no indication. Card just returns the requested
          response data (gated by P2).
        - ``0x01`` "Current application is initialized in the
          terminal" -- informational marker. Same response shape as
          P1=0x00 because the card has no follow-up data to volunteer.
        - ``0x02`` "Terminal will initiate the termination of the
          current application". Per §11.1.5.4 the card may close the
          session: drop CHV-verified state, clear the SCP03 session,
          and reset the toolkit pending-fetch queue. The response is
          empty regardless of P2 because the application context is
          being torn down.

        P2 controls the response payload:

        - ``0x00`` FCP of the currently selected DF/EF.
        - ``0x01`` AID of the currently selected ADF (DF name).
        - ``0x0C`` no response data.

        Any other P1/P2 combination is rejected with 6A 86.
        """
        p1_value = int(p1) & 0xFF
        p2_value = int(p2) & 0xFF
        if p1_value not in (0x00, 0x01, 0x02):
            return b"", 0x6A, 0x86
        if p2_value not in (0x00, 0x01, 0x0C):
            return b"", 0x6A, 0x86

        if p1_value == 0x02:
            self._terminate_iso_session()
            return b"", 0x90, 0x00

        if p2_value == 0x0C:
            return b"", 0x90, 0x00

        node = self.fs.current_node()
        if p2_value == 0x01:
            if node.kind != "adf" or len(node.aid) == 0:
                return b"", 0x6A, 0x82
            return bytes.fromhex(node.aid), 0x90, 0x00

        # P2 == 0x00 -- full FCP. EFs are rare for STATUS targets but
        # the spec allows it; commercial cards return their FCP.
        try:
            fcp = self.fs.build_fcp(node)
        except Exception:
            return b"", 0x6F, 0x00
        return fcp, 0x90, 0x00

    def _terminate_iso_session(self) -> None:
        """TS 102 221 §11.1.5.4 session-termination side-effects.

        Clears every per-session piece of volatile state so a follow-up
        SELECT picks up a clean context. The persistent file system
        and PIN retry counters survive because they are stored on the
        card image proper.
        """
        self.naa.reset()
        self.scp03.reset()
        self.toolkit.reset()
        self.state.pending_fetch_queue.clear()
        self.state.store_data_buffer = b""
        self.state.store_data_expected_block = 0
        self.state.last_response_buffer = b""
        # Channels above 0 are torn down so the IFD must MANAGE CHANNEL
        # OPEN again; channel 0 is implicit per ISO 7816-4 §7.1.2.
        self.state.open_logical_channels = {0}

    def _handle_get_response(self, le: int | None) -> ApduResult:
        """ETSI TS 102 221 §11.1.12 GET RESPONSE.

        Consumes ``state.last_response_buffer`` and serves it to the
        IFD. Le may request fewer bytes than buffered, in which case
        the card returns the requested prefix and keeps the remainder
        for the next GET RESPONSE round-trip (mirroring real UICC
        behaviour where extended responses chain across multiple
        GET RESPONSE invocations). An empty buffer fails with 6985
        ("conditions of use not satisfied").
        """
        buffer = bytes(self.state.last_response_buffer or b"")
        if len(buffer) == 0:
            return b"", 0x69, 0x85
        if le is None or int(le) == 0:
            requested = len(buffer)
        else:
            requested = int(le)
        if requested > len(buffer):
            return b"", 0x6C, len(buffer) & 0xFF
        chunk = buffer[:requested]
        remainder = buffer[requested:]
        self.state.last_response_buffer = remainder
        if len(remainder) > 0:
            return chunk, 0x61, len(remainder) & 0xFF
        return chunk, 0x90, 0x00

    def _handle_retrieve_data(self, p1: int, p2: int, le: int | None) -> ApduResult:
        """ETSI TS 102 221 §11.1.14 RETRIEVE DATA.

        The 16-bit data-object tag is encoded as P1||P2. The matching
        blob from ``state.card_data_objects`` is returned wrapped in a
        primitive TLV ``<tag> <length> <value>`` so a generic terminal
        TLV walker can consume it. Unknown tags return ``6A 88``
        ("referenced data not found"); this matches the §10.2.5
        diagnostic for a card that does not implement the requested
        data object.
        """
        self._seed_default_card_data_objects()
        tag = ((int(p1) & 0xFF) << 8) | (int(p2) & 0xFF)
        registry = self.state.card_data_objects
        if tag not in registry:
            return b"", 0x6A, 0x88
        blob = bytes(registry[tag] or b"")
        # Encode the response as a primitive TLV using the canonical
        # short-form length when possible; longer payloads use the
        # standard BER long form (81 / 82 prefix).
        length = len(blob)
        if length < 0x80:
            length_bytes = bytes((length,))
        elif length < 0x100:
            length_bytes = bytes((0x81, length))
        else:
            length_bytes = bytes((0x82, (length >> 8) & 0xFF, length & 0xFF))
        encoded_tag = bytes((p1 & 0xFF, p2 & 0xFF)) if (p1 & 0xFF) != 0 else bytes((p2 & 0xFF,))
        response = encoded_tag + length_bytes + blob
        if le not in (None, 0, 256, 65536):
            response = response[: int(le)]
        return response, 0x90, 0x00

    def _handle_set_data(self, p1: int, p2: int, data: bytes) -> ApduResult:
        """ETSI TS 102 221 §11.1.15 SET DATA.

        Updates ``state.card_data_objects[tag]`` with the C-APDU body.
        The simulator does not enforce the §10.2.5.2 access conditions
        for SET DATA because the registry is only addressable from
        either the secure-messaging path (administrator) or a
        privileged toolkit applet; both already require prior PIN /
        SCP03 authentication enforced higher in the stack. An empty
        body deletes the entry to mirror the §11.1.15.4 erase
        semantics.
        """
        self._seed_default_card_data_objects()
        tag = ((int(p1) & 0xFF) << 8) | (int(p2) & 0xFF)
        if len(data) == 0:
            self.state.card_data_objects.pop(tag, None)
            return b"", 0x90, 0x00
        self.state.card_data_objects[tag] = bytes(data)
        return b"", 0x90, 0x00

    def _seed_default_card_data_objects(self) -> None:
        """Populate ``state.card_data_objects`` with the canonical UICC
        data objects on first access. Called lazily so that re-loading
        a persisted state does not clobber operator-supplied overrides.
        """
        registry = self.state.card_data_objects
        if len(registry) > 0:
            return
        # ETSI TS 102 221 §10.1.2 Card Capabilities (tag 0x66): the
        # blob below mirrors what a stock GP 2.3 / TS 31.102 release
        # 17 UICC reports: support for SELECT by AID and the standard
        # logical channel matrix (4 channels, 1 secure messaging).
        registry[0x0066] = bytes.fromhex("8201F08105FF010F1F00")
        # ISO 7816-4 §8.1.1 Application Identifier (tag 0x004F):
        # we publish the USIM application AID exposed by the card.
        registry[0x004F] = bytes.fromhex("A0000000871002FFFFFFFF8907090000")
        # ISO 7816-4 §8.2 Card Service Data (tag 0x0043).
        # 0xC0 = card supports SELECT BY AID and EF.DIR-based
        # discovery (ISO 7816-4 §8.2.1.3 table 87).
        registry[0x0043] = bytes((0xC0,))
        # GP 2.3 §H.2 Extended Card Resources (tag 0xFF21). Padded
        # placeholder values so a discovery probe sees plausible
        # numbers; an installer can overwrite via SET DATA.
        registry[0xFF21] = bytes.fromhex("810107C2025000C30201F4")

    def _handle_manage_channel(self, p1: int, p2: int, le: int | None) -> ApduResult:
        """ISO 7816-4 §7.1.2 MANAGE CHANNEL.

        P1=0x00 opens a channel (P2=0x00 asks the card to allocate one,
        P2=0x01..0x03 opens a specific channel). P1=0x80 closes the
        channel indicated by P2. When the open-channel allocation form
        is used without an Le byte, ISO 7816-4 expects the card to
        reply ``6C 01`` so the terminal knows to reissue with Le=1.
        """
        open_channels = self.state.open_logical_channels
        if p1 == 0x00:
            if p2 == 0x00:
                if le is None:
                    return b"", 0x6C, 0x01
                for candidate in (1, 2, 3):
                    if candidate in open_channels:
                        continue
                    open_channels.add(candidate)
                    return bytes([candidate]), 0x90, 0x00
                return b"", 0x68, 0x82
            if p2 in (0x01, 0x02, 0x03):
                open_channels.add(p2)
                return b"", 0x90, 0x00
            return b"", 0x6A, 0x86
        if p1 == 0x80:
            if p2 == 0x00:
                return b"", 0x6A, 0x86
            if p2 not in open_channels:
                return b"", 0x68, 0x82
            open_channels.discard(p2)
            return b"", 0x90, 0x00
        return b"", 0x6A, 0x86

    def _handle_store_data(self, p1: int, p2: int, data: bytes) -> ApduResult:
        normalized = bytes(data or b"")
        if p1 == 0x11:
            if p2 != (self.state.store_data_expected_block & 0xFF):
                self.state.store_data_buffer = b""
                self.state.store_data_expected_block = 0
                return b"", 0x6A, 0x80
            self.state.store_data_buffer += normalized
            self.state.store_data_expected_block = (self.state.store_data_expected_block + 1) & 0xFF
            return b"", 0x90, 0x00

        if len(self.state.store_data_buffer) > 0:
            if p2 != (self.state.store_data_expected_block & 0xFF):
                self.state.store_data_buffer = b""
                self.state.store_data_expected_block = 0
                return b"", 0x6A, 0x80
            normalized = self.state.store_data_buffer + normalized
            self.state.store_data_buffer = b""
            self.state.store_data_expected_block = 0
        result = self.sgp.handle_store_data(normalized)
        self._maybe_queue_refresh_after_store_data(normalized, result)
        return result

    def _maybe_queue_refresh_after_store_data(self, command: bytes, result: "ApduResult") -> None:
        if result is None:
            return
        _response_bytes, sw1, sw2 = result
        if (sw1, sw2) != (0x90, 0x00):
            return
        head = bytes(command or b"")
        if len(head) == 0:
            return
        tag2 = head[:2]
        profile_state_tags = (
            bytes.fromhex("BF31"),
            bytes.fromhex("BF32"),
            bytes.fromhex("BF33"),
            bytes.fromhex("BF64"),
        )
        bpp_commit_first_byte = head[0] == 0xA3
        if tag2 not in profile_state_tags and bpp_commit_first_byte is False:
            return
        queue_refresh = getattr(self.toolkit, "queue_refresh", None)
        if callable(queue_refresh) is False:
            return
        try:
            queue_refresh(source="sgp-store-data")
        except Exception:
            return

    @staticmethod
    def _is_supported_cla(cla: int) -> bool:
        """Gate APDU dispatch on CLA values recognised by this simulator.

        Accepts ISO 7816-4 interindustry CLAs (0x00..0x0F, channels 0-3
        with optional secure messaging), GP proprietary CLAs
        (0x80..0x8F, channels 0-3 with optional SCP SM), the
        first-interindustry extended range for channels 4-19
        (0x40..0x7F), and the legacy GSM/UMTS class
        (0xA0..0xAF) used by 3GPP TS 11.11 / TS 51.011 and still
        emitted by many baseband modems during cold attach before
        they fall back to ETSI TS 102 221's 0x00 family.

        ETSI TS 102 221 §10.1.1 and 3GPP TS 11.11 §9.4 both reserve
        the 0xA0 nibble for SIM-class commands (SELECT, READ BINARY,
        READ RECORD, VERIFY, etc.); their INS values overlap 1:1 with
        the modern surface so the dispatcher routes them through the
        same handlers further down. We deliberately stop at 0xAF so
        the upper proprietary range (0xB0+) still falls through to
        `6E 00` per ISO 7816-4 §5.4.1, rather than being silently
        accepted.
        """
        value = int(cla) & 0xFF
        if 0x00 <= value <= 0x0F:
            return True
        if 0x40 <= value <= 0x7F:
            return True
        if 0x80 <= value <= 0x8F:
            return True
        if 0xA0 <= value <= 0xAF:
            return True
        return False

    def _record_fault(self, command: bytes, exc: BaseException) -> None:
        """Capture unexpected dispatch faults into a bounded ring.

        Enabled verbosely when ``YGGDRASIM_SIM_DEBUG_FAULTS`` is set,
        otherwise the ring silently accumulates the last 32 entries so
        post-mortem inspection is possible without bloating logs.
        """
        snapshot = {
            "apdu": bytes(command or b"")[:16].hex().upper(),
            "exc_type": type(exc).__name__,
            "exc_msg": str(exc)[:200],
        }
        self._fault_ring.append(snapshot)
        if str(os.environ.get("YGGDRASIM_SIM_DEBUG_FAULTS", "")).strip() == "1":
            trace_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            snapshot["traceback"] = trace_text
            try:
                print(f"[SIMCARD] dispatch fault: {snapshot['apdu']} -> {snapshot['exc_type']}: {snapshot['exc_msg']}")
            except Exception:
                pass
