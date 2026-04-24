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
        self.auth = AuthLogic(self.state)
        self.scp03 = Scp03CardLogic(self.state)
        self.gp = GpLogic(self.state)
        self.sgp = SgpLogic(self.state, sim_eim_identity_path=selected_sim_eim_identity_path)
        self.scp80 = Scp80Logic(self.state)
        self.toolkit = ToolkitLogic(self.state)
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
        if callable(callback) is False:
            raise TypeError("profile-download hook must be callable")
        if getattr(self, "_profile_download_hooks", None) is None:
            self._profile_download_hooks = []
        self._profile_download_hooks.append(callback)

    def unregister_profile_download_hook(
        self,
        callback,
    ) -> None:
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

        if ins == 0xA4:
            return self.fs.select(data, p1=p1, p2=p2)
        if ins == 0xB0:
            return self.fs.read_binary(p1=p1, p2=p2, le=le_value)
        if ins == 0xB2:
            return self.fs.read_record(record_number=p1, p2=p2, le=le_value)
        if ins == 0xD6:
            offset = (p1 << 8) | p2
            return self.fs.update_binary(offset=offset, payload=data)
        if ins == 0xDC:
            return self.fs.update_record(record_number=p1, payload=data)
        if ins == 0x20:
            return self.naa.verify(p2, data)
        if ins == 0x2C:
            return self.naa.unblock_chv(p2, data)
        if ins == 0x88:
            return self.auth.internal_authenticate(p2, data)
        if ins == 0x50 and (cla & 0x80):
            return self.scp03.handle_initialize_update(p1, data)
        if ins == 0x82 and (cla & 0x80):
            return self.scp03.handle_external_authenticate(p1, data)
        if ins == 0xCA:
            return self.gp.handle_get_data(p1, p2)
        if ins == 0xF2:
            # ETSI TS 102 223 STK STATUS uses P1 in (0x00, 0x01) for
            # polling / location-change notifications. GP Card Spec v2.3.1
            # §11.4 reserves P1 values 0x02, 0x10, 0x20, 0x40, 0x80 for
            # registry scopes (ISD, Applications, ELF, etc.). Split the
            # dispatch so toolkit STATUS does not swallow GP GET STATUS
            # unless the APDU is actually an STK polling command.
            is_gp_status = p1 not in (0x00, 0x01)
            if (cla & 0x80) and self.toolkit.should_handle_status() and is_gp_status is False:
                return self.toolkit.handle_status(p1, p2, data)
            if is_gp_status and (cla & 0x80) != 0 and self.state.scp03_session.authenticated is False:
                return b"", 0x69, 0x82
            return self.gp.handle_get_status(p1, p2, data)
        if ins == 0xE2:
            return self._handle_store_data(p1, p2, data)
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
        (0x80..0x8F, channels 0-3 with optional SCP SM), and the
        first-interindustry extended range for channels 4-19
        (0x40..0x7F). Anything else is rejected with `6E 00` per ISO
        7816-4 §5.4.1, rather than falling through to a misleading
        `6D 00`.
        """
        value = int(cla) & 0xFF
        if 0x00 <= value <= 0x0F:
            return True
        if 0x40 <= value <= 0x7F:
            return True
        if 0x80 <= value <= 0x8F:
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
