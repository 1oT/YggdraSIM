from __future__ import annotations

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
from SIMCARD.utils import parse_apdu
from yggdrasim_common.card_backend import (
    get_sim_eim_identity_path,
    get_sim_euicc_store_root,
    get_sim_isdr_config_path,
    get_sim_profile_store_path,
    get_sim_quirks_path,
)


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
        self.scp03 = Scp03CardLogic(self.state)
        self.gp = GpLogic(self.state)
        self.sgp = SgpLogic(self.state, sim_eim_identity_path=selected_sim_eim_identity_path)
        self.scp80 = Scp80Logic(self.state)
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
            except Exception:
                pass
        try:
            sync_profiles_to_store(str(self.state.profile_store_path or "").strip(), self.state.profiles)
        except Exception:
            pass

    def reset(self) -> None:
        self.fs.reset()
        self.naa.reset()
        self.scp03.reset()
        self.sgp.reset()
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
        except Exception:
            result = (b"", 0x6F, 0x00)

        for hook in self.quirks.after_apdu_hooks:
            overridden = hook(command, result, self.state)
            if overridden is not None:
                result = overridden
        return result

    def _dispatch(self, parsed: dict[str, int | bytes | None]) -> ApduResult:
        cla = int(parsed["cla"])
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        data = bytes(parsed["data"] or b"")
        le = parsed["le"]
        le_value = None if le is None else int(le)

        if ins == 0xA4:
            return self.fs.select(data)
        if ins == 0xB0:
            offset = (p1 << 8) | p2
            return self.fs.read_binary(offset=offset, le=le_value)
        if ins == 0xB2:
            return self.fs.read_record(record_number=p1, le=le_value)
        if ins == 0xD6:
            offset = (p1 << 8) | p2
            return self.fs.update_binary(offset=offset, payload=data)
        if ins == 0xDC:
            return self.fs.update_record(record_number=p1, payload=data)
        if ins == 0x20:
            return self.naa.verify(p2, data)
        if ins == 0x50 and (cla & 0x80):
            return self.scp03.handle_initialize_update(p1, data)
        if ins == 0x82 and (cla & 0x80):
            return self.scp03.handle_external_authenticate(p1, data)
        if ins == 0xCA:
            return self.gp.handle_get_data(p1, p2)
        if ins == 0xF2:
            return self.gp.handle_get_status(p1, p2, data)
        if ins == 0xE2:
            return self._handle_store_data(p1, p2, data)
        if ins == 0xC2:
            return self.scp80.handle_envelope(data)
        if ins == 0x10 and (cla & 0x80):
            return b"", 0x90, 0x00
        if ins == 0x12 and (cla & 0x80):
            if len(self.state.pending_fetch_queue) == 0:
                return b"", 0x6A, 0x86
            payload = self.state.pending_fetch_queue.pop(0)
            return payload, 0x90, 0x00
        if ins == 0x14 and (cla & 0x80):
            return b"", 0x90, 0x00
        if ins == 0x70:
            return b"", 0x68, 0x81
        return b"", 0x6D, 0x00

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
        return self.sgp.handle_store_data(normalized)
