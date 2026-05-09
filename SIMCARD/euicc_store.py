# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eUICC profile store: on-disk JSON persistence for installed profiles and associated metadata."""
from __future__ import annotations

import os
from typing import Any

from SIMCARD.etsi_fs import apply_security_domain_config
from SIMCARD.state import SimCardState, SimEimEntry, SimEuiccPackageResultEntry
from yggdrasim_common.inventory_crypto import read_secret_json_file, write_secret_json_file

STORE_VERSION = 1
EUICC_MANIFEST_FILENAME = "euicc.json"
PROFILES_DIRNAME = "profiles"


def resolve_euicc_store_path(root_path: str, eid: str) -> str:
    """Resolve and return the absolute path of the eUICC profile store directory."""
    raw_root = str(root_path or "").strip()
    if len(raw_root) == 0:
        return ""
    normalized_root = os.path.abspath(os.path.expanduser(raw_root))
    os.makedirs(normalized_root, exist_ok=True)
    eid_text = str(eid or "").strip().upper()
    if len(eid_text) == 0:
        eid_text = "UNKNOWN"
    return os.path.join(normalized_root, f"EID_{eid_text}")


def default_profile_store_path(euicc_store_path: str) -> str:
    raw_path = str(euicc_store_path or "").strip()
    if len(raw_path) == 0:
        return ""
    normalized = os.path.abspath(os.path.expanduser(raw_path))
    return os.path.join(normalized, PROFILES_DIRNAME)


def euicc_store_exists(euicc_store_path: str) -> bool:
    """Return True when the eUICC profile store directory exists and contains at least one profile."""
    raw_path = str(euicc_store_path or "").strip()
    if len(raw_path) == 0:
        return False
    manifest_path = os.path.join(
        os.path.abspath(os.path.expanduser(raw_path)),
        EUICC_MANIFEST_FILENAME,
    )
    return os.path.isfile(manifest_path)


def sync_euicc_store(state: SimCardState) -> None:
    """Write current in-memory profile state back to the eUICC profile store directory."""
    raw_path = str(state.euicc_store_path or "").strip()
    if len(raw_path) == 0:
        return
    store_path = os.path.abspath(os.path.expanduser(raw_path))
    os.makedirs(store_path, exist_ok=True)
    manifest_path = os.path.join(store_path, EUICC_MANIFEST_FILENAME)
    write_secret_json_file(manifest_path, _serialize_state(state))


def load_euicc_store_into_state(store_path: str, state: SimCardState) -> bool:
    """Load the eUICC store from disk into the simulator state."""
    raw_path = str(store_path or "").strip()
    if len(raw_path) == 0:
        return False
    manifest_path = os.path.join(
        os.path.abspath(os.path.expanduser(raw_path)),
        EUICC_MANIFEST_FILENAME,
    )
    if os.path.isfile(manifest_path) is False:
        return False
    payload = read_secret_json_file(
        manifest_path,
        protect_plaintext_on_read=True,
    )
    if isinstance(payload, dict) is False:
        return False
    # The runtime cache must not shadow card-identity fields. Identity
    # (ATR, EID, default DP address, root CI PKID, ISDR/ECASD/MNO_SD AIDs
    # and labels) is operator configuration and comes from
    # ``isdr_config.json`` / quirks. Persisting it back here would mean a
    # stale cache pins a value forever and silently overrides any later
    # change in ``isdr_config.json`` — which is what bit the simulated
    # ATR after the ISO 7816-3 fix landed.
    apply_euicc_state_payload(state, payload, apply_identity=False)
    return True


def _serialize_state(state: SimCardState) -> dict[str, Any]:
    return {
        "store_version": STORE_VERSION,
        "eid": str(state.eid).strip().upper(),
        "atr_hex": bytes(state.atr or b"").hex().upper(),
        "default_dp_address": str(state.default_dp_address).strip(),
        "root_ci_pkid_hex": bytes(state.root_ci_pkid or b"").hex().upper(),
        "isdr": {
            "aid": str(state.isdr_aid).strip().upper(),
            "label": str(state.isdr_label).strip(),
        },
        "ecasd": {
            "aid": str(state.ecasd_aid).strip().upper(),
            "label": str(state.ecasd_label).strip(),
        },
        "mno_sd": {
            "aid": str(state.mno_sd_aid).strip().upper(),
            "label": str(state.mno_sd_label).strip(),
        },
        "euicc_info": {
            "info1_svn_hex": bytes(state.euicc_info.info1_svn).hex().upper(),
            "profile_version_hex": bytes(state.euicc_info.profile_version).hex().upper(),
            "svn_hex": bytes(state.euicc_info.svn).hex().upper(),
            "firmware_version_hex": bytes(state.euicc_info.firmware_version).hex().upper(),
            "ts102241_version_hex": bytes(state.euicc_info.ts102241_version).hex().upper(),
            "globalplatform_version_hex": bytes(state.euicc_info.globalplatform_version).hex().upper(),
            "uicc_capability_bits": list(state.euicc_info.uicc_capability_bits),
            "rsp_capability_bits": list(state.euicc_info.rsp_capability_bits),
            "euicc_category": int(state.euicc_info.euicc_category),
            "forbidden_profile_policy_bits": list(state.euicc_info.forbidden_profile_policy_bits),
            "pp_version_hex": bytes(state.euicc_info.pp_version).hex().upper(),
            "sas_accreditation_number": str(state.euicc_info.sas_accreditation_number),
            "ipa_mode": int(state.euicc_info.ipa_mode),
            "ext_card_resources": {
                "system_apps_count": int(state.euicc_info.ext_card_resources.system_apps_count),
                "free_nvm": int(state.euicc_info.ext_card_resources.free_nvm),
                "free_ram": int(state.euicc_info.ext_card_resources.free_ram),
            },
            "iot_specific_info": {
                "iot_versions_hex": [bytes(item).hex().upper() for item in state.euicc_info.iot_specific_info.iot_versions],
                "ecall_supported": bool(state.euicc_info.iot_specific_info.ecall_supported),
                "fallback_supported": bool(state.euicc_info.iot_specific_info.fallback_supported),
            },
            "additional_pp_versions_hex": [
                bytes(item).hex().upper() for item in state.euicc_info.additional_pp_versions
            ],
        },
        "configured_data": {
            "root_smds_address": str(state.configured_data.root_smds_address),
            "additional_root_smds_addresses": list(state.configured_data.additional_root_smds_addresses),
            "allowed_ci_pkids_hex": [bytes(item).hex().upper() for item in state.configured_data.allowed_ci_pkids],
            "ci_list_hex": [bytes(item).hex().upper() for item in state.configured_data.ci_list],
        },
        "eim_entries": [
            {
                "eim_id": str(entry.eim_id),
                "eim_fqdn": str(entry.eim_fqdn),
                "eim_id_type": int(entry.eim_id_type),
                "counter_value": int(entry.counter_value),
                "association_token": int(entry.association_token),
                "supported_protocol_bits": list(entry.supported_protocol_bits),
                "euicc_ci_pkid_hex": bytes(entry.euicc_ci_pkid).hex().upper(),
                "indirect_profile_download": bool(entry.indirect_profile_download),
                "eim_public_key_data_hex": bytes(entry.eim_public_key_data).hex().upper(),
                "trusted_tls_public_key_data_hex": bytes(entry.trusted_tls_public_key_data).hex().upper(),
            }
            for entry in state.eim_entries
        ],
        "eum_certificate_der_hex": bytes(state.eum_certificate_der or b"").hex().upper(),
        "euicc_certificate_der_hex": bytes(state.euicc_certificate_der or b"").hex().upper(),
        "scp03_keys": {
            "kenc_hex": bytes(state.scp03_keys.kenc).hex().upper(),
            "kmac_hex": bytes(state.scp03_keys.kmac).hex().upper(),
            "dek_hex": bytes(state.scp03_keys.dek).hex().upper(),
            "kvn": int(state.scp03_keys.kvn),
        },
        "scp80_security": {
            "spi": str(state.scp80_security.spi),
            "kic": str(state.scp80_security.kic),
            "kid": str(state.scp80_security.kid),
            "tar": str(state.scp80_security.tar),
            "key_enc_hex": bytes(state.scp80_security.key_enc).hex().upper(),
            "key_mac_hex": bytes(state.scp80_security.key_mac).hex().upper(),
        },
        "euicc_package_results": [
            {
                "seq_number": int(entry.seq_number),
                "eim_id": str(entry.eim_id),
                "counter_value": int(entry.counter_value),
                "eim_transaction_id_hex": bytes(entry.eim_transaction_id or b"").hex().upper(),
                "payload_hex": bytes(entry.payload or b"").hex().upper(),
            }
            for entry in state.euicc_package_results
        ],
        "association_token_counter": int(state.association_token_counter),
        "next_notification_seq": int(state.next_notification_seq),
        "immediate_enable": {
            "flag": bool(state.immediate_enable_flag),
            "smdp_oid": str(state.immediate_enable_smdp_oid),
            "smdp_address": str(state.immediate_enable_smdp_address),
        },
        "previous_enabled_aid": str(state.previous_enabled_aid).strip().upper(),
        "emergency_profile": {
            "active": bool(state.emergency_profile_active),
            "pre_aid": str(state.emergency_pre_aid).strip().upper(),
        },
        # ETSI TS 102 223 STK polling configuration. ``poll_strategy``
        # selects the proactive bring-up shape ("timer" /
        # "poll_interval" / "both" / "off"); ``timer_management_*``
        # parameters drive the §6.6.21 TIMER MANAGEMENT START used by
        # the SGP.32 IPA-poll trigger.
        "toolkit": {
            "poll_strategy": str(state.toolkit.poll_strategy or "timer"),
            "timer_management_seconds": int(state.toolkit.timer_management_seconds),
            "timer_management_id": int(state.toolkit.timer_management_id),
            "timer_management_auto_rearm": bool(state.toolkit.timer_management_auto_rearm),
            "poll_interval_seconds": int(state.toolkit.poll_interval_seconds),
            "provide_imei": bool(state.toolkit.provide_imei),
            "ipa_poll": {
                "enabled": bool(state.toolkit.ipa_poll_enabled),
                "eim_fqdn": str(state.toolkit.ipa_poll_eim_fqdn or ""),
                "eim_port": int(state.toolkit.ipa_poll_eim_port),
                "transport_type": int(state.toolkit.ipa_poll_transport_type),
                "buffer_size": int(state.toolkit.ipa_poll_buffer_size),
                "receive_size": int(state.toolkit.ipa_poll_receive_size),
                "alpha_id": str(state.toolkit.ipa_poll_alpha_id or ""),
                "request_payload_hex": bytes(state.toolkit.ipa_poll_request_payload or b"").hex().upper(),
            },
        },
    }


def apply_euicc_state_payload(
    state: SimCardState,
    payload: dict[str, Any],
    *,
    apply_identity: bool = True,
) -> None:
    """Merge a serialized eUICC manifest into ``state``.

    ``apply_identity`` controls whether identity fields (ATR, EID,
    default DP address, root CI PKID, ISDR/ECASD/MNO_SD AIDs and labels)
    are honoured. Operator configuration loaders (e.g. the
    ``isdr_config.json`` reader) call with the default ``True`` because
    those files are the authoritative identity source. The runtime
    eUICC store loader passes ``False`` so a previously persisted
    snapshot can never shadow a fresher identity coming from
    ``isdr_config.json`` or quirks. See ``load_euicc_store_into_state``
    for the rationale.
    """
    if apply_identity:
        if "eid" in payload:
            state.eid = str(payload.get("eid", state.eid)).strip().upper() or state.eid
        if "atr_hex" in payload:
            state.atr = _hex_bytes(payload.get("atr_hex"), fallback=bytes(state.atr))
        if "default_dp_address" in payload:
            state.default_dp_address = str(payload.get("default_dp_address", state.default_dp_address)).strip()
        if "root_ci_pkid_hex" in payload:
            state.root_ci_pkid = _hex_bytes(payload.get("root_ci_pkid_hex"), fallback=bytes(state.root_ci_pkid))
        isdr = payload.get("isdr")
        if isinstance(isdr, dict):
            if "aid" in isdr:
                state.isdr_aid = str(isdr.get("aid", state.isdr_aid)).strip().upper() or state.isdr_aid
            if "label" in isdr:
                state.isdr_label = str(isdr.get("label", state.isdr_label)).strip() or state.isdr_label
        ecasd = payload.get("ecasd")
        if isinstance(ecasd, dict):
            if "aid" in ecasd:
                state.ecasd_aid = str(ecasd.get("aid", state.ecasd_aid)).strip().upper() or state.ecasd_aid
            if "label" in ecasd:
                state.ecasd_label = str(ecasd.get("label", state.ecasd_label)).strip() or state.ecasd_label
        mno_sd = payload.get("mno_sd")
        if isinstance(mno_sd, dict):
            if "aid" in mno_sd:
                state.mno_sd_aid = str(mno_sd.get("aid", state.mno_sd_aid)).strip().upper() or state.mno_sd_aid
            if "label" in mno_sd:
                state.mno_sd_label = str(mno_sd.get("label", state.mno_sd_label)).strip() or state.mno_sd_label

    euicc_info = payload.get("euicc_info")
    if isinstance(euicc_info, dict):
        mapping = {
            "info1_svn_hex": "info1_svn",
            "profile_version_hex": "profile_version",
            "svn_hex": "svn",
            "firmware_version_hex": "firmware_version",
            "ts102241_version_hex": "ts102241_version",
            "globalplatform_version_hex": "globalplatform_version",
            "pp_version_hex": "pp_version",
        }
        for source_key, target_attr in mapping.items():
            if source_key in euicc_info:
                setattr(
                    state.euicc_info,
                    target_attr,
                    _hex_bytes(euicc_info.get(source_key), fallback=bytes(getattr(state.euicc_info, target_attr))),
                )
        if "uicc_capability_bits" in euicc_info:
            state.euicc_info.uicc_capability_bits = [int(item) for item in euicc_info.get("uicc_capability_bits", [])]
        if "rsp_capability_bits" in euicc_info:
            state.euicc_info.rsp_capability_bits = [int(item) for item in euicc_info.get("rsp_capability_bits", [])]
        if "euicc_category" in euicc_info:
            state.euicc_info.euicc_category = int(euicc_info.get("euicc_category", state.euicc_info.euicc_category))
        if "forbidden_profile_policy_bits" in euicc_info:
            state.euicc_info.forbidden_profile_policy_bits = [
                int(item) for item in euicc_info.get("forbidden_profile_policy_bits", [])
            ]
        if "sas_accreditation_number" in euicc_info:
            state.euicc_info.sas_accreditation_number = str(
                euicc_info.get("sas_accreditation_number", state.euicc_info.sas_accreditation_number)
            )
        if "ipa_mode" in euicc_info:
            state.euicc_info.ipa_mode = int(euicc_info.get("ipa_mode", state.euicc_info.ipa_mode))
        ext_card_resources = euicc_info.get("ext_card_resources")
        if isinstance(ext_card_resources, dict):
            if "system_apps_count" in ext_card_resources:
                state.euicc_info.ext_card_resources.system_apps_count = int(
                    ext_card_resources.get("system_apps_count", state.euicc_info.ext_card_resources.system_apps_count)
                )
            if "free_nvm" in ext_card_resources:
                state.euicc_info.ext_card_resources.free_nvm = int(
                    ext_card_resources.get("free_nvm", state.euicc_info.ext_card_resources.free_nvm)
                )
            if "free_ram" in ext_card_resources:
                state.euicc_info.ext_card_resources.free_ram = int(
                    ext_card_resources.get("free_ram", state.euicc_info.ext_card_resources.free_ram)
                )
        iot_specific_info = euicc_info.get("iot_specific_info")
        if isinstance(iot_specific_info, dict):
            if "iot_versions_hex" in iot_specific_info:
                state.euicc_info.iot_specific_info.iot_versions = [
                    _hex_bytes(item, fallback=b"")
                    for item in iot_specific_info.get("iot_versions_hex", [])
                    if len(_hex_bytes(item, fallback=b"")) > 0
                ]
            if "ecall_supported" in iot_specific_info:
                state.euicc_info.iot_specific_info.ecall_supported = bool(iot_specific_info.get("ecall_supported"))
            if "fallback_supported" in iot_specific_info:
                state.euicc_info.iot_specific_info.fallback_supported = bool(
                    iot_specific_info.get("fallback_supported")
                )
        if "additional_pp_versions_hex" in euicc_info:
            state.euicc_info.additional_pp_versions = [
                _hex_bytes(item, fallback=b"")
                for item in euicc_info.get("additional_pp_versions_hex", [])
                if len(_hex_bytes(item, fallback=b"")) > 0
            ]

    configured_data = payload.get("configured_data")
    if isinstance(configured_data, dict):
        if "root_smds_address" in configured_data:
            state.configured_data.root_smds_address = str(
                configured_data.get("root_smds_address", state.configured_data.root_smds_address)
            )
        if "additional_root_smds_addresses" in configured_data:
            state.configured_data.additional_root_smds_addresses = [
                str(item) for item in configured_data.get("additional_root_smds_addresses", [])
            ]
        if "allowed_ci_pkids_hex" in configured_data:
            state.configured_data.allowed_ci_pkids = [
                _hex_bytes(item, fallback=b"")
                for item in configured_data.get("allowed_ci_pkids_hex", [])
                if len(_hex_bytes(item, fallback=b"")) > 0
            ]
        if "ci_list_hex" in configured_data:
            state.configured_data.ci_list = [
                _hex_bytes(item, fallback=b"")
                for item in configured_data.get("ci_list_hex", [])
                if len(_hex_bytes(item, fallback=b"")) > 0
            ]

    if isinstance(payload.get("eim_entries"), list):
        entries: list[SimEimEntry] = []
        for raw_entry in payload.get("eim_entries", []):
            if isinstance(raw_entry, dict) is False:
                continue
            eim_id = str(raw_entry.get("eim_id", "")).strip()
            if len(eim_id) == 0:
                continue
            entries.append(
                SimEimEntry(
                    eim_id=eim_id,
                    eim_fqdn=str(raw_entry.get("eim_fqdn", "")).strip(),
                    eim_id_type=int(raw_entry.get("eim_id_type", 1)),
                    counter_value=int(raw_entry.get("counter_value", 1)),
                    association_token=int(raw_entry.get("association_token", 1)),
                    supported_protocol_bits=[int(item) for item in raw_entry.get("supported_protocol_bits", [])],
                    euicc_ci_pkid=_hex_bytes(raw_entry.get("euicc_ci_pkid_hex"), fallback=b""),
                    indirect_profile_download=bool(raw_entry.get("indirect_profile_download", True)),
                    eim_public_key_data=_hex_bytes(raw_entry.get("eim_public_key_data_hex"), fallback=b""),
                    trusted_tls_public_key_data=_hex_bytes(
                        raw_entry.get("trusted_tls_public_key_data_hex"),
                        fallback=b"",
                    ),
                )
            )
        state.eim_entries = entries

    if "eum_certificate_der_hex" in payload:
        state.eum_certificate_der = _hex_bytes(payload.get("eum_certificate_der_hex"), fallback=b"")
    if "euicc_certificate_der_hex" in payload:
        state.euicc_certificate_der = _hex_bytes(payload.get("euicc_certificate_der_hex"), fallback=b"")

    scp03_keys = payload.get("scp03_keys")
    if isinstance(scp03_keys, dict):
        if "kenc_hex" in scp03_keys:
            state.scp03_keys.kenc = _hex_bytes(scp03_keys.get("kenc_hex"), fallback=bytes(state.scp03_keys.kenc))
        if "kmac_hex" in scp03_keys:
            state.scp03_keys.kmac = _hex_bytes(scp03_keys.get("kmac_hex"), fallback=bytes(state.scp03_keys.kmac))
        if "dek_hex" in scp03_keys:
            state.scp03_keys.dek = _hex_bytes(scp03_keys.get("dek_hex"), fallback=bytes(state.scp03_keys.dek))
        if "kvn" in scp03_keys:
            state.scp03_keys.kvn = int(scp03_keys.get("kvn", state.scp03_keys.kvn))

    scp80_security = payload.get("scp80_security")
    if isinstance(scp80_security, dict):
        if "spi" in scp80_security:
            state.scp80_security.spi = str(scp80_security.get("spi", state.scp80_security.spi)).strip().upper()
        if "kic" in scp80_security:
            state.scp80_security.kic = str(scp80_security.get("kic", state.scp80_security.kic)).strip().upper()
        if "kid" in scp80_security:
            state.scp80_security.kid = str(scp80_security.get("kid", state.scp80_security.kid)).strip().upper()
        if "tar" in scp80_security:
            state.scp80_security.tar = str(scp80_security.get("tar", state.scp80_security.tar)).strip().upper()
        if "key_enc_hex" in scp80_security:
            state.scp80_security.key_enc = _hex_bytes(
                scp80_security.get("key_enc_hex"),
                fallback=bytes(state.scp80_security.key_enc),
            )
        if "key_mac_hex" in scp80_security:
            state.scp80_security.key_mac = _hex_bytes(
                scp80_security.get("key_mac_hex"),
                fallback=bytes(state.scp80_security.key_mac),
            )

    if isinstance(payload.get("euicc_package_results"), list):
        package_results: list[SimEuiccPackageResultEntry] = []
        for raw_entry in payload.get("euicc_package_results", []):
            if isinstance(raw_entry, dict) is False:
                continue
            try:
                seq_number = int(raw_entry.get("seq_number", 0))
            except (TypeError, ValueError):
                continue
            if seq_number <= 0:
                continue
            package_results.append(
                SimEuiccPackageResultEntry(
                    seq_number=seq_number,
                    eim_id=str(raw_entry.get("eim_id", "")).strip(),
                    counter_value=int(raw_entry.get("counter_value", 0)),
                    eim_transaction_id=_hex_bytes(raw_entry.get("eim_transaction_id_hex"), fallback=b""),
                    payload=_hex_bytes(raw_entry.get("payload_hex"), fallback=b""),
                )
            )
        state.euicc_package_results = package_results

    if "association_token_counter" in payload:
        try:
            state.association_token_counter = max(0, int(payload.get("association_token_counter", 0)))
        except (TypeError, ValueError):
            pass
    if "next_notification_seq" in payload:
        try:
            state.next_notification_seq = max(1, int(payload.get("next_notification_seq", 1)))
        except (TypeError, ValueError):
            pass

    immediate_enable = payload.get("immediate_enable")
    if isinstance(immediate_enable, dict):
        state.immediate_enable_flag = bool(immediate_enable.get("flag", state.immediate_enable_flag))
        state.immediate_enable_smdp_oid = str(
            immediate_enable.get("smdp_oid", state.immediate_enable_smdp_oid)
        ).strip()
        state.immediate_enable_smdp_address = str(
            immediate_enable.get("smdp_address", state.immediate_enable_smdp_address)
        ).strip()
    emergency_profile = payload.get("emergency_profile")
    if isinstance(emergency_profile, dict):
        state.emergency_profile_active = bool(
            emergency_profile.get("active", state.emergency_profile_active)
        )
        state.emergency_pre_aid = str(
            emergency_profile.get("pre_aid", state.emergency_pre_aid) or ""
        ).strip().upper()
    if "previous_enabled_aid" in payload:
        state.previous_enabled_aid = str(
            payload.get("previous_enabled_aid", state.previous_enabled_aid) or ""
        ).strip().upper()

    toolkit = payload.get("toolkit")
    if isinstance(toolkit, dict):
        # ETSI TS 102 223 §6.6.21 TIMER MANAGEMENT vs §6.6.5 POLL
        # INTERVAL bring-up selector. The default ``"timer"`` strategy
        # arms an ME timer that the modem expires into a TIMER
        # EXPIRATION (D7) envelope so SGP.32 IPA-poll triggers fire on
        # cadence. Operators that need the legacy POLL INTERVAL
        # heartbeat can flip the strategy here without code edits.
        if "poll_strategy" in toolkit:
            strategy = str(toolkit.get("poll_strategy", state.toolkit.poll_strategy) or "").strip().lower()
            if strategy in {"timer", "poll_interval", "both", "off"}:
                state.toolkit.poll_strategy = strategy
        if "timer_management_seconds" in toolkit:
            try:
                state.toolkit.timer_management_seconds = max(
                    0, int(toolkit.get("timer_management_seconds", state.toolkit.timer_management_seconds))
                )
            except (TypeError, ValueError):
                pass
        if "timer_management_id" in toolkit:
            try:
                # ETSI TS 102 223 §6.6.21: timer identifier 1..8.
                tid = int(toolkit.get("timer_management_id", state.toolkit.timer_management_id))
                state.toolkit.timer_management_id = max(1, min(8, tid))
            except (TypeError, ValueError):
                pass
        if "timer_management_auto_rearm" in toolkit:
            state.toolkit.timer_management_auto_rearm = bool(
                toolkit.get("timer_management_auto_rearm", state.toolkit.timer_management_auto_rearm)
            )
        if "poll_interval_seconds" in toolkit:
            try:
                state.toolkit.poll_interval_seconds = max(
                    0, int(toolkit.get("poll_interval_seconds", state.toolkit.poll_interval_seconds))
                )
            except (TypeError, ValueError):
                pass
        if "provide_imei" in toolkit:
            state.toolkit.provide_imei = bool(
                toolkit.get("provide_imei", state.toolkit.provide_imei)
            )
        ipa_poll = toolkit.get("ipa_poll")
        if isinstance(ipa_poll, dict):
            # SGP.32 §3.5 IPA-poll BIP trigger configuration. Each
            # field maps onto a TLV inside the OPEN CHANNEL / SEND
            # DATA / RECEIVE DATA proactive commands enqueued on
            # every D7 TIMER EXPIRATION envelope.
            if "enabled" in ipa_poll:
                state.toolkit.ipa_poll_enabled = bool(
                    ipa_poll.get("enabled", state.toolkit.ipa_poll_enabled)
                )
            if "eim_fqdn" in ipa_poll:
                state.toolkit.ipa_poll_eim_fqdn = str(
                    ipa_poll.get("eim_fqdn", state.toolkit.ipa_poll_eim_fqdn) or ""
                ).strip()
            if "eim_port" in ipa_poll:
                try:
                    port_value = int(ipa_poll.get("eim_port", state.toolkit.ipa_poll_eim_port))
                    state.toolkit.ipa_poll_eim_port = max(1, min(0xFFFF, port_value))
                except (TypeError, ValueError):
                    pass
            if "transport_type" in ipa_poll:
                try:
                    transport = int(ipa_poll.get("transport_type", state.toolkit.ipa_poll_transport_type))
                    state.toolkit.ipa_poll_transport_type = transport & 0xFF
                except (TypeError, ValueError):
                    pass
            if "buffer_size" in ipa_poll:
                try:
                    state.toolkit.ipa_poll_buffer_size = max(
                        0x40,
                        min(0xFFFF, int(ipa_poll.get("buffer_size", state.toolkit.ipa_poll_buffer_size))),
                    )
                except (TypeError, ValueError):
                    pass
            if "receive_size" in ipa_poll:
                try:
                    state.toolkit.ipa_poll_receive_size = max(
                        1,
                        min(0xFF, int(ipa_poll.get("receive_size", state.toolkit.ipa_poll_receive_size))),
                    )
                except (TypeError, ValueError):
                    pass
            if "alpha_id" in ipa_poll:
                state.toolkit.ipa_poll_alpha_id = str(
                    ipa_poll.get("alpha_id", state.toolkit.ipa_poll_alpha_id) or ""
                )
            if "request_payload_hex" in ipa_poll:
                state.toolkit.ipa_poll_request_payload = _hex_bytes(
                    ipa_poll.get("request_payload_hex", b""),
                    fallback=state.toolkit.ipa_poll_request_payload,
                )

    apply_security_domain_config(state)


def _hex_bytes(value: Any, *, fallback: bytes) -> bytes:
    text = str(value or "").strip().replace(" ", "").replace(":", "").replace("-", "")
    if len(text) == 0:
        return bytes(fallback)
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError:
        return bytes(fallback)
