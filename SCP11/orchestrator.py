# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 orchestrator: sequences ES2+ / ES9+ / ES8+ calls for download, install, enable, disable, and delete operations."""
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Canonical SCP11 orchestrator.

This module is the ``canonical`` SCP11 orchestrator tree for YggdraSIM v1.
Bug-fixes, spec-correctness work, and API additions should land here first.
``SCP11/live/orchestrator.py`` and ``SCP11/test/orchestrator.py`` mirror this
implementation with variant-specific overlays (e.g. ``stk_polling`` mixin for
live, extra request shaping for the test tree) and are treated as *legacy
mirrors* for v1. Any change made here should be evaluated against both
mirrors; the long-term goal tracked by audit item ``SCP11-P1-01`` is to turn
the mirrors into thin shim packages that import from this module and only
override the variant delta.
"""

import base64
import binascii
import copy
import time
from typing import Any, Optional

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from SCP03.logic.sgp32_decode import decode_eim_configuration_entries as decode_eim_configuration_entries_shared
from SCP03.logic.sgp32_decode import decode_eim_configuration_entry as decode_eim_configuration_entry_shared
from SCP11.shared.gsma_error_codes import describe_sgp32_eim_package_error
from SCP11.shared.safe_parse import safe_parse
from yggdrasim_common.process_debug import debug_print

try:
    from .asn1_registry import ASN1Registry
    from .crypto_engine import CryptoEngine
    from .eim_packages import (
        TYPE_EUICC_CONFIGURATION,
        TYPE_INDIRECT_PROFILE_DOWNLOAD,
        TYPE_PROFILE_DOWNLOAD_TRIGGER,
        TYPE_PROFILE_STATE_MANAGEMENT,
        parse_eim_package,
    )
    from .models import (
        AuthenticateClientRequest,
        BACKEND_MODE_LOCAL_SGP26,
        CancelSessionRequest,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        SCP11SessionState,
    )
    from .payload_builder import PayloadBuilder
    from .pysim_support import (
        decode_certificate,
        decode_authenticate_server_response,
        decode_initialise_secure_channel_request as decode_initialise_secure_channel_request_pysim,
        decode_list_notification_response,
        decode_pending_notification,
        decode_prepare_download_response,
        decode_retrieve_notifications_list_response,
        encode_cancel_session_request,
        encode_notification_sent_request,
        extract_euicc_signed1,
        extract_euicc_signed2,
        get_certificate_authority_key_identifier,
        verify_certificate_against_ca_bundle,
    )
except ImportError:
    from asn1_registry import ASN1Registry
    from crypto_engine import CryptoEngine
    from eim_packages import (
        TYPE_EUICC_CONFIGURATION,
        TYPE_INDIRECT_PROFILE_DOWNLOAD,
        TYPE_PROFILE_DOWNLOAD_TRIGGER,
        TYPE_PROFILE_STATE_MANAGEMENT,
        parse_eim_package,
    )
    from models import (
        AuthenticateClientRequest,
        BACKEND_MODE_LOCAL_SGP26,
        CancelSessionRequest,
        EimPollRequest,
        EimPollResponse,
        GetBoundProfilePackageRequest,
        HandleNotificationRequest,
        InitiateAuthenticationRequest,
        SCP11SessionState,
    )
    from payload_builder import PayloadBuilder
    from pysim_support import (
        decode_certificate,
        decode_authenticate_server_response,
        decode_initialise_secure_channel_request as decode_initialise_secure_channel_request_pysim,
        decode_list_notification_response,
        decode_pending_notification,
        decode_prepare_download_response,
        decode_retrieve_notifications_list_response,
        encode_cancel_session_request,
        encode_notification_sent_request,
        extract_euicc_signed1,
        extract_euicc_signed2,
        get_certificate_authority_key_identifier,
        verify_certificate_against_ca_bundle,
    )


class SGP22Orchestrator:
    """Phase-based SCP11/SGP.22 orchestration with pluggable transport/provider."""

    CANCEL_SESSION_REASON_END_USER_REJECTION = 0
    CANCEL_SESSION_REASON_POSTPONED = 1
    CANCEL_SESSION_REASON_TIMEOUT = 2
    CANCEL_SESSION_REASON_PPR_NOT_ALLOWED = 3

    def __init__(self, cfg: Any, apdu_channel: Any, profile_provider: Optional[Any] = None):
        self.cfg = cfg
        self.apdu_channel = apdu_channel
        self.profile_provider = profile_provider
        self.state = SCP11SessionState()
        self.cert_auth = None
        self.key_auth = None
        self.cert_pb = None
        self.key_pb = None
        self._local_credentials_loaded = False
        self._use_stk_mode_for_es10b_store_data = False
        self._es10b_logical_channel = 0
        # Set True once any configured eIM entry successfully reaches the
        # server during ``run_eim_poll``. Consumed by the console layer to
        # gate the post-download notification auto-clear sweep: if nothing
        # was delivered server-side, on-card notifications must be kept.
        self._last_eim_poll_reached_server = False
        # SGP.22 §5.6.4: pending profile-state notifications MUST be
        # forwarded to the recipient SM-DP+ via ES9+.HandleNotification
        # before being removed from the eUICC queue. Track whether the
        # most recent _sync_pending_notifications call actually
        # completed the listNotifications round-trip; the console layer
        # reads this to decide whether the post-command auto-clear is
        # safe to run. ``None`` means "no sync attempted in this
        # command", ``True`` means "sync ran and either drained the
        # queue or saw it empty", ``False`` means "sync failed before
        # reaching the queue (notifications must NOT be deleted)".
        self._last_notification_sync_succeeded: Optional[bool] = None

    def run_flow(self, matching_id: str = "", smdp_address: Optional[str] = None) -> None:
        """Execute the full SGP.22 ES2+/ES9+/ES8+ profile download flow for one EID target."""
        effective_smdp_address = smdp_address
        if effective_smdp_address is None:
            effective_smdp_address = self.cfg.RSP_SERVER_URL

        print("--- IOT / SGP.22 TOOL - RELAY READY ---")
        self._phase_connect()
        self._phase_load_credentials()
        auth_seed = self._phase_authentication_seed(
            matching_id=matching_id,
            smdp_address=effective_smdp_address,
        )
        self._phase_authenticate_server(auth_seed, matching_id=matching_id)
        self._phase_prepare_download(smdp_address=effective_smdp_address)
        bpp_ready = self._phase_get_bound_profile_package(smdp_address=effective_smdp_address)
        try:
            install_complete = self._phase_install_package()
        except Exception as error:
            if bpp_ready:
                self._attempt_install_failure_cleanup(error)
            raise
        if bpp_ready and install_complete:
            print("\n[SUCCESS] Sequence Completed.")
            return
        print("\n[*] Sequence completed without profile installation.")

    def run_eim_poll(self, matching_id: str = "", entry_index: Optional[int] = None) -> None:
        """Drive one IPA-poll round: GetBoundProfilePackage → ES8+ STORE-DATA delivery (SGP.32 §3.2)."""
        debug_print("--- IOT / SGP.32 eIM POLL - RELAY READY ---")
        self._last_eim_poll_reached_server = False
        self._phase_connect()
        self._phase_eim_card_challenge()
        entry_indices = self._resolve_eim_poll_entry_indices(entry_index)
        total_entries = len(entry_indices)
        if total_entries > 1:
            print(f"[*] eIM poll: {total_entries} configured entry(s) to poll.")
        for ordinal, current_entry_index in enumerate(entry_indices, start=1):
            request = None
            try:
                request = self._build_eim_poll_request(
                    matching_id=matching_id, entry_index=current_entry_index
                )
                self._run_single_eim_poll_round(request)
                self._last_eim_poll_reached_server = True
                self._print_eim_poll_entry_summary(ordinal, total_entries, current_entry_index, request)
            except Exception as error:
                # Multi-entry resilience: keep the overall DOWNLOAD flow
                # progressing on per-entry failures (TLS pin mismatch, DNS,
                # HTTP) so post-flow steps like notification sync still run.
                # Console gates its auto-clear sweep on
                # ``_last_eim_poll_reached_server``. For a single configured
                # entry we re-raise so that the failure surfaces to the
                # caller; otherwise the operator gets a silent no-op.
                fqdn_text = ""
                if request is not None:
                    fqdn_text = str(getattr(request, "eim_fqdn", "") or "").strip()
                if len(fqdn_text) > 0:
                    label_text = f"index={current_entry_index}, fqdn={fqdn_text}"
                else:
                    label_text = f"index={current_entry_index}"
                error_text = str(error).strip()
                if total_entries > 1:
                    print(
                        "[!] eIM entry failed; continuing with next configured "
                        f"entry: {label_text}"
                    )
                else:
                    print(f"[!] eIM entry failed: {label_text}")
                if len(error_text) > 0:
                    print(f"    reason: {error_text}")
                if total_entries <= 1:
                    raise

    def _run_single_eim_poll_round(self, request: EimPollRequest) -> None:
        poll_round = 1
        pending_response = None
        max_rounds = int(getattr(self.cfg, "EIM_MAX_POLL_ROUNDS", 16) or 16)
        if max_rounds <= 0:
            max_rounds = 16
        while poll_round <= max_rounds:
            if pending_response is None:
                response = self._get_eim_package(request)
            else:
                response = pending_response
                pending_response = None
            self._log_eim_poll_round(response, poll_round)
            if len(response.transaction_id) > 0:
                request.transaction_id = response.transaction_id

            if len(response.euicc_package_list) == 0:
                if response.eim_result_code == 1:
                    debug_print("[*] eIM returned noEimPackageAvailable.")
                elif response.eim_result_code == 127:
                    raise RuntimeError(
                        "eIM GetEimPackage failed with undefinedError(127); "
                        "live endpoint accepted the request family but did not return any packages."
                    )
                clear_ack = getattr(self.cfg, "EIM_CLEAR_ACK_ON_NO_PACKAGE", False)
                if clear_ack:
                    clear_request = copy.deepcopy(request)
                    if len(response.transaction_id) > 0:
                        clear_request.transaction_id = response.transaction_id
                    err_hex = getattr(
                        self.cfg, "EIM_CLEAR_ACK_GENERIC_ERROR_HEX", ""
                    ).strip().replace(" ", "")
                    clear_payload = b""
                    if len(err_hex) > 0:
                        try:
                            clear_payload = bytes.fromhex(err_hex)
                        except ValueError:
                            clear_payload = b""
                    else:
                        clear_payload = self._build_provide_eim_package_result_error_tlv(127)
                    clear_request.euicc_package_result = ""
                    clear_request.raw_body = clear_payload
                    debug_print(
                        "[*] Sending eIM clear ack (no packages)"
                        + (" with ProvideEimPackageResult error" if len(clear_payload) > 0 else "")
                        + " to close transaction."
                    )
                    provide_response = self._provide_eim_package_result(clear_request)
                    normalized_response = self._coerce_eim_poll_response(provide_response)
                    if self._has_eim_poll_follow_up(normalized_response):
                        pending_response = normalized_response
                        poll_round += 1
                        continue
                if response.polling_complete:
                    debug_print("[+] eIM polling completed.")
                    return
                if response.retry_after_seconds > 0:
                    time.sleep(response.retry_after_seconds)
                poll_round += 1
                continue

            follow_up_response = None
            completion_response = response
            for package_index, package_text in enumerate(response.euicc_package_list, start=1):
                package_bytes = self._decode_string_payload(package_text)
                if len(package_bytes) == 0:
                    raise RuntimeError(
                        f"eIM package {package_index} in poll round {poll_round} was empty after decode."
                    )
                card_response = self._relay_eim_package_to_card(
                    package_bytes,
                    poll_round=poll_round,
                    package_index=package_index,
                )
                if len(card_response) == 0:
                    raise RuntimeError("eIM polling requires a card package result, but the last relay response was empty.")
                provide_result = self._build_provide_eim_package_result_tlv(
                    card_response,
                    eid=request.eid,
                )
                provide_request = copy.deepcopy(request)
                provide_request.euicc_package_result = ""
                provide_request.raw_body = provide_result
                if len(response.transaction_id) > 0:
                    provide_request.transaction_id = response.transaction_id
                print(
                    f"[*] Sending eIM package result to server for package {package_index} "
                    f"in poll round {poll_round}."
                )
                provide_response = self._provide_eim_package_result(provide_request)
                normalized_response = self._normalize_provide_eim_package_result_response(
                    provide_response,
                    card_response,
                    transaction_id=(response.transaction_id or request.transaction_id),
                )
                completion_response = normalized_response
                if self._has_eim_poll_follow_up(normalized_response):
                    follow_up_response = normalized_response

            poll_round += 1
            if follow_up_response is not None:
                pending_response = follow_up_response
                continue
            if completion_response.polling_complete:
                debug_print("[+] eIM polling completed.")
                return
            if completion_response.retry_after_seconds > 0:
                time.sleep(completion_response.retry_after_seconds)
        raise RuntimeError("eIM polling exceeded maximum follow-up rounds without completion.")

    def _log_eim_poll_round(self, response: EimPollResponse, poll_round: int) -> None:
        self._last_eim_poll_response = response
        debug_print(
            f"[*] eIM poll round {poll_round}: "
            f"packages={len(response.euicc_package_list)} complete={response.polling_complete}"
        )
        if len(response.transaction_id) > 0:
            debug_print(f"[*] eIM transactionId: {response.transaction_id}")
        if response.eim_result_code is not None:
            debug_print(
                "[*] GetEimPackage result code: "
                f"{describe_sgp32_eim_package_error(int(response.eim_result_code))} [SGP.32]"
            )
        if response.package_format == "eimAcknowledgements":
            if len(response.ack_sequence_numbers) > 0:
                debug_print(
                    "[*] ProvideEimPackageResult acknowledgement: seqNumber(s)="
                    + ", ".join(str(item) for item in response.ack_sequence_numbers)
                )
            else:
                debug_print("[*] ProvideEimPackageResult acknowledgement: empty BF53.")

    def _print_eim_poll_entry_summary(
        self,
        ordinal: int,
        total_entries: int,
        entry_index: int,
        request: Optional[EimPollRequest],
    ) -> None:
        # Compact one-liner so the operator can scan drain results at a
        # glance even with the phase/round debug chatter suppressed.
        last_response = getattr(self, "_last_eim_poll_response", None)
        fqdn = ""
        if request is not None:
            fqdn = str(getattr(request, "eim_fqdn", "") or "").strip()
        label_text = fqdn if len(fqdn) > 0 else f"index={entry_index}"
        result_text = ""
        package_count = 0
        complete_flag = False
        if last_response is not None:
            package_count = len(getattr(last_response, "euicc_package_list", []) or [])
            complete_flag = bool(getattr(last_response, "polling_complete", False))
            result_code = getattr(last_response, "eim_result_code", None)
            if result_code is not None:
                result_text = describe_sgp32_eim_package_error(int(result_code))
        parts: list[str] = []
        if total_entries > 1:
            parts.append(f"[{ordinal}/{total_entries}]")
        parts.append(label_text)
        suffix_parts: list[str] = []
        if len(result_text) > 0:
            suffix_parts.append(result_text)
        suffix_parts.append(f"packages={package_count}")
        if complete_flag:
            suffix_parts.append("complete")
        print(f"[*] eIM poll {' '.join(parts)} -> {', '.join(suffix_parts)}")

    def _phase_connect(self) -> None:
        debug_print("\n[*] Phase: Connect")
        self._use_stk_mode_for_es10b_store_data = False
        if bool(getattr(self.cfg, "RESET_CARD_BEFORE_FLOW", False)):
            reset_method = getattr(self.apdu_channel, "reset", None)
            if callable(reset_method):
                try:
                    did_reset = bool(reset_method())
                    if did_reset:
                        debug_print("[*] Card transport reset before flow start.")
                except Exception as error:
                    debug_print(f"[*] Card transport reset skipped ({error}).")
        # TS 102 221 §11.1.19 TERMINAL CAPABILITY: declare extended logical
        # channels (tag 0x82) and eUICC support (tag 0x84) on the very first
        # call. Some eUICC stacks gate ES10 STORE DATA on the eUICC bit and
        # latch the first TERMINAL CAPABILITY they receive, so a stripped
        # body sent first then "fixed" later does not recover -- ES10 keeps
        # returning 6985 (Conditions of use not satisfied).
        try:
            self.apdu_channel.send(
                bytes.fromhex("80AA00000DA90B8100820101830107840101"),
                "INIT: TERMINAL CAPABILITY",
            )
        except IOError:
            pass

        self._select_isd_r("INIT: SELECT ISD-R")

    def _select_isd_r(self, log_name: str) -> None:
        select_apdu = b"\x00\xA4\x04\x00" + bytes([len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
        self.apdu_channel.send(select_apdu, log_name)

    @staticmethod
    def _should_retry_with_stk_bootstrap(error: Exception) -> bool:
        # SGP.22 §5.7.10 ListNotifications and §5.7.13 GetEUICCInfo can
        # both surface 6985 / 6E00 / 6881 / 6882 when the card's logical
        # channel binding for ISD-R has been invalidated by a profile
        # state change (EnableProfile / DisableProfile / DeleteProfile).
        # All four status words are recoverable by reopening ISD-R on a
        # fresh logical channel — see _send_es10b_store_data_with_logical_channel_recovery.
        error_text = str(error).upper()
        if "6985" in error_text:
            return True
        if "6E00" in error_text:
            return True
        if "6881" in error_text:
            return True
        if "6882" in error_text:
            return True
        return False

    @staticmethod
    def _build_es10b_store_data_apdu(
        payload: bytes,
        p1: int = 0x91,
        p2: int = 0x00,
        cla: int = 0x80,
    ) -> bytes:
        return bytes([cla & 0xFF, 0xE2, p1 & 0xFF, p2 & 0xFF, len(payload)]) + payload

    def _send_es10b_store_data_with_stk_mode(self, payload: bytes, log_name: str) -> bytes:
        # STK-mode last-resort path. ETSI TS 102 221 §10.1.1 reserves
        # the low nibble of an 8X CLA for the active logical channel.
        # No MANAGE CHANNEL OPEN is issued in this branch -- channel 1
        # does not exist. Several eUICC OSes interpret a channel
        # selector for a non-open channel as an attempt to start GP
        # secure messaging and reject with 6882 (ISO 7816-4 §5.1.5:
        # secure messaging not supported). Sending on CLA=0x80 keeps
        # the dispatch on the basic channel where ISD-R was just
        # SELECTed.
        #
        # TERMINAL PROFILE is followed by a proactive-cycle drain
        # (TS 102 223 §6) so non-REFRESH proactive commands queued by
        # the newly-active profile's STK applets do not strand the
        # next ES10b on 6985 / 6882.
        print(f"[*] {log_name}: entering STK mode bootstrap.")
        self._reset_apdu_channel_for_recovery(log_name, "STK mode")
        self.apdu_channel.send(
            bytes.fromhex("80AA00000DA90B8100820101830107840101"),
            f"{log_name} [STK MODE TERMINAL CAPABILITY]",
        )
        self._select_isd_r(f"{log_name} [STK MODE SELECT ISD-R]")
        self._drain_proactive_after_terminal_profile(
            bytes.fromhex("80100000010C"),
            f"{log_name} [STK MODE TERMINAL PROFILE]",
        )
        response = self.apdu_channel.send(
            self._build_es10b_store_data_apdu(payload, cla=0x80),
            f"{log_name} [STK MODE BASIC]",
        )
        self._use_stk_mode_for_es10b_store_data = True
        return response

    def _reset_apdu_channel_for_recovery(self, log_name: str, attempt_label: str) -> None:
        # Mirrors the console-side fallback in
        # _send_store_data_with_logical_fallback so a stale CLA-bound
        # logical channel from a previous EnableProfile / DisableProfile
        # cannot poison the next attempt.
        reset_method = getattr(self.apdu_channel, "reset", None)
        if callable(reset_method) is False:
            return
        try:
            did_reset = bool(reset_method())
        except Exception as error:
            debug_print(f"[*] {log_name}: transport reset before {attempt_label} retry failed ({error}).")
            return
        if did_reset:
            debug_print(f"[*] {log_name}: card transport reset before {attempt_label} retry.")

    def _send_es10b_store_data_on_recovery_channel(
        self,
        payload: bytes,
        log_name: str,
    ) -> bytes:
        # Fresh MANAGE CHANNEL OPEN + SELECT ISD-R on the new channel,
        # then STATUS / TERMINAL PROFILE so eUICC stacks that gate
        # ES10b on the proactive-UICC handshake (TS 102 223 §5.4) drop
        # their 6985 ``conditions of use not satisfied'' guard. ETSI
        # TS 102 221 §11.1.17 governs MANAGE CHANNEL semantics; the
        # recovery channel is closed in finally so we do not leak
        # supplementary channels.
        open_response = self.apdu_channel.send(
            bytes.fromhex("0070000001"),
            f"{log_name} [OPEN LOGICAL CHANNEL]",
        )
        if len(open_response) == 0:
            raise RuntimeError("Logical channel open did not return a channel number.")
        channel_number = int(open_response[0])
        if channel_number <= 0 or channel_number > 3:
            raise RuntimeError(f"Unsupported logical channel returned by card: {channel_number}")
        try:
            select_cla = channel_number & 0x03
            select_apdu = (
                bytes([select_cla, 0xA4, 0x04, 0x00, len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
            )
            self.apdu_channel.send(select_apdu, f"{log_name} [SELECT ISD-R CH{channel_number}]")
            self._prime_recovery_channel_for_es10b(log_name, channel_number)
            recovery_apdu = self._build_es10b_store_data_apdu(
                payload,
                cla=(0x80 | (channel_number & 0x03)),
            )
            return self.apdu_channel.send(recovery_apdu, f"{log_name} [CH{channel_number}]")
        finally:
            try:
                close_apdu = bytes([0x00, 0x70, 0x80, channel_number & 0xFF, 0x00])
                self.apdu_channel.send(
                    close_apdu,
                    f"{log_name} [CLOSE LOGICAL CHANNEL {channel_number}]",
                )
            except Exception:
                pass

    def _prime_recovery_channel_for_es10b(self, log_name: str, channel_number: int) -> None:
        # Replay the proactive-UICC handshake the card expects on a
        # fresh session, in spec-mandated order:
        #
        # 1. TERMINAL CAPABILITY (TS 102 221 §11.1.19) -- declares
        #    extended logical channels (tag 82) and eUICC support
        #    (tag 84). MUST precede TERMINAL PROFILE.
        # 2. STATUS (TS 102 221 §11.1.2) -- refreshes the
        #    active-AID view on the supplementary channel.
        # 3. TERMINAL PROFILE + proactive cycle drain (TS 102 223
        #    §5.4 + §6) -- signals proactive-UICC capabilities and
        #    acknowledges any proactive command (SET UP MENU,
        #    POLLING OFF, DISPLAY TEXT, REFRESH) the newly-active
        #    profile's STK applets queue. Without draining, the
        #    card holds ES10b in 6985 ``conditions of use not
        #    satisfied'' until the proactive cycle is closed.
        #
        # The first two are sent best-effort: cards that have
        # already latched the corresponding state typically reply
        # 6D00 / 6E00 / 6985 to the duplicate and the recovery path
        # proceeds anyway.
        try:
            self.apdu_channel.send(
                bytes.fromhex("80AA00000DA90B8100820101830107840101"),
                f"{log_name} [TERMINAL CAPABILITY]",
            )
        except Exception as terminal_capability_error:
            debug_print(
                f"[*] {log_name}: TERMINAL CAPABILITY skipped "
                f"({terminal_capability_error})."
            )
        try:
            self.apdu_channel.send(
                bytes.fromhex("80F2000C00"),
                f"{log_name} [STATUS CH{channel_number}]",
            )
        except Exception as status_error:
            debug_print(f"[*] {log_name}: STATUS on CH{channel_number} skipped ({status_error}).")
        self._drain_proactive_after_terminal_profile(
            bytes.fromhex("80100000010C"),
            f"{log_name} [TERMINAL PROFILE CH{channel_number}]",
        )

    @staticmethod
    def _build_generic_terminal_response_apdu(fetch_data: bytes) -> bytes:
        # Build a TS 102 223 §6.6 TERMINAL RESPONSE acknowledging any
        # proactive command with a §8.12 General Result of
        # ``command performed successfully`` (0x00). The proactive
        # command is wrapped in a D0 BER-TLV; we extract the inner
        # Command Details TLV (tag 01 / 81, length 3) and Device
        # Identities TLV (tag 02 / 82, length 2) and rebuild a minimal
        # success response. Source/destination in Device Identities is
        # swapped so the response addresses the UICC (0x81) from the
        # terminal (0x82). On parse failure we fall back to a synthetic
        # body so the card still receives a syntactically valid TR and
        # the proactive cycle does not stall.
        command_details_tlv = bytes.fromhex("8103010000")
        device_identities_tlv = bytes.fromhex("82028281")
        try:
            offset = 0
            if len(fetch_data) > 1 and fetch_data[0] == 0xD0:
                length_byte = fetch_data[1]
                if length_byte & 0x80:
                    num_octets = length_byte & 0x7F
                    offset = 2 + num_octets
                else:
                    offset = 2
            pos = offset
            while pos + 1 < len(fetch_data):
                tag = fetch_data[pos]
                length = fetch_data[pos + 1]
                if tag in (0x01, 0x81) and length == 3 and pos + 5 <= len(fetch_data):
                    command_details_tlv = fetch_data[pos:pos + 5]
                elif tag in (0x02, 0x82) and length == 2 and pos + 4 <= len(fetch_data):
                    device_identities_tlv = fetch_data[pos:pos + 2] + bytes.fromhex("8281")
                pos += 2 + length
        except Exception:
            pass
        body = command_details_tlv + device_identities_tlv + bytes.fromhex("830100")
        return bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body

    def _drain_proactive_after_terminal_profile(
        self, terminal_profile_apdu: bytes, log_name: str
    ) -> None:
        # Send TERMINAL PROFILE and drain any pending proactive UICC
        # commands (TS 102 223 §6) by acknowledging each with a
        # ``command performed successfully`` TERMINAL RESPONSE.
        #
        # The PCSC / Relay channel's send() auto-handler only knows
        # how to acknowledge REFRESH; non-REFRESH proactive commands
        # (SET UP MENU registered by an STK applet on the newly-
        # active profile, POLLING OFF, DISPLAY TEXT) get raised back
        # to the orchestrator and the proactive cycle stays open on
        # the card. ES10b then returns 6985 ``conditions of use not
        # satisfied'' until the cycle is closed. This helper goes
        # through raw exchange() so it can ack any command type and
        # free the card for the next ES10b request.
        #
        # When exchange() is not exposed (test stubs that only mock
        # send()), fall back to send() so the existing test fixtures
        # continue to work.
        exchange = getattr(self.apdu_channel, "exchange", None)
        if not callable(exchange):
            try:
                self.apdu_channel.send(terminal_profile_apdu, log_name)
            except Exception as terminal_profile_error:
                debug_print(
                    f"[*] {log_name}: TERMINAL PROFILE skipped "
                    f"({terminal_profile_error})."
                )
            return
        try:
            _, sw1, sw2 = exchange(terminal_profile_apdu, log_name)
        except Exception as terminal_profile_error:
            debug_print(
                f"[*] {log_name}: TERMINAL PROFILE skipped "
                f"({terminal_profile_error})."
            )
            return
        drain_count = 0
        while sw1 == 0x91 and sw2 > 0 and drain_count < 8:
            try:
                fetch_data, fetch_sw1, fetch_sw2 = exchange(
                    bytes([0x80, 0x12, 0x00, 0x00, sw2]),
                    f"{log_name} [FETCH proactive #{drain_count + 1}]",
                )
            except Exception as fetch_error:
                debug_print(
                    f"[*] {log_name}: FETCH on proactive cycle "
                    f"#{drain_count + 1} failed ({fetch_error}); aborting drain."
                )
                return
            if fetch_sw1 != 0x90 or fetch_sw2 != 0x00:
                debug_print(
                    f"[*] {log_name}: FETCH on proactive cycle "
                    f"#{drain_count + 1} returned "
                    f"{fetch_sw1:02X}{fetch_sw2:02X}; aborting drain."
                )
                return
            terminal_response_apdu = self._build_generic_terminal_response_apdu(fetch_data)
            try:
                _, sw1, sw2 = exchange(
                    terminal_response_apdu,
                    f"{log_name} [TERMINAL RESPONSE proactive #{drain_count + 1}]",
                )
            except Exception as tr_error:
                debug_print(
                    f"[*] {log_name}: TERMINAL RESPONSE on proactive cycle "
                    f"#{drain_count + 1} failed ({tr_error})."
                )
                return
            drain_count += 1
        if drain_count > 0:
            debug_print(
                f"[*] {log_name}: drained {drain_count} proactive command(s) "
                f"after TERMINAL PROFILE."
            )

    def _send_es10b_store_data(
        self,
        payload: bytes,
        log_name: str,
        *,
        allow_stk_retry: bool = False,
    ) -> bytes:
        if self._use_stk_mode_for_es10b_store_data:
            return self._send_es10b_store_data_with_stk_mode(payload, log_name)
        apdu = self._build_es10b_store_data_apdu(payload)
        try:
            return self.apdu_channel.send(apdu, log_name)
        except Exception as error:
            if allow_stk_retry is False or self._should_retry_with_stk_bootstrap(error) is False:
                raise
            print(
                f"[*] {log_name} failed ({error}); reopening ISD-R on a fresh "
                f"logical channel and retrying."
            )
            self._reset_apdu_channel_for_recovery(log_name, "logical channel")
            self._es10b_logical_channel = 0
            try:
                return self._send_es10b_store_data_on_recovery_channel(payload, log_name)
            except Exception as logical_error:
                print(
                    f"[*] {log_name} failed on logical channel recovery ({logical_error}); "
                    f"falling back to STK mode."
                )
                try:
                    return self._send_es10b_store_data_with_stk_mode(payload, log_name)
                except Exception as stk_mode_error:
                    raise RuntimeError(
                        f"{log_name} failed ({error}); logical channel retry failed: "
                        f"{logical_error}; STK mode retry failed: {stk_mode_error}"
                    ) from stk_mode_error

    @staticmethod
    def _is_notification_list_empty_status_word(error: Exception) -> bool:
        # ``6A88`` (SW_REFERENCED_DATA_NOT_FOUND) -- some eUICC vendors
        # return it from ES10b.ListNotifications when the pending queue
        # is empty rather than encoding the empty notificationMetadataList
        # the spec suggests. Treat as a synonymous ``empty list`` marker.
        error_text = str(error).upper()
        return "6A88" in error_text

    @staticmethod
    def _should_retry_with_retrieve_notifications_fallback(error: Exception) -> bool:
        # SGP.22 §5.7.10 ListNotifications (BF28) is mandatory in v2.x+,
        # but several Gemalto / Thales eUICC OS revisions (FCI marker
        # ``GTO04M``) reject BF28 after a profile state change with
        # 6E00 ``CLA not supported`` on the basic channel and 6985
        # ``conditions of use not satisfied'' even on a clean
        # supplementary channel. The same cards still implement BF2B
        # RetrieveNotificationsList (§5.7.12), which carries the same
        # NotificationMetadata so the queue can still be enumerated.
        error_text = str(error).upper()
        return ("6E00" in error_text) or ("6985" in error_text)

    def _list_pending_notifications_with_context_recovery(self) -> bytes:
        payload = bytes.fromhex("BF2800")
        log_name = "DOWNLOAD: ListNotifications"
        try:
            return self._send_es10b_store_data(
                payload,
                log_name,
                allow_stk_retry=True,
            )
        except Exception as error:
            if self._is_notification_list_empty_status_word(error):
                debug_print(
                    f"[*] Notification sync: listNotifications returned {error}; "
                    "treating as empty pending-notification list (card quirk)."
                )
                return b""
            if self._should_retry_with_retrieve_notifications_fallback(error):
                return self._list_pending_notifications_via_retrieve_fallback(error)
            raise

    def _list_pending_notifications_via_retrieve_fallback(self, primary_error: Exception) -> bytes:
        # Card-quirk path: rebuild the BF28 NotificationMetadataList from
        # a BF2B RetrieveNotificationsList response (SGP.22 §5.7.12) so
        # eUICC OSes that refuse BF28 can still surface their pending
        # queue to the eIM forwarder.
        log_name = "DOWNLOAD: RetrieveNotificationsList (BF28 fallback)"
        print(
            f"[*] DOWNLOAD: ListNotifications rejected ({primary_error}); "
            "falling back to RetrieveNotificationsList (BF2B)."
        )
        try:
            bf2b_response = self._send_es10b_store_data(
                bytes.fromhex("BF2B00"),
                log_name,
                allow_stk_retry=True,
            )
        except Exception as bf2b_error:
            if self._is_notification_list_empty_status_word(bf2b_error):
                debug_print(
                    f"[*] {log_name}: BF2B returned {bf2b_error}; "
                    "treating as empty pending-notification list (card quirk)."
                )
                return b""
            raise RuntimeError(
                f"DOWNLOAD: ListNotifications failed ({primary_error}); "
                f"BF2B fallback also failed: {bf2b_error}"
            ) from bf2b_error
        repackaged = self._repackage_retrieve_notifications_as_metadata_list(bf2b_response)
        if len(repackaged) == 0:
            print(
                "[*] Notification sync: BF2B fallback returned no decodable "
                "metadata; treating as empty pending-notification list."
            )
        return repackaged

    def _repackage_retrieve_notifications_as_metadata_list(self, bf2b_response: bytes) -> bytes:
        # SGP.22 §5.7.12 RetrieveNotificationsListResponse:
        #   BF2B LL
        #     A0 LL                          -- notificationList CHOICE
        #       30 LL  | BF37 LL             -- PendingNotification entries
        #         ...
        #         BF2F LL                    -- NotificationMetadata
        #         ...
        #
        # SGP.22 §5.7.10 ListNotificationsResponse on success:
        #   BF28 LL
        #     A0 LL                          -- notificationMetadataList
        #       BF2F LL  BF2F LL  ...        -- direct metadata entries
        #
        # The repackager walks the BF2B body, harvests each
        # PendingNotification's nested BF2F TLV, and rewraps them inside
        # a BF28 / A0 list so the downstream NotificationMetadataList
        # decoder accepts the buffer.
        if len(bf2b_response) == 0:
            return b""
        try:
            root_tag, root_value, _, _ = self._read_tlv(bf2b_response, 0)
        except Exception:
            return b""
        if root_tag != bytes.fromhex("BF2B"):
            return b""
        metadata_entries: list[bytes] = []
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, choice_value, _, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                break
            if tag_bytes == b"\xA0":
                inner_offset = 0
                while inner_offset < len(choice_value):
                    try:
                        _, _, pending_raw, inner_next = self._read_tlv(choice_value, inner_offset)
                    except Exception:
                        break
                    bf2f_raw = self._find_first_tlv_in_value(pending_raw, bytes.fromhex("BF2F"))
                    if len(bf2f_raw) > 0:
                        metadata_entries.append(bf2f_raw)
                    inner_offset = inner_next
            offset = next_offset
        if len(metadata_entries) == 0:
            return b""
        list_value = b"".join(metadata_entries)
        list_tlv = self._wrap_tlv(b"\xA0", list_value)
        return self._wrap_tlv(bytes.fromhex("BF28"), list_tlv)

    def _phase_eim_card_challenge(self) -> None:
        debug_print("\n[*] Phase: eIM card challenge (GetEuiccChallenge)")
        challenge_response = self.apdu_channel.send(
            bytes.fromhex("80E2910003BF2E00"),
            "EIM: GetEuiccChallenge",
        )
        if len(challenge_response) >= 16:
            self.state.card_challenge = challenge_response[-16:]
            debug_print(f"[+] Card challenge: {self.state.card_challenge.hex().upper()}")
        else:
            self.state.card_challenge = b""
            print("[*] GetEuiccChallenge response too short; eIM poll will omit euiccChallenge.")

    def _resolve_eim_poll_entry_indices(self, entry_index: Optional[int]) -> list[int]:
        eim_configuration_data = self._retrieve_es10b_data(bytes.fromhex("BF5500"), "EIM: InspectEimConfigurationData")
        entries = self._decode_eim_configuration_entries(eim_configuration_data)
        if len(entries) == 0:
            raise RuntimeError("Card did not expose any BF55 eIM configuration entries.")
        if entry_index is not None:
            if entry_index < 0 or entry_index >= len(entries):
                raise ValueError(f"Requested eIM entry index {entry_index} is out of range (entries={len(entries)}).")
            return [entry_index]
        return list(range(len(entries)))

    def _eim_euicc_challenge_b64(self, challenge: bytes) -> str:
        """Encode eUICC challenge for eIM poll. If EIM_EUICC_CHALLENGE_ASN1: base64(DER(EuiccChallenge)), else raw base64."""
        if len(challenge) != 16:
            return ""
        use_asn1 = getattr(self.cfg, "EIM_EUICC_CHALLENGE_ASN1", True)
        if use_asn1:
            try:
                der = ASN1Registry.EuiccChallenge(challenge).dump()
                return base64.b64encode(der).decode("ascii")
            except Exception:
                pass
        return self._b64encode(challenge)

    def _eim_euicc_challenge_binary(self, challenge: bytes) -> bytes:
        if len(challenge) != 16:
            return b""
        return bytes(challenge)

    def _decode_eim_euicc_challenge_binary(self, value: str) -> bytes:
        raw_value = self._decode_string_payload(value)
        if len(raw_value) == 16:
            return raw_value
        try:
            tag, inner_value, _, end_offset = self._read_tlv(raw_value, 0)
        except Exception:
            return b""
        if end_offset != len(raw_value):
            return b""
        if tag != b"\x81":
            return b""
        if len(inner_value) != 16:
            return b""
        return inner_value

    def _should_include_initial_eim_challenge(self, eim_fqdn: str, variant: int) -> bool:
        if variant == 1:
            return True
        normalized = str(eim_fqdn).strip().lower()
        if normalized.endswith(".example.test"):
            return True
        return False

    def _should_include_initial_eim_notify_state_change(self, eim_fqdn: str) -> bool:
        return False

    def _get_initial_eim_state_change_cause(self, eim_fqdn: str) -> Optional[int]:
        configured_cause = str(getattr(self.cfg, "EIM_GET_PACKAGE_STATE_CHANGE_CAUSE", "")).strip()
        if len(configured_cause) > 0:
            try:
                cause_value = int(configured_cause, 0)
            except ValueError:
                print("[*] eIM poll: ignoring invalid EIM_GET_PACKAGE_STATE_CHANGE_CAUSE value.")
            else:
                if 0 <= cause_value <= 127:
                    return cause_value
                print("[*] eIM poll: ignoring out-of-range EIM_GET_PACKAGE_STATE_CHANGE_CAUSE value.")
        if self._should_include_initial_eim_notify_state_change(eim_fqdn):
            return 3
        return None

    def _get_eim_package_rplmn_bytes(self) -> bytes:
        configured_rplmn = str(getattr(self.cfg, "EIM_GET_PACKAGE_RPLMN", "")).strip()
        if len(configured_rplmn) == 0:
            return b""
        normalized = "".join(ch for ch in configured_rplmn if ch not in " :-")
        if len(normalized) != 6 or self._is_hex(normalized) is False:
            print(
                "[*] eIM poll: ignoring invalid EIM_GET_PACKAGE_RPLMN value; "
                "expected exactly 3 bytes in hex."
            )
            return b""
        return bytes.fromhex(normalized)

    def _extract_candidate_rplmn_from_euicc_info2(self, euicc_info2: bytes) -> bytes:
        if len(euicc_info2) == 0:
            return b""
        try:
            root_tag, root_value, _, _ = self._read_tlv(euicc_info2, 0)
        except Exception:
            return b""
        if root_tag != bytes.fromhex("BF22"):
            return b""
        offset = 0
        while offset < len(root_value):
            try:
                tag_bytes, field_value, _, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                return b""
            if tag_bytes == b"\x83" and len(field_value) == 3:
                return field_value
            offset = next_offset
        return b""

    def _build_eim_poll_request(self, matching_id: str, entry_index: int) -> EimPollRequest:
        debug_print("\n[*] Phase: Read eIM Metadata")
        euicc_configured_data = self._retrieve_es10b_data(bytes.fromhex("BF3C00"), "EIM: GetEuiccConfiguredData")
        eim_configuration_data = self._retrieve_es10b_data(bytes.fromhex("BF5500"), "EIM: GetEimConfigurationData")
        euicc_info1 = self._retrieve_es10b_data(bytes.fromhex("BF2000"), "EIM: GetEuiccInfo1")
        euicc_info2 = self._retrieve_es10b_data(bytes.fromhex("BF2200"), "EIM: GetEuiccInfo2")
        eid = self._read_card_eid(reselect_isdr=True)

        entries = self._decode_eim_configuration_entries(eim_configuration_data)
        if len(entries) == 0:
            raise RuntimeError("Card did not expose any BF55 eIM configuration entries.")
        if entry_index < 0 or entry_index >= len(entries):
            raise ValueError(f"Requested eIM entry index {entry_index} is out of range (entries={len(entries)}).")

        entry = entries[entry_index]
        self.state.current_euicc_ci_pkid = str(entry.get("euicc_ci_pkid", "")).strip()
        fragments = [f"index={entry_index}", f"fqdn={entry.get('eim_fqdn', '')}"]
        eim_id = str(entry.get("eim_id", "")).strip()
        if len(eim_id) > 0:
            fragments.append(f"eimId={eim_id}")
        eim_id_type = str(entry.get("eim_id_type", "")).strip()
        if len(eim_id_type) > 0:
            fragments.append(f"eimIdType={eim_id_type}")
        debug_print("[*] Selected eIM entry: " + ", ".join(fragments))

        variant = getattr(self.cfg, "EIM_REQUEST_VARIANT", 0)
        raw_body = None
        challenge_b64 = self._eim_euicc_challenge_b64(self.state.card_challenge)
        eim_fqdn = str(entry.get("eim_fqdn", "")).strip()
        notify_state_change = bool(getattr(self.cfg, "EIM_GET_PACKAGE_NOTIFY_STATE_CHANGE", False))
        if notify_state_change is False and self._should_include_initial_eim_notify_state_change(eim_fqdn):
            notify_state_change = True
            print("[*] eIM poll: live endpoint detected; including notifyStateChange in initial GetEimPackage.")
        state_change_cause = self._get_initial_eim_state_change_cause(eim_fqdn)
        if state_change_cause is not None and notify_state_change:
            print(
                "[*] eIM poll: including stateChangeCause in initial GetEimPackage: "
                f"{state_change_cause}"
            )
        rplmn_bytes = self._get_eim_package_rplmn_bytes()
        if len(rplmn_bytes) == 0 and self._should_include_initial_eim_notify_state_change(eim_fqdn):
            rplmn_bytes = self._extract_candidate_rplmn_from_euicc_info2(euicc_info2)
            if len(rplmn_bytes) > 0:
                print(
                    "[*] eIM poll: live endpoint detected; including candidate rPLMN from "
                    f"EuiccInfo2: {rplmn_bytes.hex().upper()}"
                )
        if variant != 2:
            raw_body = self._build_get_eim_package_tlv(
                eid,
                notify_state_change=notify_state_change,
                state_change_cause=state_change_cause,
                rplmn_bytes=rplmn_bytes,
            )
            if len(raw_body) == 0:
                raw_body = None
        if variant == 2:
            raw_body = None
        return EimPollRequest(
            eim_fqdn=str(entry.get("eim_fqdn", "")).strip(),
            eim_id=eim_id,
            eim_id_type=eim_id_type,
            counter_value=str(entry.get("counter_value", "")).strip(),
            association_token=str(entry.get("association_token", "")).strip(),
            supported_protocol=str(entry.get("supported_protocol", "")).strip(),
            euicc_ci_pkid=str(entry.get("euicc_ci_pkid", "")).strip(),
            indirect_profile_download=str(entry.get("indirect_profile_download", "")).strip(),
            euicc_configured_data=self._b64encode(euicc_configured_data),
            eim_configuration_data=self._b64encode(eim_configuration_data),
            euicc_info1=self._b64encode(euicc_info1),
            euicc_info2=self._b64encode(euicc_info2),
            eid=eid,
            matching_id=matching_id,
            euicc_challenge=challenge_b64,
            trusted_tls_public_key_data=bytes(entry.get("trusted_tls_public_key_data", b"")),
            raw_body=raw_body if raw_body is not None and len(raw_body) > 0 else None,
        )

    def _retrieve_es10b_data(self, payload: bytes, log_name: str) -> bytes:
        return self._send_es10b_store_data(payload, log_name)

    def _read_card_eid(self, reselect_isdr: bool = True) -> str:
        try:
            ecasd_aid = bytes.fromhex("A0000005591010FFFFFFFF8900000200")
            select_apdu = b"\x00\xA4\x04\x00" + bytes([len(ecasd_aid)]) + ecasd_aid
            self.apdu_channel.send(select_apdu, "EIM: SELECT ECASD")
            response = self.apdu_channel.send(bytes.fromhex("80CA005A00"), "EIM: GetEID")
            if len(response) == 0:
                return ""
            try:
                tag_bytes, value, _, _ = self._read_tlv(response, 0)
            except ValueError:
                value = response
            else:
                if tag_bytes != b"\x5A":
                    return ""
            return self._decode_bcd_digits(value)
        except Exception as error:
            print(f"[*] EIM metadata: failed to read EID ({error}).")
            return ""
        finally:
            if reselect_isdr:
                try:
                    select_apdu = b"\x00\xA4\x04\x00" + bytes([len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
                    self.apdu_channel.send(select_apdu, "EIM: RESELECT ISD-R")
                except Exception:
                    pass

    def _decode_eim_configuration_entries(self, response: bytes) -> list:
        entries = []
        for entry in decode_eim_configuration_entries_shared(response):
            if len(str(entry.get("eim_id", "")).strip()) == 0:
                continue
            normalized_entry = dict(entry)
            tls_data = normalized_entry.get("trusted_tls_public_key_data")
            if isinstance(tls_data, bytes):
                normalized_entry["trusted_tls_public_key_data"] = self._extract_subject_public_key_info(tls_data)
            eim_data = normalized_entry.get("eim_public_key_data")
            if isinstance(eim_data, bytes):
                normalized_entry["eim_public_key_data"] = self._extract_subject_public_key_info(eim_data)
            entry = normalized_entry
            if len(entry) == 0:
                continue
            entries.append(entry)
        return entries

    def _find_eim_entry_values(self, data: bytes) -> list:
        matches = []
        seen = set()

        def walk(node_bytes: bytes) -> None:
            """Depth-first walk helper used during the ES10b profile-tree traversal."""
            if len(node_bytes) == 0:
                return

            immediate_tags = []
            offset = 0
            while offset < len(node_bytes):
                try:
                    tag_bytes, value_bytes, _, next_offset = self._read_tlv(node_bytes, offset)
                except Exception:
                    return
                immediate_tags.append(tag_bytes)
                if self._is_constructed_tag(tag_bytes):
                    walk(value_bytes)
                offset = next_offset

            has_identity = b"\x80" in immediate_tags and b"\x81" in immediate_tags
            if has_identity is False:
                return

            fingerprint = node_bytes.hex().upper()
            if fingerprint in seen:
                return
            seen.add(fingerprint)
            matches.append(node_bytes)

        walk(data)
        return matches

    def _decode_eim_configuration_entry(self, value: bytes) -> dict:
        entry = decode_eim_configuration_entry_shared(value)
        tls_data = entry.get("trusted_tls_public_key_data")
        if isinstance(tls_data, bytes):
            entry["trusted_tls_public_key_data"] = self._extract_subject_public_key_info(tls_data)
        eim_data = entry.get("eim_public_key_data")
        if isinstance(eim_data, bytes):
            entry["eim_public_key_data"] = self._extract_subject_public_key_info(eim_data)
        return entry

    def _extract_subject_public_key_info(self, value: bytes) -> bytes:
        if len(value) == 0:
            return b""

        try:
            tag_bytes, inner_value, raw_tlv, _ = self._read_tlv(value, 0)
        except Exception:
            return b""
        if tag_bytes == b"\x30":
            certificate_spki = self._extract_certificate_subject_public_key_info(raw_tlv)
            if len(certificate_spki) > 0:
                return certificate_spki
            return raw_tlv

        if self._is_constructed_tag(tag_bytes):
            try:
                first_tag, _, _, next_offset = self._read_tlv(inner_value, 0)
            except Exception:
                return b""
            if first_tag == b"\x30" and next_offset < len(inner_value):
                remainder = inner_value[next_offset:]
                if len(remainder) > 0 and remainder[0] == 0x03:
                    spki = self._wrap_tlv(b"\x30", inner_value)
                    certificate_spki = self._extract_certificate_subject_public_key_info(spki)
                    if len(certificate_spki) > 0:
                        return certificate_spki
                    return spki

            nested_spki = self._extract_subject_public_key_info(inner_value)
            if len(nested_spki) > 0:
                return nested_spki
        return b""

    def _extract_certificate_subject_public_key_info(self, value: bytes) -> bytes:
        certificate = safe_parse(
            "scp11.extract_cert_spki",
            value,
            crypto_x509.load_der_x509_certificate,
            default=None,
        )
        if certificate is None:
            return b""
        return certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_eim_package(self, request: EimPollRequest):
        debug_print("\n[*] Phase: GetEimPackage")
        if self.profile_provider is None:
            raise RuntimeError("No profile provider configured for eIM polling.")
        try:
            response = self.profile_provider.get_eim_package(request)
        except NotImplementedError as error:
            raise RuntimeError(f"Provider getEimPackage is not implemented: {error}") from error
        except Exception as error:
            variant_response = self._probe_get_eim_package_variants_after_error(
                request,
                error,
                tried_bodies=[request.raw_body] if request.raw_body is not None else None,
            )
            if variant_response is not None:
                debug_print(
                    f"[+] eIM poll response: packages={len(variant_response.euicc_package_list)}, "
                    f"complete={variant_response.polling_complete}, "
                    f"retryAfter={variant_response.retry_after_seconds}"
                )
                return variant_response
            raise RuntimeError(f"Provider getEimPackage failed: {error}") from error
        response = self._probe_get_eim_package_variants(request, response)
        debug_print(
            f"[+] eIM poll response: packages={len(response.euicc_package_list)}, "
            f"complete={response.polling_complete}, retryAfter={response.retry_after_seconds}"
        )
        return response

    def _provide_eim_package_result(self, request: EimPollRequest) -> dict:
        debug_print("\n[*] Phase: ProvideEimPackageResult")
        if self.profile_provider is None:
            raise RuntimeError("No profile provider configured for eIM polling.")
        try:
            response = self.profile_provider.provide_eim_package_result(request)
        except NotImplementedError as error:
            raise RuntimeError(f"Provider provideEimPackageResult is not implemented: {error}") from error
        except Exception as error:
            raise RuntimeError(f"Provider provideEimPackageResult failed: {error}") from error
        return response

    def _poll_eim(self, request: EimPollRequest):
        return self._get_eim_package(request)

    def _coerce_eim_poll_response(self, response: Any) -> EimPollResponse:
        def coerce_ack_sequence_numbers(value: Any) -> list[int]:
            """Normalise pending notification sequence numbers before sending acknowledgements."""
            if isinstance(value, list) is False:
                return []
            out: list[int] = []
            for item in value:
                if isinstance(item, bool):
                    continue
                if isinstance(item, int):
                    out.append(item)
                    continue
                if isinstance(item, str):
                    try:
                        out.append(int(item.strip(), 10))
                    except ValueError:
                        continue
            return out

        if isinstance(response, EimPollResponse):
            return response
        if hasattr(response, "euicc_package_list") and hasattr(response, "polling_complete"):
            return EimPollResponse(
                transaction_id=str(getattr(response, "transaction_id", "") or ""),
                euicc_package_list=list(getattr(response, "euicc_package_list", []) or []),
                package_format=str(getattr(response, "package_format", "") or ""),
                ack_sequence_numbers=coerce_ack_sequence_numbers(
                    getattr(response, "ack_sequence_numbers", [])
                ),
                polling_complete=bool(getattr(response, "polling_complete", True)),
                retry_after_seconds=int(getattr(response, "retry_after_seconds", 0) or 0),
                eim_result_code=getattr(response, "eim_result_code", None),
            )
        if isinstance(response, dict) is False:
            return EimPollResponse()

        candidates = []

        def collect(node: Any) -> None:
            """Collect and aggregate results from parallel sub-operations."""
            if isinstance(node, dict) is False:
                return
            candidates.append(node)
            for key in (
                "body",
                "data",
                "getEimPackageResponse",
                "getEimPackageOk",
                "provideEimPackageResultResponse",
                "provideEimPackageResultOk",
            ):
                nested = node.get(key)
                if isinstance(nested, dict):
                    collect(nested)

        def to_response(node: dict) -> EimPollResponse:
            """Serialise the orchestrator result to a JSON-serialisable response dict."""
            package_list = []
            for key in ("euiccPackageList", "packages", "packageList", "requestPackageJson"):
                value = node.get(key)
                if isinstance(value, list):
                    package_list = [str(item) for item in value if isinstance(item, (str, bytes))]
                    break
            if len(package_list) == 0:
                for key in ("euiccPackage", "packageData", "euiccPackageRequest", "requestPackageJson"):
                    value = node.get(key)
                    if isinstance(value, str) and len(value) > 0:
                        package_list = [value]
                        break
            retry_after = node.get("retryAfterSeconds", node.get("retryCounter", 0))
            try:
                retry_after_int = int(retry_after)
            except Exception:
                retry_after_int = 0
            result_code = node.get("eimResultCode", node.get("eimPackageError"))
            if isinstance(result_code, bool):
                result_code = int(result_code)
            elif isinstance(result_code, (int, float)) is False:
                result_code = None
            return EimPollResponse(
                transaction_id=str(
                    node.get("transactionId", node.get("transactionID", node.get("eimTransactionId", ""))) or ""
                ),
                euicc_package_list=package_list,
                package_format=str(node.get("packageFormat", node.get("euiccPackageFormat", "")) or ""),
                ack_sequence_numbers=coerce_ack_sequence_numbers(node.get("ackSequenceNumbers")),
                polling_complete=bool(node.get("pollingComplete", True)),
                retry_after_seconds=retry_after_int,
                eim_result_code=result_code,
            )

        def score(value: EimPollResponse) -> tuple[int, int, int, int, int]:
            """Compute a fitness score for this orchestrator attempt used by the retry ladder."""
            return (
                1 if len(value.euicc_package_list) > 0 else 0,
                1 if value.polling_complete is False else 0,
                1 if value.eim_result_code is not None else 0,
                1 if len(value.ack_sequence_numbers) > 0 or len(value.package_format) > 0 else 0,
                1 if len(value.transaction_id) > 0 else 0,
            )

        collect(response)
        if len(candidates) == 0:
            return EimPollResponse()
        normalized_candidates = [to_response(candidate) for candidate in candidates]
        best = EimPollResponse()
        best_score = (-1, -1, -1, -1, -1)
        for normalized in normalized_candidates:
            current_score = score(normalized)
            if current_score > best_score:
                best = normalized
                best_score = current_score
        if len(best.transaction_id) == 0:
            for normalized in normalized_candidates:
                if len(normalized.transaction_id) > 0:
                    best.transaction_id = normalized.transaction_id
                    break
        if len(best.package_format) == 0:
            for normalized in normalized_candidates:
                if len(normalized.package_format) > 0:
                    best.package_format = normalized.package_format
                    break
        if len(best.ack_sequence_numbers) == 0:
            for normalized in normalized_candidates:
                if len(normalized.ack_sequence_numbers) > 0:
                    best.ack_sequence_numbers = list(normalized.ack_sequence_numbers)
                    break
        return best

    def _has_eim_poll_follow_up(self, response: EimPollResponse) -> bool:
        if len(response.euicc_package_list) > 0:
            return True
        if response.polling_complete is False:
            return True
        if response.eim_result_code is not None:
            return True
        return False

    def _should_synthesize_provide_eim_acknowledgement(
        self,
        response: EimPollResponse,
    ) -> bool:
        package_format = str(response.package_format).strip()
        if package_format == "eimAcknowledgements":
            return False
        if package_format == "provideEimPackageResultError":
            return False
        if len(response.euicc_package_list) > 0:
            return False
        if response.polling_complete is False:
            return False
        if response.eim_result_code is not None:
            return False
        return True

    def _normalize_provide_eim_package_result_response(
        self,
        response: Any,
        card_response: bytes,
        transaction_id: str = "",
    ) -> EimPollResponse:
        normalized = self._coerce_eim_poll_response(response)
        if self._should_synthesize_provide_eim_acknowledgement(normalized) is False:
            return normalized
        synthesized = EimPollResponse(
            transaction_id=normalized.transaction_id or str(transaction_id or ""),
            package_format="eimAcknowledgements",
            ack_sequence_numbers=self._extract_eim_ack_sequence_numbers_from_card_response(card_response),
            polling_complete=True,
            retry_after_seconds=0,
            eim_result_code=None,
        )
        if len(synthesized.ack_sequence_numbers) > 0:
            print(
                "[*] ProvideEimPackageResult acknowledgement synthesized from "
                f"card seqNumber(s): {', '.join(str(item) for item in synthesized.ack_sequence_numbers)}"
            )
        else:
            debug_print("[*] ProvideEimPackageResult acknowledgement synthesized as empty BF53.")
        return synthesized

    def _build_eim_timeout_retry_request(
        self,
        request: EimPollRequest,
        error: Exception,
    ) -> Optional[EimPollRequest]:
        error_text = str(error).lower()
        if "timed out" not in error_text:
            return None
        if request.raw_body is None or len(request.raw_body) == 0:
            return None
        if request.raw_body.startswith(bytes.fromhex("BF4F")) is False:
            return None
        variant_requests = self._build_get_eim_package_variant_requests(request)
        if len(variant_requests) == 0:
            return None
        _, retry_request = variant_requests[0]
        return retry_request

    def _probe_get_eim_package_variants(
        self,
        request: EimPollRequest,
        initial_response: EimPollResponse,
    ) -> EimPollResponse:
        if self._should_probe_get_eim_package_variants(request, initial_response) is False:
            return initial_response
        if self.profile_provider is None:
            return initial_response
        variant_requests = self._build_get_eim_package_variant_requests(request)
        if len(variant_requests) == 0:
            return initial_response
        best_response = initial_response
        print("[*] eIM poll variant probe: initial response returned undefinedError(127); trying alternative GetEimPackage variants.")
        for variant_name, variant_request in variant_requests:
            print(f"[*] eIM poll variant probe: trying {variant_name}.")
            try:
                response = self.profile_provider.get_eim_package(variant_request)
            except Exception as error:
                print(f"[*] eIM poll variant probe: {variant_name} failed ({error}).")
                continue
            result_code = response.eim_result_code
            print(
                f"[*] eIM poll variant probe: {variant_name} -> packages={len(response.euicc_package_list)} "
                f"complete={response.polling_complete} result={result_code}"
            )
            best_response = self._select_better_get_eim_package_response(best_response, response)
            if self._is_acceptable_get_eim_package_response(response):
                print(f"[+] eIM poll variant probe: selected {variant_name}.")
                return response
        print("[*] eIM poll variant probe: no variant improved on undefinedError(127).")
        return best_response

    def _probe_get_eim_package_variants_after_error(
        self,
        request: EimPollRequest,
        initial_error: Exception,
        tried_bodies: Optional[list[bytes]] = None,
    ) -> Optional[EimPollResponse]:
        if self.profile_provider is None:
            return None
        if self._should_probe_get_eim_package_variants_after_error(request, initial_error) is False:
            return None
        variant_requests = self._build_get_eim_package_variant_requests(
            request,
            additional_seen_bodies=tried_bodies,
        )
        if len(variant_requests) == 0:
            return None
        best_response = None
        print(
            "[*] eIM poll variant probe: initial request failed; trying alternative "
            "GetEimPackage variants."
        )
        for variant_name, variant_request in variant_requests:
            print(f"[*] eIM poll variant probe: trying {variant_name}.")
            try:
                response = self.profile_provider.get_eim_package(variant_request)
            except Exception as error:
                print(f"[*] eIM poll variant probe: {variant_name} failed ({error}).")
                continue
            result_code = response.eim_result_code
            print(
                f"[*] eIM poll variant probe: {variant_name} -> packages={len(response.euicc_package_list)} "
                f"complete={response.polling_complete} result={result_code}"
            )
            best_response = self._select_better_get_eim_package_response(best_response, response)
            if self._is_acceptable_get_eim_package_response(response):
                print(f"[+] eIM poll variant probe: selected {variant_name}.")
                return response
        if best_response is not None:
            if (
                len(best_response.euicc_package_list) == 0
                and best_response.eim_result_code is None
            ):
                print("[*] eIM poll variant probe: no variant produced a meaningful response after the initial failure.")
                return None
            best_code = best_response.eim_result_code
            print(
                "[*] eIM poll variant probe: no variant produced a usable response after the initial failure; "
                f"returning best observed result={best_code} packages={len(best_response.euicc_package_list)}."
            )
            return best_response
        print("[*] eIM poll variant probe: no variant produced a usable response after the initial failure.")
        return None

    def _should_probe_get_eim_package_variants(
        self,
        request: EimPollRequest,
        response: EimPollResponse,
    ) -> bool:
        if request.raw_body is None or len(request.raw_body) == 0:
            return False
        if request.raw_body.startswith(bytes.fromhex("BF4F")) is False:
            return False
        if len(response.euicc_package_list) > 0:
            return False
        if response.eim_result_code != 127:
            return False
        return True

    def _should_probe_get_eim_package_variants_after_error(
        self,
        request: EimPollRequest,
        error: Exception,
    ) -> bool:
        if request.raw_body is None or len(request.raw_body) == 0:
            return False
        if request.raw_body.startswith(bytes.fromhex("BF4F")) is False:
            return False
        error_text = str(error).lower()
        if "timed out" not in error_text:
            return False
        normalized_fqdn = str(request.eim_fqdn).strip().lower()
        if normalized_fqdn.endswith(".example.test"):
            return True
        if len(str(getattr(request, "euicc_info2", "") or "").strip()) > 0:
            return True
        return False

    def _is_acceptable_get_eim_package_response(self, response: EimPollResponse) -> bool:
        if len(response.euicc_package_list) > 0:
            return True
        if response.eim_result_code is None:
            return False
        if response.eim_result_code != 127:
            return True
        return False

    def _score_get_eim_package_response(self, response: Optional[EimPollResponse]) -> tuple[int, int, int]:
        if response is None:
            return (-2, -1, -1)
        package_count = len(response.euicc_package_list)
        if package_count > 0:
            return (3, package_count, 0)
        if response.eim_result_code is None:
            return (-1, 0, 0)
        if response.eim_result_code != 127:
            return (1, 0, -int(response.eim_result_code))
        return (0, 0, 0)

    def _select_better_get_eim_package_response(
        self,
        current_best: Optional[EimPollResponse],
        candidate: Optional[EimPollResponse],
    ) -> Optional[EimPollResponse]:
        if self._score_get_eim_package_response(candidate) > self._score_get_eim_package_response(current_best):
            return candidate
        return current_best

    def _build_get_eim_package_variant_requests(
        self,
        request: EimPollRequest,
        additional_seen_bodies: Optional[list[bytes]] = None,
    ) -> list[tuple[str, EimPollRequest]]:
        seen_bodies = set()
        if request.raw_body is not None and len(request.raw_body) > 0:
            seen_bodies.add(request.raw_body)
        if isinstance(additional_seen_bodies, list):
            for body in additional_seen_bodies:
                if isinstance(body, bytes) and len(body) > 0:
                    seen_bodies.add(body)
        variants = []
        state_change_cause = self._get_initial_eim_state_change_cause(request.eim_fqdn)
        info2_bytes = self._decode_string_payload(request.euicc_info2)
        candidate_rplmn_values = []
        configured_rplmn = self._get_eim_package_rplmn_bytes()
        if len(configured_rplmn) > 0:
            candidate_rplmn_values.append(configured_rplmn)
        info2_rplmn = self._extract_candidate_rplmn_from_euicc_info2(info2_bytes)
        if len(info2_rplmn) > 0 and info2_rplmn not in candidate_rplmn_values:
            candidate_rplmn_values.append(info2_rplmn)
        candidate_definitions = [
            ("eid-only", False, None, b""),
            ("notify-state-change", True, None, b""),
        ]
        if state_change_cause is not None:
            candidate_definitions.append(
                ("notify-state-change-cause", True, state_change_cause, b"")
            )
        for candidate_rplmn in candidate_rplmn_values:
            candidate_definitions.append(
                ("notify-state-change-rplmn", True, None, candidate_rplmn)
            )
            if state_change_cause is not None:
                candidate_definitions.append(
                    (
                        "notify-state-change-cause-rplmn",
                        True,
                        state_change_cause,
                        candidate_rplmn,
                    )
                )
        for variant_name, use_notify, effective_state_change_cause, rplmn_bytes in candidate_definitions:
            raw_body = self._build_get_eim_package_tlv(
                request.eid,
                notify_state_change=use_notify,
                state_change_cause=effective_state_change_cause,
                rplmn_bytes=rplmn_bytes,
            )
            if len(raw_body) == 0:
                continue
            if raw_body in seen_bodies:
                continue
            seen_bodies.add(raw_body)
            variant_request = copy.deepcopy(request)
            variant_request.raw_body = raw_body
            variants.append((variant_name, variant_request))
        return variants

    def _as_https_smdp(self, smdp_address: str) -> str:
        cleaned = smdp_address.strip()
        if len(cleaned) == 0:
            return ""
        lowered = cleaned.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return cleaned.rstrip("/")
        return f"https://{cleaned.rstrip('/')}"

    def _profile_download_provider_base_url(self, smdp_address: str) -> str:
        provider_override = str(
            getattr(self, "_profile_download_base_url_override", "") or ""
        ).strip()
        if len(provider_override) > 0:
            return provider_override.rstrip("/")
        return self._as_https_smdp(smdp_address)

    def _relay_eim_package_to_card(self, package_bytes: bytes, poll_round: int, package_index: int) -> bytes:
        log_name = f"EIM: RelayPackage [poll={poll_round} package={package_index}]"
        print(
            f"[*] Relaying eIM package {package_index} from poll round {poll_round}: "
            f"tag={self._tag_hex(package_bytes)} len={len(package_bytes)}"
        )
        parsed = parse_eim_package(package_bytes)
        print(f"[*] eIM package type: {parsed.package_type}")

        if parsed.package_type == TYPE_INDIRECT_PROFILE_DOWNLOAD and parsed.smdp_address and parsed.matching_id:
            print(
                f"[*] Indirect profile download: smdp={parsed.smdp_address} matchingId={parsed.matching_id}; "
                "running SGP.22 profile download."
            )
            if self.profile_provider is not None and hasattr(self.profile_provider, "set_base_url"):
                base_url = self._profile_download_provider_base_url(parsed.smdp_address)
                if len(base_url) > 0:
                    self.profile_provider.set_base_url(base_url)
            download_error = None
            try:
                self.run_flow(
                    matching_id=parsed.matching_id,
                    smdp_address=parsed.smdp_address,
                )
            except Exception as error:
                download_error = error
                print(f"[*] eIM-triggered profile download failed: {error}")
            last_response = getattr(self.state, "load_bpp_response", b"") or b""
            if len(last_response) == 0 and download_error is not None:
                last_response = self._build_profile_download_trigger_result_error(
                    eim_transaction_id=parsed.eim_transaction_id,
                    error_reason=127,
                )
                print(
                    f"[!] Download failed; returning ProfileDownloadTriggerResult error "
                    f"(undefinedError) to eIM: {last_response.hex().upper()}"
                )
            eim_response = self._build_profile_download_trigger_result_tlv(
                card_response=last_response,
                eim_transaction_id=parsed.eim_transaction_id,
            )
            self.state.eim_package_response = eim_response
            return eim_response

        if parsed.package_type == TYPE_PROFILE_DOWNLOAD_TRIGGER and parsed.smdp_address and parsed.matching_id:
            print(
                f"[*] Profile download trigger: smdp={parsed.smdp_address} "
                f"matchingId={parsed.matching_id}; running SGP.22 profile download."
            )
            if self.profile_provider is not None and hasattr(self.profile_provider, "set_base_url"):
                base_url = self._profile_download_provider_base_url(parsed.smdp_address)
                if len(base_url) > 0:
                    self.profile_provider.set_base_url(base_url)
            download_error = None
            try:
                self.run_flow(
                    matching_id=parsed.matching_id,
                    smdp_address=parsed.smdp_address,
                )
            except Exception as error:
                download_error = error
                print(f"[*] eIM-triggered profile download failed: {error}")
            last_response = getattr(self.state, "load_bpp_response", b"") or b""
            if len(last_response) == 0 and download_error is not None:
                last_response = self._build_profile_download_trigger_result_error(
                    eim_transaction_id=parsed.eim_transaction_id,
                    error_reason=127,
                )
                print(
                    f"[!] Download failed; returning ProfileDownloadTriggerResult error "
                    f"(undefinedError) to eIM: {last_response.hex().upper()}"
                )
            eim_response = self._build_profile_download_trigger_result_tlv(
                card_response=last_response,
                eim_transaction_id=parsed.eim_transaction_id,
            )
            self.state.eim_package_response = eim_response
            return eim_response

        if parsed.package_type == TYPE_EUICC_CONFIGURATION:
            last_response = self._build_ipa_euicc_data_response(parsed, log_name)
            self.state.eim_package_response = last_response
            print(f"[*] eIM card response: {last_response.hex().upper()}")
            self._sync_pending_notifications(last_response)
            return last_response

        if len(parsed.card_request) > 0:
            print(
                f"[*] eIM inner card request: tag={self._tag_hex(parsed.card_request)} "
                f"len={len(parsed.card_request)}"
            )
        preserve_signed_wrapper_types = (
            TYPE_PROFILE_STATE_MANAGEMENT,
            TYPE_EUICC_CONFIGURATION,
            TYPE_PROFILE_DOWNLOAD_TRIGGER,
        )
        if parsed.package_type in preserve_signed_wrapper_types:
            print("[*] eIM package will be relayed with its signed wrapper intact.")
        if len(parsed.card_request) > 0 and parsed.package_type not in preserve_signed_wrapper_types:
            last_response = self._retrieve_es10b_data(parsed.card_request, log_name)
            self.state.eim_package_response = last_response
            if len(last_response) == 0:
                print("[*] eIM relay completed with empty card response.")
                self._sync_pending_notifications()
                return last_response
            print(f"[*] eIM card response: {last_response.hex().upper()}")
            self._sync_pending_notifications(last_response)
            return last_response

        segments = self._segment_card_package(package_bytes)
        print(f"[*] eIM package segmented into {len(segments)} ES10b payload(s).")
        last_response = b""
        for segment_index, segment in enumerate(segments, start=1):
            last_response = self._send_personalization_store_data(
                segment,
                f"{log_name} [{segment_index}/{len(segments)}]",
            )
        self.state.eim_package_response = last_response
        if len(last_response) == 0:
            print("[*] eIM relay completed with empty card response.")
            self._sync_pending_notifications()
            return last_response
        print(f"[*] eIM card response: {last_response.hex().upper()}")
        self._handle_profile_load_result(last_response)
        self._sync_pending_notifications(last_response)
        return last_response

    def _build_ipa_euicc_data_response(self, parsed_package: Any, log_name: str) -> bytes:
        print("[*] Handling ipaEuiccDataRequest locally.")
        requested_tags = tuple(getattr(parsed_package, "requested_tags", ()) or ())
        request_token = bytes(getattr(parsed_package, "request_token", b"") or b"")
        notification_seq_number = getattr(parsed_package, "notification_seq_number", None)
        euicc_package_result_seq_number = getattr(parsed_package, "euicc_package_result_seq_number", None)
        if isinstance(notification_seq_number, int) is False:
            notification_seq_number = None
        if isinstance(euicc_package_result_seq_number, int) is False:
            euicc_package_result_seq_number = None
        requested_tag_set = set(requested_tags)

        euicc_info1 = b""
        euicc_info2 = b""
        configured_data = b""
        eim_configuration_data = b""
        certs_data = b""
        pending_notification_list = b""
        euicc_package_result_list = b""

        if bytes.fromhex("BF20") in requested_tag_set:
            euicc_info1 = self._retrieve_es10b_data(bytes.fromhex("BF2000"), f"{log_name}: GetEuiccInfo1")
        if bytes.fromhex("BF22") in requested_tag_set:
            euicc_info2 = self._retrieve_es10b_data(bytes.fromhex("BF2200"), f"{log_name}: GetEuiccInfo2")
        if b"\x81" in requested_tag_set or b"\x83" in requested_tag_set:
            configured_data = self._retrieve_es10b_data(bytes.fromhex("BF3C00"), f"{log_name}: GetEuiccConfiguredData")
        if b"\x84" in requested_tag_set:
            eim_configuration_data = self._retrieve_es10b_data(bytes.fromhex("BF5500"), f"{log_name}: GetEimConfigurationData")
        if b"\xA5" in requested_tag_set or b"\xA6" in requested_tag_set:
            certs_data = self._retrieve_es10b_data(bytes.fromhex("BF5600"), f"{log_name}: GetCerts")
        if b"\xA0" in requested_tag_set:
            pending_notification_list = self._retrieve_es10b_data(
                self._build_retrieve_notification_request_payload(notification_seq_number),
                f"{log_name}: RetrieveNotificationsList",
            )
        if b"\xA2" in requested_tag_set:
            euicc_package_result_list = self._retrieve_es10b_data(
                self._build_retrieve_euicc_package_result_request_payload(euicc_package_result_seq_number),
                f"{log_name}: RetrieveEuiccPackageResults",
            )

        first_entry = self._extract_first_eim_entry_bytes(eim_configuration_data)

        response_items = {}
        for requested_tag in requested_tags:
            raw_field = b""

            if requested_tag == b"\xA0":
                raw_field = self._extract_notification_list_item(pending_notification_list)
            elif requested_tag == b"\x81":
                raw_field = self._build_text_item_from_source(configured_data, b"\x80", b"\x81")
            elif requested_tag == b"\xA2":
                raw_field = self._extract_euicc_package_result_list_item(euicc_package_result_list)
            elif requested_tag == bytes.fromhex("BF20"):
                raw_field = euicc_info1
            elif requested_tag == bytes.fromhex("BF22"):
                raw_field = euicc_info2
            elif requested_tag == b"\x83":
                raw_field = self._build_text_item_from_source(configured_data, b"\x81", b"\x83")
            elif requested_tag == b"\x84":
                raw_field = self._find_first_raw_tlv_recursive(first_entry, b"\x84")
            elif requested_tag == b"\xA5":
                raw_field = self._find_first_raw_tlv_recursive(certs_data, b"\xA5")
            elif requested_tag == b"\xA6":
                raw_field = self._find_first_raw_tlv_recursive(certs_data, b"\xA6")
            elif requested_tag == b"\xA8":
                raw_field = self._build_ipa_capabilities_item()
            elif requested_tag == b"\xA9":
                raw_field = self._build_device_information_item()

            if len(raw_field) > 0:
                response_items[requested_tag] = raw_field

        if len(request_token) > 0:
            response_items[b"\x87"] = self._wrap_tlv(b"\x87", request_token)

        body = b""
        response_order = [
            b"\xA0",
            b"\x81",
            b"\xA2",
            bytes.fromhex("BF20"),
            bytes.fromhex("BF22"),
            b"\x83",
            b"\x84",
            b"\xA5",
            b"\xA6",
            b"\x87",
            b"\xA8",
            b"\xA9",
        ]
        for tag in response_order:
            item = response_items.get(tag, b"")
            if len(item) > 0:
                body += item

        ipa_euicc_data = self._wrap_tlv(b"\xA0", body)
        return self._wrap_tlv(bytes.fromhex("BF52"), ipa_euicc_data)

    def _extract_notification_list_item(self, response: bytes) -> bytes:
        raw_field = self._extract_choice_item(response, b"\xA0")
        if len(raw_field) == 0:
            return b""
        return raw_field

    def _extract_euicc_package_result_list_item(self, response: bytes) -> bytes:
        raw_field = self._extract_choice_item(response, b"\xA2")
        if len(raw_field) == 0:
            return self._wrap_tlv(b"\xA2", b"")
        return raw_field

    def _build_text_item_from_source(self, source_data: bytes, source_tag: bytes, output_tag: bytes) -> bytes:
        value = self._find_first_tlv_value_recursive(source_data, source_tag)
        if len(value) == 0:
            return self._wrap_tlv(output_tag, b"")
        return self._wrap_tlv(output_tag, value)

    def _build_ipa_capabilities_item(self) -> bytes:
        raw_capabilities = getattr(self.cfg, "IPA_CAPABILITIES_BER_TLV", b"")
        if isinstance(raw_capabilities, bytes):
            if len(raw_capabilities) == 0:
                raw_capabilities = self._default_ipa_capabilities_value()
            return self._wrap_tlv(b"\xA8", raw_capabilities)
        if isinstance(raw_capabilities, str):
            text = raw_capabilities.strip()
            if len(text) == 0:
                return self._wrap_tlv(b"\xA8", self._default_ipa_capabilities_value())
            try:
                return self._wrap_tlv(b"\xA8", bytes.fromhex(text))
            except ValueError:
                return self._wrap_tlv(b"\xA8", text.encode("utf-8"))
        return self._wrap_tlv(b"\xA8", self._default_ipa_capabilities_value())

    def _build_device_information_item(self) -> bytes:
        include_device_info = bool(getattr(self.cfg, "IPA_INCLUDE_DEVICE_INFO_IN_EIM_DATA", False))
        if include_device_info is False:
            return b""
        tac = bytes(getattr(self.cfg, "TAC", b"") or b"")
        capabilities = dict(getattr(self.cfg, "CAPABILITIES", {}) or {})
        if len(tac) == 0:
            return b""

        capability_fields = [
            "gsmSupportedRelease",
            "utranSupportedRelease",
            "cdma2000onexSupportedRelease",
            "cdma2000hrpdSupportedRelease",
            "cdma2000ehrpdSupportedRelease",
            "eutranEpcSupportedRelease",
            "contactlessSupportedRelease",
            "rspCrlSupportedVersion",
        ]
        capability_value = b""
        for field_name in capability_fields:
            field_bytes = bytes(capabilities.get(field_name, b"") or b"")
            if len(field_bytes) == 0:
                continue
            capability_value += self._wrap_tlv(b"\x04", field_bytes)

        device_info_value = self._wrap_tlv(b"\x04", tac)
        device_info_value += self._wrap_tlv(b"\x30", capability_value)
        return self._wrap_tlv(b"\xA9", device_info_value)

    def _default_ipa_capabilities_value(self) -> bytes:
        # We return euiccInfo1/2 and certificate material in ESIPA data responses,
        # so advertise minimizeEsipaBytes support per SGP.32.
        ipa_features = self._encode_named_bit_string([0, 1, 5])
        ipa_supported_protocols = self._encode_named_bit_string([0])
        return self._wrap_tlv(b"\x80", ipa_features) + self._wrap_tlv(b"\x81", ipa_supported_protocols)

    def _extract_first_eim_entry_bytes(self, response: bytes) -> bytes:
        tlv = safe_parse(
            "scp11.first_eim_entry.root",
            response,
            lambda buf: self._read_tlv(buf, 0),
            default=None,
        )
        if tlv is None:
            return b""
        root_tag, root_value, _, _ = tlv
        if root_tag != bytes.fromhex("BF55"):
            return b""
        entries = self._find_eim_entry_values(root_value)
        if len(entries) == 0:
            return b""
        return entries[0]

    def _find_first_raw_tlv_recursive(self, data: bytes, target_tag: bytes) -> bytes:
        if len(data) == 0:
            return b""
        try:
            tag_bytes, value, raw_tlv, _ = self._read_tlv(data, 0)
        except Exception:
            tag_bytes = b""
            value = data
            raw_tlv = b""
        if tag_bytes == target_tag and len(raw_tlv) > 0:
            return raw_tlv
        offset = 0
        while offset < len(data):
            try:
                tag_bytes, value, raw_tlv, next_offset = self._read_tlv(data, offset)
            except Exception:
                break
            if tag_bytes == target_tag:
                return raw_tlv
            if self._is_constructed_tag(tag_bytes):
                nested = self._find_first_raw_tlv_recursive(value, target_tag)
                if len(nested) > 0:
                    return nested
            offset = next_offset
        return b""

    def _find_first_tlv_value_recursive(self, data: bytes, target_tag: bytes) -> bytes:
        raw_tlv = self._find_first_raw_tlv_recursive(data, target_tag)
        if len(raw_tlv) == 0:
            return b""
        tlv = safe_parse(
            "scp11.find_first_tlv.value",
            raw_tlv,
            lambda buf: self._read_tlv(buf, 0),
            default=None,
        )
        if tlv is None:
            return b""
        _, value, _, _ = tlv
        return value

    def _unwrap_single_tlv_value(self, data: bytes, expected_tag: bytes) -> bytes:
        if len(data) == 0:
            return b""
        try:
            tag_bytes, value, raw_tlv, _ = self._read_tlv(data, 0)
        except Exception:
            return b""
        if tag_bytes != expected_tag:
            return b""
        if raw_tlv != data:
            return b""
        return value

    def _extract_choice_item(self, response: bytes, expected_choice_tag: bytes) -> bytes:
        if len(response) == 0:
            return b""
        root_tlv = safe_parse(
            "scp11.choice_item.root",
            response,
            lambda buf: self._read_tlv(buf, 0),
            default=None,
        )
        if root_tlv is None:
            return b""
        root_tag, root_value, _, _ = root_tlv
        if root_tag != bytes.fromhex("BF2B"):
            return b""
        inner_tlv = safe_parse(
            "scp11.choice_item.inner",
            root_value,
            lambda buf: self._read_tlv(buf, 0),
            default=None,
        )
        if inner_tlv is None:
            return b""
        choice_tag, _, choice_raw, _ = inner_tlv
        if choice_tag != expected_choice_tag:
            return b""
        return choice_raw

    def _encode_named_bit_string(self, bit_positions: list) -> bytes:
        if len(bit_positions) == 0:
            return b"\x00"
        highest_bit = max(int(position) for position in bit_positions if int(position) >= 0)
        byte_length = (highest_bit // 8) + 1
        payload = bytearray(byte_length)
        for position in bit_positions:
            bit_index = int(position)
            if bit_index < 0:
                continue
            byte_index = bit_index // 8
            bit_in_byte = bit_index % 8
            payload[byte_index] |= 0x80 >> bit_in_byte
        unused_bits = (8 - ((highest_bit % 8) + 1)) % 8
        return bytes([unused_bits]) + bytes(payload)

    def _segment_card_package(self, payload: bytes) -> list:
        if len(payload) == 0:
            return []
        try:
            tag_bytes, _, _, _ = self._read_tlv(payload, 0)
        except Exception:
            return [payload]
        if tag_bytes == bytes.fromhex("BF36"):
            return self._segment_bound_profile_package(payload)
        return [payload]

    def _decode_ascii_or_hex(self, value: bytes) -> str:
        if len(value) == 0:
            return ""
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex().upper()
        if text.isprintable():
            return text
        return value.hex().upper()

    def _decode_small_value(self, value: bytes) -> str:
        if len(value) == 0:
            return ""
        if len(value) == 1:
            return str(value[0])
        return value.hex().upper()

    def _phase_load_credentials(self) -> None:
        print("\n[*] Phase: Load Credentials")
        if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
            self._ensure_local_credentials_loaded()
            print("[+] Local DP credentials loaded for SGP.26 simulation.")
            return

        if self._local_fallback_enabled():
            try:
                self._ensure_local_credentials_loaded()
                print("[+] Remote DP mode with local fallback enabled (credentials loaded).")
            except Exception as error:
                print(f"[*] Remote DP mode; local fallback unavailable ({error}).")
            return

        print("[*] Remote DP mode. Using provider-managed credentials only.")

    def _phase_authentication_seed(self, matching_id: str, smdp_address: str) -> dict:
        print("\n[*] Phase: Authentication Seed")
        euicc_info1 = self._send_es10b_store_data(
            bytes.fromhex("BF2000"),
            "HANDSHAKE: GetEuiccInfo1",
            allow_stk_retry=True,
        )
        challenge_response = self._send_es10b_store_data(
            bytes.fromhex("BF2E00"),
            "HANDSHAKE: GetEuiccChallenge",
            allow_stk_retry=True,
        )
        self.state.card_challenge = challenge_response[-16:]
        print(f"[+] Card Challenge: {self.state.card_challenge.hex().upper()}")

        auth_seed = self._initiate_authentication_with_provider(
            euicc_info1,
            smdp_address=smdp_address,
        )
        auth_seed["matching_id"] = matching_id
        return auth_seed

    def _initiate_authentication_with_provider(self, euicc_info1: bytes, smdp_address: str) -> dict:
        can_use_provider = self.profile_provider is not None
        if can_use_provider is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("No profile provider configured and local fallback is disabled.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        request_obj = InitiateAuthenticationRequest(
            euicc_challenge=self._b64encode(self.state.card_challenge),
            euicc_info1=self._b64encode(euicc_info1),
            smdp_address=smdp_address,
            euicc_ci_pkid_hint=str(getattr(self.state, "current_euicc_ci_pkid", "")).strip(),
        )
        try:
            response = self.profile_provider.initiate_authentication(request_obj)
        except NotImplementedError:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider initiateAuthentication not implemented and local fallback is disabled.")
            print("[*] Provider initiateAuthentication not implemented, using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)
        except Exception as error:
            if self._local_fallback_enabled() is False:
                raise RuntimeError(f"Provider initiateAuthentication failed: {error}")
            print(f"[*] Provider initiateAuthentication failed ({error}), using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        server_signed1_bytes = self._decode_string_payload(response.server_signed1)
        server_signature1 = self._decode_string_payload(response.server_signature1)
        server_certificate_bytes = self._decode_string_payload(response.server_certificate)
        ci_pk_id = self._decode_ci_pk_id_payload(response.euicc_ci_pkid_to_be_used)
        provider_transaction_id = str(response.transaction_id).strip()
        transaction_id = self._decode_string_payload(provider_transaction_id)

        has_required_fields = True
        if len(server_signed1_bytes) == 0:
            has_required_fields = False
        if len(server_signature1) == 0:
            has_required_fields = False
        if len(server_certificate_bytes) == 0:
            has_required_fields = False
        if len(transaction_id) == 0:
            has_required_fields = False

        if has_required_fields is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider initiateAuthentication response incomplete.")
            print("[*] Provider initiateAuthentication response incomplete, using local fallback.")
            return self._build_local_auth_seed(smdp_address=smdp_address)

        self._validate_provider_server_certificate(server_certificate_bytes, ci_pk_id)
        self.state.provider_transaction_id = provider_transaction_id
        self.state.transaction_id = transaction_id
        return {
            "server_signed1": server_signed1_bytes,
            "server_signature1": server_signature1,
            "server_certificate": server_certificate_bytes,
            "root_ci_id": ci_pk_id,
        }

    def _build_local_auth_seed(self, smdp_address: str) -> dict:
        self._ensure_local_credentials_loaded()
        signed1, transaction_id, server_challenge = CryptoEngine.generate_server_challenges(
            self.state.card_challenge,
            smdp_address,
        )
        self.state.transaction_id = transaction_id
        self.state.provider_transaction_id = self._b64encode(transaction_id)
        self.state.server_challenge = server_challenge
        signature = CryptoEngine.sign_asn1(signed1, self.key_auth)
        return {
            "server_signed1": signed1,
            "server_signature1": signature,
            "server_certificate": self.cert_auth,
            "root_ci_id": self.cfg.ROOT_CI_ID,
        }

    def _phase_authenticate_server(self, auth_seed: dict, matching_id: str) -> None:
        print("\n[*] Phase: Authenticate Server with eUICC")
        ctx_params = {
            "matchingId": matching_id,
            "deviceInfo": {
                "tac": self.cfg.TAC,
                "deviceCapabilities": self.cfg.CAPABILITIES,
            },
        }
        payload = PayloadBuilder.build_auth_server(
            signed1=auth_seed["server_signed1"],
            signature=auth_seed["server_signature1"],
            cert=auth_seed["server_certificate"],
            ctx_params=ctx_params,
            root_ci_id=auth_seed["root_ci_id"],
        )
        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "AUTH: AuthenticateServer",
        )
        self._parse_authenticate_server_response(response)
        self.state.authenticate_server_response_b64 = self._b64encode(response)

    def _parse_authenticate_server_response(self, data: bytes) -> None:
        print("\n[*] Parsing Auth Response...")
        if data[:2] != b"\xBF\x38":
            raise ValueError("Invalid Response Tag (Expected BF38)")

        try:
            decoded = decode_authenticate_server_response(data)
        except Exception:
            decoded = None

        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "authenticateResponseError":
                error_detail = self._extract_error_details_from_decoded(choice_value)
                if len(error_detail) > 0:
                    raise PermissionError(f"Server Auth Refused by Card. {error_detail}")
                raise PermissionError("Server Auth Refused by Card (decoded error response)")

            if choice_name == "authenticateResponseOk" and isinstance(choice_value, dict):
                self.state.euicc_signed1 = self._extract_euicc_signed1(data)
                euicc_signature1 = choice_value.get("euiccSignature1", b"")
                if isinstance(euicc_signature1, bytes):
                    self.state.euicc_signature1 = euicc_signature1
                    preview = self.state.euicc_signature1.hex()[:32]
                    print(f"[+] Captured euiccSignature1: {preview}...")
                    return

        choice_kind, choice_payload = self._extract_choice_payload(data)
        if choice_kind == "error":
            error_detail = self._decode_authenticate_server_error_constructed(choice_payload)
            if len(error_detail) > 0:
                raise PermissionError(f"Server Auth Refused by Card. {error_detail}")
            raise PermissionError("Server Auth Refused by Card (error response)")

        if choice_kind == "ok":
            if self._parse_authenticate_server_ok_fallback(choice_payload):
                return

        preview = data.hex().upper()
        if len(preview) > 120:
            preview = preview[:120] + "..."
        raise ValueError(f"Could not parse AuthenticateServer response. Raw={preview}")

    def _parse_authenticate_server_ok_fallback(self, payload: bytes) -> bool:
        try:
            first_tag, first_value, first_raw, offset = self._read_tlv(payload, 0)
            if first_tag != b"\x30":
                return False

            second_tag, second_value, _, offset = self._read_tlv(payload, offset)
            if second_tag != bytes.fromhex("5F37"):
                return False

            # Optional certificates follow. We do not need to parse them here
            # to continue the remote ES9 flow; the raw AuthenticateServer response
            # is already preserved for authenticateClient.
            self.state.euicc_signed1 = first_raw
            self.state.euicc_signature1 = second_value
            preview = self.state.euicc_signature1.hex()[:32]
            print(f"[+] Captured euiccSignature1: {preview}...")
            return True
        except Exception:
            return False

    def _extract_choice_payload(self, payload: bytes) -> tuple:
        if len(payload) == 0:
            return "", b""
        try:
            _, root_value, _, _ = self._read_tlv(payload, 0)
            choice_tag, choice_value, _, _ = self._read_tlv(root_value, 0)
        except Exception:
            return "", b""
        if choice_tag in [b"\xA1", b"\x61"]:
            return "error", choice_value
        if choice_tag in [b"\xA0", b"\x60"]:
            return "ok", choice_value
        return "", b""

    def _decode_authenticate_server_error_constructed(self, payload: bytes) -> str:
        details = self._collect_small_integer_tlvs(payload)
        if len(details) == 0:
            return "AuthenticateResponseError (constructed) received."
        return "AuthenticateResponseError (constructed) " + ", ".join(details)

    def _collect_small_integer_tlvs(self, data: bytes) -> list:
        details = []
        index = 0
        while index < len(data):
            tag = data[index]
            index += 1
            length, len_size = self._decode_length(data, index)
            if len_size == 0:
                break
            index += len_size
            end = index + length
            if end > len(data):
                break
            value = data[index:end]
            index = end

            if len(value) == 0:
                continue
            if len(value) > 4:
                continue
            int_value = int.from_bytes(value, "big", signed=False)
            details.append(f"tag 0x{tag:02X}=0x{int_value:X}")
        return details

    def _decode_length(self, data: bytes, offset: int) -> tuple:
        if offset >= len(data):
            return 0, 0
        first = data[offset]
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        if count == 0:
            return 0, 0
        end = offset + 1 + count
        if end > len(data):
            return 0, 0
        length = int.from_bytes(data[offset + 1:end], "big")
        return length, 1 + count

    def _extract_euicc_signed1(self, authenticate_server_response: bytes) -> bytes:
        try:
            return extract_euicc_signed1(authenticate_server_response)
        except Exception as error:
            print(f"[*] pySim could not extract euiccSigned1 ({error}).")
            return b""

    def _read_tlv(self, data: bytes, offset: int):
        if offset >= len(data):
            raise ValueError("TLV offset out of range.")

        tag_start = offset
        offset += 1
        if data[tag_start] & 0x1F == 0x1F:
            while offset < len(data):
                current = data[offset]
                offset += 1
                if current & 0x80 == 0:
                    break
            else:
                raise ValueError("Truncated multi-byte tag.")

        tag_bytes = data[tag_start:offset]
        length, length_size = self._decode_length(data, offset)
        if length_size == 0:
            raise ValueError("Invalid TLV length.")

        value_start = offset + length_size
        value_end = value_start + length
        if value_end > len(data):
            raise ValueError("TLV value overruns input.")

        raw_tlv = data[tag_start:value_end]
        return tag_bytes, data[value_start:value_end], raw_tlv, value_end

    def _extract_euicc_signed2(self, prepare_download_response: bytes) -> bytes:
        try:
            return extract_euicc_signed2(prepare_download_response)
        except Exception as error:
            print(f"[*] pySim could not extract euiccSigned2 ({error}).")
            return b""

    def _validate_provider_server_certificate(self, server_certificate_bytes: bytes, ci_pk_id: bytes) -> None:
        bundle_path = ""
        provider = self.profile_provider
        if hasattr(provider, "resolve_provider_certificate_validation_bundle"):
            try:
                bundle_path = provider.resolve_provider_certificate_validation_bundle(
                    server_certificate_bytes,
                    trust_hint_ci_pkid=(
                        ci_pk_id.hex().upper()
                        if len(ci_pk_id) > 0
                        else str(getattr(self.state, "current_euicc_ci_pkid", "")).strip()
                    ),
                )
            except Exception as error:
                print(f"[*] Dynamic provider certificate bundle resolution failed ({error}).")
                bundle_path = ""
        if len(bundle_path) == 0:
            bundle_path = str(getattr(self.cfg, "ES9_CA_BUNDLE_PATH", "")).strip()
        if len(bundle_path) > 0:
            matched_subject = verify_certificate_against_ca_bundle(server_certificate_bytes, bundle_path)
            if len(matched_subject) > 0:
                print(f"[+] Provider certificate validated against CA bundle: {matched_subject}")

        authority_key_id = get_certificate_authority_key_identifier(server_certificate_bytes)
        if len(ci_pk_id) == 0:
            return
        if len(authority_key_id) == 0:
            return
        if authority_key_id != ci_pk_id:
            raise RuntimeError(
                "Provider certificate authority key identifier does not match euiccCiPKIdToBeUsed."
            )

    def _phase_prepare_download(self, smdp_address: str) -> None:
        print("\n[*] Phase: Prepare Download")
        remote_payload = self._get_prepare_download_payload_from_provider(smdp_address=smdp_address)
        if remote_payload is None:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient did not return usable payload and local fallback is disabled.")
            self._ensure_local_credentials_loaded()
            payload = PayloadBuilder.build_prepare_download(
                self.state.transaction_id,
                self.state.euicc_signature1,
                self.cert_pb,
                self.key_pb,
            )
        else:
            payload = remote_payload

        response = self.apdu_channel.send_chunked(
            0x80,
            0xE2,
            0x91,
            0x00,
            payload,
            "DOWNLOAD: PrepareDownload",
        )
        self._parse_prepare_download_response(response)
        self.state.euicc_signed2 = self._extract_euicc_signed2(response)
        self.state.prepare_download_response_b64 = self._b64encode(response)
        print(f"[+] PrepareDownload Response: {response.hex()[:60]}...")

    def _get_prepare_download_payload_from_provider(self, smdp_address: str) -> Optional[bytes]:
        if self.profile_provider is None:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("No profile provider configured for authenticateClient.")
            return None

        authenticate_request = AuthenticateClientRequest(
            transaction_id=self._encode_transaction_id(self.state.transaction_id),
            authenticate_server_response=self.state.authenticate_server_response_b64,
            smdp_address=smdp_address,
        )
        try:
            authenticate_response = self.profile_provider.authenticate_client(authenticate_request)
        except NotImplementedError:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient not implemented and local fallback is disabled.")
            if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
                print("[*] Local SGP.26 authenticateClient not available yet, fallback to local signing.")
            return None
        except Exception as error:
            if self._local_fallback_enabled() is False:
                raise RuntimeError(f"Provider authenticateClient failed: {error}")
            print(f"[*] Provider authenticateClient failed ({error}), fallback to local signing.")
            return None

        smdp_signed2_raw = self._decode_string_payload(authenticate_response.smdp_signed2)
        smdp_signature2_raw = self._decode_string_payload(authenticate_response.smdp_signature2)
        smdp_certificate_raw = self._decode_string_payload(authenticate_response.smdp_certificate)

        has_remote_payload = True
        if len(smdp_signed2_raw) == 0:
            has_remote_payload = False
        if len(smdp_signature2_raw) == 0:
            has_remote_payload = False
        if len(smdp_certificate_raw) == 0:
            has_remote_payload = False

        if has_remote_payload is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient returned incomplete payload.")
            return None

        if self._provider_certificate_payload_supported(smdp_certificate_raw) is False:
            if self._local_fallback_enabled() is False:
                raise RuntimeError("Provider authenticateClient payload parse failed: invalid smdpCertificate.")
            print("[*] Provider authenticateClient payload parse failed (invalid smdpCertificate), fallback to local signing.")
            return None
        self.state.provider_smdp_certificate = smdp_certificate_raw
        return PayloadBuilder.build_prepare_download_remote(
            smdp_signed2_der=smdp_signed2_raw,
            smdp_signature2=smdp_signature2_raw,
            cert=smdp_certificate_raw,
        )

    @staticmethod
    def _provider_certificate_payload_supported(certificate_bytes: bytes) -> bool:
        raw_value = bytes(certificate_bytes or b"")
        if len(raw_value) == 0:
            return False
        try:
            if decode_certificate(raw_value) is not None:
                return True
        except Exception:
            pass
        try:
            crypto_x509.load_der_x509_certificate(raw_value)
            return True
        except Exception:
            pass
        try:
            crypto_x509.load_pem_x509_certificate(raw_value)
            return True
        except Exception:
            return False

    def _phase_get_bound_profile_package(self, smdp_address: str) -> bool:
        print("\n[*] Phase: Get Bound Profile Package")
        self.state.bpp_b64 = ""
        self.state.bpp_bytes = b""
        if self.profile_provider is None:
            print("[*] No provider configured, skipping BPP retrieval.")
            return False

        request = GetBoundProfilePackageRequest(
            transaction_id=self._encode_transaction_id(self.state.transaction_id),
            prepare_download_response=self.state.prepare_download_response_b64,
            smdp_address=smdp_address,
        )
        try:
            response = self.profile_provider.get_bound_profile_package(request)
        except NotImplementedError:
            print("[*] Provider getBoundProfilePackage not implemented yet.")
            return False
        except Exception as error:
            raise RuntimeError(f"Provider getBoundProfilePackage failed: {error}") from error

        self.state.bpp_b64 = response.bound_profile_package
        self.state.bpp_bytes = self._decode_string_payload(response.bound_profile_package)
        if len(self.state.bpp_bytes) == 0:
            print("[*] Bound Profile Package is empty.")
            return False

        structure_summary = self._summarize_bound_profile_package(self.state.bpp_bytes)
        print(f"[+] Bound Profile Package was received ({len(self.state.bpp_bytes)} bytes).")
        if len(structure_summary) > 0:
            print(f"[*] BPP structure: {structure_summary}")
        return True

    def _parse_prepare_download_response(self, data: bytes) -> None:
        if len(data) < 3 or data[:2] != b"\xBF\x21":
            return

        try:
            decoded = decode_prepare_download_response(data)
        except Exception:
            decoded = None

        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "downloadResponseError":
                error_detail = self._extract_error_details_from_decoded(choice_value)
                if len(error_detail) > 0:
                    raise PermissionError(f"PrepareDownload refused by card. {error_detail}")
                raise PermissionError("PrepareDownload refused by card (decoded error response)")
            return

        choice_kind, choice_payload = self._extract_choice_payload(data)
        if choice_kind == "error":
            error_detail = self._decode_prepare_download_error_constructed(choice_payload)
            if len(error_detail) > 0:
                raise PermissionError(f"PrepareDownload refused by card. {error_detail}")
            raise PermissionError("PrepareDownload refused by card (error response)")

    def _decode_prepare_download_error_constructed(self, payload: bytes) -> str:
        details = self._collect_small_integer_tlvs(payload)
        if len(details) == 0:
            return "PrepareDownloadResponseError (constructed) received."
        return "PrepareDownloadResponseError (constructed) " + ", ".join(details)

    def _phase_install_package(self) -> bool:
        print("\n[*] Phase: Install Package")
        self.state.load_bpp_response = b""
        self.state.load_bpp_aid = b""
        self.state.load_bpp_sima_response = b""
        if len(self.state.bpp_bytes) == 0:
            print("[*] No Bound Profile Package available for installation.")
            return False

        structure_summary = self._summarize_bound_profile_package(self.state.bpp_bytes)
        if len(structure_summary) > 0:
            print(f"[*] Loading BPP: {structure_summary}")

        segments = self._segment_bound_profile_package(self.state.bpp_bytes)
        print(f"[*] Segmented BPP into {len(segments)} ES10b payload(s).")
        self._inspect_install_bootstrap(segments)

        last_response = b""
        for index, segment in enumerate(segments, start=1):
            segment_tag = self._tag_hex(segment)
            print(f"[*] Load segment {index}/{len(segments)}: tag={segment_tag} len={len(segment)}")
            last_response = self._send_personalization_store_data(
                segment,
                f"DOWNLOAD: LoadBoundProfilePackage [{index}/{len(segments)}]",
            )
            if self._is_terminal_profile_installation_result(last_response):
                print("[*] LoadBoundProfilePackage returned terminal ProfileInstallationResult; stopping further segments.")
                break

        self.state.load_bpp_response = last_response
        if len(last_response) == 0:
            print("[+] LoadBoundProfilePackage completed with empty response data.")
            self._sync_pending_notifications()
            return True

        print(f"[+] LoadBoundProfilePackage Response: {last_response.hex()[:60]}...")
        self._handle_profile_load_result(last_response)
        self._sync_pending_notifications(last_response)
        if self._is_failed_profile_installation_result(last_response):
            failure_summary = self._summarize_profile_installation_result(last_response)
            if len(failure_summary) == 0:
                failure_summary = "ProfileInstallationResult reported failure."
            raise RuntimeError(f"LoadBoundProfilePackage failed: {failure_summary}")
        return True

    def _attempt_install_failure_cleanup(self, install_error: Exception) -> None:
        print(f"[*] Install failure cleanup: attempting cancelSession ({install_error}).")
        try:
            cancel_response = self._send_cancel_session_request(reason=self.CANCEL_SESSION_REASON_TIMEOUT)
        except Exception as error:
            print(f"[*] Install failure cleanup: ES10b cancelSession failed ({error}).")
            return

        if len(cancel_response) == 0:
            print("[*] Install failure cleanup: cancelSession returned no response payload.")
            return

        if self.profile_provider is None:
            print("[*] Install failure cleanup: no profile provider configured, skipping ES9 cancelSession.")
            return

        try:
            request = CancelSessionRequest(
                transaction_id=self._encode_transaction_id(self.state.transaction_id),
                cancel_session_response=self._b64encode(cancel_response),
            )
            es9_response = self.profile_provider.cancel_session(request)
            print("[+] Install failure cleanup: ES9 cancelSession sent.")
            print(f"[*] Install failure cleanup: ES9 cancelSession response: {self._summarize_es9_response(es9_response)}")
            self._sync_pending_notifications()
        except Exception as error:
            print(f"[*] Install failure cleanup: ES9 cancelSession failed ({error}).")

    def _send_cancel_session_request(self, reason: int) -> bytes:
        print(f"[*] Install failure cleanup: cancelSession reason={reason}.")
        payload = self._build_cancel_session_request_payload(reason)
        response = self._send_es10b_store_data(
            payload,
            "DOWNLOAD: CancelSession",
            allow_stk_retry=True,
        )
        return response

    def _build_cancel_session_request_payload(self, reason: int) -> bytes:
        transaction_id = self._decode_prepare_download_response_ok(
            self._decode_string_payload(self.state.prepare_download_response_b64)
        ).get("transactionId", b"")
        if len(transaction_id) == 0:
            transaction_id = self.state.transaction_id
        if len(transaction_id) == 0:
            raise RuntimeError("Cannot cancel session without transactionId.")
        payload = encode_cancel_session_request(transaction_id=transaction_id, reason=reason)
        if len(payload) > 0:
            return payload
        return self._wrap_tlv(bytes.fromhex("BF41"), self._wrap_tlv(b"\x80", transaction_id) + self._wrap_tlv(b"\x81", bytes([reason & 0xFF])))

    def _summarize_es9_response(self, response: Any) -> str:
        if isinstance(response, dict) is False:
            if response is None:
                return "empty body"
            return str(response)

        if len(response) == 0:
            return "empty body"

        header = response.get("header")
        if isinstance(header, dict):
            execution = header.get("functionExecutionStatus")
            if isinstance(execution, dict):
                status = str(execution.get("status", "")).strip()
                status_code = execution.get("statusCodeData")
                fragments = []
                if len(status) > 0:
                    fragments.append(f"status={status}")
                if isinstance(status_code, dict):
                    subject_code = str(status_code.get("subjectCode", "")).strip()
                    reason_code = str(status_code.get("reasonCode", "")).strip()
                    message = str(status_code.get("message", "")).strip()
                    if len(subject_code) > 0:
                        fragments.append(f"subjectCode={subject_code}")
                    if len(reason_code) > 0:
                        fragments.append(f"reasonCode={reason_code}")
                    if len(message) > 0:
                        fragments.append(f"message={message}")
                if len(fragments) > 0:
                    return ", ".join(fragments)

        keys = sorted(str(key) for key in response.keys())
        return "keys=" + ",".join(keys)

    def _sync_pending_notifications(self, initial_response: bytes = b"") -> None:
        # SGP.22 §5.6.4: pending profile-state notifications MUST be
        # forwarded to the recipient SM-DP+ before the LPA removes them
        # from the eUICC queue. ``_last_notification_sync_succeeded``
        # carries that outcome to the console layer's auto-clear gate.
        self._last_notification_sync_succeeded = None
        if self.profile_provider is None:
            return
        forward_failures = 0
        inline_notification, inline_seq_number = self._extract_inline_pending_notification(initial_response)
        if len(inline_notification) > 0:
            if self._forward_pending_notification(inline_notification, inline_seq_number, "inline"):
                self._remove_notification_from_list(inline_seq_number)
            else:
                forward_failures += 1
        try:
            response = self._list_pending_notifications_with_context_recovery()
        except Exception as error:
            print(
                f"[*] Notification sync: listNotifications failed ({error}); "
                "leaving on-card notifications queued for the next attempt."
            )
            self._last_notification_sync_succeeded = False
            return

        notifications = self._extract_notification_metadata_entries(response)
        if len(notifications) == 0:
            print("[*] Notification sync: no queued notifications found.")
            self._last_notification_sync_succeeded = forward_failures == 0
            return

        print(f"[*] Notification sync: forwarding {len(notifications)} notification(s).")
        for notification in notifications:
            seq_number = notification.get("seqNumber")
            if isinstance(seq_number, int) is False:
                continue

            raw_pending_notification = self._retrieve_pending_notification(seq_number)
            if len(raw_pending_notification) == 0:
                forward_failures += 1
                continue
            if self._forward_pending_notification(raw_pending_notification, seq_number, "queued") is False:
                forward_failures += 1
                continue
            self._remove_notification_from_list(seq_number)
        # SGP.22 §5.6.4 again: a successful list round-trip with N forward
        # failures still leaves N entries on the card, so the sync is only
        # ``succeeded'' when every retrieved notification was either ack'd
        # by SM-DP+ or removed locally. Anything less must propagate to the
        # console auto-clear gate or unforwarded entries get silently
        # dropped on the next post-command sweep.
        if forward_failures > 0:
            print(
                f"[*] Notification sync: {forward_failures} notification(s) "
                "could not be forwarded to SM-DP+; leaving the unforwarded "
                "entries on-card for the next attempt."
            )
            self._last_notification_sync_succeeded = False
            return
        self._last_notification_sync_succeeded = True

    def _extract_inline_pending_notification(self, raw_response: bytes) -> tuple:
        if len(raw_response) == 0:
            return b"", None
        root_tlv = safe_parse(
            "scp11.inline_pending_notification.root",
            raw_response,
            lambda buf: self._read_tlv(buf, 0),
            default=None,
        )
        if root_tlv is None:
            return b"", None
        root_tag, _, _, _ = root_tlv
        if root_tag != bytes.fromhex("BF37"):
            return b"", None
        bf2f_raw = self._find_first_tlv_in_value(raw_response, bytes.fromhex("BF2F"))
        if len(bf2f_raw) == 0:
            return b"", None
        seq_number = self._extract_notification_sequence_from_metadata(bf2f_raw)
        return raw_response, seq_number

    def _forward_pending_notification(self, raw_pending_notification: bytes, seq_number: Optional[int], source: str) -> bool:
        try:
            details = self._decode_pending_notification_details(raw_pending_notification)
            notification_address = self._extract_notification_address_for_forwarding(details)
            request = HandleNotificationRequest(
                pending_notification=self._b64encode(raw_pending_notification),
                smdp_address=notification_address,
            )
            self._announce_handle_notification_target(notification_address, source, seq_number)
            es9_response = self.profile_provider.handle_notification(request)
            seq_fragment = ""
            if isinstance(seq_number, int):
                seq_fragment = f" seq={seq_number}"
            detail_fragment = self._format_notification_details(details)
            if len(detail_fragment) > 0:
                detail_fragment = f" ({detail_fragment})"
            print(
                f"[*] Notification sync: forwarded {source} notification{seq_fragment}{detail_fragment}. "
                f"ES9 response: {self._summarize_es9_response(es9_response)}"
            )
            return True
        except Exception as error:
            seq_fragment = ""
            if isinstance(seq_number, int):
                seq_fragment = f" seq={seq_number}"
            print(f"[*] Notification sync: handleNotification failed for {source} notification{seq_fragment} ({error}).")
            return False

    def _extract_notification_address_for_forwarding(self, details: dict) -> str:
        """Pick the SM-DP+ FQDN that minted the notification.

        SGP.22 §5.6.4 -- NotificationMetadata.notificationAddress (BF2F
        tag 0C, UTF8String) names the destination ES9+ endpoint per
        notification. Falls back to "" when absent so the ES9 client
        keeps using its configured base URL (legacy behaviour).
        """
        if not isinstance(details, dict):
            return ""
        candidate = details.get("notificationAddress")
        if isinstance(candidate, bytes):
            try:
                candidate = candidate.decode("utf-8", "ignore")
            except Exception:
                return ""
        if not isinstance(candidate, str):
            return ""
        return candidate.strip()

    def _announce_handle_notification_target(
        self,
        notification_address: str,
        source: str,
        seq_number: Optional[int],
    ) -> None:
        seq_fragment = ""
        if isinstance(seq_number, int):
            seq_fragment = f" seq={seq_number}"
        if len(notification_address) > 0:
            print(
                f"[*] Notification sync: routing {source} notification{seq_fragment} "
                f"to SM-DP+ {notification_address} (per SGP.22 §5.6.4 notificationAddress)."
            )
        else:
            print(
                f"[*] Notification sync: routing {source} notification{seq_fragment} "
                f"to configured ES9 base URL (no notificationAddress in metadata)."
            )

    def _handle_profile_load_result(self, raw_response: bytes) -> None:
        details = self._decode_profile_installation_result(raw_response)
        if len(details) == 0:
            return
        aid = details.get("aid")
        if isinstance(aid, bytes):
            self.state.load_bpp_aid = aid
        sima_response = details.get("simaResponse")
        if isinstance(sima_response, bytes):
            self.state.load_bpp_sima_response = sima_response
        fragments = []
        transaction_id = details.get("transactionId")
        if isinstance(transaction_id, bytes) and len(transaction_id) > 0:
            fragments.append(f"transactionId={transaction_id.hex().upper()}")
        aid_bytes = details.get("aid")
        if isinstance(aid_bytes, bytes) and len(aid_bytes) > 0:
            fragments.append(f"aid={aid_bytes.hex().upper()}")
        sima_bytes = details.get("simaResponse")
        if isinstance(sima_bytes, bytes) and len(sima_bytes) > 0:
            fragments.append(f"simaResponse={self._format_sima_response(sima_bytes)}")
        result_code = details.get("resultCode")
        if isinstance(result_code, int):
            fragments.append(f"resultCode={result_code}")
        result_detail = details.get("resultDetail")
        if isinstance(result_detail, int):
            fragments.append(f"resultDetail={result_detail}")
        result_meaning = self._describe_profile_installation_result_code(
            result_code,
            result_detail,
            details.get("finalResultTag"),
        )
        if len(result_meaning) > 0:
            fragments.append(f"meaning={result_meaning}")
        smdp_oid = details.get("smdpOid")
        if isinstance(smdp_oid, str) and len(smdp_oid) > 0:
            fragments.append(f"smdpOid={smdp_oid}")
        print("[*] LoadBoundProfilePackage decoded result: " + ", ".join(fragments))

    def _remove_notification_from_list(self, seq_number: Optional[int]) -> None:
        if isinstance(seq_number, int) is False:
            return
        try:
            payload = encode_notification_sent_request(seq_number)
            if len(payload) == 0:
                seq_bytes = self._encode_notification_sequence(seq_number)
                payload = self._wrap_tlv(bytes.fromhex("BF30"), self._wrap_tlv(b"\x80", seq_bytes))
            self._send_es10b_store_data(
                payload,
                f"DOWNLOAD: RemoveNotificationFromList [{seq_number}]",
                allow_stk_retry=True,
            )
        except Exception as error:
            print(f"[*] Notification sync: removeNotificationFromList failed for seq={seq_number} ({error}).")

    def _extract_notification_sequence_from_metadata(self, raw_metadata: bytes) -> Optional[int]:
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_metadata, 0)
        except Exception:
            return None
        if root_tag != bytes.fromhex("BF2F"):
            return None
        offset = 0
        while offset < len(root_value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                return None
            if field_tag == b"\x80" and len(field_value) > 0:
                return int.from_bytes(field_value, "big", signed=False)
            offset = next_offset
        return None

    def _find_first_tlv_in_value(self, value: bytes, target_tag: bytes) -> bytes:
        offset = 0
        while offset < len(value):
            try:
                tag_bytes, child_value, raw_tlv, next_offset = self._read_tlv(value, offset)
            except Exception:
                return b""
            if tag_bytes == target_tag:
                return raw_tlv
            if self._is_constructed_tag(tag_bytes):
                nested = self._find_first_tlv_in_value(child_value, target_tag)
                if len(nested) > 0:
                    return nested
            offset = next_offset
        return b""

    def _decode_profile_installation_result(self, raw_response: bytes) -> dict:
        if len(raw_response) == 0:
            return {}
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        except Exception:
            return {}
        if root_tag != bytes.fromhex("BF37"):
            return {}
        try:
            inner_tag, inner_value, _, _ = self._read_tlv(root_value, 0)
        except Exception:
            return {}
        if inner_tag != bytes.fromhex("BF27"):
            return {}
        details = {
            "transactionId": b"",
            "seqNumber": None,
            "profileManagementOperation": None,
            "notificationAddress": "",
            "iccid": "",
            "smdpOid": "",
            "aid": b"",
            "simaResponse": b"",
            "euiccSignPIR": b"",
            "finalResultTag": b"",
            "resultCode": None,
            "resultDetail": None,
        }
        offset = 0
        while offset < len(inner_value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(inner_value, offset)
            except Exception:
                break
            if field_tag == b"\x80":
                details["transactionId"] = field_value
            elif field_tag == bytes.fromhex("BF2F"):
                metadata = self._decode_notification_metadata_fields(field_value)
                details.update(metadata)
            elif field_tag == b"\x06":
                details["smdpOid"] = self._decode_oid(field_value)
            elif field_tag == b"\xA2":
                self._decode_profile_installation_final_result(field_value, details)
            elif field_tag == bytes.fromhex("5F37"):
                details["euiccSignPIR"] = field_value
            offset = next_offset
        return details

    def _decode_profile_installation_final_result(self, value: bytes, details: dict) -> None:
        offset = 0
        while offset < len(value):
            try:
                result_tag, result_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                return
            if result_tag in [b"\xA0", b"\xA1"]:
                details["finalResultTag"] = result_tag
                inner_offset = 0
                while inner_offset < len(result_value):
                    try:
                        field_tag, field_value, _, inner_next_offset = self._read_tlv(result_value, inner_offset)
                    except Exception:
                        return
                    if field_tag == b"\x80":
                        details["resultCode"] = int.from_bytes(field_value, "big", signed=False)
                    elif field_tag == b"\x81":
                        details["resultDetail"] = int.from_bytes(field_value, "big", signed=False)
                    elif field_tag == b"\x4F":
                        details["aid"] = field_value
                    elif field_tag == b"\x04":
                        details["simaResponse"] = field_value
                    inner_offset = inner_next_offset
            offset = next_offset

    def _decode_notification_metadata_fields(self, value: bytes) -> dict:
        details = {
            "seqNumber": None,
            "profileManagementOperation": None,
            "notificationAddress": "",
            "iccid": "",
        }
        offset = 0
        while offset < len(value):
            try:
                field_tag, field_value, _, next_offset = self._read_tlv(value, offset)
            except Exception:
                return details
            if field_tag == b"\x80":
                details["seqNumber"] = int.from_bytes(field_value, "big", signed=False)
            elif field_tag == b"\x81":
                details["profileManagementOperation"] = int.from_bytes(field_value, "big", signed=False)
            elif field_tag == b"\x0C":
                details["notificationAddress"] = field_value.decode("utf-8", "ignore")
            elif field_tag == b"\x5A":
                details["iccid"] = self._decode_iccid_digits(field_value)
            offset = next_offset
        return details

    def _decode_pending_notification_details(self, raw_pending_notification: bytes) -> dict:
        inline_details = self._decode_profile_installation_result(raw_pending_notification)
        if len(inline_details) > 0:
            inline_details["choice"] = "profileInstallationResult"
            return inline_details
        details = {}
        try:
            decoded = decode_pending_notification(raw_pending_notification)
        except Exception:
            return details
        self._collect_notification_details(decoded, details)
        return details

    def _collect_notification_details(self, node: Any, details: dict) -> None:
        if isinstance(node, tuple) and len(node) == 2 and isinstance(node[0], str):
            choice_name, choice_value = node
            details.setdefault("choice", choice_name)
            self._collect_notification_details(choice_value, details)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "transactionId" and isinstance(value, bytes):
                    details.setdefault("transactionId", value)
                elif key == "seqNumber" and isinstance(value, int):
                    details.setdefault("seqNumber", value)
                elif key == "profileManagementOperation":
                    if isinstance(value, int):
                        details.setdefault("profileManagementOperation", value)
                    elif isinstance(value, bytes):
                        details.setdefault("profileManagementOperation", int.from_bytes(value, "big", signed=False))
                elif key == "notificationAddress":
                    if isinstance(value, str):
                        details.setdefault("notificationAddress", value)
                    elif isinstance(value, bytes):
                        details.setdefault("notificationAddress", value.decode("utf-8", "ignore"))
                elif key == "iccid":
                    if isinstance(value, bytes):
                        details.setdefault("iccid", self._decode_iccid_digits(value))
                    elif isinstance(value, str):
                        details.setdefault("iccid", value)
                elif key == "smdpOid":
                    if isinstance(value, str):
                        details.setdefault("smdpOid", value)
                    elif isinstance(value, bytes):
                        details.setdefault("smdpOid", self._decode_oid(value))
                elif key == "aid" and isinstance(value, bytes):
                    details.setdefault("aid", value)
                elif key == "simaResponse" and isinstance(value, bytes):
                    details.setdefault("simaResponse", value)
                elif key in ["euiccSignPIR", "euiccNotificationSignature"] and isinstance(value, bytes):
                    details.setdefault("euiccSignPIR", value)
                else:
                    self._collect_notification_details(value, details)
            return
        if isinstance(node, list):
            for item in node:
                self._collect_notification_details(item, details)

    def _format_notification_details(self, details: dict) -> str:
        if len(details) == 0:
            return ""
        fragments = []
        for key in ["choice", "seqNumber", "profileManagementOperation", "notificationAddress", "iccid", "smdpOid"]:
            value = details.get(key)
            if value is None:
                continue
            if isinstance(value, str) and len(value) == 0:
                continue
            fragments.append(f"{key}={value}")
        result_code = details.get("resultCode")
        if isinstance(result_code, int):
            fragments.append(f"resultCode={result_code}")
        result_detail = details.get("resultDetail")
        if isinstance(result_detail, int):
            fragments.append(f"resultDetail={result_detail}")
        result_meaning = self._describe_profile_installation_result_code(
            result_code,
            result_detail,
            details.get("finalResultTag"),
        )
        if len(result_meaning) > 0:
            fragments.append(f"meaning={result_meaning}")
        aid = details.get("aid")
        if isinstance(aid, bytes) and len(aid) > 0:
            fragments.append(f"aid={aid.hex().upper()}")
        sima_response = details.get("simaResponse")
        if isinstance(sima_response, bytes) and len(sima_response) > 0:
            fragments.append(f"simaResponse={self._format_sima_response(sima_response)}")
        return ", ".join(fragments)

    def _describe_profile_installation_result_code(
        self,
        result_code: Optional[int],
        result_detail: Optional[int],
        final_result_tag: Optional[bytes] = None,
    ) -> str:
        if isinstance(result_code, int) is False:
            return ""
        if result_code == 5:
            if final_result_tag == b"\xA0" and result_detail == 0:
                return "card completed the final profile installation step"
            if result_detail == 8:
                return "card rejected the bound profile package content during installation"
            if result_detail == 9:
                return "card rejected the profile because its ICCID is already installed"
            return "card reported a profile installation failure"
        return ""

    def _is_terminal_profile_installation_result(self, raw_response: bytes) -> bool:
        details = self._decode_profile_installation_result(raw_response)
        return len(details) > 0

    def _is_failed_profile_installation_result(self, raw_response: bytes) -> bool:
        details = self._decode_profile_installation_result(raw_response)
        if len(details) == 0:
            return False
        return details.get("finalResultTag") == b"\xA1"

    def _summarize_profile_installation_result(self, raw_response: bytes) -> str:
        details = self._decode_profile_installation_result(raw_response)
        if len(details) == 0:
            return ""
        fragments = []
        result_code = details.get("resultCode")
        if isinstance(result_code, int):
            fragments.append(f"resultCode={result_code}")
        result_detail = details.get("resultDetail")
        if isinstance(result_detail, int):
            fragments.append(f"resultDetail={result_detail}")
        aid = details.get("aid")
        if isinstance(aid, bytes) and len(aid) > 0:
            fragments.append(f"aid={aid.hex().upper()}")
        sima_response = details.get("simaResponse")
        if isinstance(sima_response, bytes) and len(sima_response) > 0:
            fragments.append(f"simaResponse={self._format_sima_response(sima_response)}")
        return ", ".join(fragments)

    def _format_sima_response(self, sima_response: bytes) -> str:
        raw_hex = sima_response.hex().upper()
        translation = self._translate_sima_response_tlv(sima_response)
        semantic = self._decode_sima_response_semantics(sima_response)
        parts = []
        if len(translation) > 0:
            parts.append(translation)
        if len(semantic) > 0:
            parts.append(semantic)
        if len(parts) == 0:
            return raw_hex
        return raw_hex + " [" + "; ".join(parts) + "]"

    def _translate_sima_response_tlv(self, data: bytes) -> str:
        return self._translate_sima_response_tlv_with_path(data, path=[])

    def _translate_sima_response_tlv_with_path(self, data: bytes, path: list) -> str:
        if len(data) == 0:
            return ""
        fragments = []
        offset = 0
        child_index = 0
        while offset < len(data):
            try:
                tag_bytes, value_bytes, _, next_offset = self._read_tlv(data, offset)
            except Exception:
                return ""
            tag_hex = tag_bytes.hex().upper()
            label = self._describe_sima_response_tag(tag_bytes, path, child_index)
            prefix = f"{tag_hex}(len={len(value_bytes)}"
            if len(label) > 0:
                prefix += f", {label}"
            prefix += ")"
            if self._is_constructed_tag(tag_bytes):
                nested = self._translate_sima_response_tlv_with_path(value_bytes, path + [tag_bytes])
                if len(nested) > 0:
                    fragments.append(prefix + "{" + nested + "}")
                else:
                    fragments.append(prefix)
            else:
                fragments.append(prefix + "=" + value_bytes.hex().upper())
            offset = next_offset
            child_index += 1
        return " -> ".join(fragments)

    def _describe_sima_response_tag(self, tag_bytes: bytes, path: list, child_index: int) -> str:
        if len(path) == 0 and tag_bytes == b"\x30":
            return "simaResponse"
        if path == [b"\x30"] and tag_bytes == b"\xA0":
            return "finalResult.successResult"
        if path == [b"\x30"] and tag_bytes == b"\xA1":
            return "finalResult.failureResult"
        if path in [[b"\x30", b"\xA0"], [b"\x30", b"\xA1"]] and tag_bytes == b"\x30":
            return "resultData"
        if path in [[b"\x30", b"\xA0"], [b"\x30", b"\xA1"]] and tag_bytes == b"\x80":
            return "resultCode"
        if path in [[b"\x30", b"\xA0"], [b"\x30", b"\xA1"]] and tag_bytes == b"\x81":
            return "resultDetail"
        if path in [[b"\x30", b"\xA0", b"\x30"], [b"\x30", b"\xA1", b"\x30"]] and tag_bytes == b"\x80":
            return "resultCode"
        if path in [[b"\x30", b"\xA0", b"\x30"], [b"\x30", b"\xA1", b"\x30"]] and tag_bytes == b"\x81":
            return "resultDetail"
        if tag_bytes == b"\x30":
            return "SEQUENCE"
        if tag_bytes == b"\xA0":
            return "ctx[0]"
        if tag_bytes == b"\xA1":
            return "ctx[1]"
        if tag_bytes == b"\x80":
            return "ctx[0]"
        if tag_bytes == b"\x81":
            return "ctx[1]"
        return ""

    def _translate_tlv_bytes(self, data: bytes) -> str:
        if len(data) == 0:
            return ""
        fragments = []
        offset = 0
        while offset < len(data):
            try:
                tag_bytes, value_bytes, _, next_offset = self._read_tlv(data, offset)
            except Exception:
                return ""
            tag_hex = tag_bytes.hex().upper()
            label = self._describe_tlv_tag(tag_bytes)
            prefix = f"{tag_hex}(len={len(value_bytes)}"
            if len(label) > 0:
                prefix += f", {label}"
            prefix += ")"
            if self._is_constructed_tag(tag_bytes):
                nested = self._translate_tlv_bytes(value_bytes)
                if len(nested) > 0:
                    fragments.append(prefix + "{" + nested + "}")
                else:
                    fragments.append(prefix)
            else:
                fragments.append(prefix + "=" + value_bytes.hex().upper())
            offset = next_offset
        return " -> ".join(fragments)

    def _describe_tlv_tag(self, tag_bytes: bytes) -> str:
        if tag_bytes == b"\x30":
            return "SEQUENCE"
        if tag_bytes == b"\xA0":
            return "ctx[0]"
        if tag_bytes == b"\xA1":
            return "ctx[1]"
        if tag_bytes == b"\x80":
            return "ctx[0]"
        if tag_bytes == b"\x81":
            return "ctx[1]"
        return ""

    def _decode_sima_response_semantics(self, sima_response: bytes) -> str:
        try:
            root_tag, root_value, _, _ = self._read_tlv(sima_response, 0)
        except Exception:
            return ""
        if root_tag != b"\x30":
            return ""
        try:
            result_choice_tag, result_choice_value, _, _ = self._read_tlv(root_value, 0)
        except Exception:
            return ""
        if result_choice_tag not in [b"\xA0", b"\xA1"]:
            return ""
        sequence_value = result_choice_value
        try:
            sequence_tag, nested_sequence_value, _, sequence_end = self._read_tlv(result_choice_value, 0)
        except Exception:
            sequence_tag = b""
            nested_sequence_value = b""
            sequence_end = 0
        if sequence_tag == b"\x30" and sequence_end == len(result_choice_value):
            sequence_value = nested_sequence_value
        try:
            field_tag, field_value, _, next_offset = self._read_tlv(sequence_value, 0)
        except Exception:
            return ""
        if field_tag != b"\x80" or len(field_value) == 0:
            return ""
        result_code = int.from_bytes(field_value, "big", signed=False)
        choice_name = "successResult"
        if result_choice_tag == b"\xA1":
            choice_name = "failureResult"
        fragments = [f"{choice_name}.resultCode={result_code}"]
        if next_offset < len(sequence_value):
            try:
                detail_tag, detail_value, _, _ = self._read_tlv(sequence_value, next_offset)
            except Exception:
                detail_tag = b""
                detail_value = b""
            if detail_tag == b"\x81" and len(detail_value) > 0:
                detail_code = int.from_bytes(detail_value, "big", signed=False)
                fragments.append(f"{choice_name}.resultDetail={detail_code}")
        return ", ".join(fragments)

    def _eid_bcd_string_to_bytes(self, digits: str) -> bytes:
        """Encode BCD digit string to bytes (two digits per byte, high nibble first)."""
        digits = "".join(c for c in digits if c.isdigit())
        if len(digits) % 2 != 0:
            digits = "0" + digits
        out = []
        for i in range(0, len(digits), 2):
            out.append((int(digits[i], 10) << 4) | int(digits[i + 1], 10))
        return bytes(out)

    def _build_get_eim_package_tlv(
        self,
        eid: str,
        euicc_challenge_bytes: bytes = b"",
        notify_state_change: bool = False,
        state_change_cause: Optional[int] = None,
        rplmn_bytes: bytes = b"",
    ) -> bytes:
        """Build GetEimPackage (BF4F) TLV with EID (5A) and optional fields.

        Binary BF4F only supports notifyStateChange [0], stateChangeCause [1],
        and rPlmn [2] in addition to eidValue. Keep euiccChallenge on the
        request object for JSON-mode compatibility, but do not encode it here.
        """
        eid_bytes = self._eid_bcd_string_to_bytes(eid)
        if len(eid_bytes) != 16:
            return b""
        inner = self._wrap_tlv(b"\x5A", eid_bytes)
        if notify_state_change:
            inner += self._wrap_tlv(b"\x80", b"")
        if state_change_cause is not None:
            if 0 <= state_change_cause <= 127:
                inner += self._wrap_tlv(b"\x81", bytes([state_change_cause]))
        if len(rplmn_bytes) > 0:
            inner += self._wrap_tlv(b"\x82", rplmn_bytes)
        return self._wrap_tlv(bytes.fromhex("BF4F"), inner)

    def _build_provide_eim_package_result_error_tlv(self, error_code: int = 127) -> bytes:
        """Build ProvideEimPackageResult (BF50) with eimPackageResultResponseError [0].
        EimPackageResultErrorCode: invalidPackageFormat(1), unknownPackage(2), undefinedError(127).
        Minimal encoding: no eidValue, no eimTransactionId."""
        if error_code < 0 or error_code > 127:
            error_code = 127
        inner_seq = bytes([0x30, 0x03, 0x02, 0x01, error_code & 0xFF])
        eim_result_error = bytes([0x80, len(inner_seq)]) + inner_seq
        provide_result = bytes([0xBF, 0x50, len(eim_result_error)]) + eim_result_error
        return provide_result

    def _build_profile_download_trigger_result_error(
        self,
        eim_transaction_id: bytes = b"",
        error_reason: int = 127,
    ) -> bytes:
        """Build ProfileDownloadTriggerResult (BF54) with profileDownloadError.
        SGP.32 v1.2 section 2.11.2.3.
        profileDownloadErrorReason: ecallActive(104), undefinedError(127).
        profileDownloadError is a bare SEQUENCE (0x30) within the CHOICE since
        profileInstallationResult already carries [55] and disables auto-tagging."""
        if error_reason < 0 or error_reason > 127:
            error_reason = 127
        reason_tlv = bytes([0x80, 0x01, error_reason & 0xFF])
        download_error_seq = self._wrap_tlv(b"\x30", reason_tlv)
        body = b""
        if len(eim_transaction_id) > 0:
            body += self._wrap_tlv(b"\x82", eim_transaction_id)
        body += download_error_seq
        return self._wrap_tlv(bytes.fromhex("BF54"), body)

    def _build_profile_download_trigger_result_tlv(
        self,
        card_response: bytes,
        eim_transaction_id: bytes = b"",
    ) -> bytes:
        if len(card_response) == 0:
            return b""
        if card_response.startswith(bytes.fromhex("BF54")):
            return card_response
        body = b""
        if len(eim_transaction_id) > 0:
            body += self._wrap_tlv(b"\x82", eim_transaction_id)
        body += card_response
        return self._wrap_tlv(bytes.fromhex("BF54"), body)

    def _encode_der_positive_integer(self, value: int) -> bytes:
        if int(value) <= 0:
            return b"\x00"
        encoded = int(value).to_bytes((int(value).bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            return b"\x00" + encoded
        return encoded

    def _build_eim_acknowledgements_tlv(self, sequence_numbers: list[int] | tuple[int, ...]) -> bytes:
        body = b""
        for sequence_number in sequence_numbers:
            integer_value = self._encode_der_positive_integer(int(sequence_number))
            body += self._wrap_tlv(b"\x80", integer_value)
        return self._wrap_tlv(bytes.fromhex("BF53"), body)

    def _build_provide_eim_package_result_ack_tlv(
        self,
        sequence_numbers: list[int] | tuple[int, ...],
        eid: str = "",
    ) -> bytes:
        body = b""
        eid_bytes = self._eid_bcd_string_to_bytes(eid)
        if len(eid_bytes) == 16:
            body += self._wrap_tlv(b"\x5A", eid_bytes)
        body += self._build_eim_acknowledgements_tlv(sequence_numbers)
        return self._wrap_tlv(bytes.fromhex("BF50"), body)

    def _find_first_context_specific_integer(
        self,
        data: bytes,
        target_tag: bytes,
    ) -> Optional[int]:
        offset = 0
        while offset < len(data):
            try:
                tag_bytes, value, _, next_offset = self._read_tlv(data, offset)
            except Exception:
                return None
            offset = next_offset
            if tag_bytes == target_tag and len(value) > 0:
                return int.from_bytes(value, "big", signed=False)
            if self._is_constructed_tag(tag_bytes):
                nested_value = self._find_first_context_specific_integer(value, target_tag)
                if nested_value is not None:
                    return nested_value
        return None

    def _extract_eim_ack_sequence_numbers_from_card_response(self, card_response: bytes) -> list[int]:
        if card_response.startswith(bytes.fromhex("BF51")) is False:
            return []
        sequence_number = self._find_first_context_specific_integer(card_response, b"\x83")
        if sequence_number is None:
            return []
        return [sequence_number]

    def _build_provide_eim_package_result_tlv(self, card_response: bytes, eid: str = "") -> bytes:
        """Build ProvideEimPackageResult (BF50) with an EimPackageResult CHOICE payload."""
        if len(card_response) == 0:
            return b""
        body = b""
        eid_bytes = self._eid_bcd_string_to_bytes(eid)
        if len(eid_bytes) == 16:
            body += self._wrap_tlv(b"\x5A", eid_bytes)
        if card_response.startswith(bytes.fromhex("BF51")) or card_response.startswith(bytes.fromhex("BF52")) or card_response.startswith(bytes.fromhex("BF54")):
            body += card_response
        else:
            body += self._wrap_tlv(bytes.fromhex("BF51"), card_response)
        return self._wrap_tlv(bytes.fromhex("BF50"), body)

    def _decode_bcd_digits(self, value: bytes) -> str:
        digits = ""
        for byte in value:
            high = (byte >> 4) & 0x0F
            low = byte & 0x0F
            for nibble in [high, low]:
                if nibble == 0x0F:
                    continue
                digits += str(nibble)
        return digits

    def _decode_iccid_digits(self, value: bytes) -> str:
        digits = ""
        for byte in value:
            low = byte & 0x0F
            high = (byte >> 4) & 0x0F
            for nibble in [low, high]:
                if nibble == 0x0F:
                    continue
                digits += str(nibble)
        return digits

    def _decode_oid(self, value: bytes) -> str:
        if len(value) == 0:
            return ""
        first = value[0]
        parts = [str(first // 40), str(first % 40)]
        current = 0
        for byte in value[1:]:
            current = (current << 7) | (byte & 0x7F)
            if (byte & 0x80) == 0:
                parts.append(str(current))
                current = 0
        if current != 0:
            parts.append(str(current))
        return ".".join(parts)

    def _extract_notification_metadata_entries(self, raw_response: bytes) -> list:
        entries = []
        if len(raw_response) == 0:
            return entries
        try:
            decoded = decode_list_notification_response(raw_response)
        except Exception:
            decoded = None
        if isinstance(decoded, tuple) is True and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "notificationMetadataList" and isinstance(choice_value, list):
                for entry in choice_value:
                    if isinstance(entry, dict) is False:
                        continue
                    seq_number = entry.get("seqNumber")
                    entries.append(
                        {
                            "seqNumber": int(seq_number) if isinstance(seq_number, int) else None,
                            "metadata": entry,
                        }
                    )
                return entries
        # pySim decoder returned nothing usable — fall back to manual BER-TLV
        # parsing so that notifications queued on the eUICC are never missed.
        try:
            root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        except Exception:
            return entries
        bf28_tag = bytes.fromhex("BF28")
        bf2b_tag = bytes.fromhex("BF2B")
        if root_tag not in (bf28_tag, bf2b_tag):
            return entries
        bf2f_tag = bytes.fromhex("BF2F")
        seq_tag = bytes.fromhex("80")
        list_value = root_value
        # Unwrap the outer CHOICE (A0 for notificationMetadataList /
        # notificationList) when present.
        try:
            choice_tag, choice_value, _, _ = self._read_tlv(list_value, 0)
        except Exception:
            return entries
        if choice_tag in (b"\xA0", b"\x60"):
            list_value = choice_value
        inner_offset = 0
        while inner_offset < len(list_value):
            try:
                entry_tag, entry_value, _, next_offset = self._read_tlv(list_value, inner_offset)
            except Exception:
                break
            bf2f_raw = b""
            if entry_tag == bf2f_tag:
                bf2f_raw = list_value[inner_offset:next_offset]
            else:
                bf2f_raw = self._find_first_tlv_in_value(entry_value, bf2f_tag)
            if len(bf2f_raw) > 0:
                seq_raw = self._find_first_tlv_in_value(bf2f_raw, seq_tag)
                seq_number = None
                if len(seq_raw) > 0:
                    try:
                        _, seq_value, _, _ = self._read_tlv(seq_raw, 0)
                        seq_number = int.from_bytes(seq_value, "big")
                    except Exception:
                        pass
                entries.append(
                    {
                        "seqNumber": seq_number,
                        "metadata": {"seqNumber": seq_number},
                    }
                )
            inner_offset = next_offset
        return entries

    def _retrieve_pending_notification(self, seq_number: int) -> bytes:
        payload = self._build_retrieve_notification_request_payload(seq_number)
        try:
            response = self._send_es10b_store_data(
                payload,
                f"DOWNLOAD: RetrieveNotification [{seq_number}]",
                allow_stk_retry=True,
            )
        except Exception as error:
            print(f"[*] Notification sync: retrieveNotification failed for seq={seq_number} ({error}).")
            return b""
        raw_pending_notification = self._extract_pending_notification_payload(response)
        if len(raw_pending_notification) == 0:
            print(f"[*] Notification sync: no decodable pending notification for seq={seq_number}.")
        return raw_pending_notification

    def _build_retrieve_notification_request_payload(self, seq_number: Optional[int] = None) -> bytes:
        if isinstance(seq_number, int) is False:
            return bytes.fromhex("BF2B00")
        seq_bytes = self._encode_notification_sequence(seq_number)
        search_criteria = self._wrap_tlv(b"\x80", seq_bytes)
        return self._wrap_tlv(bytes.fromhex("BF2B"), self._wrap_tlv(b"\xA0", search_criteria))

    def _build_retrieve_euicc_package_result_request_payload(self, seq_number: Optional[int] = None) -> bytes:
        if isinstance(seq_number, int) is False:
            return bytes.fromhex("BF2B028200")
        return self._build_retrieve_notification_request_payload(seq_number)

    def _extract_pending_notification_payload(self, raw_response: bytes) -> bytes:
        if len(raw_response) == 0:
            return b""
        try:
            decoded = decode_retrieve_notifications_list_response(raw_response)
        except Exception:
            decoded = None
        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "notificationList" and isinstance(choice_value, list) and len(choice_value) > 0:
                try:
                    root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
                    if root_tag != bytes.fromhex("BF2B"):
                        return b""
                    choice_tag, choice_bytes, _, _ = self._read_tlv(root_value, 0)
                    if choice_tag not in [b"\xA0", b"\x60"]:
                        return b""
                    pending_tag, _, pending_raw, _ = self._read_tlv(choice_bytes, 0)
                    if pending_tag in [b"\x30", bytes.fromhex("BF37")]:
                        decode_pending_notification(pending_raw)
                        return pending_raw
                except Exception:
                    return b""
        return b""

    def _wrap_tlv(self, tag_bytes: bytes, value: bytes) -> bytes:
        return tag_bytes + self._encode_der_length(len(value)) + value

    def _encode_notification_sequence(self, seq_number: int) -> bytes:
        if seq_number <= 0xFF:
            return seq_number.to_bytes(1, "big")
        if seq_number <= 0xFFFF:
            return seq_number.to_bytes(2, "big")
        return seq_number.to_bytes(4, "big")

    def _encode_der_length(self, length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        if length <= 0xFF:
            return bytes([0x81, length])
        if length <= 0xFFFF:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        raise ValueError("DER length exceeds supported two-octet long-form encoding.")

    def _is_constructed_tag(self, tag: Any) -> bool:
        if isinstance(tag, bytes):
            if len(tag) == 0:
                return False
            return (tag[0] & 0x20) != 0
        if isinstance(tag, int):
            byte_length = max(1, (tag.bit_length() + 7) // 8)
            first_octet = tag.to_bytes(byte_length, "big")[0]
            return (first_octet & 0x20) != 0
        return False

    def _segment_bound_profile_package(self, bpp_bytes: bytes) -> list:
        # Per SGP.22 v2.x / v3.x Annex M "ES10b.LoadBoundProfilePackage"
        # A0 ships as a single wrapped segment, while A1/A2/A3 require
        # the container header as its own StoreData chain followed by
        # each inner 86/88 TLV. Stripping the container headers lets a
        # compliant eUICC misread the first bare 86 as a terminal
        # loadProfileElements completion and leave the SM-DP+ session
        # pending.
        if len(bpp_bytes) == 0:
            raise ValueError("Bound Profile Package is empty.")

        root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        if root_tag != bytes.fromhex("BF36"):
            raise ValueError(f"Unexpected Bound Profile Package root tag: {root_tag.hex().upper()}")

        segments = []
        child_offset = 0
        first_child = True
        while child_offset < len(root_value):
            child_tag, child_value, child_raw, next_offset = self._read_tlv(root_value, child_offset)
            if first_child and child_tag != bytes.fromhex("BF23"):
                raise ValueError(f"Expected BF23 as first Bound Profile Package child, got {child_tag.hex().upper()}")
            if child_tag == bytes.fromhex("BF23"):
                bootstrap_end = next_offset + (len(bpp_bytes) - len(root_value))
                segments.append(bpp_bytes[:bootstrap_end])
            elif child_tag == b"\xA0":
                segments.append(child_raw)
            elif child_tag in (b"\xA1", b"\xA2", b"\xA3"):
                segments.append(self._encode_tlv_header(child_tag, len(child_value)))
                if len(child_value) > 0:
                    segments.extend(self._extract_sequence_members(child_value))
            else:
                raise ValueError(f"Unexpected Bound Profile Package child tag: {child_tag.hex().upper()}")
            child_offset = next_offset
            first_child = False

        if len(segments) == 0:
            raise ValueError("Bound Profile Package did not contain any loadable segments.")
        return segments

    def _reselect_isdr_for_install(self) -> None:
        select_apdu = b"\x00\xA4\x04\x00" + bytes([len(self.cfg.AID_ISD_R)]) + self.cfg.AID_ISD_R
        self.apdu_channel.send(select_apdu, "INSTALL: RE-SELECT ISD-R")

    def _inspect_install_bootstrap(self, segments: list) -> None:
        if len(segments) == 0:
            raise RuntimeError("LoadBoundProfilePackage segmentation produced no segments.")
        bf23_payload = self._extract_initialise_secure_channel_request(self.state.bpp_bytes)
        if len(bf23_payload) == 0:
            raise RuntimeError("Bound Profile Package does not contain a BF23 bootstrap.")

        bf23_info = self._decode_initialise_secure_channel_request(bf23_payload)
        pd_info = self._decode_prepare_download_response_ok(
            self._decode_string_payload(self.state.prepare_download_response_b64)
        )

        remote_op_id = bf23_info.get("remoteOpId")
        txid = bf23_info.get("transactionId", b"")
        crt = bf23_info.get("controlRefTemplate", {})
        smdp_otpk = bf23_info.get("smdpOtpk", b"")
        smdp_sign = bf23_info.get("smdpSign", b"")

        print(
            "[*] BF23 bootstrap: "
            f"remoteOpId={remote_op_id}, "
            f"transactionId={txid.hex().upper()}, "
            f"keyType={crt.get('keyType', b'').hex().upper()}, "
            f"keyLen={crt.get('keyLen', b'').hex().upper()}, "
            f"hostId={crt.get('hostId', b'').decode('utf-8', 'ignore')}, "
            f"smdpOtpkLen={len(smdp_otpk)}, "
            f"smdpSignLen={len(smdp_sign)}"
        )

        pd_txid = pd_info.get("transactionId", b"")
        euicc_otpk = pd_info.get("euiccOtpk", b"")
        if len(pd_txid) > 0 or len(euicc_otpk) > 0:
            print(
                "[*] PrepareDownload session: "
                f"transactionId={pd_txid.hex().upper()}, "
                f"euiccOtpkLen={len(euicc_otpk)}"
            )

        if remote_op_id != 1:
            raise RuntimeError(
                f"InitialiseSecureChannelRequest remoteOpId must be installBoundProfilePackage (1), got {remote_op_id}."
            )

        if len(pd_txid) > 0 and txid != pd_txid:
            raise RuntimeError(
                "InitialiseSecureChannelRequest transactionId does not match PrepareDownloadResponse euiccSigned2."
            )

        if len(self.state.transaction_id) > 0 and txid != self.state.transaction_id:
            print(
                "[*] Warning: BF23 transactionId differs from local session state: "
                f"{self.state.transaction_id.hex().upper()}"
            )

        key_type = crt.get("keyType", b"")
        key_len = crt.get("keyLen", b"")
        host_id = crt.get("hostId", b"")
        if key_type not in [b"\x88", b"\x89"]:
            raise RuntimeError(
                f"InitialiseSecureChannelRequest keyType must be 88 (AES-128) or 89 (SM4), got {key_type.hex().upper()}."
            )
        if key_len != b"\x10":
            raise RuntimeError(
                f"InitialiseSecureChannelRequest keyLen must be 10, got {key_len.hex().upper()}."
            )
        if len(host_id) == 0 or len(host_id) > 16:
            raise RuntimeError(
                f"InitialiseSecureChannelRequest hostId must be 1..16 bytes, got {len(host_id)}."
            )
        if len(smdp_otpk) == 0:
            raise RuntimeError("InitialiseSecureChannelRequest smdpOtpk is empty.")
        if len(smdp_sign) == 0:
            raise RuntimeError("InitialiseSecureChannelRequest smdpSign is empty.")

        if len(pd_info.get("euiccOtpk", b"")) > 0:
            self._verify_bf23_signature(bf23_info, pd_info)

    def _extract_initialise_secure_channel_request(self, bpp_bytes: bytes) -> bytes:
        if len(bpp_bytes) == 0:
            return b""
        try:
            root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        except Exception:
            return b""
        if root_tag != bytes.fromhex("BF36"):
            return b""
        offset = 0
        while offset < len(root_value):
            try:
                child_tag, _, child_raw, next_offset = self._read_tlv(root_value, offset)
            except Exception:
                return b""
            if child_tag == bytes.fromhex("BF23"):
                return child_raw
            offset = next_offset
        return b""

    def _decode_initialise_secure_channel_request(self, raw_tlv: bytes) -> dict:
        try:
            decoded = decode_initialise_secure_channel_request_pysim(raw_tlv)
        except Exception:
            decoded = None

        if isinstance(decoded, dict):
            control_ref_template = decoded.get("controlRefTemplate", {})
            key_type = bytes(control_ref_template.get("keyType", b""))
            key_len = bytes(control_ref_template.get("keyLen", b""))
            host_id = bytes(control_ref_template.get("hostId", b""))
            tag, value, _, _ = self._read_tlv(raw_tlv, 0)
            if tag != bytes.fromhex("BF23"):
                raise RuntimeError(f"Expected BF23 InitialiseSecureChannelRequest, got {tag.hex().upper()}.")
            result = {
                "remoteOpId": decoded.get("remoteOpId"),
                "transactionId": bytes(decoded.get("transactionId", b"")),
                "controlRefTemplate": {
                    "keyType": key_type,
                    "keyLen": key_len,
                    "hostId": host_id,
                },
                "smdpOtpk": bytes(decoded.get("smdpOtpk", b"")),
                "smdpSign": bytes(decoded.get("smdpSign", b"")),
                "remoteOpIdRaw": b"",
                "transactionIdRaw": b"",
                "controlRefTemplateRaw": b"",
                "smdpOtpkRaw": b"",
            }
            offset = 0
            while offset < len(value):
                field_tag, field_value, field_raw, next_offset = self._read_tlv(value, offset)
                if field_tag == b"\x82":
                    result["remoteOpIdRaw"] = field_raw
                elif field_tag == b"\x80":
                    result["transactionIdRaw"] = field_raw
                elif field_tag == b"\xA6":
                    result["controlRefTemplateRaw"] = field_raw
                elif field_tag == bytes.fromhex("5F49"):
                    result["smdpOtpkRaw"] = field_raw
                offset = next_offset
            return result

        tag, value, _, _ = self._read_tlv(raw_tlv, 0)
        if tag != bytes.fromhex("BF23"):
            raise RuntimeError(f"Expected BF23 InitialiseSecureChannelRequest, got {tag.hex().upper()}.")

        offset = 0
        result = {
            "remoteOpId": None,
            "transactionId": b"",
            "controlRefTemplate": {},
            "smdpOtpk": b"",
            "smdpSign": b"",
            "remoteOpIdRaw": b"",
            "transactionIdRaw": b"",
            "controlRefTemplateRaw": b"",
            "smdpOtpkRaw": b"",
        }
        while offset < len(value):
            field_tag, field_value, field_raw, next_offset = self._read_tlv(value, offset)
            if field_tag == b"\x82":
                result["remoteOpId"] = int.from_bytes(field_value, "big", signed=False)
                result["remoteOpIdRaw"] = field_raw
            elif field_tag == b"\x80":
                result["transactionId"] = field_value
                result["transactionIdRaw"] = field_raw
            elif field_tag == b"\xA6":
                result["controlRefTemplate"] = self._decode_control_ref_template(field_value)
                result["controlRefTemplateRaw"] = field_raw
            elif field_tag == bytes.fromhex("5F49"):
                result["smdpOtpk"] = field_value
                result["smdpOtpkRaw"] = field_raw
            elif field_tag == bytes.fromhex("5F37"):
                result["smdpSign"] = field_value
            offset = next_offset
        return result

    def _decode_control_ref_template(self, value: bytes) -> dict:
        result = {
            "keyType": b"",
            "keyLen": b"",
            "hostId": b"",
        }
        offset = 0
        while offset < len(value):
            field_tag, field_value, _, next_offset = self._read_tlv(value, offset)
            if field_tag == b"\x80":
                result["keyType"] = field_value
            elif field_tag == b"\x81":
                result["keyLen"] = field_value
            elif field_tag == b"\x84":
                result["hostId"] = field_value
            offset = next_offset
        return result

    def _decode_prepare_download_response_ok(self, raw_response: bytes) -> dict:
        try:
            decoded = decode_prepare_download_response(raw_response)
        except Exception:
            decoded = None

        if isinstance(decoded, tuple) and len(decoded) == 2:
            choice_name, choice_value = decoded
            if choice_name == "downloadResponseOk" and isinstance(choice_value, dict):
                euicc_signed2 = choice_value.get("euiccSigned2", {})
                if isinstance(euicc_signed2, dict):
                    euicc_signed2_raw = self._extract_euicc_signed2(raw_response)
                    result = {
                        "transactionId": bytes(euicc_signed2.get("transactionId", b"")),
                        "euiccOtpk": bytes(euicc_signed2.get("euiccOtpk", b"")),
                        "euiccOtpkRaw": b"",
                    }
                    if len(euicc_signed2_raw) > 0:
                        inner_offset = 0
                        while inner_offset < len(euicc_signed2_raw):
                            field_tag, field_value, field_raw, next_offset = self._read_tlv(euicc_signed2_raw, inner_offset)
                            if field_tag == bytes.fromhex("5F49"):
                                result["euiccOtpkRaw"] = field_raw
                            inner_offset = next_offset
                    return result

        result = {
            "transactionId": b"",
            "euiccOtpk": b"",
            "euiccOtpkRaw": b"",
        }
        if len(raw_response) == 0:
            return result

        root_tag, root_value, _, _ = self._read_tlv(raw_response, 0)
        if root_tag != bytes.fromhex("BF21"):
            return result

        choice_tag, choice_value, _, _ = self._read_tlv(root_value, 0)
        if choice_tag not in [b"\xA0", b"\x60"]:
            return result

        euicc_signed2_value = b""
        first_tag, first_value, _, first_end = self._read_tlv(choice_value, 0)
        if first_tag != b"\x30":
            return result

        nested_tag, nested_value, _, _ = self._read_tlv(first_value, 0)
        if nested_tag == b"\x30":
            euicc_signed2_value = nested_value
        elif first_end == len(choice_value):
            euicc_signed2_value = first_value
        else:
            euicc_signed2_value = first_value

        inner_offset = 0
        while inner_offset < len(euicc_signed2_value):
            field_tag, field_value, field_raw, next_offset = self._read_tlv(euicc_signed2_value, inner_offset)
            if field_tag == b"\x80":
                result["transactionId"] = field_value
            elif field_tag == bytes.fromhex("5F49"):
                result["euiccOtpk"] = field_value
                result["euiccOtpkRaw"] = field_raw
            inner_offset = next_offset

        return result

    def _extract_error_details_from_decoded(self, decoded_error: Any) -> str:
        if isinstance(decoded_error, dict) is False:
            return ""
        fragments = []
        transaction_id = decoded_error.get("transactionId")
        if isinstance(transaction_id, bytes) and len(transaction_id) > 0:
            fragments.append(f"transactionId={transaction_id.hex().upper()}")
        for key in ["authenticateErrorCode", "downloadErrorCode"]:
            value = decoded_error.get(key)
            if value is None:
                continue
            fragments.append(f"{key}={value}")
        return ", ".join(fragments)

    def _verify_bf23_signature(self, bf23_info: dict, pd_info: dict) -> bool:
        certificate_der = self._get_install_signature_certificate()
        if len(certificate_der) == 0:
            print("[*] BF23 signature verification skipped: no DPpb certificate available.")
            return False

        signed_parts = [
            bf23_info.get("remoteOpIdRaw", b""),
            bf23_info.get("transactionIdRaw", b""),
            bf23_info.get("controlRefTemplateRaw", b""),
            bf23_info.get("smdpOtpkRaw", b""),
            pd_info.get("euiccOtpkRaw", b""),
        ]
        signed_data = b"".join(signed_parts)
        raw_signature = bf23_info.get("smdpSign", b"")
        if len(raw_signature) != 64:
            print(f"[*] BF23 signature verification skipped: unexpected raw signature length {len(raw_signature)}.")
            return False

        r_value = int.from_bytes(raw_signature[:32], "big", signed=False)
        s_value = int.from_bytes(raw_signature[32:], "big", signed=False)
        der_signature = asym_utils.encode_dss_signature(r_value, s_value)
        certificate = crypto_x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key()

        try:
            public_key.verify(der_signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except Exception as error:
            print(
                "[*] BF23 signature verification warning: "
                f"{type(error).__name__} with signedDataLen={len(signed_data)}. "
                "Continuing with card-side validation."
            )
            return False

        print("[+] BF23 smdpSign verified against DPpb certificate.")
        return True

    def _get_install_signature_certificate(self) -> bytes:
        provider_certificate = bytes(getattr(self.state, "provider_smdp_certificate", b""))
        if len(provider_certificate) > 0:
            return provider_certificate

        cert_pb = self.cert_pb
        if cert_pb is None:
            return b""
        if isinstance(cert_pb, bytes):
            return cert_pb
        dump_method = getattr(cert_pb, "dump", None)
        if callable(dump_method):
            return dump_method()
        return b""

    def _extract_sequence_members(self, value: bytes) -> list:
        members = []
        offset = 0
        while offset < len(value):
            _, _, raw_tlv, next_offset = self._read_tlv(value, offset)
            members.append(raw_tlv)
            offset = next_offset
        return members

    def _encode_tlv_header(self, tag_bytes: bytes, value_length: int) -> bytes:
        return tag_bytes + self._encode_der_length(value_length)

    def _tag_hex(self, tlv_bytes: bytes) -> str:
        if len(tlv_bytes) == 0:
            return ""

        offset = 1
        if tlv_bytes[0] & 0x1F == 0x1F:
            while offset < len(tlv_bytes):
                current = tlv_bytes[offset]
                offset += 1
                if current & 0x80 == 0:
                    break
        return tlv_bytes[:offset].hex().upper()

    def _send_personalization_store_data(self, payload: bytes, log_name: str, chunk_size: int = 120) -> bytes:
        total = len(payload)
        offset = 0
        block = 0
        response = b""

        print(f"\n--- Transmitting {log_name} ({total} bytes) ---")
        while offset < total:
            end_offset = offset + chunk_size
            chunk = payload[offset:end_offset]
            is_last_chunk = end_offset >= total
            p1 = 0x11
            if is_last_chunk:
                p1 = 0x91
            apdu = bytes([0x80, 0xE2, p1, block & 0xFF, len(chunk)]) + chunk
            print(f"  > Block {block:02X} (Len={len(chunk)}) P1={p1:02X}")
            response = self.apdu_channel.send(apdu, f"{log_name} [Block {block}]")
            offset += chunk_size
            block += 1

        return response

    def _summarize_bound_profile_package(self, bpp_bytes: bytes) -> str:
        if len(bpp_bytes) == 0:
            return ""

        try:
            root_tag, root_value, _, _ = self._read_tlv(bpp_bytes, 0)
        except ValueError:
            return "unparsed"

        root_hex = root_tag.hex().upper()
        if root_tag != bytes.fromhex("BF36"):
            return f"root={root_hex}"

        parts = [f"root={root_hex}"]
        child_offset = 0
        while child_offset < len(root_value):
            try:
                child_tag, child_value, _, next_offset = self._read_tlv(root_value, child_offset)
            except ValueError:
                parts.append("truncated")
                break

            child_hex = child_tag.hex().upper()
            if child_tag in [b"\xA0", b"\xA1", b"\xA2", b"\xA3"]:
                child_count = self._count_tlv_members(child_value)
                parts.append(f"{child_hex}x{child_count}")
            else:
                parts.append(child_hex)
            child_offset = next_offset

        return ", ".join(parts)

    def _count_tlv_members(self, value: bytes) -> int:
        count = 0
        offset = 0
        while offset < len(value):
            try:
                _, _, _, next_offset = self._read_tlv(value, offset)
            except ValueError:
                break
            count += 1
            offset = next_offset
        return count

    def _encode_transaction_id(self, transaction_id: bytes) -> str:
        provider_transaction_id = str(getattr(self.state, "provider_transaction_id", "")).strip()
        if len(provider_transaction_id) > 0:
            return provider_transaction_id
        if len(transaction_id) == 0:
            return ""
        return self._b64encode(transaction_id)

    def _decode_string_payload(self, value: str) -> bytes:
        text = str(value).strip()
        if len(text) == 0:
            return b""

        if self._is_hex(text):
            return bytes.fromhex(text)

        try:
            return base64.b64decode(text.encode("utf-8"), validate=True)
        except binascii.Error:
            return text.encode("utf-8")

    def _decode_ci_pk_id_payload(self, value: str) -> bytes:
        raw_value = self._decode_string_payload(value)
        if len(raw_value) == 0:
            return b""

        try:
            tag, inner_value, _, end_offset = self._read_tlv(raw_value, 0)
        except Exception:
            return raw_value
        if tag == b"\x04" and end_offset == len(raw_value):
            return inner_value
        return raw_value

    def _b64encode(self, raw_value: bytes) -> str:
        if len(raw_value) == 0:
            return ""
        return base64.b64encode(raw_value).decode("utf-8")

    def _is_hex(self, value: str) -> bool:
        if len(value) % 2 != 0:
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return True

    def _local_fallback_enabled(self) -> bool:
        if self.cfg.BACKEND_MODE == BACKEND_MODE_LOCAL_SGP26:
            return True
        return bool(getattr(self.cfg, "REMOTE_DP_ALLOW_LOCAL_FALLBACK", False))

    def _ensure_local_credentials_loaded(self) -> None:
        if self._local_credentials_loaded:
            return
        self.cert_auth, self.key_auth = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_AUTH,
            self.cfg.KEY_PATH_AUTH,
        )
        self.cert_pb, self.key_pb = CryptoEngine.load_credentials(
            self.cfg.CERT_PATH_PB,
            self.cfg.KEY_PATH_PB,
        )
        self._local_credentials_loaded = True
