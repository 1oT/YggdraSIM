# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge simulated modem channel: bridges AT+CSIM commands from a serial modem to the card relay."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from SIMCARD.utils import parse_apdu

LEGACY_USIM_AID = bytes.fromhex("A0000000871002FF34FF0789312E30FF")
LEGACY_ISIM_AID = bytes.fromhex("A0000000871004FF34FF0789312E30FF")

SELECT_INS = 0xA4
GET_RESPONSE_INS = 0xC0
MANAGE_CHANNEL_INS = 0x70
INTERNAL_AUTHENTICATE_INS = 0x88

APP_ROOT_FID_ALIAS = "7FFF"
MAX_LOGICAL_CHANNEL = 3


@dataclass(slots=True)
class PendingResponse:
    data: bytes
    sw1: int = 0x90
    sw2: int = 0x00


class SimulatedModemCardChannel:
    """Modem-facing compatibility wrapper for the simulated card backend."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self._pending_responses: dict[int, PendingResponse] = {}
        self._current_node_by_channel: dict[int, str] = {0: "3F00"}
        # ETSI TS 102 221 §8.4.2.3 / TS 102 222 §6.6: the "currently
        # selected application" is sticky per logical channel and only
        # changes on an explicit SELECT-by-AID. A modem that briefly
        # walks back through MF (e.g. to read EF.ARR at 2F06) must not
        # lose the USIM scope, otherwise every subsequent
        # ``00A40804047FFF<EF>`` collapses to 6A82 even though the EF
        # is wired up. ``_active_application_root_by_channel`` carries
        # the sticky pointer so the 7FFF alias keeps resolving across
        # MF side-trips.
        self._active_application_root_by_channel: dict[int, str] = {}
        self._open_channels: set[int] = set()

    def disconnect(self) -> None:
        self._pending_responses.clear()
        self._current_node_by_channel = {0: "3F00"}
        self._active_application_root_by_channel = {}
        self._open_channels.clear()
        self._connection.disconnect()

    def get_atr(self) -> bytes:
        return bytes(self._connection.getATR())

    def queue_refresh(self, mode: str | int = "euicc-profile-state-change", *, source: str = "") -> dict[str, Any]:
        """Queue a REFRESH proactive command through the AT-simlink modem channel."""
        toolkit = getattr(self._engine(), "toolkit", None)
        if toolkit is None:
            raise RuntimeError("Simulated engine toolkit is not available.")
        queue_method = getattr(toolkit, "queue_refresh", None)
        if callable(queue_method) is False:
            raise RuntimeError("Simulated engine toolkit does not expose REFRESH queueing.")
        return dict(queue_method(mode, source=source))

    def proactive_status_payload(self) -> dict[str, Any]:
        """Return the current proactive command queue state dict for the modem channel."""
        toolkit = getattr(self._engine(), "toolkit", None)
        if toolkit is None:
            return {}
        status_method = getattr(toolkit, "status_payload", None)
        if callable(status_method) is False:
            return {}
        return dict(status_method())

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        """Transmit a raw APDU via the AT+CSIM modem command and return (response_bytes, SW1, SW2)."""
        command = bytes(apdu or b"")
        parsed = parse_apdu(command)
        cla = int(parsed["cla"])
        ins = int(parsed["ins"])
        p1 = int(parsed["p1"])
        p2 = int(parsed["p2"])
        payload = bytes(parsed["data"] or b"")
        le = parsed["le"]
        logical_channel = self._logical_channel(cla)

        if ins == GET_RESPONSE_INS:
            return self._handle_get_response(logical_channel, le)
        if ins == MANAGE_CHANNEL_INS and (cla & 0x80) == 0:
            return self._handle_manage_channel(logical_channel, p1, p2)
        if ins == INTERNAL_AUTHENTICATE_INS:
            return self._handle_internal_authenticate(logical_channel, command)
        if ins == SELECT_INS:
            return self._handle_select(logical_channel, p1, payload)

        response_data, sw1, sw2 = self._delegate_exchange(logical_channel, command)
        return self._rewrite_response_aliases(response_data), sw1, sw2

    def _handle_get_response(self, logical_channel: int, le: int | None) -> tuple[bytes, int, int]:
        pending = self._pending_responses.get(logical_channel)
        if pending is None:
            return b"", 0x6A, 0x86

        if le in (None, 0, 256, 65536):
            requested_length = len(pending.data)
        else:
            requested_length = max(0, int(le))

        chunk = bytes(pending.data[:requested_length])
        remaining = bytes(pending.data[requested_length:])
        if len(remaining) == 0:
            del self._pending_responses[logical_channel]
            return chunk, int(pending.sw1), int(pending.sw2)

        self._pending_responses[logical_channel] = PendingResponse(
            remaining,
            sw1=int(pending.sw1),
            sw2=int(pending.sw2),
        )
        return chunk, 0x61, self._advertised_length(remaining)

    def _handle_manage_channel(self, logical_channel: int, p1: int, p2: int) -> tuple[bytes, int, int]:
        if p1 == 0x00:
            for channel_number in range(1, MAX_LOGICAL_CHANNEL + 1):
                if channel_number in self._open_channels:
                    continue
                self._open_channels.add(channel_number)
                self._current_node_by_channel[channel_number] = "3F00"
                # TS 102 221 §11.1.17: a freshly opened logical channel
                # inherits the basic channel's currently-selected
                # application so the modem can split traffic without
                # re-running SELECT-by-AID on the new channel.
                inherited_root = self._active_application_root_by_channel.get(logical_channel, "")
                if len(inherited_root) > 0:
                    self._active_application_root_by_channel[channel_number] = inherited_root
                self._pending_responses.pop(channel_number, None)
                return bytes((channel_number,)), 0x90, 0x00
            return b"", 0x6A, 0x81

        if p1 == 0x80:
            close_channel = logical_channel
            if p2 > 0:
                close_channel = int(p2) & 0x03
            self._open_channels.discard(close_channel)
            self._current_node_by_channel.pop(close_channel, None)
            self._active_application_root_by_channel.pop(close_channel, None)
            self._pending_responses.pop(close_channel, None)
            return b"", 0x90, 0x00

        return b"", 0x68, 0x81

    def _handle_internal_authenticate(self, logical_channel: int, apdu: bytes) -> tuple[bytes, int, int]:
        response_data, sw1, sw2 = self._delegate_exchange(logical_channel, bytes(apdu or b""))
        response_bytes = self._rewrite_response_aliases(bytes(response_data))
        if sw1 == 0x90 and len(response_bytes) > 0:
            return self._queue_pending_response(logical_channel, response_bytes, sw1=0x90, sw2=0x00)
        return response_bytes, int(sw1), int(sw2)

    def _handle_select(self, logical_channel: int, p1: int, payload: bytes) -> tuple[bytes, int, int]:
        state = self._engine_state()
        previous_node_id = self._current_node_by_channel.get(logical_channel, "3F00")
        state.current_node_id = previous_node_id

        requested_selector = bytes(payload)
        if p1 == 0x08:
            response_data, sw1, sw2 = self._select_by_path(logical_channel, requested_selector)
        elif len(requested_selector) == 2 and requested_selector.hex().upper() == APP_ROOT_FID_ALIAS:
            response_data, sw1, sw2 = self._select_current_application_root(logical_channel)
        else:
            selector = self._resolve_select_selector(requested_selector)
            response_data, sw1, sw2 = self._engine().fs.select(selector, p1=int(p1) & 0xFF)
            if sw1 == 0x90:
                landed_id = str(state.current_node_id or previous_node_id)
                self._current_node_by_channel[logical_channel] = landed_id
                # TS 102 221 §8.4.2.3: SELECT-by-AID (P1=0x04) and
                # any other select that lands on an ADF rewires the
                # "currently selected application" anchor used by the
                # 7FFF alias. Path-rooted (P1=0x08) and FID selects
                # also have the side-effect of pinning the application
                # if the cursor walks into an ADF subtree.
                self._update_active_application_root_from_landing(logical_channel, landed_id)
            else:
                self._current_node_by_channel[logical_channel] = previous_node_id

        response_bytes = self._rewrite_response_aliases(bytes(response_data))
        if sw1 == 0x90 and len(response_bytes) > 0:
            return self._queue_pending_response(logical_channel, response_bytes, sw1=0x90, sw2=0x00)
        return response_bytes, int(sw1), int(sw2)

    def _select_by_path(self, logical_channel: int, payload: bytes) -> tuple[bytes, int, int]:
        if len(payload) == 0 or len(payload) % 2 != 0:
            return b"", 0x6A, 0x86

        segments = [payload[offset : offset + 2].hex().upper() for offset in range(0, len(payload), 2)]
        state = self._engine_state()
        current_id = "3F00"

        if segments[0] == APP_ROOT_FID_ALIAS:
            root_id = self._current_application_root_id(logical_channel)
            if len(root_id) == 0:
                return b"", 0x6A, 0x82
            current_id = root_id
            segments = segments[1:]
            if len(segments) == 0:
                state.current_node_id = current_id
                node = state.nodes[current_id]
                self._current_node_by_channel[logical_channel] = current_id
                self._update_active_application_root_from_landing(logical_channel, current_id)
                return self._engine().fs.build_fcp(node), 0x90, 0x00

        for segment in segments:
            child = self._find_child_by_fid(current_id, segment)
            if child is None:
                return b"", 0x6A, 0x82
            current_id = child.node_id

        state.current_node_id = current_id
        self._current_node_by_channel[logical_channel] = current_id
        self._update_active_application_root_from_landing(logical_channel, current_id)
        return self._engine().fs.build_fcp(state.nodes[current_id]), 0x90, 0x00

    def _select_current_application_root(self, logical_channel: int) -> tuple[bytes, int, int]:
        root_id = self._current_application_root_id(logical_channel)
        if len(root_id) == 0:
            return b"", 0x6A, 0x82
        state = self._engine_state()
        state.current_node_id = root_id
        self._current_node_by_channel[logical_channel] = root_id
        self._update_active_application_root_from_landing(logical_channel, root_id)
        return self._engine().fs.build_fcp(state.nodes[root_id]), 0x90, 0x00

    def _update_active_application_root_from_landing(self, logical_channel: int, landed_node_id: str) -> None:
        """Re-anchor the sticky ``7FFF`` pointer if the SELECT cursor
        lands inside an ADF subtree.

        The pointer is *not* cleared when the cursor walks back to MF
        (or into a non-ADF DF such as DF.TELECOM) -- TS 102 221
        §8.4.2.3 only switches the "currently selected application"
        on an explicit SELECT-by-AID (or path/FID select that
        actually targets a different ADF root).
        """
        target = str(landed_node_id or "").strip()
        if len(target) == 0:
            return
        adf_root_id = self._enclosing_adf_id(target)
        if len(adf_root_id) == 0:
            return
        self._active_application_root_by_channel[logical_channel] = adf_root_id

    def _enclosing_adf_id(self, node_id: str) -> str:
        state = self._engine_state()
        cursor = str(node_id or "").strip()
        while len(cursor) > 0:
            node = state.nodes.get(cursor)
            if node is None:
                return ""
            if str(getattr(node, "kind", "")).strip().lower() == "adf":
                return cursor
            cursor = str(getattr(node, "parent_id", "") or "").strip()
        return ""

    def _delegate_exchange(self, logical_channel: int, apdu: bytes) -> tuple[bytes, int, int]:
        state = self._engine_state()
        previous_node_id = self._current_node_by_channel.get(logical_channel, "3F00")
        state.current_node_id = previous_node_id
        response_data, sw1, sw2 = self._connection.transmit(list(bytes(apdu)))
        self._current_node_by_channel[logical_channel] = str(state.current_node_id or previous_node_id)
        return bytes(response_data), int(sw1), int(sw2)

    def _queue_pending_response(
        self,
        logical_channel: int,
        response_data: bytes,
        *,
        sw1: int = 0x90,
        sw2: int = 0x00,
    ) -> tuple[bytes, int, int]:
        payload = bytes(response_data)
        self._pending_responses[logical_channel] = PendingResponse(payload, sw1=sw1, sw2=sw2)
        return b"", 0x61, self._advertised_length(payload)

    def _advertised_length(self, payload: bytes) -> int:
        length = len(bytes(payload or b""))
        if length == 256:
            return 0x00
        return min(0xFF, int(length))

    def _resolve_select_selector(self, requested_selector: bytes) -> bytes:
        selector = bytes(requested_selector)
        if len(selector) <= 2:
            return selector
        if self._node_with_aid(selector) is not None:
            return selector

        if selector.startswith(LEGACY_USIM_AID[:7]):
            actual_usim = self._actual_aid_for_label("USIM")
            if len(actual_usim) > 0:
                return actual_usim
        if selector.startswith(LEGACY_ISIM_AID[:7]):
            actual_isim = self._actual_aid_for_label("ISIM")
            if len(actual_isim) > 0:
                return actual_isim
        return selector

    def _rewrite_response_aliases(self, payload: bytes) -> bytes:
        rewritten = bytes(payload or b"")
        for actual_aid, alias_aid in self._aid_alias_pairs():
            if actual_aid == alias_aid or len(actual_aid) != len(alias_aid):
                continue
            rewritten = rewritten.replace(actual_aid, alias_aid)
        return rewritten

    def _aid_alias_pairs(self) -> list[tuple[bytes, bytes]]:
        pairs: list[tuple[bytes, bytes]] = []
        actual_usim = self._actual_aid_for_label("USIM")
        actual_isim = self._actual_aid_for_label("ISIM")
        if len(actual_usim) > 0:
            pairs.append((actual_usim, LEGACY_USIM_AID))
        if len(actual_isim) > 0:
            pairs.append((actual_isim, LEGACY_ISIM_AID))
        return pairs

    def _actual_aid_for_label(self, label: str) -> bytes:
        normalized_label = str(label or "").strip().upper()
        state = self._engine_state()
        for node in state.nodes.values():
            candidate_label = str(getattr(node, "label", "") or getattr(node, "name", "")).strip().upper()
            candidate_name = str(getattr(node, "name", "")).strip().upper()
            if candidate_label != normalized_label and candidate_name != f"ADF.{normalized_label}":
                continue
            aid_hex = str(getattr(node, "aid", "") or "").strip().upper()
            if len(aid_hex) == 0:
                continue
            try:
                return bytes.fromhex(aid_hex)
            except ValueError:
                continue
        return b""

    def _node_with_aid(self, selector: bytes):
        target = bytes(selector).hex().upper()
        state = self._engine_state()
        for node in state.nodes.values():
            if str(getattr(node, "aid", "") or "").strip().upper() == target:
                return node
        return None

    def _current_application_root_id(self, logical_channel: int) -> str:
        # Sticky-first lookup: TS 102 221 §8.4.2.3 ties the 7FFF
        # alias to the *currently selected application*, not to the
        # current EF cursor. The application stays selected until an
        # explicit SELECT-by-AID switches it, even when the cursor
        # transiently walks to MF/2F06 or to a non-ADF DF.
        state = self._engine_state()
        sticky = str(self._active_application_root_by_channel.get(logical_channel, "") or "").strip()
        if len(sticky) > 0:
            sticky_node = state.nodes.get(sticky)
            if sticky_node is not None and str(getattr(sticky_node, "kind", "")).strip().lower() == "adf":
                return sticky
            self._active_application_root_by_channel.pop(logical_channel, None)

        node_id = str(self._current_node_by_channel.get(logical_channel, "3F00") or "3F00")
        while len(node_id) > 0:
            node = state.nodes.get(node_id)
            if node is None:
                return ""
            if str(getattr(node, "kind", "")).strip().lower() == "adf":
                # Cache the discovered ADF so subsequent 7FFF resolves
                # also when the cursor moves out of the ADF subtree.
                self._active_application_root_by_channel[logical_channel] = node_id
                return node_id
            node_id = str(getattr(node, "parent_id", "") or "").strip()
        return ""

    def _find_child_by_fid(self, parent_id: str, fid_hex: str):
        state = self._engine_state()
        parent = state.nodes.get(str(parent_id or "").strip())
        if parent is None:
            return None
        target = str(fid_hex or "").strip().upper()
        for child_id in getattr(parent, "children", []):
            child = state.nodes.get(child_id)
            if child is None:
                continue
            if str(getattr(child, "fid", "") or "").strip().upper() == target:
                return child
        return None

    def _engine(self):
        return self._connection._engine

    def _engine_state(self):
        return self._engine().state

    def _logical_channel(self, cla: int) -> int:
        normalized_cla = int(cla) & 0xFF
        if normalized_cla & 0x40:
            return normalized_cla & 0x0F
        return normalized_cla & 0x03
