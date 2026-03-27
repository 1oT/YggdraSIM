from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from importlib import import_module
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4


BridgeFactory = Callable[[Any], Any]
EmitFunc = Callable[[str], None]
OrchestratorLoader = Callable[[str, Any, Any, Any], Any]
CloseRuntimeFunc = Callable[[Any], None]
SessionFactory = Callable[[argparse.Namespace], Any]


class StandaloneDependencyError(RuntimeError):
    """Raised when standalone runtime hooks were not supplied."""


@dataclass
class StandaloneIPAdConfig:
    READER_INDEX: int = 0
    RSP_SERVER_URL: str = ""
    EIM_BASE_URL: str = ""
    ES9_BASE_URL: str = ""
    ES9_VERIFY_TLS: bool = False
    ES9_CA_BUNDLE_PATH: str = ""


@dataclass
class StandaloneIPAdState:
    session_open: bool = False


@dataclass
class StandaloneIPAdSession:
    cfg: Any = field(default_factory=StandaloneIPAdConfig)
    eid_hint: str = ""
    smdp_address: str = ""
    state: Any = field(default_factory=StandaloneIPAdState)
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    close_callback: Optional[Callable[[], None]] = None

    def close_session(self) -> None:
        self.state.session_open = False
        if callable(self.close_callback):
            self.close_callback()

    def _read_card_eid_safe(self) -> str:
        return str(self.eid_hint or "").strip()

    def _resolve_runtime_smdp_address(self, _: dict[str, Any]) -> str:
        return str(self.smdp_address or "").strip()

    def record_poll_audit_event(self, **kwargs: Any) -> None:
        self.audit_events.append(dict(kwargs))


def _decorate_localized_log_name(log_name: str) -> str:
    text = str(log_name or "")
    stripped = text.strip()
    if len(stripped) == 0:
        return text
    if stripped.startswith("[eIM]") or stripped.startswith("[SM-DP+]"):
        return text
    if (
        stripped.startswith("EIM:")
        or stripped.startswith("EIM-POLL:")
        or stripped.startswith("STK INIT:")
    ):
        return f"[eIM] {text}"
    if stripped.startswith("AUTH:") or stripped.startswith("DOWNLOAD:"):
        return f"[SM-DP+] {text}"
    return text


_TRACE_RESET = "\033[0m"
_TRACE_EIM = "\033[38;2;95;220;203m"
_TRACE_SMDP = "\033[38;2;138;167;255m"
_TRACE_OK = "\033[38;2;141;255;141m"
_TRACE_FAIL = "\033[38;2;255;154;154m"
_TRACE_INFO = "\033[38;2;247;252;255m"
_LOCALIZED_PATH_LABEL_IPAD = "IPAd"
_LOCALIZED_ROUTE_IPAD = "SIM <-> IPAd <-> eIM/SM-DP+"


def _localized_trace_color(label: str) -> str:
    stripped = str(label or "").strip()
    if stripped.startswith("[eIM]"):
        return _TRACE_EIM
    if stripped.startswith("[SM-DP+]"):
        return _TRACE_SMDP
    return _TRACE_INFO


def _localized_route_banner(path_label: str, route: str) -> str:
    return f"[*] Active path: {path_label} | Route: {route}"


class LocalizedRelayApduChannel:
    def __init__(self, channel: Any):
        self._channel = channel

    def _raw_logging_enabled(self) -> bool:
        current = self.get_raw_apdu_logging()
        if current is None:
            return True
        return bool(current)

    def _print_concise_start(self, label: str) -> None:
        if self._raw_logging_enabled():
            return
        color = _localized_trace_color(label)
        print(f"\n{color}[*] {label}{_TRACE_RESET}")

    def _print_concise_send_result(self, response: bytes) -> None:
        _ = response
        if self._raw_logging_enabled():
            return

    def _print_concise_exchange_result(self, response: bytes, sw1: int, sw2: int) -> None:
        _ = response
        if self._raw_logging_enabled():
            return
        status_hex = f"{sw1:02X}{sw2:02X}"
        if status_hex in ("9000", "9100"):
            return
        status_color = _TRACE_FAIL
        print(f"{status_color}    -> SW {status_hex} len={len(response)}{_TRACE_RESET}")

    def send(self, apdu: bytes, log_name: str) -> bytes:
        decorated = _decorate_localized_log_name(log_name)
        self._print_concise_start(decorated)
        response = self._channel.send(apdu, decorated)
        self._print_concise_send_result(bytes(response))
        return response

    def exchange(self, apdu: bytes, log_name: str):
        decorated = _decorate_localized_log_name(log_name)
        self._print_concise_start(decorated)
        response, sw1, sw2 = self._channel.exchange(apdu, decorated)
        self._print_concise_exchange_result(bytes(response), int(sw1), int(sw2))
        return response, sw1, sw2

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        setter = getattr(self._channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(enabled))

    def get_raw_apdu_logging(self) -> Optional[bool]:
        getter = getattr(self._channel, "get_raw_apdu_logging", None)
        if callable(getter):
            current = getter()
            if current is None:
                return None
            return bool(current)
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._channel, name)


def _missing_bridge_factory(session: Any) -> Any:
    _ = session
    raise StandaloneDependencyError(
        "bridge_factory is required. "
        "`ipad_standalone.py` is stdlib-only and does not import a project bridge automatically."
    )


def _missing_orchestrator_loader(profile_name: str, bridge: Any, session: Any, cfg: Any) -> Any:
    _ = profile_name
    _ = bridge
    _ = session
    _ = cfg
    raise StandaloneDependencyError(
        "orchestrator_loader is required. "
        "`ipad_standalone.py` is stdlib-only and does not import a project orchestrator automatically."
    )


@dataclass
class LocalizedIPAdRunResult:
    profile_name: str
    matching_id: str
    flow: str
    flow_run_id: str
    eid: str
    queue_index: int
    pending_package_path: str
    ack_count: int
    eim_base_url: str
    smdp_base_url: str
    bridge_status: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LocalizedIPAdRunner:
    """
    Standalone IPAd runner for embedded or exported Python runtimes.

    Design constraints:

    - stdlib-only module surface
    - no implicit imports from repository-local bridge / orchestrator code
    - runtime-specific networking / transport is supplied explicitly by the
      embedding firmware or adapter layer

    Runtime hooks supplied by the embedding environment:

    - `bridge_factory(session) -> bridge`
    - `orchestrator_loader(profile_name, bridge, session, cfg) -> orchestrator`

    Session contract:

    - `session.cfg`
    - optional `session.state.session_open`
    - optional `session.close_session()`
    - optional `session._read_card_eid_safe()`
    - optional `session._resolve_runtime_smdp_address(dict)`
    - optional `session.record_poll_audit_event(...)`
    """

    def __init__(
        self,
        session: Any,
        *,
        bridge_factory: Optional[BridgeFactory] = None,
        orchestrator_loader: Optional[OrchestratorLoader] = None,
        close_runtime: Optional[CloseRuntimeFunc] = None,
        emit: Optional[EmitFunc] = None,
    ) -> None:
        self.session = session
        self.cfg = getattr(session, "cfg", None)
        if self.cfg is None:
            raise ValueError("session must expose a cfg attribute.")
        self._bridge_factory = bridge_factory or _missing_bridge_factory
        self._orchestrator_loader = orchestrator_loader or _missing_orchestrator_loader
        self._close_runtime = close_runtime or self.close_network_runtime
        self._emit = emit
        self._poll_bridge: Optional[Any] = None

    def _log(self, message: str) -> None:
        if callable(self._emit):
            self._emit(message)

    def _close_session_if_open(self) -> None:
        state = getattr(self.session, "state", None)
        if bool(getattr(state, "session_open", False)) is False:
            return
        close_session = getattr(self.session, "close_session", None)
        if callable(close_session) is False:
            return
        close_session()

    def ensure_poll_bridge(self, reset_runtime: bool = True) -> Any:
        if self._poll_bridge is None:
            self._poll_bridge = self._bridge_factory(self.session)
        start_method = getattr(self._poll_bridge, "start", None)
        if callable(start_method):
            start_method()
        if reset_runtime:
            reset_method = getattr(self._poll_bridge, "reset_runtime_state", None)
            if callable(reset_method):
                reset_method()
        return self._poll_bridge

    @staticmethod
    def close_network_runtime(orchestrator: Any) -> None:
        if orchestrator is None:
            return
        close_open_channel = getattr(orchestrator, "_close_stk_open_channel", None)
        if callable(close_open_channel):
            try:
                close_open_channel()
            except Exception:
                pass
        apdu_channel = getattr(orchestrator, "apdu_channel", None)
        if apdu_channel is None:
            return
        close_method = getattr(apdu_channel, "close", None)
        if callable(close_method):
            try:
                close_method()
            except Exception:
                pass
            return
        connection = getattr(apdu_channel, "_conn", None)
        disconnect_method = getattr(connection, "disconnect", None)
        if callable(disconnect_method):
            try:
                disconnect_method()
            except Exception:
                pass

    def load_network_orchestrator(self, profile_name: str) -> Any:
        normalized_profile = str(profile_name or "").strip().lower()
        if normalized_profile not in ("live", "test"):
            raise ValueError("Network orchestrator profile must be 'live' or 'test'.")
        bridge = self.ensure_poll_bridge(reset_runtime=False)
        return self._orchestrator_loader(
            normalized_profile,
            bridge,
            self.session,
            self.cfg,
        )

    @staticmethod
    def _bridge_status_payload(bridge: Any) -> dict[str, Any]:
        status_payload = getattr(bridge, "status_payload", None)
        if callable(status_payload):
            payload = status_payload()
            if isinstance(payload, dict):
                return payload
        return {}

    def _read_card_eid_safe(self) -> str:
        reader = getattr(self.session, "_read_card_eid_safe", None)
        if callable(reader):
            try:
                return str(reader() or "").strip()
            except Exception:
                return ""
        return ""

    @staticmethod
    def _set_raw_apdu_logging(apdu_channel: Any, enabled: bool) -> Optional[bool]:
        setter = getattr(apdu_channel, "set_raw_apdu_logging", None)
        getter = getattr(apdu_channel, "get_raw_apdu_logging", None)
        previous_value: Optional[bool] = None
        if callable(getter):
            current_value = getter()
            if current_value is not None:
                previous_value = bool(current_value)
        if callable(setter):
            setter(bool(enabled))
        return previous_value

    def _record_audit_event(
        self,
        *,
        flow_name: str,
        flow_run_id: str,
        matching_id: str,
        eid_hint: str,
        bridge_status: dict[str, Any],
        success: bool,
        error: Optional[Exception] = None,
    ) -> None:
        record_event = getattr(self.session, "record_poll_audit_event", None)
        if callable(record_event) is False:
            return
        record_event(
            action="localized_ipad_poll",
            package_path="",
            package_type="localized_ipad_poll",
            transaction_id_hex="",
            matching_id=matching_id,
            success=success,
            result_len=int(bridge_status.get("ack_count", 0) or 0),
            response_preview_hex="",
            details={
                "profile_name": flow_name.replace("ipad_", "", 1),
                "queue_index": int(bridge_status.get("queue_index", 0) or 0),
                "pending_package_path": str(bridge_status.get("pending_package_path", "")).strip(),
                "ack_count": int(bridge_status.get("ack_count", 0) or 0),
            },
            error=error,
            flow=flow_name,
            flow_run_id=flow_run_id,
            eid=eid_hint,
        )

    def run(
        self,
        profile_name: str,
        matching_id: str = "",
        *,
        debug: bool = False,
    ) -> LocalizedIPAdRunResult:
        normalized_profile = str(profile_name or "").strip().lower()
        if normalized_profile not in ("live", "test"):
            raise ValueError("profile_name must be either 'live' or 'test'.")
        self._close_session_if_open()
        flow_name = f"ipad_{normalized_profile}"
        flow_run_id = uuid4().hex
        eid_hint = self._read_card_eid_safe()
        bridge = self.ensure_poll_bridge(reset_runtime=True)
        set_flow_context = getattr(bridge, "set_flow_context", None)
        if callable(set_flow_context):
            set_flow_context(flow=flow_name, flow_run_id=flow_run_id, eid=eid_hint)
        effective_matching_id = str(matching_id or "").strip()
        orchestrator = None
        previous_raw_apdu_logging: Optional[bool] = None
        try:
            orchestrator = self.load_network_orchestrator(normalized_profile)
            previous_raw_apdu_logging = self._set_raw_apdu_logging(
                getattr(orchestrator, "apdu_channel", None),
                bool(debug),
            )
            self._log(
                _localized_route_banner(
                    _LOCALIZED_PATH_LABEL_IPAD,
                    _LOCALIZED_ROUTE_IPAD,
                )
            )
            self._log(
                f"[*] Localized IPAd ({normalized_profile.upper()}) "
                f"eIM={getattr(bridge, 'eim_base_url', '-')} "
                f"smdp={getattr(bridge, 'smdp_base_url', '-')} "
                f"mode={'debug' if debug else 'concise'}"
            )
            if len(effective_matching_id) > 0:
                self._log(f"[*] matchingId={effective_matching_id}")
            run_eim_poll = getattr(orchestrator, "run_eim_poll", None)
            if callable(run_eim_poll) is False:
                raise RuntimeError("Configured orchestrator does not expose run_eim_poll().")
            run_eim_poll(matching_id=effective_matching_id)
            bridge_status = self._bridge_status_payload(bridge)
            self._record_audit_event(
                flow_name=flow_name,
                flow_run_id=flow_run_id,
                matching_id=effective_matching_id,
                eid_hint=eid_hint,
                bridge_status=bridge_status,
                success=True,
            )
        except Exception as error:
            bridge_status = self._bridge_status_payload(bridge)
            self._record_audit_event(
                flow_name=flow_name,
                flow_run_id=flow_run_id,
                matching_id=effective_matching_id,
                eid_hint=eid_hint,
                bridge_status=bridge_status,
                success=False,
                error=error,
            )
            raise
        finally:
            if previous_raw_apdu_logging is not None:
                self._set_raw_apdu_logging(
                    getattr(orchestrator, "apdu_channel", None),
                    previous_raw_apdu_logging,
                )
            self._close_runtime(orchestrator)
        result = LocalizedIPAdRunResult(
            profile_name=normalized_profile,
            matching_id=effective_matching_id,
            flow=flow_name,
            flow_run_id=flow_run_id,
            eid=eid_hint,
            queue_index=int(bridge_status.get("queue_index", 0) or 0),
            pending_package_path=str(bridge_status.get("pending_package_path", "")).strip(),
            ack_count=int(bridge_status.get("ack_count", 0) or 0),
            eim_base_url=str(getattr(bridge, "eim_base_url", "") or ""),
            smdp_base_url=str(getattr(bridge, "smdp_base_url", "") or ""),
            bridge_status=bridge_status,
        )
        self._log("[+] Localized IPAd run completed.")
        self._log(f"    queue_index  : {result.queue_index}")
        self._log(f"    pending_path : {result.pending_package_path or '-'}")
        self._log(f"    ack_count    : {result.ack_count}")
        return result


def build_default_session(
    *,
    reader_index: int = 0,
    eid_hint: str = "",
    smdp_address: str = "",
) -> StandaloneIPAdSession:
    cfg = StandaloneIPAdConfig(
        READER_INDEX=int(reader_index or 0),
        RSP_SERVER_URL=str(smdp_address or "").strip(),
    )
    return StandaloneIPAdSession(
        cfg=cfg,
        eid_hint=str(eid_hint or "").strip(),
        smdp_address=str(smdp_address or "").strip(),
    )


def _load_adapter_module(adapter_value: str) -> Any:
    normalized = str(adapter_value or "").strip()
    if len(normalized) == 0:
        raise ValueError("adapter_value must not be empty.")
    if normalized.endswith(".py") or "/" in normalized or "\\" in normalized:
        module_path = Path(normalized).expanduser()
        if module_path.is_absolute() is False:
            module_path = (Path.cwd() / module_path).resolve()
        else:
            module_path = module_path.resolve()
        if module_path.is_file() is False:
            raise FileNotFoundError(f"Adapter module not found: {module_path}")
        spec = spec_from_file_location(module_path.stem, str(module_path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load adapter module spec from: {module_path}")
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return import_module(normalized)


def _resolve_adapter_callable(module: Any, name: str, *, required: bool) -> Optional[Callable[..., Any]]:
    resolved = getattr(module, str(name or "").strip(), None)
    if callable(resolved):
        return resolved
    if required:
        raise StandaloneDependencyError(
            f"Adapter module does not expose callable `{name}`."
        )
    return None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Standalone localized IPAd runner. "
            "This module is stdlib-only and requires an explicit adapter."
        ),
    )
    parser.add_argument(
        "--profile",
        choices=("live", "test"),
        default="live",
        help="Relay profile to use for the IPAd path.",
    )
    parser.add_argument(
        "--matching-id",
        default="",
        help="Optional matchingId carried into the relay poll flow.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable raw APDU logging for the localized relay run.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the final run result as JSON.",
    )
    parser.add_argument(
        "--adapter",
        default="",
        help=(
            "Adapter module name or Python file path. "
            "Required for CLI execution."
        ),
    )
    parser.add_argument(
        "--session-factory-name",
        default="build_session",
        help="Adapter callable used to build a session from parsed CLI arguments.",
    )
    parser.add_argument(
        "--bridge-factory-name",
        default="build_bridge",
        help="Adapter callable used to build the localized bridge.",
    )
    parser.add_argument(
        "--orchestrator-loader-name",
        default="build_orchestrator",
        help="Adapter callable used to build the IPAd orchestrator/runtime.",
    )
    parser.add_argument(
        "--reader-index",
        type=int,
        default=0,
        help="Reader index hint for the generic standalone session.",
    )
    parser.add_argument(
        "--eid",
        default="",
        help="Optional EID hint for the generic standalone session.",
    )
    parser.add_argument(
        "--smdp-address",
        default="",
        help="Optional SM-DP+ address hint for the generic standalone session.",
    )
    args = parser.parse_args(argv)
    if len(str(args.adapter or "").strip()) == 0:
        parser.error(
            "--adapter is required for CLI execution. "
            "Programmatic users may instantiate LocalizedIPAdRunner directly."
        )
    adapter_module = _load_adapter_module(args.adapter)
    session_factory = _resolve_adapter_callable(
        adapter_module,
        args.session_factory_name,
        required=False,
    )
    bridge_factory = _resolve_adapter_callable(
        adapter_module,
        args.bridge_factory_name,
        required=True,
    )
    orchestrator_loader = _resolve_adapter_callable(
        adapter_module,
        args.orchestrator_loader_name,
        required=True,
    )
    emit: Optional[EmitFunc] = print
    if args.json:
        emit = None
    if callable(session_factory):
        session = session_factory(args)
    else:
        session = build_default_session(
            reader_index=args.reader_index,
            eid_hint=args.eid,
            smdp_address=args.smdp_address,
        )
    runner = LocalizedIPAdRunner(
        session=session,
        bridge_factory=bridge_factory,
        orchestrator_loader=orchestrator_loader,
        emit=emit,
    )
    result = runner.run(
        profile_name=args.profile,
        matching_id=args.matching_id,
        debug=bool(args.debug),
    )
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
