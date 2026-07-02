# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Remote Lab agent YAML configuration parsing and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class AccessTokenConfig:
    id: str
    token_hash: str
    role: str = "user"


@dataclass(frozen=True, slots=True)
class RemoteLabDefaults:
    reservation_timeout_seconds: int = 30
    heartbeat_timeout_seconds: int = 60
    max_session_seconds: int = 14_400


@dataclass(frozen=True, slots=True)
class AgentConfig:
    id: str
    name: str
    bind_host: str = "127.0.0.1"
    control_port: int = 8700
    public_host: str = ""


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    url: str
    token_file: str = ""
    token: str = ""
    health_check: str = ""


@dataclass(frozen=True, slots=True)
class StreamProxyConfig:
    bind_host: str = "127.0.0.1"
    external_port: int = 0
    public_host: str = ""


@dataclass(frozen=True, slots=True)
class RigConfig:
    id: str
    name: str
    location: str = ""
    tags: tuple[str, ...] = ()
    owner: str = ""
    notes: str = ""
    capabilities: tuple[str, ...] = ()
    enabled: bool = True
    stream_proxy: StreamProxyConfig = StreamProxyConfig()
    upstream: UpstreamConfig = UpstreamConfig(url="")
    locks: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RemoteLabAgentConfig:
    agent: AgentConfig
    defaults: RemoteLabDefaults
    access_tokens: tuple[AccessTokenConfig, ...]
    rigs: tuple[RigConfig, ...]
    resources: tuple[dict[str, Any], ...] = ()


def _as_dict(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping")
    return dict(value)


def _as_list(value: Any, field_name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return list(value)


def _str_list(value: Any) -> tuple[str, ...]:
    return tuple(str(item).strip() for item in _as_list(value, "list") if str(item).strip())


def _port(value: Any, field_name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer TCP port") from exc
    if port <= 0 or port > 65535:
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return port


def _binds_overlap(left: str, right: str) -> bool:
    left_s = str(left or "").strip()
    right_s = str(right or "").strip()
    if left_s == right_s:
        return True
    wildcards = {"", "0.0.0.0", "::", "[::]"}
    return left_s in wildcards or right_s in wildcards


def _normalize_apdu_url(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) == 0:
        return ""
    if text.startswith(("http://", "https://")) is False:
        raise ValueError("upstream URL must start with http:// or https://")
    if text.rstrip("/").endswith("/apdu"):
        return text.rstrip("/")
    return text.rstrip("/") + "/apdu"


def _upstream_url_from_config(raw: dict[str, Any], field_name: str) -> str:
    if raw.get("url"):
        return _normalize_apdu_url(raw.get("url"))
    host = str(raw.get("host") or "").strip()
    port = raw.get("port")
    scheme = str(raw.get("scheme") or "http").strip() or "http"
    if host and port:
        return _normalize_apdu_url(f"{scheme}://{host}:{_port(port, field_name + '.port')}/apdu")
    return ""


def load_config(path: str | Path) -> RemoteLabAgentConfig:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Remote Lab agent requires PyYAML (pyyaml).") from exc

    resolved = Path(path).expanduser().resolve()
    try:
        payload = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Cannot read Remote Lab config {resolved}: {exc}") from exc
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError("Remote Lab config root must be a mapping")
    return parse_config(payload)


def parse_config(payload: dict[str, Any]) -> RemoteLabAgentConfig:
    agent_raw = _as_dict(payload.get("agent"), "agent")
    agent_id = str(agent_raw.get("id") or "").strip()
    if len(agent_id) == 0:
        raise ValueError("agent.id is required")
    agent = AgentConfig(
        id=agent_id,
        name=str(agent_raw.get("name") or agent_id).strip(),
        bind_host=str(agent_raw.get("bind_host") or "127.0.0.1").strip() or "127.0.0.1",
        control_port=_port(agent_raw.get("control_port") or 8700, "agent.control_port"),
        public_host=str(agent_raw.get("public_host") or "").strip(),
    )

    defaults_raw = _as_dict(payload.get("defaults"), "defaults")
    defaults = RemoteLabDefaults(
        reservation_timeout_seconds=max(1, int(defaults_raw.get("reservation_timeout_seconds") or 30)),
        heartbeat_timeout_seconds=max(1, int(defaults_raw.get("heartbeat_timeout_seconds") or 60)),
        max_session_seconds=max(1, int(defaults_raw.get("max_session_seconds") or 14_400)),
    )

    security_raw = _as_dict(payload.get("security"), "security")
    access_tokens: list[AccessTokenConfig] = []
    for index, raw in enumerate(_as_list(security_raw.get("access_tokens"), "security.access_tokens")):
        item = _as_dict(raw, f"security.access_tokens[{index}]")
        token_id = str(item.get("id") or "").strip()
        token_hash = str(item.get("token_hash") or "").strip()
        role = str(item.get("role") or "user").strip().lower() or "user"
        if not token_id:
            raise ValueError(f"security.access_tokens[{index}].id is required")
        if not token_hash.startswith("sha256:"):
            raise ValueError(f"security.access_tokens[{index}].token_hash must start with sha256:")
        if role not in ("user", "admin"):
            raise ValueError(f"security.access_tokens[{index}].role must be user or admin")
        access_tokens.append(AccessTokenConfig(id=token_id, token_hash=token_hash, role=role))
    if len(access_tokens) == 0:
        raise ValueError("at least one security.access_tokens entry is required")

    rigs: list[RigConfig] = []
    rig_ids: set[str] = set()
    relay_ports: set[tuple[str, int]] = set()
    for index, raw in enumerate(_as_list(payload.get("rigs"), "rigs")):
        item = _as_dict(raw, f"rigs[{index}]")
        rig_id = str(item.get("id") or "").strip()
        if len(rig_id) == 0:
            raise ValueError(f"rigs[{index}].id is required")
        if rig_id in rig_ids:
            raise ValueError(f"duplicate rig id: {rig_id}")
        rig_ids.add(rig_id)

        proxy_raw = _as_dict(item.get("stream_proxy"), f"rigs[{index}].stream_proxy")
        external_port = _port(proxy_raw.get("external_port"), f"rigs[{index}].stream_proxy.external_port")
        bind_host = str(proxy_raw.get("bind_host") or agent.bind_host).strip() or agent.bind_host
        relay_key = (bind_host, external_port)
        if relay_key in relay_ports:
            raise ValueError(f"duplicate stream proxy bind/port: {bind_host}:{external_port}")
        if external_port == agent.control_port and _binds_overlap(bind_host, agent.bind_host):
            raise ValueError(
                "stream proxy bind/port conflicts with agent control port: "
                f"{bind_host}:{external_port}"
            )
        relay_ports.add(relay_key)
        stream_proxy = StreamProxyConfig(
            bind_host=bind_host,
            external_port=external_port,
            public_host=str(proxy_raw.get("public_host") or "").strip(),
        )

        upstream_raw = _as_dict(item.get("upstream"), f"rigs[{index}].upstream")
        upstream_url = _upstream_url_from_config(upstream_raw, f"rigs[{index}].upstream")
        if not upstream_url:
            raise ValueError(f"rigs[{index}].upstream.url or host/port is required")
        upstream = UpstreamConfig(
            url=upstream_url,
            token_file=str(upstream_raw.get("token_file") or "").strip(),
            token=str(upstream_raw.get("token") or "").strip(),
            health_check=str(upstream_raw.get("health_check") or "").strip(),
        )

        locks = _str_list(item.get("locks"))
        if len(locks) == 0:
            locks = (f"rig:{rig_id}",)

        rigs.append(
            RigConfig(
                id=rig_id,
                name=str(item.get("name") or rig_id).strip(),
                location=str(item.get("location") or "").strip(),
                tags=_str_list(item.get("tags")),
                owner=str(item.get("owner") or "").strip(),
                notes=str(item.get("notes") or "").strip(),
                capabilities=_str_list(item.get("capabilities")),
                enabled=bool(item.get("enabled", True)),
                stream_proxy=stream_proxy,
                upstream=upstream,
                locks=locks,
            )
        )

    if len(rigs) == 0:
        raise ValueError("at least one rig is required")

    resources = tuple(
        _as_dict(item, "resources[]")
        for item in _as_list(payload.get("resources"), "resources")
    )
    return RemoteLabAgentConfig(
        agent=agent,
        defaults=defaults,
        access_tokens=tuple(access_tokens),
        rigs=tuple(rigs),
        resources=resources,
    )
