# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Remote Lab agent YAML configuration parsing and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


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
    public_base_url: str = ""


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
    left_s = _normalize_bind_host(left)
    right_s = _normalize_bind_host(right)
    if left_s == right_s:
        return True
    wildcards = {"", "0.0.0.0", "::", "[::]"}
    return left_s in wildcards or right_s in wildcards


def _normalize_bind_host(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1].strip()
    return text


def _url_host(value: Any) -> str:
    host = _normalize_bind_host(value)
    if "%25" in host and ":" in host:
        host = host.replace("%25", "%")
    if ":" in host:
        return f"[{host.replace('%', '%25')}]"
    return host


def _normalize_public_base_url(value: Any) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    parsed = urlsplit(text)
    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "stream_proxy.public_base_url must be an http(s) URL without credentials, query, or fragment"
        )
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
        )
    ).rstrip("/")


def _normalize_apdu_url(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) == 0:
        return ""
    parsed = urlsplit(text)
    if (
        parsed.scheme.lower() not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "upstream URL must be http(s) without credentials, query, or fragment"
        )
    path = parsed.path.rstrip("/")
    if not path.endswith("/apdu"):
        path += "/apdu"
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, path or "/apdu", "", "")
    )


def _upstream_url_from_config(raw: dict[str, Any], field_name: str) -> str:
    if raw.get("url"):
        return _normalize_apdu_url(raw.get("url"))
    host = str(raw.get("host") or "").strip()
    port = raw.get("port")
    scheme = str(raw.get("scheme") or "http").strip() or "http"
    if host and port:
        return _normalize_apdu_url(
            f"{scheme}://{_url_host(host)}:{_port(port, field_name + '.port')}/apdu"
        )
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
        bind_host=_normalize_bind_host(agent_raw.get("bind_host") or "127.0.0.1")
        or "127.0.0.1",
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
            raise ValueError(
                f"security.access_tokens[{index}].token_hash must start with sha256:"
            )
        if role not in ("user", "admin"):
            raise ValueError(
                f"security.access_tokens[{index}].role must be user or admin"
            )
        access_tokens.append(
            AccessTokenConfig(id=token_id, token_hash=token_hash, role=role)
        )
    if len(access_tokens) == 0:
        raise ValueError("at least one security.access_tokens entry is required")

    rigs: list[RigConfig] = []
    rig_ids: set[str] = set()
    relay_ports: list[tuple[str, int]] = []
    for index, raw in enumerate(_as_list(payload.get("rigs"), "rigs")):
        item = _as_dict(raw, f"rigs[{index}]")
        rig_id = str(item.get("id") or "").strip()
        if len(rig_id) == 0:
            raise ValueError(f"rigs[{index}].id is required")
        normalized_rig_id = rig_id.casefold()
        if normalized_rig_id in rig_ids:
            raise ValueError(f"duplicate rig id: {rig_id}")
        rig_ids.add(normalized_rig_id)

        proxy_raw = _as_dict(item.get("stream_proxy"), f"rigs[{index}].stream_proxy")
        external_port = _port(
            proxy_raw.get("external_port"),
            f"rigs[{index}].stream_proxy.external_port",
        )
        bind_host = (
            _normalize_bind_host(proxy_raw.get("bind_host") or agent.bind_host)
            or agent.bind_host
        )
        if any(
            existing_port == external_port
            and _binds_overlap(existing_host, bind_host)
            for existing_host, existing_port in relay_ports
        ):
            raise ValueError(
                f"duplicate stream proxy bind/port (including overlap): {bind_host}:{external_port}"
            )
        if external_port == agent.control_port and _binds_overlap(
            bind_host, agent.bind_host
        ):
            raise ValueError(
                "stream proxy bind/port conflicts with agent control port: "
                f"{bind_host}:{external_port}"
            )
        relay_ports.append((bind_host, external_port))
        stream_proxy = StreamProxyConfig(
            bind_host=bind_host,
            external_port=external_port,
            public_host=str(proxy_raw.get("public_host") or "").strip(),
            public_base_url=_normalize_public_base_url(
                proxy_raw.get("public_base_url")
            ),
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
