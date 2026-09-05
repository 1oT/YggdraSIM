#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from ``uv.lock``."""

from __future__ import annotations

import argparse
import json
import os
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


def _timestamp() -> str:
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    try:
        epoch = int(raw_epoch)
    except ValueError:
        epoch = 0
    if epoch <= 0:
        return "1970-01-01T00:00:00Z"
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _source_properties(source: object) -> list[dict[str, str]]:
    if not isinstance(source, dict):
        return []
    return [
        {"name": f"yggdrasim:lock-source:{key}", "value": str(value)}
        for key, value in sorted(source.items())
    ]


def build_sbom(lock_path: Path, project_name: str, project_version: str) -> dict[str, object]:
    with Path(lock_path).open("rb") as handle:
        lock = tomllib.load(handle)
    components: list[dict[str, object]] = []
    for package in lock.get("package", []):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name or not version or name.casefold() == project_name.casefold():
            continue
        component: dict[str, object] = {
            "type": "library",
            "name": name,
            "version": version,
            "bom-ref": f"pkg:pypi/{quote(name.casefold())}@{quote(version)}",
            "purl": f"pkg:pypi/{quote(name.casefold())}@{quote(version)}",
        }
        properties = _source_properties(package.get("source"))
        if properties:
            component["properties"] = properties
        components.append(component)
    components.sort(key=lambda value: (str(value["name"]).casefold(), str(value["version"])))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            "urn:uuid:"
            + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{project_name}@{project_version}"))
        ),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version,
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "YggdraSIM release SBOM generator",
                        "version": "1",
                    }
                ]
            },
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--name", default="yggdrasim")
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_sbom(args.lock, args.name, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(payload['components'])} components to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
