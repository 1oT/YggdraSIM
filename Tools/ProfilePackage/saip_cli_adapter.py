# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Bundled SAIP command adapter used by frozen YggdraSIM children.

Upstream pySim installs its SAIP library but does not install the
``contrib/saip-tool.py`` script.  Frozen builds therefore cannot safely launch
that script through ``sys.executable`` or discover it in the host filesystem.
This module implements the ProfilePackage command contract directly over the
installed ``pySim.esim.saip`` API.

It is intentionally a normal callable, not a generic script runner.  The
frozen dispatcher exposes it under one fixed allow-listed entry.
"""

from __future__ import annotations

import argparse
import logging
import pprint
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    ensure_private_directory,
    ensure_private_file,
    read_bounded_regular_file,
)

_MAX_PROFILE_BYTES = 128 * 1024 * 1024
_MAX_APPLICATION_BYTES = 256 * 1024 * 1024
_SAFE_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="saip-tool",
        description="Inspect and update eSIM SAIP profile packages.",
    )
    parser.add_argument("input_upp", help="Unprotected Profile Package input")
    parser.add_argument(
        "--loglevel",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
    )
    parser.add_argument("--debug", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)

    split = commands.add_parser("split")
    split.add_argument("--output-prefix", default=".")

    dump = commands.add_parser("dump")
    dump.add_argument(
        "mode",
        choices=("all_pe", "all_pe_by_type", "all_pe_by_naa"),
    )
    dump.add_argument("--dump-decoded", action="store_true")

    commands.add_parser("check")

    remove_naa = commands.add_parser("remove-naa")
    remove_naa.add_argument("--output-file", required=True)
    remove_naa.add_argument("--naa-type", choices=("csim", "usim", "isim"), required=True)

    info = commands.add_parser("info")
    info.add_argument("--apps", action="store_true")

    extract_apps = commands.add_parser("extract-apps")
    extract_apps.add_argument("--output-dir", default=".")
    extract_apps.add_argument("--format", choices=("ijc", "cap"), default="cap")

    commands.add_parser("tree")
    return parser


def _hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    if value is None:
        return ""
    return str(value)


def _safe_component(value: object, fallback: str) -> str:
    normalized = _SAFE_FILENAME_PATTERN.sub("_", str(value or "").strip())
    normalized = normalized.strip("._")
    return normalized or fallback


def _write_sequence(pes: Any, output_file: object) -> Path:
    target = Path(str(output_file)).expanduser().resolve()
    payload = bytes(pes.to_der())
    atomic_write_bytes(target, payload)
    print(f"Wrote {len(pes.pe_list)} profile elements to '{target}'.")
    return target


def _load_sequence(input_path: Path) -> Any:
    from pySim.esim.saip import ProfileElementSequence

    payload = read_bounded_regular_file(input_path, _MAX_PROFILE_BYTES)
    return ProfileElementSequence.from_der(payload)


def _print_decoded(value: Any) -> None:
    pprint.pprint(value, width=140, sort_dicts=False)


def _output_directory(path_value: object) -> Path:
    """Resolve an output directory without changing permissions on an existing one."""
    target = Path(str(path_value)).expanduser().resolve()
    if target.exists():
        if target.is_dir() is False:
            raise NotADirectoryError(str(target))
        return target
    return ensure_private_directory(target)


def _split(pes: Any, options: argparse.Namespace) -> int:
    output_dir = _output_directory(options.output_prefix)
    source_stem = _safe_component(Path(options.input_upp).stem, "profile")
    for index, pe in enumerate(pes.pe_list):
        pe_type = _safe_component(getattr(pe, "type", ""), "unknown")
        identification = getattr(pe, "identification", None)
        identity_text = ""
        if identification is not None:
            identity_text = f"-{int(identification):05d}"
        filename = f"{source_stem}-{index:02d}{identity_text}-{pe_type}.der"
        target = output_dir / filename
        atomic_write_bytes(target, bytes(pe.to_der()))
        print(f"Wrote profile element {index} ({pe_type}) to '{target}'.")
    return 0


def _dump(pes: Any, options: argparse.Namespace) -> int:
    if options.mode == "all_pe":
        groups = [
            (str(getattr(pe, "type", "unknown")), [pe])
            for pe in pes
        ]
    elif options.mode == "all_pe_by_type":
        groups = [
            (str(pe_type), list(elements))
            for pe_type, elements in pes.pe_by_type.items()
        ]
    else:
        groups = []
        for naa_type, instances in pes.pes_by_naa.items():
            for index, elements in enumerate(instances):
                groups.append((f"{naa_type}{index}", list(elements)))

    for label, elements in groups:
        print(f"{'=' * 70} {label}")
        for pe in elements:
            if options.mode != "all_pe":
                pe_type = str(getattr(pe, "type", "unknown"))
                identification = getattr(pe, "identification", None)
                print(
                    f"{pe_type} "
                    f"(identification={identification if identification is not None else 'none'})"
                )
            if options.dump_decoded:
                _print_decoded(getattr(pe, "decoded", None))
    return 0


def _check(pes: Any, _options: argparse.Namespace) -> int:
    from pySim.esim.saip.validation import CheckBasicStructure

    print("Checking profile-element sequence structure...")
    CheckBasicStructure().check(pes)
    print("No basic-structure violations found.")
    return 0


def _remove_naa(pes: Any, options: argparse.Namespace) -> int:
    from pySim.esim.saip import NAAs

    pes.remove_naas_of_type(NAAs[options.naa_type])
    print(f"Removed all {options.naa_type.upper()} NAA instances.")
    _write_sequence(pes, options.output_file)
    return 0


def _print_application_info(pes: Any) -> None:
    applications = list(pes.pe_by_type.get("application", []))
    if len(applications) == 0:
        print("No application profile elements are present.")
        return
    for index, application in enumerate(applications):
        decoded = getattr(application, "decoded", {}) or {}
        load_block = decoded.get("loadBlock", {}) or {}
        print(f"Application {index}:")
        print(f"  Load package AID: {_hex(load_block.get('loadPackageAID'))}")
        print(f"  Security-domain AID: {_hex(load_block.get('securityDomainAID'))}")
        load_object = load_block.get("loadBlockObject", b"")
        print(f"  Load block bytes: {len(load_object or b'')}")
        for instance_index, instance in enumerate(decoded.get("instanceList", []) or []):
            print(
                f"  Instance {instance_index}: "
                f"{_hex(instance.get('instanceAID'))}"
            )


def _info(pes: Any, options: argparse.Namespace) -> int:
    if options.apps:
        _print_application_info(pes)
        return 0

    header_list = list(pes.pe_by_type.get("header", []))
    header = getattr(header_list[0], "decoded", {}) if header_list else {}
    major = header.get("major-version", "?")
    minor = header.get("minor-version", "?")
    print(f"SAIP profile version: {major}.{minor}")
    print(f"Profile type: {header.get('profileType', '(unknown)')}")
    print(f"ICCID: {_hex(header.get('iccid'))}")
    mandatory = header.get("eUICC-Mandatory-services", {}) or {}
    print(f"Mandatory services: {', '.join(str(key) for key in mandatory)}")
    naa_groups = list(pes.pes_by_naa.items())
    naa_counts = ", ".join(
        f"{naa_type}[{len(instances)}]" for naa_type, instances in naa_groups
    )
    print(f"NAAs: {naa_counts or '(none)'}")
    for naa_type, instances in naa_groups:
        for index, elements in enumerate(instances):
            if len(elements) == 0:
                continue
            first_pe = elements[0]
            adf_name = str(getattr(first_pe, "adf_name", "") or "").upper()
            adf_suffix = f" ({adf_name})" if adf_name else ""
            print(
                f"NAA {naa_type}[{index}]: "
                f"{getattr(first_pe, 'type', 'unknown')}{adf_suffix}"
            )
            imsi = str(getattr(first_pe, "imsi", "") or "").strip()
            if imsi:
                print(f"  IMSI: {imsi}")

    applications = list(pes.pe_by_type.get("application", []))
    print(f"Applications: {len(applications)}")
    for index, application in enumerate(applications):
        decoded = getattr(application, "decoded", {}) or {}
        load_block = decoded.get("loadBlock", {}) or {}
        print(
            f"  Application {index} load package AID: "
            f"{_hex(load_block.get('loadPackageAID'))}"
        )
        print(
            f"    Load block bytes: "
            f"{len(load_block.get('loadBlockObject', b'') or b'')}"
        )
        for instance in decoded.get("instanceList", []) or []:
            print(f"    Instance AID: {_hex(instance.get('instanceAID'))}")

    security_domains = list(pes.pe_by_type.get("securityDomain", []))
    print(f"Security domains: {len(security_domains)}")
    for index, security_domain in enumerate(security_domains):
        decoded = getattr(security_domain, "decoded", {}) or {}
        instance = decoded.get("instance", {}) or {}
        print(
            f"  Security domain {index} instance AID: "
            f"{_hex(instance.get('instanceAID'))}"
        )
        for key in list(getattr(security_domain, "keys", []) or []):
            print(
                "    Key "
                f"KVN=0x{int(getattr(key, 'key_version_number', 0)):02X}, "
                f"KID=0x{int(getattr(key, 'key_identifier', 0)):02X}, "
                f"components={len(getattr(key, 'key_components', []) or [])} "
                "(data redacted)"
            )

    rfms = list(pes.pe_by_type.get("rfm", []))
    print(f"RFM instances: {len(rfms)}")
    for index, rfm in enumerate(rfms):
        decoded = getattr(rfm, "decoded", {}) or {}
        print(f"  RFM {index} instance AID: {_hex(decoded.get('instanceAID'))}")
        minimum_security_level = bytes(
            decoded.get("minimumSecurityLevel", b"") or b""
        )
        if minimum_security_level:
            print(
                f"    Minimum security level: "
                f"0x{minimum_security_level[0]:02X}"
            )
        adf_access = decoded.get("adfRFMAccess", {}) or {}
        if adf_access:
            print(f"    ADF AID: {_hex(adf_access.get('adfAID'))}")
        for tar in decoded.get("tarList", []) or []:
            print(f"    TAR: {_hex(tar)}")
    return 0


def _write_application_file(application: Any, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".yggdrasim-saip-app-",
        dir=str(target.parent),
    ) as temp_dir:
        temporary = Path(temp_dir) / target.name
        application.to_file(str(temporary))
        payload = read_bounded_regular_file(
            temporary,
            _MAX_APPLICATION_BYTES,
        )
        atomic_write_bytes(target, payload)


def _extract_apps(pes: Any, options: argparse.Namespace) -> int:
    output_dir = _output_directory(options.output_dir)
    iccid = _safe_component(getattr(pes, "iccid", ""), "profile")
    applications = list(pes.pe_by_type.get("application", []))
    for index, application in enumerate(applications):
        decoded = getattr(application, "decoded", {}) or {}
        load_block = decoded.get("loadBlock", {}) or {}
        package_aid = _safe_component(
            _hex(load_block.get("loadPackageAID")),
            f"application-{index}",
        )
        target = output_dir / f"{iccid}-{package_aid}.{options.format}"
        _write_application_file(application, target)
        ensure_private_file(target)
        print(f"Wrote application {package_aid} to '{target}'.")
    return 0


def _tree(pes: Any, _options: argparse.Namespace) -> int:
    filesystem = getattr(pes, "mf", None)
    if filesystem is None:
        print("No MF filesystem tree is present.")
        return 0
    filesystem.print_tree()
    return 0


_COMMAND_HANDLERS = {
    "split": _split,
    "dump": _dump,
    "check": _check,
    "remove-naa": _remove_naa,
    "info": _info,
    "extract-apps": _extract_apps,
    "tree": _tree,
}


def _requested_command(arguments: Sequence[str]) -> str | None:
    """Find the subcommand while skipping supported global options."""
    positional_count = 0
    index = 0
    while index < len(arguments):
        argument = str(arguments[index])
        if argument == "--debug":
            index += 1
            continue
        if argument == "--loglevel":
            index += 2
            continue
        if argument.startswith("--loglevel="):
            index += 1
            continue
        if argument.startswith("-"):
            index += 1
            continue
        positional_count += 1
        if positional_count == 2:
            return argument
        index += 1
    return None


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Run one SAIP command and return a process-style exit code."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    requested_command = _requested_command(raw_args)
    if (
        requested_command is not None
        and requested_command not in _COMMAND_HANDLERS
    ):
        sys.stderr.write(
            "saip-tool: the bundled frozen adapter does not support RAW "
            f"subcommand {requested_command!r}. Configure YGGDRASIM_SAIP_TOOL "
            "to a separate trusted executable for additional mutations.\n"
        )
        return 2
    options = _build_parser().parse_args(raw_args)
    logging.basicConfig(
        level=logging.DEBUG if options.debug else getattr(logging, options.loglevel),
    )
    input_path = Path(options.input_upp).expanduser().resolve()
    try:
        pes = _load_sequence(input_path)
        print(
            f"Read {len(pes.pe_list)} profile elements from "
            f"'{input_path}'."
        )
        handler = _COMMAND_HANDLERS[options.command]
        return int(handler(pes, options))
    except Exception as error:
        sys.stderr.write(
            f"saip-tool: {type(error).__name__}: {error}\n"
        )
        return 2


__all__ = ["run_cli"]


if __name__ == "__main__":
    raise SystemExit(run_cli())
