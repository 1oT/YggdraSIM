# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Decode-boundary contract for every public byte-taking decoder.

Every ``decode_*`` / ``parse_*`` entry point whose leading parameter is
annotated as bytes gets fed the malformed inputs the agent coding
standards name: empty input, a single byte, a truncated TLV header, a
length that over-claims its body, a long-form length with no body, and an
odd-nibble BCD run. A decoder may reject any of them; it may not crash.

A rejection is clean when it is ``ValueError``, ``KeyError``,
``NotImplementedError``, or any exception class this repository defines
(``Scp03ResponseProtectionError``, ``EuiccPackageDecodeError``, and
friends). ``IndexError``, ``struct.error``, ``AttributeError``, and the
upstream ``OutOfByteDataError`` / ``MissingDataError`` families read as
crashes and fail the test.

Discovery is automatic for bytes-annotated parameters, so a decoder added
later is covered without touching this file. Decoders that take hex text
rather than bytes are opted in through ``EXTRA_TEXT_TARGETS``.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import unittest
from pathlib import Path
from typing import Any, Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]

# Packages walked for decode entry points.
TARGET_PACKAGES = (
    "SCP03",
    "SCP80",
    "SCP11",
    "SIMCARD",
    "Tools.ProfilePackage",
    "Tools.Asn1TlvDecode",
    "Tools.HilBridge",
    "yggdrasim_common",
)

# Annotations that mean "this parameter is the payload".
BYTES_ANNOTATIONS = frozenset(
    {
        "bytes",
        "bytearray",
        "memoryview",
        "bytes | None",
        "bytes | bytearray",
        "Optional[bytes]",
        "Sequence[int]",
    }
)

# Malformed inputs named by the decode-boundary standard.
MALFORMED_PAYLOADS: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("single byte", b"\x62"),
    ("truncated TLV header", b"\x62\x81"),
    ("length over-claims body", b"\x62\xc8"),
    ("long-form length, no body", b"\x62\x82"),
    ("long-form length 0x8204, no body", b"\x62\x82\x04\x00"),
    ("odd-nibble BCD run", b"\x98\x64\x0f"),
    ("all-ones", b"\xff\xff\xff\xff"),
    ("nested truncated BF37", b"\xbf\x37\x82\xff\xff\x30"),
    ("indefinite length", b"\x30\x80"),
)

# Rejections that read as a deliberate "no" rather than a crash.
CLEAN_REJECTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    KeyError,
    NotImplementedError,
)

# Decoders whose leading parameter is hex text or ``Any`` rather than
# bytes. Auto-discovery cannot tell these apart from path or filename
# arguments, so they are listed rather than guessed.
EXTRA_TEXT_TARGETS: tuple[tuple[str, str], ...] = (
    ("Tools.ProfilePackage.saip_pin_digits", "decode_hex_to_digits"),
    ("Tools.ProfilePackage.saip_arr_record_picker", "decode_arr_reference"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_access_domain"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_msl"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_afi"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_key_usage"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_key_access"),
    ("Tools.ProfilePackage.saip_security_domain_catalog", "decode_key_version"),
    ("Tools.ProfilePackage.saip_connectivity_parameters", "decode_connectivity_parameters"),
)

MALFORMED_TEXT: tuple[tuple[str, str], ...] = (
    ("empty text", ""),
    ("odd-nibble hex", "62C"),
    ("non-hex text", "zzzz"),
    ("truncated TLV hex", "6281"),
    ("over-claiming hex", "62C8"),
    ("all-ones hex", "FFFFFFFF"),
)


def _repo_owned(exc: BaseException) -> bool:
    """True when the exception class is defined inside this repository."""
    module = sys.modules.get(type(exc).__module__ or "")
    source = getattr(module, "__file__", None)
    if source is None:
        return False
    try:
        return Path(source).resolve().is_relative_to(REPO_ROOT)
    except (OSError, ValueError):
        return False


def _walk_module_names() -> Iterator[str]:
    for package_name in TARGET_PACKAGES:
        try:
            package = importlib.import_module(package_name)
        except Exception:
            continue
        yield package_name
        search_paths = getattr(package, "__path__", None)
        if search_paths is None:
            continue
        for entry in pkgutil.walk_packages(search_paths, prefix=package_name + "."):
            yield entry.name


def _annotation_text(annotation: Any) -> str:
    if annotation is inspect.Parameter.empty:
        return ""
    if isinstance(annotation, str):
        return annotation
    return getattr(annotation, "__name__", "") or str(annotation)


def _byte_targets(module: Any) -> Iterator[tuple[str, Callable[..., Any], list[Any]]]:
    """Yield (name, function, trailing-argument fillers) for byte decoders."""
    for name, obj in vars(module).items():
        if not inspect.isfunction(obj):
            continue
        if getattr(obj, "__module__", None) != module.__name__:
            continue
        if not (name.startswith("decode_") or name.startswith("parse_")):
            continue
        try:
            signature = inspect.signature(obj)
        except (ValueError, TypeError):
            continue
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        required = [
            parameter
            for parameter in positional
            if parameter.default is inspect.Parameter.empty
        ]
        if not required:
            continue
        if _annotation_text(required[0].annotation) not in BYTES_ANNOTATIONS:
            continue
        # Trailing required parameters are only fillable when they are tag
        # integers; anything else means this is not a single-payload decoder.
        fillers: list[Any] = []
        for parameter in required[1:]:
            if _annotation_text(parameter.annotation).startswith("int"):
                fillers.append(0x80)
            else:
                break
        else:
            yield name, obj, fillers


def _assert_clean(
    test: unittest.TestCase,
    function: Callable[..., Any],
    payload: Any,
    fillers: list[Any],
) -> None:
    try:
        function(payload, *fillers)
    except CLEAN_REJECTIONS:
        return
    except Exception as exc:  # noqa: BLE001 - classifying the escape is the point
        if _repo_owned(exc):
            return
        test.fail(
            f"{function.__module__}.{function.__name__} raised "
            f"{type(exc).__name__} instead of rejecting cleanly: {exc}"
        )


class DecoderBoundaryContractTests(unittest.TestCase):
    """Malformed input must produce a rejection, never a crash."""

    def test_byte_decoders_reject_malformed_input(self) -> None:
        probed = 0
        for module_name in _walk_module_names():
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            for name, function, fillers in _byte_targets(module):
                probed += 1
                for label, payload in MALFORMED_PAYLOADS:
                    with self.subTest(decoder=f"{module_name}.{name}", payload=label):
                        _assert_clean(self, function, payload, fillers)
        # Guards against a refactor that silently empties discovery.
        self.assertGreater(
            probed,
            25,
            "byte-decoder discovery collapsed; the contract stopped covering anything",
        )

    def test_hex_text_decoders_reject_malformed_input(self) -> None:
        for module_name, function_name in EXTRA_TEXT_TARGETS:
            module = importlib.import_module(module_name)
            function = getattr(module, function_name)
            for label, payload in MALFORMED_TEXT:
                with self.subTest(decoder=f"{module_name}.{function_name}", payload=label):
                    _assert_clean(self, function, payload, [])


if __name__ == "__main__":
    unittest.main()
