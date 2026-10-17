# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Length indicators that count an F-padded BCD field inside an EF.

Several EF codings put a one-byte length in front of a fixed-width BCD
field whose unused nibbles are 'F':

* the dialling-number tail shared by EF.ADN, EF.FDN, EF.MSISDN, EF.SDN,
  EF.BDN, EF.MBDN, EF.LND, EF.ICE_DN, EF.ICI and EF.OCI: "Length of BCD
  number/SSC contents" gives the number of bytes of the TON/NPI byte and
  the dialling number that carry actual information, at most 11 (3GPP
  TS 31.102 v18.4.0 §4.4.2.3; the other files point at that clause);
* EF.CFIS, the same tail behind two status bytes (TS 31.102 §4.2.64);
* EF.SMSP, whose TP-Destination Address length counts useful semi-octets
  (3GPP TS 23.040 v19 §9.1.2.5) and whose TS-Service Centre Address
  length counts the octets that follow it, 2 to 11 (3GPP TS 24.011 v19
  §8.2.5.2), see TS 31.102 §4.2.27;
* EF.IMSI, whose "Length of IMSI" is the number of significant bytes
  that follow it (TS 31.102 §4.2.2);
* the additional-data records of EF.EXT1 to EF.EXT7, whose byte 2 counts
  the BCD bytes that continue a dialling number (TS 31.102 §4.4.2.4).

A template hard-codes such a byte while the field behind it is a
placeholder, so a stored value shorter than the placeholder span (an
11-digit MSISDN in an 8-byte slot) leaves the length byte counting 'FF'
filler, which the digit coding of TS 24.008 v19.5.0 §10.5.4.7 never
produces. :func:`derive_length_edits` reads a field the way the card
does and returns the bytes that disagree; the file view shows them, a
complete export writes them, and the linter reports what nothing fixes.

Codings are keyed by file name and checked against the identifier, as
``saip_ef_default_fill`` does: a ``6Fxx`` identifier is allocated per
DF, so 6F40 is EF.ICON under DF.GRAPHICS and EF.MSISDN under ADF.USIM.
"""

from __future__ import annotations

import copy
import math
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Sequence

_FILLER = 0x0F
# TS 24.008 v19.5.0 §10.5.4.7 Table 10.5.118: 0-9 are digits, A-E code
# '*', '#', 'a', 'b', 'c', and F is the endmark for an odd digit count.
_DIALLING_NIBBLES = frozenset(range(0x0, 0xF))
# TS 31.102 v18.4.0 §4.2.2: decimal digits; unused nibbles are 'F'.
_IMSI_NIBBLES = frozenset(range(0x0, 0xA))
_ADN_MAX_LENGTH = 11
_DATA_TAGS = frozenset({"fillFileContent", "fillFileOffset"})
_DF_GRAPHICS = "5F50"
_DF_PHONEBOOK = "5F3A"


@dataclass(frozen=True)
class LengthField:
    """One length byte and the F-padded field it counts, record-relative."""

    label: str
    length_offset: int
    ton_offset: int | None
    digits_start: int
    digits_end: int
    counting: str
    spec: str
    # ``(offset, mask)`` of a presence bit that marks the field absent when
    # set (EF.SMSP Parameter Indicators, TS 31.102 §4.2.27).
    absent_when: tuple[int, int] | None = None
    # ``(offset, value)`` a byte must equal for the field to exist at all
    # (the EXT record type 02 "additional data", TS 31.102 §4.4.2.4).
    only_when: tuple[int, int] | None = None


@dataclass(frozen=True)
class EfLengthCoding:
    """The length fields of one EF coding."""

    ef_name: str
    fid: str
    structure: str
    spec: str
    tail: int = 0
    fixed_size: int | None = None

    def fields_for(self, record_size: int | None) -> tuple[LengthField, ...]:
        """The fields of one record (or of the transparent body)."""
        if self.ef_name == "IMSI":
            return (
                LengthField(
                    "Length of IMSI", 0, None, 1, 9, "imsi_octets", self.spec
                ),
            )
        if self.ef_name.startswith("EXT"):
            if record_size is not None and record_size < 13:
                return ()
            return (
                LengthField(
                    "Length of extension data",
                    1,
                    None,
                    2,
                    12,
                    "bcd_bytes",
                    self.spec,
                    only_when=(0, 0x02),
                ),
            )
        if self.ef_name == "CFIS":
            if record_size is not None and record_size < 14:
                return ()
            return (
                LengthField(
                    "Length of BCD number", 2, 3, 4, 14, "octets", self.spec
                ),
            )
        if not isinstance(record_size, int) or record_size < self.tail:
            return ()
        if self.ef_name == "SMSP":
            alpha = record_size - self.tail
            return (
                LengthField(
                    "TP-Destination Address length",
                    alpha + 1,
                    alpha + 2,
                    alpha + 3,
                    alpha + 13,
                    "semi_octets",
                    "3GPP TS 31.102 v18.4.0 §4.2.27 / 3GPP TS 23.040 v19 §9.1.2.5",
                    absent_when=(alpha, 0x01),
                ),
                LengthField(
                    "TS-Service Centre Address length",
                    alpha + 13,
                    alpha + 14,
                    alpha + 15,
                    alpha + 25,
                    "octets",
                    "3GPP TS 31.102 v18.4.0 §4.2.27 / 3GPP TS 24.011 v19 §8.2.5.2",
                    absent_when=(alpha, 0x02),
                ),
            )
        alpha = record_size - self.tail
        return (
            LengthField(
                "Length of BCD number/SSC contents",
                alpha,
                alpha + 1,
                alpha + 2,
                alpha + 12,
                "octets",
                self.spec,
            ),
        )


def _tail(ef_name: str, fid: str, spec: str, tail: int) -> EfLengthCoding:
    return EfLengthCoding(ef_name, fid, "record", spec, tail=tail)


# Keyed by the bare file name (EF.MSISDN -> MSISDN). The dialling-number
# tail is X+14 bytes behind an alpha identifier of X bytes; EF.BDN adds a
# byte, EF.ICI and EF.OCI add the call log fields.
_CODINGS: dict[str, EfLengthCoding] = {
    "ADN": _tail("ADN", "6F3A", "3GPP TS 31.102 v18.4.0 §4.4.2.3", 14),
    "FDN": _tail("FDN", "6F3B", "3GPP TS 31.102 v18.4.0 §4.2.24", 14),
    "MSISDN": _tail("MSISDN", "6F40", "3GPP TS 31.102 v18.4.0 §4.2.26", 14),
    "SDN": _tail("SDN", "6F49", "3GPP TS 31.102 v18.4.0 §4.2.29", 14),
    "BDN": _tail("BDN", "6F4D", "3GPP TS 31.102 v18.4.0 §4.2.44", 15),
    "MBDN": _tail("MBDN", "6FC7", "3GPP TS 31.102 v18.4.0 §4.2.60", 14),
    "LND": _tail("LND", "6F44", "3GPP TS 51.011 v4.15.0 §10.5.8", 14),
    "ICE_DN": _tail("ICE_DN", "6FE0", "3GPP TS 31.102 v18.4.0 §4.5.6", 14),
    "ICI": _tail("ICI", "6F80", "3GPP TS 31.102 v18.4.0 §4.2.33", 28),
    "OCI": _tail("OCI", "6F81", "3GPP TS 31.102 v18.4.0 §4.2.34", 27),
    "CFIS": EfLengthCoding(
        "CFIS", "6FCB", "record", "3GPP TS 31.102 v18.4.0 §4.2.64", tail=16
    ),
    "SMSP": _tail("SMSP", "6F42", "3GPP TS 31.102 v18.4.0 §4.2.27", 28),
    # Extension records: byte 1 record type, byte 2 length of extension data,
    # bytes 3-12 extension data, byte 13 identifier (13-byte records).
    "EXT1": _tail("EXT1", "6F4A", "3GPP TS 31.102 v18.4.0 §4.4.2.4", 13),
    "EXT2": _tail("EXT2", "6F4B", "3GPP TS 31.102 v18.4.0 §4.2.30", 13),
    "EXT3": _tail("EXT3", "6F4C", "3GPP TS 31.102 v18.4.0 §4.2.31", 13),
    "EXT4": _tail("EXT4", "6F55", "3GPP TS 31.102 v18.4.0 §4.2.45", 13),
    "EXT5": _tail("EXT5", "6F4E", "3GPP TS 31.102 v18.4.0 §4.2.37", 13),
    "EXT6": _tail("EXT6", "6FC8", "3GPP TS 31.102 v18.4.0 §4.2.61", 13),
    "EXT7": _tail("EXT7", "6FCC", "3GPP TS 31.102 v18.4.0 §4.2.65", 13),
    "IMSI": EfLengthCoding(
        "IMSI", "6F07", "transparent", "3GPP TS 31.102 v18.4.0 §4.2.2", fixed_size=9
    ),
}
_CODING_BY_FID: dict[str, EfLengthCoding] = {
    coding.fid: coding for coding in _CODINGS.values()
}


def normalise_ef_name(name: Any) -> str:
    """``EF.MSISDN`` / ``ef-msisdn`` / ``EF_MSISDN`` -> ``MSISDN``."""
    text = str(name or "").strip().upper().replace("-", "_").replace(" ", "_")
    for prefix in ("EF.", "EF_"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def coding_for_file(
    ef_name: Any,
    fid: Any = None,
    *,
    parent_fid: Any = None,
) -> EfLengthCoding | None:
    """The coding of a file, by name first and by identifier as a check.

    Without a name the identifier decides, except under DF.GRAPHICS (its
    6F40..6F7B are EF.ICON) and DF.PHONEBOOK (4Fxx files), where the same
    numbers name other files.
    """
    fid_text = str(fid or "").strip().upper().replace(" ", "")
    if fid_text.startswith("0X"):
        fid_text = fid_text[2:]
    name = normalise_ef_name(ef_name)
    if name:
        coding = _CODINGS.get(name)
        if coding is None:
            return None
        if fid_text and fid_text != coding.fid:
            return None
        return coding
    parent = str(parent_fid or "").strip().upper()
    if parent in (_DF_GRAPHICS, _DF_PHONEBOOK):
        return None
    return _CODING_BY_FID.get(fid_text)


@dataclass(frozen=True)
class LengthFieldEdit:
    """A length byte that disagrees with the field it counts."""

    ef_name: str
    label: str
    record: int
    offset: int
    declared: int
    derived: int
    digits: int
    counting: str
    spec: str

    @property
    def value_hex(self) -> str:
        return f"{self.derived:02X}"

    @property
    def template_hex(self) -> str:
        return f"{self.declared:02X}"

    def describe(self) -> str:
        """``EF.MSISDN record 1: Length of BCD number/SSC contents 09 -> 07 (...)``."""
        where = f"EF.{self.ef_name}"
        if self.record > 0:
            where += f" record {self.record}"
        if self.counting == "semi_octets":
            reason = f"{self.derived} useful semi-octet(s) for {self.digits} digit(s)"
        elif self.counting == "imsi_octets":
            reason = f"{self.derived} significant byte(s) for {self.digits} digit(s)"
        elif self.counting == "bcd_bytes":
            reason = f"{self.derived} BCD byte(s) for {self.digits} digit(s)"
        else:
            reason = (
                f"1 TON/NPI byte + {self.derived - 1} BCD byte(s) for "
                f"{self.digits} digit(s)"
            )
        return f"{where}: {self.label} {self.declared:02X} -> {self.derived:02X} ({reason})"

    def to_wire(self) -> dict[str, Any]:
        return {
            "kind": "length_field",
            "ef_name": f"EF.{self.ef_name}",
            "label": self.label,
            "record": self.record,
            "start": self.offset,
            "end": self.offset + 1,
            "template_hex": self.template_hex,
            "value_hex": self.value_hex,
            "declared": self.declared,
            "derived": self.derived,
            "digits": self.digits,
            "spec": self.spec,
            "note": self.describe(),
            "resolved": True,
        }


def _read_digit_run(
    data: bytes, start: int, end: int, allowed: frozenset[int]
) -> tuple[int, int, str]:
    """``(used_bytes, digits, problem)`` of an F-padded BCD run.

    Digits are packed low nibble first; the first F nibble ends the number
    and every later nibble must be F. A byte beyond ``data`` reads as FF.
    """
    used = 0
    digits = 0
    ended = False
    for offset in range(start, end):
        byte = data[offset] if offset < len(data) else 0xFF
        in_byte = 0
        for nibble in (byte & 0x0F, byte >> 4):
            if ended:
                if nibble != _FILLER:
                    return used, digits, f"digit after the F endmark at byte {offset}"
                continue
            if nibble == _FILLER:
                ended = True
                continue
            if nibble not in allowed:
                return used, digits, f"nibble {nibble:X} at byte {offset} is not a BCD digit"
            in_byte += 1
        if in_byte > 0:
            used += 1
        digits += in_byte
    return used, digits, ""


def _derive(field: LengthField, data: bytes) -> tuple[int | None, int, str]:
    """``(derived_length, digits, problem)``; ``None`` when the field is unused."""
    if field.absent_when is not None:
        indicator_offset, mask = field.absent_when
        indicator = data[indicator_offset] if indicator_offset < len(data) else 0xFF
        if indicator & mask:
            return None, 0, ""
    if field.only_when is not None:
        marker_offset, expected = field.only_when
        marker = data[marker_offset] if marker_offset < len(data) else 0xFF
        if marker != expected:
            return None, 0, ""
    if field.counting == "bcd_bytes":
        used, digits, problem = _read_digit_run(
            data, field.digits_start, field.digits_end, _DIALLING_NIBBLES
        )
        if problem:
            return None, 0, problem
        if used == 0:
            return None, 0, ""
        return used, digits, ""
    if field.counting == "imsi_octets":
        first = data[field.digits_start] if field.digits_start < len(data) else 0xFF
        if first == 0xFF:
            return None, 0, ""
        if (first >> 4) not in _IMSI_NIBBLES:
            return None, 0, f"IMSI digit 1 nibble {first >> 4:X} is not a decimal digit"
        used, digits, problem = _read_digit_run(
            data, field.digits_start + 1, field.digits_end, _IMSI_NIBBLES
        )
        if problem:
            return None, 0, problem
        return 1 + used, 1 + digits, ""
    ton = 0xFF
    if field.ton_offset is not None and field.ton_offset < len(data):
        ton = data[field.ton_offset]
    used, digits, problem = _read_digit_run(
        data, field.digits_start, field.digits_end, _DIALLING_NIBBLES
    )
    if problem:
        return None, 0, problem
    if used == 0:
        return None, 0, ""
    if ton == 0xFF:
        # TS 31.102 §4.4.2.3: TON/NPI is 'FF' only when no dialling number
        # is present, so digits behind it are not something to count.
        return None, 0, "TON/NPI is FF while the number holds digits"
    if field.counting == "semi_octets":
        return digits, digits, ""
    return min(_ADN_MAX_LENGTH, 1 + used), digits, ""


def _overlaps(ranges: Iterable[tuple[int, int]], start: int, end: int) -> bool:
    for range_start, range_end in ranges:
        if int(range_start) < end and int(range_end) > start:
            return True
    return False


def derive_length_edits(
    coding: EfLengthCoding,
    image: bytes,
    record_size: int | None = None,
    *,
    skip_ranges: Sequence[tuple[int, int]] = (),
) -> list[LengthFieldEdit]:
    """Length bytes of ``image`` that disagree with the fields they count.

    ``image`` is the file body; a short image reads as FF beyond its end.
    ``skip_ranges`` are file-absolute ``(start, end)`` spans whose bytes are
    not data (unresolved template placeholders): a field they touch is
    left alone. Malformed fields (a digit after the endmark, a non-BCD
    nibble, TON/NPI 'FF' in front of digits) are skipped as well; the
    linter names them separately.
    """
    payload = bytes(image or b"")
    if len(payload) == 0:
        return []
    if coding.structure == "transparent":
        windows = [(0, 0, len(payload))]
        fields = coding.fields_for(None)
    else:
        size = int(record_size or 0)
        if size <= 0:
            return []
        fields = coding.fields_for(size)
        count = max(1, math.ceil(len(payload) / size))
        windows = [(index + 1, index * size, size) for index in range(count)]
    edits: list[LengthFieldEdit] = []
    for record_number, base, window in windows:
        chunk = payload[base : base + window]
        for field in fields:
            if _overlaps(skip_ranges, base + field.length_offset, base + field.digits_end):
                continue
            derived, digits, problem = _derive(field, chunk)
            if derived is None or problem:
                continue
            declared = chunk[field.length_offset] if field.length_offset < len(chunk) else 0xFF
            if declared == derived:
                continue
            edits.append(
                LengthFieldEdit(
                    ef_name=coding.ef_name,
                    label=field.label,
                    record=record_number,
                    offset=base + field.length_offset,
                    declared=declared,
                    derived=derived,
                    digits=digits,
                    counting=field.counting,
                    spec=field.spec,
                )
            )
    return edits


def apply_length_edits(image: bytes, edits: Iterable[LengthFieldEdit]) -> bytes:
    """``image`` with every edit's derived byte written at its offset."""
    out = bytearray(image or b"")
    for edit in edits:
        if edit.offset >= len(out):
            out.extend(b"\xff" * (edit.offset + 1 - len(out)))
        out[edit.offset] = edit.derived & 0xFF
    return bytes(out)


def substitute_ranges(image: bytes, ranges: Iterable[dict[str, Any]]) -> bytes:
    """``image`` with each resolved range's ``value_hex`` in place of its bytes.

    The rule is the hex pane's: a value is used when it is hex of exactly
    the range's width; anything else leaves the bytes as they are.
    """
    out = bytearray(image or b"")
    for entry in ranges:
        if not isinstance(entry, dict):
            continue
        try:
            start = int(entry.get("start"))
            end = int(entry.get("end"))
        except (TypeError, ValueError):
            continue
        value_hex = str(entry.get("value_hex") or "").replace(" ", "")
        if start < 0 or end > len(out) or end <= start:
            continue
        if len(value_hex) != (end - start) * 2:
            continue
        try:
            out[start:end] = bytes.fromhex(value_hex)
        except ValueError:
            continue
    return bytes(out)


# ----------------------------------------------------------------------
# Document-level pass: fill tuples in a decoded document
# ----------------------------------------------------------------------


def _tagged_items(entries: Any) -> list[tuple[int, str, Any]]:
    """``(index, tag, value)`` for every tagged item of a file entry list.

    Accepts the pySim tuple form ``("fillFileContent", b"...")``, the JSON
    pair form ``["fillFileContent", {...}]`` and the editor projection
    ``{"@": ["fillFileContent", {...}]}``.
    """
    out: list[tuple[int, str, Any]] = []
    if not isinstance(entries, (list, tuple)):
        return out
    for index, item in enumerate(entries):
        tag: Any = None
        value: Any = None
        if isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[0], str):
            tag, value = item
        elif isinstance(item, dict):
            inner = item.get("@")
            if inner is None:
                inner = item.get("__ygg_saip_tuple__")
            if isinstance(inner, (list, tuple)) and len(inner) >= 2 and isinstance(inner[0], str):
                tag, value = inner[0], inner[1]
        if not tag:
            continue
        out.append((index, str(tag), value))
    return out


def _as_bytes(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, dict):
        for key in ("hex", "__ygg_saip_bytes__"):
            inner = value.get(key)
            if isinstance(inner, str):
                return _as_bytes(inner)
        return None
    if isinstance(value, str):
        text = value.replace(" ", "").strip()
        if len(text) == 0 or len(text) % 2:
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raw = _as_bytes(value)
    if raw is not None and len(raw) > 0:
        return int.from_bytes(raw, "big")
    return None


def _with_value(item: Any, value: bytes) -> Any:
    """``item`` (any accepted shape) carrying ``value`` instead of its bytes."""
    if isinstance(item, tuple):
        return (item[0], value)
    if isinstance(item, list):
        return [item[0], value]
    if isinstance(item, dict):
        inner = item.get("@")
        key = "@"
        if inner is None:
            inner = item.get("__ygg_saip_tuple__")
            key = "__ygg_saip_tuple__"
        original = inner[1] if isinstance(inner, (list, tuple)) and len(inner) >= 2 else None
        if isinstance(original, dict) and "hex" in original:
            payload: Any = dict(original, hex=value.hex().upper())
        elif isinstance(original, dict) and "__ygg_saip_bytes__" in original:
            payload = dict(original, __ygg_saip_bytes__=value.hex().upper())
        elif isinstance(original, str):
            payload = value.hex().upper()
        else:
            payload = value
        return dict(item, **{key: [inner[0], payload]})
    return item


def record_size_from_descriptor(descriptor: Any) -> tuple[int | None, int | None]:
    """``(record_size, file_size)`` from a createFCP / fileDescriptor payload."""
    if not isinstance(descriptor, dict):
        return None, None
    fd = _as_bytes(descriptor.get("fileDescriptor"))
    record_size: int | None = None
    if fd is not None and len(fd) >= 4 and (fd[0] & 0x07) in (0x02, 0x06):
        # ETSI TS 102 222: linear fixed / cyclic descriptors carry the
        # record length in bytes 3-4.
        record_size = int.from_bytes(fd[2:4], "big") or None
    file_size = _as_int(descriptor.get("efFileSize"))
    return record_size, file_size


@dataclass
class _FileChunks:
    """A file's fill tuples, assembled into an image with offsets kept."""

    image: bytes
    chunks: list[tuple[int, int, int]]
    record_size: int | None
    file_size: int | None

    def owner_of(self, offset: int) -> int | None:
        for index, start, length in self.chunks:
            if start <= offset < start + length:
                return index
        return None


def _assemble(entries: Any) -> _FileChunks:
    items = _tagged_items(entries)
    cursor = 0
    chunks: list[tuple[int, int, int]] = []
    pieces: list[tuple[int, bytes]] = []
    record_size: int | None = None
    file_size: int | None = None
    for index, tag, value in items:
        if tag in ("fileDescriptor", "createFCP"):
            record_size, file_size = record_size_from_descriptor(value)
            continue
        if tag == "fillFileOffset":
            step = _as_int(value)
            if step is not None:
                cursor += int(step)
            continue
        if tag != "fillFileContent":
            continue
        raw = _as_bytes(value)
        if raw is None:
            continue
        chunks.append((index, cursor, len(raw)))
        pieces.append((cursor, raw))
        cursor += len(raw)
    total = max([start + len(raw) for start, raw in pieces] + [0])
    image = bytearray(b"\xff" * total)
    for start, raw in pieces:
        image[start : start + len(raw)] = raw
    return _FileChunks(bytes(image), chunks, record_size, file_size)


@dataclass(frozen=True)
class DocumentLengthEdit:
    """A :class:`LengthFieldEdit` located in a decoded document."""

    section_key: str
    path: str
    edit: LengthFieldEdit
    patched: bool

    def describe(self) -> str:
        return self.edit.describe()


def _sentinel_ranges(image: bytes, sentinel_hexes: Iterable[str]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for hex_text in sentinel_hexes:
        try:
            needle = bytes.fromhex(str(hex_text))
        except ValueError:
            continue
        if len(needle) == 0:
            continue
        cursor = 0
        while True:
            start = image.find(needle, cursor)
            if start < 0:
                break
            ranges.append((start, start + len(needle)))
            cursor = start + len(needle)
    return ranges


def template_record_size(template_oid: Any, pe_name: str) -> int | None:
    """The TCA template's record length for ``pe_name``, when pySim knows it."""
    try:
        from pySim.esim.saip.templates import ProfileTemplateRegistry
    except ImportError:
        return None
    oid_text = str(template_oid or "").strip()
    if len(oid_text) == 0:
        return None
    try:
        template = ProfileTemplateRegistry.get_by_oid(oid_text)
    except (TypeError, ValueError):
        return None
    if template is None:
        return None
    files = getattr(template, "files_by_pename", None) or {}
    entry = files.get(pe_name)
    size = getattr(entry, "rec_len", None)
    return int(size) if isinstance(size, int) and size > 0 else None


def _reconcile_entries(
    entries: Any,
    coding: EfLengthCoding,
    *,
    record_size_hint: int | None,
    sentinel_hexes: Iterable[str],
    apply: bool,
) -> tuple[Any, list[tuple[LengthFieldEdit, bool]]]:
    assembled = _assemble(entries)
    if len(assembled.image) == 0:
        return entries, []
    record_size = assembled.record_size or record_size_hint
    if coding.structure == "record" and not record_size:
        return entries, []
    edits = derive_length_edits(
        coding,
        assembled.image,
        record_size,
        skip_ranges=_sentinel_ranges(assembled.image, sentinel_hexes),
    )
    if not edits:
        return entries, []
    out = list(entries) if apply else entries
    results: list[tuple[LengthFieldEdit, bool]] = []
    for edit in edits:
        owner = assembled.owner_of(edit.offset)
        patched = False
        if apply and owner is not None:
            chunk_start = next(start for index, start, _length in assembled.chunks if index == owner)
            items = dict((index, (tag, value)) for index, tag, value in _tagged_items(out))
            _tag, value = items[owner]
            raw = bytearray(_as_bytes(value) or b"")
            raw[edit.offset - chunk_start] = edit.derived & 0xFF
            out[owner] = _with_value(out[owner], bytes(raw))
            patched = True
        results.append((edit, patched))
    return out, results


def _iter_gfm_files(groups: Any) -> Iterator[tuple[str, str, list[int], list[Any]]]:
    """``(parent_fid, fid, [(group, index)], entries)`` per file of a GFM element.

    Mirrors pySim's ``ProfileElementGFM.pe2files``: ``filePath`` selects
    the DF (an empty path is the MF), ``createFCP`` starts a file and the
    fill tuples that follow belong to it. Entries are returned as a list
    so the caller can rewrite them and put them back by position.
    """
    if not isinstance(groups, (list, tuple)):
        return
    path: list[str] = ["3F00"]
    current: list[tuple[int, int]] = []
    current_fid = ""
    current_entries: list[Any] = []

    def flush() -> tuple[str, str, list[int], list[Any]] | None:
        if not current_fid or not current_entries:
            return None
        return (path[-1] if len(path) > 1 else "3F00", current_fid, list(current), list(current_entries))

    for group_index, group in enumerate(groups):
        items = _tagged_items(group)
        for index, tag, value in items:
            if tag == "filePath":
                done = flush()
                if done is not None:
                    yield done
                current, current_fid, current_entries = [], "", []
                raw = _as_bytes(value) or b""
                path = ["3F00"] + [raw[i : i + 2].hex().upper() for i in range(0, len(raw) - 1, 2)]
                continue
            if tag == "createFCP":
                done = flush()
                if done is not None:
                    yield done
                fid_bytes = _as_bytes(value.get("fileID")) if isinstance(value, dict) else None
                current_fid = fid_bytes.hex().upper() if fid_bytes else ""
                current = [(group_index, index)]
                current_entries = [group[index]]
                continue
            if tag in _DATA_TAGS and current_fid:
                current.append((group_index, index))
                current_entries.append(group[index])
    done = flush()
    if done is not None:
        yield done


def reconcile_document(
    document: Any,
    *,
    apply: bool = True,
    sentinel_hexes: Iterable[str] = (),
    record_sizes: dict[tuple[str, str], int] | None = None,
) -> tuple[Any, list[DocumentLengthEdit]]:
    """Reconcile every length field in a decoded document.

    Walks the template-based file entries (``usim.ef-msisdn`` and friends)
    and the generic-file-management command groups, assembles each file's
    fill tuples into its image and derives the length edits. With ``apply``
    the edits are written into a deep copy of the document, which is what
    a complete export encodes; without it the document is only read, which
    is what the linter wants. ``sentinel_hexes`` are template sentinels
    whose bytes are not data; ``record_sizes`` supplies
    ``(section_key, path) -> record size`` for entries whose descriptor
    omits it (the TCA template default the session knows).
    """
    sections = (document or {}).get("sections") if isinstance(document, dict) else None
    if not isinstance(sections, dict):
        return document, []
    target = copy.deepcopy(document) if apply else document
    target_sections = target["sections"]
    sentinels = [str(item) for item in sentinel_hexes if str(item)]
    hints = record_sizes or {}
    found: list[DocumentLengthEdit] = []
    for section_key, pe in target_sections.items():
        if not isinstance(pe, dict):
            continue
        template_oid = pe.get("templateID")
        for key, value in list(pe.items()):
            if key == "fileManagementCMD" or (
                key == "file" and isinstance(value, dict) and "fileManagementCMD" in value
            ):
                groups = value if key == "fileManagementCMD" else value["fileManagementCMD"]
                if not isinstance(groups, list):
                    continue
                for parent_fid, fid, positions, entries in list(_iter_gfm_files(groups)):
                    coding = coding_for_file("", fid, parent_fid=parent_fid)
                    if coding is None:
                        continue
                    hint = hints.get((str(section_key), f"{parent_fid}/{fid}"))
                    rewritten, results = _reconcile_entries(
                        entries,
                        coding,
                        record_size_hint=hint,
                        sentinel_hexes=sentinels,
                        apply=apply,
                    )
                    if apply and results:
                        for (group_index, index), item in zip(positions, rewritten):
                            if not isinstance(groups[group_index], list):
                                groups[group_index] = list(groups[group_index])
                            groups[group_index][index] = item
                    for edit, patched in results:
                        found.append(
                            DocumentLengthEdit(
                                str(section_key),
                                f"fileManagementCMD.{parent_fid}/{fid}",
                                edit,
                                patched,
                            )
                        )
                continue
            if not str(key).startswith("ef-") or not isinstance(value, (list, tuple)):
                continue
            coding = coding_for_file(key)
            if coding is None:
                continue
            hint = hints.get((str(section_key), str(key)))
            if hint is None and coding.structure == "record":
                hint = template_record_size(template_oid, str(key))
            rewritten, results = _reconcile_entries(
                value,
                coding,
                record_size_hint=hint,
                sentinel_hexes=sentinels,
                apply=apply,
            )
            if apply and results:
                pe[key] = rewritten
            for edit, patched in results:
                found.append(DocumentLengthEdit(str(section_key), str(key), edit, patched))
    return target, found


def record_sizes_from_sequence(pes: Any) -> dict[tuple[str, str], int]:
    """``(section_key, path) -> record size`` from a live ProfileElementSequence.

    Section keys follow the decoded document (``usim``, ``usim_2`` ...);
    the path is the file's PE name for a template element and
    ``<parent fid>/<fid>`` for a generic-file-management element.
    """
    out: dict[tuple[str, str], int] = {}
    pe_list = list(getattr(pes, "pe_list", None) or [])
    seen: dict[str, int] = {}
    for pe in pe_list:
        pe_type = str(getattr(pe, "type", "") or "")
        count = seen.get(pe_type, 0) + 1
        seen[pe_type] = count
        section_key = pe_type if count == 1 else f"{pe_type}_{count}"
        files = getattr(pe, "files", None)
        if not isinstance(files, dict):
            continue
        for path, pe_file in files.items():
            size = getattr(pe_file, "rec_len", None)
            if not isinstance(size, int) or size <= 0:
                continue
            text = str(path)
            if "/" in text:
                parts = text.split("/")
                text = f"{parts[-2]}/{parts[-1]}" if len(parts) >= 2 else text
            out[(section_key, text)] = int(size)
    return out


@dataclass(frozen=True)
class DocumentFile:
    """One file of a decoded document: a template entry or a GFM file.

    ``path`` is the file's PE name for a template element (``ef-smsp``)
    and ``<parent fid>/<fid>`` for a generic-file-management file, the
    key ``record_sizes_from_sequence`` uses. ``parent_fid`` is empty for
    a template entry. ``link_path`` is the ``<parent fid>/<fid>`` a
    template entry's ``linkPath`` names (TCA SAIP ``Fcp.linkPath``: the
    file shares the body of another file and carries none of its own).
    """

    section_key: str
    path: str
    fid: str
    parent_fid: str
    entries: Any
    record_size: int | None
    link_path: str = ""

    @property
    def image(self) -> bytes:
        """The fill tuples assembled into the file body, offsets kept."""
        return _assemble(self.entries).image


def _link_path_of(entries: Any) -> str:
    for _index, tag, value in _tagged_items(entries):
        if tag not in ("fileDescriptor", "createFCP") or not isinstance(value, dict):
            continue
        raw = _as_bytes(value.get("linkPath"))
        if raw is None or len(raw) < 2:
            continue
        fids = [raw[i : i + 2].hex().upper() for i in range(0, len(raw) - 1, 2)]
        if len(fids) == 1:
            return f"3F00/{fids[0]}"
        return f"{fids[-2]}/{fids[-1]}"
    return ""


def iter_document_files(
    document: Any,
    *,
    record_sizes: dict[tuple[str, str], int] | None = None,
) -> Iterator[DocumentFile]:
    """Every file of a decoded document, in document order.

    Walks the same shapes as :func:`reconcile_document`: the template
    entries (``usim.ef-smsp`` and friends) and the generic-file-management
    command groups. A template entry carries the identifier its coding
    knows, when it has one; a GFM file carries the identifier and parent
    of its ``createFCP``. The record size is the descriptor's, else the
    ``record_sizes`` hint, else (template entries only) the TCA template's
    default.
    """
    sections = (document or {}).get("sections") if isinstance(document, dict) else None
    if not isinstance(sections, dict):
        return
    hints = record_sizes or {}
    for section_key, pe in sections.items():
        if not isinstance(pe, dict):
            continue
        template_oid = pe.get("templateID")
        for key, value in pe.items():
            if key == "fileManagementCMD" or (
                key == "file" and isinstance(value, dict) and "fileManagementCMD" in value
            ):
                groups = value if key == "fileManagementCMD" else value["fileManagementCMD"]
                if not isinstance(groups, list):
                    continue
                for parent_fid, fid, _positions, entries in _iter_gfm_files(groups):
                    path = f"{parent_fid}/{fid}"
                    size = _assemble(entries).record_size or hints.get((str(section_key), path))
                    yield DocumentFile(str(section_key), path, fid, parent_fid, entries, size)
                continue
            if not str(key).startswith("ef-") or not isinstance(value, (list, tuple)):
                continue
            coding = coding_for_file(key)
            size = _assemble(value).record_size or hints.get((str(section_key), str(key)))
            if size is None:
                size = template_record_size(template_oid, str(key))
            yield DocumentFile(
                str(section_key),
                str(key),
                coding.fid if coding is not None else "",
                "",
                value,
                size,
                link_path=_link_path_of(value),
            )
