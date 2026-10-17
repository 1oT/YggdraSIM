# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Padded file content a Profile Package need not carry.

TCA SAIP V3.4.1 section 8.3.3: content given through ``fillFileContent`` /
``fillFileOffset`` "shall have the same effect as creating a file with a
fill/repeat pattern, or non-pattern content and thereafter updating the
content via Update". A byte equal to the image the eUICC creates the file
with is carried for nothing. That image is the Fcp Filling or Repeat
Pattern (ETSI TS 102 222 v17.1 6.3.2.2.2, tags 'C1' / 'C2', laid into each
record of a record-oriented EF), else the template's default value (SAIP
section 9 tables; per record for a linear-fixed or cyclic EF, EF ICI on
page 86 being 20 records of 38 bytes with one default each). A file that
declares neither is left alone: the standard defines no initial content
for it, so nothing can be proven equal.

Per file the trimmer keeps every written byte that differs from the image,
groups the kept bytes into runs separated by ``fillFileOffset`` moves (a
move costs more than the bytes it skips below ``MERGE_GAP``), keeps the
first written record of a cyclic EF written (section 8.3.5: after creation
the record pointer sits on the first record created), refuses BER-TLV files
(section 8.3.2: no ``fillFileOffset``, TLVs concatenated), linked files and
files written beyond their declared size, and proves each result by
replaying both tuple lists onto the image before anything is replaced.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DATA_KEYS: tuple[str, ...] = ("fillFileOffset", "fillFileContent")
TRIMMABLE_FILE_TYPES: tuple[str, ...] = ("TR", "LF", "CY")
# A fillFileOffset (2 to 4 bytes) plus the head of a new fillFileContent
# (2 or 3 bytes) cost about this much, so up to this many bytes the image
# already holds are carried inline rather than skipped.
MERGE_GAP = 6
# UInt16: the largest move one fillFileOffset expresses.
_MAX_OFFSET = 0xFFFF


@dataclass
class FileTrim:
    """What the trimmer decided for one file."""

    section: str
    file: str
    file_type: str
    declared_size: int | None
    image_source: str
    bytes_before: int
    bytes_after: int
    cost_before: int
    cost_after: int
    status: str
    reason: str = ""

    @property
    def saved(self) -> int:
        return self.cost_before - self.cost_after

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["saved"] = self.saved
        return payload


@dataclass
class TrimReport:
    """The decisions for every file of a package and their totals."""

    applied: bool
    files: list[FileTrim] = field(default_factory=list)
    changed_pe_indexes: list[int] = field(default_factory=list)

    def totals(self) -> dict[str, int]:
        trimmed = [item for item in self.files if item.status == "trim"]
        return {
            "files_seen": len(self.files),
            "files_trimmed": len(trimmed),
            "files_skipped": sum(1 for item in self.files if item.status == "skipped"),
            "bytes_before": sum(item.bytes_before for item in self.files),
            "bytes_after": sum(item.bytes_after for item in self.files),
            "cost_before": sum(item.cost_before for item in self.files),
            "cost_after": sum(item.cost_after for item in self.files),
            "saved": sum(item.saved for item in trimmed),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "totals": self.totals(),
            "changed_pe_indexes": list(self.changed_pe_indexes),
            "files": [item.to_dict() for item in self.files],
        }


def tlv_cost(length: int) -> int:
    """DER bytes of a primitive TLV carrying ``length`` payload bytes."""
    if length < 0x80:
        return 2 + length
    if length < 0x100:
        return 3 + length
    return 4 + length


def offset_cost(value: int) -> int:
    """DER bytes of a UInt16 ``fillFileOffset``."""
    if value < 0x80:
        return 3
    if value < 0x8000:
        return 4
    return 5


def data_tuple_cost(tuples: list[Any]) -> int:
    """DER bytes the data tuples of one file occupy."""
    cost = 0
    for item in tuples:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        key, value = item
        if key == "fillFileOffset":
            cost += offset_cost(int(value))
        elif key == "fillFileContent":
            cost += tlv_cost(len(bytes(value)))
    return cost


def explicit_writes(tuples: list[Any]) -> dict[int, int]:
    """The bytes a tuple list writes, by body offset; a later write wins.

    SAIP V3.4.1 section 8.3.5: the pointer starts at the beginning of the
    file, ``fillFileOffset`` moves it forward without writing and
    ``fillFileContent`` writes at the pointer and moves it on.
    """
    cursor = 0
    writes: dict[int, int] = {}
    for item in tuples:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        key, value = item
        if key == "fillFileOffset":
            cursor += int(value)
        elif key == "fillFileContent":
            data = bytes(value)
            for index, byte in enumerate(data):
                writes[cursor + index] = byte
            cursor += len(data)
    return writes


def file_geometry(pe_file: Any) -> tuple[int | None, int]:
    """``(declared size, pattern window)``: the record length for LF / CY, else the size."""
    file_type = getattr(pe_file, "file_type", None)
    if file_type in ("LF", "CY"):
        rec_len = getattr(pe_file, "rec_len", None)
        if not isinstance(rec_len, int) or rec_len <= 0:
            return (None, 0)
        nb_rec = getattr(pe_file, "nb_rec", None)
        if isinstance(nb_rec, int) and nb_rec > 0:
            return (rec_len * nb_rec, rec_len)
        try:
            declared = pe_file.file_size
        except Exception:  # noqa: BLE001 -- pySim derives nb_rec lazily and may raise
            declared = None
        if isinstance(declared, int) and declared > 0:
            return (declared, rec_len)
        return (None, rec_len)
    try:
        declared = pe_file.file_size
    except Exception:  # noqa: BLE001 -- pySim's accessor may raise on a missing FCP
        declared = None
    if isinstance(declared, int) and declared > 0:
        return (declared, declared)
    return (None, 0)


def initial_image(pe_file: Any, size: int, window: int) -> tuple[list[int | None], str]:
    """The image the file is created with, one entry per byte.

    ``None`` marks a byte the standard leaves undefined (the tail of a
    literal template default shorter than its record); such a byte is never
    dropped. The second element names the source: ``fillPattern``,
    ``repeatPattern``, ``template`` or ``""`` when the file declares none.
    """
    unknown: list[int | None] = [None] * size
    if window <= 0 or size <= 0:
        return (unknown, "")
    pattern = bytes(getattr(pe_file, "fill_pattern", None) or b"")
    unit: list[int | None]
    if len(pattern) > 0:
        from pySim import ts_102_222

        repeat = bool(getattr(pe_file, "fill_pattern_repeat", False))
        expanded = bytes(ts_102_222.expand_pattern(pattern, repeat, window))[:window]
        if len(expanded) < window:
            return (unknown, "")
        unit = list(expanded)
        source = "repeatPattern" if repeat else "fillPattern"
    else:
        template = getattr(pe_file, "template", None)
        default = getattr(template, "default_val", None) if template is not None else None
        if not default:
            return (unknown, "")
        try:
            expanded_default = template.expand_default_value_pattern(window)
        except (ValueError, TypeError):
            return (unknown, "")
        if not expanded_default:
            return (unknown, "")
        literal = bytes(expanded_default)[:window]
        unit = list(literal) + [None] * (window - len(literal))
        source = "template"
    image: list[int | None] = []
    while len(image) < size:
        image.extend(unit)
    return (image[:size], source)


def _runs(keep: list[int], writes: dict[int, int], merge_gap: int) -> list[tuple[int, int]]:
    """Group kept offsets into inclusive runs, bridging short written gaps."""
    runs: list[tuple[int, int]] = []
    start: int | None = None
    prev = 0
    for offset in keep:
        if start is None:
            start = prev = offset
            continue
        gap = offset - prev - 1
        bridged = gap <= merge_gap and all((prev + step) in writes for step in range(1, gap + 1))
        if bridged:
            prev = offset
            continue
        runs.append((start, prev))
        start = prev = offset
    if start is not None:
        runs.append((start, prev))
    return runs


def encode_runs(runs: list[tuple[int, int]], writes: dict[int, int]) -> list[tuple[str, Any]]:
    """Runs of kept offsets as ``fillFileOffset`` / ``fillFileContent`` tuples."""
    tuples: list[tuple[str, Any]] = []
    cursor = 0
    for start, end in runs:
        move = start - cursor
        while move > _MAX_OFFSET:
            tuples.append(("fillFileOffset", _MAX_OFFSET))
            move -= _MAX_OFFSET
        if move > 0:
            tuples.append(("fillFileOffset", move))
        tuples.append(("fillFileContent", bytes(writes[offset] for offset in range(start, end + 1))))
        cursor = end + 1
    return tuples


def replay(tuples: list[Any], image: list[int | None]) -> list[int | None]:
    """The image after the tuple list has been applied to it."""
    result = list(image)
    for offset, byte in explicit_writes(tuples).items():
        if offset >= len(result):
            raise ValueError(f"content written at offset {offset} beyond the declared {len(result)} B")
        result[offset] = byte
    return result


def plan_trim(
    data_tuples: list[Any],
    *,
    image: list[int | None],
    file_type: str,
    rec_len: int,
    merge_gap: int = MERGE_GAP,
) -> tuple[list[tuple[str, Any]] | None, str]:
    """The trimmed data tuples of one file, or ``None`` and the reason.

    Raises ``ValueError`` when the content reaches beyond the declared size.
    """
    writes = explicit_writes(data_tuples)
    if len(writes) == 0:
        return (None, "no content")
    if max(writes) >= len(image):
        raise ValueError(
            f"content written at offset {max(writes)} beyond the declared {len(image)} B"
        )
    keep = sorted(
        offset for offset, byte in writes.items()
        if image[offset] is None or image[offset] != byte
    )
    if file_type == "CY" and rec_len > 0:
        first = min(writes)
        first_record = first // rec_len
        if all(offset // rec_len != first_record for offset in keep):
            keep.append(first)
            keep.sort()
    trimmed = encode_runs(_runs(keep, writes, merge_gap), writes)
    if replay(trimmed, image) != replay(list(data_tuples), image):
        return (None, "replay of the trimmed list differs from the original")
    return (trimmed, "")


def _fcp_of(entries: list[Any], key: str) -> dict[str, Any]:
    for item in entries:
        if isinstance(item, tuple) and len(item) == 2 and item[0] == key and isinstance(item[1], dict):
            return item[1]
    return {}


def _is_data(item: Any) -> bool:
    return isinstance(item, tuple) and len(item) == 2 and item[0] in DATA_KEYS


def _trim_one(
    report: TrimReport,
    *,
    section: str,
    file_key: str,
    pe_file: Any,
    fcp: dict[str, Any],
    data: list[Any],
    merge_gap: int,
) -> list[tuple[str, Any]] | None:
    file_type = str(getattr(pe_file, "file_type", "") or "")
    bytes_before = sum(len(bytes(value)) for key, value in data if key == "fillFileContent")
    cost_before = data_tuple_cost(data)

    def record(
        status: str,
        reason: str = "",
        *,
        trimmed: list[tuple[str, Any]] | None = None,
        source: str = "",
        size: int | None = None,
    ) -> None:
        bytes_after = bytes_before
        cost_after = cost_before
        if trimmed is not None:
            bytes_after = sum(len(bytes(value)) for key, value in trimmed if key == "fillFileContent")
            cost_after = data_tuple_cost(trimmed)
        report.files.append(FileTrim(
            section=section,
            file=file_key,
            file_type=file_type,
            declared_size=size,
            image_source=source,
            bytes_before=bytes_before,
            bytes_after=bytes_after,
            cost_before=cost_before,
            cost_after=cost_after,
            status=status,
            reason=reason,
        ))

    if bytes_before == 0:
        record("unchanged", "no content")
        return None
    if fcp.get("linkPath") is not None:
        record("skipped", "linked file: the source file owns the content (SAIP V3.4.1 section 8.3.2 linkPath)")
        return None
    if file_type == "BT":
        record("skipped", "BER-TLV: TLVs are concatenated and fillFileOffset is not allowed (SAIP V3.4.1 section 8.3.2)")
        return None
    if file_type not in TRIMMABLE_FILE_TYPES:
        record("skipped", f"file type {file_type or '?'} carries no body")
        return None
    size, window = file_geometry(pe_file)
    if size is None:
        record("skipped", "no declared size")
        return None
    image, source = initial_image(pe_file, size, window)
    if source == "":
        record(
            "skipped",
            "initial content not declared: no fill or repeat pattern and no template default",
            size=size,
        )
        return None
    try:
        trimmed, reason = plan_trim(
            data,
            image=image,
            file_type=file_type,
            rec_len=window if file_type in ("LF", "CY") else 0,
            merge_gap=merge_gap,
        )
    except ValueError as error:
        record("skipped", str(error), source=source, size=size)
        return None
    if trimmed is None:
        record("skipped", reason, source=source, size=size)
        return None
    if data_tuple_cost(trimmed) >= cost_before:
        record("unchanged", "nothing the image already holds", source=source, size=size)
        return None
    record("trim", trimmed=trimmed, source=source, size=size)
    return trimmed


def _trim_template_pe(
    pe: Any,
    section: str,
    decoded: dict[str, Any],
    report: TrimReport,
    *,
    apply: bool,
    merge_gap: int,
) -> bool:
    changed = False
    for pe_name, pe_file in list(pe.files.items()):
        entries = decoded.get(pe_name)
        if not isinstance(entries, list):
            continue
        if any(isinstance(item, tuple) and len(item) == 2 and item[0] == "doNotCreate" for item in entries):
            continue
        data = [item for item in entries if _is_data(item)]
        if len(data) == 0:
            continue
        trimmed = _trim_one(
            report,
            section=section,
            file_key=str(pe_name),
            pe_file=pe_file,
            fcp=_fcp_of(entries, "fileDescriptor"),
            data=data,
            merge_gap=merge_gap,
        )
        if trimmed is None or apply is False:
            continue
        first = next(index for index, item in enumerate(entries) if _is_data(item))
        decoded[pe_name] = (
            entries[:first]
            + list(trimmed)
            + [item for item in entries[first:] if not _is_data(item)]
        )
        changed = True
    return changed


def _trim_gfm(
    section: str,
    decoded: dict[str, Any],
    report: TrimReport,
    *,
    apply: bool,
    merge_gap: int,
) -> bool:
    from pySim.esim.saip import File

    fmc = decoded.get("fileManagementCMD")
    if not isinstance(fmc, list):
        return False
    changed = False
    for transaction_index, transaction in enumerate(fmc):
        if not isinstance(transaction, list):
            continue
        rebuilt: list[Any] = []
        pending: dict[str, Any] | None = None

        def flush() -> None:
            nonlocal changed
            nonlocal pending
            if pending is None:
                return
            head = pending["head"]
            data = pending["data"]
            others = pending["others"]
            replacement = data
            if len(data) > 0:
                file_key = f"fileManagementCMD[{transaction_index}][{pending['index']}]"
                fcp = head[1] if isinstance(head[1], dict) else {}
                try:
                    pe_file = File(file_key, [("fileDescriptor", fcp)] + data)
                except ValueError as error:
                    report.files.append(FileTrim(
                        section=section, file=file_key, file_type="?", declared_size=None,
                        image_source="", bytes_before=0, bytes_after=0,
                        cost_before=data_tuple_cost(data), cost_after=data_tuple_cost(data),
                        status="skipped", reason=f"createFCP carries no usable file descriptor: {error}",
                    ))
                    pe_file = None
                if pe_file is not None:
                    trimmed = _trim_one(
                        report,
                        section=section,
                        file_key=file_key,
                        pe_file=pe_file,
                        fcp=fcp,
                        data=data,
                        merge_gap=merge_gap,
                    )
                    if trimmed is not None and apply:
                        replacement = list(trimmed)
                        changed = True
            rebuilt.append(head)
            rebuilt.extend(replacement)
            rebuilt.extend(others)
            pending = None

        for index, item in enumerate(transaction):
            tagged = isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
            if tagged and item[0] == "createFCP":
                flush()
                pending = {"head": item, "index": index, "data": [], "others": []}
                continue
            if tagged and item[0] == "filePath":
                flush()
                rebuilt.append(item)
                continue
            if pending is not None:
                if _is_data(item):
                    pending["data"].append(item)
                else:
                    pending["others"].append(item)
                continue
            rebuilt.append(item)
        flush()
        if apply and changed:
            transaction[:] = rebuilt
    return changed


def trim_sequence(pes: Any, *, apply: bool = False, merge_gap: int = MERGE_GAP) -> TrimReport:
    """Trim every file of a pySim ``ProfileElementSequence``; mutate only when ``apply``."""
    if merge_gap < 0:
        raise ValueError("merge_gap must be zero or positive.")
    report = TrimReport(applied=bool(apply))
    for pe_index, pe in enumerate(getattr(pes, "pe_list", []) or []):
        pe_type = str(getattr(pe, "type", "") or "")
        decoded = getattr(pe, "decoded", None)
        if not isinstance(decoded, dict):
            continue
        if pe_type == "genericFileManagement":
            changed = _trim_gfm(pe_type, decoded, report, apply=apply, merge_gap=merge_gap)
        elif isinstance(getattr(pe, "files", None), dict):
            changed = _trim_template_pe(pe, pe_type, decoded, report, apply=apply, merge_gap=merge_gap)
        else:
            continue
        if changed:
            report.changed_pe_indexes.append(pe_index)
    return report
