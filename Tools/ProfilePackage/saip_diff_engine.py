# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Pure-function diff over two SAIP profile documents.

The engine consumes the **jsonified** form produced by
``Tools.ProfilePackage.saip_json_codec.jsonify_document`` (or any equivalent
dict that uses strings / lists / dicts only). It emits a flat list of
``DiffEntry`` records tagged with the jq-style dotted path, an operation
code (``added`` / ``removed`` / ``changed`` / ``moved``), and the raw
left/right payloads so a caller can render them however it wants
(terminal, Textual widget, HTML report).

Design goals:

* No I/O and no external dependencies; safe to call from the TUI thread.
* Stable ordering: entries are emitted in a depth-first, key-sorted
  walk so two diff runs on the same inputs produce byte-identical
  reports (critical for CI comparisons).
* The walker never materialises a full list of paths in memory — it
  yields ``DiffEntry`` on demand so TB-sized profile packages (very
  unlikely, but the codebase already uses streaming discipline) do not
  blow up the heap.
* Hex-heavy leaf values are preserved untouched. The engine does not
  try to pretty-print certs or BCD digits; that is the job of the
  renderer.

References: SGP.22 §2.5.3 (Profile Element structure), the jsonified
shape in ``saip_json_codec``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence


DIFF_OP_ADDED: str = "added"
DIFF_OP_REMOVED: str = "removed"
DIFF_OP_CHANGED: str = "changed"
DIFF_OP_MOVED: str = "moved"


@dataclass(frozen=True)
class DiffEntry:
    """One atomic change between document ``a`` and document ``b``.

    ``path`` is the dotted jq-style path into the jsonified tree, with
    list indices rendered as ``[n]`` segments (e.g.
    ``sections.genericFileManagement[3].file.fileDescriptor``). The
    caller should treat ``path`` as a display token — it is NOT a valid
    Python or JSONPath expression, just a stable identifier.
    """

    path: str
    op: str
    value_a: Any = None
    value_b: Any = None


@dataclass(frozen=True)
class DiffSummary:
    """Aggregate counts + ordered detail list for a whole document diff."""

    added: int = 0
    removed: int = 0
    changed: int = 0
    moved: int = 0
    entries: tuple[DiffEntry, ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        """Sum of all change-type counters."""
        return self.added + self.removed + self.changed + self.moved

    @property
    def is_empty(self) -> bool:
        """``True`` when no differences were found."""
        return self.total == 0


_PATH_SEPARATOR: str = "."


def _join_path(parent: str, child: str | int) -> str:
    if isinstance(child, int) is True:
        return f"{parent}[{int(child)}]"
    child_text = str(child)
    if len(parent) == 0:
        return child_text
    return f"{parent}{_PATH_SEPARATOR}{child_text}"


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _is_sequence(value: Any) -> bool:
    if isinstance(value, (str, bytes, bytearray)) is True:
        return False
    return isinstance(value, (list, tuple))


def _values_equal(left: Any, right: Any) -> bool:
    """Structural equality that tolerates list-vs-tuple."""
    if _is_sequence(left) is True and _is_sequence(right) is True:
        if len(left) != len(right):
            return False
        for index in range(len(left)):
            if _values_equal(left[index], right[index]) is False:
                return False
        return True
    if _is_mapping(left) is True and _is_mapping(right) is True:
        if set(left.keys()) != set(right.keys()):
            return False
        for key in left.keys():
            if _values_equal(left[key], right[key]) is False:
                return False
        return True
    return left == right


def _walk_mapping(
    path: str,
    left: dict[Any, Any],
    right: dict[Any, Any],
) -> Iterator[DiffEntry]:
    left_keys = list(left.keys())
    right_keys = list(right.keys())
    all_keys: list[Any] = []
    seen: set[Any] = set()
    for key in left_keys:
        if key in seen:
            continue
        seen.add(key)
        all_keys.append(key)
    for key in right_keys:
        if key in seen:
            continue
        seen.add(key)
        all_keys.append(key)
    all_keys.sort(key=lambda item: str(item))

    for key in all_keys:
        key_path = _join_path(path, str(key))
        if key not in left:
            yield DiffEntry(path=key_path, op=DIFF_OP_ADDED, value_a=None, value_b=right[key])
            continue
        if key not in right:
            yield DiffEntry(path=key_path, op=DIFF_OP_REMOVED, value_a=left[key], value_b=None)
            continue
        yield from _walk(key_path, left[key], right[key])


def _walk_sequence(
    path: str,
    left: Sequence[Any],
    right: Sequence[Any],
) -> Iterator[DiffEntry]:
    common_length = min(len(left), len(right))
    for index in range(common_length):
        yield from _walk(_join_path(path, index), left[index], right[index])
    for index in range(common_length, len(left)):
        yield DiffEntry(
            path=_join_path(path, index),
            op=DIFF_OP_REMOVED,
            value_a=left[index],
            value_b=None,
        )
    for index in range(common_length, len(right)):
        yield DiffEntry(
            path=_join_path(path, index),
            op=DIFF_OP_ADDED,
            value_a=None,
            value_b=right[index],
        )


def _walk(path: str, left: Any, right: Any) -> Iterator[DiffEntry]:
    if _is_mapping(left) is True and _is_mapping(right) is True:
        yield from _walk_mapping(path, left, right)
        return
    if _is_sequence(left) is True and _is_sequence(right) is True:
        yield from _walk_sequence(path, left, right)
        return
    if _values_equal(left, right) is True:
        return
    yield DiffEntry(path=path, op=DIFF_OP_CHANGED, value_a=left, value_b=right)


def _order_entries(entries: Iterable[DiffEntry]) -> tuple[DiffEntry, ...]:
    ordered = list(entries)
    ordered.sort(key=lambda entry: (entry.path, entry.op))
    return tuple(ordered)


def diff_documents(
    document_a: dict[str, Any],
    document_b: dict[str, Any],
    *,
    root_label: str = "",
) -> DiffSummary:
    """Compare two jsonified SAIP documents.

    The caller is responsible for feeding in the **same** shape — e.g.
    both sides jsonified, or both sides raw ``{"intro": [...], "sections": {...}}``
    dicts. Mixing shapes is a caller error and the result will flag
    every node as changed.

    ``root_label`` prepends a prefix to every diff path. Use it to tag
    entries with a short descriptor like ``"profileA"`` when the
    renderer wants to disambiguate multiple diff runs in the same view.
    """
    if _is_mapping(document_a) is False:
        raise TypeError("document_a must be a dict")
    if _is_mapping(document_b) is False:
        raise TypeError("document_b must be a dict")

    entries_iter = _walk(str(root_label or ""), document_a, document_b)
    entries = _order_entries(entries_iter)
    added = sum(1 for entry in entries if entry.op == DIFF_OP_ADDED)
    removed = sum(1 for entry in entries if entry.op == DIFF_OP_REMOVED)
    changed = sum(1 for entry in entries if entry.op == DIFF_OP_CHANGED)
    moved = sum(1 for entry in entries if entry.op == DIFF_OP_MOVED)
    return DiffSummary(
        added=added,
        removed=removed,
        changed=changed,
        moved=moved,
        entries=entries,
    )


_SECTION_ORDER_META_KEY: str = "__section_order__"


def detect_section_reorder(
    document_a: dict[str, Any],
    document_b: dict[str, Any],
) -> DiffEntry | None:
    """Flag an overall reordering of the top-level ``sections`` map.

    The core ``diff_documents`` walker treats mappings as unordered, so a
    profile whose SAIP sections were merely reshuffled would produce no
    entries. Many EUM failures are actually *ordering* bugs (BF36 vs
    BF37 swapped, NAA before MF, etc.), so we emit a single synthetic
    entry that the renderer can surface prominently.
    """
    sections_a = document_a.get("sections", {})
    sections_b = document_b.get("sections", {})
    if _is_mapping(sections_a) is False or _is_mapping(sections_b) is False:
        return None
    order_a = list(sections_a.keys())
    order_b = list(sections_b.keys())
    if order_a == order_b:
        return None
    common = [key for key in order_a if key in sections_b]
    common_b = [key for key in order_b if key in sections_a]
    if common == common_b:
        return None
    return DiffEntry(
        path="sections",
        op=DIFF_OP_MOVED,
        value_a=tuple(order_a),
        value_b=tuple(order_b),
    )


def diff_saip_documents(
    document_a: dict[str, Any],
    document_b: dict[str, Any],
) -> DiffSummary:
    """High-level entry point that layers section-reorder detection on
    top of the structural walk.

    Callers that want a raw structural diff (no reorder heuristics)
    should call :func:`diff_documents` directly.
    """
    base_summary = diff_documents(document_a, document_b)
    reorder_entry = detect_section_reorder(document_a, document_b)
    if reorder_entry is None:
        return base_summary
    merged_entries = _order_entries(tuple(base_summary.entries) + (reorder_entry,))
    return DiffSummary(
        added=base_summary.added,
        removed=base_summary.removed,
        changed=base_summary.changed,
        moved=base_summary.moved + 1,
        entries=merged_entries,
    )


def _render_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool) is True:
        return "true" if value else "false"
    if isinstance(value, (int, float)) is True:
        return str(value)
    if isinstance(value, (list, tuple)) is True:
        return f"[{len(value)} items]"
    if isinstance(value, dict) is True:
        return f"{{{len(value)} keys}}"
    text = str(value)
    if len(text) > 72:
        return text[:69] + "..."
    return text


def format_diff_text(summary: DiffSummary, *, show_values: bool = True) -> str:
    """Render a diff as a terminal-friendly plain-text report.

    The format is intentionally grep-able: each line starts with the op
    tag (``+`` / ``-`` / ``~`` / ``>``) followed by the path and, if
    ``show_values`` is on, the truncated value payloads. Callers that
    want richer formatting (colors, tree layout) should consume the
    ``DiffEntry`` list directly.
    """
    if summary.is_empty:
        return "(no differences)\n"
    lines: list[str] = []
    lines.append(
        f"# added={summary.added} removed={summary.removed} "
        f"changed={summary.changed} moved={summary.moved} total={summary.total}"
    )
    for entry in summary.entries:
        tag = {
            DIFF_OP_ADDED: "+",
            DIFF_OP_REMOVED: "-",
            DIFF_OP_CHANGED: "~",
            DIFF_OP_MOVED: ">",
        }.get(entry.op, "?")
        if show_values is False:
            lines.append(f"{tag} {entry.path}")
            continue
        if entry.op == DIFF_OP_ADDED:
            lines.append(f"{tag} {entry.path}  ->  {_render_scalar(entry.value_b)}")
        elif entry.op == DIFF_OP_REMOVED:
            lines.append(f"{tag} {entry.path}  ->  {_render_scalar(entry.value_a)}")
        elif entry.op == DIFF_OP_CHANGED:
            lines.append(
                f"{tag} {entry.path}  :: {_render_scalar(entry.value_a)} "
                f"=> {_render_scalar(entry.value_b)}"
            )
        else:
            lines.append(
                f"{tag} {entry.path}  :: {_render_scalar(entry.value_a)} "
                f"=> {_render_scalar(entry.value_b)}"
            )
    return "\n".join(lines) + "\n"
