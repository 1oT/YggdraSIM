"""
Semantic, context-aware diff layer over two SAIP profile documents.

This module sits on top of :mod:`saip_diff_engine` (which performs the
raw structural walk) and :mod:`saip_diff_loader` (which normalises any
on-disk shape into a diffable dict). The job here is to turn the
jq-style ``DiffEntry`` stream — paths like
``sections.usim.efImsi.body.imsi`` — into a categorised, severity-tagged
report that reads like an engineer's review note rather than a
patch hunk:

    [critical] identity   USIM.IMSI changed: 234560000000001 -> 234560000000999
    [warning]  pe_seq     PE removed: csim (CDMA NAA)
    [info]     files      EF.ARR (sections.mf.efArr) value changed (28 bytes -> 32 bytes)
    [note]     intro      header line "Issued: 2025-01-12" added

The classifier is purely heuristic — every entry from the structural
diff is matched against a list of patterns that look at the entry path,
the surrounding section name, and (where useful) the before/after
values. Unmatched entries fall into a ``other`` bucket so the operator
still sees them; we just don't pretend to know what they mean.

References:

* SGP.22 §2.5.3 (Profile Element structure)
* ETSI TS 102 221 §13 (file identifiers / SFIs used by EF/DF lookups)
* ETSI TS 102 226 §5 (security attributes referenced)
* GlobalPlatform Card Specification 2.3 §11.1.1 (lifecycle states),
  §6.6 (privileges)
* Tools/ProfilePackage/saip_json_codec.jsonify_document (path shape)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence

from Tools.ProfilePackage.saip_diff_engine import (
    DIFF_OP_ADDED,
    DIFF_OP_CHANGED,
    DIFF_OP_MOVED,
    DIFF_OP_REMOVED,
    DiffEntry,
    DiffSummary,
    diff_saip_documents,
)


# ---------------------------------------------------------------------------
# Public categories + severities. Strings are deliberately stable so
# both the GUI and tests can match them by value.
# ---------------------------------------------------------------------------

CATEGORY_IDENTITY: str = "identity"
CATEGORY_PE_SEQUENCE: str = "pe_sequence"
CATEGORY_FILES: str = "files"
CATEGORY_APPLICATIONS: str = "applications"
CATEGORY_SECURITY: str = "security"
CATEGORY_LIFECYCLE: str = "lifecycle"
CATEGORY_VARIABLES: str = "variables"
CATEGORY_STRUCTURE: str = "structure"
CATEGORY_INTRO: str = "intro"
CATEGORY_OTHER: str = "other"

CATEGORIES: tuple[str, ...] = (
    CATEGORY_IDENTITY,
    CATEGORY_PE_SEQUENCE,
    CATEGORY_FILES,
    CATEGORY_APPLICATIONS,
    CATEGORY_SECURITY,
    CATEGORY_LIFECYCLE,
    CATEGORY_VARIABLES,
    CATEGORY_STRUCTURE,
    CATEGORY_INTRO,
    CATEGORY_OTHER,
)

SEVERITY_CRITICAL: str = "critical"
SEVERITY_WARNING: str = "warning"
SEVERITY_INFO: str = "info"
SEVERITY_NOTE: str = "note"

SEVERITIES: tuple[str, ...] = (
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    SEVERITY_INFO,
    SEVERITY_NOTE,
)

_SEVERITY_RANK: Mapping[str, int] = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_WARNING: 1,
    SEVERITY_INFO: 2,
    SEVERITY_NOTE: 3,
}


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProfileDiffEntry:
    """One semantic diff entry.

    ``path`` is the same jq-style path produced by the structural walker
    so the GUI / TUI can correlate the semantic entry with the raw
    structural one (for "Jump to source" buttons, side-by-side
    rendering, etc.). ``summary`` is a one-line human-readable
    description; ``context`` carries optional metadata used by the
    renderer (PE label, file id, AID, etc.) without forcing every
    consumer to re-classify the path.
    """

    category: str
    severity: str
    op: str
    path: str
    summary: str
    section_key: str = ""
    section_label: str = ""
    before: Any = None
    after: Any = None
    context: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict (used by the GUI dispatcher)."""
        return {
            "category": self.category,
            "severity": self.severity,
            "op": self.op,
            "path": self.path,
            "summary": self.summary,
            "section_key": self.section_key,
            "section_label": self.section_label,
            "before": _safe_jsonable(self.before),
            "after": _safe_jsonable(self.after),
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class ProfileDiffReport:
    """Full semantic-diff report ready for rendering.

    ``structural_summary`` is the raw output from
    :func:`saip_diff_engine.diff_saip_documents` so callers that need
    the unfiltered jq-style entries (e.g. an existing TUI) can keep
    working without re-running the walker.
    """

    label_a: str
    label_b: str
    entries: tuple[ProfileDiffEntry, ...]
    counts_by_category: Mapping[str, int]
    counts_by_severity: Mapping[str, int]
    structural_summary: DiffSummary
    section_reorder_a: tuple[str, ...] = ()
    section_reorder_b: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def is_empty(self) -> bool:
        return self.total == 0

    @property
    def has_critical(self) -> bool:
        return self.counts_by_severity.get(SEVERITY_CRITICAL, 0) > 0

    def filter(
        self,
        *,
        categories: Optional[Iterable[str]] = None,
        severities: Optional[Iterable[str]] = None,
    ) -> tuple[ProfileDiffEntry, ...]:
        """Return entries matching both filters (intersection).

        ``None`` means "no filter on that axis". Convenience for the
        GUI's category and severity chips.
        """
        category_set = None if categories is None else set(categories)
        severity_set = None if severities is None else set(severities)
        result: list[ProfileDiffEntry] = []
        for entry in self.entries:
            if category_set is not None and entry.category not in category_set:
                continue
            if severity_set is not None and entry.severity not in severity_set:
                continue
            result.append(entry)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the whole report (GUI-ready)."""
        return {
            "label_a": self.label_a,
            "label_b": self.label_b,
            "total": self.total,
            "is_empty": self.is_empty,
            "has_critical": self.has_critical,
            "counts_by_category": dict(self.counts_by_category),
            "counts_by_severity": dict(self.counts_by_severity),
            "section_reorder_a": list(self.section_reorder_a),
            "section_reorder_b": list(self.section_reorder_b),
            "entries": [entry.to_dict() for entry in self.entries],
            "structural": {
                "added": self.structural_summary.added,
                "removed": self.structural_summary.removed,
                "changed": self.structural_summary.changed,
                "moved": self.structural_summary.moved,
                "total": self.structural_summary.total,
            },
        }


# ---------------------------------------------------------------------------
# Section-key vocabulary (the PE types we recognise + friendly labels).
# ---------------------------------------------------------------------------
#
# Source of truth: pySim ``ProfileElement.class_for_petype`` plus the
# section keys the SaipToolBridge uses (``build_decoded_document_from_sequence``).
# Unrecognised section names still classify into the right category, we
# just fall back to the section key as the label.

_SECTION_LABELS: Mapping[str, str] = {
    "header": "Profile Header",
    "mf": "MF (Master File)",
    "cd": "CD (Card Data)",
    "telecom": "DF.TELECOM",
    "usim": "USIM Application",
    "opt-usim": "USIM (optional)",
    "isim": "ISIM Application",
    "opt-isim": "ISIM (optional)",
    "csim": "CSIM Application",
    "opt-csim": "CSIM (optional)",
    "umts": "UMTS configuration",
    "phonebook": "DF.PHONEBOOK",
    "gsm-access": "GSM Access",
    "akaParameter": "AKA Parameters",
    "cdmaParameter": "CDMA Parameters",
    "5gNasParameter": "5G NAS Parameters",
    "5gAuthParameter": "5G AKA Parameters",
    "applicationManagement": "Application Management",
    "securityDomain": "Security Domain (ISD-P/SSD)",
    "rfm": "Remote File Management (RFM)",
    "ram": "Remote Application Management (RAM)",
    "genericFileManagement": "Generic File Management (GFM)",
    "eap": "EAP application",
    "df-eap": "DF.EAP",
    "df-5gs": "DF.5GS",
    "df-saip": "DF.SAIP",
    "df-tetra": "DF.TETRA",
    "end": "End of Profile marker",
    "profileHeader": "Profile Header",
}


def _section_label(section_key: str) -> str:
    """Friendly PE label, defaulting to the raw section key."""
    base = re.sub(r"_\d+$", "", str(section_key or ""))
    return _SECTION_LABELS.get(base, base or "(unknown PE)")


# ---------------------------------------------------------------------------
# Path-shape helpers
# ---------------------------------------------------------------------------
#
# Paths from saip_diff_engine look like:
#
#   sections
#   sections.usim
#   sections.usim.efImsi
#   sections.usim.efImsi.body.imsi
#   sections.genericFileManagement[3].file.fileDescriptor
#   __ygg_token_defs__.ICCID
#   intro[0]
#
# We tokenise that into ``("sections", "usim", "efImsi", "body", "imsi")``
# so individual classifiers can match by tuple prefix instead of regex
# every time.


_PATH_SEGMENT_RE = re.compile(r"([^\.\[\]]+)|\[(\d+)\]")


def _path_segments(path: str) -> tuple[str, ...]:
    """Split ``sections.foo[3].bar`` into ``("sections", "foo", "[3]", "bar")``.

    List indices keep their bracket form so callers can distinguish
    ``("foo", "0")`` (a key literally called ``"0"``) from
    ``("foo", "[0]")`` (the first list element).
    """
    if path is None or len(str(path)) == 0:
        return tuple()
    segments: list[str] = []
    for match in _PATH_SEGMENT_RE.finditer(str(path)):
        name, index = match.group(1), match.group(2)
        if name is not None:
            segments.append(name)
        elif index is not None:
            segments.append(f"[{index}]")
    return tuple(segments)


def _section_key_from_path(segments: Sequence[str]) -> str:
    """Return the top-level PE section key, or ``""`` if the path
    isn't ``sections.*``.

    ``sections`` itself (no second segment) means the change is at the
    sequence level — handled separately by the PE-sequence classifier.
    """
    if len(segments) < 2:
        return ""
    if segments[0] != "sections":
        return ""
    return segments[1]


# ---------------------------------------------------------------------------
# Field-aware leaf classifiers.
# ---------------------------------------------------------------------------
#
# Each classifier returns a ``(category, severity, summary)`` triple
# when it matches, else ``None``. The walker tries them in order and
# the first hit wins. Putting identity / security checks early ensures
# they outrank the generic file/PE catch-alls below.

_IDENTITY_LEAF_KEYS: tuple[str, ...] = (
    "iccid",
    "imsi",
    "impi",
    "impu",
    "msisdn",
    "eid",
    "profile_name",
    "profileName",
    "mcc",
    "mnc",
    "mccmnc",
    "mccMnc",
    "mcc_mnc",
    "homeplmn",
    "homePlmn",
    "spn",
)

_SECURITY_LEAF_KEYS: tuple[str, ...] = (
    "ki",
    "k",
    "opc",
    "op",
    "kic",
    "kid",
    "kik",
    "kdf",
    "isdpAid",
    "isdAid",
    "isdAID",
    "kvn",
    "scpKey",
    "scp80Key",
    "scp81Key",
    "scp02Key",
    "scp03Key",
    "scp11Key",
    "puk1",
    "puk2",
    "ppr1",
    "pinAdm",
    "adm",
)

_LIFECYCLE_LEAF_KEYS: tuple[str, ...] = (
    "lifecycle",
    "lifeCycle",
    "lcs",
    "pinStatus",
    "pin1",
    "pin2",
    "pukStatus",
    "lifeCycleStatus",
)


def _leaf_key(segments: Sequence[str]) -> str:
    if len(segments) == 0:
        return ""
    return str(segments[-1])


def _classify_leaf_key(leaf: str) -> Optional[tuple[str, str]]:
    """Map a leaf key to ``(category, severity)`` if it's well-known.

    Identity and security keys are always at least ``warning``; security
    key material rotations are escalated to ``critical`` because they
    invalidate every cached session of an existing card.
    """
    if leaf is None or len(leaf) == 0:
        return None
    leaf_lower = leaf.lower()
    if leaf_lower in {key.lower() for key in _IDENTITY_LEAF_KEYS}:
        return (CATEGORY_IDENTITY, SEVERITY_CRITICAL)
    if leaf_lower in {key.lower() for key in _SECURITY_LEAF_KEYS}:
        return (CATEGORY_SECURITY, SEVERITY_CRITICAL)
    if leaf_lower in {key.lower() for key in _LIFECYCLE_LEAF_KEYS}:
        return (CATEGORY_LIFECYCLE, SEVERITY_WARNING)
    return None


# ---------------------------------------------------------------------------
# Section-aware classifier — looks at the PE type + path tail.
# ---------------------------------------------------------------------------


def _classify_section_path(
    section_key: str,
    segments: Sequence[str],
    *,
    op: str,
    leaf_key: str,
) -> tuple[str, str]:
    """Choose a category + severity based on the PE section the path lives in.

    Order matters: more specific rules go first. The fallback at the
    bottom returns ``(CATEGORY_FILES, SEVERITY_INFO)`` for any path
    inside a known PE we couldn't otherwise classify, since most SAIP
    PEs are file-oriented.
    """
    base_section = re.sub(r"_\d+$", "", str(section_key or ""))

    leaf_hit = _classify_leaf_key(leaf_key)
    if leaf_hit is not None:
        return leaf_hit

    # Application-level changes live under USIM / ISIM / CSIM /
    # applicationManagement. A change to the AID itself is a critical
    # identity rotation; anything else inside an app PE is treated as
    # an application-scope change.
    app_sections = {"usim", "opt-usim", "isim", "opt-isim", "csim", "opt-csim",
                    "applicationManagement", "securityDomain", "rfm", "ram"}
    if base_section in app_sections:
        if leaf_key.lower() in {"aid", "applicationaid", "applicationaid"}:
            return (CATEGORY_APPLICATIONS, SEVERITY_CRITICAL)
        if op in (DIFF_OP_ADDED, DIFF_OP_REMOVED) and len(segments) <= 4:
            return (CATEGORY_APPLICATIONS, SEVERITY_WARNING)
        if "key" in leaf_key.lower() or "kvn" in leaf_key.lower():
            return (CATEGORY_SECURITY, SEVERITY_CRITICAL)
        return (CATEGORY_FILES, SEVERITY_INFO)

    if base_section in {"genericFileManagement", "telecom", "phonebook",
                        "df-eap", "df-5gs", "df-saip", "df-tetra", "mf", "cd"}:
        if op in (DIFF_OP_ADDED, DIFF_OP_REMOVED):
            # Top-level file added or removed within a file-management PE
            # is louder than a content tweak — bump to warning.
            if len(segments) <= 4:
                return (CATEGORY_FILES, SEVERITY_WARNING)
        return (CATEGORY_FILES, SEVERITY_INFO)

    if base_section in {"akaParameter", "cdmaParameter",
                        "5gAuthParameter", "5gNasParameter"}:
        # Auth parameter PEs almost always mean Ki/OPc territory, even
        # when the leaf name doesn't match the security keyword list
        # (e.g. {"sqn": "..."}).
        return (CATEGORY_SECURITY, SEVERITY_CRITICAL)

    if base_section == "header" or base_section == "profileHeader":
        # The profile header carries identity + lifecycle. Default to
        # identity since that's the more common reason to compare.
        return (CATEGORY_IDENTITY, SEVERITY_WARNING)

    if base_section == "end":
        return (CATEGORY_STRUCTURE, SEVERITY_NOTE)

    # Unknown PE section — still surface, just with a low signal.
    return (CATEGORY_OTHER, SEVERITY_INFO)


# ---------------------------------------------------------------------------
# Top-level (non-section) path classifier.
# ---------------------------------------------------------------------------


def _classify_top_level_path(
    segments: Sequence[str],
    *,
    op: str,
) -> Optional[tuple[str, str, str]]:
    """Classify paths that don't live under ``sections.*``.

    Returns ``(category, severity, summary_hint)`` or ``None`` when the
    path is unrecognised (caller falls back to the section walker).
    """
    if len(segments) == 0:
        return None
    head = segments[0]
    if head == "intro":
        return (CATEGORY_INTRO, SEVERITY_NOTE, "Intro line")
    if head in {"__ygg_token_defs__", "__ygg_placeholder_style__"}:
        return (CATEGORY_VARIABLES, SEVERITY_INFO, "Placeholder definition")
    if head == "sections" and len(segments) == 1:
        return (CATEGORY_PE_SEQUENCE, SEVERITY_WARNING, "Profile element sequence")
    if head == "sections" and len(segments) == 2:
        # sections.<name> — the entire PE was added or removed.
        return (CATEGORY_PE_SEQUENCE, SEVERITY_WARNING, "Profile element")
    return None


# ---------------------------------------------------------------------------
# Value rendering — keeps long hex / large dicts readable in summaries.
# ---------------------------------------------------------------------------


def _abbreviate_value(value: Any, *, limit: int = 48) -> str:
    if value is None:
        return "(absent)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        text = value.hex().upper()
        if len(text) > limit:
            return f"{text[: limit - 3]}... ({len(value)} bytes)"
        return text
    if isinstance(value, dict):
        return f"{{{len(value)} keys}}"
    if isinstance(value, (list, tuple)):
        return f"[{len(value)} items]"
    text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _safe_jsonable(value: Any) -> Any:
    """Convert a Python object into something json.dumps will accept.

    Primitives pass through; ``bytes`` becomes hex; ``set`` / ``tuple``
    become lists; nested mappings/sequences recurse. Used by
    :meth:`ProfileDiffEntry.to_dict` so the GUI can transmit the
    payload without a custom encoder.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return {"__hex__": value.hex().upper(), "length": len(value)}
    if isinstance(value, (list, tuple, set)):
        return [_safe_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _safe_jsonable(v) for k, v in value.items()}
    return repr(value)


def _format_summary(
    *,
    category: str,
    op: str,
    section_label: str,
    leaf_key: str,
    path: str,
    before: Any,
    after: Any,
    summary_hint: str = "",
) -> str:
    """Build a one-line human-readable description.

    The summary is intentionally compact — long hex values are
    abbreviated, lists / dicts collapse to ``"[N items]"`` /
    ``"{N keys}"``. The exact wording is shaped by the op so the GUI
    doesn't need to special-case its display.
    """
    location = section_label or summary_hint or "(top-level)"
    leaf = leaf_key or path or "value"

    if op == DIFF_OP_ADDED:
        return f"{location}: added {leaf} = {_abbreviate_value(after)}"
    if op == DIFF_OP_REMOVED:
        return f"{location}: removed {leaf} (was {_abbreviate_value(before)})"
    if op == DIFF_OP_MOVED:
        return f"{location}: reordered {leaf}"
    # changed (default)
    return (
        f"{location}: {leaf} changed: "
        f"{_abbreviate_value(before)} -> {_abbreviate_value(after)}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_diff_entry(entry: DiffEntry) -> ProfileDiffEntry:
    """Map one structural :class:`DiffEntry` to a semantic
    :class:`ProfileDiffEntry`.

    Pure function; the caller can re-classify a single entry if it
    wants to evolve the rules without re-running the structural
    walker.
    """
    segments = _path_segments(entry.path)
    section_key = _section_key_from_path(segments)
    section_label = _section_label(section_key) if len(section_key) > 0 else ""
    leaf = _leaf_key(segments) if len(segments) > 0 else ""

    # 1. Top-level paths (intro, variables, PE sequence) take priority.
    top_hit = _classify_top_level_path(segments, op=entry.op)
    if top_hit is not None:
        category, severity, hint = top_hit
        # PE-sequence add/remove lifts to "warning" / "critical" because
        # losing a whole PE is structurally significant.
        if category == CATEGORY_PE_SEQUENCE and entry.op == DIFF_OP_REMOVED:
            severity = SEVERITY_CRITICAL
        # If we landed on PE-sequence with len==2, derive a friendly
        # section label from segments[1] so the summary reads sensibly.
        if category == CATEGORY_PE_SEQUENCE and len(segments) >= 2:
            section_key = segments[1]
            section_label = _section_label(section_key)
        summary = _format_summary(
            category=category,
            op=entry.op,
            section_label=section_label or hint,
            leaf_key="" if category == CATEGORY_PE_SEQUENCE else leaf,
            path=entry.path,
            before=entry.value_a,
            after=entry.value_b,
            summary_hint=hint,
        )
        return ProfileDiffEntry(
            category=category,
            severity=severity,
            op=entry.op,
            path=entry.path,
            summary=summary,
            section_key=section_key,
            section_label=section_label,
            before=entry.value_a,
            after=entry.value_b,
            context={"hint": hint},
        )

    # 2. Section-relative classification.
    if len(section_key) > 0:
        category, severity = _classify_section_path(
            section_key,
            segments,
            op=entry.op,
            leaf_key=leaf,
        )
        summary = _format_summary(
            category=category,
            op=entry.op,
            section_label=section_label,
            leaf_key=leaf,
            path=entry.path,
            before=entry.value_a,
            after=entry.value_b,
        )
        return ProfileDiffEntry(
            category=category,
            severity=severity,
            op=entry.op,
            path=entry.path,
            summary=summary,
            section_key=section_key,
            section_label=section_label,
            before=entry.value_a,
            after=entry.value_b,
            context={},
        )

    # 3. Otherwise — it's an unknown root-level key, log it but with
    # low severity so we don't drown the operator in noise.
    summary = _format_summary(
        category=CATEGORY_OTHER,
        op=entry.op,
        section_label="",
        leaf_key=leaf,
        path=entry.path,
        before=entry.value_a,
        after=entry.value_b,
    )
    return ProfileDiffEntry(
        category=CATEGORY_OTHER,
        severity=SEVERITY_INFO,
        op=entry.op,
        path=entry.path,
        summary=summary,
        section_key="",
        section_label="",
        before=entry.value_a,
        after=entry.value_b,
        context={},
    )


def compute_profile_diff(
    document_a: dict[str, Any],
    document_b: dict[str, Any],
    *,
    label_a: str = "left",
    label_b: str = "right",
) -> ProfileDiffReport:
    """Compute a context-aware diff between two SAIP documents.

    Both inputs must be in the jsonified shape produced by
    :func:`saip_json_codec.jsonify_document` (or normalised to that
    shape via :mod:`saip_diff_loader`). Mixing shapes is a caller
    error; the structural walker will still run but every value would
    flag as changed. The returned :class:`ProfileDiffReport` carries
    the underlying :class:`DiffSummary` so callers that want the raw
    structural entries don't need to re-run the walker.

    ``label_a`` / ``label_b`` are stored verbatim on the report so
    renderers can show them without re-deriving the source path.
    """
    if isinstance(document_a, dict) is False:
        raise TypeError("document_a must be a dict (jsonified SAIP document).")
    if isinstance(document_b, dict) is False:
        raise TypeError("document_b must be a dict (jsonified SAIP document).")

    structural = diff_saip_documents(document_a, document_b)

    # Pull out section ordering so the renderer can show "sections
    # reordered: A=[mf, usim, isim] -> B=[mf, isim, usim]" prominently
    # even when the underlying mappings have identical keys.
    sections_a = document_a.get("sections")
    sections_b = document_b.get("sections")
    section_order_a: tuple[str, ...] = tuple()
    section_order_b: tuple[str, ...] = tuple()
    if isinstance(sections_a, dict):
        section_order_a = tuple(str(key) for key in sections_a.keys())
    if isinstance(sections_b, dict):
        section_order_b = tuple(str(key) for key in sections_b.keys())

    classified: list[ProfileDiffEntry] = []
    for entry in structural.entries:
        classified.append(classify_diff_entry(entry))

    classified.sort(key=_sort_key)
    classified_tuple = tuple(classified)

    counts_by_category: dict[str, int] = {category: 0 for category in CATEGORIES}
    counts_by_severity: dict[str, int] = {severity: 0 for severity in SEVERITIES}
    for item in classified_tuple:
        counts_by_category[item.category] = counts_by_category.get(item.category, 0) + 1
        counts_by_severity[item.severity] = counts_by_severity.get(item.severity, 0) + 1

    return ProfileDiffReport(
        label_a=str(label_a),
        label_b=str(label_b),
        entries=classified_tuple,
        counts_by_category=counts_by_category,
        counts_by_severity=counts_by_severity,
        structural_summary=structural,
        section_reorder_a=section_order_a if section_order_a != section_order_b else tuple(),
        section_reorder_b=section_order_b if section_order_a != section_order_b else tuple(),
    )


def _sort_key(entry: ProfileDiffEntry) -> tuple[Any, ...]:
    """Sort by severity (critical first), then category, then path.

    A stable sort means two diffs of the same documents always render
    in the same order — handy for golden-file comparisons in CI.
    """
    return (
        _SEVERITY_RANK.get(entry.severity, 99),
        entry.category,
        entry.path,
        entry.op,
    )


# ---------------------------------------------------------------------------
# Plain-text renderer (used by the CLI / tests; the GUI consumes the dict).
# ---------------------------------------------------------------------------


_OP_GLYPHS: Mapping[str, str] = {
    DIFF_OP_ADDED: "+",
    DIFF_OP_REMOVED: "-",
    DIFF_OP_CHANGED: "~",
    DIFF_OP_MOVED: ">",
}


def format_profile_diff_text(
    report: ProfileDiffReport,
    *,
    show_paths: bool = True,
) -> str:
    """Render a semantic diff report as a plain-text block.

    The output groups by severity (critical → note) and prints one
    entry per line with op glyph, category tag, and the human-readable
    summary. ``show_paths`` appends the structural jq path so a reader
    can correlate the line back to the raw walker.
    """
    if report.is_empty:
        return f"(no semantic differences between {report.label_a!r} and {report.label_b!r})\n"

    lines: list[str] = []
    lines.append(
        f"=== SAIP profile diff ===  {report.label_a!r}  ->  {report.label_b!r}"
    )
    lines.append(
        "Severity: "
        + " ".join(
            f"{severity}={report.counts_by_severity.get(severity, 0)}"
            for severity in SEVERITIES
        )
    )
    lines.append(
        "Category: "
        + " ".join(
            f"{category}={report.counts_by_category.get(category, 0)}"
            for category in CATEGORIES
            if report.counts_by_category.get(category, 0) > 0
        )
    )
    if len(report.section_reorder_a) > 0 or len(report.section_reorder_b) > 0:
        lines.append(
            f"Section order changed:\n  A = {list(report.section_reorder_a)}"
            f"\n  B = {list(report.section_reorder_b)}"
        )

    for entry in report.entries:
        glyph = _OP_GLYPHS.get(entry.op, "?")
        suffix = ""
        if show_paths is True and len(entry.path) > 0:
            suffix = f"    [{entry.path}]"
        lines.append(
            f"[{entry.severity:8}] {entry.category:12} {glyph} {entry.summary}{suffix}"
        )
    return "\n".join(lines) + "\n"
