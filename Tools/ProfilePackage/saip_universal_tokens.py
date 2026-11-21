# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Universal placeholder test values.

A universal token list maps a placeholder literal -- in any of the
template spellings, ``{iccid:ICCID:10:nibble_swap}``,
``[iccidICCID10NibbleSwap]`` or the bare body ``iccidICCID10NibbleSwap``
-- to the bytes that stand in for it while a template is still being
authored. One operator-wide list answers every template, so test profiles
can be built before a template is signed off, and the values are updated
in one place. A template can bind a second list of the same format on top
of it: a *profile-specific* list from the per-user library
(:func:`token_lists_dir`) or any file, whose entries take precedence over
the universal ones. Resolution per occurrence is typed value, then the
bound list, then the universal list (:func:`layered_universal_match`).

The lists are per-user files outside the repository (see
:func:`universal_tokens_path`) and are never tracked. Their format is one
``name,hex`` pair per line; ``#`` and ``;`` start a comment, blank lines
are ignored, and a leading ``name,value`` header is accepted. The value is
the encoded wire form (an ICCID already nibble-swapped, an MSISDN already
padded, TEXT as UTF-8 bytes), so a placeholder is satisfied by splicing
the bytes verbatim, and the width the name declares must equal the byte
count. An entry that fails either check is reported and never applied.

Every list has a *style*, the spelling its names are written in
(:func:`token_list_style`): a ``# style: typed`` directive declares it,
otherwise the first placeholder entry decides, and an empty list is
typed. The style only governs what the writers put on a new line;
matching is spelling-independent (``placeholder_key_fold``), so a typed
list answers a bracket-style template and the other way round.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from yggdrasim_common.secure_files import (
    atomic_write_bytes,
    ensure_private_directory,
    read_bounded_regular_file,
)

from .saip_hex_template import (
    DEFAULT_PLACEHOLDER_STYLE,
    PLACEHOLDER_STYLES,
    InlinePlaceholderRecord,
    format_placeholder_literal,
    parse_placeholder_literal,
    placeholder_key_fold,
    placeholder_key_fold_relaxed,
    placeholder_literal_style,
    strip_placeholder_delimiters,
)
from .saip_variable_materialization import (
    SaipVariableMaterializationError,
    decode_inline_placeholder_value,
    encode_inline_placeholder_value,
    inline_record_key,
    validate_inline_raw_value,
)

UNIVERSAL_TOKENS_ENV = "YGGDRASIM_SAIP_UNIVERSAL_TOKENS"
UNIVERSAL_TOKENS_FILE_NAME = "saip_universal_tokens.csv"
TOKEN_LISTS_DIR_ENV = "YGGDRASIM_SAIP_TOKEN_LISTS"
TOKEN_LISTS_DIR_NAME = "saip_token_lists"
TOKEN_LIST_SUFFIX = ".csv"
UNIVERSAL_LIST_SELECTOR = "universal"
_USER_DIR_NAME = ".yggdrasim"
_LIST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_LIST_BYTES = 4 * 1024 * 1024
_COMMENT_PREFIXES = ("#", ";")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAMES = frozenset({"name", "token", "placeholder", "literal"})
_HEADER_VALUES = frozenset({"value", "hex", "bytes"})
_STYLE_DIRECTIVE_RE = re.compile(
    r"^[#;]\s*style\s*[:=]\s*(?P<style>[A-Za-z_-]*)\s*$", re.IGNORECASE
)

STYLE_SOURCE_DIRECTIVE = "directive"
STYLE_SOURCE_ENTRIES = "entries"
STYLE_SOURCE_DEFAULT = "default"

PROBLEM_SYNTAX = "syntax"
PROBLEM_VALUE = "value"


class UniversalTokensError(ValueError):
    """Raised when the universal list cannot be read or written."""


@dataclass(frozen=True)
class UniversalTokenEntry:
    """One usable ``name,hex`` line.

    ``name`` is the spelling on the line; ``key`` the compact body (or the
    bare token name) and ``fold`` the spelling-independent comparison key.
    Both are derived from ``name`` when not given.
    """

    name: str
    hex: str
    line: int
    declared_bytes: int | None
    key: str = ""
    fold: str = ""

    def __post_init__(self) -> None:
        if not self.key:
            parsed = _parse_list_name(self.name)
            object.__setattr__(
                self,
                "key",
                parsed[0] if parsed is not None else strip_placeholder_delimiters(self.name),
            )
        if not self.fold:
            object.__setattr__(self, "fold", placeholder_key_fold(self.name))

    @property
    def byte_length(self) -> int:
        return len(self.hex) // 2

    @property
    def declared_only(self) -> bool:
        """``name,`` with no value: listed, answering nothing."""
        return self.hex == ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "key": self.key,
            "hex": self.hex,
            "line": self.line,
            "byte_length": self.byte_length,
            "declared_bytes": self.declared_bytes,
            "declared_only": self.declared_only,
        }


@dataclass(frozen=True)
class UniversalTokenProblem:
    """One line the loader will not apply, and why."""

    line: int
    name: str
    reason: str
    kind: str = PROBLEM_VALUE

    def to_wire(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "name": self.name,
            "reason": self.reason,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class UniversalTokenList:
    """A parsed universal list: usable entries plus the lines that were not."""

    path: Path | None
    loaded: bool
    text: str
    entries: tuple[UniversalTokenEntry, ...]
    problems: tuple[UniversalTokenProblem, ...]
    style: str = DEFAULT_PLACEHOLDER_STYLE
    style_source: str = STYLE_SOURCE_DEFAULT

    @property
    def style_declared(self) -> bool:
        return self.style_source == STYLE_SOURCE_DIRECTIVE

    def lookup(self, key: str) -> UniversalTokenEntry | None:
        """Return the entry for a literal in any spelling.

        Exact name or compact key first, then case-insensitive, then the
        spelling-independent fold (``{iccid:ICCID:10:nibble_swap}`` answers
        ``[iccidICCID10NibbleSwap]``), and last the fold with underscores
        dropped from the variable (``{scp80_kic1:BINARY:16}`` answers
        ``[scp80kic1BINARY16]``); an exact entry always wins over a looser
        one.
        """

        wanted = str(key or "").strip()
        if not wanted:
            return None
        for entry in self.entries:
            if wanted in (entry.name, entry.key):
                return entry
        folded = wanted.casefold()
        bare = strip_placeholder_delimiters(wanted).casefold()
        for entry in self.entries:
            if folded == entry.name.casefold() or bare == entry.key.casefold():
                return entry
        fold = placeholder_key_fold(wanted)
        for entry in self.entries:
            if entry.fold == fold:
                return entry
        relaxed = placeholder_key_fold_relaxed(wanted)
        if relaxed:
            for entry in self.entries:
                if placeholder_key_fold_relaxed(entry.key) == relaxed:
                    return entry
        return None

    def entries_for_variable(self, variable: Any) -> list[UniversalTokenEntry]:
        """Return the entries that name ``variable``, in any spelling, in list order.

        The last rung of a match: a plain ``PUK1`` token line, or a typed
        entry with another type, width or modifier, names the same variable
        as ``{puk1:TEXT:8:utf_8}``; underscores in the variable are ignored.
        """
        wanted = _variable_fold(variable)
        if not wanted:
            return []
        return [entry for entry in self.entries if _variable_fold(entry.name) == wanted]

    def problems_for(self, key: str) -> list[UniversalTokenProblem]:
        """Return the rejected lines naming ``key`` in any spelling, or its variable."""
        wanted = str(key or "").strip()
        variable = _variable_fold(wanted)
        return [
            problem
            for problem in self.problems
            if _names_match(problem.name, wanted)
            or (bool(variable) and _variable_fold(problem.name) == variable)
        ]

    def names(self) -> list[str]:
        return [entry.name for entry in self.entries]

    def to_wire(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path is not None else "",
            "loaded": self.loaded,
            "style": self.style,
            "style_source": self.style_source,
            "style_declared": self.style_declared,
            "entry_count": len(self.entries),
            "problem_count": len(self.problems),
            "entries": [entry.to_wire() for entry in self.entries],
            "problems": [problem.to_wire() for problem in self.problems],
        }


def universal_tokens_path(environ: Mapping[str, str] | None = None) -> Path:
    """Return the list's location: the env override, else ``~/.yggdrasim/``.

    The default sits beside ``env_overrides.json`` in the per-user directory,
    outside every checkout, so the list is shared by all templates on the
    machine and never enters a repository.
    """

    env = os.environ if environ is None else environ
    override = str(env.get(UNIVERSAL_TOKENS_ENV, "") or "").strip()
    if override:
        return Path(os.path.expanduser(override))
    return Path(os.path.expanduser("~")) / _USER_DIR_NAME / UNIVERSAL_TOKENS_FILE_NAME


def token_lists_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Return the library directory: the env override, else ``~/.yggdrasim/saip_token_lists``.

    A profile-specific list is one ``<name>.csv`` in this directory, in the
    universal list's format; the universal list itself stays at
    :func:`universal_tokens_path`.
    """

    env = os.environ if environ is None else environ
    override = str(env.get(TOKEN_LISTS_DIR_ENV, "") or "").strip()
    if override:
        return Path(os.path.expanduser(override))
    return Path(os.path.expanduser("~")) / _USER_DIR_NAME / TOKEN_LISTS_DIR_NAME


def normalise_list_name(name: Any) -> str:
    """Return a valid library name or raise; ``universal`` is reserved."""

    text = str(name or "").strip()
    if text.casefold().endswith(TOKEN_LIST_SUFFIX):
        text = text[: -len(TOKEN_LIST_SUFFIX)]
    if not text:
        raise UniversalTokensError("A token list name is required.")
    if _LIST_NAME_RE.match(text) is None:
        raise UniversalTokensError(
            f"Token list name {text!r} must be letters, digits, '.', '_' or '-' "
            "(64 characters at most) and start with a letter or digit."
        )
    if text.casefold() == UNIVERSAL_LIST_SELECTOR:
        raise UniversalTokensError(
            "'universal' names the operator-wide list; choose another name."
        )
    return text


def _looks_like_path(text: str) -> bool:
    return (
        "/" in text
        or "\\" in text
        or text.startswith(("~", "."))
        or text.casefold().endswith(TOKEN_LIST_SUFFIX)
    )


@dataclass(frozen=True)
class TokenListRef:
    """One test-value list: the universal one, a library entry, or a file.

    ``selector`` is the canonical text a binding stores: ``universal``, the
    library name, or the file's path. It is what the sidecar, the session
    and the shell verbs exchange.
    """

    selector: str
    kind: str
    path: Path

    @property
    def is_universal(self) -> bool:
        return self.kind == UNIVERSAL_LIST_SELECTOR

    @property
    def name(self) -> str:
        if self.is_universal:
            return "Universal"
        if self.kind == "library":
            return self.selector
        return self.path.name

    def to_wire(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "kind": self.kind,
            "name": self.name,
            "path": str(self.path),
            "exists": self.path.is_file(),
        }


def resolve_token_list_ref(
    selector: Any,
    environ: Mapping[str, str] | None = None,
) -> TokenListRef:
    """Turn a selector into a list reference.

    An empty selector or ``universal`` is the universal list. Text with a
    path separator, a leading ``~`` or ``.``, or a ``.csv`` suffix is a
    file path; anything else is a library name and must be valid.
    """

    text = str(selector or "").strip()
    if not text or text.casefold() == UNIVERSAL_LIST_SELECTOR:
        return TokenListRef(
            UNIVERSAL_LIST_SELECTOR, UNIVERSAL_LIST_SELECTOR, universal_tokens_path(environ)
        )
    if _looks_like_path(text):
        target = Path(os.path.expanduser(text))
        return TokenListRef(str(target), "path", target)
    name = normalise_list_name(text)
    return TokenListRef(name, "library", token_lists_dir(environ) / f"{name}{TOKEN_LIST_SUFFIX}")


def library_token_lists(environ: Mapping[str, str] | None = None) -> list[TokenListRef]:
    """Return the library's lists, sorted by name; a missing directory is empty."""

    directory = token_lists_dir(environ)
    if not directory.is_dir():
        return []
    refs: list[TokenListRef] = []
    for candidate in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
        if not candidate.is_file() or candidate.suffix.casefold() != TOKEN_LIST_SUFFIX:
            continue
        if _LIST_NAME_RE.match(candidate.stem) is None:
            continue
        if candidate.stem.casefold() == UNIVERSAL_LIST_SELECTOR:
            continue
        refs.append(TokenListRef(candidate.stem, "library", candidate))
    return refs


def token_list_catalogue(
    environ: Mapping[str, str] | None = None,
    *,
    extra: Iterable[TokenListRef] = (),
    with_counts: bool = False,
) -> list[dict[str, Any]]:
    """Describe the universal list and the library, plus ``extra`` refs.

    ``with_counts`` loads every list to report its usable and rejected
    line counts; a list that cannot be read reports the error instead.
    """

    refs: list[TokenListRef] = [resolve_token_list_ref(None, environ)]
    refs.extend(library_token_lists(environ))
    seen = {str(ref.path) for ref in refs}
    for ref in extra:
        if str(ref.path) in seen:
            continue
        seen.add(str(ref.path))
        refs.append(ref)
    rows: list[dict[str, Any]] = []
    for ref in refs:
        row = ref.to_wire()
        if with_counts:
            try:
                loaded = load_universal_tokens(ref.path)
            except UniversalTokensError as error:
                row["error"] = str(error)
            else:
                row["entry_count"] = len(loaded.entries)
                row["problem_count"] = len(loaded.problems)
                row["style"] = loaded.style
        rows.append(row)
    return rows


def delete_library_token_list(name: Any, environ: Mapping[str, str] | None = None) -> Path:
    """Remove one library list and return its path."""

    target = token_lists_dir(environ) / f"{normalise_list_name(name)}{TOKEN_LIST_SUFFIX}"
    if not target.is_file():
        raise UniversalTokensError(f"No token list named {normalise_list_name(name)!r} at {target}.")
    try:
        target.unlink()
    except OSError as error:
        raise UniversalTokensError(f"Cannot delete {target}: {error}") from error
    return target


def _normalise_hex(raw: str) -> str:
    cleaned = str(raw or "").strip().replace(" ", "").replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    return cleaned


def _parse_list_name(name: str) -> tuple[str, dict[str, Any] | None] | None:
    """Return ``(key, parts)`` for a list name in any spelling, or ``None``.

    ``key`` is the compact body of a placeholder literal, or the bare name
    of a ``{NAME}`` token, for which ``parts`` is ``None``.
    """

    body = strip_placeholder_delimiters(name)
    if not body:
        return None
    parts = parse_placeholder_literal(body)
    if parts is not None:
        return str(parts["key"]), parts
    if _NAME_RE.match(body) is None:
        return None
    return body, None


def _variable_fold(name: Any) -> str:
    """The case-folded variable a list name or literal names, underscores dropped.

    ``{scp80_kic1:BINARY:16}``, ``[scp80kic1BINARY16]`` and the token line
    ``SCP80_KIC1`` all fold to ``scp80kic1``; empty for a name that is
    neither a placeholder nor a token name.
    """
    body = strip_placeholder_delimiters(name)
    if not body:
        return ""
    parts = parse_placeholder_literal(body)
    variable = str(parts["variable"]) if parts is not None else body
    if parts is None and _NAME_RE.match(variable) is None:
        return ""
    return variable.casefold().replace("_", "")


def entry_hex_for_record(entry: UniversalTokenEntry, record: Any) -> str:
    """The bytes ``entry`` supplies for ``record`` when the two spell the variable apart.

    A typed entry of the record's type carries its value across: the bytes
    are decoded through the entry's own spelling (width and modifier) and
    encoded again for the occurrence, so a header-order ICCID entry answers
    a nibble-swapped occurrence and a 4-byte TEXT entry is refused by an
    8-byte one. Any other entry (a plain token line, another type) supplies
    its bytes as they are, at the occurrence's exact width. Raises
    :class:`SaipVariableMaterializationError` when the value cannot fit.
    """
    parsed = _parse_list_name(entry.name)
    parts = parsed[1] if parsed is not None else None
    record_type = str(getattr(record, "type_name", "") or "").strip().upper()
    if parts is not None and str(parts["type"]).upper() == record_type:
        source = InlinePlaceholderRecord(
            index=0,
            literal=entry.name,
            variable_name=str(parts["variable"]),
            type_name=str(parts["type"]),
            byte_length=int(parts["byte_length"]),
            modifier=parts["modifier"],
            sentinel_hex="",
        )
        value = decode_inline_placeholder_value(source, bytes.fromhex(entry.hex))
        if value is not None:
            try:
                return encode_inline_placeholder_value(record, value).hex().upper()
            except SaipVariableMaterializationError as error:
                raise SaipVariableMaterializationError(
                    f"{entry.name} holds {value!r}, which does not fit: {error}"
                ) from error
    return validate_inline_raw_value(record, entry.hex).hex().upper()


def _answer_record(
    token_list: UniversalTokenList,
    record: Any,
    key: str,
) -> tuple[UniversalTokenEntry | None, str, list[str]]:
    """Return ``(entry, hex, reasons)``: how one list answers one occurrence.

    The literal's own spellings come first (:meth:`UniversalTokenList.lookup`);
    an entry that only names the variable answers last, with its value
    carried across by :func:`entry_hex_for_record`. ``reasons`` names every
    entry that could not answer, with its line, so a declaration without a
    value or a value that does not fit is reported rather than silent.
    """
    reasons: list[str] = []
    entry = token_list.lookup(key)
    if entry is not None:
        if entry.declared_only:
            reasons.append(f"line {entry.line}: declared without a value")
        else:
            try:
                validate_inline_raw_value(record, entry.hex)
            except SaipVariableMaterializationError as error:
                reasons.append(f"line {entry.line}: {error}")
            else:
                return entry, entry.hex, reasons
    exact_line = entry.line if entry is not None else None
    for candidate in token_list.entries_for_variable(getattr(record, "variable_name", "")):
        if candidate.line == exact_line:
            continue
        if candidate.declared_only:
            reasons.append(f"line {candidate.line}: declared without a value")
            continue
        try:
            return candidate, entry_hex_for_record(candidate, record), reasons
        except SaipVariableMaterializationError as error:
            reasons.append(f"line {candidate.line}: {error}")
    if not reasons:
        rejected = token_list.problems_for(key)
        if rejected:
            reasons.append(f"line {rejected[0].line}: {rejected[0].reason}")
    return None, "", reasons


def _names_match(left: Any, right: Any, *, relaxed: bool = False) -> bool:
    """True when two list names spell the same placeholder or token.

    ``relaxed`` also drops underscores from the variable, the last rung of
    :meth:`UniversalTokenList.lookup`, and never matches a plain token name.
    """

    first = str(left or "").strip()
    second = str(right or "").strip()
    if not first or not second:
        return False
    if relaxed:
        loose = placeholder_key_fold_relaxed(first)
        return bool(loose) and loose == placeholder_key_fold_relaxed(second)
    if (
        strip_placeholder_delimiters(first).casefold()
        == strip_placeholder_delimiters(second).casefold()
    ):
        return True
    return placeholder_key_fold(first) == placeholder_key_fold(second)


def _entry_line_indexes(lines: list[str], name: str) -> tuple[list[int], bool]:
    """Return the indexes of the lines naming ``name`` and whether the relaxed rung found them.

    Lines spelling the same placeholder are preferred; only when there is
    none does the underscore-free comparison apply.
    """

    for relaxed in (False, True):
        found = [
            index
            for index, raw_line in enumerate(lines)
            if (line := raw_line.strip())
            and not line.startswith(_COMMENT_PREFIXES)
            and "," in line
            and _names_match(line.split(",", 1)[0].strip(), name, relaxed=relaxed)
        ]
        if found:
            return found, relaxed
    return [], False


def parse_universal_tokens(
    text: str,
) -> tuple[list[UniversalTokenEntry], list[UniversalTokenProblem]]:
    """Parse list text into usable entries and per-line problems.

    A ``syntax`` problem is a line that is not ``name,value`` with a valid
    name, or a ``# style:`` directive naming an unknown style; a ``value``
    problem is a hex, width or duplicate defect. Neither stops the other
    lines from loading; the first of duplicate names wins, and two
    spellings of one placeholder are duplicates.
    """

    entries: list[UniversalTokenEntry] = []
    problems: list[UniversalTokenProblem] = []
    seen: dict[str, int] = {}
    first_data_line = True
    for line_number, raw_line in enumerate(str(text or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(_COMMENT_PREFIXES):
            directive = _STYLE_DIRECTIVE_RE.match(line)
            if directive is not None and directive.group("style").casefold() not in PLACEHOLDER_STYLES:
                problems.append(
                    UniversalTokenProblem(
                        line_number,
                        "style",
                        f"unknown list style {directive.group('style')!r}; use "
                        f"{', '.join(PLACEHOLDER_STYLES)}",
                        PROBLEM_SYNTAX,
                    )
                )
            continue
        if "," not in line:
            problems.append(
                UniversalTokenProblem(line_number, "", "expected 'name,hex'", PROBLEM_SYNTAX)
            )
            first_data_line = False
            continue
        name_raw, value_raw = line.split(",", 1)
        name = name_raw.strip()
        value = value_raw.strip()
        is_header = (
            first_data_line
            and name.casefold() in _HEADER_NAMES
            and value.casefold() in _HEADER_VALUES
        )
        first_data_line = False
        if is_header:
            continue
        parsed_name = _parse_list_name(name)
        if parsed_name is None:
            problems.append(
                UniversalTokenProblem(
                    line_number,
                    name,
                    "name must be a placeholder literal ({var:TYPE:len[:modifier]}, "
                    "[varTYPElen] or varTYPElen) or a token name of letters, digits "
                    "and underscore",
                    PROBLEM_SYNTAX,
                )
            )
            continue
        key, parts = parsed_name
        cleaned = _normalise_hex(value)
        if not cleaned:
            # ``name,`` declares the placeholder for the pickers and the
            # listings without answering it; the match reports it as such.
            fold_declared = placeholder_key_fold(name)
            if fold_declared in seen:
                problems.append(
                    UniversalTokenProblem(
                        line_number, name, f"duplicate of line {seen[fold_declared]} (first one kept)"
                    )
                )
                continue
            seen[fold_declared] = line_number
            entries.append(
                UniversalTokenEntry(
                    name=name,
                    hex="",
                    line=line_number,
                    declared_bytes=int(parts["byte_length"]) if parts is not None else None,
                    key=key,
                    fold=fold_declared,
                )
            )
            continue
        if len(cleaned) % 2 != 0:
            problems.append(
                UniversalTokenProblem(
                    line_number, name, f"odd hex length ({len(cleaned)} chars)"
                )
            )
            continue
        try:
            bytes.fromhex(cleaned)
        except ValueError:
            problems.append(UniversalTokenProblem(line_number, name, "value is not hex"))
            continue
        declared = int(parts["byte_length"]) if parts is not None else None
        actual = len(cleaned) // 2
        if declared is not None and declared != actual:
            problems.append(
                UniversalTokenProblem(
                    line_number,
                    name,
                    f"name declares {declared} bytes but the value has {actual}",
                )
            )
            continue
        fold = placeholder_key_fold(name)
        if fold in seen:
            problems.append(
                UniversalTokenProblem(
                    line_number, name, f"duplicate of line {seen[fold]} (first one kept)"
                )
            )
            continue
        seen[fold] = line_number
        entries.append(
            UniversalTokenEntry(
                name=name,
                hex=cleaned.upper(),
                line=line_number,
                declared_bytes=declared,
                key=key,
                fold=fold,
            )
        )
    return entries, problems


def token_list_style(
    text: str,
    entries: Iterable[UniversalTokenEntry] | None = None,
) -> tuple[str, str]:
    """Return ``(style, source)``: the spelling a list writes its names in.

    A ``# style: typed`` directive (``;`` and ``=`` are accepted too)
    declares it and ``source`` is ``directive``; otherwise the first
    placeholder entry's spelling decides (``entries``), and a list without
    one is typed (``default``). ``entries`` skips a second parse when the
    caller already holds them.
    """

    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith(_COMMENT_PREFIXES):
            continue
        directive = _STYLE_DIRECTIVE_RE.match(line)
        if directive is None:
            continue
        style = directive.group("style").casefold()
        if style in PLACEHOLDER_STYLES:
            return style, STYLE_SOURCE_DIRECTIVE
        break
    if entries is None:
        entries, _problems = parse_universal_tokens(text)
    for entry in entries:
        style = placeholder_literal_style(entry.name)
        if style is not None:
            return style, STYLE_SOURCE_ENTRIES
    return DEFAULT_PLACEHOLDER_STYLE, STYLE_SOURCE_DEFAULT


def load_universal_tokens(path: Path | None = None) -> UniversalTokenList:
    """Load the list; a missing file is an empty list, not an error."""

    target = Path(path) if path is not None else universal_tokens_path()
    if not target.is_file():
        return UniversalTokenList(path=target, loaded=False, text="", entries=(), problems=())
    try:
        raw = read_bounded_regular_file(target, _MAX_LIST_BYTES)
    except (OSError, ValueError) as error:
        raise UniversalTokensError(f"Cannot read {target}: {error}") from error
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise UniversalTokensError(f"{target} is not UTF-8 text: {error}") from error
    entries, problems = parse_universal_tokens(text)
    style, style_source = token_list_style(text, entries)
    return UniversalTokenList(
        path=target,
        loaded=True,
        text=text,
        entries=tuple(entries),
        problems=tuple(problems),
        style=style,
        style_source=style_source,
    )


def write_universal_tokens(text: str, path: Path | None = None) -> UniversalTokenList:
    """Store list text and return the parsed result.

    A line that is not ``name,value`` refuses the whole write, naming it;
    a value defect is stored and reported, because the operator's text is
    theirs to fix while the loader keeps such an entry out of every
    template.
    """

    target = Path(path) if path is not None else universal_tokens_path()
    _entries, problems = parse_universal_tokens(text)
    syntax = [problem for problem in problems if problem.kind == PROBLEM_SYNTAX]
    if syntax:
        detail = "; ".join(f"line {problem.line}: {problem.reason}" for problem in syntax[:5])
        raise UniversalTokensError(f"Universal token list not written: {detail}.")
    payload = str(text or "")
    if payload and not payload.endswith("\n"):
        payload += "\n"
    try:
        ensure_private_directory(target.parent)
        atomic_write_bytes(target, payload.encode("utf-8"), overwrite=True)
    except OSError as error:
        raise UniversalTokensError(f"Cannot write {target}: {error}") from error
    return load_universal_tokens(target)


def set_token_list_entry(
    text: str,
    name: Any,
    value: Any,
    *,
    style: str | None = None,
) -> str:
    """Return ``text`` with ``name`` set to ``value``, in place or appended.

    The line must parse: a bad name, a non-hex value or a width that
    disagrees with the name is refused before anything is written; an
    empty ``value`` writes ``name,``, a declaration without a value. The
    entry is matched across spellings the way :meth:`UniversalTokenList.lookup`
    matches (an underscore-free variable last), and its name is written in
    the list's style (``style`` overrides it; a list with neither a
    directive nor a placeholder entry is written in the default, typed,
    style whatever spelling ``name`` arrived in).
    Other lines, comments and order are kept.
    """

    entry_name = str(name or "").strip()
    entry_hex = _normalise_hex(str(value or "")).upper()
    probe_entries, probe_problems = parse_universal_tokens(f"{entry_name},{entry_hex}\n")
    if probe_problems or not probe_entries:
        reason = probe_problems[0].reason if probe_problems else "invalid entry"
        raise UniversalTokensError(f"{entry_name or '(no name)'}: {reason}.")
    if style is None:
        style, _source = token_list_style(text)
    elif style not in PLACEHOLDER_STYLES:
        raise UniversalTokensError(
            f"Unknown list style {style!r}; use {', '.join(PLACEHOLDER_STYLES)}."
        )
    written = format_placeholder_literal(entry_name, style)
    lines = str(text or "").splitlines()
    matches, relaxed = _entry_line_indexes(lines, entry_name)
    for position, index in enumerate(matches):
        if position == 0:
            # A relaxed hit keeps the operator's variable spelling
            # (``scp80_kic1`` stays when ``scp80kic1`` is set).
            current_name = lines[index].strip().split(",", 1)[0].strip()
            lines[index] = f"{current_name if relaxed else written},{entry_hex}"
        else:
            lines[index] = f"# {lines[index].strip()}  (duplicate removed)"
    if not matches:
        lines.append(f"{written},{entry_hex}")
    return "\n".join(lines) + "\n"


def remove_token_list_entry(text: str, name: Any) -> tuple[str, int]:
    """Return ``text`` without the lines for ``name``, in any spelling, and the count."""

    lines = str(text or "").splitlines()
    doomed = set(_entry_line_indexes(lines, str(name or "").strip())[0])
    kept = [raw_line for index, raw_line in enumerate(lines) if index not in doomed]
    return ("\n".join(kept) + "\n") if kept else "", len(doomed)


def format_token_list(
    values: Mapping[str, str],
    *,
    comments: Iterable[str] = (),
    style: str | None = None,
) -> str:
    """Render ``key -> hex`` as list text, comments first, keys sorted.

    With ``style`` every name is written in that spelling and a
    ``# style:`` line records it after the comments; without one the names
    are written as given.
    """

    if style is not None and style not in PLACEHOLDER_STYLES:
        raise UniversalTokensError(
            f"Unknown list style {style!r}; use {', '.join(PLACEHOLDER_STYLES)}."
        )
    lines = [f"# {str(comment).strip()}" for comment in comments if str(comment).strip()]
    if style is not None:
        lines.append(f"# style: {style}")
    for key in sorted(values, key=lambda item: str(item).casefold()):
        name = format_placeholder_literal(key, style) if style is not None else str(key)
        lines.append(f"{name},{str(values[key]).upper()}")
    return ("\n".join(lines) + "\n") if lines else ""


@dataclass(frozen=True)
class UniversalMatch:
    """How a universal list answers one set of placeholder occurrences."""

    raw_values: dict[str, str]
    matched: list[dict[str, Any]]
    unmatched: list[dict[str, Any]]

    def to_wire(self) -> dict[str, Any]:
        return {
            "matched": list(self.matched),
            "unmatched": list(self.unmatched),
            "matched_count": len(self.matched),
            "unmatched_count": len(self.unmatched),
        }


def match_universal_values(records: Iterable[Any], token_list: UniversalTokenList) -> UniversalMatch:
    """Pair every occurrence with its list entry, checking the width.

    ``raw_values`` is keyed by the canonical record key and holds only
    values that fit; ``unmatched`` names the occurrences the list cannot
    serve and why (no entry, or an entry the loader rejected).
    """

    raw_values: dict[str, str] = {}
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for record in records:
        key = inline_record_key(record)
        summary = {
            "key": key,
            "literal": str(getattr(record, "literal", "") or ""),
            "variable": str(getattr(record, "variable_name", "") or ""),
            "byte_length": int(getattr(record, "byte_length", 0) or 0),
        }
        entry, hex_value, reasons = _answer_record(token_list, record, key)
        if entry is None:
            summary["reason"] = "; ".join(reasons) if reasons else "no entry in the universal list"
            unmatched.append(summary)
            continue
        raw_values[key] = hex_value
        summary["line"] = entry.line
        summary["entry"] = entry.name
        if hex_value != entry.hex:
            summary["re_encoded"] = True
        matched.append(summary)
    return UniversalMatch(raw_values=raw_values, matched=matched, unmatched=unmatched)


def layered_universal_match(
    records: Iterable[Any],
    layers: Iterable[UniversalTokenList],
) -> UniversalMatch:
    """Resolve occurrences against lists in precedence order.

    The first list that holds a usable entry for an occurrence answers it;
    a later list is consulted only for what is still open, so a bound
    profile-specific list overrides the universal one entry by entry. Each
    matched item names the ``list`` that answered it.
    """

    ordered = list(layers)
    raw_values: dict[str, str] = {}
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for record in records:
        key = inline_record_key(record)
        summary = {
            "key": key,
            "literal": str(getattr(record, "literal", "") or ""),
            "variable": str(getattr(record, "variable_name", "") or ""),
            "byte_length": int(getattr(record, "byte_length", 0) or 0),
        }
        reasons: list[str] = []
        answered = False
        for token_list in ordered:
            label = str(token_list.path.name if token_list.path is not None else "list")
            entry, hex_value, entry_reasons = _answer_record(token_list, record, key)
            reasons.extend(f"{label} {reason}" for reason in entry_reasons)
            if entry is None:
                continue
            raw_values[key] = hex_value
            summary["line"] = entry.line
            summary["entry"] = entry.name
            summary["list"] = str(token_list.path or "")
            if hex_value != entry.hex:
                summary["re_encoded"] = True
            matched.append(summary)
            answered = True
            break
        if not answered:
            summary["reason"] = "; ".join(reasons) if reasons else "no entry in any bound list"
            unmatched.append(summary)
    return UniversalMatch(raw_values=raw_values, matched=matched, unmatched=unmatched)


def load_test_value_layers(
    selector: Any,
    environ: Mapping[str, str] | None = None,
) -> tuple[list[UniversalTokenList], TokenListRef, list[str]]:
    """Load the lists a binding selects, most specific first.

    Returns the loaded layers (the bound list, then the universal list; a
    universal binding yields the universal list alone), the bound
    reference, and warnings: a bound file that is missing or unreadable is
    reported and skipped rather than blocking the universal defaults.
    """

    ref = resolve_token_list_ref(selector, environ)
    warnings: list[str] = []
    layers: list[UniversalTokenList] = []
    if not ref.is_universal:
        try:
            bound = load_universal_tokens(ref.path)
        except UniversalTokensError as error:
            warnings.append(str(error))
        else:
            if bound.loaded:
                layers.append(bound)
            else:
                warnings.append(f"Bound token list {ref.name} not found at {ref.path}.")
    try:
        layers.append(load_universal_tokens(universal_tokens_path(environ)))
    except UniversalTokensError as error:
        warnings.append(str(error))
    return layers, ref, warnings


def destination_list_style(path: Path | None) -> str:
    """The style an export into ``path`` keeps, or ``""`` for a new list.

    A list keeps the spelling its templates use: an existing list with a
    ``# style:`` line or at least one placeholder entry answers with that
    style. A missing or empty list answers nothing, and the writer falls
    back to the typed spelling, the only one the tool chooses on its own.
    """
    if path is None or Path(path).is_file() is False:
        return ""
    try:
        token_list = load_universal_tokens(Path(path))
    except UniversalTokensError:
        return ""
    if not token_list.loaded:
        return ""
    if token_list.style_declared or len(token_list.entries) > 0:
        return str(token_list.style)
    return ""


def universal_token_defs(
    names: Iterable[str],
    token_list: UniversalTokenList,
) -> dict[str, dict[str, str]]:
    """Return ``__ygg_token_defs__`` entries for the named ``{NAME}`` tokens.

    Only names the list answers are returned, so a template gains the
    definitions it references and nothing else.
    """

    defs: dict[str, dict[str, str]] = {}
    for name in names:
        entry = token_list.lookup(str(name))
        if entry is not None and entry.declared_only is False:
            defs[str(name)] = {"hex": entry.hex}
    return defs


__all__ = [
    "destination_list_style",
    "entry_hex_for_record",
    "PROBLEM_SYNTAX",
    "PROBLEM_VALUE",
    "STYLE_SOURCE_DEFAULT",
    "STYLE_SOURCE_DIRECTIVE",
    "STYLE_SOURCE_ENTRIES",
    "TOKEN_LISTS_DIR_ENV",
    "TOKEN_LISTS_DIR_NAME",
    "TOKEN_LIST_SUFFIX",
    "UNIVERSAL_LIST_SELECTOR",
    "UNIVERSAL_TOKENS_ENV",
    "UNIVERSAL_TOKENS_FILE_NAME",
    "TokenListRef",
    "UniversalMatch",
    "UniversalTokenEntry",
    "UniversalTokenList",
    "UniversalTokenProblem",
    "UniversalTokensError",
    "delete_library_token_list",
    "format_token_list",
    "layered_universal_match",
    "library_token_lists",
    "load_test_value_layers",
    "load_universal_tokens",
    "match_universal_values",
    "normalise_list_name",
    "parse_universal_tokens",
    "remove_token_list_entry",
    "resolve_token_list_ref",
    "set_token_list_entry",
    "token_list_catalogue",
    "token_list_style",
    "token_lists_dir",
    "universal_token_defs",
    "universal_tokens_path",
    "write_universal_tokens",
]
