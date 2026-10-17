# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Universal placeholder test values: list parsing, matching, materialization.

The list maps a placeholder literal body (``iccidICCID10NibbleSwap``) to
wire bytes. It lives outside the repository; these tests build their own
lists under ``tmp_path`` with reserved-range identifiers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from Tools.ProfilePackage.saip_hex_template import (
    DEFAULT_PLACEHOLDER_STYLE,
    InlinePlaceholderRecord,
    format_placeholder_literal,
    parse_placeholder_literal,
    placeholder_key_fold,
    placeholder_key_fold_relaxed,
    placeholder_literal_style,
    substitute_inline_placeholders,
)
from Tools.ProfilePackage.saip_universal_tokens import (
    PROBLEM_SYNTAX,
    PROBLEM_VALUE,
    TOKEN_LISTS_DIR_ENV,
    UNIVERSAL_TOKENS_ENV,
    UniversalTokensError,
    delete_library_token_list,
    format_token_list,
    layered_universal_match,
    library_token_lists,
    load_test_value_layers,
    load_universal_tokens,
    match_universal_values,
    normalise_list_name,
    parse_universal_tokens,
    remove_token_list_entry,
    resolve_token_list_ref,
    set_token_list_entry,
    token_list_catalogue,
    token_list_style,
    token_lists_dir,
    universal_token_defs,
    universal_tokens_path,
    write_universal_tokens,
)
from Tools.ProfilePackage.saip_variable_materialization import (
    SaipVariableMaterializationError,
    encode_inline_placeholder_value,
    inline_record_key,
    lookup_raw_value,
    match_inline_raw_values,
    materialize_inline_records,
    records_for_raw_key,
    read_inline_variable_sidecar,
    read_inline_variable_sidecar_document,
    resolve_inline_records,
    write_inline_variable_sidecar,
)


def _record(
    index: int,
    variable: str,
    type_name: str,
    byte_length: int,
    sentinel_hex: str,
    modifier: str | None = None,
) -> InlinePlaceholderRecord:
    return InlinePlaceholderRecord(
        index=index,
        literal=f"{{{variable}{type_name}{byte_length}{modifier or ''}}}",
        variable_name=variable,
        type_name=type_name,
        byte_length=byte_length,
        modifier=modifier,
        sentinel_hex=sentinel_hex,
    )


LIST_TEXT = """# universal test values
name,value
iccidICCID10NibbleSwap,98880811111111111121
accBINARY2,0040
pin1TEXT4utf8,31323334
riRI4,F0FF0000
scp80kic1BINARY8,1122334455667788
scp80kic2BINARY24,1122334455667788AABBCCDDEEFF0011112233445566778
kiBINARY16,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
accBINARY2,0041
bad line without comma
9lives,00
"""


def test_parse_accepts_header_and_comments_and_reports_every_defect() -> None:
    entries, problems = parse_universal_tokens(LIST_TEXT)

    assert [entry.name for entry in entries] == [
        "iccidICCID10NibbleSwap",
        "accBINARY2",
        "pin1TEXT4utf8",
        "riRI4",
        "scp80kic1BINARY8",
        "kiBINARY16",
    ]
    by_name = {entry.name: entry for entry in entries}
    assert by_name["accBINARY2"].hex == "0040"
    assert by_name["accBINARY2"].declared_bytes == 2
    assert by_name["iccidICCID10NibbleSwap"].byte_length == 10
    assert [(problem.line, problem.kind) for problem in problems] == [
        (8, PROBLEM_VALUE),
        (10, PROBLEM_VALUE),
        (11, PROBLEM_SYNTAX),
        (12, PROBLEM_SYNTAX),
    ]
    assert "odd hex length (47 chars)" in problems[0].reason
    assert "duplicate of line 4" in problems[1].reason


def test_width_declared_by_the_name_must_match_the_value() -> None:
    entries, problems = parse_universal_tokens("accBINARY2,004000\n")

    assert entries == []
    assert len(problems) == 1
    assert problems[0].reason == "name declares 2 bytes but the value has 3"


def test_plain_token_names_carry_no_declared_width() -> None:
    entries, problems = parse_universal_tokens("ICCID,89880811111111111112\n")

    assert problems == []
    assert entries[0].declared_bytes is None
    assert entries[0].byte_length == 10


def test_path_resolution_prefers_the_env_override(monkeypatch, tmp_path: Path) -> None:
    override = tmp_path / "custom" / "list.csv"
    assert universal_tokens_path({UNIVERSAL_TOKENS_ENV: str(override)}) == override
    monkeypatch.setenv("HOME", str(tmp_path))
    assert universal_tokens_path({}) == tmp_path / ".yggdrasim" / "saip_universal_tokens.csv"


def test_missing_list_loads_as_empty_not_error(tmp_path: Path) -> None:
    listing = load_universal_tokens(tmp_path / "absent.csv")

    assert listing.loaded is False
    assert listing.entries == ()
    assert listing.lookup("accBINARY2") is None


def test_write_refuses_syntax_defects_but_stores_value_defects(tmp_path: Path) -> None:
    target = tmp_path / "list.csv"
    with pytest.raises(UniversalTokensError, match="line 1: expected 'name,hex'"):
        write_universal_tokens("no comma here\n", target)
    assert not target.exists()

    listing = write_universal_tokens("accBINARY2,0040\nscp80kic1BINARY8,112233\n", target)

    assert target.is_file()
    assert listing.loaded is True
    assert [entry.name for entry in listing.entries] == ["accBINARY2"]
    assert [problem.line for problem in listing.problems] == [2]
    assert load_universal_tokens(target).text == listing.text


def test_lookup_is_exact_first_then_case_insensitive(tmp_path: Path) -> None:
    listing = write_universal_tokens("ACCbinary2,0041\naccBINARY2,0040\n", tmp_path / "l.csv")

    assert listing.lookup("accBINARY2").hex == "0040"
    assert listing.lookup("ACCBINARY2").hex == "0041"
    assert listing.lookup("missing") is None


def test_match_reports_width_defects_and_missing_entries(tmp_path: Path) -> None:
    # Written directly: the list carries syntax defects the writer refuses,
    # and the loader must still serve the usable lines around them.
    (tmp_path / "l.csv").write_text(LIST_TEXT, encoding="utf-8")
    listing = load_universal_tokens(tmp_path / "l.csv")
    records = [
        _record(0, "iccid", "ICCID", 10, "AA" * 10, "NibbleSwap"),
        _record(1, "acc", "BINARY", 2, "B1B2"),
        _record(2, "scp80kic2", "BINARY", 24, "CC" * 24),
        _record(3, "puk1", "BINARY", 8, "DD" * 8),
    ]

    match = match_universal_values(records, listing)

    assert match.raw_values == {
        "iccidICCID10NibbleSwap": "98880811111111111121",
        "accBINARY2": "0040",
    }
    assert [item["key"] for item in match.matched] == ["iccidICCID10NibbleSwap", "accBINARY2"]
    reasons = {item["key"]: item["reason"] for item in match.unmatched}
    assert reasons["scp80kic2BINARY24"].startswith("line 8: odd hex length")
    assert reasons["puk1BINARY8"] == "no entry in the universal list"


def test_materialize_splices_raw_values_and_typed_values_win() -> None:
    first = _record(0, "acc", "BINARY", 2, "A1A2")
    second = _record(1, "acc", "BINARY", 2, "B1B2")
    pin = _record(2, "pin1", "TEXT", 4, "C1C2C3C4", "utf8")
    document = {
        "sections": {
            "one": b"\x00\xa1\xa2\x01",
            "two": ("choice", {"payload": b"\xb1\xb2\xc1\xc2\xc3\xc4"}),
        }
    }

    materialized, remaining, results = materialize_inline_records(
        document,
        [first, second, pin],
        {"acc": "DEAD"},
        raw_values={"accBINARY2": "0040", "pin1TEXT4utf8": "31323334"},
    )

    assert document["sections"]["one"] == b"\x00\xa1\xa2\x01"
    assert materialized["sections"]["one"] == b"\x00\xde\xad\x01"
    assert materialized["sections"]["two"][1]["payload"] == b"\xde\xad1234"
    assert remaining == []
    assert {result.variable_name: result.source for result in results} == {
        "acc": "inline_varder",
        "pin1": "universal_tokens",
    }


def test_resolution_needs_a_raw_value_for_every_occurrence() -> None:
    narrow = _record(0, "msisdn", "MSISDN", 7, "A0" * 7, "NibbleSwap")
    wide = _record(1, "msisdn", "MSISDN", 8, "B0" * 8, "NibbleSwap")

    _typed, raw, unresolved = resolve_inline_records(
        [narrow, wide], {}, {"msisdnMSISDN7NibbleSwap": "100000000000F1"}
    )
    assert raw == {"msisdnMSISDN7NibbleSwap": "100000000000F1"}
    assert unresolved == ["msisdn"]

    _typed, raw, unresolved = resolve_inline_records(
        [narrow, wide],
        {},
        {"msisdnMSISDN7NibbleSwap": "100000000000F1", "msisdnMSISDN8NibbleSwap": "10000000000000F1"},
    )
    assert unresolved == []
    assert inline_record_key(wide) in raw


def test_raw_value_of_the_wrong_width_fails_closed() -> None:
    record = _record(0, "acc", "BINARY", 2, "A1A2")
    with pytest.raises(SaipVariableMaterializationError, match="exactly 2 bytes"):
        materialize_inline_records(
            {"sections": {"one": b"\xa1\xa2"}},
            [record],
            {},
            raw_values={"accBINARY2": "004000"},
        )
    with pytest.raises(SaipVariableMaterializationError, match="Unresolved inline template"):
        materialize_inline_records({"sections": {"one": b"\xa1\xa2"}}, [record], {}, raw_values={})


def test_sidecar_round_trips_raw_values_beside_typed_ones(tmp_path: Path) -> None:
    sidecar = tmp_path / "template.variables.json"
    write_inline_variable_sidecar(
        sidecar,
        {"iccid": "8988201234567890123"},
        created_from="template.hex",
        raw_values={"accBINARY2": "0040", "": "ignored"},
    )

    document = read_inline_variable_sidecar_document(sidecar)

    assert document == {
        "values": {"iccid": "8988201234567890123"},
        "raw_values": {"accBINARY2": "0040"},
        "test_value_list": "",
    }
    assert read_inline_variable_sidecar(sidecar) == {"iccid": "8988201234567890123"}


def test_parse_placeholder_literal_covers_both_grammars_and_the_vendor_types() -> None:
    typed = parse_placeholder_literal("{iccid:ICCID:10:NibbleSwap}")
    assert typed["key"] == "iccidICCID10NibbleSwap"
    assert typed["byte_length"] == 10
    compact = parse_placeholder_literal("[riRI4]")
    assert (compact["variable"], compact["type"], compact["byte_length"]) == ("ri", "RI", 4)
    assert parse_placeholder_literal("oplmnOPLMN250")["byte_length"] == 250
    assert parse_placeholder_literal("imsiIMSI8EncodeIMSI")["modifier"] == "EncodeIMSI"
    assert parse_placeholder_literal("{notaplaceholder}") is None


def test_hex_template_accepts_ri_and_oplmn_placeholders() -> None:
    _cleaned, records = substitute_inline_placeholders("AA{riRI4}BB{oplmnOPLMN250}CC")

    assert [(record.type_name, record.byte_length) for record in records] == [
        ("RI", 4),
        ("OPLMN", 250),
    ]
    assert encode_inline_placeholder_value(records[0], "F0FF0000") == bytes.fromhex("F0FF0000")


def test_token_defs_cover_only_the_names_the_list_answers(tmp_path: Path) -> None:
    listing = write_universal_tokens("ICCID,89880811111111111112\n", tmp_path / "l.csv")

    assert universal_token_defs(["ICCID", "IMSI"], listing) == {
        "ICCID": {"hex": "89880811111111111112"}
    }


def _library_env(tmp_path: Path) -> dict[str, str]:
    return {
        UNIVERSAL_TOKENS_ENV: str(tmp_path / "universal.csv"),
        TOKEN_LISTS_DIR_ENV: str(tmp_path / "lib"),
    }


def test_selector_resolves_universal_library_and_path(tmp_path: Path) -> None:
    env = _library_env(tmp_path)
    universal = resolve_token_list_ref("", env)
    assert universal.is_universal and universal.name == "Universal"
    assert universal.path == tmp_path / "universal.csv"
    assert resolve_token_list_ref("UNIVERSAL", env).is_universal

    library = resolve_token_list_ref("operator-a", env)
    assert library.kind == "library" and library.selector == "operator-a"
    assert library.path == tmp_path / "lib" / "operator-a.csv"
    assert resolve_token_list_ref("operator-a.csv", env).kind == "path"

    for raw in ("./lists/x.csv", "~/x.csv", "lists/x.csv"):
        assert resolve_token_list_ref(raw, env).kind == "path"
    assert token_lists_dir(env) == tmp_path / "lib"


@pytest.mark.parametrize("bad", ["", "bad name", "-lead", "a" * 65, "universal", "Universal"])
def test_library_names_are_validated_and_universal_is_reserved(bad: str) -> None:
    with pytest.raises(UniversalTokensError):
        normalise_list_name(bad)


def test_library_lists_and_catalogue_report_counts(tmp_path: Path) -> None:
    env = _library_env(tmp_path)
    assert library_token_lists(env) == []
    assert [row["name"] for row in token_list_catalogue(env)] == ["Universal"]
    write_universal_tokens("accBINARY2,0040\n", tmp_path / "universal.csv")
    write_universal_tokens("accBINARY2,0041\nbadBINARY2,004\n", tmp_path / "lib" / "opA.csv")
    (tmp_path / "lib" / "notes.txt").write_text("ignored", encoding="utf-8")
    (tmp_path / "lib" / "universal.csv").write_text("accBINARY2,0042\n", encoding="utf-8")

    assert [ref.selector for ref in library_token_lists(env)] == ["opA"]
    rows = token_list_catalogue(env, with_counts=True)
    assert [(row["name"], row["entry_count"], row["problem_count"]) for row in rows] == [
        ("Universal", 1, 0),
        ("opA", 1, 1),
    ]
    extra = resolve_token_list_ref(str(tmp_path / "other.csv"), env)
    listed = token_list_catalogue(env, extra=[extra])
    assert listed[-1]["kind"] == "path" and listed[-1]["exists"] is False

    assert delete_library_token_list("opA", env) == tmp_path / "lib" / "opA.csv"
    with pytest.raises(UniversalTokensError):
        delete_library_token_list("opA", env)


def test_entry_editing_keeps_comments_and_validates_the_line() -> None:
    text = "# header\naccBINARY2,0040\n"
    text = set_token_list_entry(text, "pin1TEXT4utf8", "31 32 33 34")
    text = set_token_list_entry(text, "ACCBINARY2", "0041")
    assert text == "# header\nACCBINARY2,0041\npin1TEXT4utf8,31323334\n"
    text, removed = remove_token_list_entry(text, "accbinary2")
    assert removed == 1 and text == "# header\npin1TEXT4utf8,31323334\n"
    assert remove_token_list_entry(text, "missing") == (text, 0)
    with pytest.raises(UniversalTokensError):
        set_token_list_entry("", "accBINARY2", "00")
    with pytest.raises(UniversalTokensError):
        set_token_list_entry("", "9lives", "00")


def test_format_token_list_sorts_keys_and_leads_with_comments() -> None:
    assert format_token_list({"b": "aa", "A": "bb"}, comments=["hello", ""]) == (
        "# hello\nA,BB\nb,AA\n"
    )
    assert format_token_list({}) == ""


def test_layered_match_prefers_the_bound_list_and_names_it(tmp_path: Path) -> None:
    env = _library_env(tmp_path)
    write_universal_tokens("accBINARY2,0040\npin1TEXT4utf8,31323334\n", tmp_path / "universal.csv")
    write_universal_tokens("accBINARY2,0041\nkiBINARY16,00\n", tmp_path / "lib" / "opA.csv")
    records = [
        _record(0, "acc", "BINARY", 2, "0000"),
        _record(1, "pin1", "TEXT", 4, "00000000", "utf8"),
        _record(2, "ki", "BINARY", 16, "00" * 16),
    ]
    layers, ref, warnings = load_test_value_layers("opA", env)
    assert ref.selector == "opA" and warnings == []
    assert [layer.path.name for layer in layers] == ["opA.csv", "universal.csv"]

    match = layered_universal_match(records, layers)
    assert match.raw_values == {"accBINARY2": "0041", "pin1TEXT4utf8": "31323334"}
    assert [(item["key"], Path(item["list"]).name) for item in match.matched] == [
        ("accBINARY2", "opA.csv"),
        ("pin1TEXT4utf8", "universal.csv"),
    ]
    assert match.unmatched[0]["key"] == "kiBINARY16"
    assert "opA.csv line 2" in match.unmatched[0]["reason"]


def test_missing_bound_list_is_a_warning_and_the_universal_list_still_answers(
    tmp_path: Path,
) -> None:
    env = _library_env(tmp_path)
    write_universal_tokens("accBINARY2,0040\n", tmp_path / "universal.csv")
    layers, ref, warnings = load_test_value_layers("gone", env)
    assert ref.selector == "gone" and not ref.path.is_file()
    assert [layer.path.name for layer in layers] == ["universal.csv"]
    assert warnings == [f"Bound token list gone not found at {tmp_path / 'lib' / 'gone.csv'}."]
    universal_only, universal_ref, _ = load_test_value_layers("", env)
    assert universal_ref.is_universal and len(universal_only) == 1



TYPED_LIST_TEXT = """# style: typed
{iccid:ICCID:10:nibble_swap},98880811111111111121
{scp80_kic1:BINARY:16},11223344556677881122334455667788
{pin1:TEXT:4},31323334
[accBINARY2],0040
{ICCID},89880811111111111112
"""


def test_list_names_are_accepted_in_every_spelling_and_keyed_by_the_compact_body() -> None:
    entries, problems = parse_universal_tokens(TYPED_LIST_TEXT)

    assert problems == []
    assert [(entry.name, entry.key, entry.declared_bytes) for entry in entries] == [
        ("{iccid:ICCID:10:nibble_swap}", "iccidICCID10nibble_swap", 10),
        ("{scp80_kic1:BINARY:16}", "scp80_kic1BINARY16", 16),
        ("{pin1:TEXT:4}", "pin1TEXT4", 4),
        ("[accBINARY2]", "accBINARY2", 2),
        ("{ICCID}", "ICCID", None),
    ]
    assert entries[0].fold == "iccid|ICCID|10|nibbleswap"
    assert entries[0].to_wire()["key"] == "iccidICCID10nibble_swap"
    _entries, width = parse_universal_tokens("{acc:BINARY:2},004000\n")
    assert width[0].reason == "name declares 2 bytes but the value has 3"
    _entries, duplicate = parse_universal_tokens("accBINARY2,0040\n{acc:BINARY:2},0041\n")
    assert duplicate[0].reason == "duplicate of line 1 (first one kept)"
    _entries, bad = parse_universal_tokens("{acc:BINARY},00\n")
    assert bad[0].kind == PROBLEM_SYNTAX


def test_lookup_answers_every_spelling_and_the_relaxed_variable_last(tmp_path: Path) -> None:
    listing = write_universal_tokens(TYPED_LIST_TEXT, tmp_path / "typed.csv")

    assert listing.style == "typed" and listing.style_declared is True
    assert listing.to_wire()["style_source"] == "directive"
    assert listing.lookup("iccidICCID10NibbleSwap").name == "{iccid:ICCID:10:nibble_swap}"
    assert listing.lookup("[iccidICCID10SwapNibbles]").name == "{iccid:ICCID:10:nibble_swap}"
    assert listing.lookup("pin1TEXT4utf8").name == "{pin1:TEXT:4}"
    assert listing.lookup("{acc:BINARY:2}").name == "[accBINARY2]"
    assert listing.lookup("ICCID").name == "{ICCID}"
    assert listing.lookup("scp80kic1BINARY16").name == "{scp80_kic1:BINARY:16}"
    assert listing.lookup("iccidICCID10") is None
    assert listing.lookup("scp80_kic2BINARY16") is None
    exact = write_universal_tokens(
        "{scp80_kic1:BINARY:16}," + "11" * 16 + "\n{scp80kic1:BINARY:16}," + "22" * 16 + "\n",
        tmp_path / "exact.csv",
    )
    assert exact.lookup("[scp80kic1BINARY16]").hex == "22" * 16

    match = match_universal_values(
        [_record(0, "iccid", "ICCID", 10, "AA" * 10, "NibbleSwap")], listing
    )
    assert match.raw_values == {"iccidICCID10NibbleSwap": "98880811111111111121"}
    assert match.matched[0]["entry"] == "{iccid:ICCID:10:nibble_swap}"
    rejected = write_universal_tokens("{acc:BINARY:2},004\n", tmp_path / "rejected.csv")
    assert rejected.problems_for("[accBINARY2]")[0].line == 1


def test_list_style_is_declared_or_inferred_and_drives_the_writers(tmp_path: Path) -> None:
    # The operator's templates and lists are written typed, so a list with
    # neither a directive nor a placeholder entry is typed too.
    assert DEFAULT_PLACEHOLDER_STYLE == "typed"
    assert token_list_style("") == ("typed", "default")
    assert token_list_style("accBINARY2,0040\n") == ("compact", "entries")
    assert token_list_style("[accBINARY2],0040\n") == ("bracket", "entries")
    assert token_list_style("{accBINARY2},0040\n") == ("brace", "entries")
    assert token_list_style("; style = Bracket\n{acc:BINARY:2},0040\n") == ("bracket", "directive")
    _entries, problems = parse_universal_tokens("# style: fancy\naccBINARY2,0040\n")
    assert problems[0].kind == PROBLEM_SYNTAX
    assert "unknown list style 'fancy'" in problems[0].reason
    with pytest.raises(UniversalTokensError):
        write_universal_tokens("# style: fancy\n", tmp_path / "bad.csv")

    text = set_token_list_entry(TYPED_LIST_TEXT, "puk1BINARY8", "3131313131313131")
    assert text.splitlines()[-1] == "{puk1:BINARY:8},3131313131313131"
    text = set_token_list_entry(text, "[iccidICCID10NibbleSwap]", "AA" * 10)
    assert text.splitlines()[1] == "{iccid:ICCID:10:nibble_swap}," + "AA" * 10
    text = set_token_list_entry(text, "scp80kic1BINARY16", "BB" * 16)
    assert text.splitlines()[2] == "{scp80_kic1:BINARY:16}," + "BB" * 16
    updated, removed = remove_token_list_entry(text, "[scp80kic1BINARY16]")
    assert removed == 1 and "scp80_kic1" not in updated
    assert set_token_list_entry("", "{acc:BINARY:2}", "0040") == "{acc:BINARY:2},0040\n"
    # A fresh list has no spelling of its own, so the default (typed) is
    # written whatever spelling the operator typed.
    assert set_token_list_entry("", "accBINARY2", "0040") == "{acc:BINARY:2},0040\n"
    assert (
        set_token_list_entry("# header\n", "[accBINARY2]", "0040")
        == "# header\n{acc:BINARY:2},0040\n"
    )
    assert (
        set_token_list_entry("", "{acc:BINARY:2}", "0040", style="bracket")
        == "[accBINARY2],0040\n"
    )
    with pytest.raises(UniversalTokensError):
        set_token_list_entry("", "accBINARY2", "0040", style="fancy")
    write_universal_tokens(TYPED_LIST_TEXT, tmp_path / "lib" / "opA.csv")
    rows = token_list_catalogue(
        {UNIVERSAL_TOKENS_ENV: str(tmp_path / "none.csv"), TOKEN_LISTS_DIR_ENV: str(tmp_path / "lib")},
        with_counts=True,
    )
    # A missing universal list reports the default style; the library list its own.
    assert [row.get("style") for row in rows] == ["typed", "typed"]


def test_format_token_list_renders_a_style_and_records_it() -> None:
    values = {
        "iccidICCID10NibbleSwap": "aa" * 10,
        "imsiIMSI8EncodeIMSI": "bb" * 8,
        "ICCID": "cc" * 10,
    }
    typed = format_token_list(values, comments=["from x"], style="typed")
    assert typed == (
        "# from x\n# style: typed\n{ICCID}," + "CC" * 10 + "\n"
        "{iccid:ICCID:10:nibble_swap}," + "AA" * 10 + "\n"
        "{imsi:IMSI:8:encode_imsi}," + "BB" * 8 + "\n"
    )
    entries, problems = parse_universal_tokens(typed)
    assert problems == [] and token_list_style(typed, entries) == ("typed", "directive")
    bracket = format_token_list({"iccid:ICCID:10:nibble_swap": "aa" * 10}, style="bracket")
    assert bracket == "# style: bracket\n[iccidICCID10NibbleSwap]," + "AA" * 10 + "\n"
    with pytest.raises(UniversalTokensError):
        format_token_list(values, style="fancy")


def test_placeholder_folds_and_renderers_cover_the_vendor_spellings() -> None:
    assert placeholder_key_fold("{iccid:ICCID:10:nibble_swap}") == placeholder_key_fold(
        "[iccidICCID10NibbleSwap]"
    )
    assert placeholder_key_fold("iccidICCID10SwapNibbles") == "iccid|ICCID|10|nibbleswap"
    assert placeholder_key_fold("pin1TEXT4utf8") == placeholder_key_fold("{pin1:TEXT:4}")
    assert placeholder_key_fold("{ICCID}") == "iccid"
    assert placeholder_key_fold_relaxed("{scp80_kic1:BINARY:16}") == placeholder_key_fold_relaxed(
        "scp80kic1BINARY16"
    )
    assert placeholder_key_fold_relaxed("ICCID") == ""
    assert [
        placeholder_literal_style(text)
        for text in ("{iccid:ICCID:10}", "[accBINARY2]", "{accBINARY2}", "accBINARY2", "{ICCID}")
    ] == ["typed", "bracket", "brace", "compact", None]
    assert format_placeholder_literal("imsiIMSI8EncodeIMSI", "typed") == "{imsi:IMSI:8:encode_imsi}"
    assert format_placeholder_literal("pin1TEXT4utf8", "typed") == "{pin1:TEXT:4:utf_8}"
    assert format_placeholder_literal("{pin1:TEXT:4:utf_8}", "compact") == "pin1TEXT4utf8"
    assert format_placeholder_literal("[accBINARY2]") == "{acc:BINARY:2}"
    assert (
        format_placeholder_literal("{iccid:ICCID:10:nibble_swap}", "compact")
        == "iccidICCID10NibbleSwap"
    )
    assert (
        format_placeholder_literal("{iccid:ICCID:10:nibble_swap}", "brace")
        == "{iccidICCID10NibbleSwap}"
    )
    assert (
        format_placeholder_literal("{msisdn:MSISDN:8:custom_mod}", "bracket")
        == "[msisdnMSISDN8custom_mod]"
    )
    assert format_placeholder_literal("ICCID", "typed") == "{ICCID}"
    assert format_placeholder_literal("{ICCID}", "compact") == "ICCID"
    with pytest.raises(ValueError):
        format_placeholder_literal("accBINARY2", "fancy")


def test_modifier_spellings_encode_alike_and_raw_values_match_across_them() -> None:
    snake = _record(0, "iccid", "ICCID", 10, "AA" * 10, "nibble_swap")
    camel = _record(1, "iccid", "ICCID", 10, "BB" * 10, "NibbleSwap")
    plain = _record(2, "iccid", "ICCID", 10, "CC" * 10)
    swapped = encode_inline_placeholder_value(snake, "8988201234567890123")
    assert swapped == encode_inline_placeholder_value(camel, "8988201234567890123")
    assert swapped != encode_inline_placeholder_value(plain, "8988201234567890123")
    text = _record(3, "pin1", "TEXT", 4, "DD" * 4, "utf_8")
    assert encode_inline_placeholder_value(text, "1234") == b"1234"

    raw = match_inline_raw_values([snake, camel], {"{iccid:ICCID:10:nibble_swap}": "98" * 10})
    assert raw == {"iccidICCID10nibble_swap": "98" * 10, "iccidICCID10NibbleSwap": "98" * 10}
    assert lookup_raw_value({"[iccidICCID10NibbleSwap]": "98" * 10}, "iccidICCID10nibble_swap") == (
        "98" * 10
    )
    assert lookup_raw_value({"accBINARY2": "0040"}, "{acc:BINARY:4}") is None


def test_raw_values_keyed_by_the_other_variable_spelling_still_serve_their_occurrences() -> None:
    typed = _record(0, "scp80_kic1", "BINARY", 16, "AA" * 16)
    compact = _record(1, "scp80kic1", "BINARY", 16, "BB" * 16)
    stored = {"scp80kic1BINARY16": "11" * 16}

    assert match_inline_raw_values([typed], stored) == {"scp80_kic1BINARY16": "11" * 16}
    assert lookup_raw_value(stored, "{scp80_kic1:BINARY:16}") == "11" * 16
    # The same spelling is preferred; the relaxed rung only applies without one.
    assert records_for_raw_key([typed, compact], "scp80kic1BINARY16") == [compact]
    assert records_for_raw_key([typed], "scp80kic1BINARY16") == [typed]
    assert records_for_raw_key([typed], "ICCID") == []


def test_an_entry_that_names_the_variable_answers_in_any_spelling() -> None:
    from Tools.ProfilePackage.saip_universal_tokens import (
        UniversalTokenList,
        entry_hex_for_record,
        layered_universal_match,
        parse_universal_tokens,
    )

    entries, problems = parse_universal_tokens(
        "PUK1,3131313131313131\n"
        "{iccid:ICCID:10},8988201234567890123F\n"
        "{pin1:TEXT:4},31323334\n"
        "{scp80_kic1:BINARY:16},11223344556677889900AABBCCDDEEFF\n"
        "{puk2:TEXT:8},3232323232323232\n"
        "puk2,3333333333333333\n"
        "{adm1:BINARY:8},\n"
    )
    assert problems == []
    token_list = UniversalTokenList(path=None, loaded=True, text="", entries=tuple(entries), problems=())
    puk1 = _record(0, "puk1", "TEXT", 8, "AA" * 8, "utf_8")
    iccid = _record(1, "iccid", "ICCID", 10, "BB" * 10, "nibble_swap")
    pin1 = _record(2, "pin1", "TEXT", 8, "CC" * 8)
    kic = _record(3, "scp80kic1", "BINARY", 16, "DD" * 16)
    puk2 = _record(4, "puk2", "TEXT", 8, "EE" * 8, "utf_8")
    adm1 = _record(5, "adm1", "TEXT", 8, "FF" * 8)
    match = layered_universal_match([puk1, iccid, pin1, kic, puk2, adm1], [token_list])

    # A plain token line supplies its bytes at the occurrence's width; a
    # header-order ICCID entry is re-encoded nibble-swapped; the underscore
    # rule still applies; the exact spelling wins over the plain line.
    assert match.raw_values == {
        "puk1TEXT8utf_8": "3131313131313131",
        "iccidICCID10nibble_swap": "988802214365870921F3",
        "scp80kic1BINARY16": "11223344556677889900AABBCCDDEEFF",
        "puk2TEXT8utf_8": "3232323232323232",
    }
    by_key = {item["key"]: item for item in match.matched}
    assert by_key["puk1TEXT8utf_8"]["entry"] == "PUK1"
    assert by_key["iccidICCID10nibble_swap"]["re_encoded"] is True
    assert "re_encoded" not in by_key["puk2TEXT8utf_8"]
    reasons = {item["key"]: item["reason"] for item in match.unmatched}
    # A value that cannot be made to fit, and a declaration, are named with their line.
    assert reasons["pin1TEXT8"].startswith("list line 3: {pin1:TEXT:4} holds '1234', which does not fit")
    assert reasons["adm1TEXT8"] == "list line 7: declared without a value"
    assert entry_hex_for_record(entries[1], iccid) == "988802214365870921F3"
    assert token_list.entries_for_variable("SCP80KIC1") == [entries[3]]
    assert token_list.entries_for_variable("") == []


def test_a_line_without_a_value_declares_the_placeholder_and_answers_nothing() -> None:
    from Tools.ProfilePackage.saip_universal_tokens import (
        UniversalTokenList,
        layered_universal_match,
        parse_universal_tokens,
        set_token_list_entry,
        universal_token_defs,
    )

    entries, problems = parse_universal_tokens("{smsc:MSISDN:6:nibble_swap},\n{ki:BINARY:16},00112233445566778899AABBCCDDEEFF\n")
    assert problems == []
    assert [(entry.name, entry.declared_only) for entry in entries] == [
        ("{smsc:MSISDN:6:nibble_swap}", True),
        ("{ki:BINARY:16}", False),
    ]
    token_list = UniversalTokenList(path=None, loaded=True, text="", entries=tuple(entries), problems=())
    smsc = _record(0, "smsc", "MSISDN", 6, "AA" * 6, "nibble_swap")
    ki = _record(1, "ki", "BINARY", 16, "BB" * 16)
    match = layered_universal_match([smsc, ki], [token_list])
    assert set(match.raw_values) == {"kiBINARY16"}
    assert match.unmatched[0]["reason"].endswith("declared without a value")
    assert universal_token_defs(["smsc", "ki"], token_list) == {}
    # The writer declares with an empty value and later fills it in place.
    text = set_token_list_entry("", "{smsc:MSISDN:6:nibble_swap}", "")
    assert text == "{smsc:MSISDN:6:nibble_swap},\n"
    assert set_token_list_entry(text, "[smscMSISDN6NibbleSwap]", "0100000000F1") == (
        "{smsc:MSISDN:6:nibble_swap},0100000000F1\n"
    )
