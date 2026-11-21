<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# SAIP Templates and Tokens

This guide describes how YggdraSIM authors placeholder-bearing SAIP
profile templates, how token definitions are carried alongside those
templates, and how the shell and the SAIP transcode TUI cooperate to
author, export, apply, migrate, and mass-produce profiles.

The template surface lives inside the `Tools/ProfilePackage/` subsystem.
This document is the authoritative entry point for operators. The
related reference pages are:

- `HELP TOKENS` -- shell command reference for token management
- `HELP TEMPLATE` -- shell command reference for template creation /
  application
- `HELP EDIT` -- decoded-editing and roundtrip encoding

## Mental model

A SAIP profile is a deterministic sequence of tagged byte blobs. A
**template** is the same document, but certain byte ranges are replaced
by placeholder tokens that expand at build time.

Two placeholder styles exist. Only one style is active per document:

- **Brace style** (default): `{ICCID}`, `{#ICCID}` (derived length)
- **Bracket style** (SGP-32 style sources): `[ICCID]`, `[#ICCID]`

The active style is declared once in the document metadata:

```json
"__ygg_placeholder_style__": "brace"
```

Token definitions live in a sibling metadata key:

```json
"__ygg_token_defs__": {
  "ICCID": "89881111111111111112",
  "IMSI": { "pattern_hex": "FF", "byte_len": 8 }
}
```

Three token value shapes are accepted:

1. A hex string (spaces tolerated) that resolves to those exact bytes.
2. `{"zero_len": N}` - N zero bytes.
3. `{"pattern_hex": "XX", "byte_len": N}` - N repetitions of the
   single-byte pattern.

Any other shape is rejected by the validator.

## Placeholder kinds

Three placeholder kinds are recognised inside tagged hex fields:

- Content: `{NAME}` / `[NAME]` expands to the token's bytes.
- Length companion: `{#NAME}` / `[#NAME]` expands to the BER-TLV length
  prefix (short form for ≤127, long form for longer content).
- Literal: everything outside the placeholder regex is copied verbatim.

The canonical length-companion form is:

```
{#ICCID}{ICCID}
```

Older hand-authored templates often look like `0A{ICCID}` - a literal
byte followed by the content placeholder. The `RETOKENISE-LENGTHS`
command (or the in-TUI "migrate companions" prompt) rewrites these to
the canonical form whenever the literal exactly matches the current
BER-TLV length.

## Template authoring lifecycle

### 1. Author

Either start from a preset via `NEW-TEMPLATE` / `NEW-PROFILE-WIZARD`,
or open an existing profile and manually annotate the fields you want
to parameterise.

The wizard now includes a dedicated token-declaration step when the
output format is JSON. You can declare any number of tokens, choose
brace or bracket style, and commit the declarations alongside the
generated template.

### 2. Export tokens to a sidecar

A sidecar is a standalone JSON file that carries only the
`__ygg_placeholder_style__` and `__ygg_token_defs__` metadata:

```
TOKENS EXPORT my_template.json my_template.tokens.json
```

Sidecars are ideal for sharing token values across teams without
redistributing the full template and for version-controlling the token
set independently.

### 3. Apply a sidecar onto a tokenless template

```
TOKENS APPLY template_without_defs.json my_template.tokens.json
```

The command refuses to overwrite an existing non-empty
`__ygg_token_defs__` block, protecting against accidental merges.

### 3b. Round-trip with personalisation-data CSV files

Personalisation data shipped from third-party issuance tooling is
commonly distributed as a plain two-column CSV -- the convention used
across the TCA SAIP ecosystem. One line per variable, `name,hex`, with
`#`-prefixed comment lines separating independent personalisation-data
sets when multiple profile packages share a single file. YggdraSIM
round-trips between the JSON sidecar and this CSV via:

```
EXPORT-TOKENS-CSV my_template.json my_template.csv
IMPORT-TOKENS-CSV personalisation.csv personalisation.tokens.json
```

Multi-block CSV input produces `personalisation_1.tokens.json`,
`personalisation_2.tokens.json`, ... -- one sidecar per CSV block -- so
each set can be fed to `APPLY-TOKENS` independently. Pattern-only token
definitions (defs that carry only `pattern_hex` / `byte_len`) are
silently skipped on export, because the CSV format has no column shape
for placeholder patterns.

### 3c. Transformation functions inside hex templates

Both placeholder styles accept a transformation-function form:

```
[Func(NAME)]    bracket style
{Func(NAME)}    brace style
[#Func(NAME)]   companion that emits the BER-TLV length of Func(NAME)
```

Two functions are bundled:

- `SwapNibbles(NAME)` -- byte-wise nibble swap, mirroring the
  ETSI TS 102 221 §13.2 (EF.ICCID) and 3GPP TS 31.102 BCD encodings.
  Example: token value `8988001304080000014F` expands to
  `988800314080000010F4`. Useful for feeding nibble-swapped EF.ICCID
  content from an upright ICCID source.
- `EncodeEfImsi(NAME)` -- wraps an ASCII IMSI (1..15 digits) into the
  EF.IMSI body per 3GPP TS 31.102 §4.2.2: length byte, then a
  parity-tagged digit-1 byte (low nibble `0x9` for odd digit counts,
  `0x1` for even per the spec's bit-4 parity flag), then 7
  nibble-swapped digit-pair bytes (`F`-padded for odd counts).

These transformations resolve against the same `__ygg_token_defs__`
table; nothing else in the template surface changes.

### 4. Edit tokens in-place

Three interchangeable surfaces exist:

- Flat shell commands: `ADD-TOKEN`, `SET-TOKEN`, `REMOVE-TOKEN`,
  `RENAME-TOKEN`, `RETOKENISE-LENGTHS`, `LIST-TOKENS`.
- Unified namespace: `TOKENS ADD`, `TOKENS SET`, `TOKENS REMOVE`,
  `TOKENS RENAME`, `TOKENS RETOKENISE-LENGTHS`, `TOKENS LIST`,
  `TOKENS EXPORT`, `TOKENS APPLY`, `TOKENS HELP`.
- TUI token manager modal (`Ctrl+K` inside SAIP Transcode TUI) with
  row-level add / edit-value / rename / delete actions.

Destructive commands (`REMOVE-TOKEN`, `RENAME-TOKEN`,
`RETOKENISE-LENGTHS`) accept `--dry-run` (preview only) and
`--no-backup` (skip the automatic `.bak` copy) flags.

Length-companion migration is offered automatically inside the TUI
whenever a token value change would make a pre-existing
`<length>{NAME}` pattern valid for rewriting to `{#NAME}{NAME}`.

### 5. Auto-reload defs edited elsewhere

While a profile is open in the SAIP Transcode TUI, the app watches the
source JSON file's mtime. If an external shell (for example, another
terminal running `SET-TOKEN`) updates the on-disk
`__ygg_token_defs__`, the TUI raises a modal prompt offering to import
the new defs into the active buffer without discarding any other
unsaved edits.

### 6. Apply a template

```
APPLY-TEMPLATE my_template.json my_profile.der
```

The command fully resolves all placeholders, re-encodes the profile to
DER, and refuses to proceed if any token is still undefined.

### 7. Mass produce profiles

`GENERATE-BATCH` uses a template and a list of per-record value sets
to produce many unique profiles in a single invocation. Derived-length
companions (`{#NAME}`) automatically track per-record length changes,
so records with different-length values remain BER-valid without any
manual intervention.

## Lint and the template-mode banner

The lint engine recognises template mode. When a document contains
unresolved placeholders:

- `FAIL`/`WARN` findings that stem from placeholder-affected paths are
  downgraded to informational findings.
- A dedicated `YRL-TPL-OK` informational banner summarises the
  situation and lists the exact commands that will resolve the
  template:

  ```
  Run APPLY-TOKENS my_template.json my_template.tokens.json
  Run APPLY-TEMPLATE my_template.json my_profile.der
  Run GENERATE-BATCH my_template.json records.csv out_dir/
  ```

The TUI surfaces the same state via a persistent badge in the subtitle
(`TEMPLATE MODE · 2 unresolved`) and the placeholder HUD strip
(`4 placeholder(s) · 3 content · 1 length · 1 unresolved ·
Ctrl+Alt+N / Ctrl+Alt+P to cycle`). `Ctrl+R` toggles a read-only
resolved-preview rendering that shows what the final profile would
look like after placeholder expansion.

## Troubleshooting

### "Undefined placeholder token 'NAME'"

Open the template and run `TOKENS LIST <template.json>` to see which
tokens are defined. Missing tokens can be added either by loading a
sidecar (`TOKENS APPLY`) or by declaring them directly with
`TOKENS ADD` / `TOKENS SET`.

### "Lint downgraded but DER encoding still fails"

Template mode permits undefined placeholders for **lint**, but
encoding requires every token to resolve. Run `TOKENS LIST` to locate
the unresolved names, then define or remove them before retrying
`APPLY-TEMPLATE`.

### "I renamed a token but the template still references the old name"

`RENAME-TOKEN` rewrites references by default. If you renamed via the
TUI and declined the rewrite prompt, re-run:

```
TOKENS RENAME <template.json> <old_name> <new_name>
```

### "Length byte after my edit no longer matches token length"

Either use the canonical companion form (`{#NAME}{NAME}`) so the
length is recomputed automatically, or run `RETOKENISE-LENGTHS` /
`TOKENS RETOKENISE-LENGTHS` to migrate existing literal-length sites
to the companion form.

## Inline typed hex placeholders (vendor templates)

Some vendor templates ship a profile as ASCII hex, or as ASN.1 value
notation, with typed placeholders baked directly into the byte values:

```
62128202412183026F078B036F06068001098800810908{imsi:IMSI:8:encode_imsi}80027F20
iccid '[iccidICCID10]'H
```

Two grammars are accepted. The typed form is
`{<var>:<TYPE>:<byte_length>[:<modifier>]}`; it is the default spelling,
the one every writer uses unless a list's `# style:` line or its entries
decide otherwise. The compact form folds the
type and length into the name: `[iccidICCID10]`, `{imsiIMSI8}`,
`[puk1BINARY8]`, `[iccidICCID10nibbleswap]`. Recognised types are
`ICCID`, `IMSI`, `MSISDN`, `BINARY`, `TEXT`, `RI` and `OPLMN` (the last
two carry raw bytes like `BINARY`); the byte length is the width of the
region the placeholder occupies, and a modifier such as `nibbleswap`
selects the EF wire form of an ICCID.

When `OPEN` / `USE` or the GUI's Package > Open selects a `.varder`,
`.hex`, `.txt` or `.asn` file carrying this shape:

1. Each placeholder is replaced with a deterministic, per-index sentinel
   of the declared byte length so the stream decodes as valid DER.
2. The literal, variable name, type, byte length, modifier and sentinel
   are recorded per occurrence (the transcode path writes them to
   `<cache>.placeholders.json`; the GUI keeps them on the session).
3. Every projection shows the literal where the sentinel bytes sit: the
   PE JSON tab (`"iccid": "[iccidICCID10]"`), the profile-header editor,
   the encoded-bytes card, the file Data / ASN.1 hex dumps (placeholder
   bytes print as `··` with a legend), the decoded-fields panel (a
   read-only placeholder entry), and single-PE JSON exports. The
   sentinel never reaches the operator as if it were data.

### Storing values in the Variables panel

The session keeps its placeholders for its whole life. The Variables
panel (`Ctrl+E`, ribbon Tokens > Variables) lists one row per
placeholder: the name, a value input, the type and width, and a Source
badge that says where the value comes from: **Typed** (a value stored
through the panel, which wins over every list), **Profile list** (the
test-value list bound to this profile), **Universal list**, **List
value** (bytes stored from a list the session no longer names), or
**Unset** (nothing yet; the test profile is blocked). Typing a value
and pressing Enter stores it (`saip.set_variable`) after every
occurrence's typed encoder accepted it; the placeholder stays in the
template. **Use list value** drops a typed value and takes the lists'
answer again; a catalog or token row offers **Reset** to its source
instead. A value typed and not yet stored is a draft of the package,
kept while the operator switches packages or elements. Values show in
full in the panel, secret-classified names included; the log and the
message text never carry them. The panel header counts
`N of M variables have a stored value`. **Set a variable by name**,
folded under the rows, covers a name the table does not list: a legacy
`{NAME}` token or a catalog variable. A field that takes a placeholder
opens the panel on its new variable.

The panel docks at the right edge of the workbench, so the package drawer,
the PE list and the detail pane stay live while values are bound. `Ctrl+E`
opens it, focuses it while it is open without focus, and closes it when it
has focus; `Esc` closes it from inside. It repaints only when the listing
changed and keeps a half-typed value across a reload.

A length byte that counts a placeholder-filled BCD field follows the stored
value. An 11-digit MSISDN in an 8-byte `[msisdnMSISDN8NibbleSwap]` slot
encodes to six digit bytes and two bytes of `FF` filler, so the record's
*Length of BCD number/SSC contents* byte reads `07`, not the template's
`09` (3GPP TS 31.102 §4.4.2.3): the digit coding of TS 24.008 §10.5.4.7
never produces `FF` inside the counted span. The file view shows the
reconciled byte with the value (a *Length byte* row under the placeholder
rows, and the record wizards decode it), the Set summary names it, a
generated test profile writes it, and the template keeps its own byte.
The same holds for the dialling-number tail of EF.ADN, EF.FDN, EF.SDN,
EF.BDN, EF.MBDN, EF.LND, EF.ICE_DN, EF.ICI, EF.OCI and EF.CFIS, for the two
address lengths of EF.SMSP (§4.2.27, per TS 23.040 §9.1.2.5 and TS 24.011
§8.2.5.2), for the length byte of EF.IMSI (§4.2.2) and for the
additional-data records of EF.EXT1 to EF.EXT7 (§4.4.2.4). The linter
reports what nothing fixes as `YRL-LEN-001` (dialling-number tail),
`YRL-LEN-002` (EF.IMSI), `YRL-LEN-003` (EF.SMSP) and `YRL-LEN-004`
(extension records), WARN: a length byte that reaches into `FF` filler,
stops short of the digits, or marks a field unused while it holds digits.
A record that still carries an unresolved placeholder is not linted for
its length byte. Other nested lengths cannot drift through a token: TEXT,
BINARY, ICCID and IMSI placeholders must fill their declared width exactly,
so only the F-padded BCD number types need this.

The IMSI placeholder type writes digit 1 and the odd/even indication of
TS 24.008 §10.5.1.4 itself (low nibble 9 for an odd digit count, 1 for an
even one) and the F endmark; the length byte in front of it follows the
digit count. `YRL-IMS-002`, `-003` and `-005` check exactly that coding.

Two exports are then available, both from the Variables panel's buttons
and from Save As:

- **Save template** -- varder, ASN.1 or tagged JSON. Placeholders are
  written back as their literals. Tagged JSON embeds the stored values
  in its `__ygg_inline_placeholders__` block; varder and ASN.1 cannot
  carry them, so a `<stem>.variables.json` sidecar is written beside the
  template (`saip.save_package` input `write_variable_sidecar`, default
  on). Opening a template later restores the values from either place,
  validating each one first.
- **Generate test profile** -- DER or HEX (`saip.generate_test_profile`;
  Save As to a `.der` or `.hex` target does the same). Every placeholder
  is replaced, in a copy of the sequence, by the value its row in the
  Variables panel shows: a typed value, else the test value of the
  profile's list or the universal one, which are read again at that
  moment so an entry added since the package opened counts. The session
  stays bound to its template, so a template save is still possible
  afterwards. The run refuses, naming the variables, while any
  placeholder has no value anywhere, and reports the value and source
  used for each variable. `resolve_variables=true` on
  `saip.save_package` produces the same complete document in ASN.1 or
  JSON form.

The `<stem>.variables.json` sidecar carries the operator's typed input,
not encoded bytes:

```json
{
  "schema": "yggdrasim.saip-inline-variables/v1",
  "created_from": "profile.varder",
  "values": { "iccid": "8988201234567890123", "puk1": "3131313131313131" }
}
```

### Declaring a placeholder in the workbench

A placeholder is declared where its bytes go, in any package the
workbench opens (DER, hex, varder, ASN.1, tagged JSON). The JSON tab,
the Data tab's editors, the raw body and record editors and the header's
ICCID take the literal `{var:TYPE:len[:modifier]}` in place of the hex;
Apply registers the occurrence, the projections show the literal from
then on, a varder or ASN.1 save writes it, and a DER / HEX export
substitutes the value. Three affordances put the literal there without
typing it:

- **Drag or copy from the Variables panel.** Every listed variable, and
  below the rows every universal-list placeholder the package does not
  carry yet (listed the same way, with its test value), is a chip: drag it
  into a hex field of the Data tab, the
  record or whole-file hex, a header input or the JSON tab, or click it to
  copy its placeholder and paste it there. A dropped or pasted literal
  overwrites the bytes it stands for after the landing point (a landing
  inside a byte moves to the byte boundary), so the field keeps its width;
  Apply then registers it. Dropping `{smsc:MSISDN:6:nibble_swap}` after
  the length and TON/NPI bytes of an EF.SMSP service-centre field keeps
  the field at twelve bytes.
- **Insert variable...** on the JSON tab (at the caret, with the same
  overwrite), on the raw hex, ICCID and IMSI editors and on the header
  card's ICCID row opens the picker: a variable the package or the
  universal list already names (a narrower one is placed at a byte
  offset of the field, a wider one is greyed out), or a new one with its
  name, type, width, modifier, an optional value and **Save to the
  universal list** (on by default, so the variable is offered in every
  profile). Select bytes first to replace only those (**The selected
  bytes**). The IMSI editor keeps the length byte of EF.IMSI in front of
  the eight-byte placeholder (3GPP TS 31.102 section 4.2.2).
- **Define a variable** in the Variables panel adds a placeholder to the
  universal list without touching the package, with its value or
  declared alone (`saip.define_variable`).

The header follows the files. "Sync from EF.ICCID" on a header whose
EF.ICCID holds `{iccid:ICCID:10:nibble_swap}` makes the header's ICCID
`{iccid:ICCID:10}` (the same variable in header order) instead of copying
bytes, and "Sync from EF.SMSP" on an SMS-PP bearer whose EF.SMSP service
centre holds `{smsc:MSISDN:6:nibble_swap}` puts the same placeholder in
the bearer's dialing number; the value the file resolves to becomes the
variable's typed value when the following occurrence has none, so one
value drives both on export. The dialing-number box of an SMS-PP bearer
takes an MSISDN placeholder directly, dropped, pasted or typed, and the
connectivity blob carries it where the digit bytes go.

A new occurrence is answered by the test-value lists where they can. One
without a value is accepted and flagged: the Variables panel shows
**Unset** (for an IMSI or MSISDN placeholder with the note that the
length byte which counts it cannot be reconciled), the apply log says so,
Generate test profile refuses, and the validate run reports `YRL-VAR-001`
with a jump to the file. A list entry written as `name,` with no value
declares the placeholder for the pickers and the listings without
answering it; `{smsc:MSISDN:6:nibble_swap},0100000000F1` answers it.
Removing the literal from a field retires the occurrence and the values
stored for it. An editor that encodes structured fields and ignores a hex
mirror refuses a literal typed into the mirror, naming where it goes.
**Set a variable by name** refuses a name no placeholder of the package
carries, so a value never lands in an orphan token definition.

### Test-value lists (before sign-off)

A template under review is usually built into test profiles many times
before its values are final. A **test-value list** answers placeholder
literals with test bytes so those builds need no per-template typing.
Two kinds of list exist, in one format:

- The **universal list** is one operator-wide file that answers every
  template: `~/.yggdrasim/saip_universal_tokens.csv` by default, or the
  path in `YGGDRASIM_SAIP_UNIVERSAL_TOKENS` (Environment > Configuration).
- A **profile-specific list** is a named entry in the library
  (`~/.yggdrasim/saip_token_lists/<name>.csv`, or the directory in
  `YGGDRASIM_SAIP_TOKEN_LISTS`) or any `.csv` file. A template **binds**
  one such list on top of the universal one; its entries answer a
  placeholder first, so it only needs the values that differ.

Every list is one `name,hex` line per placeholder literal, `#` for
comments, an optional `name,value` header. The name is written in any of
the template spellings: typed `{iccid:ICCID:10:nibble_swap}`, compact
`iccidICCID10NibbleSwap`, or the compact body in braces or brackets
(`[scp80kic1BINARY16]`). Matching is spelling-independent: the variable,
the type, the width and the modifier are compared; a modifier's spelling
does not matter (`nibble_swap`, `NibbleSwap` and `SwapNibbles` are one,
and `utf8` on a TEXT placeholder counts as none); when nothing matches,
the variable is compared without its underscores, so
`{scp80_kic1:BINARY:16}` answers `[scp80kic1BINARY16]`; and when still
nothing matches, an entry that merely names the variable answers, in
whatever spelling: a plain `PUK1,3131313131313131` line supplies its
bytes to `{puk1:TEXT:8:utf_8}`, and a typed entry of the same type with
another width or modifier travels as its value, re-encoded for the
occurrence (`{iccid:ICCID:10},8988...123F` answers
`{iccid:ICCID:10:nibble_swap}` nibble-swapped). A value that cannot be
made to fit is reported with the entry's line number. An exact entry
always wins over a looser one. The value is the wire form: an ICCID
already nibble-swapped, an MSISDN already padded, TEXT as UTF-8 bytes,
so it is spliced verbatim. The width the name declares must equal the
byte count. A line that fails that, or is not hex, is reported with its
line number and never applied; the other lines still load. Only a line
that is not `name,value` at all refuses a save. The files live outside
every checkout and are never tracked.

Each list has a **style**, the spelling its names are written in:
`typed` (`{var:TYPE:len[:modifier]}`), `compact` (`varTYPElen[Modifier]`),
`brace` or `bracket` (the compact body in `{}` or `[]`); the typed style
spells a known modifier in snake_case (`nibble_swap`, `encode_imsi`,
`utf_8`), the compact styles as `NibbleSwap`, `EncodeIMSI`, `utf8`. A
`# style: typed` line declares it; without one the first placeholder line
decides, and an empty list is typed. The style governs what the writers
put on a line,
never what the list answers: `TOKEN-LISTS SET` and the editor write an
entry in the list's style whatever spelling was typed (an entry found
through the underscore rule keeps its own variable spelling), and an
export into an existing list keeps that list's style. A new list is
written typed, the only spelling the tool chooses on its own, unless
`STYLE=` names one (`STYLE=universal` follows the universal list),
recording it as a `# style:` line. A list is therefore kept in the
spelling its templates use, and the lists a template consults may each
use a different one.

Resolution per occurrence is fixed: a stored value (typed, or from the
template's sidecar or JSON block) wins, then the bound list, then the
universal list. Opening a template seeds every occurrence that has no
stored value this way, so a test profile can be exported at once and
only the values that matter are replaced;
`YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS=0` opens templates unresolved
instead, and the lists are then applied on demand. The seeding is not
an edit: the session opens clean. Applying the lists stores the bytes
per occurrence; the placeholders stay in the template exactly as the
token editor keeps typed values, and a DER / HEX export substitutes
them. A typed value stored for a variable keeps precedence over the
lists (the editor's *Replace typed values* option drops it); setting a
typed value later replaces the list bytes for that variable, and Reset
clears either.

The binding travels with the template. Tagged JSON saves carry it, with
the bytes, in the `__ygg_inline_placeholders__` block (`test_value_list`
and `raw_values`); varder and ASN.1 saves put them in the
`<stem>.variables.json` sidecar next to the typed values. Until a
template is saved, and for templates in read-only locations, the
machine-local store `<runtime>/state/saip_test_value_lists.json`
remembers the binding per absolute path. A bound list that has gone
missing is reported on open and the universal list answers alone.

```json
{
  "schema": "yggdrasim.saip-inline-variables/v1",
  "values": { "iccid": "8988201234567890123" },
  "raw_values": { "puk1BINARY8": "3132333435363738" },
  "test_value_list": "operator-a"
}
```

In the GUI the Variables panel (`Ctrl+E`) carries the controls for an
inline template, above its rows: the **Test-value list** selector binds
the universal list, a library list or another file
(`saip.set_test_value_list`, which also applies the lists to every
occurrence without a typed value); **Apply test values** runs
`saip.apply_universal_tokens`; **Export list** writes the profile's
current values as a list (`saip.export_test_value_list`: typed values in
wire form, secret-classified names included, in the universal list's
style or the *Name style* chosen, optionally binding the profile to it);
**Edit lists** opens the list editor (`saip.universal_tokens`), which
shows any list with the rejected lines, saves an edited copy, creates a
new library list from the contents, or deletes one; **Generate test
profile** writes the DER or HEX with every row's value, the lists
answering what has no typed value (read again at that moment). The
ribbon's Tokens group carries two entries, Variables and Generate test
profile; the
list actions are reachable from the panel and from the action palette.
Every placeholder row in a field or a file then
shows the literal, its declared width and a `test value` chip with the
bytes it will take. Whoever holds the profile sees every value in the
workbench: a secret-classified name (`pin1`, `puk1`, `adm1`, `ki`, the
SCP80 keys) keeps its *Sensitive* mark, nothing is masked, and only log
lines and message text stay clear of the value. A field whose value is a
placeholder shows the bytes with the literal in place, the bytes the
export will write once every placeholder has a value, and one binding
row per placeholder; the raw placeholder model sits behind *Show JSON*.
A placeholder embedded in a longer value, such as a PIN's
`[pin1TEXT4utf8]FFFFFFFF`, binds the same way and the row names the
bytes around it. In a file's hex pane a resolved placeholder shows its
bytes in place of the sentinel, flagged above the pane, and an
unresolved one shows its literal; *Apply hex* puts the template marker
back, so a whole-file edit can never overwrite a placeholder with data.
`{NAME}` tokens of a tagged JSON template that match a list entry by name
receive a `hex` definition the same way.

### Shell

```
VARIABLES
VARIABLES SET <name>=<value> [<name>=<value> ...]
VARIABLES CLEAR <name> [...]
VARIABLES USE <universal|list|file.csv>
VARIABLES FILL [OVERWRITE]
VARIABLES GENERATE <out.der|out.hex>          (EXPORT is the same)
VARIABLES EXPORT-LIST <name|out.csv> [OVERWRITE] [BIND]
VARIABLES LISTS [LIST | SHOW <list> | SET ... | UNSET ... | DELETE ... | BIND ... | CHECK ... | EXPORT ...]
VARIABLES NORMALISE [IN-PLACE | OUTPUT=<file>] [--no-backup]
VARIABLES DEFINE <{var:TYPE:len[:modifier]}> [<value>] [LIST=<list>]
```

is the one verb over the active template (`USE <template>` first), for
both grammars: a varder / hex / ASN.1 template with inline typed
placeholders, and a tagged JSON template with `{NAME}` tokens. The
listing shows every placeholder with its type, width, the value it takes
and its source: `typed` (a value in the template's `<stem>.variables.json`,
its JSON placeholder block, or a token definition), the name of the list
whose entry it holds, `(from list on export)` when a list answers an
occurrence that has no stored value, or `none`. `SET` validates each value
against every occurrence's encoder and writes it where the template keeps
its values (a `{NAME}` template gets a `hex` definition; `ICCID=` and
`IMSI=` go through their typed encoders); `CLEAR` drops it; `USE` is
`TOKEN-LISTS BIND`; `FILL` is `APPLY-UNIVERSAL-TOKENS`; `GENERATE`
(`EXPORT` is the same spelling) is `MATERIALIZE-TEMPLATE` (or
`APPLY-TEMPLATE` for a `{NAME}` template) with the lists consulted for
whatever has no typed value, writing DER or, for a `.hex` target, its
ASCII hex; `EXPORT-LIST` is
`TOKEN-LISTS EXPORT`; `LISTS` is `TOKEN-LISTS`. `NORMALISE` respells a
vendor template's inline placeholders in the typed form, the only one the
tool writes: it reports each rewrite, `IN-PLACE` writes the template (a
`.bak` copy first unless `--no-backup`), `OUTPUT=` writes elsewhere; the
occurrence keys do not change, so the values file keeps answering. The
GUI's Variables panel offers the same as **Typed spelling** while a
template carries a compact literal. `DEFINE` adds a placeholder to a
test-value list, with its value (typed input or the exact bytes as hex)
or declared alone, which the listing shows as `declared, no value`. The long-form verbs below stay for
scripts and for the cases the one verb does not cover (exports in another
style, batch runs); `HELP TOKENS` lists them.

```
MATERIALIZE-TEMPLATE <template.varder|.asn|.json> <out.der|out.hex> [NAME=value ...] [--values <file.variables.json>] [--universal]
```

builds a complete DER (or, for a `.hex` target, its ASCII hex) from an
inline-placeholder template. Values come
from the `<stem>.variables.json` sidecar next to the template, from
`--values`, or from `NAME=value` arguments (later sources win); every
placeholder needs one. `--universal` fills the occurrences that still
lack a typed value from the template's test-value lists, the bound list
first, and names the ones no list can serve. The template file is left
untouched. `MATERIALISE-TEMPLATE` is accepted as a spelling alias.
Templates that use `{NAME}` tokens with `__ygg_token_defs__` keep using
`APPLY-TEMPLATE` / `GENERATE-PROFILE` / `GENERATE-BATCH`.

```
UNIVERSAL-TOKENS [SHOW|PATH|CHECK <template>]
APPLY-UNIVERSAL-TOKENS <template> [<out>] [OVERWRITE]
TOKEN-LISTS [LIST]
TOKEN-LISTS SHOW <list>
TOKEN-LISTS SET <list> <literal> [<hex>]
TOKEN-LISTS UNSET <list> <literal>
TOKEN-LISTS DELETE <name|file.csv>
TOKEN-LISTS BIND <template> <list>
TOKEN-LISTS CHECK <template>
TOKEN-LISTS EXPORT <template> <name|out.csv> [OVERWRITE] [BIND] [STYLE=<style>]
```

`UNIVERSAL-TOKENS` prints the universal list (or its path), including
the rejected lines; `CHECK` reports which of a template's placeholders it
answers. `APPLY-UNIVERSAL-TOKENS` records the universal bytes on disk: a
tagged JSON template gains `hex` definitions for the `{NAME}` tokens the
list answers (written to `<out>` or in place); a varder / hex / ASN.1
template keeps its placeholders and gets `raw_values` in its
`<stem>.variables.json` (`<out>` names another sidecar). `OVERWRITE`
replaces definitions and values that already exist.

`TOKEN-LISTS` manages every list, where `<list>` is `universal`, a
library name or a `.csv` path: `LIST` shows the catalogue with the usable
and rejected line counts, `SHOW` one list, `SET` and `UNSET` rewrite one
line (a library list is created on first `SET`), `DELETE` removes a
library list or file, never the universal one. `BIND` records a
template's bound list where the loader reads it (`<stem>.variables.json`,
or the placeholder block of a tagged JSON template) and in the
machine-local store; `CHECK` reports which occurrences the template's
lists answer and which list answers each; `EXPORT` writes the template's
current values (typed values in wire form, test values as stored) as a
reusable list, typed unless the destination list already has a style or
`STYLE=` names one (`universal`, `typed`, `compact`, `brace`, `bracket`),
`BIND` making it the template's bound list. All of them
are also reachable as `TOKENS UNIVERSAL`, `TOKENS APPLY-UNIVERSAL` and
`TOKENS LISTS`.

## Standards and references

- GSMA SGP.22 / SGP.32 - profile metadata and placeholder patterns
- GlobalPlatform Card Specification v2.3 - TLV layout
- ETSI TS 102 221 - BER-TLV length encoding used by length companions
- ISO/IEC 7816-4 - APDU framing (consumed by `APPLY-TEMPLATE`)
