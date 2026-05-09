# SAIP Templates and Tokens

This guide describes how YggdraSIM authors placeholder-bearing SAIP
profile templates, how token definitions are carried alongside those
templates, and how the shell and the SAIP transcode TUI cooperate to
author, export, apply, migrate, and mass-produce profiles.

The template surface lives inside the `Tools/ProfilePackage/` subsystem.
This document is the authoritative entry point for operators. The
related reference pages are:

- `HELP TOKENS` — shell command reference for token management
- `HELP TEMPLATE` — shell command reference for template creation /
  application
- `HELP EDIT` — decoded-editing and roundtrip encoding

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
  "ICCID": "8988201234567890123",
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

Some vendor templates ship a profile as ASCII hex with typed
placeholders baked directly into the hex body:

```
62128202412183026F078B036F06068001098800810908{imsi:IMSI:8:encode_imsi}80027F20
```

The grammar is `{<var>:<TYPE>:<byte_length>[:<modifier>]}`. The byte
length is the only field YggdraSIM interprets; `TYPE` and `modifier`
are carried along as opaque strings. When `OPEN` / `USE` selects a
`.txt` / `.hex` file carrying this shape:

1. Each placeholder is replaced with a deterministic, per-index
   sentinel of the declared byte length so the hex stream decodes as
   valid DER.
2. A sidecar JSON (`<cache>.placeholders.json`) is written next to
   the cached DER, capturing every placeholder's literal, variable
   name, type, byte length, modifier, and the sentinel that stands
   in for it inside the materialised DER.
3. After pySim decodes the sequence, the sidecar is consulted and
   every sentinel run found inside a tagged hex leaf is rewritten
   back to the original placeholder literal. The operator sees the
   placeholder text exactly where it sat in the source file.

Nothing in this path *resolves* the placeholder to real bytes — that
surface stays with the JSON template / `__ygg_token_defs__`
machinery. Saving the template round-trips the literals:

1. The editor JSON buffer carries the vendor literal text inside every
   `"hex"` leaf (e.g. `"hex": "0908{imsi:IMSI:8:encode_imsi}"`).
2. On save, the literal is substituted back to its sentinel bytes,
   the buffer is DER-encoded, re-decoded, and re-jsonified, then the
   literal is re-inserted into the tagged hex leaves of the fresh
   tree.
3. The `*.transcode.json` sidecar ships with the literals intact; the
   `*.transcode.der` carries the sentinel bytes; a placeholder
   sidecar (`<transcode-der>.placeholders.json`) is written beside
   the DER so re-opening the transcode output picks the literals back
   up.

To produce a provisioning-ready DER (one with real ICCID / IMSI /
keys rather than sentinel fillers), lift the template into the
native JSON form (`GENERATE-TEMPLATE` or the TUI's export-to-JSON
action) and drive `APPLY-TEMPLATE` / `GENERATE-BATCH` against it.

## Standards and references

- GSMA SGP.22 / SGP.32 - profile metadata and placeholder patterns
- GlobalPlatform Card Specification v2.3 - TLV layout
- ETSI TS 102 221 - BER-TLV length encoding used by length companions
- ISO/IEC 7816-4 - APDU framing (consumed by `APPLY-TEMPLATE`)
