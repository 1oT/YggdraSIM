---
title: SAIP Profiles
tags:
  - concepts
  - saip
  - upp
  - bpp
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SAIP Profiles

SAIP is the SIMalliance / TCA Interoperable Profile format. It specifies how a
cellular profile is expressed before it gets bound into a `BPP` and sent to
an eUICC. The authoritative text lives in `docs/Profile_interoperability_V3.4.1.md`
and the technical specification in
`docs/Profile_interoperability_technical_specification_V3.4.1.md`.

YggdraSIM's `Tools/ProfilePackage` workbench is the operator surface that
edits, lints, and transcodes SAIP content.

## Layers

```mermaid
flowchart LR
    Template["SAIP template<br/>text / JSON"] --> UPP["Unprotected Profile Package"]
    UPP --> PE["Profile Elements<br/>PE list"]
    UPP --> ASN1["ASN.1 DER encoding"]
    UPP --> Bind["BPP binding<br/>(on SM-DP+)"]
    Bind --> BPP["Bound Profile Package"]
    BPP --> Card["eUICC"]
```

- A **template** is a human-authored profile description.
- A **UPP** is the full profile, as a PE list, ASN.1 encoded in DER.
- A **BPP** is the UPP wrapped in SCP11-derived session keys and segmented so
  the eUICC can consume it.
- The card only ever sees the BPP at install time.

## Profile Element shape

The PE list is an ordered sequence of PE structures. Each PE is one of:

- a header PE with profile-wide metadata
- a file-system PE that creates directories or files
- a PE that installs an applet, a security domain, or an NAA
- a PE that carries the keyset, PINs, or toolkit configuration
- a PE that writes EF records or transparent content
- a PE that sets access conditions

The PE order matters. File-system PEs create structure, content PEs fill it,
and key/auth PEs anchor the operational state. The SAIP spec lists the valid
ordering constraints.

## JSON and DER forms

YggdraSIM works with both forms of a profile.

- the **DER** form is the binary that an SM-DP+ emits and a card consumes
- the **JSON** form is an easier review surface and is round-trip safe for the
  supported PE set

The shell's `ENCODE-JSON` path rebuilds a valid DER from a tagged JSON
representation. The transcode TUI shows the two sides next to each other so
edits can be reviewed before re-encoding.

## Linting

Profile linting in YggdraSIM checks:

- PE ordering rules
- required PE presence, for example a header PE and at least one NAA
- key and PIN consistency
- access-condition sanity
- EF content width and structure against the file FCP
- metadata sanity, for example `profileName` and `serviceProviderName`

Lint modes include strict mode, metadata attachment, preset gate profiles,
and explicit rule gates. Output is YAML by default and JSON when requested.

## Sidecars

The transcode UI persists a stable set of sidecar files next to the profile
under review:

| Sidecar | Contents |
| --- | --- |
| `*.transcode.json` | canonical JSON view of the profile |
| `*.transcode.der` | canonical DER re-encoding |
| `*.transcode.txt` | human-readable inspector text |

These sidecars are used by the download flows to validate what will actually
land on the card.

## Single profile elements

The GUI workbench exports and imports one PE at a time (ribbon *Element*
group and the PE card's context menu; `saip.export_pe` / `saip.import_pe`
in the action registry). The complete form is the *PE document*, a
`.pe.json` file with the schema `ygg.pe_document.v1`:

| Key | Contents |
| --- | --- |
| `__ygg_pe_document__` | `schema` and `pe_type`; a template PE adds `template` and its `placeholders` |
| `sections` | the PE's decoded tree in the tagged form a saved package uses, without the display labels, so every setting and the workbench's PE name survive |

The document names nothing outside the PE: no source package, no summary,
no DER copy. Import rebuilds the PE from the tree, which re-encodes to the
same bytes. For PE-Application (TCA eUICC Profile Package v3.4.1 section
8.7) the tree carries the load block with its `loadBlockObject` bytes and
every `ApplicationInstance`; the export's response lists the load package
AID, the load block size, a CAP / IJC header inspection and the instance
AIDs. DER and HEX exports carry the PE bytes only.

Import accepts the PE document, a tagged single-section JSON document, the
plain decoded JSON the JSON tab shows, binary DER and ASCII hex. The tree
is the editable truth: a document an earlier release wrote also records
`der_hex`, and when that no longer matches the tree's re-encoding the
import reports it and uses the tree. The imported PE takes
the next free `identification` (section 8.1.3 requires uniqueness), so the
other PEs keep theirs. A template PE that still carries placeholder
literals is refused; export it with the stored values substituted first.

The *PE library* (`saip.save_pe`, `saip.list_pe_library`, `saip.load_pe`,
`saip.delete_saved_pe`; `Tools/ProfilePackage/saip_pe_library.py`) stores
the same PE document under a name in `~/.yggdrasim/saip_pe_library/`
(`YGGDRASIM_SAIP_PE_LIBRARY`), so a standardised element loads into any
package without a file dialog. Unlike the file import, loading a saved
template PE keeps its placeholder literals: they are registered in the
receiving package the way a literal typed into an editor is.

## Standards map

| Area | Spec |
| --- | --- |
| SAIP template and PE catalog | `docs/Profile_interoperability_V3.4.1.md` |
| SAIP technical specification | `docs/Profile_interoperability_technical_specification_V3.4.1.md` |
| BPP construction and binding | SGP.22 annexes, optional local `docs/SGP.22-v3.1.md` |

## Where to look in YggdraSIM

- [Profile Package](../subsystems/profile-package.md) for the operator
  surface
- [Inspect and Transcode SAIP](../how-to/inspect-and-transcode-saip.md)
  for a recipe-style walkthrough
- [SCP11 Live Relay](../subsystems/scp11-live.md) and
  [Local Access](../subsystems/scp11-local-access.md) for where the
  resulting BPP is consumed
