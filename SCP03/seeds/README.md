# SCP03 default seeds

This directory contains the **read-only seed defaults** that are copied into
the per-user runtime workspace (`<runtime-root>/Workspace/SCP03/...`) on first
launch. They are loaded through `yggdrasim_common.runtime_paths.ensure_seeded_workspace_file`
from `SCP03/config.py`.

## Seed → runtime mapping

| Seed (this directory)        | Runtime target                                |
| ---------------------------- | --------------------------------------------- |
| `SCP03/seeds/fids.txt`       | `<runtime-root>/Workspace/SCP03/fids.txt`     |
| `SCP03/seeds/aid.txt`        | `<runtime-root>/Workspace/SCP03/aid.txt`      |
| `SCP03/seeds/keys.ini`       | `<runtime-root>/Workspace/SCP03/keys.ini`     |
| `SCP03/seeds/binds.json`     | `<runtime-root>/Workspace/SCP03/binds.json`   |

The copy is a one-shot, on first launch. Once a runtime file exists it is
never overwritten by the seed; this keeps user edits sticky across upgrades.
Delete the runtime file to force a re-seed on next launch.

## File contracts

### `fids.txt` — ETSI / 3GPP file-identifier registry

Plain-text tree of file identifiers consumed by `SCP03.logic.fs.SCP03FileSystem`.
Indentation marks parent–child nesting; lines of the form `NAME:FID[:AID...]`
declare nodes. `EF_UNKNOWN:6Fxx` is a wildcard catcher for unrecognised entries
during deep scans. References:

- ETSI TS 102 221 §13 (Master File / Dedicated File hierarchy)
- 3GPP TS 31.102 §4.4 (USIM file structure)
- 3GPP TS 31.103 §4.2 (ISIM file structure)
- 3GPP TS 31.104 §4.2 (HPSIM file structure)
- 3GPP2 C.S0023-D §3.4 (CSIM file structure)

### `aid.txt` — Application identifier registry

Plain-text `LABEL:AID-HEX` registry consumed by `SCP03.config.Config` and the
SCP03 wizards. Labels are short tokens (`ISDR`, `ECASD`, `ARAM`, `ARAC`,
`ISDPx`, `MNOSD`) used by the TUI to resolve well-known applications without
hard-coding their AIDs. References:

- GSMA SGP.02 §2.2 (eUICC application identifiers)
- GSMA SGP.22 §2.2 (RSP architecture, ISD-R / ECASD / ISD-P)
- GlobalPlatform Card Specification v2.3 §11.1 (AID format)

### `keys.ini` — SCP03 key material

INI file consumed by `SCP03.config.Config` for SCP02/SCP03 base-key derivation
and for ETSI ADM verification. The shipped values are the **publicly-known
GlobalPlatform demo placeholder** `1122334455667788AABBCCDDEEFF0011` and the
ASCII string `12345678` (`3132333435363738`) for ADM. They are not, and have
never been, live operator material. Replace them through the SCP03 CONFIG
wizard before talking to any production card.

### `binds.json` — custom command macros

JSON object whose keys are user-defined shell command labels and whose values
are the macro bodies they expand to. The seed is intentionally an empty
object so a fresh install starts with zero macros.

## Hardening notes

- **No live operator keys ever.** The repository ships only the public
  GlobalPlatform demo placeholder. Live keys must come from operator-side
  inventory (`device-inventory` or operator-managed `keys.ini`).
- **No live certificates ever.** Certificate handling lives under `SCP11/`
  and is gated by `SCP11/TEST_MATERIAL_NOTICE.md`.
- This directory is part of the shipped bundle. Do not store any
  per-installation secret here; the runtime copy under
  `<runtime-root>/Workspace/SCP03/` is the only writable surface.
