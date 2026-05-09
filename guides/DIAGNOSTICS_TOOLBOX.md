# Diagnostics Toolbox

Four v1-era capabilities ship as first-class tooling next to the
core YggdraSIM subsystems. Each is additive — nothing existing
changes behaviour unless the new command is explicitly invoked.

| Capability | Entry point | Safety posture |
| --- | --- | --- |
| SAIP visual diff | `DIFF` / `DIFF-TUI` in the profile-package shell | Read-only |
| SIMCARD → TUI auto-open | `yggdrasim-profile-autoload` / `WATCH-SIMCARD` | Read-only |
| APDU mutation fuzzer | `yggdrasim-apdu-fuzzer` | **Opt-in, allow-listed, hard-gated** |
| EUM / SM-DP+ diagnostics | `yggdrasim-eum-diag` | Operator-only (requires key material) |

---

## 1. Visual SAIP Profile Diffing

### 1.1 What it does

Given two SAIP-compatible inputs (transcode JSON, SIMCARD profile
manifest, or raw DER via optional pySim), render the structural
difference as either:

- an ANSI-coloured summary in the shell (`DIFF`), or
- a Textual side-by-side tree (`DIFF-TUI`).

Both forms produce the same `DiffEntry` stream (`added`, `removed`,
`changed`, `moved`) with deterministic jq-style dotted paths, and
both fold SAIP top-level section reorders into a single `moved`
entry instead of a flood of add/remove pairs.

### 1.2 Shell usage

```
yggdrasim-profile-package
> DIFF /path/to/profile_a.der /path/to/profile_b.json
> DIFF /path/to/a.json /path/to/b.json NO-VALUES
> DIFF /path/to/a.der /path/to/b.der BY-CMD-INDEX
> DIFF-TUI /path/to/a.der /path/to/b.der
```

Pass `NO-VALUES` to suppress value rendering (structure-only view).
`DIFF-TUI` opens a Textual application; `n` / `N` step between
differences, `v` toggles values, `d` toggles a side-by-side decoded
view of the leaf under the tree cursor (same read-only decoder
cascade as the transcode TUI's Decoded pane), `o` toggles a
diffs-only filter that prunes the tree to the diff-bearing
breadcrumb plus every changed subtree (everything else is hidden,
which makes spotting real changes much easier on a 400+ entry
diff), `h` toggles the hex-diff overlay (see below), `q` quits.

The decoded pane has two display modes, switched with `h`:

* **JSON view** (default) — the leaf under the tree cursor is
  rendered using the read-only decoder cascade as a pretty-printed
  JSON object. No diff colouring is applied inside the pane; the
  side-by-side tree above carries the diff signal via its op
  markers and op colours.
* **Hex-diff overlay** — when the leaf carries a flat hex blob,
  the pane switches to an xxd-style 16-byte-per-line panel with a
  byte-level diff against the other side. Diverging bytes are
  painted on a directional background: red on the A side
  ("byte present in A, different / missing in B"), green on the B
  side ("byte present in B, different / missing in A"). A summary
  line at the top of the panel reports `(n of m bytes differ)`.
  Leaves with no flat hex fall back to JSON view automatically, so
  toggling the overlay on is always safe.

The decoded pane scrolls vertically (mouse wheel or `PageUp` /
`PageDown` on focus) and resizes with `]` (grow) / `[` (shrink)
between 4 and 60 rows. `F7` cycles the Textual theme through the
same palette as the transcode TUI. The chosen theme, the decoded-
pane visibility, the decoded-pane height, the values toggle, the
diffs-only filter, and the hex-diff overlay all persist between
sessions in `Tools/ProfilePackage/saip_transcode_tui_config.json`
(theme is shared with the transcode TUI; layout settings live
under a `diff_tui` sub-key).

### 1.3 Canonical vs raw `genericFileManagement` comparison

By default both `DIFF` and `DIFF-TUI` re-key
`sections.genericFileManagement` from a list of PE blocks into a
dict keyed by the resolved file-system path of each EF / DF / MF
(e.g. `3F00/7F20/6F07` for EF.IMSI under DF.GSM). `filePath`
SELECT chains are absorbed into the keys, so two profiles that
contain the same EFs at different list-index positions produce
byte-identical canonical maps and the diff engine no longer flags
mechanical SELECT shifts as `added` / `removed` entries. The
remaining diff is dominated by real changes (FCP fields, EF
content, security attributes).

The canonical pass also strips the per-PE
`<peName>-header.identification` field (SGP.22 §2.5.3), which is a
sequential PE index that shifts whenever the two profiles differ
in PE count or order. Suppressing it removes a `changed` entry on
every PE that would otherwise hide the real semantic differences.

Pass `BY-CMD-INDEX` to opt back to the raw command-index
comparison (the pre-canonical noisy view, including the PE-header
`identification` field) — useful when verifying that two encoders
emit byte-for-byte identical SAIP, or when chasing a regression in
the file-management command stream itself.

### 1.4 Library use

`Tools/ProfilePackage/saip_diff_engine.py` exposes `diff_saip_documents`,
`diff_documents`, and `format_diff_text`. The loader layer
(`saip_diff_loader.py`) normalises the three supported shapes into
a single dict for the engine, and `saip_diff_canonical.py` provides
the optional path-keyed re-keying step.

---

## 2. Direct Simulator-to-TUI Pipeline

### 2.1 What it does

Watches the SIMCARD profile store for new ICCIDs. When a new profile
lands (typically because SIMCARD just finished an SCP11 download),
the watcher launches a command per arrival. The default command is
the SAIP TUI against the newly written profile manifest.

The trigger surface is an in-engine hook:

```python
from SIMCARD.connection import get_shared_engine

engine = get_shared_engine()
engine.register_profile_download_hook(lambda event: print(event["iccid"]))
```

`get_shared_engine()` returns the same `SimulatedSimCardEngine`
instance that every `--card-backend sim` consumer talks to, so the
hook fires regardless of which shell triggered the profile download.

Hooks are error-isolated: one raising callback does not poison the
others.

### 2.2 Console script

```
yggdrasim-profile-autoload --help
yggdrasim-profile-autoload --store-root /path/to/profile_store --max-arrivals 10
yggdrasim-profile-autoload --store-root ... \
    --launcher '{python} -m Tools.ProfilePackage --cmd "USE {profile}; INFO; TREE; EXIT"'
```

Available template variables in `--launcher` (single-brace Python
`str.format` style — unknown names are substituted with the empty
string rather than raising):

- `{iccid}` — the newly seen ICCID
- `{profile}` — the preferred profile file path
- `{profile_path}` — alias of `{profile}`; kept for older scripts
- `{profile_dir}` — the per-profile directory
- `{manifest}` — the manifest JSON path (empty string if absent)
- `{python}` — `sys.executable`

If no `--launcher` is supplied the watcher falls back to
`python -m Tools.ProfilePackage --cmd "USE <profile>; INFO; TREE; EXIT"`,
which drops the operator straight into the SAIP inspect view for the
freshly downloaded profile.

### 2.3 Shell usage

Inside the profile-package shell:

```
> WATCH-SIMCARD STORE /path/to/profile_store POLL 0.5 MAX 5
> WATCH-SIMCARD LAUNCHER "yggdrasim-profile-package --cmd 'USE {profile}; INFO; TREE; EXIT'"
```

---

## 3. APDU Mutation Fuzzer

> **Warning.** The fuzzer is intended for eUICC vulnerability
> research against cards you own and have explicitly allow-listed.
> It refuses to run without an opt-in token *and* an ICCID/IMSI
> allow-list. It dumps crash records to disk with `0o600` mode.

### 3.1 What it does

Loads a corpus of known-good APDUs (typically from a SIMCARD
session recording), applies deterministic mutations
(`bit-flip`, `length-mangle`, `zero-Lc`, `tag-shuffle`,
`padding-bloat`), and transmits them through a selected transport.
Halts on crash-class status words (`6F 00`, `6E 00`, `6D 00`) or
transport errors and writes a forensic dump per crash.

### 3.2 Safety gate

The runner refuses to start unless all of the following are true:

- `--i-mean-it` is passed on the command line.
- At least one `--allow-iccid` **or** `--allow-imsi` value is
  supplied.
- The probed card identity matches the allow-list exactly.

Crash dumps and the per-run manifest land under
`--crash-dump-root` (default: `./.apdu_fuzz_runs/`) in a
timestamped subdirectory. The dump root itself is created `0o700`.

### 3.3 Usage

```
yggdrasim-apdu-fuzzer \
    --corpus /path/to/session.json \
    --transport pcsc \
    --allow-iccid 89000012345678901234 \
    --seed 0xCAFEBABE \
    --max-apdus 500 \
    --i-mean-it
```

Use `--transport null` for a dry-run against a synthetic transport
(useful in CI and for smoke-testing mutation strategies without a
card).

---

## 4. EUM Diagnostics "God-Mode"

### 4.1 What it does

Operates the *server* side of an ES8+ / BPP provisioning flow. The
operator supplies ShS-ENC, ShS-MAC, and (optionally) DEK for a
given ICCID — material that a production EUM or SM-DP+ retains
in its session database. The tooling writes an on-disk JSON
repository and hands it to a Wireshark/tshark Lua dissector that
annotates BF36 Bound Profile Package TLVs with the matched keys,
turning an otherwise opaque capture into an analysable one.

The dissector is written in pure Lua, ships with the wheel as
package-data, and degrades gracefully if the key repository is
missing, malformed, or does not contain a match for the observed
ICCID.

### 4.2 Usage

```
# Write keys + launch tshark against a capture:
yggdrasim-eum-diag inject-keys \
    --iccid 89000012345678901234 \
    --shs-enc <32 hex chars> \
    --shs-mac <32 hex chars> \
    --dek     <32 hex chars> \
    --pcap    /captures/provisioning-2026-04-19.pcapng

# Write keys only (useful when a separate tshark/wireshark session
# already has the dissector loaded):
yggdrasim-eum-diag store-keys \
    --iccid 89000012345678901234 \
    --shs-enc ... --shs-mac ... \
    --keys-out /tmp/session-keys.json

# Offline BPP decode (requires optional pySim checkout):
yggdrasim-eum-diag decode-bpp --bpp /path/to/bpp.bin
```

### 4.3 Key repository on disk

The repository is a single JSON file written atomically with `0o600`
on POSIX. Format:

```json
{
    "format": "yggdrasim-eum-session-keys/v1",
    "entries": {
        "89000012345678901234": {
            "iccid": "89000012345678901234",
            "shs_enc_hex": "...",
            "shs_mac_hex": "...",
            "dek_hex": "...",
            "comment": "case-id"
        }
    }
}
```

The Lua dissector looks up its path via the environment variable
`YGGDRASIM_EUM_SESSION_KEYS`. The tshark runner sets it for you.

---

## 5. Related diagnostics outside this guide

These complementary diagnostic surfaces are documented in their own
guides because they sit on top of larger subsystems:

- **HIL offline pcap replay + SCP keybag unwrap.** `main/main.py
  --open-pcap <pcap> [--keybag <json>]` opens the HIL decoded-APDU
  TUI without spinning up the bridge. SCP03 / SCP11c session-keys
  are unwrapped on the fly when a keybag JSON is supplied (sidecars
  named `<pcap>.keys.json` are auto-discovered). Full write-up:
  `HIL_BRIDGE_GUIDE.md` §11.
- **`main/main.py --doctor`.** Read-only preflight covering Python
  version, `cryptography`, `pycryptodomex`, `asn1tools`, optional
  on-disk `pysim/` clone, SQLite, optional `textual` (TUI), PC/SC
  reader visibility, and `gpg`. Safe to run at pipeline entry; never
  opens a card transport. See `CLI_AND_PIPING_GUIDE.md` §"Wrapper
  diagnostics".
