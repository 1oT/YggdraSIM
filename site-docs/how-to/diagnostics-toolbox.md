---
title: Diagnostics Toolbox
tags:
  - how-to
  - diagnostics
  - saip
  - simcard
  - fuzzing
  - scp11
---

# Diagnostics Toolbox

Four capabilities land next to the core subsystems for the v1
release. Each is additive — nothing existing changes unless the
new command is explicitly invoked.

| Capability | Entry point | Safety posture |
| --- | --- | --- |
| SAIP visual diff | `DIFF` / `DIFF-TUI` | Read-only |
| SIMCARD → TUI auto-open | `yggdrasim-profile-autoload` | Read-only |
| APDU mutation fuzzer | `yggdrasim-apdu-fuzzer` | **Opt-in, allow-listed** |
| EUM / SM-DP+ diagnostics | `yggdrasim-eum-diag` | Operator-only |

---

## 1. Visual SAIP profile diffing

Drop into the profile-package shell and compare two inputs:

```bash
yggdrasim-profile-package
```

```text
> DIFF /path/to/profile_a.der /path/to/profile_b.json
> DIFF /path/to/a.json /path/to/b.json NO-VALUES
> DIFF-TUI /path/to/a.der /path/to/b.der
```

Both commands accept transcode JSON, simulator profile manifests,
and raw DER. Top-level SAIP section reorders are folded into a
single `moved` entry.

Inside `DIFF-TUI`:

- `n` / `N` — next / previous diff
- `v` — toggle value rendering
- `q` — quit

See [Profile Package subsystem](../subsystems/profile-package.md).

---

## 2. Simulator-to-TUI auto-open

When SIMCARD writes a new ICCID to its profile store (typically
after a successful SCP11 download), a polling watcher picks it up
and launches a command per arrival — by default the SAIP TUI.

```bash
yggdrasim-profile-autoload --store-root /path/to/profile_store
yggdrasim-profile-autoload --store-root ... --max-arrivals 5
yggdrasim-profile-autoload \
    --launcher '{python} -m Tools.ProfilePackage --cmd "USE {profile}; INFO; TREE; EXIT"'
```

Template variables (single-brace Python `str.format` style; unknown
tokens substitute the empty string rather than raising):

- `{iccid}` — the newly seen ICCID
- `{profile}` — preferred profile path
- `{profile_path}` — alias of `{profile}`
- `{profile_dir}` — the per-profile directory
- `{manifest}` — the manifest JSON path (empty if absent)
- `{python}` — `sys.executable`

With no `--launcher` flag the watcher runs
`python -m Tools.ProfilePackage --cmd "USE <profile>; INFO; TREE; EXIT"`,
which opens the new profile in the SAIP inspect view immediately.

From inside the profile-package shell:

```text
> WATCH-SIMCARD STORE /path/to/profile_store POLL 0.5 MAX 5
> WATCH-SIMCARD LAUNCHER "yggdrasim-profile-package --cmd 'USE {profile}; INFO; TREE; EXIT'"
```

---

## 3. APDU mutation fuzzer

!!! danger "Operator responsibility"
    Only run this against cards you own and have explicitly
    allow-listed. The tooling refuses to start without both
    `--i-mean-it` and at least one `--allow-iccid` / `--allow-imsi`.

```bash
yggdrasim-apdu-fuzzer \
    --corpus /path/to/session.json \
    --transport pcsc \
    --allow-iccid 89000012345678901234 \
    --seed 0xCAFEBABE \
    --max-apdus 500 \
    --i-mean-it
```

Dry-runs without a physical card use the null transport:

```bash
yggdrasim-apdu-fuzzer --corpus /path/to/session.json --transport null --allow-iccid ANY --i-mean-it
```

See [APDU Mutation Fuzzer](../subsystems/apdu-fuzzer.md).

---

## 4. EUM / SM-DP+ diagnostics

Operates the server side of an ES8+ / BPP provisioning flow.
Supply ShS-ENC, ShS-MAC, and optionally DEK for a given ICCID;
the tooling writes a local JSON key repository (atomic, `0o600`)
and launches `tshark` with the shipped Lua dissector.

```bash
yggdrasim-eum-diag inject-keys \
    --iccid 89000012345678901234 \
    --shs-enc <32 hex chars> \
    --shs-mac <32 hex chars> \
    --dek     <32 hex chars> \
    --pcap    /captures/provisioning.pcapng
```

Write keys only (for when a separate `wireshark` instance is
handling the capture):

```bash
yggdrasim-eum-diag store-keys \
    --iccid 89000012345678901234 \
    --shs-enc ... --shs-mac ... \
    --keys-out /tmp/session-keys.json
```

Offline BPP decode via optional pySim:

```bash
yggdrasim-eum-diag decode-bpp --bpp /path/to/bpp.bin
```

See [EUM Diagnostics](../subsystems/eum-diagnostics.md).
