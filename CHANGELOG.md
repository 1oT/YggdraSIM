<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Changelog

All notable changes to YggdraSIM are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
honours [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for
the public API surface -- the launcher, the documented CLI shells, the
SCP03 / SCP11 / SCP80 / SIMCARD module entry points, and the
`yggdrasim_common` helpers consumed by external integrators.

Internal helpers (modules under leading-underscore names, undocumented
SAIP wrappers, and any path explicitly marked post-v1 staging in this
file) may change without notice between minor releases.

## [Unreleased]

### Added

- `Tools/ApduDissector/` is a Wireshark and tshark dissector for the
  GSMTAP SIM frames the HIL bridge mirrors on UDP `4729`. It decodes the
  ISO/IEC 7816-4 header with its class-byte breakdown and case
  classification, status words including the `61XX` / `6CXX` / `63CX`
  families whose SW2 carries a count, BER-TLV and COMPREHENSION-TLV,
  ETSI TS 102 221 clause 11.1.1.3 file-control templates, the contents
  of EF.ICCID / EF.IMSI / EF.UST / EF.AD, and ISO/IEC 7816-3 ATR frames.
  Each command also carries the risk class from
  `yggdrasim_common/apdu_risk.py`, so `yapdu.risk == 3` lists every
  irreversible command in a capture.

  Measured against TShark 4.2.2, this fixes three defects in the stock
  decode: a `GET RESPONSE` carrying an FCP template was reported as a
  malformed packet, a `STORE DATA` to the ISD-R rendered as a bare `e2`
  with its payload untouched, and ATR frames were mis-parsed as APDUs
  down to an invented status word.

  Available as `yggdrasim-apdu-dissect` (`decode`, `sidecar`,
  `install`, `uninstall`, `path`, `probe`), and loaded automatically by
  the HIL-bridge terminal decode view, offline pcap review, and the
  Wireshark launch under HIL start mode `[2]`. Set
  `YGGDRASIM_APDU_DISSECTOR=0` to opt out. A bare `tshark` or a
  desktop-launched Wireshark does not load it until
  `yggdrasim-apdu-dissect install` copies the Lua tree into the personal
  plugin folder, after which both read it at startup with no flags.

- `scripts/generate_apdu_dissector_tables.py` generates the dissector's
  Lua lookup tables from the Python modules that already own them, so an
  instruction name or status word cannot mean one thing in the toolkit
  and another in a packet trace. `tests/test_apdu_dissector_tables.py`
  fails when the committed Lua drifts.

- `yggdrasim_common/stk_tables.py` holds the ETSI TS 102 223 Table 9.4
  and clause 8.25 tables, which previously existed only as literals
  inside `tests/test_stk_spec_tables.py`.

- `yggdrasim_common/apdu_tables.py` records the ISO 7816-4 case each
  instruction normally uses, used as a confidence signal when splitting
  a concatenated command/response frame.

- `yggdrasim-apdu-dissect sidecar` recovers SCP03 / SCP11c plaintext
  from a capture into a sidecar file the dissector reads, using the
  same replay engine the terminal decode view uses. Wireshark's Lua
  binding has no AES, no CMAC and no hash, so a Lua dissector cannot
  decrypt regardless of what keys it is given. Recovered plaintext is
  re-decoded in full, so a ciphered ES10b STORE DATA renders as an
  ES10b tree. Sidecars are bound to their capture by the on-wire
  ciphered command rather than by frame number, so one built from a
  different capture contributes nothing instead of misattributing.

- `ScpReplayEngine.try_unwrap_bytes` returns the recovered plaintext
  bytes alongside the lines `try_unwrap` already rendered.

### Changed

- `Tools/EumDiag/dissector.lua` is retired. `yggdrasim-eum-diag` now
  hands its captures to `Tools/ApduDissector`, which decodes the BF36
  BoundProfilePackage as a tree rather than dumping it as one blob, and
  still honours `YGGDRASIM_EUM_SESSION_KEYS`. The retired file
  byte-scanned for the tag with no TLV awareness, so it matched inside
  unrelated values; loaded the session keys and never applied them; set
  the protocol column on every packet in the capture whether or not it
  had touched it; and built a TvbRange from half the digit count of an
  ICCID, which breaks on any real 19-digit one.

- The HIL-bridge decode view names proactive command `0x04` `POLLING
  OFF`, matching ETSI TS 102 223 Table 9.4. It previously read `POLL
  OFF`. The TUI summary marker changed with it.

- `scripts/check_repo_hygiene.py` now scans `.lua` files.

### Security

- The GUI file picker (`/api/fs/browse`) no longer enumerates arbitrary
  directories in `--web-server` mode. That endpoint is authenticated and
  returns metadata only, never file contents, but a web-server session
  binds `0.0.0.0` by default and its token holder need not own the host,
  so directory enumeration was a disclosure. Listing is now limited to the
  roots the picker already offers (home, working dir, workspace,
  Documents, Downloads, Desktop). `--gui` is unchanged: it is loopback
  bound on the operator's own machine. `YGGDRASIM_GUI_FS_ROOTS` overrides
  either default. Paths are checked after resolution, so `..` traversal
  and symlinks are judged by their real target.

### Added

- Model Context Protocol server (`Tools/YggdraMCP`, opt-in `[mcp]` extra,
  console script `yggdrasim-mcp`). 26 tools covering spec / status-word /
  AID lookup, ASN.1 and APDU decode, SAIP and eIM linting, SAIP and
  session diffing, card transport control, and batch
  execution in all eight operator shells (`profile_package`, `scp80`,
  `scp11_eim`, `suci_tool`, `scp03`, `scp11_live`, `scp11_relay`,
  `scp11_local_access`) across 360 classified verbs. Four reference
  resources and three canned workflows.
  Private extensions register through the `mcp_extensions` plugin
  capability.
- MCP access model. The server is read-only by default;
  `YGGDRASIM_MCP_ACCESS=write` permits state changes,
  `YGGDRASIM_MCP_ALLOW_CARD` permits reaching a card, and
  `YGGDRASIM_MCP_ALLOW_SCRIPT_FILES` permits verbs whose payload the gate
  cannot classify (`RUN`, `SCRIPT`, `RAW`). The three are independent.
  Shell verbs are allow-listed per shell, and every shell's classification
  is checked against that shell's own command table on each test run.
- MCP card transport control: `card_backend_status`,
  `card_backend_select`, `card_session_open`, `card_session_transmit`, and
  `card_session_close`. Sessions hold one connection open, so a
  select-then-read or secure-channel sequence survives across calls, which
  the stateless `pcsc_transmit` cannot do. Bounded to 4 concurrent
  sessions with a 10-minute idle reap.
- Standalone `yggdrasim-mcp` distribution generated by
  `scripts/release/build_mcp_standalone.py`. Publishes a single
  `yggdrasim_mcp` package that installs alongside `yggdrasim`, declares no
  Git dependencies, and vendors the card transport chain so it can drive a
  card locally or through a relay without the rest of the tree.
- HIL bridge: the supervisor now reboots the SIMtrace2 board before
  every session, replacing the trip to the rig to press the physical
  reset button. The cardem firmware resets its own microcontroller when
  USB drops below `CONFIGURED`, so `Tools/HilBridge/device_reset.py`
  forces that from the host -- `USBDEVFS_RESET` on the usbfs node by
  default, or a `uhubctl` VBUS cycle that also power-cycles the SIM.
  Selected with `--simtrace-reset` / `YGGDRASIM_HIL_SIMTRACE_RESET`
  (`usb-reset`, `port-power`, `auto`, `off`); the USB snapshot is
  re-read afterwards so `osmo-remsim-client-st2` is pinned to the
  board's new USB address. A new `yggdrasim-hil-reset` console script
  performs the same reset on demand, and the supervisor state file
  reports the result under `simtraceReset`.
- HIL bridge: relay sessions now power-cycle the physical card at their
  boundaries. Operator shells transact under a relay session id, and the
  bridge cold-resets the card (`SCARD_UNPOWER_CARD`) when that id first
  appears, when another shell replaces it, and when the shell
  disconnects -- so a selected AID, an open logical channel, or an
  established SCP03 / SCP11 secure channel can no longer leak into the
  modem session. Because a power-cycle invalidates every view of the
  card, the bankd side is dropped too and `osmo-remsim-client-st2`
  re-handshakes against the post-power-up ATR. Disable with
  `YGGDRASIM_HIL_RELAY_SESSION_RESET=0` or `--no-relay-session-reset`.
  The remote-rig systemd unit also gained the SIMtrace2 reset knobs, and
  `PcscCardChannel.disconnect()` now pins `SCARD_UNPOWER_CARD` instead
  of inheriting whatever disposition was last set.
- Post-v1 Tools tier staging (not part of this release):
  in-process `Tools/YggdraCore/` stubs (subscription store, AUSF
  stub, AAnF stub, FastAPI loopback, BYO Open5GS bridge);
  local-loopback `Tools/CardBridge/` HTTP card-relay daemon. The HTTP / CLI surface
  hardening, BYO-Open5GS resilience checks, and the public docs
  pass for these modules are still pending -- they are not part of
  the v1.0.0 promise.

## [1.0.1] -- 2026-06-05

### Fixed

- A conformance sweep of `Tools/ApduDissector/` against the governing
  specifications corrected a set of defects that produced confidently
  wrong output rather than missing output. These change what an operator
  reads off a capture they have already collected, so they are listed
  individually:

  - The life-cycle status integer was inverted against ISO/IEC 7816-4
    Table 13. `'05'` and `'07'` were reported as deactivated when they
    are activated, and `'0C'` to `'0F'` -- the **termination state** --
    were reported as operational, so a permanently dead file or ADF
    rendered as healthy. The GlobalPlatform registry codings were also
    consulted ahead of the ISO table for an FCP `'8A'`, which made every
    ordinary UICC file report "LOADED" or "INSTALLED".
  - Warning status words were counted as success. `63 CX` is a *failed*
    verification, so `yapdu.sw_success` reported "Succeeded: True"
    beside the text "Verification failed", and a filter for failures
    missed every consumed retry and every blocked PIN. Status words are
    now classified into the four categories of ISO/IEC 7816-4
    clause 5.1.3 and published as `yapdu.sw.category`.
  - ETSI TS 102 223 clause 8.7 device identities had the UICC and the
    terminal swapped, reversing the reported direction of every
    proactive command and every terminal response; the channel block was
    read from `'10'` rather than `'21'`, so channels 1--7 were named as
    card readers. Source and destination are now rendered, which they
    previously were not at all.
  - The clause 8.52 bearer table was numbered from `'00'` instead of
    `'01'`, shifting every entry -- including `'03'`, the default packet
    bearer this repository's own toolkit emits, which read as "local
    link technology independent".
  - The clause 8.12 general result table was shifted by two from `'04'`
    up, so a REFRESH that merely could not draw an icon was reported as
    an inactive NAA.
  - Clause 8.59 transport levels had local and remote swapped, reporting
    a channel terminating on the handset as one to the network.
  - Case-4 commands were split one byte short. The case hint was scored
    as a single string comparison, so an instruction hinted `3S` beat
    its true `4S` reading by 20 points -- at confidence 100 and with no
    ambiguity flag -- and the trailing Le rendered as a one-byte
    response body. Every ES10b `STORE DATA` is case 4. Scoring now
    models the two properties a case actually asserts, and confidence
    derives from the margin over the runner-up rather than from evidence
    every candidate shares.
  - Secure messaging was detected from bit 3 alone, which missed
    ISO/IEC 7816-4 Table 3 type `'10'` (CLA `'08'` and `'88'`) and
    invented an eight-byte C-MAC on the further interindustry classes
    `'44'` and `'4C'`, where that bit is part of the channel number.
  - `61 00` and `6C 00` reported zero bytes rather than 256; `92 40`, a
    memory problem, was reported as a normal ending after 64 retries;
    and `9E XX`, a SIM data download error, had no description at all.
  - A proprietary or reserved class byte had a logical channel, a
    secure-messaging level and a chaining flag decoded out of bits
    ISO/IEC 7816-4 clause 5.4.1 assigns no meaning to, stating three
    facts per command that the specification does not.
  - COMPREHENSION-TLV tags `'1C'`, `'1D'` and `'1E'` were each named as
    their neighbour and `'32'` was named as `'3F'`; the tag table now
    covers the full ETSI TS 101 220 clause 7.2 allocation.
  - The BoundProfilePackage sections were numbered from `'A0'` as the
    initialiseSecureChannelRequest. GSMA SGP.22 clause 2.5.2 puts the
    request in `BF23` and gives `'A0'` to `'A3'` to the four sequences,
    so every name was shifted by one and `secondSequenceOf87` was
    missing entirely.
  - A secure-messaged SELECT had its ciphertext read as an AID, a file
    identifier or a path, and the result was committed to the
    cross-frame state -- so every following read in that channel was
    attributed to a file identifier made of ciphertext, while still
    reporting its context as available.
  - `Tools/ApduDissector/sidecar.py` split a wrapped exchange as case 3
    unconditionally. A GlobalPlatform `INSTALL` is sent case 4, so the
    recorded command was one byte short of the frame and a valid sidecar
    was refused with "does not match", which is both false and the most
    misleading thing the tool can report. It also hardcoded the card
    session index and the selected AID, making every keybag session that
    matches on either unreachable; both are now tracked from the
    capture.
  - A sidecar entry with no `command_hex` bypassed the check that binds
    a sidecar to its capture, making the guarantee opt-in. It now fails
    closed.

- The dissector also closes gaps the sweep found where the decode simply
  stopped early: ENVELOPE bodies (`D1`--`DE`) are unwrapped, so Event
  download exposes its event code, channel status and pending byte
  count; the Result cause byte names which of the thirteen BIP failures
  occurred; Channel status reports whether the link came up and whether
  it dropped; the OPEN CHANNEL port is bound to the channel the terminal
  allocates, so DNS inside a BIP session resolves; chained `STORE DATA`
  is reassembled; and DGI-format `STORE DATA`, the INSTALL extradition,
  registry-update and personalisation layouts, and SCP01/02/03/11
  INITIALIZE UPDATE responses are decoded per their own structures
  rather than a shared guess.

- SCP11 live and relay notification sync now encode
  `seqNumber >= 0x80` as positive ASN.1 INTEGER values before
  `RetrieveNotification`, `RemoveNotificationFromList`, and local-access
  notification requests. This avoids cards interpreting values such as
  `188` as a negative INTEGER.
- SCP11 notification sync now reports
  `notificationsListResultError` responses such as `undefinedError(127)`
  directly, instead of treating the response as an undecodable pending
  notification.
- SCP11 live notification listing now preserves active-channel recovery
  context and falls back through active logical channel priming, fresh
  logical-channel recovery, and STK-mode bootstrap for recoverable
  `6E00` / `6985` style failures after profile-state changes.

## [1.0.0] -- 2026-04-29

First SemVer-tagged release. Cut at git tag `v1.0.0`. Pinned commit
exposes a frozen v1 footprint; the v2 staging continues on `main`.

### Added

- Default eUICC identity is now the reserved SGP.22 Annex A.2 test EID
  `89049032123451234512345678901235`, with prefix `89049032` and a valid
  Luhn check digit.
- SIMCARD 5G core: TS 33.501 Annex A AKA helpers (`SIMCARD/aka_5g.py`),
  TS 33.535 AKMA (`SIMCARD/akma.py`), TS 33.501 section C.3 SUCI Profile A & B
  with EF.SUCI_Calc_Info codec (`SIMCARD/suci.py`), TS 31.102 section 7.1.2.4
  `GET IDENTITY` handler (`SIMCARD/identity.py`).
  transport (`SIMCARD/ipa_tls.py`); SAIP pySIM specs bridge
  (`SIMCARD/saip_pysim_specs.py`); SGP.32 package surfaces
  (`SIMCARD/sgp32_packages.py`); modem write persistence; shared EF
  mirror; legacy GSM modem attach path; FCP decoder; GFM walker;
  service-table staging.
- SAIP PE editors (`Tools/ProfilePackage/saip_pe_editors/`); SAIP
  profile diff engine and loader; AT-simlink modem bridge
  (`Tools/HilBridge/at_simlink.py`); APDU relay auth.
- SCP03 STK ETSI defaults / conformance, service-table decoders /
  staging, card-backend relay-token plumbing, doctor card-relay
  probe.
- SCP11 shared profile-actions module, card-overview renderer,
  eim_local live-delete auto-disable.
- yggdrasim_common: APDU recorder + WebSocket stream, card-bridge
  bearer-token helper (`card_bridge_auth.py`), Nord palette,
  remote-card argument parsing.
- Documentation: configuration & certificates guide, GUI host shell
  guide, "Load certificates and config" how-to recipe.
- `tests/live_scp03/` golden inputs for the SCP03 admin shell.
- Demo scripts under `scripts/demos/` covering 3GPP attach and profile
  lifecycle.

### Changed

- `pyproject.toml` version moves from CalVer `2026.4.10` to SemVer
  `1.0.0`. Both `yggdrasim_common.__about__` and the launcher's
  `--version` resolve to the new value through the existing dynamic
  pyproject lookup.
- HilBridge live decode TUI: ISO/IEC 7816-4 `MANAGE CHANNEL`
  (INS=0x70) is now classified into the STK group ahead of the BIP
  marker scan, so `MANAGE CHANNEL Operation=Open Channel` frames no
  longer fall into the unbound-channel tail in the decoded-APDU view.
- All hard-coded EID test fixtures that used to pin the previous
  default updated to the new BCD marker; tests that exercise
  `isdr_config` overrides keep their distinct fixtures.

### Removed

- `bridge` and `modem` zero-byte scratch files at the repo root.
- Legacy `YggdraSIM-docs-oneot.zip` documentation snapshot. The
  same content is canonically tracked in `site-docs/`.

### Security / Repo Hygiene

- `reports/` is now ignored. Live SCP03 capture reports contain
  derived session keys (s_enc / s_mac / s_rmac) and chaining
  values; pushing them to a shared remote was a foot-gun. The
  `reports/.gitkeep` placeholder documents the intended layout.

[Unreleased]: https://example.invalid/yggdrasim/compare/v1.0.1...HEAD
[1.0.1]: https://example.invalid/yggdrasim/releases/tag/v1.0.1
[1.0.0]: https://example.invalid/yggdrasim/releases/tag/v1.0.0
